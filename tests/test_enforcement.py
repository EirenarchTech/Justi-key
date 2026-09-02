"""Limits enforced by software rather than left to policy.

Each control here corresponds to a stated JustiKey value that was previously
only a human expectation: keep scope narrow, keep oversight reviewable, keep
access bounded, and do not retain forever.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import helpers  # noqa: E402
from justikey import audit, config, db, models, policy, timeutil  # noqa: E402


class TestWindowBreadth(unittest.TestCase):
    """'Not unnecessarily broad' must be enforced, not merely expected."""

    def test_a_decade_wide_window_is_refused(self):
        ok, max_days = policy.check_window_breadth(
            timeutil.parse("2020-01-01T00:00"), timeutil.parse("2030-01-01T00:00"))
        self.assertFalse(ok)
        self.assertEqual(max_days, config.MAX_WINDOW_DAYS)

    def test_a_proportionate_window_is_allowed(self):
        ok, _ = policy.check_window_breadth(
            timeutil.parse("2026-08-01T00:00"), timeutil.parse("2026-08-15T00:00"))
        self.assertTrue(ok)

    def test_the_boundary_is_inclusive(self):
        start = timeutil.now()
        end = start + timedelta(days=config.MAX_WINDOW_DAYS)
        ok, _ = policy.check_window_breadth(
            timeutil.to_canonical(start), timeutil.to_canonical(end))
        self.assertTrue(ok)

    def test_one_day_past_the_limit_is_refused(self):
        start = timeutil.now()
        end = start + timedelta(days=config.MAX_WINDOW_DAYS + 1)
        ok, _ = policy.check_window_breadth(
            timeutil.to_canonical(start), timeutil.to_canonical(end))
        self.assertFalse(ok)

    def test_a_zero_limit_disables_the_check(self):
        ok, _ = policy.check_window_breadth(
            timeutil.parse("2000-01-01T00:00"), timeutil.parse("2030-01-01T00:00"), max_days=0)
        self.assertTrue(ok)


class PolicyFixture(unittest.TestCase):
    def setUp(self):
        self.conn = db.get_connection(":memory:")
        self.conn.executescript(db.SCHEMA)
        self.requester_id = models.create_user(self.conn, "officer1", "pw", "requester")
        self.approver_id = models.create_user(self.conn, "supervisor1", "pw", "approver")
        now = timeutil.now()
        models.insert_event(self.conn, "ABC123", timeutil.to_canonical(now - timedelta(hours=1)),
                            "CAM-1", 0.95, "Gate", "sim")
        self.auth_id = models.create_authorization(
            self.conn, "CASE-1", "Warrant 1", "Investigation", "ABC123",
            timeutil.to_canonical(now - timedelta(days=2)),
            timeutil.to_canonical(now + timedelta(days=2)), self.requester_id)
        helpers.approve_signed(self.conn, self.auth_id, self.approver_id)

    def tearDown(self):
        self.conn.close()

    def requester(self):
        return models.get_user_by_id(self.conn, self.requester_id)


class TestDisclosureCap(PolicyFixture):
    """One approval must not authorize unlimited re-querying."""

    def test_disclosures_are_permitted_up_to_the_cap(self):
        for _ in range(config.MAX_DISCLOSURES_PER_AUTHORIZATION):
            allowed, reason, _ = policy.evaluate_disclosure(
                self.conn, self.auth_id, "ABC123", self.requester())
            self.assertTrue(allowed, reason)
            models.record_disclosure(self.conn, self.auth_id)

    def test_the_cap_then_blocks_further_use(self):
        for _ in range(config.MAX_DISCLOSURES_PER_AUTHORIZATION):
            models.record_disclosure(self.conn, self.auth_id)
        allowed, reason, _ = policy.evaluate_disclosure(
            self.conn, self.auth_id, "ABC123", self.requester())
        self.assertFalse(allowed)
        self.assertEqual(reason, "disclosure_limit_reached")

    def test_the_counter_increments_per_use(self):
        self.assertEqual(models.record_disclosure(self.conn, self.auth_id), 1)
        self.assertEqual(models.record_disclosure(self.conn, self.auth_id), 2)


class TestBreadthRecheckedAtDisclosure(PolicyFixture):
    def test_an_over_broad_window_is_refused_even_once_approved(self):
        """A limit applied only at creation could be bypassed later."""
        self.conn.execute(
            "UPDATE authorizations SET window_start=?, window_end=? WHERE id=?",
            (timeutil.parse("2000-01-01T00:00"), timeutil.parse("2030-01-01T00:00"),
             self.auth_id))
        allowed, reason, _ = policy.evaluate_disclosure(
            self.conn, self.auth_id, "ABC123", self.requester())
        self.assertFalse(allowed)
        self.assertEqual(reason, "window_too_broad")


class TestLoginLockout(unittest.TestCase):
    def setUp(self):
        self.conn = db.get_connection(":memory:")
        self.conn.executescript(db.SCHEMA)

    def tearDown(self):
        self.conn.close()

    def test_account_locks_after_the_configured_failures(self):
        for i in range(config.MAX_FAILED_LOGINS - 1):
            models.record_login_failure(self.conn, "officer1")
            self.assertEqual(models.login_lock_remaining(self.conn, "officer1"), 0,
                             f"locked too early, after {i + 1} failures")
        failures, locked = models.record_login_failure(self.conn, "officer1")
        self.assertEqual(failures, config.MAX_FAILED_LOGINS)
        self.assertGreater(locked, 0)
        self.assertGreater(models.login_lock_remaining(self.conn, "officer1"), 0)

    def test_a_successful_sign_in_clears_the_counter(self):
        for _ in range(config.MAX_FAILED_LOGINS - 1):
            models.record_login_failure(self.conn, "officer1")
        models.clear_login_failures(self.conn, "officer1")
        models.record_login_failure(self.conn, "officer1")
        self.assertEqual(models.login_lock_remaining(self.conn, "officer1"), 0)

    def test_lockout_is_per_account(self):
        for _ in range(config.MAX_FAILED_LOGINS):
            models.record_login_failure(self.conn, "officer1")
        self.assertGreater(models.login_lock_remaining(self.conn, "officer1"), 0)
        self.assertEqual(models.login_lock_remaining(self.conn, "supervisor1"), 0)

    def test_an_expired_lock_releases(self):
        models.record_login_failure(self.conn, "officer1")
        self.conn.execute(
            "UPDATE login_failures SET locked_until=? WHERE username=?",
            (timeutil.to_canonical(timeutil.now() - timedelta(seconds=1)), "officer1"))
        self.assertEqual(models.login_lock_remaining(self.conn, "officer1"), 0)


class TestRetention(unittest.TestCase):
    """Data that no longer exists cannot be disclosed by a future compromise."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "justikey.db")
        db.init_db(self.path)
        conn = db.get_connection(self.path)
        try:
            src = models.create_source(conn, "cam", "Cam")
            now = timeutil.now()
            models.insert_event(conn, "OLD001", timeutil.to_canonical(now - timedelta(days=400)),
                                "CAM-1", 0.9, "Gate", "sim", source_ref=src)
            models.insert_event(conn, "NEW001", timeutil.to_canonical(now - timedelta(days=5)),
                                "CAM-1", 0.9, "Gate", "sim", source_ref=src)
        finally:
            conn.close()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def run_script(self, *args):
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "scripts", "enforce_retention.py"),
             "--db", self.path, *args], capture_output=True, text=True)

    def count(self):
        conn = db.get_connection(self.path)
        try:
            return conn.execute("SELECT COUNT(*) c FROM lpr_events").fetchone()["c"]
        finally:
            conn.close()

    def test_a_dry_run_deletes_nothing(self):
        result = self.run_script("--days", "365")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.count(), 2)
        self.assertIn("Dry run", result.stdout)

    def test_apply_removes_only_records_past_retention(self):
        result = self.run_script("--days", "365", "--apply")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.count(), 1)

    def test_the_purge_is_audited(self):
        self.run_script("--days", "365", "--apply")
        conn = db.get_connection(self.path)
        try:
            row = conn.execute(
                "SELECT details FROM audit_log WHERE event_type='retention_purge'").fetchone()
            self.assertIsNotNone(row, "a deletion that leaves no trace is not reviewable")
            self.assertIn('"deleted":1', row["details"])
            ok, _, why = audit.verify_chain(conn)
            self.assertTrue(ok, why)
        finally:
            conn.close()

    def test_audit_entries_outlive_the_data_they_describe(self):
        before = self.audit_count()
        self.run_script("--days", "365", "--apply")
        self.assertGreater(self.audit_count(), before)

    def audit_count(self):
        conn = db.get_connection(self.path)
        try:
            return conn.execute("SELECT COUNT(*) c FROM audit_log").fetchone()["c"]
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
