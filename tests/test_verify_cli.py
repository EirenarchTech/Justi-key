"""Tests for the standalone verifier in scripts/verify_audit.py.

That script is the tool an auditor actually runs, and it deliberately
re-implements every check rather than importing the package. That
independence is the point -- and it means the reimplementation needs its own
coverage, since a bug there would not be caught by the package's tests.
"""
import importlib.util
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from justikey import anchor, audit, db  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "verify_audit_cli", os.path.join(ROOT, "scripts", "verify_audit.py"))
cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cli)

KEY = b"\x01" * 32


class TestStandaloneVerifier(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.dir, "justikey.db")
        db.init_db(self.db_path)
        self.conn = db.get_connection(self.db_path)
        self.store = anchor.AnchorStore(os.path.join(self.dir, "anchors.jsonl"), key=KEY)
        for i in range(10):
            audit.append_event(self.conn, "login_success", "alice", {"i": i})
        anchor.create_anchor(self.conn, self.store)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def rows(self):
        return cli.load_entries(self.db_path)

    def anchors(self):
        return cli.load_anchor_file(self.store.path)

    def test_clean_ledger_passes_both_checks(self):
        ok, _, _ = cli.verify_chain(self.rows())
        self.assertTrue(ok)
        ok, message = cli.verify_anchors(self.anchors(), self.rows(), KEY)
        self.assertTrue(ok, message)

    def test_chain_check_agrees_with_the_package(self):
        """The independent reimplementation must not drift from the original."""
        pkg_ok, pkg_info, _ = audit.verify_chain(self.conn)
        cli_ok, cli_info, _ = cli.verify_chain(self.rows())
        self.assertEqual((pkg_ok, pkg_info), (cli_ok, cli_info))

    def test_detects_tail_truncation(self):
        self.conn.execute("DELETE FROM audit_log WHERE seq > 6")
        chain_ok, _, _ = cli.verify_chain(self.rows())
        self.assertTrue(chain_ok, "the chain alone cannot see a missing tail")
        ok, message = cli.verify_anchors(self.anchors(), self.rows(), KEY)
        self.assertFalse(ok)
        self.assertIn("4 entries have been removed", message)

    def test_reports_truncation_alongside_a_bad_signature(self):
        """Deletion evidence must not hide behind a signature complaint."""
        self.conn.execute("DELETE FROM audit_log WHERE seq > 6")
        wrong_key = b"\x02" * 32
        ok, message = cli.verify_anchors(self.anchors(), self.rows(), wrong_key)
        self.assertFalse(ok)
        self.assertIn("invalid signature", message)
        self.assertIn("entries have been removed", message)

    def test_without_a_key_truncation_is_still_detected(self):
        """A verifier lacking the key can still prove deletion."""
        self.conn.execute("DELETE FROM audit_log WHERE seq > 6")
        ok, message = cli.verify_anchors(self.anchors(), self.rows(), None)
        self.assertFalse(ok)
        self.assertIn("entries have been removed", message)

    def test_without_a_key_a_clean_ledger_says_signatures_unchecked(self):
        ok, message = cli.verify_anchors(self.anchors(), self.rows(), None)
        self.assertTrue(ok)
        self.assertIn("UNCHECKED", message)

    def test_no_anchors_is_not_an_integrity_failure(self):
        ok, message = cli.verify_anchors([], self.rows(), KEY)
        self.assertTrue(ok)

    def test_malformed_anchor_log_raises(self):
        with open(self.store.path, "a") as fh:
            fh.write("{not json\n")
        with self.assertRaises(ValueError):
            cli.load_anchor_file(self.store.path)


if __name__ == "__main__":
    unittest.main()
