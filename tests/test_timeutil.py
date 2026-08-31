import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from justikey import db, models, policy, timeutil


class TestCanonicalTimestamps(unittest.TestCase):
    def test_all_canonical_strings_are_fixed_width(self):
        values = [
            timeutil.to_canonical(datetime(2026, 8, 31, 12, 0, 0, 0, tzinfo=timezone.utc)),
            timeutil.to_canonical(datetime(2026, 8, 31, 12, 0, 0, 500000, tzinfo=timezone.utc)),
            timeutil.now_iso(),
        ]
        for v in values:
            self.assertEqual(len(v), timeutil.CANONICAL_LENGTH, v)

    def test_equivalent_instants_in_different_formats_are_identical(self):
        """The whole point: vendor format must not change the stored value."""
        forms = [
            "2026-08-31T23:59:59Z",
            "2026-08-31T23:59:59+00:00",
            "2026-08-31T23:59:59",
            "2026-08-31 23:59:59",
            "2026-09-01T00:59:59+01:00",   # same instant, different offset
        ]
        canonical = {timeutil.parse(f) for f in forms}
        self.assertEqual(len(canonical), 1, f"formats diverged: {canonical}")

    def test_lexicographic_order_matches_chronological_order(self):
        base = datetime(2026, 8, 31, 12, 0, 0, tzinfo=timezone.utc)
        offsets = [0, 1, 999, 1000, 59_999_999, 86_399_000_000]
        stamps = [timeutil.to_canonical(base + timedelta(microseconds=o)) for o in offsets]
        self.assertEqual(stamps, sorted(stamps))

    def test_rejects_unparseable_values(self):
        for bad in ["", "   ", "not-a-date", "2026-13-45T99:99:99", None, 12345]:
            with self.assertRaises(ValueError):
                timeutil.parse(bad)


class TestWindowFilteringAcrossVendorFormats(unittest.TestCase):
    """A camera-independent ingest API receives many ISO-8601 flavors.

    Every one of these observations really falls inside the authorized
    window, so every one must be disclosed.
    """

    def setUp(self):
        self.conn = db.get_connection(":memory:")
        self.conn.executescript(db.SCHEMA)
        self.requester_id = models.create_user(self.conn, "officer1", "pw", "requester")
        self.approver_id = models.create_user(self.conn, "supervisor1", "pw", "approver")

        self.vendor_timestamps = [
            "2026-08-31T23:59:59Z",              # RFC 3339 "Z"
            "2026-08-31T00:00:00",               # naive, exactly at window start
            "2026-08-31T12:00:00.500000+00:00",  # python isoformat with microseconds
            "2026-08-31T12:00:00+00:00",         # zero microseconds, omitted
            "2026-08-31 08:30:00",               # space separator
        ]
        for ts in self.vendor_timestamps:
            models.insert_event(self.conn, "ABC123", ts, "CAM-1", 0.95, "Gate", "vendor")

        self.auth_id = models.create_authorization(
            self.conn, "CASE-1", "Warrant 1", "Investigation", "ABC123",
            window_start=timeutil.parse("2026-08-31T00:00:00"),
            window_end=timeutil.parse("2026-08-31T23:59:59"),
            requested_by=self.requester_id,
        )
        models.approve_authorization(self.conn, self.auth_id, self.approver_id)

    def tearDown(self):
        self.conn.close()

    def test_no_in_window_observation_is_silently_dropped(self):
        user = models.get_user_by_id(self.conn, self.requester_id)
        allowed, reason, events = policy.evaluate_disclosure(self.conn, self.auth_id, "ABC123", user)
        self.assertTrue(allowed, reason)
        self.assertEqual(
            len(events), len(self.vendor_timestamps),
            "an observation inside the authorized window was not disclosed",
        )

    def test_observation_outside_window_is_still_excluded(self):
        models.insert_event(self.conn, "ABC123", "2026-09-01T00:00:01Z", "CAM-1", 0.9, "Gate", "vendor")
        user = models.get_user_by_id(self.conn, self.requester_id)
        allowed, reason, events = policy.evaluate_disclosure(self.conn, self.auth_id, "ABC123", user)
        self.assertTrue(allowed, reason)
        self.assertEqual(len(events), len(self.vendor_timestamps))


if __name__ == "__main__":
    unittest.main()
