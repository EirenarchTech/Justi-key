"""Source identity: authenticated provenance and independent revocation."""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from justikey import db, models  # noqa: E402


class TestSourceIdentity(unittest.TestCase):
    def setUp(self):
        self.conn = db.get_connection(":memory:")
        self.conn.executescript(db.SCHEMA)
        self.gate_id = models.create_source(self.conn, "gate-north", "North gate")
        self.gate_key = models.issue_source_credential(self.conn, self.gate_id)
        self.lot_id = models.create_source(self.conn, "lot-south", "South lot")
        self.lot_key = models.issue_source_credential(self.conn, self.lot_id)

    def tearDown(self):
        self.conn.close()

    def test_credential_resolves_to_its_own_source(self):
        self.assertEqual(models.authenticate_source(self.conn, self.gate_key)["source_key"],
                         "gate-north")
        self.assertEqual(models.authenticate_source(self.conn, self.lot_key)["source_key"],
                         "lot-south")

    def test_unknown_credential_is_rejected(self):
        self.assertIsNone(models.authenticate_source(self.conn, "not-a-real-key"))
        self.assertIsNone(models.authenticate_source(self.conn, ""))
        self.assertIsNone(models.authenticate_source(self.conn, None))

    def test_revoking_one_source_leaves_the_others_working(self):
        """The point of per-source identity: no shared-key blast radius."""
        models.revoke_source(self.conn, self.gate_id)
        self.assertIsNone(models.authenticate_source(self.conn, self.gate_key))
        self.assertIsNotNone(models.authenticate_source(self.conn, self.lot_key))

    def test_suspended_source_is_refused_then_restored(self):
        models.revoke_source(self.conn, self.gate_id, status="suspended")
        self.assertIsNone(models.authenticate_source(self.conn, self.gate_key))
        models.reactivate_source(self.conn, self.gate_id)
        self.assertIsNotNone(models.authenticate_source(self.conn, self.gate_key))

    def test_credentials_rotate_without_changing_identity(self):
        replacement = models.issue_source_credential(self.conn, self.gate_id, "replacement")
        # Both work during the overlap window.
        self.assertIsNotNone(models.authenticate_source(self.conn, self.gate_key))
        self.assertIsNotNone(models.authenticate_source(self.conn, replacement))

        models.revoke_source_credentials(self.conn, self.gate_id)
        self.assertIsNone(models.authenticate_source(self.conn, replacement))

        third = models.issue_source_credential(self.conn, self.gate_id, "third")
        source = models.authenticate_source(self.conn, third)
        self.assertEqual(source["id"], self.gate_id, "identity must survive rotation")

    def test_revoked_credential_does_not_revive_with_the_source(self):
        models.revoke_source_credentials(self.conn, self.gate_id)
        models.reactivate_source(self.conn, self.gate_id)
        self.assertIsNone(models.authenticate_source(self.conn, self.gate_key))

    def test_source_keys_are_unique(self):
        import sqlite3
        with self.assertRaises(sqlite3.IntegrityError):
            models.create_source(self.conn, "gate-north", "Duplicate")


class TestProvenance(unittest.TestCase):
    def setUp(self):
        self.conn = db.get_connection(":memory:")
        self.conn.executescript(db.SCHEMA)
        self.source_id = models.create_source(self.conn, "gate-north", "North gate")

    def tearDown(self):
        self.conn.close()

    def test_authenticated_source_is_recorded_separately_from_the_claim(self):
        """A payload's self-declared feed name must not become provenance."""
        event_id = models.insert_event(
            self.conn, "ABC123", "2026-08-31T12:00:00Z", "CAM-1", 0.9, "Gate",
            source_id="i-am-somebody-else",       # the claim
            source_ref=self.source_id,            # the proof
            adapter="justikey",
        )
        row = self.conn.execute("SELECT * FROM lpr_events WHERE id=?", (event_id,)).fetchone()
        self.assertEqual(row["source_id"], "i-am-somebody-else")
        self.assertEqual(row["source_ref"], self.source_id)
        self.assertEqual(row["adapter"], "justikey")

    def test_observation_counts_attribute_to_the_authenticated_source(self):
        for _ in range(3):
            models.insert_event(self.conn, "ABC123", "2026-08-31T12:00:00Z", "CAM-1",
                                0.9, "Gate", "claimed", source_ref=self.source_id)
        row = next(r for r in models.list_sources(self.conn) if r["id"] == self.source_id)
        self.assertEqual(row["observation_count"], 3)


class TestLegacyMigration(unittest.TestCase):
    """A database predating source identity must keep working."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "legacy.db")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_legacy_shared_key_is_adopted_by_a_named_source(self):
        from justikey import crypto_utils
        conn = db.get_connection(self.path)
        conn.executescript(db.SCHEMA)
        legacy_key = "legacy-shared-key-value"
        models.create_api_key(conn, legacy_key, "default-sensor-key")
        conn.close()

        db.init_db(self.path)   # runs the migration

        conn = db.get_connection(self.path)
        try:
            source = models.authenticate_source(conn, legacy_key)
            self.assertIsNotNone(source, "an existing key must keep working after upgrade")
            self.assertEqual(source["source_key"], "legacy-api-key")
            # Idempotent: a second migration must not duplicate the credential.
            db.migrate(conn)
            count = conn.execute(
                "SELECT COUNT(*) c FROM source_credentials WHERE key_hash=?",
                (crypto_utils.hash_token(legacy_key),)).fetchone()["c"]
            self.assertEqual(count, 1)
        finally:
            conn.close()

    def test_migration_adds_provenance_columns_to_an_existing_events_table(self):
        conn = db.get_connection(self.path)
        conn.executescript("""
            CREATE TABLE lpr_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, plate TEXT NOT NULL,
                captured_at TEXT NOT NULL, camera_id TEXT NOT NULL,
                confidence REAL NOT NULL, location TEXT, source_id TEXT,
                ingested_at TEXT NOT NULL);
        """)
        conn.close()

        db.init_db(self.path)

        conn = db.get_connection(self.path)
        try:
            columns = {r["name"] for r in conn.execute("PRAGMA table_info(lpr_events)")}
            self.assertIn("source_ref", columns)
            self.assertIn("adapter", columns)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
