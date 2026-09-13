"""Registry integrity: rollback and silent replacement (stage 4 invariant).

Deciding whose approvals and whose proofs of presence the disclosure service
will accept is privileged configuration. That the application cannot write it
is stage 3's contribution; it says nothing about an attacker who reaches the
service host or the path the file travels.

Two attacks, neither of which a digest alone catches, because the attacker
recomputes the digest:

    replacement   a registry containing a key the attacker holds
    rollback      yesterday's copy, reinstating a key revoked this morning

What catches them is state the service already committed to its own ledger.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from justikey import db, registry, sealing  # noqa: E402

SKIP = not sealing.SEALING_AVAILABLE


class TestEnvelope(unittest.TestCase):
    def test_a_bare_mapping_reads_as_version_zero(self):
        """Registries written before versioning are genuine registries."""
        version, principals = registry.unwrap({"alice": {"public_key": "aa"}})
        self.assertEqual(version, 0)
        self.assertEqual(list(principals), ["alice"])

    def test_a_versioned_envelope_round_trips(self):
        principals = {"alice": {"public_key": "aa"}}
        version, restored = registry.unwrap(registry.wrap(principals, 7))
        self.assertEqual((version, restored), (7, principals))

    def test_a_nonsense_version_is_refused(self):
        for bad in ("3", -1, 1.5, True, None):
            with self.assertRaises(registry.RegistryError):
                registry.unwrap({"version": bad, "principals": {}})

    def test_the_digest_covers_contents_and_not_the_version(self):
        """A version bump must be visible AS a version bump, not as a content
        change, or the two become indistinguishable in the ledger."""
        principals = {"alice": {"public_key": "aa"}}
        self.assertEqual(registry.digest(principals), registry.digest(dict(principals)))
        self.assertNotEqual(registry.digest(principals),
                            registry.digest({"alice": {"public_key": "bb"}}))

    def test_key_order_does_not_change_the_digest(self):
        self.assertEqual(
            registry.digest({"a": {"public_key": "1"}, "b": {"public_key": "2"}}),
            registry.digest({"b": {"public_key": "2"}, "a": {"public_key": "1"}}))


class TestAdmissionChecks(unittest.TestCase):
    def setUp(self):
        self.principals = {"supervisor1": {"public_key": "aa" * 32, "revoked": False}}
        self.digest = registry.digest(self.principals)

    def check(self, version, last_version, last_digest):
        return registry.check("approver", version, self.principals,
                              last_version, last_digest)

    def test_nothing_recorded_yet(self):
        status, detail = self.check(1, None, None)
        self.assertEqual(status, "new")
        self.assertEqual(detail["version"], 1)

    def test_same_version_same_contents(self):
        self.assertEqual(self.check(1, 1, self.digest)[0], "unchanged")

    def test_a_version_moving_forward_is_recorded(self):
        status, detail = self.check(2, 1, "an older digest")
        self.assertEqual(status, "updated")
        self.assertEqual(detail["previous_version"], 1)
        self.assertEqual(detail["previous_digest"], "an older digest")

    def test_a_rollback_is_refused(self):
        with self.assertRaises(registry.RegistryError) as caught:
            self.check(1, 2, "whatever")
        self.assertIn("cannot go backwards", str(caught.exception))

    def test_changed_contents_at_the_same_version_are_refused(self):
        """What a silent swap looks like from the verifier's side."""
        with self.assertRaises(registry.RegistryError) as caught:
            self.check(1, 1, registry.digest({"attacker": {"public_key": "bb" * 32}}))
        self.assertIn("same version", str(caught.exception))


@unittest.skipIf(SKIP, "the service requires the cryptography package")
class TestTheServiceRefusesToStart(unittest.TestCase):
    """End to end: a registry the service cannot account for stops it."""

    def setUp(self):
        import disclosure_server

        self.module = disclosure_server
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.ledger = os.path.join(self.dir, "ledger.db")
        conn = db.get_connection(self.ledger)
        try:
            conn.executescript(disclosure_server.LEDGER_SCHEMA)
        finally:
            conn.close()
        self.path = os.path.join(self.dir, "approvers.json")
        self.principals = {"supervisor1": {"public_key": "aa" * 32, "revoked": False}}
        self.write(1, self.principals)

    def write(self, version, principals):
        with open(self.path, "w") as fh:
            json.dump(registry.wrap(principals, version), fh)

    def admit(self):
        return self.module.admit_registry(self.ledger, "approver", self.path)

    def test_first_admission_records_the_version(self):
        _, status, detail = self.admit()
        self.assertEqual(status, "new")
        conn = db.get_connection(self.ledger)
        try:
            stored = self.module.get_meta(
                conn, registry.REGISTRY_VERSION_KEY % "approver")
        finally:
            conn.close()
        self.assertEqual(stored, "1")

    def test_readmitting_the_same_file_is_unchanged(self):
        self.admit()
        self.assertEqual(self.admit()[1], "unchanged")

    def test_a_swapped_registry_is_refused(self):
        self.admit()
        self.write(1, dict(self.principals,
                           attacker={"public_key": "bb" * 32, "revoked": False}))
        with self.assertRaises(registry.RegistryError) as caught:
            self.admit()
        self.assertIn("same version", str(caught.exception))

    def test_a_rolled_back_registry_is_refused(self):
        self.admit()
        revoked = {"supervisor1": {"public_key": "aa" * 32, "revoked": True}}
        self.write(2, revoked)
        self.assertEqual(self.admit()[1], "updated")

        self.write(1, self.principals)               # yesterday's copy
        with self.assertRaises(registry.RegistryError) as caught:
            self.admit()
        self.assertIn("already run with version 2", str(caught.exception))

    def test_a_legitimate_change_is_admitted_and_stays_admitted(self):
        self.admit()
        changed = dict(self.principals,
                       supervisor2={"public_key": "cc" * 32, "revoked": False})
        self.write(2, changed)
        self.assertEqual(self.admit()[1], "updated")
        self.assertEqual(self.admit()[1], "unchanged")

    def test_a_counter_advancing_does_not_look_like_a_registry_change(self):
        """Sign counts live in the service database precisely so that routine
        use never has to touch the file whose digest is committed."""
        from justikey import disclosure

        self.admit()
        usage = disclosure.UsageStore(self.ledger)
        usage.record_sign_count("cred-1", 5)
        usage.record_sign_count("cred-1", 9)
        self.assertEqual(usage.sign_count("cred-1"), 9)
        usage.record_sign_count("cred-1", 2)          # never downwards
        self.assertEqual(usage.sign_count("cred-1"), 9)
        self.assertEqual(self.admit()[1], "unchanged")


if __name__ == "__main__":
    unittest.main()
