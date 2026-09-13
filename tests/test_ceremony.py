"""The v1 -> v3 migration ceremony.

A migration whose last step destroys a key needs its checks to be real, so
these tests mostly assert that the ceremony *refuses*: before credentials are
re-keyed, on the wrong confirmation phrase, when the store has changed since
it was verified, and when completing the step would quietly rotate the
blind-index key and leave the archive unsearchable.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from justikey import config, crypto_store, models, sealing, timeutil  # noqa: E402

SCRIPT = os.path.join(ROOT, "scripts", "seal_store.py")
SKIP = not sealing.SEALING_AVAILABLE

BUILD_V1 = r'''
import os, sys
from datetime import timedelta
sys.path.insert(0, %r)
path = sys.argv[1]
os.environ["JUSTIKEY_DB"] = path
from justikey import config, db, models, timeutil
config.SEAL_RECORDS = False
db.init_db(path)
conn = db.get_connection(path)
src = models.create_source(conn, "cam-a", "Camera A")
hmac_src = models.create_source(conn, "cam-b", "Camera B", auth_mode="hmac")
secret = models.issue_source_credential(conn, hmac_src, "signing-1")
models.create_user(conn, "officer1", "pw", "requester")
models.create_user(conn, "supervisor1", "pw", "approver")
now = timeutil.now()
for i in range(12):
    models.insert_event(conn, "ABC%%03d" %% i,
                        timeutil.to_canonical(now - timedelta(hours=i + 1)),
                        "CAM-1", 0.9, "Depot %%d" %% i, "claimed", source_ref=src)
print(secret)
conn.close()
''' % (ROOT,)


@unittest.skipIf(SKIP, "sealing requires the cryptography package")
class CeremonyTest(unittest.TestCase):
    """Each test gets its own v1 store, built in a subprocess.

    A separate process because the store's mode is decided at creation and
    cached on connections; sharing one interpreter across v1 and v3 stores
    would test the cache rather than the ceremony.
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = os.path.join(self.dir, "justikey.db")
        self.manifest = os.path.join(self.dir, "justikey.ceremony.json")
        builder = os.path.join(self.dir, "build.py")
        with open(builder, "w") as fh:
            fh.write(BUILD_V1)
        result = self.python(builder, self.db)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.sensor_secret = result.stdout.strip().splitlines()[-1]

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def python(self, script, *args, env=None):
        environment = dict(os.environ, JUSTIKEY_DB=self.db)
        environment.pop("JUSTIKEY_DISCLOSURE_URL", None)
        environment.update(env or {})
        return subprocess.run([sys.executable, script, *args],
                              capture_output=True, text=True, env=environment)

    def ceremony(self, *args, env=None):
        return self.python(SCRIPT, *args, "--db", self.db, env=env)

    def read_manifest(self):
        with open(self.manifest) as fh:
            return json.load(fh)

    def stages(self):
        return {s["stage"]: s for s in self.read_manifest()["stages"]}


class TestPlanAndMigrate(CeremonyTest):
    def test_plan_changes_nothing(self):
        before = os.path.getmtime(self.db)
        result = self.ceremony("plan")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("12 v1", result.stdout)
        self.assertFalse(os.path.exists(self.manifest))
        self.assertEqual(os.path.getmtime(self.db), before)

    def test_migrate_reseals_and_verifies(self):
        result = self.ceremony("migrate")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("5/5", result.stdout)

        stage = self.stages()["migrate"]
        self.assertEqual(stage["observations_before"]["v1"], 12)
        self.assertEqual(stage["observations_after"]["v1"], 0)
        self.assertEqual(stage["observations_after"]["sealed"], 12)
        self.assertEqual(stage["problems"], [])
        self.assertEqual(stage["sample_level"], "full")

    def test_migrating_twice_is_refused(self):
        self.assertEqual(self.ceremony("migrate").returncode, 0)
        again = self.ceremony("migrate")
        self.assertEqual(again.returncode, 1)
        self.assertIn("expected a v1 store", again.stderr)

    def test_the_manifest_digest_covers_its_contents(self):
        self.ceremony("migrate")
        manifest = self.read_manifest()
        manifest["stages"][0]["resealed"] = 99999
        with open(self.manifest, "w") as fh:
            json.dump(manifest, fh)

        result = self.ceremony("verify")
        self.assertEqual(result.returncode, 1)
        self.assertIn("digest does not match", result.stderr)


class TestVerify(CeremonyTest):
    def test_verify_detects_a_changed_store(self):
        self.assertEqual(self.ceremony("migrate").returncode, 0)
        self.assertEqual(self.ceremony("verify").returncode, 0)

        from justikey import db
        conn = db.get_connection(self.db)
        try:
            conn.execute("DELETE FROM lpr_events WHERE id = (SELECT MIN(id) FROM lpr_events)")
        finally:
            conn.close()

        result = self.ceremony("verify")
        self.assertEqual(result.returncode, 1)
        self.assertIn("has changed since the migration", result.stdout + result.stderr)

    def test_verify_reopens_the_sample_where_the_key_lives(self):
        self.ceremony("migrate")
        result = self.ceremony("verify")
        self.assertIn("5/5 re-opened", result.stdout)


class TestRekeyGuard(CeremonyTest):
    """The guard that a live end-to-end run found the hard way."""

    def test_local_mode_refuses_to_rotate_a_derived_index_key(self):
        self.assertEqual(self.ceremony("migrate").returncode, 0)
        result = self.ceremony("rekey-credentials")
        self.assertEqual(result.returncode, 1)
        self.assertIn("blind-index key", result.stderr)
        self.assertIn("unsearchable", result.stderr)
        # Nothing staged, nothing retired: the refusal is before any write.
        self.assertFalse(os.path.exists(self.db[:-3] + ".data-key.new"))
        self.assertFalse(os.path.exists(self.db[:-3] + ".data-key.legacy"))
        self.assertNotIn("rekey-credentials", self.stages())


class TestDestroyRefuses(CeremonyTest):
    def test_destroy_without_a_migration(self):
        result = self.ceremony("destroy-legacy-key", "--confirm",
                               "destroy the legacy key for justikey.db")
        self.assertEqual(result.returncode, 1)
        self.assertIn("no manifest", result.stderr)

    def test_destroy_before_credentials_are_rekeyed(self):
        self.assertEqual(self.ceremony("migrate").returncode, 0)
        result = self.ceremony("destroy-legacy-key", "--confirm",
                               "destroy the legacy key for justikey.db")
        self.assertEqual(result.returncode, 1)
        self.assertIn("TOTP second factor", result.stderr)
        self.assertTrue(os.path.exists(self.db[:-3] + ".data-key"))

    def test_destroy_needs_the_exact_confirmation_phrase(self):
        self.assertEqual(self.ceremony("migrate").returncode, 0)
        for phrase in ("yes", "destroy", "destroy the legacy key", ""):
            result = self.ceremony("destroy-legacy-key", "--confirm", phrase)
            self.assertEqual(result.returncode, 1)
            self.assertTrue(os.path.exists(self.db[:-3] + ".data-key"))


@unittest.skipIf(SKIP, "sealing requires the cryptography package")
class TestTheWholeCeremonyRemote(CeremonyTest):
    """End to end against a real disclosure service, which is the only
    configuration where the ceremony can finish.

    Locally the application derives the blind-index key from the data key, so
    the last two steps have nowhere to go. With the service holding that key,
    rotating the application's key touches nothing the store depends on for
    lookup -- which is the whole reason the migration exists.
    """

    def setUp(self):
        super().setUp()
        import secrets
        import threading
        import urllib.request
        from http.server import ThreadingHTTPServer

        sys.path.insert(0, os.path.join(ROOT, "scripts"))
        import disclosure_server
        from justikey import approvals, db, disclosure

        self.private_hex, self.public_hex = sealing.generate_keypair()
        self.index_key = secrets.token_bytes(32)
        self.secret = secrets.token_hex(32)

        # Enrol the approver whose signature the sample check needs.
        conn = db.get_connection(self.db)
        try:
            approver = models.get_user_by_username(conn, "supervisor1")
            public, wrapped, salt = approvals.generate_signing_key("pw")
            models.set_signing_key(conn, approver["id"], public, wrapped, salt)
        finally:
            conn.close()

        ledger = os.path.join(self.dir, "disclosure-audit.db")
        lconn = db.get_connection(ledger)
        try:
            lconn.executescript(disclosure_server.LEDGER_SCHEMA)
        finally:
            lconn.close()

        usage = disclosure.UsageStore(ledger)
        self.saved_state = dict(disclosure_server.STATE)
        disclosure_server.STATE.update({
            "ledger": ledger, "client_secret": self.secret, "index_limit": 0,
            "usage": usage,
            "service": disclosure.DisclosureService(
                sealing.RecordOpener(self.private_hex), self.index_key,
                {"supervisor1": {"public_key": public, "revoked": False}},
                usage=usage, max_disclosures=0),
        })
        self.module = disclosure_server
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), disclosure_server.Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        self.remote_env = {
            "JUSTIKEY_DISCLOSURE_URL": f"http://127.0.0.1:{self.port}",
            "JUSTIKEY_DISCLOSURE_CLIENT_ID": "app",
            "JUSTIKEY_DISCLOSURE_CLIENT_SECRET": self.secret,
            "JUSTIKEY_DISCLOSURE_PUBLIC_KEY": self.public_hex,
            "JUSTIKEY_CEREMONY_PASSWORD": "pw",
        }

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.module.STATE.clear()
        self.module.STATE.update(self.saved_state)
        super().tearDown()

    def remote(self, *args):
        return self.ceremony(*args, env=self.remote_env)

    def test_the_sample_check_needs_an_enrolled_approver(self):
        """A remote service keeps its own registry, so a throwaway key is no use."""
        result = self.remote("migrate")
        self.assertEqual(result.returncode, 1)
        self.assertIn("--approver", result.stderr)
        self.assertEqual(crypto_store.MODE_V1, self.mode())

    def mode(self):
        from justikey import db
        conn = db.get_connection(self.db)
        try:
            return crypto_store.encryption_mode(conn)
        finally:
            conn.close()

    def test_all_four_steps(self):
        migrate = self.remote("migrate", "--approver", "supervisor1")
        self.assertEqual(migrate.returncode, 0, migrate.stderr)
        self.assertIn("5/5", migrate.stdout)
        self.assertEqual(self.mode(), crypto_store.MODE_V3)

        self.assertEqual(self.remote("verify").returncode, 0)

        rekey = self.remote("rekey-credentials")
        self.assertEqual(rekey.returncode, 0, rekey.stderr)
        retired = self.db[:-3] + ".data-key.legacy"
        self.assertTrue(os.path.exists(retired))

        destroy = self.remote("destroy-legacy-key", "--confirm",
                              "destroy the legacy key for justikey.db")
        self.assertEqual(destroy.returncode, 0, destroy.stderr)
        self.assertFalse(os.path.exists(retired))

        stages = self.stages()
        self.assertEqual(set(stages), {"migrate", "verify", "rekey-credentials",
                                       "destroy-legacy-key"})
        self.assertEqual(stages["destroy-legacy-key"]["destroyed_key_fingerprint"],
                         stages["rekey-credentials"]["legacy_key_fingerprint"])

    def test_the_store_still_works_afterwards(self):
        """The check that matters: migrated records still disclose, credentials
        still open, and new observations still land."""
        import helpers
        from justikey import audit, db, policy

        self.assertEqual(self.remote("migrate", "--approver", "supervisor1").returncode, 0)
        self.assertEqual(self.remote("rekey-credentials").returncode, 0)
        self.assertEqual(self.remote("destroy-legacy-key", "--confirm",
                                     "destroy the legacy key for justikey.db").returncode, 0)

        for key, value in self.remote_env.items():
            os.environ[key] = value
        self.addCleanup(lambda: [os.environ.pop(k, None) for k in self.remote_env])
        # config is read at import time, so point this process at the service.
        config.DISCLOSURE_URL = self.remote_env["JUSTIKEY_DISCLOSURE_URL"]
        config.DISCLOSURE_CLIENT_ID = "app"
        config.DISCLOSURE_CLIENT_SECRET = self.secret
        config.DISCLOSURE_PUBLIC_KEY = self.public_hex
        self.addCleanup(self._restore_config)

        conn = db.get_connection(self.db)
        try:
            requester = models.get_user_by_username(conn, "officer1")
            approver = models.get_user_by_username(conn, "supervisor1")

            # Credentials survived the key rotation.
            self.assertTrue(models.totp_secret_for(conn, requester))
            source = models.get_source_by_key(conn, "cam-b")
            self.assertEqual(models.signing_secrets_for(conn, source), [self.sensor_secret])

            # A record migrated by the ceremony still discloses.
            now = timeutil.now()
            auth_id = models.create_authorization(
                conn, "CASE-9", "Warrant 9", "Investigation", "ABC007",
                timeutil.to_canonical(now - timedelta(days=30)),
                timeutil.to_canonical(now), requester["id"])
            helpers.approve_signed(conn, auth_id, approver["id"], password="pw")
            allowed, reason, events = policy.evaluate_disclosure(
                conn, auth_id, "ABC007", requester)
            self.assertTrue(allowed, reason)
            self.assertEqual([e["plate"] for e in events], ["ABC007"])

            # And new observations still land and open.
            models.insert_event(conn, "NEW123", timeutil.to_canonical(now - timedelta(minutes=5)),
                                "CAM-1", 0.99, "New Depot", "claimed")
            new_id = models.create_authorization(
                conn, "CASE-10", "Warrant 10", "Investigation", "NEW123",
                timeutil.to_canonical(now - timedelta(days=1)),
                timeutil.to_canonical(now), requester["id"])
            helpers.approve_signed(conn, new_id, approver["id"], password="pw")
            allowed, reason, events = policy.evaluate_disclosure(
                conn, new_id, "NEW123", requester)
            self.assertTrue(allowed, reason)
            self.assertEqual([e["plate"] for e in events], ["NEW123"])

            self.assertTrue(audit.verify_chain(conn)[0])
        finally:
            conn.close()

    def _restore_config(self):
        config.DISCLOSURE_URL = ""
        config.DISCLOSURE_CLIENT_SECRET = ""
        config.DISCLOSURE_PUBLIC_KEY = ""


if __name__ == "__main__":
    unittest.main()
