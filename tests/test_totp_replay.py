import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from justikey import crypto_utils, db, models


class TestTotpReplayPrevention(unittest.TestCase):
    def setUp(self):
        self.conn = db.get_connection(":memory:")
        self.conn.executescript(db.SCHEMA)
        self.secret = crypto_utils.generate_totp_secret()
        uid = models.create_user(self.conn, "supervisor1", "pw", "approver", totp_secret=self.secret)
        self.user = models.get_user_by_id(self.conn, uid)

    def tearDown(self):
        self.conn.close()

    def test_a_code_cannot_be_used_twice_for_the_same_purpose(self):
        code = crypto_utils.totp_now(self.secret)
        self.assertTrue(models.consume_totp(self.conn, self.user, code, "approval"))
        self.assertFalse(
            models.consume_totp(self.conn, self.user, code, "approval"),
            "one code approved two separate requests",
        )

    def test_purposes_are_tracked_independently(self):
        code = crypto_utils.totp_now(self.secret)
        self.assertTrue(models.consume_totp(self.conn, self.user, code, "login"))
        self.assertTrue(models.consume_totp(self.conn, self.user, code, "approval"))

    def test_invalid_code_is_rejected_and_consumes_nothing(self):
        self.assertFalse(models.consume_totp(self.conn, self.user, "000000", "approval"))
        spent = self.conn.execute("SELECT COUNT(*) c FROM used_totp").fetchone()["c"]
        self.assertEqual(spent, 0)

    def test_one_users_code_does_not_block_another_user(self):
        other_secret = crypto_utils.generate_totp_secret()
        other_id = models.create_user(self.conn, "supervisor2", "pw", "approver", totp_secret=other_secret)
        other = models.get_user_by_id(self.conn, other_id)
        self.assertTrue(models.consume_totp(self.conn, self.user, crypto_utils.totp_now(self.secret), "approval"))
        self.assertTrue(models.consume_totp(self.conn, other, crypto_utils.totp_now(other_secret), "approval"))

    def test_match_totp_counter_reports_the_step_used(self):
        t = 1_000_000
        code = crypto_utils.totp_now(self.secret, t=t)
        self.assertEqual(crypto_utils.match_totp_counter(self.secret, code, t=t), t // 30)
        self.assertIsNone(crypto_utils.match_totp_counter(self.secret, "not-a-code", t=t))


if __name__ == "__main__":
    unittest.main()
