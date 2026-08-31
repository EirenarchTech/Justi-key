import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from justikey import crypto_utils


class TestTotp(unittest.TestCase):
    def test_generated_code_verifies(self):
        secret = crypto_utils.generate_totp_secret()
        code = crypto_utils.totp_now(secret, t=1000000)
        self.assertTrue(crypto_utils.verify_totp(secret, code, t=1000000))

    def test_wrong_code_rejected(self):
        secret = crypto_utils.generate_totp_secret()
        other = crypto_utils.generate_totp_secret()
        code = crypto_utils.totp_now(other, t=1000000)
        self.assertFalse(crypto_utils.verify_totp(secret, code, t=1000000))

    def test_code_outside_window_rejected(self):
        secret = crypto_utils.generate_totp_secret()
        code = crypto_utils.totp_now(secret, t=1000000)
        # Two steps (60s) later, well outside the +-1 step window.
        self.assertFalse(crypto_utils.verify_totp(secret, code, t=1000000 + 90))

    def test_password_hash_roundtrip(self):
        h, salt = crypto_utils.hash_password("correct horse battery staple")
        self.assertTrue(crypto_utils.verify_password("correct horse battery staple", salt, h))
        self.assertFalse(crypto_utils.verify_password("wrong password", salt, h))


if __name__ == "__main__":
    unittest.main()
