"""WebAuthn assertion verification and the custody layer (stage 4).

Tested against a synthetic authenticator (tests/authenticator.py) that
produces byte-exact assertions: real COSE keys, real authenticatorData, real
signatures over authData || SHA-256(clientDataJSON). Most of these assert a
refusal, because a verifier that accepts a valid assertion but also accepts
one for another origin, another challenge, or another site is worse than no
verifier -- it reports a guarantee it does not provide.
"""
import hashlib
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from justikey import custody, webauthn  # noqa: E402

SKIP = not webauthn.WEBAUTHN_AVAILABLE
if not SKIP:
    from authenticator import Authenticator  # noqa: E402

RP_ID = "justikey.example"
ORIGIN = "https://justikey.example"
MESSAGE = b'{"case":"CASE-1","plate":"SECRET99"}'


@unittest.skipIf(SKIP, "WebAuthn verification requires the cryptography package")
class WebAuthnTest(unittest.TestCase):
    def setUp(self):
        self.token = Authenticator(rp_id=RP_ID, origin=ORIGIN)
        self.credential = self.token.credential()
        self.challenge = webauthn.challenge_for(MESSAGE)

    def verify(self, assertion, challenge=None, **kwargs):
        return webauthn.verify_assertion(
            self.credential, assertion, challenge or self.challenge, RP_ID, ORIGIN, **kwargs)


class TestAcceptance(WebAuthnTest):
    def test_es256_assertion_verifies(self):
        self.assertEqual(self.verify(self.token.assert_challenge(self.challenge)), 1)

    def test_ed25519_assertion_verifies(self):
        self.token = Authenticator(algorithm=webauthn.ALG_EDDSA, rp_id=RP_ID, origin=ORIGIN)
        self.credential = self.token.credential()
        self.assertEqual(self.verify(self.token.assert_challenge(self.challenge)), 1)

    def test_presence_alone_is_enough_when_we_do_not_require_verification(self):
        assertion = self.token.assert_challenge(self.challenge, user_verified=False)
        self.assertEqual(self.verify(assertion, require_user_verification=False), 1)

    def test_the_challenge_is_the_statement(self):
        """Two statements must never share a challenge, or an assertion for one
        would authorize the other."""
        self.assertNotEqual(webauthn.challenge_for(b"statement A"),
                            webauthn.challenge_for(b"statement B"))
        self.assertEqual(webauthn.challenge_for(MESSAGE), hashlib.sha256(MESSAGE).digest())


class TestRefusals(WebAuthnTest):
    def refuses(self, assertion, fragment, **kwargs):
        with self.assertRaises(webauthn.WebAuthnError) as caught:
            self.verify(assertion, **kwargs)
        self.assertIn(fragment, str(caught.exception))

    def test_an_assertion_for_another_statement(self):
        self.refuses(self.token.assert_challenge(webauthn.challenge_for(b"something else")),
                     "different challenge")

    def test_a_tampered_signature(self):
        self.refuses(self.token.assert_challenge(self.challenge, tamper_signature=True),
                     "does not verify")

    def test_an_assertion_produced_for_another_site(self):
        self.refuses(self.token.assert_challenge(self.challenge, origin="https://evil.example"),
                     "origin")

    def test_an_assertion_for_another_relying_party(self):
        self.refuses(self.token.assert_challenge(self.challenge, rp_id="evil.example"),
                     "different relying party")

    def test_an_absent_user(self):
        self.refuses(self.token.assert_challenge(self.challenge, user_present=False),
                     "present user")

    def test_presence_without_verification_when_we_require_it(self):
        self.refuses(self.token.assert_challenge(self.challenge, user_verified=False),
                     "user verification")

    def test_a_registration_ceremony_replayed_as_an_assertion(self):
        self.refuses(self.token.assert_challenge(self.challenge, ceremony="webauthn.create"),
                     "ceremony")

    def test_another_authenticator(self):
        other = Authenticator(rp_id=RP_ID, origin=ORIGIN)
        self.refuses(other.assert_challenge(self.challenge), "different credential")

    def test_a_counter_that_does_not_advance(self):
        """The documented cloned-authenticator signal, once the count is stored."""
        assertion = self.token.assert_challenge(self.challenge)
        self.credential["sign_count"] = self.verify(assertion)
        self.refuses(assertion, "cloned")

    def test_an_authenticator_that_never_counts_is_not_treated_as_cloned(self):
        token = Authenticator(rp_id=RP_ID, origin=ORIGIN, sign_count=0)
        self.credential = token.credential(sign_count=0)
        assertion = token.assert_challenge(self.challenge, sign_count=0)
        self.assertEqual(self.verify(assertion), 0)

    def test_a_missing_field(self):
        assertion = self.token.assert_challenge(self.challenge)
        for field in ("credential_id", "authenticator_data", "client_data_json", "signature"):
            broken = dict(assertion)
            broken[field] = ""
            with self.assertRaises(webauthn.WebAuthnError):
                self.verify(broken)


class TestUserPresenceIsNotOptional(WebAuthnTest):
    """UP has no off switch, at any layer, for any role.

    An assertion the authenticator produced with nobody touching it is not
    evidence a human did anything, so every claim built on top of it would be
    false. This is pinned as an invariant rather than left to a default.
    """

    def test_no_argument_relaxes_user_presence(self):
        absent = self.token.assert_challenge(self.challenge, user_present=False)
        for kwargs in ({}, {"require_user_verification": False},
                       {"require_user_verification": True}):
            with self.assertRaises(webauthn.WebAuthnError) as caught:
                self.verify(absent, **kwargs)
            self.assertIn("present user", str(caught.exception))

    def test_verify_assertion_has_no_user_presence_parameter(self):
        import inspect
        parameters = inspect.signature(webauthn.verify_assertion).parameters
        self.assertNotIn("require_user_presence", parameters)
        self.assertIn("require_user_verification", parameters)


class TestPerRoleUserVerification(unittest.TestCase):
    """Which roles must clear the stronger bar is a deployment decision."""

    def setUp(self):
        from justikey import config
        self.config = config
        self._saved = config.WEBAUTHN_REQUIRE_UV_ROLES
        self.addCleanup(setattr, config, "WEBAUTHN_REQUIRE_UV_ROLES", self._saved)

    def set_roles(self, value):
        self.config.WEBAUTHN_REQUIRE_UV_ROLES = tuple(
            part.strip().lower() for part in value.split(",") if part.strip())

    def test_all_requires_every_role(self):
        self.set_roles("all")
        for role in ("requester", "approver", "auditor"):
            self.assertTrue(self.config.require_user_verification(role))

    def test_none_requires_no_role(self):
        self.set_roles("none")
        self.assertFalse(self.config.require_user_verification("approver"))

    def test_a_named_role_is_required_and_others_are_not(self):
        self.set_roles("approver")
        self.assertTrue(self.config.require_user_verification("approver"))
        self.assertFalse(self.config.require_user_verification("requester"))

    def test_the_default_requires_every_role(self):
        """A weaker default would make the stronger claim the exception."""
        self.assertEqual(self._saved, ("all",))


@unittest.skipIf(SKIP, "WebAuthn verification requires the cryptography package")
class TestCoseDecoding(unittest.TestCase):
    def test_a_truncated_key(self):
        with self.assertRaises(webauthn.WebAuthnError):
            webauthn.decode_cose_key(b"\xa5\x01\x02\x03")

    def test_an_unsupported_algorithm(self):
        token = Authenticator()
        raw = bytearray(webauthn.b64url_decode(token.public_key))
        # 0x26 is -7 (ES256) in CBOR; 0x38 0x24 is -37 (PS256), which we do not accept.
        self.assertIn(b"\x03\x26", bytes(raw))
        raw = bytes(raw).replace(b"\x03\x26", b"\x03\x38\x24", 1)
        with self.assertRaises(webauthn.WebAuthnError) as caught:
            webauthn.decode_cose_key(raw)
        self.assertIn("unsupported COSE algorithm", str(caught.exception))

    def test_trailing_bytes_are_refused(self):
        token = Authenticator()
        raw = webauthn.b64url_decode(token.public_key)
        with self.assertRaises(webauthn.WebAuthnError):
            webauthn.decode_cose_key(raw + b"\x00")


@unittest.skipIf(SKIP, "custody requires the cryptography package")
class TestCustody(unittest.TestCase):
    """One proof format over two very different kinds of key."""

    def setUp(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        self.key = ed25519.Ed25519PrivateKey.generate()
        public_hex = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.software = custody.credential_from_registry({"public_key": public_hex})

        self.token = Authenticator(rp_id=RP_ID, origin=ORIGIN)
        self.hardware = custody.credential_from_registry({
            "public_key": public_hex,
            "webauthn": {"credential_id": self.token.credential_id,
                         "public_key": self.token.public_key, "sign_count": 0,
                         "rp_id": RP_ID, "origin": ORIGIN}})

    def hardware_proof(self, message=MESSAGE):
        return custody.webauthn_proof(
            self.token.assert_challenge(webauthn.challenge_for(message)))

    def test_a_software_proof_verifies(self):
        result = custody.verify_proof(self.software, MESSAGE, custody.sign(self.key, MESSAGE))
        self.assertEqual(result["custody"], "software")

    def test_a_hardware_proof_verifies_and_reports_its_counter(self):
        result = custody.verify_proof(self.hardware, MESSAGE, self.hardware_proof())
        self.assertEqual(result["custody"], "hardware")
        self.assertEqual(result["sign_count"], 1)

    def test_a_legacy_bare_hex_signature_still_verifies(self):
        """Approvals written before proof envelopes existed were validly made."""
        bare = custody.sign(self.key, MESSAGE)["sig"]
        self.assertEqual(custody.verify_proof(self.software, MESSAGE, bare)["custody"],
                         "software")

    def test_hardware_enrolment_refuses_a_software_signature(self):
        """The downgrade. Enrolling a security key must raise the bar, not add
        a second way in that the old password still opens."""
        with self.assertRaises(custody.CustodyError) as caught:
            custody.verify_proof(self.hardware, MESSAGE, custody.sign(self.key, MESSAGE))
        self.assertIn("hardware authenticator", str(caught.exception))

    def test_a_webauthn_proof_against_a_software_principal(self):
        with self.assertRaises(custody.CustodyError):
            custody.verify_proof(self.software, MESSAGE, self.hardware_proof())

    def test_a_proof_of_one_message_does_not_verify_another(self):
        for credential, proof in ((self.software, custody.sign(self.key, MESSAGE)),
                                  (self.hardware, self.hardware_proof())):
            with self.assertRaises(custody.CustodyError):
                custody.verify_proof(credential, b"a different statement", proof)

    def test_a_revoked_key_is_not_a_credential(self):
        with self.assertRaises(custody.CustodyError) as caught:
            custody.credential_from_registry({"public_key": "aa" * 32, "revoked": True})
        self.assertIn("revoked", str(caught.exception))

    def test_hardware_without_an_origin_cannot_be_checked(self):
        credential = custody.webauthn_credential(
            self.token.credential_id, self.token.public_key, 0, rp_id=None, origin=None)
        with self.assertRaises(custody.CustodyError) as caught:
            custody.verify_proof(credential, MESSAGE, self.hardware_proof())
        self.assertIn("origin", str(caught.exception))

    def test_key_ids_distinguish_custody(self):
        self.assertNotEqual(custody.credential_key_id(self.software),
                            custody.credential_key_id(self.hardware))

    def test_an_unknown_algorithm_is_refused(self):
        with self.assertRaises(custody.CustodyError):
            custody.verify_proof(self.software, MESSAGE, {"alg": "rsa-pkcs1", "sig": "00"})

    def test_proofs_round_trip_through_storage(self):
        proof = self.hardware_proof()
        restored = custody.decode_proof(custody.encode_proof(proof))
        self.assertEqual(restored, proof)
        self.assertEqual(custody.verify_proof(self.hardware, MESSAGE, restored)["custody"],
                         "hardware")


if __name__ == "__main__":
    unittest.main()
