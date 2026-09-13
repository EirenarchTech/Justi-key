"""Requester proof-of-presence at disclosure.

Stage 4 of docs/capability-model.md, and the direct answer to
docs/threat-model.md finding 5.

THE HOLE THIS CLOSES

Through stage 3, an approval is a bearer capability. The disclosure service
checks that the approval is genuine, unexpired, in scope, and not past its
count -- and all of that is true of a request a compromised application sends
on its own, using an approval it lifted from its own database and the string
`requester="officer1"`. The service has no evidence officer1 is anywhere
near a keyboard. Within the approval's window, scope and remaining count, a
compromised application can act in an officer's name.

The bounds were real. The absence of the officer was too.

WHAT REPLACES IT

The requester signs each disclosure at the moment they ask for it. Not the
authorization -- that was the approver's signature, made earlier -- but
*this* request: which approval is being spent, over exactly which signed
scope, by whom, once, now.

    {"v", "approval_nonce", "statement_digest", "requester",
     "requester_key_id", "request_nonce", "issued_at", "expires_at"}

Every field is load-bearing. `approval_nonce` and `statement_digest` bind the
proof to one specific approval and to the exact scope the approver signed, so
a proof cannot be moved onto a different approval or onto an approval whose
row was edited afterwards. `requester` must match the signed statement, so a
present officer cannot be used to spend somebody else's approval.
`request_nonce` is spent once by the service. `issued_at`/`expires_at` keep
the proof usable for seconds rather than for the approval's whole lifetime --
a captured proof is worth one disclosure inside a short window, not the
authorization.

WHAT IT DOES NOT CLOSE

With a software key, the requester's private key is unwrapped with their
password, in this process, at request time. A compromised application
observes that moment and can mint further proofs while it holds the
unwrapped key. So the honest claim is the same shape as stage 1's: the
attacker's window narrows from *the approval's whole validity period* to
*moments when the requester is actually present and working*, and it stops
the instant they stop.

With a hardware authenticator (justikey/custody.py) the claim gets stronger,
because nothing in this process ever holds the key: the attacker can obtain
proofs only for challenges a present human physically confirms, one touch at
a time, and none afterwards.
"""
import hashlib
import json
import secrets

from . import approvals, config, custody, timeutil

PRESENCE_VERSION = 1

REQUIRED_FIELDS = ("approval_nonce", "statement_digest", "requester",
                   "requester_key_id", "request_nonce", "issued_at", "expires_at")


class PresenceError(RuntimeError):
    """A proof of presence was absent, stale, or did not bind to this request."""


def canonical(proof_statement):
    return json.dumps(proof_statement, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def statement_digest(statement):
    """Digest of the approver's signed statement, exactly as signed.

    Binding to the digest rather than to a few copied fields means there is
    no subset of the approval a proof could be silently detached from.
    """
    return hashlib.sha256(approvals.canonical(statement)).hexdigest()


def build(statement, requester_key_id, ttl_seconds=None, issued_at=None):
    """The thing a requester signs to show they are here, now, for this."""
    from datetime import timedelta
    ttl = config.PRESENCE_TTL_SECONDS if ttl_seconds is None else ttl_seconds
    issued = timeutil.now() if issued_at is None else timeutil.parse_dt(issued_at)
    return {
        "v": PRESENCE_VERSION,
        "approval_nonce": statement["nonce"],
        "statement_digest": statement_digest(statement),
        "requester": statement["requester"],
        "requester_key_id": requester_key_id,
        "request_nonce": secrets.token_hex(16),
        "issued_at": timeutil.to_canonical(issued),
        "expires_at": timeutil.to_canonical(issued + timedelta(seconds=ttl)),
    }


def sign(private_key, proof_statement):
    """Software path. A hardware authenticator produces the proof itself."""
    return custody.sign(private_key, canonical(proof_statement))


def verify(credential, proof_statement, proof, statement, requester,
           max_ttl_seconds=None, require_user_verification=True):
    """Check a proof of presence against the approval it claims to spend.

    Returns what was proved, including whether the key was in hardware.
    Raises PresenceError on anything less than a complete match: there is no
    partial presence.
    """
    if not isinstance(proof_statement, dict):
        raise PresenceError("malformed proof of presence")
    if proof_statement.get("v") != PRESENCE_VERSION:
        raise PresenceError(
            f"unsupported proof-of-presence schema {proof_statement.get('v')!r}")
    for field in REQUIRED_FIELDS:
        if not proof_statement.get(field):
            raise PresenceError(f"proof of presence is missing {field}")

    # Bind to this approval, this scope, this person.
    if proof_statement["approval_nonce"] != statement.get("nonce"):
        raise PresenceError("this proof of presence was made for a different approval")
    if proof_statement["statement_digest"] != statement_digest(statement):
        raise PresenceError(
            "this proof of presence covers a different scope than the approval "
            "being spent; the authorization may have been altered after it was signed")
    if proof_statement["requester"] != statement.get("requester"):
        raise PresenceError(
            "the proof of presence names a different person than the approval does")
    if proof_statement["requester"] != requester:
        raise PresenceError("this proof of presence belongs to another requester")

    expected_key_id = custody.credential_key_id(credential)
    if proof_statement["requester_key_id"] != expected_key_id:
        raise PresenceError(
            "the proof names a different signing key than the one enrolled for "
            "this requester")

    # Freshness. Checked before the signature so a stale proof costs nothing,
    # and the TTL is capped here rather than trusted: a caller who could set
    # its own expiry would simply issue one good for a year.
    now = timeutil.now_iso()
    if proof_statement["issued_at"] > now:
        raise PresenceError("the proof of presence is dated in the future")
    if proof_statement["expires_at"] <= now:
        raise PresenceError(
            "the proof of presence has expired; the requester must confirm again")
    maximum = config.PRESENCE_MAX_TTL_SECONDS if max_ttl_seconds is None else max_ttl_seconds
    lifetime = (timeutil.parse_dt(proof_statement["expires_at"])
                - timeutil.parse_dt(proof_statement["issued_at"])).total_seconds()
    if lifetime > maximum:
        raise PresenceError(
            f"the proof of presence claims a {int(lifetime)}s lifetime; the maximum "
            f"is {maximum}s")

    try:
        result = custody.verify_proof(
            credential, canonical(proof_statement), proof,
            require_user_verification=require_user_verification)
    except custody.CustodyError as exc:
        raise PresenceError(str(exc)) from exc

    return dict(result, requester=proof_statement["requester"],
                request_nonce=proof_statement["request_nonce"])
