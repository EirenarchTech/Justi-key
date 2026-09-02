"""Shared test helpers."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from justikey import approvals, models  # noqa: E402


def approve_signed(conn, auth_id, approver_id, password="pw"):
    """Approve the way the application does: with the approver's signature.

    Tests that go on to exercise disclosure must approve through this path,
    because an unsigned approval is refused by the policy engine.
    """
    approver = models.get_user_by_id(conn, approver_id)
    if not approver["signing_pub"]:
        public_hex, wrapped, salt = approvals.generate_signing_key(password)
        models.set_signing_key(conn, approver_id, public_hex, wrapped, salt)
        approver = models.get_user_by_id(conn, approver_id)
    key = approvals.unwrap_signing_key(approver, password)
    return models.approve_authorization(conn, auth_id, approver_id, signing_key=key)
