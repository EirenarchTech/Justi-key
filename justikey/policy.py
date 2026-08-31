"""Policy enforcement engine for disclosing protected LPR records.

An authorization does not unlock the database. Every disclosure request
is re-checked against all required conditions at the moment of the
request: ownership, approval state, expiration, exact target-plate match,
and the authorized date/time window. If any condition fails, disclosure
is denied and the reason is returned so the caller can audit it.
"""
from . import models, timeutil

DENIAL_MESSAGES = {
    "authorization_not_found": "No such authorization exists.",
    "authorization_not_owned_by_requester": "This authorization does not belong to you.",
    "authorization_not_approved": "This authorization has not been independently approved.",
    "authorization_expired": "This authorization's approval window has expired. Create a new request.",
    "plate_mismatch": "The searched plate does not match the plate authorized in this request.",
}


def evaluate_disclosure(conn, auth_id, requested_plate, actor_user):
    """Return (allowed: bool, reason: str|None, events: list)."""
    auth_row = models.get_authorization(conn, auth_id)
    if auth_row is None:
        return False, "authorization_not_found", []

    if auth_row["requested_by"] != actor_user["id"]:
        return False, "authorization_not_owned_by_requester", []

    if auth_row["status"] != "approved":
        return False, "authorization_not_approved", []

    if not auth_row["approval_expires_at"] or auth_row["approval_expires_at"] <= timeutil.now_iso():
        return False, "authorization_expired", []

    if requested_plate.strip().upper() != auth_row["target_plate"]:
        return False, "plate_mismatch", []

    events = models.search_events(
        conn, auth_row["target_plate"], auth_row["window_start"], auth_row["window_end"]
    )
    return True, None, events
