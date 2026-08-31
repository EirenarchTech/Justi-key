"""Policy enforcement engine for disclosing protected LPR records.

An authorization does not unlock the database. Every disclosure request
is re-checked against all required conditions at the moment of the
request: ownership, approval state, expiration, exact target-plate match,
and the authorized date/time window. If any condition fails, disclosure
is denied and the reason is returned so the caller can audit it.
"""
from . import config, models, timeutil

DENIAL_MESSAGES = {
    "authorization_not_found": "No such authorization exists.",
    "authorization_not_owned_by_requester": "This authorization does not belong to you.",
    "authorization_not_approved": "This authorization has not been independently approved.",
    "authorization_expired": "This authorization's approval window has expired. Create a new request.",
    "plate_mismatch": "The searched plate does not match the plate authorized in this request.",
    "window_too_broad": "This authorization's time window exceeds the permitted maximum.",
    "disclosure_limit_reached": "This authorization has reached its disclosure limit and must be "
                                "re-approved.",
}


def window_days(window_start, window_end):
    return (timeutil.parse_dt(window_end) - timeutil.parse_dt(window_start)).total_seconds() / 86400.0


def check_window_breadth(window_start, window_end, max_days=None):
    """Reject a time window wider than policy permits.

    'Not unnecessarily broad' is listed as something the approver should
    judge, but leaving it entirely to human judgement is exactly the
    policy-not-architecture gap this system exists to close. A request
    spanning years is refused before anyone can approve it.
    """
    max_days = config.MAX_WINDOW_DAYS if max_days is None else max_days
    if max_days <= 0:
        return True, None
    return (window_days(window_start, window_end) <= max_days), max_days


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

    # Re-check breadth at disclosure time, not only at creation. A limit that
    # is only applied when a request is written could be bypassed by any path
    # that edits an authorization afterwards, and by rows created before the
    # limit existed.
    within_limit, _ = check_window_breadth(auth_row["window_start"], auth_row["window_end"])
    if not within_limit:
        return False, "window_too_broad", []

    limit = config.MAX_DISCLOSURES_PER_AUTHORIZATION
    if limit > 0 and auth_row["disclosure_count"] >= limit:
        return False, "disclosure_limit_reached", []

    events = models.search_events(
        conn, auth_row["target_plate"], auth_row["window_start"], auth_row["window_end"]
    )
    return True, None, events
