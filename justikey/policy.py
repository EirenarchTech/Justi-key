"""Policy enforcement engine for disclosing protected LPR records.

An authorization does not unlock the database. Every disclosure request
is re-checked against all required conditions at the moment of the
request: ownership, approval state, expiration, exact target-plate match,
and the authorized date/time window. If any condition fails, disclosure
is denied and the reason is returned so the caller can audit it.
"""
from . import approvals, config, disclosure, models, sealing, timeutil

DENIAL_MESSAGES = {
    "authorization_not_found": "No such authorization exists.",
    "authorization_not_owned_by_requester": "This authorization does not belong to you.",
    "authorization_not_approved": "This authorization has not been independently approved.",
    "authorization_expired": "This authorization's approval window has expired. Create a new request.",
    "plate_mismatch": "The searched plate does not match the plate authorized in this request.",
    "window_too_broad": "This authorization's time window exceeds the permitted maximum.",
    "disclosure_limit_reached": "This authorization has reached its disclosure limit and must be "
                                "re-approved.",
    "approval_signature_invalid": "This authorization's approval signature does not match its "
                                  "current contents. It may have been altered after approval.",
    "disclosure_refused": "The disclosure service refused to release these records. The "
                          "approval could not be verified against the request.",
    "disclosure_unavailable": "The disclosure service is unavailable, so these records cannot "
                              "be opened. Records stay sealed; no partial disclosure occurs.",
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

    # The approver signed the exact scope. Rebuilding that statement from the
    # row and checking it catches any post-approval edit -- widening the
    # window, or swapping the target plate onto a real approver's name.
    signed_ok, signature_reason = approvals.verify_authorization(conn, auth_row)
    if not signed_ok:
        # A missing signature and a wrong one are different failures. A wrong
        # signature means the row was altered and is always refused; a missing
        # one means the approval predates signing, which a deployment may
        # deliberately tolerate while it migrates.
        unsigned = signature_reason == "approval carries no signature"
        if not unsigned or config.REQUIRE_SIGNED_APPROVALS:
            return False, "approval_signature_invalid", []

    limit = config.MAX_DISCLOSURES_PER_AUTHORIZATION
    if limit > 0 and auth_row["disclosure_count"] >= limit:
        return False, "disclosure_limit_reached", []

    candidates = models.search_events(
        conn, auth_row["target_plate"], auth_row["window_start"], auth_row["window_end"]
    )

    try:
        service = disclosure.service_for(conn, conn.db_path or "")
    except disclosure.DisclosureError:
        # The key holder being unreachable is an expected operating state, not
        # a fault: once the service is a separate process it can be down or
        # unreachable. Deny cleanly and audibly rather than erroring out, and
        # never fall back to a path that would open records without it.
        return False, "disclosure_unavailable", []
    if service is None:
        return True, None, candidates      # v1: already revealed

    # v2: this process cannot open a sealed record. The disclosure service
    # holds the key, and it re-derives scope from the approver's signed
    # statement rather than trusting the selection made above.
    approver = models.get_user_by_id(conn, auth_row["approved_by"])
    statement = approvals.build_statement(
        auth_row, actor_user["username"], approver["username"],
        auth_row["approved_at"], auth_row["approval_expires_at"],
        approver_key_id=sealing.key_id(approver["signing_pub"]))
    try:
        opened = service.disclose(candidates, statement, auth_row["approval_signature"],
                                  actor_user["username"])
    except (disclosure.DisclosureError, sealing.SealingError):
        return False, "disclosure_refused", []

    by_id = {item["id"]: item for item in opened}
    events = []
    for row in candidates:
        fields = by_id.get(row["id"])
        if fields is None:
            continue
        event = dict(row)
        event["plate"] = fields.get("plate")
        event["location"] = fields.get("location")
        events.append(event)
    return True, None, events
