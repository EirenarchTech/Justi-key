"""Canonical UTC timestamp handling.

Timestamps are stored as TEXT and compared lexicographically by SQLite, so
every timestamp JustiKey persists is first normalized to one fixed-width
UTC representation:

    YYYY-MM-DDTHH:MM:SS.ffffff+00:00     (always 32 characters)

This matters because the ingest API is deliberately camera-independent and
accepts whatever ISO-8601 flavor a vendor emits. Without normalization,
`datetime.isoformat()` drops the microseconds when they happen to be zero,
an RFC 3339 "Z" suffix sorts after "+00:00", and a naive timestamp sorts
before both. Any of those makes a TEXT comparison disagree with real
chronology, which would silently include or exclude observations at the
edges of an authorized time window -- returning incomplete results to an
investigator holding a valid warrant, with no indication anything was
missed.
"""
from datetime import datetime, timezone

CANONICAL_LENGTH = 32


def now():
    """Current time as an aware UTC datetime."""
    return datetime.now(timezone.utc)


def to_canonical(dt):
    """Render an aware or naive datetime as a canonical UTC string.

    A naive datetime is interpreted as already being UTC.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return "%04d-%02d-%02dT%02d:%02d:%02d.%06d+00:00" % (
        dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, dt.microsecond,
    )


def now_iso():
    """Current time as a canonical UTC string."""
    return to_canonical(now())


def parse_dt(value):
    """Parse an ISO-8601-ish string into an aware UTC datetime."""
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    text = value.strip()
    if not text:
        raise ValueError("timestamp must not be empty")
    if text[-1] in ("Z", "z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse(value):
    """Parse an ISO-8601-ish string into a canonical UTC string.

    Accepts the forms JustiKey actually receives: an RFC 3339 "Z" suffix,
    an explicit numeric offset, a space instead of "T", and the naive
    "YYYY-MM-DDTHH:MM" that HTML datetime-local inputs submit. A value
    carrying no offset is interpreted as UTC. Raises ValueError on
    anything it cannot parse.
    """
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    text = value.strip()
    if not text:
        raise ValueError("timestamp must not be empty")
    return to_canonical(parse_dt(text))
