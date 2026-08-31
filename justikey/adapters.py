"""Payload adapters: translating other ALPR systems into one observation shape.

JustiKey's privacy architecture is deliberately indifferent to who made the
camera, which only holds if every upstream format is reduced to a single
canonical observation at the trust boundary. That is this module's whole job.

An adapter takes one vendor payload and returns the canonical form:

    plate         normalized registration string
    captured_at   canonical UTC timestamp (see timeutil)
    camera_id     the device that made the observation
    confidence    recognition confidence, 0.0-1.0
    location      human-readable place label, optional
    source_label  the vendor's own name for the feed, optional

Two rules hold for every adapter:

1. **Adapters translate; they do not authorize.** The source an observation
   is attributed to comes from the credential it authenticated with, never
   from anything in the payload. A vendor field naming a feed is recorded as
   `source_label` -- a claim, kept for troubleshooting, never an identity.

2. **Adapters normalize time.** Vendors emit epoch millis, epoch seconds,
   RFC 3339 with a "Z", local time with an offset. All of it becomes one
   fixed-width UTC form, because a stored timestamp is later range-compared
   as text when an authorized search runs.

ADDING A VENDOR: the adapters below are reference implementations of the two
payload shapes that dominate in practice. They are *patterns*, not certified
vendor integrations -- a real one needs that vendor's specification and
captured sample payloads, and should ship with fixtures of those samples in
the test suite. Register a new adapter with @adapter("name") and set a
source's `adapter` column to it.
"""
from datetime import datetime, timezone

from . import timeutil

MAX_PLATE_LEN = 16
MAX_FIELD_LEN = 128

_REGISTRY = {}


class AdapterError(ValueError):
    """A payload could not be translated into a canonical observation."""


def adapter(name):
    def deco(fn):
        _REGISTRY[name] = fn
        return fn
    return deco


def available():
    return sorted(_REGISTRY)


def normalize(name, payload):
    """Translate a vendor payload, then validate the canonical result."""
    fn = _REGISTRY.get(name)
    if fn is None:
        raise AdapterError(f"unknown adapter {name!r}; available: {', '.join(available())}")
    if not isinstance(payload, dict):
        raise AdapterError("payload must be a JSON object")
    return _validate(fn(payload))


# ---------------------------------------------------------------------------
# Shared coercion helpers
# ---------------------------------------------------------------------------

def _first(payload, *names, default=None):
    """Return the first present, non-empty value among several field names."""
    for name in names:
        if name in payload and payload[name] not in (None, ""):
            return payload[name]
    return default


def _text(value, limit=MAX_FIELD_LEN, default=None):
    if value is None:
        return default
    text = str(value).strip()
    return text[:limit] if text else default


def _confidence(value, default=0.9):
    """Accept 0.0-1.0 or a 0-100 percentage; reject anything else."""
    if value is None:
        return default
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise AdapterError(f"confidence {value!r} is not numeric")
    if number > 1.0:
        # Vendors commonly report percentages. Above 100 is not a percentage.
        if number > 100.0:
            raise AdapterError(f"confidence {value!r} is out of range")
        number /= 100.0
    if number < 0.0:
        raise AdapterError(f"confidence {value!r} is out of range")
    return number


def _timestamp(value):
    """Accept epoch seconds, epoch millis, or any ISO-8601 flavor."""
    if value in (None, ""):
        return timeutil.now_iso()
    if isinstance(value, bool):
        raise AdapterError("timestamp must not be a boolean")
    if isinstance(value, (int, float)):
        seconds = float(value)
        # Values this large are milliseconds: 10^11 seconds is year 5138,
        # while 10^11 ms is 1973, so the boundary is unambiguous in practice.
        if seconds > 1e11:
            seconds /= 1000.0
        try:
            return timeutil.to_canonical(datetime.fromtimestamp(seconds, timezone.utc))
        except (OverflowError, OSError, ValueError):
            raise AdapterError(f"timestamp {value!r} is out of range")
    try:
        return timeutil.parse(str(value))
    except ValueError:
        raise AdapterError(f"timestamp {value!r} is not a recognizable date/time")


def _validate(obs):
    plate = _text(obs.get("plate"), MAX_PLATE_LEN)
    if not plate:
        raise AdapterError("payload contains no plate")
    plate = plate.upper()
    if len(str(obs.get("plate", "")).strip()) > MAX_PLATE_LEN:
        raise AdapterError(f"plate exceeds {MAX_PLATE_LEN} characters")
    return {
        "plate": plate,
        "captured_at": obs["captured_at"],
        "camera_id": _text(obs.get("camera_id"), default="unknown-camera"),
        "confidence": obs["confidence"],
        "location": _text(obs.get("location")),
        "source_label": _text(obs.get("source_label")),
    }


# ---------------------------------------------------------------------------
# Adapters
# ---------------------------------------------------------------------------

@adapter("justikey")
def _justikey(payload):
    """JustiKey's own observation format, as the simulator and edge agent emit."""
    return {
        "plate": payload.get("plate"),
        "captured_at": _timestamp(payload.get("captured_at")),
        "camera_id": payload.get("camera_id"),
        "confidence": _confidence(payload.get("confidence")),
        "location": payload.get("location"),
        "source_label": payload.get("source_id"),
    }


@adapter("flat_epoch_v1")
def _flat_epoch(payload):
    """Flat fields with an epoch timestamp and a 0-100 score.

    Reference pattern for the many fixed-site systems that post a single flat
    record per read. Field names vary between vendors, so several common
    spellings are accepted rather than one guessed spelling.
    """
    return {
        "plate": _first(payload, "plate_number", "plateNumber", "plate", "registration"),
        "captured_at": _timestamp(_first(payload, "timestamp_ms", "timestampMs",
                                         "timestamp", "epoch", "time")),
        "camera_id": _first(payload, "camera", "camera_id", "device_id", "deviceId"),
        "confidence": _confidence(_first(payload, "score", "confidence", "match_score")),
        "location": _first(payload, "site", "location", "lane", "site_name"),
        "source_label": _first(payload, "feed", "source", "source_id"),
    }


@adapter("nested_results_v1")
def _nested_results(payload):
    """Recognizer output carrying ranked candidates in a `results` array.

    Reference pattern for engine-style output (an OpenALPR/Rekor-shaped
    response). The highest-confidence candidate wins; the rest are discarded
    rather than stored, since keeping rejected guesses about a vehicle would
    widen the protected record for no investigative benefit.
    """
    results = payload.get("results") or payload.get("candidates")
    if not isinstance(results, list) or not results:
        raise AdapterError("payload contains no results array")
    best = max(
        (r for r in results if isinstance(r, dict)),
        key=lambda r: _confidence(r.get("confidence"), default=0.0),
        default=None,
    )
    if best is None:
        raise AdapterError("results array contains no usable candidate")
    return {
        "plate": _first(best, "plate", "plate_number", "text"),
        "captured_at": _timestamp(_first(payload, "epoch_time", "epochTime",
                                         "timestamp", "captured_at")),
        "camera_id": _first(payload, "camera_id", "cameraId", "camera", "agent_uid"),
        "confidence": _confidence(best.get("confidence")),
        "location": _first(payload, "site", "location", "camera_label"),
        "source_label": _first(payload, "agent_uid", "source", "source_id"),
    }
