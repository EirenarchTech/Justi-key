"""Adapter translation from other ALPR systems into the canonical observation."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from justikey import adapters, timeutil  # noqa: E402

# 2026-08-31T12:00:00Z
EPOCH_SECONDS = 1788177600
EPOCH_MILLIS = EPOCH_SECONDS * 1000
EXPECTED = timeutil.parse("2026-08-31T12:00:00Z")


class TestCanonicalOutput(unittest.TestCase):
    def test_every_adapter_produces_the_same_canonical_shape(self):
        payloads = {
            "justikey": {"plate": "abc123", "captured_at": "2026-08-31T12:00:00Z",
                         "camera_id": "CAM-1", "confidence": 0.91, "location": "Gate",
                         "source_id": "feed-a"},
            "flat_epoch_v1": {"plate_number": "abc123", "timestamp_ms": EPOCH_MILLIS,
                              "camera": "CAM-1", "score": 91, "site": "Gate", "feed": "feed-a"},
            "nested_results_v1": {"results": [{"plate": "abc123", "confidence": 91}],
                                  "epoch_time": EPOCH_MILLIS, "camera_id": "CAM-1",
                                  "site": "Gate", "agent_uid": "feed-a"},
        }
        self.assertEqual(set(payloads), set(adapters.available()))
        results = [adapters.normalize(name, p) for name, p in payloads.items()]
        for obs in results:
            self.assertEqual(obs["plate"], "ABC123")
            self.assertEqual(obs["captured_at"], EXPECTED)
            self.assertEqual(obs["camera_id"], "CAM-1")
            self.assertAlmostEqual(obs["confidence"], 0.91, places=3)
            self.assertEqual(obs["location"], "Gate")
        self.assertEqual(len({obs["captured_at"] for obs in results}), 1,
                         "the same instant must normalize identically across vendors")

    def test_unknown_adapter_is_rejected(self):
        with self.assertRaises(adapters.AdapterError):
            adapters.normalize("no-such-vendor", {"plate": "ABC123"})

    def test_non_object_payload_is_rejected(self):
        with self.assertRaises(adapters.AdapterError):
            adapters.normalize("justikey", ["not", "an", "object"])


class TestConfidence(unittest.TestCase):
    def test_percentage_and_fraction_both_normalize(self):
        frac = adapters.normalize("justikey", {"plate": "A1", "confidence": 0.85})
        pct = adapters.normalize("flat_epoch_v1", {"plate_number": "A1", "score": 85})
        self.assertAlmostEqual(frac["confidence"], 0.85, places=3)
        self.assertAlmostEqual(pct["confidence"], 0.85, places=3)

    def test_out_of_range_confidence_is_rejected(self):
        for bad in (150, -1, "high"):
            with self.assertRaises(adapters.AdapterError):
                adapters.normalize("justikey", {"plate": "A1", "confidence": bad})

    def test_confidence_of_exactly_one_stays_one(self):
        obs = adapters.normalize("justikey", {"plate": "A1", "confidence": 1.0})
        self.assertEqual(obs["confidence"], 1.0)


class TestTimestamps(unittest.TestCase):
    def test_epoch_seconds_and_millis_are_distinguished(self):
        secs = adapters.normalize("flat_epoch_v1", {"plate_number": "A1", "timestamp": EPOCH_SECONDS})
        millis = adapters.normalize("flat_epoch_v1", {"plate_number": "A1", "timestamp": EPOCH_MILLIS})
        self.assertEqual(secs["captured_at"], EXPECTED)
        self.assertEqual(millis["captured_at"], EXPECTED)

    def test_missing_timestamp_defaults_to_now(self):
        obs = adapters.normalize("justikey", {"plate": "A1"})
        self.assertEqual(len(obs["captured_at"]), timeutil.CANONICAL_LENGTH)

    def test_unparseable_timestamp_is_rejected(self):
        with self.assertRaises(adapters.AdapterError):
            adapters.normalize("justikey", {"plate": "A1", "captured_at": "yesterday"})

    def test_offset_timestamps_convert_to_utc(self):
        obs = adapters.normalize("justikey", {"plate": "A1",
                                              "captured_at": "2026-08-31T13:00:00+01:00"})
        self.assertEqual(obs["captured_at"], EXPECTED)


class TestPlateHandling(unittest.TestCase):
    def test_missing_plate_is_rejected(self):
        for payload in ({}, {"plate": ""}, {"plate": "   "}, {"plate": None}):
            with self.assertRaises(adapters.AdapterError):
                adapters.normalize("justikey", payload)

    def test_oversized_plate_is_rejected_not_silently_truncated(self):
        with self.assertRaises(adapters.AdapterError):
            adapters.normalize("justikey", {"plate": "A" * 40})

    def test_plate_is_uppercased_and_trimmed(self):
        obs = adapters.normalize("justikey", {"plate": "  ab-123c "})
        self.assertEqual(obs["plate"], "AB-123C")


class TestNestedResults(unittest.TestCase):
    def test_highest_confidence_candidate_wins(self):
        obs = adapters.normalize("nested_results_v1", {
            "results": [
                {"plate": "WRONG1", "confidence": 62},
                {"plate": "RIGHT1", "confidence": 94},
                {"plate": "WRONG2", "confidence": 71},
            ],
            "epoch_time": EPOCH_MILLIS, "camera_id": "CAM-1"})
        self.assertEqual(obs["plate"], "RIGHT1")
        self.assertAlmostEqual(obs["confidence"], 0.94, places=3)

    def test_rejected_candidates_are_not_carried_forward(self):
        """Storing discarded guesses would widen the protected record."""
        obs = adapters.normalize("nested_results_v1", {
            "results": [{"plate": "AAA111", "confidence": 90},
                        {"plate": "BBB222", "confidence": 40}],
            "epoch_time": EPOCH_MILLIS})
        self.assertNotIn("BBB222", str(obs))

    def test_empty_or_missing_results_is_rejected(self):
        for payload in ({"results": []}, {"results": "nope"}, {"epoch_time": EPOCH_MILLIS}):
            with self.assertRaises(adapters.AdapterError):
                adapters.normalize("nested_results_v1", payload)


class TestFieldNameVariants(unittest.TestCase):
    def test_alternate_spellings_are_accepted(self):
        a = adapters.normalize("flat_epoch_v1", {"plateNumber": "A1", "deviceId": "D1",
                                                 "timestampMs": EPOCH_MILLIS})
        b = adapters.normalize("flat_epoch_v1", {"plate": "A1", "camera_id": "D1",
                                                 "timestamp_ms": EPOCH_MILLIS})
        self.assertEqual(a["plate"], b["plate"])
        self.assertEqual(a["camera_id"], b["camera_id"])
        self.assertEqual(a["captured_at"], b["captured_at"])

    def test_missing_camera_falls_back_rather_than_failing(self):
        obs = adapters.normalize("justikey", {"plate": "A1"})
        self.assertEqual(obs["camera_id"], "unknown-camera")


if __name__ == "__main__":
    unittest.main()
