"""Edge agent: store-and-forward behavior at the camera."""
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

_spec = importlib.util.spec_from_file_location(
    "edge_agent", os.path.join(ROOT, "scripts", "edge_agent.py"))
agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agent)


class TestProcessedFrames(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.watch = os.path.join(self.dir, "captures")
        os.makedirs(self.watch)
        self.state = os.path.join(self.dir, "state.json")
        self.frame = os.path.join(self.watch, "f1.jpg")
        with open(self.frame, "w") as fh:
            fh.write("frame")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_a_frame_is_recognized_once_across_restarts(self):
        """Re-reading frames would invent observations that never happened."""
        first = agent.ProcessedFrames(self.state)
        self.assertNotIn(self.frame, first)
        first.add(self.frame)
        first.save(self.watch)

        restarted = agent.ProcessedFrames(self.state)
        self.assertIn(self.frame, restarted)

    def test_a_rewritten_frame_counts_as_new(self):
        seen = agent.ProcessedFrames(self.state)
        seen.add(self.frame)
        seen.save(self.watch)
        # Same name, different content and mtime.
        with open(self.frame, "w") as fh:
            fh.write("a completely different frame")
        os.utime(self.frame, (0, 0))
        self.assertNotIn(self.frame, agent.ProcessedFrames(self.state))

    def test_state_is_pruned_when_frames_are_deleted(self):
        seen = agent.ProcessedFrames(self.state)
        seen.add(self.frame)
        seen.save(self.watch)
        os.remove(self.frame)
        seen.save(self.watch)
        with open(self.state) as fh:
            self.assertEqual(json.load(fh), [])

    def test_corrupt_state_file_does_not_crash_the_agent(self):
        with open(self.state, "w") as fh:
            fh.write("{ not json")
        self.assertNotIn(self.frame, agent.ProcessedFrames(self.state))


class TestBuffer(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "buffer.jsonl")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_observations_survive_a_restart(self):
        buf = agent.Buffer(self.path)
        buf.add({"plate": "ABC123"})
        buf.add({"plate": "DEF456"})
        self.assertEqual(len(agent.Buffer(self.path)), 2)

    def test_keep_only_retains_undelivered_observations(self):
        buf = agent.Buffer(self.path)
        for plate in ("A", "B", "C"):
            buf.add({"plate": plate})
        buf.keep_only([{"plate": "C"}])
        self.assertEqual(buf.read_all(), [{"plate": "C"}])

    def test_corrupt_lines_are_skipped_not_fatal(self):
        buf = agent.Buffer(self.path)
        buf.add({"plate": "A"})
        with open(self.path, "a") as fh:
            fh.write("{ truncated write\n")
        buf.add({"plate": "B"})
        self.assertEqual(len(buf.read_all()), 2)

    def test_missing_buffer_reads_as_empty(self):
        self.assertEqual(agent.Buffer(self.path).read_all(), [])


class TestRecognizerOutputParsing(unittest.TestCase):
    def test_csv_lines(self):
        self.assertEqual(agent._parse_recognizer_output("ABC123,0.94\nDEF456,0.81"),
                         [("ABC123", 0.94), ("DEF456", 0.81)])

    def test_json_array(self):
        out = agent._parse_recognizer_output('[{"plate":"abc123","confidence":0.9}]')
        self.assertEqual(out, [("ABC123", 0.9)])

    def test_json_results_object(self):
        out = agent._parse_recognizer_output('{"results":[{"plate":"abc123","confidence":0.9}]}')
        self.assertEqual(out, [("ABC123", 0.9)])

    def test_empty_and_garbage_output_yield_nothing_usable(self):
        self.assertEqual(agent._parse_recognizer_output(""), [])
        self.assertEqual(agent._parse_recognizer_output("   \n  "), [])
        self.assertEqual(agent._parse_recognizer_output("{}"), [])

    def test_missing_confidence_defaults_rather_than_failing(self):
        self.assertEqual(agent._parse_recognizer_output("ABC123"), [("ABC123", 0.9)])


class TestObserve(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.frame = os.path.join(self.dir, "f.jpg")
        with open(self.frame, "w") as fh:
            fh.write("frame")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_low_confidence_reads_are_discarded(self):
        recognizer = lambda p: [("AAA111", 0.95), ("BBB222", 0.20)]  # noqa: E731
        out = agent.observe(self.frame, recognizer, "cam", "loc", "src", min_confidence=0.5)
        self.assertEqual([o["plate"] for o in out], ["AAA111"])

    def test_observation_carries_the_frame_capture_time(self):
        os.utime(self.frame, (1_700_000_000, 1_700_000_000))
        out = agent.observe(self.frame, agent.stub_recognizer, "cam", None, "src", 0.0)
        self.assertTrue(out[0]["captured_at"].startswith("2023-11-"))

    def test_stub_recognizer_is_deterministic(self):
        self.assertEqual(agent.stub_recognizer(self.frame), agent.stub_recognizer(self.frame))


if __name__ == "__main__":
    unittest.main()
