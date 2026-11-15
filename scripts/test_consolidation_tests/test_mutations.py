"""Failure controls for preservation of mutation detections."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from compare_mutation_results import compare_runs


class MutationGateControls(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.before, self.after = (Path(self.directory.name) / name for name in ("before", "after"))
        self.baseline = {"scenario": "Baseline", "summary": "Success", "phase_results": [
            {"phase": "Build", "process_status": "Success"},
            {"phase": "Test", "process_status": "Success"}]}
        self.mutant = {"name": "production fault"}
        self.caught = {"scenario": {"Mutant": self.mutant}, "summary": "CaughtMutant",
                       "log_path": "fault.log", "phase_results": [
                           {"phase": "Build", "process_status": "Success"},
                           {"phase": "Test", "process_status": {"Failure": 100}}]}
        self.write(self.before, self.caught)
        self.write(self.after, self.caught)

    def write(self, path, outcome):
        path.mkdir(exist_ok=True)
        data = {"verification.json": {"schema": 1, "configuration": {"seed": 0},
                                      "production_sources": {"word.rs": "hash"}},
                "mutants.json": [self.mutant],
                "outcomes.json": {"end_time": "finished", "total_mutants": 1,
                                  "outcomes": [self.baseline, outcome]}}
        for filename, value in data.items():
            (path / filename).write_text(json.dumps(value))
        (path / "fault.log").write_text("thread 'property' panicked at assertion failed")

    def test_preserved_assertion_detection_is_accepted(self):
        self.assertTrue(compare_runs(self.before, self.after)["accepted"])

    def test_lost_detection_is_rejected(self):
        missed = copy.deepcopy(self.caught)
        missed["summary"] = "MissedMutant"
        missed["phase_results"][1]["process_status"] = "Success"
        self.write(self.after, missed)
        self.assertEqual(compare_runs(self.before, self.after)["lost_detections"], ["production fault"])

    def test_build_failure_and_timeout_cannot_count_as_caught(self):
        for summary, status in (("Unviable", {"Failure": 101}), ("Timeout", "Timeout")):
            with self.subTest(summary=summary):
                invalid = copy.deepcopy(self.caught)
                invalid["summary"] = summary
                invalid["phase_results"][0]["process_status"] = status
                self.write(self.after, invalid)
                result = compare_runs(self.before, self.after)
                self.assertFalse(result["accepted"])
                self.assertEqual(result["after_inconclusive"], ["production fault"])

    def test_test_tool_failure_without_assertion_is_inconclusive(self):
        (self.after / "fault.log").write_text("test runner failed to start")
        self.assertFalse(compare_runs(self.before, self.after)["accepted"])

    def test_partial_outcomes_are_rejected(self):
        path = self.after / "outcomes.json"
        data = json.loads(path.read_text())
        data["outcomes"].pop()
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "complete inventory"):
            compare_runs(self.before, self.after)

    def test_unfinished_run_is_rejected(self):
        path = self.after / "outcomes.json"
        data = json.loads(path.read_text())
        data["end_time"] = None
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "not finished"):
            compare_runs(self.before, self.after)

    def test_configuration_drift_is_rejected(self):
        path = self.after / "verification.json"
        data = json.loads(path.read_text())
        data["configuration"]["seed"] = 1
        path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "configurations"):
            compare_runs(self.before, self.after)
