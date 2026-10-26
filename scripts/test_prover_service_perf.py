import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import prover_service_perf as perf


def write_estimate(directory, axis, point, lower, upper):
    path = directory / "tiny_proof" / axis / "new/estimates.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"mean": {"point_estimate": point, "confidence_interval": {
        "confidence_level": 0.95, "lower_bound": lower, "upper_bound": upper}}}))


class PerformanceComparison(unittest.TestCase):
    def test_decisions_and_confirmation_order(self):
        for grpc, reverse, enforce, expected, order in [
            ((102, 101, 103), None, True, 0, ["native", "grpc"]),
            ((105, 104, 106), None, True, 0, ["native", "grpc"]),
            ((120, 119, 121), None, True, 1, ["native", "grpc", "grpc", "native"]),
            ((120, 119, 121), None, False, 0, ["native", "grpc", "grpc", "native"]),
            ((108, 99, 115), None, True, 0, ["native", "grpc", "grpc", "native"]),
            ((120, 119, 121), (102, 101, 103), True, 0, ["native", "grpc", "grpc", "native"]),
        ]:
            with self.subTest(grpc=grpc, enforce=enforce), tempfile.TemporaryDirectory() as root:
                calls = []

                def run(command, **kwargs):
                    if "--no-run" not in command:
                        axis = command[command.index("--") + 1].split("/")[1]
                        calls.append(axis)
                        output = Path(kwargs["env"]["CRITERION_HOME"])
                        rpc = reverse if output.name == "reverse" and reverse is not None else grpc
                        values = (100, 99, 101) if axis == "native" else rpc
                        write_estimate(output, axis, *values)

                with patch.object(perf.subprocess, "run", side_effect=run), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(perf.main([root] + (["--enforce"] if enforce else [])), expected)
                self.assertEqual(calls, order)

    def test_missing_and_invalid_measurements_fail(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            with self.assertRaises(FileNotFoundError):
                perf.read_estimate(directory, "native")
            for values in [(0, 0, 0), (True, 1, 2), (float("nan"), 1, 2),
                           (1, 2, 3), (1, 0.5, float("inf"))]:
                with self.subTest(values=values):
                    write_estimate(directory, "native", *values)
                    with self.assertRaises(ValueError):
                        perf.read_estimate(directory, "native")
