#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import unittest
import unittest.mock as mock
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run and compare the synthetic transaction kernel non-regression benchmark."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="Build from clean state and run the benchmark.")
    run.add_argument("--repo-root", required=True, type=Path)
    run.add_argument("--output-dir", required=True, type=Path)
    run.add_argument("--rayon-num-threads", type=int, default=8)
    run.add_argument("--scenario-filter", default="")
    run.add_argument("--sample-size", type=int)
    run.add_argument("--measurement-time-secs", type=int)
    run.add_argument("--warm-up-time-secs", type=int)
    run.add_argument("--git-ref", default="")

    collect = commands.add_parser("collect", help="Collect Criterion estimates into JSON.")
    collect.add_argument("--repo-root", required=True, type=Path)
    collect.add_argument("--output", required=True, type=Path)
    collect.add_argument("--bench-wall-ms", type=float)
    collect.add_argument("--rayon-num-threads", type=int)
    collect.add_argument("--scenario-filter", default="")
    collect.add_argument("--git-ref", default="")

    compare = commands.add_parser("compare", help="Compare two benchmark result JSON files.")
    compare.add_argument("--baseline", required=True, type=Path)
    compare.add_argument("--current", required=True, type=Path)
    compare.add_argument("--summary-out", required=True, type=Path)
    compare.add_argument("--json-out", required=True, type=Path)
    compare.add_argument("--threshold-pct", required=True, type=float)
    compare.add_argument("--github-output", type=Path)

    self_test = commands.add_parser("self-test", help="Run parser and comparison tests.")
    self_test.add_argument("--runs", type=int, default=1)

    return parser.parse_args()


def run_logged_command(command: list[str], *, cwd: Path, env: dict[str, str], log_path: Path) -> float:
    start = time.perf_counter()
    with log_path.open("w", encoding="utf-8") as handle:
        handle.write(f"$ {' '.join(command)}\n")
        handle.flush()

        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert process.stdout is not None
        for line in process.stdout:
            sys.stdout.write(line)
            handle.write(line)

        code = process.wait()
        if code != 0:
            raise subprocess.CalledProcessError(code, command)

    return (time.perf_counter() - start) * 1000.0


def current_sha(repo_root: Path) -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo_root, text=True).strip()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_criterion_estimate_path(criterion_root: Path, estimates_path: Path) -> tuple[str, str, str]:
    relative_parts = estimates_path.relative_to(criterion_root).parts
    if len(relative_parts) == 5 and relative_parts[-2:] == ("new", "estimates.json"):
        producer, scenario, axis = relative_parts[:3]
        return producer, scenario, axis

    if len(relative_parts) == 4 and relative_parts[-2:] == ("new", "estimates.json"):
        group, axis = relative_parts[:2]
        producer, separator, scenario = group.partition("_")
        if separator and scenario:
            return producer, scenario, axis

    raise ValueError(f"Unexpected synthetic benchmark estimate path: {estimates_path}")


def collect_criterion_metrics(repo_root: Path, *, estimate: str = "mean") -> dict[str, dict[str, Any]]:
    criterion_root = repo_root / "target" / "criterion"
    metrics: dict[str, dict[str, Any]] = {}

    for estimates_path in sorted(criterion_root.glob("**/new/estimates.json")):
        producer, scenario, axis = parse_criterion_estimate_path(criterion_root, estimates_path)
        name = f"{producer}/{scenario}/{axis}"
        estimate_data = json.loads(estimates_path.read_text(encoding="utf-8"))[estimate]
        metrics[name] = {
            "name": name,
            "producer": producer,
            "scenario": scenario,
            "axis": axis,
            "estimate_ms": float(estimate_data["point_estimate"]) / 1_000_000.0,
            "low_ms": float(estimate_data["confidence_interval"]["lower_bound"]) / 1_000_000.0,
            "high_ms": float(estimate_data["confidence_interval"]["upper_bound"]) / 1_000_000.0,
        }

    if not metrics:
        raise ValueError(f"No Criterion estimates found under {criterion_root}")
    return dict(sorted(metrics.items()))


def collect_result(
    repo_root: Path,
    *,
    git_ref: str,
    bench_wall_ms: float | None,
    rayon_num_threads: int | None,
    scenario_filter: str,
) -> dict[str, Any]:
    return {
        "repo_root": str(repo_root),
        "git_ref": git_ref,
        "git_sha": current_sha(repo_root),
        "bench_wall_ms": bench_wall_ms,
        "rayon_num_threads": rayon_num_threads,
        "scenario_filter": scenario_filter,
        "metrics": collect_criterion_metrics(repo_root),
    }


def cmd_run(args: argparse.Namespace) -> int:
    repo_root = args.repo_root.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["RAYON_NUM_THREADS"] = str(args.rayon_num_threads)
    if args.scenario_filter:
        env["SYNTH_SCENARIO"] = args.scenario_filter

    run_logged_command(["cargo", "clean"], cwd=repo_root, env=env, log_path=output_dir / "clean.log")

    bench_command = [
        "cargo",
        "bench",
        "--profile",
        "optimized",
        "-p",
        "miden-vm-synthetic-bench",
        "--bench",
        "synthetic_bench",
        "--",
        "--noplot",
    ]
    if args.sample_size is not None:
        bench_command.extend(["--sample-size", str(args.sample_size)])
    if args.measurement_time_secs is not None:
        bench_command.extend(["--measurement-time", str(args.measurement_time_secs)])
    if args.warm_up_time_secs is not None:
        bench_command.extend(["--warm-up-time", str(args.warm_up_time_secs)])

    bench_wall_ms = run_logged_command(
        bench_command, cwd=repo_root, env=env, log_path=output_dir / "bench.log"
    )
    write_json(
        output_dir / "result.json",
        collect_result(
            repo_root,
            git_ref=args.git_ref,
            bench_wall_ms=bench_wall_ms,
            rayon_num_threads=args.rayon_num_threads,
            scenario_filter=args.scenario_filter,
        ),
    )
    return 0


def cmd_collect(args: argparse.Namespace) -> int:
    write_json(
        args.output,
        collect_result(
            args.repo_root.resolve(),
            git_ref=args.git_ref,
            bench_wall_ms=args.bench_wall_ms,
            rayon_num_threads=args.rayon_num_threads,
            scenario_filter=args.scenario_filter,
        ),
    )
    return 0


def percent_delta(current: float | None, baseline: float | None) -> float | None:
    if baseline in (None, 0) or current is None:
        return None
    return ((current - baseline) / baseline) * 100.0


def fmt_ms(value: float | None) -> str:
    return "n/a" if value is None else f"{value:,.2f} ms"


def fmt_delta(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{'+' if value >= 0 else ''}{value:,.2f} ms"


def fmt_pct(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{'+' if value >= 0 else ''}{value:.2f}%"


def compare_results(
    baseline: dict[str, Any], current: dict[str, Any], threshold_pct: float
) -> dict[str, Any]:
    baseline_metrics = baseline.get("metrics", {})
    current_metrics = current.get("metrics", {})
    shared = sorted(set(baseline_metrics) & set(current_metrics))
    if not shared:
        raise ValueError("Baseline and current benchmark results have no metric names in common.")

    rows = []
    for name in shared:
        baseline_ms = baseline_metrics[name]["estimate_ms"]
        current_ms = current_metrics[name]["estimate_ms"]
        rows.append(
            {
                "name": name,
                "baseline_ms": baseline_ms,
                "current_ms": current_ms,
                "delta_ms": current_ms - baseline_ms,
                "delta_pct": percent_delta(current_ms, baseline_ms),
            }
        )
    rows.sort(key=lambda r: r["delta_pct"] if r["delta_pct"] is not None else float("-inf"), reverse=True)
    worst = rows[0]
    regression = bool(worst["delta_pct"] is not None and worst["delta_pct"] > threshold_pct)
    return {
        "status": "regression" if regression else "ok",
        "regression": regression,
        "threshold_pct": threshold_pct,
        "baseline_sha": baseline.get("git_sha", ""),
        "current_sha": current.get("git_sha", ""),
        "baseline_ref": baseline.get("git_ref", ""),
        "current_ref": current.get("git_ref", ""),
        "baseline_bench_wall_ms": baseline.get("bench_wall_ms"),
        "current_bench_wall_ms": current.get("bench_wall_ms"),
        "max_delta_metric": worst["name"],
        "max_delta_ms": worst["delta_ms"],
        "max_delta_pct": worst["delta_pct"],
        "metric_rows": rows,
        "missing_in_current": sorted(set(baseline_metrics) - set(current_metrics)),
        "missing_in_baseline": sorted(set(current_metrics) - set(baseline_metrics)),
    }


def summary_markdown(result: dict[str, Any]) -> str:
    status = "REGRESSION" if result["regression"] else "OK"
    baseline = result["baseline_sha"][:12] or result["baseline_ref"] or "baseline"
    current = result["current_sha"][:12] or result["current_ref"] or "current"
    wall_delta = (
        None
        if result["baseline_bench_wall_ms"] is None or result["current_bench_wall_ms"] is None
        else result["current_bench_wall_ms"] - result["baseline_bench_wall_ms"]
    )
    wall_delta_pct = percent_delta(result["current_bench_wall_ms"], result["baseline_bench_wall_ms"])
    over_threshold = [
        row
        for row in result["metric_rows"]
        if row["delta_pct"] is not None and row["delta_pct"] > result["threshold_pct"]
    ]
    metric_rows = result["metric_rows"]
    lines = [
        "# BENCHMARK REPORT: synthetic-tx-kernel-nonregression",
        "",
        "## Synthetic Transaction Kernel Non-Regression",
        "",
        "### Run",
        "",
        f"- Baseline: `{baseline}`",
        f"- Current: `{current}`",
        f"- Threshold: `{result['threshold_pct']:.2f}%`",
        "- Bench wall: "
        f"{fmt_ms(result['baseline_bench_wall_ms'])} -> "
        f"{fmt_ms(result['current_bench_wall_ms'])} "
        f"({fmt_delta(wall_delta)}, {fmt_pct(wall_delta_pct)})",
        "",
        "### Result",
        "",
        f"- Status: **{status}**",
        "- Worst regression: "
        f"`{result['max_delta_metric']}` moved by "
        f"`{fmt_delta(result['max_delta_ms'])}` ({fmt_pct(result['max_delta_pct'])})",
        "",
        "### Metrics over threshold",
        "",
    ]
    if over_threshold:
        lines.extend(
            f"- `{row['name']}`: {fmt_delta(row['delta_ms'])} ({fmt_pct(row['delta_pct'])})"
            for row in over_threshold
        )
    else:
        lines.append("- None")
    lines += [
        "",
        f"### Per-benchmark results ({len(metric_rows)} of {len(metric_rows)})",
        "",
        "| Benchmark | Baseline | Current | Delta | Delta % |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    lines += [
        (
            f"| {row['name']} | {fmt_ms(row['baseline_ms'])} | {fmt_ms(row['current_ms'])} | "
            f"{fmt_delta(row['delta_ms'])} | {fmt_pct(row['delta_pct'])} |"
        )
        for row in metric_rows
    ]
    if result["missing_in_current"] or result["missing_in_baseline"]:
        lines.append("\nMetric set changed:")
        if result["missing_in_current"]:
            lines.append(
                "- Missing in current: "
                + ", ".join(f"`{name}`" for name in result["missing_in_current"][:10])
            )
        if result["missing_in_baseline"]:
            lines.append(
                "- Missing in baseline: "
                + ", ".join(f"`{name}`" for name in result["missing_in_baseline"][:10])
            )
    return "\n".join(lines) + "\n"


def write_github_output(path: Path, result: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(
            "\n".join(
                [
                    f"status={result['status']}",
                    f"regression={'true' if result['regression'] else 'false'}",
                    f"baseline_sha={result['baseline_sha']}",
                    f"current_sha={result['current_sha']}",
                    f"max_delta_metric={result['max_delta_metric']}",
                    f"max_delta_ms={result['max_delta_ms']:.6f}",
                    f"max_delta_pct={result['max_delta_pct']:.6f}",
                ]
            )
            + "\n"
        )


def cmd_compare(args: argparse.Namespace) -> int:
    result = compare_results(
        json.loads(args.baseline.read_text(encoding="utf-8")),
        json.loads(args.current.read_text(encoding="utf-8")),
        args.threshold_pct,
    )
    write_json(args.json_out, result)
    args.summary_out.parent.mkdir(parents=True, exist_ok=True)
    args.summary_out.write_text(summary_markdown(result), encoding="utf-8")
    if args.github_output is not None:
        write_github_output(args.github_output, result)
    return 0


class Tests(unittest.TestCase):
    def test_collect_criterion_estimate(self) -> None:
        with mock.patch("subprocess.check_output", return_value="abc\n"):
            root = Path(self.id().replace("/", "_"))
            estimates = (
                root
                / "target"
                / "criterion"
                / "bench-tx"
                / "consume-single-p2id-note"
                / "prove"
                / "new"
                / "estimates.json"
            )
            estimates.parent.mkdir(parents=True, exist_ok=True)
            write_json(
                estimates,
                {
                    "mean": {
                        "point_estimate": 1_500_000.0,
                        "confidence_interval": {"lower_bound": 1_000_000.0, "upper_bound": 2_000_000.0},
                    }
                },
            )
            try:
                metrics = collect_criterion_metrics(root)
                self.assertEqual(metrics["bench-tx/consume-single-p2id-note/prove"]["estimate_ms"], 1.5)
            finally:
                subprocess.run(["rm", "-rf", str(root)], check=False)

    def test_collect_criterion_estimate_from_sanitized_group_dir(self) -> None:
        with mock.patch("subprocess.check_output", return_value="abc\n"):
            root = Path(self.id().replace("/", "_"))
            estimates = (
                root
                / "target"
                / "criterion"
                / "bench-tx_create-single-p2id-note"
                / "prove"
                / "new"
                / "estimates.json"
            )
            estimates.parent.mkdir(parents=True, exist_ok=True)
            write_json(
                estimates,
                {
                    "mean": {
                        "point_estimate": 1_500_000.0,
                        "confidence_interval": {"lower_bound": 1_000_000.0, "upper_bound": 2_000_000.0},
                    }
                },
            )
            try:
                metrics = collect_criterion_metrics(root)
                self.assertEqual(metrics["bench-tx/create-single-p2id-note/prove"]["estimate_ms"], 1.5)
            finally:
                subprocess.run(["rm", "-rf", str(root)], check=False)

    def test_compare_uses_worst_positive_delta(self) -> None:
        baseline = {"metrics": {"bench-tx/a/prove": {"estimate_ms": 100.0}, "bench-tx/a/verify": {"estimate_ms": 50.0}}}
        current = {"metrics": {"bench-tx/a/prove": {"estimate_ms": 104.0}, "bench-tx/a/verify": {"estimate_ms": 60.0}}}
        result = compare_results(baseline, current, 5.0)
        self.assertTrue(result["regression"])
        self.assertEqual(result["max_delta_metric"], "bench-tx/a/verify")

    def test_summary_markdown_uses_requested_report_shape(self) -> None:
        result = compare_results(
            {
                "git_sha": "1764d66ca1c6deadbeef",
                "bench_wall_ms": 145_000.0,
                "metrics": {
                    "bench-tx/consume-b2agg-note-bridge-out/exec": {"estimate_ms": 23.96},
                    "bench-tx/consume-single-p2id-note/prove": {"estimate_ms": 1_987.33},
                },
            },
            {
                "git_sha": "1234567890abcdef",
                "bench_wall_ms": 152_000.0,
                "metrics": {
                    "bench-tx/consume-b2agg-note-bridge-out/exec": {"estimate_ms": 23.96},
                    "bench-tx/consume-single-p2id-note/prove": {"estimate_ms": 2_132.40},
                },
            },
            5.0,
        )

        summary = summary_markdown(result)

        self.assertIn("# BENCHMARK REPORT: synthetic-tx-kernel-nonregression", summary)
        self.assertIn("### Run", summary)
        self.assertIn("- Baseline: `1764d66ca1c6`", summary)
        self.assertIn("- Current: `1234567890ab`", summary)
        self.assertIn("- Threshold: `5.00%`", summary)
        self.assertIn("- Bench wall: 145,000.00 ms -> 152,000.00 ms (+7,000.00 ms, +4.83%)", summary)
        self.assertIn("### Result", summary)
        self.assertIn("- Status: **REGRESSION**", summary)
        self.assertIn(
            "- Worst regression: `bench-tx/consume-single-p2id-note/prove` moved by `+145.07 ms` (+7.30%)",
            summary,
        )
        self.assertIn("### Metrics over threshold", summary)
        self.assertIn("- `bench-tx/consume-single-p2id-note/prove`: +145.07 ms (+7.30%)", summary)
        self.assertIn("### Per-benchmark results (2 of 2)", summary)
        self.assertIn(
            "| bench-tx/consume-single-p2id-note/prove | 1,987.33 ms | 2,132.40 ms | +145.07 ms | +7.30% |",
            summary,
        )


def cmd_self_test(args: argparse.Namespace) -> int:
    for run in range(args.runs):
        result = unittest.TextTestRunner(verbosity=1, stream=sys.stderr).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
        )
        if not result.wasSuccessful():
            return 1
        if args.runs > 1:
            print(f"self-test run {run + 1}/{args.runs} passed")
    return 0


def main() -> int:
    args = parse_args()
    if args.command == "run":
        return cmd_run(args)
    if args.command == "collect":
        return cmd_collect(args)
    if args.command == "compare":
        return cmd_compare(args)
    if args.command == "self-test":
        return cmd_self_test(args)
    raise ValueError(f"Unhandled command: {args.command}")


if __name__ == "__main__":
    sys.exit(main())
