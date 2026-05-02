#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import textwrap
import time
import unittest
from pathlib import Path
from typing import Any

ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
TIME_RE = re.compile(
    r"^(?:(?P<name>[A-Za-z0-9_.-][^\s]*)\s+)?"
    r"time:\s*\[\s*"
    r"(?P<low>[0-9]+(?:\.[0-9]+)?)\s*(?P<low_unit>ps|ns|us|\u00b5s|\u03bcs|ms|s)\s+"
    r"(?P<estimate>[0-9]+(?:\.[0-9]+)?)\s*(?P<estimate_unit>ps|ns|us|\u00b5s|\u03bcs|ms|s)\s+"
    r"(?P<high>[0-9]+(?:\.[0-9]+)?)\s*(?P<high_unit>ps|ns|us|\u00b5s|\u03bcs|ms|s)\s*"
    r"\]"
)
BENCH_LINE_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+$")
BENCHMARKING_RE = re.compile(r"^Benchmarking (?P<name>[^:]+)(?::|$)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run and compare the synthetic transaction kernel non-regression benchmark."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    parse_log = subparsers.add_parser("parse-log", help="Parse Criterion output into JSON.")
    parse_log.add_argument("--log", required=True, type=Path)
    parse_log.add_argument("--output", required=True, type=Path)
    parse_log.add_argument("--repo-root", type=Path)
    parse_log.add_argument("--bench-wall-ms", type=float)
    parse_log.add_argument("--rayon-num-threads", type=int)
    parse_log.add_argument("--scenario-filter", default="")
    parse_log.add_argument("--git-ref", default="")

    run = subparsers.add_parser("run", help="Build from clean state and run the benchmark.")
    run.add_argument("--repo-root", required=True, type=Path)
    run.add_argument("--output-dir", required=True, type=Path)
    run.add_argument("--rayon-num-threads", type=int, default=8)
    run.add_argument("--scenario-filter", default="")
    run.add_argument("--sample-size", type=int)
    run.add_argument("--measurement-time-secs", type=int)
    run.add_argument("--warm-up-time-secs", type=int)
    run.add_argument("--git-ref", default="")

    compare = subparsers.add_parser(
        "compare", help="Compare two parsed benchmark result JSON files."
    )
    compare.add_argument("--baseline", required=True, type=Path)
    compare.add_argument("--current", required=True, type=Path)
    compare.add_argument("--summary-out", required=True, type=Path)
    compare.add_argument("--json-out", required=True, type=Path)
    compare.add_argument("--threshold-pct", required=True, type=float)
    compare.add_argument("--github-output", type=Path)

    self_test = subparsers.add_parser("self-test", help="Run parser and comparison tests.")
    self_test.add_argument("--runs", type=int, default=1)

    return parser.parse_args()


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def parse_duration_ms(value: str, unit: str) -> float:
    amount = float(value)
    if unit == "ps":
        return amount / 1_000_000_000.0
    if unit == "ns":
        return amount / 1_000_000.0
    if unit in ("us", "\u00b5s", "\u03bcs"):
        return amount / 1000.0
    if unit == "ms":
        return amount
    if unit == "s":
        return amount * 1000.0
    raise ValueError(f"Unsupported duration unit: {unit}")


def run_logged_command(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None,
    log_path: Path,
) -> float:
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
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repo_root, text=True
    ).strip()


def parse_criterion_log(contents: str) -> dict[str, Any]:
    metrics: dict[str, dict[str, Any]] = {}
    pending_name: str | None = None

    for line_number, raw_line in enumerate(contents.splitlines(), start=1):
        line = strip_ansi(raw_line).strip()
        if not line:
            continue

        benchmarking = BENCHMARKING_RE.match(line)
        if benchmarking:
            name = benchmarking.group("name").strip()
            if BENCH_LINE_RE.match(name):
                pending_name = name
            continue

        match = TIME_RE.match(line)
        if match:
            name = match.group("name") or pending_name
            if name is None:
                raise ValueError(f"Criterion timing without benchmark name on line {line_number}")
            estimate_ms = parse_duration_ms(
                match.group("estimate"), match.group("estimate_unit")
            )
            low_ms = parse_duration_ms(match.group("low"), match.group("low_unit"))
            high_ms = parse_duration_ms(match.group("high"), match.group("high_unit"))
            parts = name.split("/")
            metrics[name] = {
                "name": name,
                "producer": parts[0] if len(parts) >= 3 else "",
                "scenario": "/".join(parts[1:-1]) if len(parts) >= 3 else "",
                "axis": parts[-1],
                "low_ms": low_ms,
                "estimate_ms": estimate_ms,
                "high_ms": high_ms,
                "line": line_number,
            }
            pending_name = None
            continue

        if BENCH_LINE_RE.match(line):
            pending_name = line

    if not metrics:
        raise ValueError("Could not find any Criterion timing rows in the benchmark log.")

    return {"metrics": dict(sorted(metrics.items()))}


def parse_log_file(
    log_path: Path,
    *,
    repo_root: Path | None,
    git_ref: str,
    bench_wall_ms: float | None,
    rayon_num_threads: int | None,
    scenario_filter: str,
) -> dict[str, Any]:
    parsed = parse_criterion_log(log_path.read_text(encoding="utf-8"))
    metadata = {
        "log_path": str(log_path),
        "git_ref": git_ref,
        "bench_wall_ms": bench_wall_ms,
        "rayon_num_threads": rayon_num_threads,
        "scenario_filter": scenario_filter,
    }
    if repo_root is not None:
        metadata["repo_root"] = str(repo_root)
        metadata["git_sha"] = current_sha(repo_root)
    return {**metadata, **parsed}


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def cmd_run(args: argparse.Namespace) -> int:
    repo_root = args.repo_root.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["RAYON_NUM_THREADS"] = str(args.rayon_num_threads)
    if args.scenario_filter:
        env["SYNTH_SCENARIO"] = args.scenario_filter

    run_logged_command(
        ["cargo", "clean"], cwd=repo_root, env=env, log_path=output_dir / "clean.log"
    )

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

    bench_log = output_dir / "bench.log"
    bench_wall_ms = run_logged_command(bench_command, cwd=repo_root, env=env, log_path=bench_log)

    payload = parse_log_file(
        bench_log,
        repo_root=repo_root,
        git_ref=args.git_ref,
        bench_wall_ms=bench_wall_ms,
        rayon_num_threads=args.rayon_num_threads,
        scenario_filter=args.scenario_filter,
    )
    write_json(output_dir / "result.json", payload)
    return 0


def percent_delta(current: float | None, baseline: float | None) -> float | None:
    if baseline in (None, 0) or current is None:
        return None
    return ((current - baseline) / baseline) * 100.0


def format_ms(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:,.2f} ms"


def format_delta(value: float | None) -> str:
    if value is None:
        return "n/a"
    sign = "+" if value >= 0 else ""
    return f"{sign}{value:,.2f} ms"


def format_pct(value: float | None) -> str:
    if value is None:
        return "n/a"
    sign = "+" if value >= 0 else ""
    return f"{sign}{value:.2f}%"


def compare_results(
    baseline: dict[str, Any],
    current: dict[str, Any],
    threshold_pct: float,
) -> dict[str, Any]:
    baseline_metrics = baseline.get("metrics", {})
    current_metrics = current.get("metrics", {})
    missing_in_current = sorted(set(baseline_metrics) - set(current_metrics))
    missing_in_baseline = sorted(set(current_metrics) - set(baseline_metrics))
    shared = sorted(set(baseline_metrics) & set(current_metrics))
    if not shared:
        raise ValueError("Baseline and current benchmark results have no metric names in common.")

    rows: list[dict[str, Any]] = []
    for name in shared:
        baseline_ms = baseline_metrics[name]["estimate_ms"]
        current_ms = current_metrics[name]["estimate_ms"]
        delta_ms = current_ms - baseline_ms
        delta_pct = percent_delta(current_ms, baseline_ms)
        rows.append(
            {
                "name": name,
                "producer": current_metrics[name].get("producer", ""),
                "scenario": current_metrics[name].get("scenario", ""),
                "axis": current_metrics[name].get("axis", ""),
                "baseline_ms": baseline_ms,
                "current_ms": current_ms,
                "delta_ms": delta_ms,
                "delta_pct": delta_pct,
            }
        )

    rows.sort(
        key=lambda row: row["delta_pct"] if row["delta_pct"] is not None else float("-inf"),
        reverse=True,
    )
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
        "missing_in_current": missing_in_current,
        "missing_in_baseline": missing_in_baseline,
    }


def summary_markdown(result: dict[str, Any]) -> str:
    status_word = "REGRESSION" if result["regression"] else "OK"
    baseline_sha = result["baseline_sha"][:12] or result["baseline_ref"] or "baseline"
    current_sha = result["current_sha"][:12] or result["current_ref"] or "current"

    lines = [
        "# BENCHMARK REPORT: synthetic-tx-kernel-nonregression",
        "",
        "## Synthetic Transaction Kernel Non-Regression",
        "",
        f"Status: **{status_word}**",
        f"Threshold: `{result['threshold_pct']:.2f}%`",
        f"Baseline: `{baseline_sha}`",
        f"Current: `{current_sha}`",
        (
            "Worst slowdown: "
            f"`{result['max_delta_metric']}` moved by "
            f"`{format_delta(result['max_delta_ms'])}` ({format_pct(result['max_delta_pct'])})"
        ),
        "",
        "| Metric | Baseline | Current | Delta | Delta % |",
        "| --- | ---: | ---: | ---: | ---: |",
        (
            "| bench wall | "
            f"{format_ms(result['baseline_bench_wall_ms'])} | "
            f"{format_ms(result['current_bench_wall_ms'])} | "
            f"{format_delta(None if result['baseline_bench_wall_ms'] is None or result['current_bench_wall_ms'] is None else result['current_bench_wall_ms'] - result['baseline_bench_wall_ms'])} | "
            f"{format_pct(percent_delta(result['current_bench_wall_ms'], result['baseline_bench_wall_ms']))} |"
        ),
    ]

    lines.extend(
        [
            "",
            "| Benchmark | Baseline | Current | Delta | Delta % |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in result["metric_rows"][:20]:
        lines.append(
            "| "
            f"{row['name']} | "
            f"{format_ms(row['baseline_ms'])} | "
            f"{format_ms(row['current_ms'])} | "
            f"{format_delta(row['delta_ms'])} | "
            f"{format_pct(row['delta_pct'])} |"
        )

    if result["missing_in_current"] or result["missing_in_baseline"]:
        lines.extend(["", "Metric set changed:"])
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
    lines = [
        f"status={result['status']}",
        f"regression={'true' if result['regression'] else 'false'}",
        f"baseline_sha={result['baseline_sha']}",
        f"current_sha={result['current_sha']}",
        f"max_delta_metric={result['max_delta_metric']}",
        f"max_delta_ms={result['max_delta_ms']:.6f}",
        f"max_delta_pct={result['max_delta_pct']:.6f}",
    ]
    with path.open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def cmd_parse_log(args: argparse.Namespace) -> int:
    payload = parse_log_file(
        args.log,
        repo_root=args.repo_root,
        git_ref=args.git_ref,
        bench_wall_ms=args.bench_wall_ms,
        rayon_num_threads=args.rayon_num_threads,
        scenario_filter=args.scenario_filter,
    )
    write_json(args.output, payload)
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    current = json.loads(args.current.read_text(encoding="utf-8"))
    result = compare_results(baseline, current, args.threshold_pct)
    write_json(args.json_out, result)
    args.summary_out.parent.mkdir(parents=True, exist_ok=True)
    args.summary_out.write_text(summary_markdown(result), encoding="utf-8")
    if args.github_output is not None:
        write_github_output(args.github_output, result)
    return 0


class ParserTests(unittest.TestCase):
    def test_parse_split_criterion_rows(self) -> None:
        payload = parse_criterion_log(
            textwrap.dedent(
                """
                Benchmarking bench-tx/consume-single-p2id-note/prove: Warming up for 1.0000 s
                bench-tx/consume-single-p2id-note/prove
                                        time:   [1.2345 s 1.3456 s 1.4567 s]
                Found 3 outliers among 30 measurements
                bench-tx/consume-single-p2id-note/verify
                                        time:   [997.00 us 1.0000 ms 1.0130 ms]
                """
            )
        )
        self.assertAlmostEqual(
            payload["metrics"]["bench-tx/consume-single-p2id-note/prove"]["estimate_ms"],
            1345.6,
        )
        self.assertAlmostEqual(
            payload["metrics"]["bench-tx/consume-single-p2id-note/verify"]["estimate_ms"],
            1.0,
        )

    def test_parse_inline_colored_row(self) -> None:
        payload = parse_criterion_log(
            "\x1b[32mbench-tx/foo/exec time: [10.00 ms 11.50 ms 13.00 ms]\x1b[0m\n"
        )
        self.assertAlmostEqual(payload["metrics"]["bench-tx/foo/exec"]["estimate_ms"], 11.5)

    def test_compare_uses_worst_positive_delta(self) -> None:
        baseline = {
            "metrics": {
                "bench-tx/a/prove": {"estimate_ms": 100.0},
                "bench-tx/a/verify": {"estimate_ms": 50.0},
            }
        }
        current = {
            "metrics": {
                "bench-tx/a/prove": {"estimate_ms": 104.0},
                "bench-tx/a/verify": {"estimate_ms": 60.0},
            }
        }
        result = compare_results(baseline, current, 5.0)
        self.assertTrue(result["regression"])
        self.assertEqual(result["max_delta_metric"], "bench-tx/a/verify")

    def test_empty_log_fails(self) -> None:
        with self.assertRaises(ValueError):
            parse_criterion_log("running 0 tests\n")


def cmd_self_test(args: argparse.Namespace) -> int:
    for run in range(args.runs):
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(ParserTests)
        result = unittest.TextTestRunner(verbosity=1, stream=sys.stderr).run(suite)
        if not result.wasSuccessful():
            return 1
        if args.runs > 1:
            print(f"parser self-test run {run + 1}/{args.runs} passed")
    return 0


def main() -> int:
    args = parse_args()
    if args.command == "parse-log":
        return cmd_parse_log(args)
    if args.command == "run":
        return cmd_run(args)
    if args.command == "compare":
        return cmd_compare(args)
    if args.command == "self-test":
        return cmd_self_test(args)
    raise ValueError(f"Unhandled command: {args.command}")


if __name__ == "__main__":
    sys.exit(main())
