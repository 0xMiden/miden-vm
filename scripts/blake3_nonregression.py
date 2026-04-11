#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

BENCHMARK_PATH = "./miden-vm/masm-examples/hashing/blake3_1to1/blake3_1to1.masm"
BENCHMARK_COMMAND = [
    "./target/optimized/miden-vm",
    "prove",
    BENCHMARK_PATH,
    "--release",
]

ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
TIMING_RE = re.compile(
    r"^(?:(?P<prefix>(?:[ \u2502]{3})*)(?P<branch>[\u251d\u2515]\u2501)\s+)?"
    r"(?P<name>.+?)\s+\[\s*(?P<duration>[^|]+?)\s*\|"
)
PROGRAM_PROVED_RE = re.compile(r"^Program proved in (?P<ms>\d+) ms$")

KEY_METRICS = [
    ("prove_program_sync", "prove_program_sync"),
    (
        "prove_program_sync > execute_trace_inputs_sync",
        "execute_trace_inputs_sync",
    ),
    ("prove_program_sync > prove_trace_sync", "prove_trace_sync"),
    ("prove_program_sync > prove_trace_sync > build_trace", "build_trace"),
    (
        "prove_program_sync > prove_trace_sync > to_row_major_matrix",
        "to_row_major_matrix",
    ),
    ("prove_program_sync > prove_trace_sync > prove", "prove"),
    (
        "prove_program_sync > prove_trace_sync > prove > commit to main traces",
        "commit to main traces",
    ),
    (
        "prove_program_sync > prove_trace_sync > prove > build_aux_trace",
        "build_aux_trace",
    ),
    (
        "prove_program_sync > prove_trace_sync > prove > commit to aux traces",
        "commit to aux traces",
    ),
    (
        "prove_program_sync > prove_trace_sync > prove > evaluate constraints",
        "evaluate constraints",
    ),
    (
        "prove_program_sync > prove_trace_sync > prove > commit to quotient poly chunks",
        "commit to quotient poly chunks",
    ),
    ("prove_program_sync > prove_trace_sync > prove > open", "open"),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run and compare the blake3 1-to-1 non-regression benchmark."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    parse_log = subparsers.add_parser("parse-log", help="Parse a prove log into JSON.")
    parse_log.add_argument("--log", required=True, type=Path)
    parse_log.add_argument("--output", required=True, type=Path)
    parse_log.add_argument("--repo-root", type=Path)
    parse_log.add_argument("--build-wall-ms", type=float)
    parse_log.add_argument("--prove-wall-ms", type=float)
    parse_log.add_argument("--rayon-num-threads", type=int)
    parse_log.add_argument("--git-ref")

    run = subparsers.add_parser("run", help="Build from clean state and run the benchmark.")
    run.add_argument("--repo-root", required=True, type=Path)
    run.add_argument("--output-dir", required=True, type=Path)
    run.add_argument("--rayon-num-threads", type=int, default=8)
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

    return parser.parse_args()


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def parse_duration_ms(raw: str) -> float:
    value = raw.strip()
    if value.endswith("ms"):
        return float(value[:-2])
    if value.endswith("us"):
        return float(value[:-2]) / 1000.0
    if value.endswith("\u00b5s"):
        return float(value[:-2]) / 1000.0
    if value.endswith("ns"):
        return float(value[:-2]) / 1_000_000.0
    if value.endswith("s"):
        return float(value[:-1]) * 1000.0
    raise ValueError(f"Unsupported duration format: {raw}")


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


def parse_log_contents(contents: str) -> dict[str, Any]:
    timings: list[dict[str, Any]] = []
    first_by_base_path: dict[str, float] = {}
    stack: list[str] = []
    path_counts: dict[str, int] = {}
    program_proved_ms: float | None = None

    for line_number, raw_line in enumerate(contents.splitlines(), start=1):
        line = strip_ansi(raw_line)

        proved_match = PROGRAM_PROVED_RE.match(line)
        if proved_match:
            program_proved_ms = float(proved_match.group("ms"))
            continue

        if not line.startswith("INFO"):
            continue

        rest = line[4:]
        if rest.startswith("     "):
            rest = rest[5:]
        else:
            rest = rest.lstrip(" ")

        match = TIMING_RE.match(rest)
        if not match:
            continue

        depth = 0
        if match.group("branch"):
            depth = (len(match.group("prefix") or "") // 3) + 1

        name = match.group("name").strip()
        duration_ms = parse_duration_ms(match.group("duration"))

        stack = stack[:depth]
        stack.append(name)
        base_path = " > ".join(stack)
        occurrence = path_counts.get(base_path, 0) + 1
        path_counts[base_path] = occurrence
        unique_path = base_path if occurrence == 1 else f"{base_path} [{occurrence}]"

        first_by_base_path.setdefault(base_path, duration_ms)
        timings.append(
            {
                "name": name,
                "base_path": base_path,
                "path": unique_path,
                "depth": depth,
                "duration_ms": duration_ms,
                "line": line_number,
            }
        )

    if program_proved_ms is None and "prove_program_sync" in first_by_base_path:
        program_proved_ms = first_by_base_path["prove_program_sync"]

    if program_proved_ms is None:
        raise ValueError("Could not find the overall prove time in the benchmark log.")

    key_metrics = {
        label: first_by_base_path[path]
        for path, label in KEY_METRICS
        if path in first_by_base_path
    }

    return {
        "program_proved_ms": program_proved_ms,
        "timings": timings,
        "timings_by_base_path": first_by_base_path,
        "key_metrics": key_metrics,
    }


def parse_log_file(
    log_path: Path,
    *,
    repo_root: Path | None,
    git_ref: str | None,
    build_wall_ms: float | None,
    prove_wall_ms: float | None,
    rayon_num_threads: int | None,
) -> dict[str, Any]:
    parsed = parse_log_contents(log_path.read_text(encoding="utf-8"))
    metadata = {
        "log_path": str(log_path),
        "git_ref": git_ref or "",
        "rayon_num_threads": rayon_num_threads,
        "build_wall_ms": build_wall_ms,
        "prove_wall_ms": prove_wall_ms,
    }
    if repo_root is not None:
        metadata["repo_root"] = str(repo_root)
        metadata["git_sha"] = current_sha(repo_root)
    return {**metadata, **parsed}


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def format_ms(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:,.2f} ms"


def format_delta(value: float) -> str:
    sign = "+" if value >= 0 else ""
    return f"{sign}{value:,.2f} ms"


def format_pct(value: float | None) -> str:
    if value is None:
        return "n/a"
    sign = "+" if value >= 0 else ""
    return f"{sign}{value:.2f}%"


def percent_delta(current: float | None, baseline: float | None) -> float | None:
    if baseline in (None, 0) or current is None:
        return None
    return ((current - baseline) / baseline) * 100.0


def format_optional_delta(current: float | None, baseline: float | None) -> str:
    if current is None or baseline is None:
        return "n/a"
    return format_delta(current - baseline)


def build_stage_rows(
    baseline: dict[str, Any],
    current: dict[str, Any],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    baseline_metrics = baseline.get("key_metrics", {})
    current_metrics = current.get("key_metrics", {})

    for _, label in KEY_METRICS:
        baseline_ms = baseline_metrics.get(label)
        current_ms = current_metrics.get(label)
        if baseline_ms is None or current_ms is None:
            continue
        delta_ms = current_ms - baseline_ms
        delta_pct = percent_delta(current_ms, baseline_ms)
        rows.append(
            {
                "stage": label,
                "baseline_ms": baseline_ms,
                "current_ms": current_ms,
                "delta_ms": delta_ms,
                "delta_pct": delta_pct,
            }
        )

    return rows


def compare_results(
    baseline: dict[str, Any],
    current: dict[str, Any],
    threshold_pct: float,
) -> dict[str, Any]:
    baseline_total = baseline["program_proved_ms"]
    current_total = current["program_proved_ms"]
    delta_ms = current_total - baseline_total
    delta_pct = percent_delta(current_total, baseline_total)
    regression = bool(delta_pct is not None and delta_pct > threshold_pct)
    stage_rows = build_stage_rows(baseline, current)

    slowdown_rows = [
        row
        for row in stage_rows
        if row["delta_pct"] is not None
        and row["delta_pct"] > 0
        and row["stage"] != "prove_program_sync"
    ]
    slowdown_rows.sort(key=lambda row: row["delta_pct"], reverse=True)

    result = {
        "status": "regression" if regression else "ok",
        "regression": regression,
        "threshold_pct": threshold_pct,
        "baseline_sha": baseline.get("git_sha", ""),
        "current_sha": current.get("git_sha", ""),
        "baseline_ref": baseline.get("git_ref", ""),
        "current_ref": current.get("git_ref", ""),
        "baseline_program_proved_ms": baseline_total,
        "current_program_proved_ms": current_total,
        "program_delta_ms": delta_ms,
        "program_delta_pct": delta_pct,
        "baseline_build_wall_ms": baseline.get("build_wall_ms"),
        "current_build_wall_ms": current.get("build_wall_ms"),
        "baseline_prove_wall_ms": baseline.get("prove_wall_ms"),
        "current_prove_wall_ms": current.get("prove_wall_ms"),
        "stage_rows": stage_rows,
        "top_slowdowns": slowdown_rows[:5],
    }
    return result


def summary_markdown(result: dict[str, Any]) -> str:
    status_word = "REGRESSION" if result["regression"] else "OK"
    baseline_sha = result["baseline_sha"][:12] or result["baseline_ref"] or "baseline"
    current_sha = result["current_sha"][:12] or result["current_ref"] or "current"
    stage_rows = result["stage_rows"]
    top_slowdowns = result["top_slowdowns"]

    lines = [
        "## Blake3 1-to-1 Non-Regression",
        "",
        f"Status: **{status_word}**",
        f"Threshold: `{result['threshold_pct']:.2f}%`",
        f"Baseline: `{baseline_sha}` ({format_ms(result['baseline_program_proved_ms'])})",
        f"Current: `{current_sha}` ({format_ms(result['current_program_proved_ms'])})",
        f"Overall delta: `{format_delta(result['program_delta_ms'])}` ({format_pct(result['program_delta_pct'])})",
        "",
        "| Metric | Baseline | Current | Delta | Delta % |",
        "| --- | ---: | ---: | ---: | ---: |",
        (
            "| build wall | "
            f"{format_ms(result['baseline_build_wall_ms'])} | "
            f"{format_ms(result['current_build_wall_ms'])} | "
            f"{format_optional_delta(result['current_build_wall_ms'], result['baseline_build_wall_ms'])} | "
            f"{format_pct(percent_delta(result['current_build_wall_ms'], result['baseline_build_wall_ms']))} |"
        ),
        (
            "| prove wall | "
            f"{format_ms(result['baseline_prove_wall_ms'])} | "
            f"{format_ms(result['current_prove_wall_ms'])} | "
            f"{format_optional_delta(result['current_prove_wall_ms'], result['baseline_prove_wall_ms'])} | "
            f"{format_pct(percent_delta(result['current_prove_wall_ms'], result['baseline_prove_wall_ms']))} |"
        ),
        (
            "| program proved | "
            f"{format_ms(result['baseline_program_proved_ms'])} | "
            f"{format_ms(result['current_program_proved_ms'])} | "
            f"{format_delta(result['program_delta_ms'])} | "
            f"{format_pct(result['program_delta_pct'])} |"
        ),
    ]

    if stage_rows:
        lines.extend(
            [
                "",
                "| Stage | Baseline | Current | Delta | Delta % |",
                "| --- | ---: | ---: | ---: | ---: |",
            ]
        )
        for row in stage_rows:
            lines.append(
                "| "
                f"{row['stage']} | "
                f"{format_ms(row['baseline_ms'])} | "
                f"{format_ms(row['current_ms'])} | "
                f"{format_delta(row['delta_ms'])} | "
                f"{format_pct(row['delta_pct'])} |"
            )

    if top_slowdowns:
        lines.extend(["", "Top slowdowns:"])
        for row in top_slowdowns:
            lines.append(
                "- "
                f"`{row['stage']}` moved by {format_delta(row['delta_ms'])} "
                f"({format_pct(row['delta_pct'])})."
            )

    return "\n".join(lines) + "\n"


def write_github_output(path: Path, result: dict[str, Any]) -> None:
    lines = [
        f"status={result['status']}",
        f"regression={'true' if result['regression'] else 'false'}",
        f"baseline_sha={result['baseline_sha']}",
        f"current_sha={result['current_sha']}",
        f"program_delta_ms={result['program_delta_ms']:.6f}",
        f"program_delta_pct={result['program_delta_pct']:.6f}",
    ]
    with path.open("a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def cmd_parse_log(args: argparse.Namespace) -> int:
    payload = parse_log_file(
        args.log,
        repo_root=args.repo_root,
        git_ref=args.git_ref,
        build_wall_ms=args.build_wall_ms,
        prove_wall_ms=args.prove_wall_ms,
        rayon_num_threads=args.rayon_num_threads,
    )
    write_json(args.output, payload)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    repo_root = args.repo_root.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    build_log = output_dir / "build.log"
    prove_log = output_dir / "prove.log"
    result_json = output_dir / "result.json"

    run_logged_command(["cargo", "clean"], cwd=repo_root, env=os.environ.copy(), log_path=output_dir / "clean.log")
    build_wall_ms = run_logged_command(
        ["make", "exec-info"],
        cwd=repo_root,
        env=os.environ.copy(),
        log_path=build_log,
    )

    prove_env = os.environ.copy()
    prove_env["MIDEN_LOG"] = "info"
    prove_env["RAYON_NUM_THREADS"] = str(args.rayon_num_threads)
    prove_wall_ms = run_logged_command(
        BENCHMARK_COMMAND,
        cwd=repo_root,
        env=prove_env,
        log_path=prove_log,
    )

    payload = parse_log_file(
        prove_log,
        repo_root=repo_root,
        git_ref=args.git_ref,
        build_wall_ms=build_wall_ms,
        prove_wall_ms=prove_wall_ms,
        rayon_num_threads=args.rayon_num_threads,
    )
    write_json(result_json, payload)
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


def main() -> int:
    args = parse_args()
    if args.command == "parse-log":
        return cmd_parse_log(args)
    if args.command == "run":
        return cmd_run(args)
    if args.command == "compare":
        return cmd_compare(args)
    raise ValueError(f"Unhandled command: {args.command}")


if __name__ == "__main__":
    sys.exit(main())
