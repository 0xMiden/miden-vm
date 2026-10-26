"""Compare full service latency with native proving at the same revision.

The 5% overhead budget is advisory until CI noise has been measured. Use --enforce
to reject confirmed regressions. Missing or malformed measurements always fail.
"""

import argparse
import json
import math
import os
from pathlib import Path
import subprocess
import tempfile

BUDGET = 1.05


def read_estimate(directory, axis):
    estimate = json.loads((directory / "tiny_proof" / axis / "new/estimates.json").read_text())["mean"]
    interval = estimate["confidence_interval"]
    values = (estimate["point_estimate"], interval["lower_bound"], interval["upper_bound"])
    if any(type(value) not in (int, float) or not math.isfinite(value) for value in values):
        raise ValueError(f"Invalid {axis} estimate: {values}")
    point, lower, upper = values
    if not 0 < lower <= point <= upper or interval["confidence_level"] != 0.95:
        raise ValueError(f"Invalid {axis} confidence interval: {interval}")
    return values


def compare(native, grpc):
    # Marginal bounds provide a decision margin, not a confidence interval for the ratio.
    return grpc[0] / native[0], grpc[1] > BUDGET * native[2]


def format_estimate(estimate):
    point, lower, upper = (value / 1_000_000 for value in estimate)
    return f"{point:.2f} [{lower:.2f}, {upper:.2f}]"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument("--enforce", action="store_true")
    args = parser.parse_args(argv)
    args.results.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="run-", dir=args.results)).resolve()
    repository = Path(__file__).resolve().parents[1]
    command = ["cargo", "bench", "--locked", "--profile", "optimized",
               "-p", "miden-prover-service", "--bench", "proving_service"]
    env = {**os.environ, "RAYON_NUM_THREADS": "8"}
    # GNU timeout covers the process group, including Cargo's compiler and benchmark children.
    subprocess.run(["timeout", "--kill-after=10s", "1800s", *command, "--no-run"],
                   cwd=repository, env=env, check=True)
    lines = ["# Proving service performance", "",
             "Times are milliseconds with Criterion's 95% marginal intervals. Budget: RPC/native <= 1.05.", "",
             "| Order | Native | RPC | RPC/native | Clear breach |",
             "| --- | --- | --- | --- | --- |"]
    breaches = []
    for label, axes in [("forward", ("native", "grpc")), ("reverse", ("grpc", "native"))]:
        output = directory / label
        env["CRITERION_HOME"] = str(output)
        for axis in axes:
            subprocess.run(["timeout", "--kill-after=10s", "600s", *command,
                            "--", f"tiny_proof/{axis}", "--exact", "--noplot"],
                           cwd=repository, env=env, check=True)
        native = read_estimate(output, "native")
        grpc = read_estimate(output, "grpc")
        ratio, clear = compare(native, grpc)
        breaches.append(clear)
        lines.append(f"| {label} | {format_estimate(native)} | {format_estimate(grpc)} | {ratio:.3f} | {clear} |")
        if label == "forward" and ratio <= BUDGET:
            break
    regression = len(breaches) == 2 and all(breaches)
    status = "Point estimate within budget"
    if len(breaches) == 2:
        status = "Confirmed regression" if regression else "Inconclusive breach"
    lines.extend(["", f"{status}. Enforcement is {'enabled' if args.enforce else 'advisory'}.", ""])
    summary = "\n".join(lines)
    (directory / "summary.md").write_text(summary)
    print(summary)
    print(f"Results: {directory}")
    if len(breaches) == 2:
        print(f"::warning::{status}; inspect the timing intervals and raw results.")
    return int(regression and args.enforce)


if __name__ == "__main__":
    raise SystemExit(main())
