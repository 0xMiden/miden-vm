#!/usr/bin/env python3
"""Compare fresh cargo-mutants runs before accepting a test removal.

Each directory contains mutants.json, outcomes.json, logs and verification.json.
The latter records schema=1, configuration (seed, cases, tool versions, features,
profile and command options), and production_sources from focused coverage.
Compile failures and timeouts prevent acceptance. Caught results require a
successful build and a nextest test failure with an actual Rust panic in its log.
"""
import argparse
import json
from pathlib import Path
import re
import sys


def load_run(directory):
    metadata = json.loads((directory / "verification.json").read_text())
    if metadata.get("schema") != 1 or not metadata.get("configuration") or not metadata.get("production_sources"):
        raise ValueError("Missing mutation verification configuration or source hashes")
    inventory = json.loads((directory / "mutants.json").read_text())
    names = {mutant["name"] for mutant in inventory}
    if not names or len(names) != len(inventory):
        raise ValueError("Empty or duplicate mutation inventory")
    results = json.loads((directory / "outcomes.json").read_text())
    if not results.get("end_time"):
        raise ValueError("Mutation run has not finished")
    outcomes, baseline = {}, []
    for outcome in results["outcomes"]:
        if outcome["scenario"] == "Baseline":
            baseline.append(outcome)
            continue
        name = outcome["scenario"]["Mutant"]["name"]
        if name in outcomes:
            raise ValueError(f"Duplicate mutation outcome: {name}")
        outcomes[name] = outcome
    if len(baseline) != 1 or baseline[0]["summary"] != "Success":
        raise ValueError("A successful fresh unmutated baseline is required")
    baseline_phases = {phase["phase"]: phase["process_status"]
                       for phase in baseline[0]["phase_results"]}
    if baseline_phases != {"Build": "Success", "Test": "Success"}:
        raise ValueError("Unmutated build and tests must both succeed")
    if set(outcomes) != names or results["total_mutants"] != len(names):
        raise ValueError("Mutation outcomes do not match the complete inventory")
    caught, missed, inconclusive = set(), set(), set()
    for name, outcome in outcomes.items():
        phases = {phase["phase"]: phase for phase in outcome["phase_results"]}
        built = phases.get("Build", {}).get("process_status") == "Success"
        tested = phases.get("Test", {}).get("process_status")
        if outcome["summary"] == "MissedMutant" and built and tested == "Success":
            missed.add(name)
        elif outcome["summary"] == "CaughtMutant" and built and tested == {"Failure": 100}:
            log_path = (directory / outcome["log_path"]).resolve()
            if not log_path.is_relative_to(directory.resolve()):
                raise ValueError("Mutation log escapes the results directory")
            log = log_path.read_text()
            if re.search(r"panicked at|Test failed:", log):
                caught.add(name)
            else:
                inconclusive.add(name)
        else:
            inconclusive.add(name)
    return metadata, inventory, caught, missed, inconclusive


def compare_runs(before_directory, after_directory):
    before, old_inventory, old_caught, old_missed, old_inconclusive = load_run(before_directory)
    after, new_inventory, new_caught, new_missed, new_inconclusive = load_run(after_directory)
    if before != after:
        raise ValueError("Mutation configurations or production sources differ")
    if old_inventory != new_inventory:
        raise ValueError("The reviewed mutation corpus differs")
    lost = sorted(old_caught - new_caught)
    return {
        "accepted": not (lost or old_inconclusive or new_inconclusive),
        "lost_detections": lost,
        "existing_gaps": sorted(old_missed & new_missed),
        "new_detections": sorted(new_caught - old_caught),
        "before_inconclusive": sorted(old_inconclusive),
        "after_inconclusive": sorted(new_inconclusive),
        "before_caught": len(old_caught), "after_caught": len(new_caught),
        "total_mutants": len(old_inventory),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    args = parser.parse_args()
    try:
        result = compare_runs(args.before, args.after)
        print(json.dumps(result, indent=2))
        return 0 if result["accepted"] else 1
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
