#!/usr/bin/env python3
"""Check each no_std library without workspace feature unification."""

import argparse
import json
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="wasm32v1-none")
    args = parser.parse_args()
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
        text=True,
    ))
    packages = sorted(
        package["name"]
        for package in metadata["packages"]
        if package["id"] in metadata["workspace_members"]
        and any(
            any(kind in ("lib", "rlib", "dylib", "cdylib", "staticlib") for kind in target["kind"])
            and "no_std" in Path(target["src_path"]).read_text()
            for target in package["targets"]
        )
    )
    if not packages:
        raise SystemExit("No no_std libraries found")
    failed = []
    for package in packages:
        print(f"Checking {package} without std on {args.target}", flush=True)
        result = subprocess.run([
            "cargo", "check", "--locked", "--package", package, "--lib",
            "--no-default-features", "--target", args.target,
        ])
        if result.returncode:
            failed.append(package)
    if failed:
        raise SystemExit(f"no_std checks failed: {', '.join(failed)}")
    print(f"Checked {len(packages)} no_std libraries")


if __name__ == "__main__":
    main()
