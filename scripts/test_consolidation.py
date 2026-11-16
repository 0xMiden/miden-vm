#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["tree-sitter==0.26.1", "tree-sitter-rust==0.24.2"]
# ///
"""Collect and compare the field-library coverage used to verify test removals.

Run with uv run scripts/test_consolidation.py --help. Reports are comparable only
with identical production sources and verification configuration. This focused
collector does not replace scripts/coverage.sh's exhaustive workspace collection.
"""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import unittest

from tree_sitter import Language, Parser
import tree_sitter_rust

PREFIXES = ("crates/field/src/", "crates/serde-utils/src/")
SCHEMA = 1


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    with path.open("x") as destination:
        json.dump(value, destination, indent=2)
        destination.write("\n")


def source_inventory(root):
    """Hash production text and identify complete Rust test/generator modules."""
    parser = Parser(Language(tree_sitter_rust.language()))
    inventory = {}
    for prefix in PREFIXES:
        for path in sorted((root / prefix).rglob("*.rs")):
            relative = path.relative_to(root).as_posix()
            if path.name == "tests.rs" or "tests" in path.relative_to(root).parts:
                continue
            source = path.read_bytes()
            tree = parser.parse(source)
            if tree.root_node.has_error:
                raise ValueError(f"Rust source cannot be parsed: {relative}")
            excluded = []
            stack = [tree.root_node]
            while stack:
                node = stack.pop()
                if node.type == "mod_item":
                    name = node.child_by_field_name("name").text.decode()
                    attributes = []
                    sibling = node.prev_named_sibling
                    while sibling and sibling.type in ("attribute_item", "line_comment", "block_comment"):
                        if sibling.type == "attribute_item":
                            attributes.append("".join(sibling.text.decode().split()))
                        sibling = sibling.prev_named_sibling
                    test_only = any(a.startswith(("#[cfg(test)]", "#[cfg(all(test,")) for a in attributes)
                    generator = name == "arbitrary" and any('feature="arbitrary"' in a for a in attributes)
                    if test_only or generator:
                        excluded.append(node)
                        continue
                stack.extend(node.named_children)
            excluded.sort(key=lambda node: node.start_byte)
            chunks, offset = [], 0
            for node in excluded:
                chunks.append(source[offset:node.start_byte])
                offset = node.end_byte
            chunks.append(source[offset:])
            inventory[relative] = {
                "production_sha256": sha256(b"".join(chunks)),
                "excluded_spans": [
                    [node.start_point.row + 1, node.start_point.column + 1,
                     node.end_point.row + 1, node.end_point.column + 1]
                    for node in excluded
                ],
            }
    return inventory


def source_path(filename, root):
    path = Path(filename)
    if path.is_absolute():
        try:
            path = path.relative_to(root)
        except ValueError:
            return None
    if ".." in path.parts:
        raise ValueError(f"Coverage path escapes workspace: {filename}")
    return path.as_posix()


def excluded_point(source, line, column):
    return any((sl, sc) <= (line, column) < (el, ec)
               for sl, sc, el, ec in source["excluded_spans"])


def locations(llvm, lcov, root, sources, *, mapping_baseline=None, allow_uncovered=False):
    if llvm.get("type") != "llvm.coverage.json.export" or len(llvm.get("data", [])) != 1:
        raise ValueError("Expected one complete LLVM coverage export")
    data = llvm["data"][0]
    if not data.get("functions") or not data.get("files"):
        raise ValueError("Coverage export has no functions or files")
    mapped_regions, covered_regions = set(), set()
    for function in data["functions"]:
        filenames = [source_path(name, root) for name in function["filenames"]]
        for region in function["regions"]:
            sl, sc, el, ec, count, file_id, expanded_id, kind = region
            if kind not in (0, 1):  # Code and macro-expansion regions, excluding gaps.
                continue
            filename = filenames[file_id]
            if filename not in sources:
                continue
            if excluded_point(sources[filename], sl, sc):
                continue
            if (sl, sc) >= (el, ec):
                continue
            expanded = filenames[expanded_id] if kind == 1 else None
            key = (filename, sl, sc, el, ec, kind, expanded)
            mapped_regions.add(key)
            if count > 0:
                covered_regions.add(key)
    json_files = {source_path(f["filename"], root): f for f in data["files"]}
    mapped_lines, covered_lines, lcov_files = set(), set(), set()
    filename = None
    active = False
    totals = {}
    for line in lcov.splitlines():
        if line.startswith("SF:"):
            if active:
                raise ValueError("LCOV record has no end_of_record marker")
            filename = source_path(line[3:], root)
            if filename in sources and filename not in json_files:
                raise ValueError("LLVM JSON and LCOV file inventories disagree")
            active, totals = True, {}
        elif line == "end_of_record":
            if not active:
                raise ValueError("LCOV end_of_record has no source file")
            if filename in sources:
                if set(totals) != {"LF", "LH"}:
                    raise ValueError(f"Incomplete LCOV line totals: {filename}")
                summary = json_files.get(filename, {}).get("summary", {}).get("lines", {})
                # LLVM's native summaries may differ from the number of DA rows.
                # Compare export summaries before folding physical source locations.
                if summary.get("count") != totals["LF"] or summary.get("covered") != totals["LH"]:
                    raise ValueError(f"LLVM JSON and LCOV line totals disagree: {filename}")
                lcov_files.add(filename)
            active, filename = False, None
        elif line.startswith(("LF:", "LH:")):
            totals[line[:2]] = int(line[3:])
        elif line.startswith("DA:"):
            if not active:
                raise ValueError("LCOV line has no source file")
            number, count, *_ = line[3:].split(",")
            number, count = int(number), int(count)
            if filename not in sources:
                continue
            if any(sl <= number <= el for sl, _, el, _ in sources[filename]["excluded_spans"]):
                continue
            key = (filename, number)
            mapped_lines.add(key)
            if count > 0:
                covered_lines.add(key)
    if active:
        raise ValueError("LCOV record has no end_of_record marker")
    if not allow_uncovered and (not covered_lines or not covered_regions):
        raise ValueError("No covered production lines or regions")
    measured_files = {key[0] for key in mapped_lines}
    region_files = {key[0] for key in mapped_regions}
    scoped_json_files = json_files.keys() & sources.keys()
    if measured_files != region_files or lcov_files != scoped_json_files:
        raise ValueError("LLVM JSON and LCOV file inventories disagree")
    required = {"crates/field/src/word/mod.rs", "crates/field/src/native/mod.rs"}
    if not required <= measured_files:
        raise ValueError("Required field source mappings are missing")
    result = {
        "mapped_lines": sorted(mapped_lines), "covered_lines": sorted(covered_lines),
        "mapped_regions": sorted(mapped_regions), "covered_regions": sorted(covered_regions),
    }
    if mapping_baseline is not None:
        # Both measured exports can omit the same function or file. Read the
        # expected denominator from the binary without consulting its profiles.
        expected = locations(*mapping_baseline, root, sources, allow_uncovered=True)
        for kind in ("lines", "regions"):
            if result[f"mapped_{kind}"] != expected[f"mapped_{kind}"]:
                raise ValueError(f"Coverage {kind} mappings differ from the instrumented binary")
    return result


def compare(before, after):
    for report in (before, after):
        if report.get("schema") != SCHEMA or report.get("complete") is not True:
            raise ValueError("Incomplete or unsupported coverage report")
        for kind in ("lines", "regions"):
            mapped = set(map(tuple, report["locations"][f"mapped_{kind}"]))
            covered = set(map(tuple, report["locations"][f"covered_{kind}"]))
            if not mapped or not covered or not covered <= mapped:
                raise ValueError(f"Invalid {kind} inventory")
        if ({location[0] for location in report["locations"]["mapped_lines"]}
                != {location[0] for location in report["locations"]["mapped_regions"]}):
            raise ValueError("Line and region file inventories disagree")
    if before["configuration"] != after["configuration"]:
        raise ValueError("Verification configurations differ")
    if before["production_sources"] != after["production_sources"]:
        raise ValueError("Production sources differ; locations cannot be aligned")
    changes = {}
    for kind in ("lines", "regions"):
        for state in ("mapped", "covered"):
            key = f"{state}_{kind}"
            old = set(map(tuple, before["locations"][key]))
            new = set(map(tuple, after["locations"][key]))
            changes[f"lost_{key}"] = sorted(old - new)
            changes[f"gained_{key}"] = sorted(new - old)
    changes["accepted"] = not any(value for key, value in changes.items() if key.startswith("lost_"))
    return changes


def collect(args):
    root = args.root.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "build-profiles").mkdir()
    started = time.monotonic()
    env = dict(os.environ)
    # Make random verification independent of persisted failures and ambient settings.
    for name in list(env):
        if name.startswith("PROPTEST_"):
            del env[name]
        if name.startswith(("CARGO_LLVM_COV", "__CARGO_LLVM_COV")):
            del env[name]
    env.update({
        "CARGO_TARGET_DIR": str(output / "build"),
        "CARGO_BUILD_BUILD_DIR": str(output / "build"),
        "CARGO_LLVM_COV_TARGET_DIR": str(output / "build"),
        "CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "4", "RUSTC_WRAPPER": "",
        "PROPTEST_RNG_SEED": str(args.seed), "PROPTEST_CASES": str(args.cases),
        "PROPTEST_DISABLE_FAILURE_PERSISTENCE": "1",
    })
    sources = source_inventory(root)
    inputs = {p.relative_to(root).as_posix(): sha256(p.read_bytes())
              for prefix in PREFIXES for p in (root / prefix).rglob("*.rs")}
    collector_sha256 = sha256(Path(__file__).read_bytes())
    configuration = {
        "test_scope": "miden-field library", "features": ["arbitrary"],
        "profile": "test-dev", "seed": args.seed, "cases": args.cases,
        "failure_persistence": False,
        "collector_sha256": collector_sha256,
        "source_parser": {name: importlib.metadata.version(name)
                          for name in ("tree-sitter", "tree-sitter-rust")},
        "manifests": {name: sha256((root / name).read_bytes()) for name in (
            "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".cargo/config.toml", ".config/nextest.toml",
            "crates/field/Cargo.toml", "crates/serde-utils/Cargo.toml",
            "crates/test-serialization-macros/Cargo.toml",
            "crates/test-serialization-macros/src/lib.rs",
        )},
        "rustflags": env.get("RUSTFLAGS", ""),
        "encoded_rustflags": env.get("CARGO_ENCODED_RUSTFLAGS", ""),
    }
    timings = []
    with (output / "commands.log").open("x") as log:
        def run(command, *, capture=False):
            log.write(json.dumps(command) + "\n")
            log.flush()
            result = subprocess.run(command, cwd=root, env=env, text=True,
                                    stdout=subprocess.PIPE if capture else log, stderr=log)
            if result.returncode:
                raise RuntimeError(f"Command failed ({result.returncode}): {command}; see {output}")
            return result.stdout

        for key, command in (("rustc", ["rustc", "-Vv"]),
                             ("llvm_cov", ["cargo", "llvm-cov", "--version"]),
                             ("nextest", ["cargo", "nextest", "--version"])):
            configuration[key] = run(command, capture=True).strip()
        script = run(["cargo", "llvm-cov", "show-env", "--sh", "--remap-path-prefix"], capture=True)
        (output / "instrumentation.sh").write_text(script)
        exports = run(["bash", "-c", 'source "$1"; env -0', "coverage", str(output / "instrumentation.sh")], capture=True)
        env.update(item.split("=", 1) for item in exports.split("\0") if item)
        configuration["instrumentation_flags"] = {
            key: env.get(key, "").replace(str(root), "$WORKSPACE").replace(str(output), "$OUTPUT")
            for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "__CARGO_LLVM_COV_RUSTC_WRAPPER_RUSTFLAGS")
        }
        env["LLVM_PROFILE_FILE"] = str(output / "build-profiles" / "coverage-%p-%m.profraw")
        selection = ["--locked", "-p", "miden-field", "--features", "arbitrary", "--lib",
                     "--cargo-profile", "test-dev", "--ignore-default-filter"]
        phase = time.monotonic()
        tests = json.loads(run(["cargo", "nextest", "list", *selection, "--message-format", "json"], capture=True))
        timings.append({"phase": "build_and_inventory", "seconds": time.monotonic() - phase})
        suites = list(tests["rust-suites"].values())
        if len(suites) != 1 or suites[0]["kind"] != "lib" or suites[0]["package-name"] != "miden-field":
            raise ValueError("Expected exactly the field library test binary")
        write_json(output / "tests.json", tests)
        llvm_cov = env.get("LLVM_COV") or str(
            Path(run(["rustc", "--print", "target-libdir"], capture=True).strip()).parent / "bin/llvm-cov")
        configuration["mapping_inventory_tool"] = run([llvm_cov, "--version"], capture=True).strip()
        # An empty profile retains unexecuted mappings and cannot inherit a
        # missing record from the measured profile data.
        for flags, name in (([], "mapping-baseline.json"), (["--format=lcov"], "mapping-baseline.lcov")):
            exported = run([llvm_cov, "export", suites[0]["binary-path"], "--empty-profile", *flags], capture=True)
            (output / name).write_text(exported)
        env["LLVM_PROFILE_FILE"] = str(output / "build" / "coverage-%p-%m.profraw")
        phase = time.monotonic()
        run(["cargo", "nextest", "run", *selection, "--no-fail-fast", "--no-tests=fail"])
        timings.append({"phase": "tests", "seconds": time.monotonic() - phase})
        report = ["cargo", "llvm-cov", "report", "--profile", "test-dev", "-p", "miden-field",
                  "-p", "miden-serde-utils", "--remap-path-prefix"]
        phase = time.monotonic()
        for flag, name in (("--json", "coverage.json"), ("--lcov", "coverage.lcov"),
                           ("--cobertura", "coverage.xml")):
            run([*report, flag, "--output-path", str(output / name)])
        timings.append({"phase": "exports", "seconds": time.monotonic() - phase})
    diagnostics = (output / "commands.log").read_text()
    if re.search(r"mismatched data|hash-mismatch|malformed instrumentation|profile.*corrupt", diagnostics, re.I):
        raise ValueError("LLVM profile diagnostics prevent comparison")
    current_inputs = {p.relative_to(root).as_posix(): sha256(p.read_bytes())
                      for prefix in PREFIXES for p in (root / prefix).rglob("*.rs")}
    if inputs != current_inputs or collector_sha256 != sha256(Path(__file__).read_bytes()):
        raise ValueError("Source or collector changed during collection")
    llvm = json.loads((output / "coverage.json").read_text())
    result = {
        "schema": SCHEMA, "complete": True, "configuration": configuration,
        "production_sources": {name: value["production_sha256"] for name, value in sources.items()},
        "source_inventory": sources,
        "locations": locations(
            llvm, (output / "coverage.lcov").read_text(), root, sources,
            mapping_baseline=(json.loads((output / "mapping-baseline.json").read_text()),
                              (output / "mapping-baseline.lcov").read_text())),
        "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "elapsed_seconds": time.monotonic() - started,
        "timings": timings,
        "test_count": tests["test-count"],
        "input_sha256": inputs,
        "explicit_case_configs": [
            {"file": str(p.relative_to(root)), "line": index, "source": line.strip()}
            for p in [*(root / "crates/field/src").rglob("*.rs"),
                      root / "crates/test-serialization-macros/src/lib.rs"]
            for index, line in enumerate(p.read_text().splitlines(), 1)
            if "proptest_config" in line or re.search(r"\bcases\s*:", line)
        ],
    }
    write_json(output / "comparison.json", result)
    print(json.dumps({"output": str(output), "tests": result["test_count"],
                      "covered_lines": len(result["locations"]["covered_lines"]),
                      "covered_regions": len(result["locations"]["covered_regions"])}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    collector = commands.add_parser("collect", help="Collect a fresh field-library report")
    collector.add_argument("output", type=Path)
    collector.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    collector.add_argument("--seed", type=int, required=True)
    collector.add_argument("--cases", type=int, default=256)
    comparison = commands.add_parser("compare", help="Reject any lost production coverage or mappings")
    comparison.add_argument("before", type=Path)
    comparison.add_argument("after", type=Path)
    commands.add_parser("check-controls", help="Run coverage and mutation gate controls")
    args = parser.parse_args()
    try:
        if args.command == "collect":
            if args.seed < 0 or args.cases < 1:
                parser.error("Seed must be nonnegative and case budget must be positive")
            collect(args)
        elif args.command == "compare":
            result = compare(json.loads(args.before.read_text()), json.loads(args.after.read_text()))
            print(json.dumps(result, indent=2))
            return 0 if result["accepted"] else 1
        else:
            suite = unittest.defaultTestLoader.discover(
                str(Path(__file__).parent / "test_consolidation_tests"))
            return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
