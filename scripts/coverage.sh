#!/usr/bin/env bash
# Collect all workspace Rust tests and debugger fixtures with LLVM instrumentation.
set -euo pipefail
SECONDS=0
if [[ ${1:-} == --snapshot ]]; then
    root=$2
    output=$3
else
    tools=$(cd "$(dirname "$0")" && pwd)
    root=${COVERAGE_WORKSPACE:-$(cd "$tools/.." && pwd)}
    mkdir -p "$root/target/coverage-workspace"
    output=$(mktemp -d "$root/target/coverage-workspace/run.XXXXXX")
    cp "$0" "$output/collector.sh"
    cp "$tools/coverage-nextest.toml" "$output/nextest.toml"
    exec bash "$output/collector.sh" --snapshot "$root" "$output"
fi
export COVERAGE_OUTPUT="$output"
export CARGO_TARGET_DIR="$output/build" CARGO_BUILD_BUILD_DIR="$output/build"
export CARGO_LLVM_COV_TARGET_DIR="$output/build"
export CARGO_INCREMENTAL=0 RUST_MIN_STACK=16777216
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4} RAYON_NUM_THREADS=${RAYON_NUM_THREADS:-4}
export PROPTEST_RNG_SEED=0 RUSTC_WRAPPER=''
export MIDEN_COVERAGE_PROOF_TIMEOUT_SECS=${MIDEN_COVERAGE_PROOF_TIMEOUT_SECS:-600}
export RUSTC_BOOTSTRAP=1 MIDEN_BUILD_LIB_DOCS=1
export PYO3_PYTHON=${PYO3_PYTHON:-python3.14}
if [[ $(uname -s) == Darwin && -z ${LIBCLANG_PATH:-} ]]; then
    export LIBCLANG_PATH=/opt/homebrew/opt/llvm/lib
fi
printf 'Coverage output: %s\n' "$output"
cd "$root"
{
    git rev-parse HEAD
    git diff --stat
    uname -sm
    printf 'Scope: all workspace packages; unit, binary, integration, documentation and debugger lit tests\n'
    printf 'Features: --all-features; normal Rust ignore policy; no package or test filters\n'
    printf 'Profile: test-dev; Nextest: coverage; Proptest seed: 0; no collection deadline\n'
    printf 'Build jobs: %s; Rayon threads per process: %s\n' "$CARGO_BUILD_JOBS" "$RAYON_NUM_THREADS"
    printf 'Success-path service proof budget: %ss (explicit deadline tests unchanged)\n' "$MIDEN_COVERAGE_PROOF_TIMEOUT_SECS"
    printf 'Reports include reachable workspace dependencies and inline test code.\n'
} > "$output/context.txt"
set +e
bash -s 2>&1 <<'COLLECT' | tee "$output/collection.log"
set -euo pipefail
output=$COVERAGE_OUTPUT
phase() {
    local label=$1 started=$SECONDS status=0
    shift
    "$@" || status=$?
    printf '%s\t%ss\texit=%s\n' "$label" "$((SECONDS - started))" "$status" >> "$output/timings.txt"
    return "$status"
}
{
    rustc -Vv
    cargo llvm-cov --version
    cargo nextest --version
} >> "$output/context.txt"
command -v protoc
command -v litcheck
command -v "$PYO3_PYTHON"
phase setup cargo llvm-cov show-env --sh --coverage-host-only --doctests --remap-path-prefix > "$output/instrumentation.sh"
# The generated file contains only exports produced by cargo-llvm-cov.
# shellcheck disable=SC1091
source "$output/instrumentation.sh"
# Separate process profiles, with four merge slots per instrumented binary.
export LLVM_PROFILE_FILE="$output/build/coverage-%p-%4m.profraw"
phase metadata cargo metadata --locked --all-features --no-deps --format-version 1 > "$output/workspace.json"
args=(--locked --workspace --all-features --tests
      --cargo-profile test-dev --profile coverage --ignore-default-filter
      --tool-config-file "miden-coverage:$output/nextest.toml")
phase build cargo nextest run "${args[@]}" --no-run
phase inventory cargo nextest list "${args[@]}" --message-format json > "$output/tests.json"
test_status=0
phase tests cargo nextest run "${args[@]}" --no-fail-fast --no-tests=fail || test_status=$?
phase doctests cargo test --locked --workspace --all-features --profile test-dev --doc --no-fail-fast || test_status=$?
phase binaries cargo build --locked --workspace --all-features --bins --profile test-dev || test_status=$?
phase fixtures litcheck lit run --verbose --path "$CARGO_TARGET_DIR/test-dev" crates/debugger/tests/lit || test_status=$?
exit "$test_status"
COLLECT
status=$?
export COVERAGE_COLLECTION_STATUS=$status
bash -s 2>&1 <<'REPORT' | tee -a "$output/collection.log"
set -euo pipefail
output=$COVERAGE_OUTPUT
mkdir "$output/diagnostic"
: > "$output/coverage-warnings.log"
trap 'cat "$output/coverage-warnings.log" >&2' EXIT
report=(cargo llvm-cov report --profile test-dev --doctests --remap-path-prefix)
title=Workspace-coverage
if (( COVERAGE_COLLECTION_STATUS != 0 )); then
    title=INCOMPLETE-workspace-coverage
    report+=(--failure-mode all)
fi
"${report[@]}" --json --output-path "$output/diagnostic/coverage.json" 2>> "$output/coverage-warnings.log"
"${report[@]}" --cobertura --output-path "$output/diagnostic/coverage.xml" 2>> "$output/coverage-warnings.log"
"${report[@]}" > "$output/diagnostic/summary.txt" 2>> "$output/coverage-warnings.log"
if grep -q 'functions have mismatched data' "$output/coverage-warnings.log"; then
    title=INCOMPLETE-profile-mismatches
fi
LLVM_COV_FLAGS="${LLVM_COV_FLAGS:-} -project-title=$title" \
    "${report[@]}" --html --output-dir "$output/diagnostic" 2>> "$output/coverage-warnings.log"
if grep -q 'functions have mismatched data' "$output/coverage-warnings.log"; then
    echo 'Profile mappings disagree; retaining diagnostic reports instead of accepting a baseline.' >&2
    exit 1
fi
test -s "$output/diagnostic/coverage.xml"
test -s "$output/diagnostic/coverage.json"
if (( COVERAGE_COLLECTION_STATUS == 0 )); then
python3 - "$output/diagnostic/coverage.json" <<'CHECK'
import json
import sys
with open(sys.argv[1]) as source:
    data = json.load(source)["data"][0]
if not data["files"] or data["totals"]["lines"]["covered"] == 0:
    sys.exit("Coverage export contains no measured source coverage")
for prefix in ("core/src/", "crates/crypto/src/", "processor/src/", "miden-vm/src/"):
    if not any(f["filename"].startswith(prefix) and f["summary"]["lines"]["covered"] for f in data["files"]):
        sys.exit(f"No measured coverage for {prefix}")
CHECK
fi
REPORT
report_status=$?
if (( status == 0 )); then status=$report_status; fi
if (( status == 0 )); then
    mv "$output/diagnostic" "$output/reports"
    status=$?
fi
set -e
complete=false
if (( status == 0 )); then complete=true; fi
printf 'exit_code=%s\ncollection_exit_code=%s\nreport_exit_code=%s\nelapsed_seconds=%s\ncomplete=%s\n' \
    "$status" "$COVERAGE_COLLECTION_STATUS" "$report_status" "$SECONDS" "$complete" > "$output/status.txt"
cat "$output/status.txt"
exit "$status"
