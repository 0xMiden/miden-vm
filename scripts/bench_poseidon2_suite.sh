#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=bench_poseidon2_lib.sh
source "$SCRIPT_DIR/bench_poseidon2_lib.sh"

FIXTURE_ROOT=""
SNAPSHOT="$ROOT/benches/synthetic-bench/snapshots/bench-tx.json"
SYNTH_FIXTURES="create-single-p2id-note,consume-single-p2id-note,consume-two-p2id-notes,consume-claim-note-l1-to-miden,consume-claim-note-l2-to-miden,consume-b2agg-note-bridge-out"
RECURSIVE_FIXTURES="consume-single-p2id-note,consume-two-p2id-notes"
RECURSIVE_PROOF_COUNTS="2,4,6"
FRI_QUERIES=28
SYNTH_REPEAT=5
RECURSIVE_REPEAT=10
WARMUP=1
THREADS=16
BUILD_JOBS="${CARGO_BUILD_JOBS:-}"
MAX_PADDED_ROWS=4194304
MONITOR_RECURSIVE=0
RESULT_ROOT="$ROOT/bench-results/poseidon2-suite"
ORIGINAL_ARGS="$*"

usage() {
  cat <<'EOF'
Usage:
  scripts/bench_poseidon2_suite.sh [options]

Generates Poseidon2 synthetic transaction MASM from the bench snapshot, then runs the synthetic
prove suite and recursive verifier suite over those generated fixtures.

Options:
  --snapshot PATH                 Synthetic bench snapshot JSON. Default: benches/synthetic-bench/snapshots/bench-tx.json
  --fixture-root PATH             Use an existing synthetic_bench_bench-tx__*.masm directory instead of generating.
  --synth-fixtures LIST           Comma-separated synthetic fixture aliases.
  --recursive-fixtures LIST       Comma-separated recursive fixture aliases.
  --recursive-proof-counts LIST   Comma-separated proof counts. Default: 2,4,6
  --fri-queries N                 Recursive verifier FRI query count. Default: 28
  --synth-repeat N                Synthetic measured repetitions. Default: 5
  --recursive-repeat N            Recursive measured repetitions. Default: 10
  --warmup N                      Warmup repetitions for both suites. Default: 1
  --threads N                     RAYON_NUM_THREADS. Default: 16
  --build-jobs N                  CARGO_BUILD_JOBS. Default: detected logical CPUs.
  --max-padded-rows N             Synthetic large-run guard. Default: 4194304
  --monitor-recursive             Capture system snapshots around recursive runs.
  --out-root PATH                 Output root. Default: bench-results/poseidon2-suite
  -h, --help                      Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fixture-root)
      FIXTURE_ROOT="${2:-}"
      shift 2
      ;;
    --snapshot)
      SNAPSHOT="${2:-}"
      shift 2
      ;;
    --synth-fixtures)
      SYNTH_FIXTURES="${2:-}"
      shift 2
      ;;
    --recursive-fixtures)
      RECURSIVE_FIXTURES="${2:-}"
      shift 2
      ;;
    --recursive-proof-counts)
      RECURSIVE_PROOF_COUNTS="${2:-}"
      shift 2
      ;;
    --fri-queries)
      FRI_QUERIES="${2:-}"
      shift 2
      ;;
    --synth-repeat)
      SYNTH_REPEAT="${2:-}"
      shift 2
      ;;
    --recursive-repeat)
      RECURSIVE_REPEAT="${2:-}"
      shift 2
      ;;
    --warmup)
      WARMUP="${2:-}"
      shift 2
      ;;
    --threads)
      THREADS="${2:-}"
      shift 2
      ;;
    --build-jobs)
      BUILD_JOBS="${2:-}"
      shift 2
      ;;
    --max-padded-rows)
      MAX_PADDED_ROWS="${2:-}"
      shift 2
      ;;
    --monitor-recursive)
      MONITOR_RECURSIVE=1
      shift
      ;;
    --out-root)
      RESULT_ROOT="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$SYNTH_FIXTURES" ]] || die "--synth-fixtures cannot be empty"
[[ -n "$RECURSIVE_FIXTURES" ]] || die "--recursive-fixtures cannot be empty"
[[ -n "$RECURSIVE_PROOF_COUNTS" ]] || die "--recursive-proof-counts cannot be empty"
require_positive_uint "--fri-queries" "$FRI_QUERIES"
require_positive_uint "--synth-repeat" "$SYNTH_REPEAT"
require_positive_uint "--recursive-repeat" "$RECURSIVE_REPEAT"
require_uint "--warmup" "$WARMUP"
require_positive_uint "--threads" "$THREADS"
require_positive_uint "--max-padded-rows" "$MAX_PADDED_ROWS"
if [[ -z "$BUILD_JOBS" ]]; then
  BUILD_JOBS="$(detect_build_jobs)"
fi
require_positive_uint "--build-jobs" "$BUILD_JOBS"
[[ -f "$SNAPSHOT" ]] || die "missing synthetic snapshot: $SNAPSHOT"

RESULT_ROOT="$(abs_dir "$RESULT_ROOT")"
timestamp="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$RESULT_ROOT/$timestamp"
mkdir -p "$RUN_DIR"

if [[ -z "$FIXTURE_ROOT" ]]; then
  FIXTURE_ROOT="$RUN_DIR/generated-fixtures"
  generate_poseidon2_fixtures \
    "$ROOT" "$SNAPSHOT" "$SYNTH_FIXTURES,$RECURSIVE_FIXTURES" "$FIXTURE_ROOT" \
    "$THREADS" "$BUILD_JOBS" "$RUN_DIR/generate_fixtures.log"
else
  [[ -d "$FIXTURE_ROOT" ]] || die "missing fixture root: $FIXTURE_ROOT"
fi

SYNTH_ROOT="$RUN_DIR/synthetic"
RECURSIVE_ROOT="$RUN_DIR/recursive"
META_FILE="$RUN_DIR/metadata.txt"
SUMMARY_MD="$RUN_DIR/summary.md"

{
  echo "command=$0 $ORIGINAL_ARGS"
  echo "timestamp=$timestamp"
  echo "root=$ROOT"
  echo "snapshot=$SNAPSHOT"
  echo "fixture_root=$FIXTURE_ROOT"
  echo "synth_fixtures=$SYNTH_FIXTURES"
  echo "recursive_fixtures=$RECURSIVE_FIXTURES"
  echo "recursive_proof_counts=$RECURSIVE_PROOF_COUNTS"
  echo "fri_queries=$FRI_QUERIES"
  echo "synth_repeat=$SYNTH_REPEAT"
  echo "recursive_repeat=$RECURSIVE_REPEAT"
  echo "warmup=$WARMUP"
  echo "threads=$THREADS"
  echo "build_jobs=$BUILD_JOBS"
  echo "max_padded_rows=$MAX_PADDED_ROWS"
  echo "monitor_recursive=$MONITOR_RECURSIVE"
} > "$META_FILE"

synthetic_args=(
  --fixture-root "$FIXTURE_ROOT"
  --fixtures "$SYNTH_FIXTURES"
  --repeat "$SYNTH_REPEAT"
  --warmup "$WARMUP"
  --threads "$THREADS"
  --build-jobs "$BUILD_JOBS"
  --max-padded-rows "$MAX_PADDED_ROWS"
  --out-root "$SYNTH_ROOT"
)

recursive_args=(
  --fixture-root "$FIXTURE_ROOT"
  --fixtures "$RECURSIVE_FIXTURES"
  --proof-counts "$RECURSIVE_PROOF_COUNTS"
  --fri-queries "$FRI_QUERIES"
  --repeat "$RECURSIVE_REPEAT"
  --warmup "$WARMUP"
  --threads "$THREADS"
  --build-jobs "$BUILD_JOBS"
  --out-root "$RECURSIVE_ROOT"
)
if (( MONITOR_RECURSIVE != 0 )); then
  recursive_args+=(--monitor-system)
fi

echo "[poseidon2-suite] synthetic benchmarks"
"$SCRIPT_DIR/bench_poseidon2_synthetic.sh" "${synthetic_args[@]}"

echo "[poseidon2-suite] recursive verifier benchmarks"
"$SCRIPT_DIR/bench_poseidon2_recursive.sh" "${recursive_args[@]}"

SYNTH_LATEST="$(cd "$SYNTH_ROOT/latest" && pwd)"
RECURSIVE_LATEST="$(cd "$RECURSIVE_ROOT/latest" && pwd)"

{
  echo "# Poseidon2 Benchmark Suite"
  echo
  echo "- Worktree: \`$ROOT\`"
  echo "- Fixture root: \`$FIXTURE_ROOT\`"
  echo "- Threads: \`$THREADS\`"
  echo "- Build jobs: \`$BUILD_JOBS\`"
  echo "- Warmup repetitions excluded: \`$WARMUP\`"
  echo "- Synthetic repetitions: \`$SYNTH_REPEAT\`"
  echo "- Recursive repetitions: \`$RECURSIVE_REPEAT\`"
  echo "- Recursive FRI queries: \`$FRI_QUERIES\`"
  echo
  echo "## Synthetic"
  echo
  echo "Result dir: \`$SYNTH_LATEST\`"
  echo
  sed '1d' "$SYNTH_LATEST/summary.md"
  echo
  echo "## Recursive"
  echo
  echo "Result dir: \`$RECURSIVE_LATEST\`"
  echo
  sed '1d' "$RECURSIVE_LATEST/summary.md"
  echo
  echo "## Files"
  echo
  echo "- Synthetic summary: \`$SYNTH_LATEST/summary.md\`"
  echo "- Synthetic rows: \`$SYNTH_LATEST/results.tsv\`"
  echo "- Recursive summary: \`$RECURSIVE_LATEST/summary.md\`"
  echo "- Recursive rows: \`$RECURSIVE_LATEST/results.tsv\`"
  echo "- Suite metadata: \`$META_FILE\`"
} > "$SUMMARY_MD"

ln -sfn "$RUN_DIR" "$RESULT_ROOT/latest"

echo
echo "[poseidon2-suite] results: $RUN_DIR"
cat "$SUMMARY_MD"
