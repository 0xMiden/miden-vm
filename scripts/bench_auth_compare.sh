#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=bench_blakeg_lib.sh
source "$SCRIPT_DIR/bench_blakeg_lib.sh"

POSEIDON_ROOT=""
BLAKEG_FIXTURE_ROOT="${MIDEN_BENCH_FIXTURE_ROOT:-$ROOT/bench-baselines/fixtures/bench-tx}"
AUTH_CSV="falcon,ecdsa"
PROOF_COUNTS_CSV="2,4,6"
FRI_QUERIES="${MIDEN_BENCH_NUM_FRI_QUERIES:-27}"
SYNTH_REPEAT=10
RECURSIVE_REPEAT=10
WARMUP=1
THREADS=16
BUILD_JOBS="${CARGO_BUILD_JOBS:-}"
MAX_PADDED_ROWS=4194304
MONITOR_RECURSIVE=0
RESULT_ROOT="$ROOT/bench-results/auth-compare"
ORIGINAL_ARGS="$*"

usage() {
  cat <<'EOF'
Usage:
  scripts/bench_auth_compare.sh --poseidon-root PATH [options]

Runs BlakeG/Eidos and Poseidon2 benchmark suites for Falcon and ECDSA P2ID
fixtures, then writes combined comparison tables.

Options:
  --poseidon-root PATH            Poseidon2 baseline checkout.
  --blakeg-fixture-root PATH      BlakeG MASM fixture root. Default: bench-baselines/fixtures/bench-tx
  --auth LIST                     Comma-separated auth variants: falcon, ecdsa. Default: falcon,ecdsa
  --recursive-proof-counts LIST   Comma-separated recursive proof counts. Default: 2,4,6
  --fri-queries N                 Recursive verifier FRI query count. Default: 27
  --synth-repeat N                Synthetic measured repetitions. Default: 10
  --recursive-repeat N            Recursive measured repetitions. Default: 10
  --warmup N                      Warmup repetitions for both suites. Default: 1
  --threads N                     RAYON_NUM_THREADS. Default: 16
  --build-jobs N                  CARGO_BUILD_JOBS. Default: detected logical CPUs.
  --max-padded-rows N             Synthetic large-run guard. Default: 4194304
  --monitor-recursive             Capture system snapshots around recursive fixture invocations.
  --out-root PATH                 Output root. Default: bench-results/auth-compare
  -h, --help                      Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --poseidon-root)
      POSEIDON_ROOT="${2:-}"
      shift 2
      ;;
    --blakeg-fixture-root)
      BLAKEG_FIXTURE_ROOT="${2:-}"
      shift 2
      ;;
    --auth)
      AUTH_CSV="${2:-}"
      shift 2
      ;;
    --recursive-proof-counts)
      PROOF_COUNTS_CSV="${2:-}"
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

[[ -n "$POSEIDON_ROOT" ]] || die "--poseidon-root is required"
[[ -f "$ROOT/Cargo.toml" ]] || die "not a Cargo workspace: $ROOT"
[[ -f "$POSEIDON_ROOT/Cargo.toml" ]] || die "not a Cargo workspace: $POSEIDON_ROOT"
[[ -x "$SCRIPT_DIR/bench_blakeg_suite.sh" ]] || die "missing BlakeG suite script"
[[ -x "$POSEIDON_ROOT/scripts/bench_poseidon2_suite.sh" ]] || die "missing Poseidon2 suite script"
[[ -d "$BLAKEG_FIXTURE_ROOT" ]] || die "missing BlakeG fixture root: $BLAKEG_FIXTURE_ROOT"
[[ -n "$AUTH_CSV" ]] || die "--auth cannot be empty"
[[ -n "$PROOF_COUNTS_CSV" ]] || die "--recursive-proof-counts cannot be empty"
POSEIDON_ROOT="$(cd "$POSEIDON_ROOT" && pwd)"
BLAKEG_FIXTURE_ROOT="$(cd "$BLAKEG_FIXTURE_ROOT" && pwd)"
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

auth_synth_fixtures() {
  case "$1" in
    ecdsa)
      echo "create-single-p2id-note-ecdsa,consume-single-p2id-note-ecdsa,consume-two-p2id-notes-ecdsa"
      ;;
    falcon)
      echo "create-single-p2id-note-falcon,consume-single-p2id-note-falcon,consume-two-p2id-notes-falcon"
      ;;
    *)
      die "unsupported auth variant: $1"
      ;;
  esac
}

auth_recursive_fixtures() {
  case "$1" in
    ecdsa)
      echo "consume-single-p2id-note-ecdsa,consume-two-p2id-notes-ecdsa"
      ;;
    falcon)
      echo "consume-single-p2id-note-falcon,consume-two-p2id-notes-falcon"
      ;;
    *)
      die "unsupported auth variant: $1"
      ;;
  esac
}

format_ms() {
  awk -v ms="$1" 'BEGIN {
    if (ms >= 1000) printf "%.3fs", ms / 1000.0;
    else printf "%.3fms", ms;
  }'
}

format_ratio() {
  awk -v num="$1" -v den="$2" 'BEGIN {
    if (den == 0) printf "n/a";
    else printf "%.3fx", num / den;
  }'
}

run_suite() {
  local side="$1"
  local auth="$2"
  local synth_fixtures="$3"
  local recursive_fixtures="$4"
  local out_root="$5"
  local script args

  case "$side" in
    blakeg)
      script="$SCRIPT_DIR/bench_blakeg_suite.sh"
      args=(--fixture-root "$BLAKEG_FIXTURE_ROOT")
      ;;
    poseidon2)
      script="$POSEIDON_ROOT/scripts/bench_poseidon2_suite.sh"
      args=()
      ;;
    *)
      die "unsupported suite side: $side"
      ;;
  esac

  args+=(
    --synth-fixtures "$synth_fixtures"
    --recursive-fixtures "$recursive_fixtures"
    --recursive-proof-counts "$PROOF_COUNTS_CSV"
    --fri-queries "$FRI_QUERIES"
    --synth-repeat "$SYNTH_REPEAT"
    --recursive-repeat "$RECURSIVE_REPEAT"
    --warmup "$WARMUP"
    --threads "$THREADS"
    --build-jobs "$BUILD_JOBS"
    --max-padded-rows "$MAX_PADDED_ROWS"
    --out-root "$out_root"
  )
  if (( MONITOR_RECURSIVE != 0 )); then
    args+=(--monitor-recursive)
  fi

  echo "[auth-compare] $side $auth"
  "$script" "${args[@]}"
}

suite_latest() {
  local side="$1"
  local auth="$2"
  (cd "$RUN_DIR/${side}-${auth}/latest" && pwd)
}

suite_synthetic_results() {
  local side="$1"
  local auth="$2"
  echo "$(suite_latest "$side" "$auth")/synthetic/latest/results.tsv"
}

suite_recursive_results() {
  local side="$1"
  local auth="$2"
  echo "$(suite_latest "$side" "$auth")/recursive/latest/results.tsv"
}

write_synthetic_table() {
  local auth="$1"
  local p2_file blakeg_file raw_fixture fixture p2_ms blakeg_ms p2_proof blakeg_proof p2_padded blakeg_padded
  p2_file="$(suite_synthetic_results poseidon2 "$auth")"
  blakeg_file="$(suite_synthetic_results blakeg "$auth")"

  echo "### ${auth} Synthetic"
  echo
  echo "| Fixture | Poseidon2 median | BlakeG median | BlakeG/P2 | Poseidon2 proof | BlakeG proof | Poseidon2 padded | BlakeG padded |"
  echo "|---|---:|---:|---:|---:|---:|---:|---:|"

  while IFS= read -r raw_fixture; do
    IFS='|' read -r fixture _path _expected _guard <<< "$(fixture_meta "$BLAKEG_FIXTURE_ROOT" "$raw_fixture")"
    p2_ms="$(median_tsv_field "$p2_file" 1 "$fixture" "" "" 3)"
    blakeg_ms="$(median_tsv_field "$blakeg_file" 1 "$fixture" "" "" 3)"
    p2_proof="$(first_tsv_field "$p2_file" 1 "$fixture" "" "" 5)"
    blakeg_proof="$(first_tsv_field "$blakeg_file" 1 "$fixture" "" "" 5)"
    p2_padded="$(first_tsv_field "$p2_file" 1 "$fixture" "" "" 12)"
    blakeg_padded="$(first_tsv_field "$blakeg_file" 1 "$fixture" "" "" 12)"
    echo "| $fixture | $(format_ms "$p2_ms") | $(format_ms "$blakeg_ms") | $(format_ratio "$blakeg_ms" "$p2_ms") | ${p2_proof} B | ${blakeg_proof} B | $p2_padded | $blakeg_padded |"
  done < <(split_csv "$(auth_synth_fixtures "$auth")")
}

write_recursive_table() {
  local auth="$1"
  local p2_file blakeg_file raw_fixture fixture proof_count p2_ms blakeg_ms p2_proof blakeg_proof p2_padded blakeg_padded
  p2_file="$(suite_recursive_results poseidon2 "$auth")"
  blakeg_file="$(suite_recursive_results blakeg "$auth")"

  echo "### ${auth} Recursive"
  echo
  echo "| Fixture | Proofs | Poseidon2 median | BlakeG median | BlakeG/P2 | Poseidon2 recursive proof | BlakeG recursive proof | Poseidon2 padded | BlakeG padded |"
  echo "|---|---:|---:|---:|---:|---:|---:|---:|---:|"

  while IFS= read -r raw_fixture; do
    IFS='|' read -r fixture _path _expected _guard <<< "$(fixture_meta "$BLAKEG_FIXTURE_ROOT" "$raw_fixture")"
    while IFS= read -r proof_count; do
      p2_ms="$(median_tsv_field "$p2_file" 1 "$fixture" 3 "$proof_count" 4)"
      blakeg_ms="$(median_tsv_field "$blakeg_file" 1 "$fixture" 3 "$proof_count" 4)"
      p2_proof="$(first_tsv_field "$p2_file" 1 "$fixture" 3 "$proof_count" 5)"
      blakeg_proof="$(first_tsv_field "$blakeg_file" 1 "$fixture" 3 "$proof_count" 5)"
      p2_padded="$(first_tsv_field "$p2_file" 1 "$fixture" 3 "$proof_count" 18)"
      blakeg_padded="$(first_tsv_field "$blakeg_file" 1 "$fixture" 3 "$proof_count" 18)"
      echo "| $fixture | $proof_count | $(format_ms "$p2_ms") | $(format_ms "$blakeg_ms") | $(format_ratio "$blakeg_ms" "$p2_ms") | ${p2_proof} B | ${blakeg_proof} B | $p2_padded | $blakeg_padded |"
    done < <(split_csv "$PROOF_COUNTS_CSV")
  done < <(split_csv "$(auth_recursive_fixtures "$auth")")
}

RESULT_ROOT="$(abs_dir "$RESULT_ROOT")"
timestamp="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$RESULT_ROOT/$timestamp"
mkdir -p "$RUN_DIR"
META_FILE="$RUN_DIR/metadata.txt"
SUMMARY_MD="$RUN_DIR/summary.md"

{
  echo "command=$0 $ORIGINAL_ARGS"
  echo "timestamp=$timestamp"
  echo "blakeg_root=$ROOT"
  echo "poseidon_root=$POSEIDON_ROOT"
  echo "blakeg_fixture_root=$BLAKEG_FIXTURE_ROOT"
  echo "auth=$AUTH_CSV"
  echo "recursive_proof_counts=$PROOF_COUNTS_CSV"
  echo "fri_queries=$FRI_QUERIES"
  echo "synth_repeat=$SYNTH_REPEAT"
  echo "recursive_repeat=$RECURSIVE_REPEAT"
  echo "warmup=$WARMUP"
  echo "threads=$THREADS"
  echo "build_jobs=$BUILD_JOBS"
  echo "max_padded_rows=$MAX_PADDED_ROWS"
  echo "monitor_recursive=$MONITOR_RECURSIVE"
  echo
  git_meta "$ROOT" blakeg
  git_meta "$POSEIDON_ROOT" poseidon2
} > "$META_FILE"

AUTH_VALUES=()
while IFS= read -r auth; do
  case "$auth" in
    ecdsa|falcon)
      AUTH_VALUES+=("$auth")
      ;;
    *)
      die "unsupported auth variant: $auth"
      ;;
  esac
done < <(split_csv "$AUTH_CSV")
(( ${#AUTH_VALUES[@]} > 0 )) || die "no auth variants selected"

for auth in "${AUTH_VALUES[@]}"; do
  synth_fixtures="$(auth_synth_fixtures "$auth")"
  recursive_fixtures="$(auth_recursive_fixtures "$auth")"
  run_suite poseidon2 "$auth" "$synth_fixtures" "$recursive_fixtures" "$RUN_DIR/poseidon2-${auth}"
  run_suite blakeg "$auth" "$synth_fixtures" "$recursive_fixtures" "$RUN_DIR/blakeg-${auth}"
done

{
  echo "# BlakeG vs Poseidon2 Auth Benchmark Comparison"
  echo
  echo "- BlakeG worktree: \`$ROOT\`"
  echo "- Poseidon2 worktree: \`$POSEIDON_ROOT\`"
  echo "- Auth variants: \`$AUTH_CSV\`"
  echo "- Synthetic repetitions: \`$SYNTH_REPEAT\`"
  echo "- Recursive repetitions: \`$RECURSIVE_REPEAT\`"
  echo "- Warmup repetitions excluded: \`$WARMUP\`"
  echo "- Recursive proof counts: \`$PROOF_COUNTS_CSV\`"
  echo "- Recursive FRI queries: \`$FRI_QUERIES\`"
  echo "- Threads: \`$THREADS\`"
  echo "- Build jobs: \`$BUILD_JOBS\`"
  echo
  echo "Ratios are BlakeG / Poseidon2."
  echo
  for auth in "${AUTH_VALUES[@]}"; do
    write_synthetic_table "$auth"
    echo
    write_recursive_table "$auth"
    echo
  done
  echo "## Files"
  echo
  for auth in "${AUTH_VALUES[@]}"; do
    echo "- Poseidon2 ${auth} suite: \`$(suite_latest poseidon2 "$auth")/summary.md\`"
    echo "- BlakeG ${auth} suite: \`$(suite_latest blakeg "$auth")/summary.md\`"
  done
  echo "- Metadata: \`$META_FILE\`"
} > "$SUMMARY_MD"

ln -sfn "$RUN_DIR" "$RESULT_ROOT/latest"

echo
echo "[auth-compare] results: $RUN_DIR"
cat "$SUMMARY_MD"
