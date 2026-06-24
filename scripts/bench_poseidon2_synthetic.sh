#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=bench_poseidon2_lib.sh
source "$SCRIPT_DIR/bench_poseidon2_lib.sh"

FIXTURE_ROOT=""
SNAPSHOT="$ROOT/benches/synthetic-bench/snapshots/bench-tx.json"
FIXTURES_CSV="create-single-p2id-note-ecdsa,consume-single-p2id-note-ecdsa,consume-two-p2id-notes-ecdsa"
REPEAT=5
WARMUP=1
THREADS=16
BUILD_JOBS="${CARGO_BUILD_JOBS:-}"
MAX_PADDED_ROWS=4194304
RESULT_ROOT="$ROOT/bench-results/poseidon2-synthetic"
ORIGINAL_ARGS="$*"

usage() {
  cat <<'EOF'
Usage:
  scripts/bench_poseidon2_synthetic.sh [options]

Generates Poseidon2 synthetic transaction MASM from the bench snapshot, then proves it.
The default fixture list is the ECDSA P2ID subset.

Options:
  --snapshot PATH       Synthetic bench snapshot JSON. Default: benches/synthetic-bench/snapshots/bench-tx.json
  --fixture-root PATH   Use an existing synthetic_bench_bench-tx__*.masm directory instead of generating.
  --fixtures LIST      Comma-separated fixture aliases.
  --repeat N           Measured repetitions per fixture. Default: 5
  --warmup N           Warmup repetitions per fixture. Default: 1
  --threads N          RAYON_NUM_THREADS. Default: 16
  --build-jobs N       CARGO_BUILD_JOBS. Default: detected logical CPUs.
  --max-padded-rows N  Fixture guard. Default: 4194304
  --out-root PATH      Output root. Default: bench-results/poseidon2-synthetic
  -h, --help           Show this help.
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
    --fixtures)
      FIXTURES_CSV="${2:-}"
      shift 2
      ;;
    --repeat)
      REPEAT="${2:-}"
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

[[ -n "$FIXTURES_CSV" ]] || die "--fixtures cannot be empty"
require_positive_uint "--repeat" "$REPEAT"
require_uint "--warmup" "$WARMUP"
require_positive_uint "--threads" "$THREADS"
require_positive_uint "--max-padded-rows" "$MAX_PADDED_ROWS"
if [[ -z "$BUILD_JOBS" ]]; then
  BUILD_JOBS="$(detect_build_jobs)"
fi
require_positive_uint "--build-jobs" "$BUILD_JOBS"

[[ -f "$ROOT/Cargo.toml" ]] || die "not a Cargo workspace: $ROOT"
[[ -f "$SNAPSHOT" ]] || die "missing synthetic snapshot: $SNAPSHOT"
RESULT_ROOT="$(abs_dir "$RESULT_ROOT")"

timestamp="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$RESULT_ROOT/$timestamp"
mkdir -p "$RUN_DIR/logs"

RESULTS_TSV="$RUN_DIR/results.tsv"
FIXTURE_PATHS_TSV="$RUN_DIR/fixture_paths.tsv"
META_FILE="$RUN_DIR/metadata.txt"
SUMMARY_MD="$RUN_DIR/summary.md"

cat > "$RESULTS_TSV" <<'EOF'
fixture	run	prove_ms	verify_ms	proof_bytes	core_rows	range_rows	chiplets_rows	hash_rows	bitwise_rows	memory_rows	padded_rows	poseidon2_perm_rows	poseidon2_unique_perms	security	expected_padded_rows	guard_padded_rows	log_file
EOF

cat > "$FIXTURE_PATHS_TSV" <<'EOF'
fixture	masm_path
EOF

if [[ -z "$FIXTURE_ROOT" ]]; then
  FIXTURE_ROOT="$RUN_DIR/generated-fixtures"
  generate_poseidon2_fixtures \
    "$ROOT" "$SNAPSHOT" "$FIXTURES_CSV" "$FIXTURE_ROOT" "$THREADS" "$BUILD_JOBS" \
    "$RUN_DIR/logs/generate_fixtures.log"
else
  [[ -d "$FIXTURE_ROOT" ]] || die "missing fixture root: $FIXTURE_ROOT"
fi

{
  echo "command=$0 $ORIGINAL_ARGS"
  echo "timestamp=$timestamp"
  echo "root=$ROOT"
  echo "snapshot=$SNAPSHOT"
  echo "fixture_root=$FIXTURE_ROOT"
  echo "fixtures=$FIXTURES_CSV"
  echo "repeat=$REPEAT"
  echo "warmup=$WARMUP"
  echo "RAYON_NUM_THREADS=$THREADS"
  echo "CARGO_BUILD_JOBS=$BUILD_JOBS"
  echo "RUSTFLAGS=-C target-cpu=native"
  echo "max_padded_rows=$MAX_PADDED_ROWS"
  echo
  git_meta "$ROOT" poseidon2
} > "$META_FILE"

run_once() {
  local fixture="$1"
  local masm_path="$2"
  local expected="$3"
  local guard="$4"
  local run_idx="$5"
  local log_file="$6"
  local record="$7"
  local label="$8"
  local env_args

  if [[ -n "$guard" ]] && (( guard > MAX_PADDED_ROWS )); then
    die "$fixture guard padded rows $guard exceeds max $MAX_PADDED_ROWS"
  fi

  echo "[poseidon2-synthetic] $fixture $label"
  env_args=(
    RAYON_NUM_THREADS="$THREADS"
    CARGO_BUILD_JOBS="$BUILD_JOBS"
    RUSTFLAGS="-C target-cpu=native"
    MIDEN_BENCH_MASM="$masm_path"
    MIDEN_BENCH_GUARD_PADDED_ROWS="$guard"
    MIDEN_BENCH_MAX_PADDED_ROWS="$MAX_PADDED_ROWS"
  )
  if [[ -n "$expected" ]]; then
    env_args+=(MIDEN_BENCH_EXPECTED_PADDED_ROWS="$expected")
  fi

  (
    cd "$ROOT"
    env "${env_args[@]}" \
      cargo test --profile optimized --features concurrent -p miden-vm --test miden-cli \
        bench_prove_masm_file -- --ignored --nocapture
  ) 2>&1 | tee "$log_file"

  (( record == 0 )) && return

  local rows_line proof_hash_line prove_raw verify_raw proof_size security
  rows_line="$(grep 'rows: core=' "$log_file" | tail -n 1 || true)"
  proof_hash_line="$(grep 'poseidon2_perm_rows=' "$log_file" | tail -n 1 || true)"
  prove_raw="$(sed -n 's/^[[:space:]]*prove_time:[[:space:]]*//p' "$log_file" | tail -n 1)"
  verify_raw="$(sed -n 's/^[[:space:]]*verify_time:[[:space:]]*//p' "$log_file" | tail -n 1)"
  proof_size="$(sed -n 's/^[[:space:]]*proof_size:[[:space:]]*\([0-9][0-9]*\) bytes$/\1/p' "$log_file" | tail -n 1)"
  security="$(sed -n 's/^[[:space:]]*security:[[:space:]]*//p' "$log_file" | tail -n 1)"

  [[ -n "$rows_line" && -n "$proof_hash_line" && -n "$prove_raw" && -n "$proof_size" ]] \
    || die "failed to parse benchmark log: $log_file"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$fixture" "$run_idx" "$(duration_to_ms "$prove_raw")" "$(duration_to_ms "$verify_raw")" \
    "$proof_size" \
    "$(extract_field core "$rows_line")" \
    "$(extract_field range "$rows_line")" \
    "$(extract_field chiplets "$rows_line")" \
    "$(extract_field hash_ctrl "$rows_line")" \
    "$(extract_field bitwise "$rows_line")" \
    "$(extract_field memory "$rows_line")" \
    "$(extract_field padded "$rows_line")" \
    "$(extract_field poseidon2_perm_rows "$proof_hash_line")" \
    "$(extract_field poseidon2_unique_perms "$proof_hash_line")" \
    "$security" "$expected" "$guard" "$log_file" \
    >> "$RESULTS_TSV"
}

FIXTURES=()
while IFS= read -r fixture; do
  FIXTURES+=("$fixture")
done < <(split_csv "$FIXTURES_CSV")
(( ${#FIXTURES[@]} > 0 )) || die "no fixtures selected"

for raw_fixture in "${FIXTURES[@]}"; do
  IFS='|' read -r fixture masm_path expected guard <<< "$(fixture_meta "$FIXTURE_ROOT" "$raw_fixture")"
  [[ -f "$masm_path" ]] || die "missing fixture file: $masm_path"
  [[ -n "$guard" ]] || guard="$MAX_PADDED_ROWS"
  printf '%s\t%s\n' "$fixture" "$masm_path" >> "$FIXTURE_PATHS_TSV"

  if (( WARMUP > 0 )); then
    for warmup_idx in $(seq 1 "$WARMUP"); do
      run_once "$fixture" "$masm_path" "$expected" "$guard" "$warmup_idx" \
        "$RUN_DIR/logs/${fixture}_warmup${warmup_idx}.log" 0 "warmup $warmup_idx/$WARMUP"
    done
  fi

  for run_idx in $(seq 1 "$REPEAT"); do
    run_once "$fixture" "$masm_path" "$expected" "$guard" "$run_idx" \
      "$RUN_DIR/logs/${fixture}_run${run_idx}.log" 1 "run $run_idx/$REPEAT"
  done
done

{
  echo "# Poseidon2 Synthetic Prove Benchmarks"
  echo
  echo "- Worktree: \`$ROOT\`"
  echo "- Fixture root: \`$FIXTURE_ROOT\`"
  echo "- Repetitions: \`$REPEAT\`"
  echo "- Warmup repetitions excluded: \`$WARMUP\`"
  echo "- Threads: \`$THREADS\`"
  echo "- Build jobs: \`$BUILD_JOBS\`"
  echo "- Max padded rows: \`$MAX_PADDED_ROWS\`"
  echo
  echo "| Fixture | Runs | Median | Average | Min-Max | Proof | Padded | Poseidon2 perms |"
  echo "|---|---:|---:|---:|---:|---:|---:|---:|"

  for raw_fixture in "${FIXTURES[@]}"; do
    IFS='|' read -r fixture _masm_path _expected _guard <<< "$(fixture_meta "$FIXTURE_ROOT" "$raw_fixture")"
    median="$(median_tsv_field "$RESULTS_TSV" 1 "$fixture" "" "" 3)"
    average="$(avg_tsv_field "$RESULTS_TSV" 1 "$fixture" "" "" 3)"
    minmax="$(minmax_tsv_field "$RESULTS_TSV" 1 "$fixture" "" "" 3)"
    proof="$(first_tsv_field "$RESULTS_TSV" 1 "$fixture" "" "" 5)"
    padded="$(first_tsv_field "$RESULTS_TSV" 1 "$fixture" "" "" 12)"
    perms="$(first_tsv_field "$RESULTS_TSV" 1 "$fixture" "" "" 14)"
    echo "| $fixture | $REPEAT | ${median} ms | ${average} ms | ${minmax} ms | ${proof} B | $padded | $perms |"
  done

  echo
  echo "## Files"
  echo
  echo "- Parsed rows: \`results.tsv\`"
  echo "- Fixture paths: \`fixture_paths.tsv\`"
  echo "- Raw logs: \`logs/\`"
  echo "- Metadata: \`metadata.txt\`"
} > "$SUMMARY_MD"

ln -sfn "$RUN_DIR" "$RESULT_ROOT/latest"

echo
echo "[poseidon2-synthetic] results: $RUN_DIR"
cat "$SUMMARY_MD"
