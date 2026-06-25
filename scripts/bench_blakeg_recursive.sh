#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=bench_blakeg_lib.sh
source "$SCRIPT_DIR/bench_blakeg_lib.sh"

FIXTURE_ROOT="${MIDEN_BENCH_FIXTURE_ROOT:-$ROOT/bench-baselines/fixtures/bench-tx}"
FIXTURES_CSV="consume-single-p2id-note-ecdsa,consume-two-p2id-notes-ecdsa"
PROOF_COUNTS_CSV="2,4,6"
FRI_QUERIES="${MIDEN_BENCH_NUM_FRI_QUERIES:-27}"
REPEAT=10
WARMUP=1
THREADS=16
BUILD_JOBS="${CARGO_BUILD_JOBS:-}"
MONITOR_SYSTEM=0
RESULT_ROOT="$ROOT/bench-results/blakeg-recursive"
ORIGINAL_ARGS="$*"

usage() {
  cat <<'EOF'
Usage:
  scripts/bench_blakeg_recursive.sh [options]

Runs recursive verifier proving over BlakeG/Eidos transaction proofs.
The default fixture list is the ECDSA P2ID subset.

Options:
  --fixture-root PATH   Directory containing synthetic_bench_bench-tx__*.masm.
  --poseidon-root PATH  Use PATH/bench-baselines/fixtures/bench-tx as fixture root.
  --fixtures LIST      Comma-separated fixture aliases.
  --proof-counts LIST  Comma-separated recursive proof counts. Default: 2,4,6
  --fri-queries N      FRI query count. Default: 27
  --repeat N           Measured repetitions. Default: 10
  --warmup N           Warmup repetitions. Default: 1
  --threads N          RAYON_NUM_THREADS. Default: 16
  --build-jobs N       CARGO_BUILD_JOBS. Default: detected logical CPUs.
  --monitor-system     Capture system snapshots around each fixture invocation.
  --out-root PATH      Output root. Default: bench-results/blakeg-recursive
  -h, --help           Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fixture-root)
      FIXTURE_ROOT="${2:-}"
      shift 2
      ;;
    --poseidon-root)
      FIXTURE_ROOT="${2:-}/bench-baselines/fixtures/bench-tx"
      shift 2
      ;;
    --fixtures)
      FIXTURES_CSV="${2:-}"
      shift 2
      ;;
    --proof-counts)
      PROOF_COUNTS_CSV="${2:-}"
      shift 2
      ;;
    --fri-queries)
      FRI_QUERIES="${2:-}"
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
    --monitor-system)
      MONITOR_SYSTEM=1
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

[[ -n "$FIXTURES_CSV" ]] || die "--fixtures cannot be empty"
[[ -n "$PROOF_COUNTS_CSV" ]] || die "--proof-counts cannot be empty"
require_positive_uint "--fri-queries" "$FRI_QUERIES"
require_positive_uint "--repeat" "$REPEAT"
require_uint "--warmup" "$WARMUP"
require_positive_uint "--threads" "$THREADS"
if [[ -z "$BUILD_JOBS" ]]; then
  BUILD_JOBS="$(detect_build_jobs)"
fi
require_positive_uint "--build-jobs" "$BUILD_JOBS"

[[ -f "$ROOT/Cargo.toml" ]] || die "not a Cargo workspace: $ROOT"
[[ -f "$ROOT/benches/synthetic-bench/benches/recursive_verify.rs" ]] \
  || die "missing recursive benchmark harness"
[[ -d "$FIXTURE_ROOT" ]] || die "missing fixture root: $FIXTURE_ROOT"
RESULT_ROOT="$(abs_dir "$RESULT_ROOT")"

timestamp="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$RESULT_ROOT/$timestamp"
mkdir -p "$RUN_DIR/logs" "$RUN_DIR/monitoring" "$RUN_DIR/candidate-fixtures"

RESULTS_TSV="$RUN_DIR/results.tsv"
AIR_TSV="$RUN_DIR/air_metadata.tsv"
FIXTURE_PATHS_TSV="$RUN_DIR/fixture_paths.tsv"
META_FILE="$RUN_DIR/metadata.txt"
SUMMARY_MD="$RUN_DIR/summary.md"

cat > "$RESULTS_TSV" <<'EOF'
fixture	run	proof_count	prove_ms	recursive_proof_bytes	tx_proof_bytes	core_rows	range_rows	chiplets_rows	hash_chiplet_rows	bitwise_rows	memory_rows	ace_rows	kernel_rows	native_hash_rows	and8_lookup_rows	max_trace_rows	max_padded_rows	log_file
EOF

cat > "$FIXTURE_PATHS_TSV" <<'EOF'
fixture	source_masm	candidate_masm
EOF

trace_width_from_comment() {
  local trace_name="$1"
  sed -n "s/^\\/\\/\\/ Number of columns in the ${trace_name} trace (\\([0-9][0-9]*\\)).*$/\\1/p" \
    "$ROOT/air/src/constraints/columns.rs" 2>/dev/null | head -n 1
}

shape_width() {
  local file="$1"
  local const_name="$2"
  sed -n "s/^pub(crate) const ${const_name}: \\[usize; \\([0-9][0-9]*\\)\\] =.*$/\\1/p" \
    "$ROOT/$file" 2>/dev/null | head -n 1
}

numeric_const() {
  local file="$1"
  local const_name="$2"
  sed -n "s/^pub const ${const_name}: usize = \\([0-9][0-9]*\\);$/\\1/p" \
    "$ROOT/$file" 2>/dev/null | head -n 1
}

numeric_const_any() {
  local value
  while (($# > 0)); do
    value="$(numeric_const "$1" "$2" || true)"
    if [[ -n "$value" ]]; then
      echo "$value"
      return
    fi
    shift 2
  done
}

shape_width_any() {
  local value
  while (($# > 0)); do
    value="$(shape_width "$1" "$2" || true)"
    if [[ -n "$value" ]]; then
      echo "$value"
      return
    fi
    shift 2
  done
}

chiplets_trace_width() {
  local data_width
  data_width="$(numeric_const air/src/trace/mod.rs CHIPLETS_DATA_WIDTH)"
  [[ -n "$data_width" ]] || return
  echo "$((data_width + 1))"
}

byte_pair_lookup_width() {
  awk '
    /pub struct And8LookupCols</ { in_struct = 1; next }
    in_struct && /^}/ { print count; exit }
    in_struct && /pub .*_multiplicity:/ { count += 1 }
  ' "$ROOT/air/src/constraints/and8_lookup/columns.rs" 2>/dev/null
}

write_air_metadata() {
  local core_width chiplets_width core_aux chiplets_aux blakeg_width blakeg_aux and8_width
  core_width="$(trace_width_from_comment core)"
  chiplets_width="$(chiplets_trace_width)"
  core_aux="$(shape_width air/src/constraints/lookup/main_air.rs MAIN_COLUMN_SHAPE)"
  chiplets_aux="$(shape_width air/src/constraints/lookup/chiplet_air.rs CHIPLET_COLUMN_SHAPE)"
  blakeg_width="$(numeric_const_any \
    air/src/constraints/blakeg_compression/layout.rs NUM_BLAKEG_COMPRESSION_COLS \
    air/src/constraints/blakeg_compression/air32_layout.rs NUM_COLS)"
  blakeg_aux="$(shape_width_any \
    air/src/constraints/lookup/blakeg_compression_air.rs BLAKEG_COMPRESSION_COLUMN_SHAPE)"
  if [[ -z "$blakeg_aux" ]]; then
    blakeg_aux="$(numeric_const air/src/constraints/blakeg_compression/air32_layout.rs AUX_COLS || true)"
  fi
  and8_width="$(byte_pair_lookup_width)"

  cat > "$AIR_TSV" <<EOF
air	trace_width	aux_width	max_constraint_degree	notes
core	${core_width:-unknown}	${core_aux:-unknown}	9	Core main trace
chiplets	${chiplets_width:-unknown}	${chiplets_aux:-unknown}	9	Chiplets trace
blakeg_compression	${blakeg_width:-unknown}	${blakeg_aux:-unknown}	3	Standalone BlakeG compression AIR
and8_lookup	${and8_width:-unknown}	${and8_width:-unknown}	2	Fixed byte-pair lookup table AIR
EOF
}

capture_system_snapshot() {
  local output_file="$1"

  {
    echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    uptime || true
    echo
    sysctl kern.memorystatus_vm_pressure_level kern.memorystatus_level 2>/dev/null || true
    memory_pressure 2>/dev/null || true
    echo
    vm_stat || true
    echo
    sysctl vm.swapusage 2>/dev/null || true
    echo
    pmset -g therm 2>/dev/null || true
    echo
    top -l 1 -n 15 -stats pid,command,cpu,mem,threads,state,time 2>/dev/null || true
  } > "$output_file"
}

tx_bytes_for_count() {
  local log_file="$1"
  local proof_count="$2"

  awk -v limit="$proof_count" '
    /^BENCH_TX_PROOF / {
      idx = ""; bytes = "";
      for (i = 1; i <= NF; i++) {
        split($i, kv, "=");
        if (kv[1] == "index") idx = kv[2];
        if (kv[1] == "proof_bytes") bytes = kv[2];
      }
      if (idx != "" && bytes != "" && idx + 0 < limit) {
        sum += bytes;
        count += 1;
      }
    }
    END {
      if (count != limit) {
        print "missing";
      } else {
        print sum;
      }
    }
  ' "$log_file"
}

parse_run_log() {
  local fixture="$1"
  local run_idx="$2"
  local log_file="$3"
  local proof_line

  grep '^BENCH_RECURSION_PROOF ' "$log_file" | while IFS= read -r proof_line; do
    local proof_count proof_run_idx shape_line tx_bytes
    proof_count="$(extract_field proofs "$proof_line")"
    proof_run_idx="$(extract_field run "$proof_line")"
    [[ -n "$proof_run_idx" ]] || proof_run_idx="$run_idx"
    shape_line="$(grep "^BENCH_RECURSION_SHAPE proofs=${proof_count} " "$log_file" | tail -n 1 || true)"
    [[ -n "$shape_line" ]] || die "missing shape line for $fixture proof_count=$proof_count"

    tx_bytes="$(tx_bytes_for_count "$log_file" "$proof_count")"
    [[ "$tx_bytes" != "missing" ]] || die "missing transaction proof rows in $log_file"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$fixture" "$proof_run_idx" "$proof_count" \
      "$(extract_field prove_ms "$proof_line")" \
      "$(extract_field proof_bytes "$proof_line")" \
      "$tx_bytes" \
      "$(extract_field core_rows "$shape_line")" \
      "$(extract_field range_rows "$shape_line")" \
      "$(extract_field chiplets_rows "$shape_line")" \
      "$(extract_field hash_chiplet_rows "$shape_line")" \
      "$(extract_field bitwise_rows "$shape_line")" \
      "$(extract_field memory_rows "$shape_line")" \
      "$(extract_field ace_rows "$shape_line")" \
      "$(extract_field kernel_rows "$shape_line")" \
      "$(extract_field native_hash_rows "$shape_line")" \
      "$(extract_field and8_lookup_rows "$shape_line")" \
      "$(extract_field max_trace_rows "$shape_line")" \
      "$(extract_field max_padded_rows "$shape_line")" \
      "$log_file" \
      >> "$RESULTS_TSV"
  done
}

run_once() {
  local fixture="$1"
  local masm_path="$2"
  local run_idx="$3"
  local log_file="$4"
  local record="$5"
  local label="$6"
  local monitor_base
  monitor_base="${fixture}_${label//[^[:alnum:]_.-]/_}"

  echo "[blakeg-recursive] $fixture $label"
  if (( MONITOR_SYSTEM != 0 )); then
    capture_system_snapshot "$RUN_DIR/monitoring/${monitor_base}.before.txt"
  fi

  (
    cd "$ROOT"
    env \
      RAYON_NUM_THREADS="$THREADS" \
      CARGO_BUILD_JOBS="$BUILD_JOBS" \
      RUSTFLAGS="-C target-cpu=native" \
      RECURSION_BENCH_MASM="$masm_path" \
      RECURSION_PROOF_COUNTS="$PROOF_COUNTS_CSV" \
      RECURSION_BENCH_HASH=eidos \
      RECURSION_BENCH_DISTINCT_STACKS=1 \
      RECURSION_PROFILE_PROVE=1 \
      RECURSION_PROFILE_PROVE_REPEATS="$REPEAT" \
      RECURSION_PROFILE_PROVE_WARMUPS="$WARMUP" \
      MIDEN_BENCH_NUM_FRI_QUERIES="$FRI_QUERIES" \
      cargo bench --profile optimized -p miden-vm-synthetic-bench --bench recursive_verify -- --noplot
  ) 2>&1 | tee "$log_file"

  if (( MONITOR_SYSTEM != 0 )); then
    capture_system_snapshot "$RUN_DIR/monitoring/${monitor_base}.after.txt"
  fi

  (( record == 0 )) || parse_run_log "$fixture" "$run_idx" "$log_file"
}

FIXTURES=()
while IFS= read -r fixture; do
  FIXTURES+=("$fixture")
done < <(split_csv "$FIXTURES_CSV")
(( ${#FIXTURES[@]} > 0 )) || die "no fixtures selected"

PROOF_COUNTS=()
while IFS= read -r count; do
  require_positive_uint "proof count" "$count"
  PROOF_COUNTS+=("$count")
done < <(split_csv "$PROOF_COUNTS_CSV")
(( ${#PROOF_COUNTS[@]} > 0 )) || die "no proof counts selected"

write_air_metadata

{
  echo "command=$0 $ORIGINAL_ARGS"
  echo "timestamp=$timestamp"
  echo "root=$ROOT"
  echo "fixture_root=$FIXTURE_ROOT"
  echo "fixtures=$FIXTURES_CSV"
  echo "proof_counts=$PROOF_COUNTS_CSV"
  echo "fri_queries=$FRI_QUERIES"
  echo "repeat=$REPEAT"
  echo "warmup=$WARMUP"
  echo "RAYON_NUM_THREADS=$THREADS"
  echo "CARGO_BUILD_JOBS=$BUILD_JOBS"
  echo "RUSTFLAGS=-C target-cpu=native"
  echo "monitor_system=$MONITOR_SYSTEM"
  echo
  git_meta "$ROOT" blakeg
} > "$META_FILE"

for raw_fixture in "${FIXTURES[@]}"; do
  IFS='|' read -r fixture source_path _expected _guard <<< "$(fixture_meta "$FIXTURE_ROOT" "$raw_fixture")"
  [[ -f "$source_path" ]] || die "missing fixture file: $source_path"

  candidate_path="$(write_blakeg_fixture "$fixture" "$source_path" "$RUN_DIR/candidate-fixtures")"
  printf '%s\t%s\t%s\n' "$fixture" "$source_path" "$candidate_path" >> "$FIXTURE_PATHS_TSV"

  run_once "$fixture" "$candidate_path" 1 "$RUN_DIR/logs/${fixture}_runs.log" 1 \
    "runs $REPEAT warmups $WARMUP"
done

{
  echo "# BlakeG Recursive Verifier Benchmarks"
  echo
  echo "- Worktree: \`$ROOT\`"
  echo "- Fixture root: \`$FIXTURE_ROOT\`"
  echo "- Proof counts: \`$PROOF_COUNTS_CSV\`"
  echo "- FRI queries: \`$FRI_QUERIES\`"
  echo "- Repetitions: \`$REPEAT\`"
  echo "- Warmup repetitions excluded: \`$WARMUP\`"
  echo "- Threads: \`$THREADS\`"
  echo "- Build jobs: \`$BUILD_JOBS\`"
  echo "- System monitoring: \`$MONITOR_SYSTEM\`"
  echo
  echo "| Fixture | Proofs | Runs | Median | Average | Min-Max | Recursive proof | Input tx proofs | Max padded |"
  echo "|---|---:|---:|---:|---:|---:|---:|---:|---:|"

  for fixture in "${FIXTURES[@]}"; do
    IFS='|' read -r fixture _source_path _expected _guard <<< "$(fixture_meta "$FIXTURE_ROOT" "$fixture")"
    for proof_count in "${PROOF_COUNTS[@]}"; do
      median="$(median_tsv_field "$RESULTS_TSV" 1 "$fixture" 3 "$proof_count" 4)"
      average="$(avg_tsv_field "$RESULTS_TSV" 1 "$fixture" 3 "$proof_count" 4)"
      minmax="$(minmax_tsv_field "$RESULTS_TSV" 1 "$fixture" 3 "$proof_count" 4)"
      proof="$(first_tsv_field "$RESULTS_TSV" 1 "$fixture" 3 "$proof_count" 5)"
      tx_proofs="$(first_tsv_field "$RESULTS_TSV" 1 "$fixture" 3 "$proof_count" 6)"
      padded="$(first_tsv_field "$RESULTS_TSV" 1 "$fixture" 3 "$proof_count" 18)"
      echo "| $fixture | $proof_count | $REPEAT | ${median} ms | ${average} ms | ${minmax} ms | ${proof} B | ${tx_proofs} B | $padded |"
    done
  done

  echo
  echo "## AIR Metadata"
  echo
  echo "| AIR | Trace width | Aux width | Max degree | Notes |"
  echo "|---|---:|---:|---:|---|"
  tail -n +2 "$AIR_TSV" | while IFS=$'\t' read -r air width aux degree notes; do
    echo "| $air | $width | $aux | $degree | $notes |"
  done

  echo
  echo "## Files"
  echo
  echo "- Parsed rows: \`results.tsv\`"
  echo "- AIR metadata: \`air_metadata.tsv\`"
  echo "- Fixture paths: \`fixture_paths.tsv\`"
  echo "- Candidate fixtures: \`candidate-fixtures/\`"
  echo "- Raw logs: \`logs/\`"
  echo "- System snapshots: \`monitoring/\`"
  echo "- Metadata: \`metadata.txt\`"
} > "$SUMMARY_MD"

ln -sfn "$RUN_DIR" "$RESULT_ROOT/latest"

echo
echo "[blakeg-recursive] results: $RUN_DIR"
cat "$SUMMARY_MD"
