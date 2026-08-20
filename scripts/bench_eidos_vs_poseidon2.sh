#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EIDOS_REV="${EIDOS_REV:-7b2b1113aa619db9dba10cdfcf679404c4b823a3}"
FIXTURE_ROOT="$ROOT/bench-baselines/fixtures/bench-tx"
MODE=""
# Keep the historical #3306/#3307 comparison default; override it for the host with --threads.
THREADS="${RAYON_NUM_THREADS:-16}"

die() {
  echo "error: $*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  scripts/bench_eidos_vs_poseidon2.sh --smoke [--threads N] [--eidos-rev REV]
  scripts/bench_eidos_vs_poseidon2.sh --full  [--threads N] [--eidos-rev REV]

--smoke  Three measured create-one ECDSA proofs in each arm, followed by the
         headline Poseidon2 5 MVM + 1 PVM versus Eidos 4 MVM + 1 PVM case.
--full   One warmup and ten measurements for all six Falcon/ECDSA transaction
         fixtures and the ECDSA/Falcon 3..9 MVM + 1 PVM recursive curves.
         High-count Eidos compositions require substantial memory; full mode
         intentionally retains them for larger machines.

--threads N            Rayon/build threads. Default: 16, matching #3306/#3307.
--eidos-rev REV         Eidos commit or branch. By default, use the production
                        revision pinned by this script.

The script benchmarks detached temporary worktrees at the current committed
Poseidon2 HEAD and the selected Eidos revision. It does not modify either tree.
EOF
}

while (( $# > 0 )); do
  case "$1" in
    --smoke|--full)
      [[ -z "$MODE" ]] || die "select exactly one of --smoke or --full"
      MODE="${1#--}"
      shift
      ;;
    --threads)
      (( $# >= 2 )) || die "--threads requires a value"
      THREADS="$2"
      shift 2
      ;;
    --eidos-rev)
      (( $# >= 2 )) || die "--eidos-rev requires a value"
      EIDOS_REV="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "unknown argument: $1"
      ;;
  esac
done
[[ -n "$MODE" ]] || { usage >&2; die "select --smoke or --full"; }
[[ "$THREADS" =~ ^[1-9][0-9]*$ ]] || die "--threads must be a positive integer"

for command in cargo git perl awk sed cmp tee rustc; do
  command -v "$command" >/dev/null 2>&1 || die "missing required command: $command"
done
POSEIDON2_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
EIDOS_COMMIT="$(git -C "$ROOT" rev-parse --verify "$EIDOS_REV^{commit}" 2>/dev/null)" ||
  die "Eidos revision $EIDOS_REV is unavailable"

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$FIXTURE_ROOT" && sha256sum --check SHA256SUMS)
elif command -v shasum >/dev/null 2>&1; then
  (cd "$FIXTURE_ROOT" && shasum -a 256 --check SHA256SUMS)
else
  die "sha256sum or shasum is required"
fi

RECURSIVE_LABELS=("ecdsa" "falcon")
RECURSIVE_FILES=(
  "synthetic_bench_bench-tx__consume-single-p2id-note-with-ecdsa-signing.masm"
  "synthetic_bench_bench-tx__consume-single-p2id-note-with-falcon-signing.masm"
)

if [[ "$MODE" == "smoke" ]]; then
  WARMUPS=0
  REPEATS=3
  LABELS=("create-one-ecdsa")
  FILES=("synthetic_bench_bench-tx__create-single-p2id-note-with-ecdsa-signing.masm")
else
  WARMUPS=1
  REPEATS=10
  LABELS=(
    "create-one-ecdsa" "create-one-falcon"
    "consume-one-ecdsa" "consume-one-falcon"
    "consume-two-ecdsa" "consume-two-falcon"
  )
  FILES=(
    "synthetic_bench_bench-tx__create-single-p2id-note-with-ecdsa-signing.masm"
    "synthetic_bench_bench-tx__create-single-p2id-note-with-falcon-signing.masm"
    "synthetic_bench_bench-tx__consume-single-p2id-note-with-ecdsa-signing.masm"
    "synthetic_bench_bench-tx__consume-single-p2id-note-with-falcon-signing.masm"
    "synthetic_bench_bench-tx__consume-two-p2id-notes-with-ecdsa-signing.masm"
    "synthetic_bench_bench-tx__consume-two-p2id-notes-with-falcon-signing.masm"
  )
fi

export RAYON_NUM_THREADS="$THREADS"
export CARGO_BUILD_JOBS="$THREADS"
unset CARGO_ENCODED_RUSTFLAGS
export RUSTFLAGS="-C target-cpu=native"
unset RECURSION_BENCH_STACK RECURSION_MASM_WRITE RECURSION_PROFILE_ONLY
RUN_ID="$(date -u +%Y%m%d-%H%M%S)-$$"
RUN_DIR="$ROOT/target/eidos-vs-poseidon2/$RUN_ID"
P2_ROOT="$RUN_DIR/worktrees/poseidon2"
EIDOS_ROOT="$RUN_DIR/worktrees/eidos"
LOG_DIR="$RUN_DIR/logs"
EIDOS_FIXTURES="$RUN_DIR/fixtures/eidos"
mkdir -p "$LOG_DIR" "$EIDOS_FIXTURES" "$RUN_DIR/cache"

cleanup() {
  git -C "$ROOT" worktree remove --force "$P2_ROOT" >/dev/null 2>&1 || true
  git -C "$ROOT" worktree remove --force "$EIDOS_ROOT" >/dev/null 2>&1 || true
  git -C "$ROOT" worktree prune >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ -n "$(git -C "$ROOT" status --porcelain)" ]]; then
  echo "warning: local worktree changes are ignored; benchmarking committed HEAD $POSEIDON2_COMMIT" >&2
fi
echo "[setup] Poseidon2 $POSEIDON2_COMMIT"
echo "[setup] Eidos $EIDOS_COMMIT ($EIDOS_REV)"
echo "[setup] results $RUN_DIR"
git -C "$ROOT" worktree add --detach "$P2_ROOT" "$POSEIDON2_COMMIT"
git -C "$ROOT" worktree add --detach "$EIDOS_ROOT" "$EIDOS_COMMIT"

install_masm_runner() {
  local worktree="$1"
  mkdir -p "$worktree/benches/synthetic-bench/benches"
  cat > "$worktree/benches/synthetic-bench/benches/masm_prove.rs" <<'RUST'
use std::{env, fs, hint::black_box, time::Instant};

use miden_assembly::Assembler;
use miden_core::{Felt, program::ExecutionClaim};
use miden_processor::{
    DefaultHost, ExecutionOptions, FastProcessor, StackInputs, advice::AdviceInputs,
    trace::build_trace,
};
use miden_vm::{HashFunction, Prover, Verifier, prove_sync};

fn number(name: &str, default: usize) -> usize {
    env::var(name).map_or(default, |raw| raw.parse().expect("invalid benchmark count"))
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[middle - 1] + values[middle]) / 2.0
    } else {
        values[middle]
    }
}

fn main() {
    let path = env::var("MASM_PROVE_PATH").expect("MASM_PROVE_PATH is required");
    let case = env::var("MASM_PROVE_CASE").expect("MASM_PROVE_CASE is required");
    let protocol = env::var("MASM_PROVE_HASH").expect("MASM_PROVE_HASH is required");
    let hash_fn = HashFunction::try_from(protocol.as_str()).expect("unsupported proof hash");
    let warmups = number("MASM_PROVE_WARMUPS", 1);
    let repeats = number("MASM_PROVE_REPEATS", 10);
    assert!(repeats > 0);

    let source = fs::read_to_string(&path).expect("read MASM fixture");
    let (required, forbidden) = if protocol == "eidos" {
        ("bcompress", "hperm")
    } else {
        ("hperm", "bcompress")
    };
    assert!(source.lines().any(|line| line.trim() == required));
    assert!(!source.lines().any(|line| line.trim() == forbidden));
    let program = Assembler::default()
        .assemble_program("synthetic_benchmark", source)
        .expect("assemble fixture")
        .unwrap_program();
    let stack_inputs = StackInputs::new(&[Felt::from_u32(0), Felt::from_u32(1)]).unwrap();

    let mut host = DefaultHost::default();
    let witness = FastProcessor::new_with_options(
        stack_inputs,
        AdviceInputs::default(),
        ExecutionOptions::default(),
    )
    .unwrap()
    .execute_for_proving_sync(&program, &mut host)
    .unwrap();
    let (vm_witness, _) = witness.into_parts();
    let trace = build_trace(vm_witness).unwrap();
    println!(
        "BENCH_MASM_TRACE case={case} protocol={protocol} summary={:?}",
        trace.trace_len_summary()
    );

    let prover = Prover::new().with_hash_fn(hash_fn);
    let mut samples = Vec::with_capacity(repeats);
    for (measured, count) in [(false, warmups), (true, repeats)] {
        for run in 1..=count {
            let mut host = DefaultHost::default();
            let started = Instant::now();
            let (outputs, proof) = prove_sync(
                &prover,
                &program,
                stack_inputs,
                AdviceInputs::default(),
                &mut host,
                ExecutionOptions::default(),
            )
            .unwrap();
            let prove_ms = started.elapsed().as_secs_f64() * 1000.0;
            let proof_bytes = proof.to_bytes().len();
            let claim = ExecutionClaim::from_program_info(program.to_info(), stack_inputs, outputs);
            let started = Instant::now();
            let outcome = Verifier::new().verify(&claim, &proof).unwrap();
            let verify_ms = started.elapsed().as_secs_f64() * 1000.0;
            assert!(outcome.is_complete());
            black_box(proof);
            let kind = if measured { "run" } else { "warmup" };
            println!(
                "BENCH_MASM_PROOF case={case} protocol={protocol} kind={kind} run={run} \
                 prove_ms={prove_ms:.3} verify_ms={verify_ms:.3} proof_bytes={proof_bytes}"
            );
            if measured {
                samples.push((prove_ms, verify_ms, proof_bytes));
            }
        }
    }

    let mut prove = samples.iter().map(|sample| sample.0).collect::<Vec<_>>();
    let mut verify = samples.iter().map(|sample| sample.1).collect::<Vec<_>>();
    println!(
        "BENCH_MASM_SUMMARY case={case} protocol={protocol} runs={} median_prove_ms={:.3} \
         median_verify_ms={:.3} first_proof_bytes={}",
        samples.len(),
        median(&mut prove),
        median(&mut verify),
        samples[0].2,
    );
}
RUST
  cat >> "$worktree/benches/synthetic-bench/Cargo.toml" <<'TOML'

[[bench]]
name = "masm_prove"
harness = false
TOML
}

patch_recursive_harness() {
  local worktree="$1"
  local config="$worktree/benches/synthetic-bench/benches/recursive_verify/config.rs"
  local measurements="$worktree/benches/synthetic-bench/benches/recursive_verify/measurements.rs"

  perl -0pi -e '
    s/const PVM_COMPARISON_COMPOSITIONS: \[ProofComposition; 4\] = \[\n    ProofComposition::mixed\(4\),\n    ProofComposition::mvm\(7\),\n    ProofComposition::mixed\(5\),\n    ProofComposition::mvm\(8\),\n\];/const PVM_COMPARISON_PROOF_COUNTS: [usize; 4] = [3, 4, 5, 6];/
      or die "unexpected recursive composition source\n";
    s/            assert!\(\n                std::env::var_os\("RECURSION_PROOF_COUNTS"\)\.is_none\(\),\n                "RECURSION_PROOF_COUNTS cannot be combined with RECURSION_PVM_COMPARISON"\n            \);\n            PVM_COMPARISON_COMPOSITIONS\.to_vec\(\)/            proof_counts_from_env(\&PVM_COMPARISON_PROOF_COUNTS)\n                .into_iter()\n                .map(ProofComposition::mixed)\n                .collect()/
      or die "unexpected recursive selection source\n";
  ' "$config"

  perl -0pi -e '
    s/use miden_processor/use miden_core::program::ExecutionClaim;\nuse miden_processor/
      or die "unexpected recursive imports\n";
    s/    ExecutionProof, ExecutionWitness, HashFunction, Prover, StackInputs, StackOutputs, VmTrace,\n    prove_sync, trace::build_trace,/    ExecutionProof, ExecutionWitness, HashFunction, Prover, StackInputs, StackOutputs, Verifier,\n    VmTrace, prove_sync, trace::build_trace,/
      or die "unexpected recursive VM imports\n";
    s/    let \(_, proof\) = prove_sync\(\n        \&Prover::new\(\)\.with_hash_fn\(hash_fn\),\n        \&case\.program,\n        StackInputs::default\(\),/    let stack_inputs = StackInputs::default();\n    let (stack_outputs, proof) = prove_sync(\n        \&Prover::new().with_hash_fn(hash_fn),\n        \&case.program,\n        stack_inputs,/
      or die "unexpected recursive prove source\n";
    s/    let proof_bytes = proof\.to_bytes\(\)\.len\(\);\n    black_box/    let proof_bytes = proof.to_bytes().len();\n    let claim =\n        ExecutionClaim::from_program_info(case.program.to_info(), stack_inputs, stack_outputs);\n    let outcome = Verifier::new().verify(\&claim, \&proof).expect("verify recursive proof");\n    assert!(outcome.is_complete(), "recursive benchmark proof must be complete");\n    black_box/
      or die "unexpected recursive proof footer\n";
  ' "$measurements"
}

for worktree in "$P2_ROOT" "$EIDOS_ROOT"; do
  install_masm_runner "$worktree"
  patch_recursive_harness "$worktree"
done

logical_hash_calls() {
  local opcode="$1"
  local path="$2"
  perl -ne '
    $repeat = $1 if /^\s*repeat\.(\d+)\s*$/;
    if (/^\s*'"$opcode"'\s*$/) {
      die "native-hash opcode is not directly inside repeat.N\n" unless defined $repeat;
      $calls += $repeat;
      undef $repeat;
    }
    END { print(($calls // 0), "\n") }
  ' "$path"
}

for index in "${!FILES[@]}"; do
  source_path="$FIXTURE_ROOT/${FILES[$index]}"
  eidos_path="$EIDOS_FIXTURES/${FILES[$index]}"
  reverse_path="$RUN_DIR/fixtures/reversed.masm"
  perl -pe 's/\bhperm\b/bcompress/g' "$source_path" > "$eidos_path"
  perl -pe 's/\bbcompress\b/hperm/g' "$eidos_path" > "$reverse_path"
  cmp -s "$source_path" "$reverse_path" ||
    die "fixture ${FILES[$index]} changed beyond hperm -> bcompress"
done
rm "$RUN_DIR/fixtures/reversed.masm"

for index in "${!RECURSIVE_FILES[@]}"; do
  auth="${RECURSIVE_LABELS[$index]}"
  fixture="${RECURSIVE_FILES[$index]}"
  eidos_fixture="$EIDOS_FIXTURES/$fixture"
  reverse_fixture="$RUN_DIR/fixtures/reversed-recursive-$auth.masm"
  if [[ ! -f "$eidos_fixture" ]]; then
    perl -pe 's/\bhperm\b/bcompress/g' "$FIXTURE_ROOT/$fixture" > "$eidos_fixture"
  fi
  perl -pe 's/\bbcompress\b/hperm/g' "$eidos_fixture" > "$reverse_fixture"
  cmp -s "$FIXTURE_ROOT/$fixture" "$reverse_fixture" ||
    die "recursive $auth fixture changed beyond hperm -> bcompress"
  rm "$reverse_fixture"
done

{
  echo "mode=$MODE"
  echo "poseidon2_commit=$POSEIDON2_COMMIT"
  echo "eidos_commit=$EIDOS_COMMIT"
  echo "eidos_revision=$EIDOS_REV"
  echo "threads=$THREADS"
  echo "warmups=$WARMUPS"
  echo "repeats=$REPEATS"
  echo "recursive_auth=ecdsa,falcon"
  echo "rustc=$(rustc --version)"
  echo "cargo=$(cargo --version)"
  echo "uname=$(uname -a)"
  echo "started=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "rustflags=${RUSTFLAGS:-}"
  df -h "$ROOT"
} > "$RUN_DIR/metadata.txt"

run_synthetic() {
  local protocol="$1" worktree="$2" case_name="$3" fixture="$4"
  echo "[synthetic] $case_name / $protocol"
  (
    cd "$worktree"
    CARGO_TARGET_DIR="$ROOT/target/eidos-vs-poseidon2-build/$protocol" \
    MASM_PROVE_PATH="$fixture" \
    MASM_PROVE_CASE="$case_name" \
    MASM_PROVE_HASH="$protocol" \
    MASM_PROVE_WARMUPS="$WARMUPS" \
    MASM_PROVE_REPEATS="$REPEATS" \
      cargo bench --locked -p miden-vm-synthetic-bench --bench masm_prove --profile optimized
  ) 2>&1 | tee "$LOG_DIR/synthetic-${case_name}-${protocol}.log"
}

for index in "${!FILES[@]}"; do
  run_synthetic poseidon2 "$P2_ROOT" "${LABELS[$index]}" "$FIXTURE_ROOT/${FILES[$index]}"
  run_synthetic eidos "$EIDOS_ROOT" "${LABELS[$index]}" "$EIDOS_FIXTURES/${FILES[$index]}"
done

run_recursive() {
  local protocol="$1" worktree="$2" auth="$3" count="$4" fixture="$5"
  echo "[recursive] $auth / $protocol / $count MVM + 1 PVM"
  (
    cd "$worktree"
    CARGO_TARGET_DIR="$ROOT/target/eidos-vs-poseidon2-build/$protocol" \
    RECURSION_BENCH_MASM="$fixture" \
    RECURSION_BENCH_HASH="$protocol" \
    RECURSION_PVM_COMPARISON=1 \
    RECURSION_PROOF_COUNTS="$count" \
    RECURSION_PROFILE_PROVE=1 \
    RECURSION_PROFILE_PROVE_WARMUPS="$WARMUPS" \
    RECURSION_PROFILE_PROVE_REPEATS="$REPEATS" \
    RECURSION_BENCH_TX_PROOF_CACHE_DIR="$RUN_DIR/cache/$protocol/tx" \
    RECURSION_BENCH_PVM_PROOF_CACHE_DIR="$RUN_DIR/cache/$protocol/pvm" \
      cargo bench --locked -p miden-vm-synthetic-bench --bench recursive_verify --profile optimized
  ) 2>&1 | tee "$LOG_DIR/recursive-${auth}-${count}mvm-1pvm-${protocol}.log"
}

if [[ "$MODE" == "smoke" ]]; then
  fixture="${RECURSIVE_FILES[0]}"
  run_recursive poseidon2 "$P2_ROOT" ecdsa 5 "$FIXTURE_ROOT/$fixture"
  run_recursive eidos "$EIDOS_ROOT" ecdsa 4 "$EIDOS_FIXTURES/$fixture"
else
  echo "[full] recursive cases run in separate processes to release each proving setup"
  for index in "${!RECURSIVE_FILES[@]}"; do
    auth="${RECURSIVE_LABELS[$index]}"
    fixture="${RECURSIVE_FILES[$index]}"
    for count in 3 4 5 6 7 8 9; do
      run_recursive poseidon2 "$P2_ROOT" "$auth" "$count" "$FIXTURE_ROOT/$fixture"
    done
    for count in 3 4 5 6 7 8 9; do
      run_recursive eidos "$EIDOS_ROOT" "$auth" "$count" "$EIDOS_FIXTURES/$fixture"
    done
  done
fi

extract_row() {
  local field="$1" log="$2"
  grep -Eo "(^|[[:space:]{,])${field}: [0-9]+" "$log" | head -n 1 | sed -E 's/.*: //'
}

printf 'case\tlogical_hash_calls\tposeidon2_core\teidos_core\tposeidon2_hash_rows\teidos_hash_rows\teidos_minus_2x_poseidon2\n' \
  > "$RUN_DIR/trace-checks.tsv"
for index in "${!FILES[@]}"; do
  label="${LABELS[$index]}"
  p2_log="$LOG_DIR/synthetic-${label}-poseidon2.log"
  eidos_log="$LOG_DIR/synthetic-${label}-eidos.log"
  p2_core="$(extract_row core_trace_len "$p2_log")"
  eidos_core="$(extract_row core_rows "$eidos_log")"
  p2_hash="$(extract_row poseidon2_permutation_trace_len "$p2_log")"
  eidos_hash="$(extract_row blakeg_compression_rows "$eidos_log")"
  [[ -n "$p2_core" && -n "$eidos_core" && -n "$p2_hash" && -n "$eidos_hash" ]] ||
    die "could not parse trace shape for $label"
  [[ "$p2_core" == "$eidos_core" ]] || die "core rows differ for $label"
  delta=$(( eidos_hash - (2 * p2_hash) ))
  (( delta >= -32 && delta <= 32 )) || die "native-hash rows are not approximately 2x for $label"
  calls="$(logical_hash_calls hperm "$FIXTURE_ROOT/${FILES[$index]}")"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$label" "$calls" "$p2_core" "$eidos_core" "$p2_hash" "$eidos_hash" "$delta" \
    >> "$RUN_DIR/trace-checks.tsv"
done

: > "$RUN_DIR/summaries.txt"
for log in "$LOG_DIR"/*.log; do
  grep -E '^BENCH_(MASM_SUMMARY|RECURSION_PROOF_SUMMARY) ' "$log" |
    sed "s|^|log=$(basename "$log") |" >> "$RUN_DIR/summaries.txt" || true
done
echo "finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$RUN_DIR/metadata.txt"

echo
cat "$RUN_DIR/summaries.txt"
echo
echo "results: $RUN_DIR"
echo "trace checks: $RUN_DIR/trace-checks.tsv"
