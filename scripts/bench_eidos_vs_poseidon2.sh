#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Resolve the repository-pinned Rust toolchain even when the script is invoked
# through an absolute path from another directory.
cd "$ROOT"
EIDOS_REV="${EIDOS_REV:-d29170b61b50cd5000871b96901919e711f8a2dc}"
FIXTURE_ROOT="$ROOT/bench-baselines/fixtures/bench-tx"
MODE=""
# Keep the historical #3306/#3307 comparison default; override it for the host with --threads.
THREADS=16
THREADS_EXPLICIT=0
CPU_PROFILE="native"
DRY_RUN=0
CPU_POOL=()
NUMA_NODES=""
NUMA_POLICY="inherited"
LLC_DOMAIN_COUNT="unavailable"
CGROUP_CPU_LIMITS="unavailable"
CGROUP_STAT_DIR=""
HUGETLB_MODE="not-controlled"
LIBC_VERSION="unavailable"

die() {
  echo "error: $*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  scripts/bench_eidos_vs_poseidon2.sh --smoke    [OPTIONS]
  scripts/bench_eidos_vs_poseidon2.sh --headline [OPTIONS]
  scripts/bench_eidos_vs_poseidon2.sh --scaling  [OPTIONS]
  scripts/bench_eidos_vs_poseidon2.sh --full     [OPTIONS]

--smoke  Three measured create-one ECDSA proofs in each arm, followed by the
         headline Poseidon2 5 MVM + 1 PVM versus Eidos 4 MVM + 1 PVM case.
--headline
         Run only the recursive headline pair at one selected thread count.
--scaling
         Run the headline pair at 8,16,32,64,64,32,16,8 Rayon threads. Linux
         guest topology selects one allowed vCPU per visible core, spreads the
         pool across NUMA/LLC domains, and interleaves memory across its nodes.
--full   One warmup and ten measurements for all six Falcon/ECDSA transaction
         fixtures and the ECDSA/Falcon 3..9 MVM + 1 PVM recursive curves.
         High-count Eidos compositions require substantial memory; full mode
         intentionally retains them for larger machines.

--threads N            Rayon/build threads. Default: 16, matching #3306/#3307.
--cpu-profile PROFILE  Rust target CPU: native, x86-64-v3, or x86-64-v4.
                       Default: native.
--dry-run              Validate a scaling host and print its placement without
                       creating worktrees or running benchmarks.
--eidos-rev REV         Eidos commit or branch. By default, use the production
                        revision pinned by this script.

The script benchmarks detached temporary worktrees at the current committed
Poseidon2 HEAD and the selected Eidos revision. It does not modify either tree.

Scaling campaigns require an explicit malloc huge-page arm on every host:
  GLIBC_TUNABLES=glibc.malloc.hugetlb=0  # requested off
  GLIBC_TUNABLES=glibc.malloc.hugetlb=1  # requested on
Kernel THP must be set to madvise so these two arms remain interpretable.
EOF
}

while (( $# > 0 )); do
  case "$1" in
    --smoke|--headline|--scaling|--full)
      [[ -z "$MODE" ]] ||
        die "select exactly one of --smoke, --headline, --scaling, or --full"
      MODE="${1#--}"
      shift
      ;;
    --threads)
      (( $# >= 2 )) || die "--threads requires a value"
      THREADS="$2"
      THREADS_EXPLICIT=1
      shift 2
      ;;
    --cpu-profile)
      (( $# >= 2 )) || die "--cpu-profile requires a value"
      CPU_PROFILE="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
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
[[ -n "$MODE" ]] || {
  usage >&2
  die "select --smoke, --headline, --scaling, or --full"
}
[[ "$THREADS" =~ ^[1-9][0-9]*$ ]] || die "--threads must be a positive integer"
case "$CPU_PROFILE" in
  native|x86-64-v3|x86-64-v4) ;;
  *) die "--cpu-profile must be native, x86-64-v3, or x86-64-v4" ;;
esac
if [[ "$CPU_PROFILE" != "native" && "$(uname -m)" != "x86_64" ]]; then
  die "$CPU_PROFILE requires an x86_64 host"
fi
if [[ "$MODE" == "scaling" ]]; then
  (( THREADS_EXPLICIT == 0 )) || die "--scaling uses its fixed thread plan; omit --threads"
else
  (( DRY_RUN == 0 )) || die "--dry-run is supported only with --scaling"
fi

for command in cargo git perl awk sed cmp tee rustc; do
  command -v "$command" >/dev/null 2>&1 || die "missing required command: $command"
done
if command -v ldd >/dev/null 2>&1; then
  LIBC_VERSION="$(ldd --version 2>&1 | sed -n '1p' || true)"
fi
if [[ "$MODE" == "scaling" ]]; then
  hugetlb_settings=()
  IFS=: read -r -a tunables <<< "${GLIBC_TUNABLES:-}"
  for tunable in "${tunables[@]}"; do
    [[ "$tunable" == glibc.malloc.hugetlb=* ]] && hugetlb_settings+=("$tunable")
  done
  ((${#hugetlb_settings[@]} == 1)) ||
    die "--scaling requires exactly one GLIBC_TUNABLES malloc hugetlb setting: 0 or 1"
  case "${hugetlb_settings[0]}" in
    glibc.malloc.hugetlb=0) HUGETLB_MODE="requested-off" ;;
    glibc.malloc.hugetlb=1) HUGETLB_MODE="requested-on" ;;
    *) die "--scaling requires glibc.malloc.hugetlb=0 or glibc.malloc.hugetlb=1" ;;
  esac
  [[ "$LIBC_VERSION" == *GLIBC* || "$LIBC_VERSION" == *"GNU libc"* ]] ||
    die "--scaling requires glibc with the malloc hugetlb tunable"
  [[ -r /sys/kernel/mm/transparent_hugepage/enabled ]] ||
    die "--scaling cannot read the kernel transparent-hugepage policy"
  grep -q '\[madvise\]' /sys/kernel/mm/transparent_hugepage/enabled ||
    die "--scaling requires kernel transparent huge pages in madvise mode"
fi
POSEIDON2_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
EIDOS_COMMIT="$(git -C "$ROOT" rev-parse --verify "$EIDOS_REV^{commit}" 2>/dev/null)" ||
  die "Eidos revision $EIDOS_REV is unavailable"

if command -v sha256sum >/dev/null 2>&1; then
  SHA256_IMPL="sha256sum"
  (cd "$FIXTURE_ROOT" && sha256sum --check SHA256SUMS)
elif command -v shasum >/dev/null 2>&1; then
  SHA256_IMPL="shasum"
  (cd "$FIXTURE_ROOT" && shasum -a 256 --check SHA256SUMS)
else
  die "sha256sum or shasum is required"
fi

sha256_file() {
  if [[ "$SHA256_IMPL" == "sha256sum" ]]; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

sha256_stdin() {
  if [[ "$SHA256_IMPL" == "sha256sum" ]]; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}

RECURSIVE_LABELS=("ecdsa" "falcon")
RECURSIVE_FILES=(
  "synthetic_bench_bench-tx__consume-single-p2id-note-with-ecdsa-signing.masm"
  "synthetic_bench_bench-tx__consume-single-p2id-note-with-falcon-signing.masm"
)

case "$MODE" in
  smoke)
    WARMUPS=0
    REPEATS=3
    RECURSIVE_AUTH="ecdsa"
    LABELS=("create-one-ecdsa")
    FILES=("synthetic_bench_bench-tx__create-single-p2id-note-with-ecdsa-signing.masm")
    ;;
  headline)
    WARMUPS=1
    REPEATS=3
    RECURSIVE_AUTH="ecdsa"
    LABELS=()
    FILES=()
    ;;
  scaling)
    WARMUPS=1
    REPEATS=3
    RECURSIVE_AUTH="ecdsa"
    LABELS=()
    FILES=()
    ;;
  full)
    WARMUPS=1
    REPEATS=10
    RECURSIVE_AUTH="ecdsa,falcon"
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
    ;;
esac

if [[ "$MODE" == "scaling" ]]; then
  THREAD_PLAN=(8 16 32 64 64 32 16 8)
  BUILD_JOBS=64
else
  THREAD_PLAN=("$THREADS")
  BUILD_JOBS="$THREADS"
fi

cpu_list_contains() {
  local target="$1" list="$2" part first last
  local parts=()
  IFS=, read -r -a parts <<< "$list"
  for part in "${parts[@]}"; do
    if [[ "$part" == *-* ]]; then
      first="${part%-*}"
      last="${part#*-}"
    else
      first="$part"
      last="$part"
    fi
    (( target >= first && target <= last )) && return 0
  done
  return 1
}

discover_scaling_topology() {
  [[ "$(uname -s)" == "Linux" ]] || die "--scaling requires Linux"
  for command in lscpu taskset numactl; do
    command -v "$command" >/dev/null 2>&1 || die "--scaling requires $command"
  done
  [[ -r /proc/self/status ]] || die "--scaling cannot read inherited CPU affinity"
  local inherited_cpus
  inherited_cpus="$(awk '/^Cpus_allowed_list:/ { print $2; exit }' /proc/self/status)"
  [[ -n "$inherited_cpus" ]] || die "--scaling could not parse Cpus_allowed_list"

  local candidate_cpus=() candidate_domains=()
  local node_order=() raw_domains=() domain_order=()
  local seen_cores=" " seen_nodes=" " seen_domains=" "
  local cpu core socket node llc key domain
  while IFS=, read -r cpu core socket node llc; do
    [[ "$cpu" =~ ^[0-9]+$ ]] || continue
    # util-linux may print CACHE as separate columns or one L1:L2:L3 field.
    llc="${llc##*:}"
    [[ "$core" =~ ^[0-9]+$ && "$socket" =~ ^[0-9]+$ && "$node" =~ ^[0-9]+$ &&
      "$llc" =~ ^[0-9]+$ ]] || die "lscpu did not report complete core/NUMA/LLC topology"
    key="$socket:$core"
    [[ "$seen_cores" != *" $key "* ]] || continue
    cpu_list_contains "$cpu" "$inherited_cpus" || continue
    taskset -c "$cpu" true >/dev/null 2>&1 || continue
    seen_cores+="$key "
    domain="$node:$llc"
    candidate_cpus+=("$cpu")
    candidate_domains+=("$domain")
    if [[ "$seen_nodes" != *" $node "* ]]; then
      seen_nodes+="$node "
      node_order+=("$node")
    fi
    if [[ "$seen_domains" != *" $domain "* ]]; then
      seen_domains+="$domain "
      raw_domains+=("$domain")
    fi
  done < <(LC_ALL=C lscpu --parse=CPU,CORE,SOCKET,NODE,CACHE |
    awk -F, '$1 !~ /^#/ { print $1 "," $2 "," $3 "," $4 "," $NF }')

  ((${#candidate_cpus[@]} >= 64)) ||
    die "--scaling needs 64 allowed guest-visible cores; found ${#candidate_cpus[@]}"
  ((${#node_order[@]} <= 8)) ||
    die "--scaling cannot spread its 8-thread point across ${#node_order[@]} NUMA nodes"
  LLC_DOMAIN_COUNT="${#raw_domains[@]}"

  # Order LLC domains round-robin across NUMA nodes, then take one core from
  # each domain per round. Every thread-count prefix is therefore as dispersed
  # as the guest topology permits while remaining nested.
  local ordinal=0 added=0 seen_on_node=0 selected_node selected_domain index
  while ((${#domain_order[@]} < ${#raw_domains[@]})); do
    added=0
    for selected_node in "${node_order[@]}"; do
      seen_on_node=0
      for domain in "${raw_domains[@]}"; do
        [[ "${domain%%:*}" == "$selected_node" ]] || continue
        if (( seen_on_node == ordinal )); then
          domain_order+=("$domain")
          added=1
          break
        fi
        seen_on_node=$((seen_on_node + 1))
      done
    done
    (( added == 1 )) || break
    ordinal=$((ordinal + 1))
  done

  ordinal=0
  while ((${#CPU_POOL[@]} < 64)); do
    added=0
    for selected_domain in "${domain_order[@]}"; do
      seen_on_node=0
      for index in "${!candidate_cpus[@]}"; do
        [[ "${candidate_domains[$index]}" == "$selected_domain" ]] || continue
        if (( seen_on_node == ordinal )); then
          CPU_POOL+=("${candidate_cpus[$index]}")
          added=1
          break
        fi
        seen_on_node=$((seen_on_node + 1))
      done
      ((${#CPU_POOL[@]} >= 64)) && break
    done
    (( added == 1 )) || break
    ordinal=$((ordinal + 1))
  done
  ((${#CPU_POOL[@]} == 64)) || die "could not construct a 64-core LLC/NUMA-spread pool"

  NUMA_NODES="$(IFS=,; echo "${node_order[*]}")"

  local pool
  pool="$(cpu_list_for_threads 64)"
  numactl --physcpubind="$pool" --interleave="$NUMA_NODES" true >/dev/null 2>&1 ||
    die "numactl cannot enforce CPU binding and interleaved memory policy"
  NUMA_POLICY="interleave:$NUMA_NODES"

  [[ -r /sys/fs/cgroup/cgroup.controllers ]] ||
    die "--scaling requires cgroup v2 to validate effective CPU quotas"
  local cgroup_path current quota period label limits="" saw_cpu_max=0
  cgroup_path="$(awk -F: '$1 == "0" { print $3; exit }' /proc/self/cgroup)"
  [[ -n "$cgroup_path" ]] || cgroup_path="/"
  current="/sys/fs/cgroup${cgroup_path%/}"
  [[ -n "$current" ]] || current="/sys/fs/cgroup"
  while [[ "$current" == /sys/fs/cgroup* ]]; do
    if [[ -z "$CGROUP_STAT_DIR" && -r "$current/cpu.stat" ]]; then
      CGROUP_STAT_DIR="$current"
    fi
    if [[ -r "$current/cpu.max" ]]; then
      read -r quota period < "$current/cpu.max"
      label="${current#/sys/fs/cgroup}"
      [[ -n "$label" ]] || label="/"
      limits+="${limits:+;}$label=$quota/$period"
      saw_cpu_max=1
      if [[ "$quota" != "max" ]]; then
        die "--scaling requires an unlimited cgroup CPU quota; $label has $quota/$period"
      fi
    fi
    [[ "$current" == "/sys/fs/cgroup" ]] && break
    current="${current%/*}"
  done
  (( saw_cpu_max == 1 )) || die "--scaling could not validate cgroup-v2 CPU quotas"
  CGROUP_CPU_LIMITS="$limits"
}

cpu_list_for_threads() {
  local count="$1"
  ((${#CPU_POOL[@]} > 0)) || return 0
  local selected=("${CPU_POOL[@]:0:$count}")
  local IFS=,
  printf '%s' "${selected[*]}"
}

if [[ "$MODE" == "scaling" ]]; then
  discover_scaling_topology
fi

TARGET_CFG="$(rustc --print cfg -C "target-cpu=$CPU_PROFILE")"
target_cfg_has() {
  grep -qFx "target_feature=\"$1\"" <<< "$TARGET_CFG"
}
case "$CPU_PROFILE" in
  x86-64-v3)
    target_cfg_has avx2 || die "rustc did not enable AVX2 for x86-64-v3"
    ! target_cfg_has avx512f || die "rustc unexpectedly enabled AVX-512 for x86-64-v3"
    ;;
  x86-64-v4)
    for feature in avx2 avx512f avx512dq avx512bw avx512cd avx512vl; do
      target_cfg_has "$feature" || die "rustc did not enable $feature for x86-64-v4"
    done
    ;;
esac
if [[ "$CPU_PROFILE" != "native" ]]; then
  [[ -r /proc/cpuinfo ]] || die "cannot validate $CPU_PROFILE without /proc/cpuinfo"
  host_has_on_all_cpus() {
    local feature="$1" alias="${2:-}"
    awk -F: -v feature="$feature" -v alias="$alias" '
      /^flags[[:space:]]*:/ {
        saw = 1
        found = 0
        count = split($2, flags, /[[:space:]]+/)
        for (i = 1; i <= count; i++) {
          if (flags[i] == feature || (alias != "" && flags[i] == alias)) found = 1
        }
        if (!found) missing = 1
      }
      END { exit !(saw && !missing) }
    ' /proc/cpuinfo
  }
  REQUIRED_FLAGS=(
    avx avx2 bmi1 bmi2 cx16 f16c fma lahf_lm lzcnt movbe popcnt pni sse4_1 sse4_2 ssse3 xsave
  )
  if [[ "$CPU_PROFILE" == "x86-64-v4" ]]; then
    REQUIRED_FLAGS+=(avx512f avx512dq avx512bw avx512cd avx512vl)
  fi
  for flag in "${REQUIRED_FLAGS[@]}"; do
    if [[ "$flag" == "lzcnt" ]]; then
      host_has_on_all_cpus lzcnt abm || die "$CPU_PROFILE requires host CPU flag lzcnt"
    else
      host_has_on_all_cpus "$flag" || die "$CPU_PROFILE requires host CPU flag $flag"
    fi
  done
fi
profile_fingerprint_input="$CPU_PROFILE
$TARGET_CFG"
if [[ "$CPU_PROFILE" == "native" ]]; then
  if command -v lscpu >/dev/null 2>&1; then
    profile_fingerprint_input+="
$(LC_ALL=C lscpu | awk -F: '/^(Vendor ID|Model name|CPU family|Model):/ { gsub(/^[ \t]+/, "", $2); print $1 "=" $2 }')"
  elif command -v sysctl >/dev/null 2>&1; then
    profile_fingerprint_input+="
$(sysctl -n machdep.cpu.brand_string 2>/dev/null || true)"
  fi
fi
CPU_PROFILE_FINGERPRINT="$(printf '%s\n' "$profile_fingerprint_input" | sha256_stdin)"
CPU_PROFILE_KEY="$CPU_PROFILE-$CPU_PROFILE_FINGERPRINT"

export CARGO_BUILD_JOBS="$BUILD_JOBS"
unset CARGO_ENCODED_RUSTFLAGS
export RUSTFLAGS="-C target-cpu=$CPU_PROFILE"
unset RECURSION_BENCH_STACK RECURSION_MASM_WRITE RECURSION_PROFILE_ONLY
unset RECURSION_PROFILE_PROVE RECURSION_PROOF_COUNTS RECURSION_PVM_COMPARISON
unset RECURSION_BENCH_HASH RECURSION_BENCH_MASM
unset RECURSION_BENCH_TX_PROOF_CACHE_DIR RECURSION_BENCH_PVM_PROOF_CACHE_DIR
unset SYNTH_BENCH_AXES SYNTH_MASM_WRITE SYNTH_SCENARIO SYNTH_SNAPSHOT

if (( DRY_RUN == 1 )); then
  echo "Poseidon2 commit: $POSEIDON2_COMMIT"
  echo "Eidos commit:     $EIDOS_COMMIT"
  echo "CPU profile:      $CPU_PROFILE"
  echo "Rayon plan:       $(IFS=,; echo "${THREAD_PLAN[*]}")"
  echo "guest CPU pool:   $(cpu_list_for_threads 64)"
  echo "NUMA policy:      $NUMA_POLICY"
  echo "LLC domains:      $LLC_DOMAIN_COUNT"
  echo "cgroup limits:    $CGROUP_CPU_LIMITS"
  echo "malloc THP:       $HUGETLB_MODE"
  echo "libc:             $LIBC_VERSION"
  exit 0
fi

RUN_ID="$(date -u +%Y%m%d-%H%M%S)-$$"
RUN_DIR="$ROOT/target/eidos-vs-poseidon2/$RUN_ID"
P2_ROOT="$RUN_DIR/worktrees/poseidon2"
EIDOS_ROOT="$RUN_DIR/worktrees/eidos"
LOG_DIR="$RUN_DIR/logs"
EIDOS_FIXTURES="$RUN_DIR/fixtures/eidos"
BUILD_CACHE_ROOT="$ROOT/target/eidos-vs-poseidon2-build/$CPU_PROFILE_KEY"
mkdir -p "$LOG_DIR" "$EIDOS_FIXTURES" "$RUN_DIR/cache"

cleanup() {
  git -C "$ROOT" worktree remove --force "$P2_ROOT" >/dev/null 2>&1 || true
  git -C "$ROOT" worktree remove --force "$EIDOS_ROOT" >/dev/null 2>&1 || true
  git -C "$ROOT" worktree prune >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ -n "$(git -C "$ROOT" status --porcelain)" ]]; then
  echo "warning: detached benchmark sources use committed HEAD $POSEIDON2_COMMIT; the live runner and fixtures remain inputs and are hashed in the result metadata" >&2
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
  if ((${#FILES[@]} > 0)); then
    install_masm_runner "$worktree"
  fi
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
rm -f "$RUN_DIR/fixtures/reversed.masm"

RECURSIVE_FIXTURE_INDEXES=(0)
if [[ "$MODE" == "full" ]]; then
  RECURSIVE_FIXTURE_INDEXES=(0 1)
fi
for index in "${RECURSIVE_FIXTURE_INDEXES[@]}"; do
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
  echo "rayon_thread_plan=$(IFS=,; echo "${THREAD_PLAN[*]}")"
  if [[ "$MODE" != "scaling" ]]; then
    echo "threads=$THREADS"
  fi
  if ((${#CPU_POOL[@]} > 0)); then
    echo "selected_vcpus=$(cpu_list_for_threads 64)"
    echo "vcpu_selection=one-per-guest-core,spread-across-numa-and-llc"
  else
    echo "selected_vcpus=unrestricted"
  fi
  echo "numa_policy=$NUMA_POLICY"
  echo "llc_domains=$LLC_DOMAIN_COUNT"
  echo "cgroup_cpu_limits=$CGROUP_CPU_LIMITS"
  echo "build_jobs=$BUILD_JOBS"
  echo "warmups=$WARMUPS"
  echo "repeats=$REPEATS"
  echo "recursive_auth=$RECURSIVE_AUTH"
  echo "cpu_profile=$CPU_PROFILE"
  echo "cpu_profile_key=$CPU_PROFILE_KEY"
  echo "build_cache_root=$BUILD_CACHE_ROOT"
  echo "rustc=$(rustc --version)"
  echo "cargo=$(cargo --version)"
  echo "uname=$(uname -a)"
  echo "libc=$LIBC_VERSION"
  if [[ -r /sys/devices/virtual/dmi/id/product_name ]]; then
    echo "machine=$(< /sys/devices/virtual/dmi/id/product_name)"
  fi
  echo "started=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "rustflags=${RUSTFLAGS:-}"
  echo "malloc_thp_policy=$HUGETLB_MODE"
  echo "glibc_tunables_requested=${GLIBC_TUNABLES:-unset}"
  if command -v getconf >/dev/null 2>&1; then
    echo "page_size=$(getconf PAGE_SIZE 2>/dev/null || echo unavailable)"
  fi
  if [[ -r /sys/kernel/mm/transparent_hugepage/enabled ]]; then
    echo "transparent_hugepage=$(< /sys/kernel/mm/transparent_hugepage/enabled)"
  fi
  echo "runner_sha256=$(sha256_file "$ROOT/scripts/bench_eidos_vs_poseidon2.sh")"
  echo "fixture_manifest_sha256=$(sha256_file "$FIXTURE_ROOT/SHA256SUMS")"
  if [[ -r /proc/self/status ]]; then
    awk '/^(Cpus_allowed_list|Mems_allowed_list):/ {
      key=$1; sub(/:$/, "", key); print tolower(key) "=" $2
    }' \
      /proc/self/status
  fi
  df -h "$ROOT"
} > "$RUN_DIR/metadata.txt"
printf '%s\n' "$TARGET_CFG" > "$RUN_DIR/rust-target-cfg.txt"
rustc -vV > "$RUN_DIR/rustc-vV.txt"
if [[ "$MODE" == "scaling" ]]; then
  LC_ALL=C lscpu > "$RUN_DIR/lscpu.txt"
  LC_ALL=C lscpu -e=CPU,CORE,SOCKET,NODE,CACHE,ONLINE > "$RUN_DIR/cpu-topology.txt"
  numactl --hardware > "$RUN_DIR/numa-hardware.txt"
  numactl --show > "$RUN_DIR/numa-parent-policy.txt" 2>&1 || true
  if [[ -r /proc/meminfo ]]; then
    grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree|HugePages_|Hugepagesize|Hugetlb):' \
      /proc/meminfo > "$RUN_DIR/memory.txt"
  fi
  if [[ -r "$CGROUP_STAT_DIR/cpu.stat" ]]; then
    cp "$CGROUP_STAT_DIR/cpu.stat" "$RUN_DIR/cgroup-cpu-stat-before.txt"
  fi
fi

run_with_affinity() {
  local cpu_list="$1"
  shift
  if [[ -n "$cpu_list" ]]; then
    if [[ -n "$NUMA_NODES" ]]; then
      numactl --physcpubind="$cpu_list" --interleave="$NUMA_NODES" "$@"
    else
      taskset -c "$cpu_list" "$@"
    fi
  else
    "$@"
  fi
}

run_synthetic() {
  local protocol="$1" worktree="$2" case_name="$3" fixture="$4" threads="$5" cpu_list="$6"
  echo "[synthetic] $case_name / $protocol"
  (
    cd "$worktree"
    run_with_affinity "$cpu_list" env \
      CARGO_TARGET_DIR="$BUILD_CACHE_ROOT/$protocol" \
      RAYON_NUM_THREADS="$threads" \
      CARGO_BUILD_JOBS="$BUILD_JOBS" \
      MASM_PROVE_PATH="$fixture" \
      MASM_PROVE_CASE="$case_name" \
      MASM_PROVE_HASH="$protocol" \
      MASM_PROVE_WARMUPS="$WARMUPS" \
      MASM_PROVE_REPEATS="$REPEATS" \
        cargo bench --locked -p miden-vm-synthetic-bench --bench masm_prove --profile optimized
  ) 2>&1 | tee "$LOG_DIR/synthetic-${case_name}-${protocol}.log"
}

DEFAULT_THREADS="${THREAD_PLAN[0]}"
DEFAULT_CPU_LIST="$(cpu_list_for_threads "$DEFAULT_THREADS")"
for index in "${!FILES[@]}"; do
  run_synthetic poseidon2 "$P2_ROOT" "${LABELS[$index]}" \
    "$FIXTURE_ROOT/${FILES[$index]}" "$DEFAULT_THREADS" "$DEFAULT_CPU_LIST"
  run_synthetic eidos "$EIDOS_ROOT" "${LABELS[$index]}" \
    "$EIDOS_FIXTURES/${FILES[$index]}" "$DEFAULT_THREADS" "$DEFAULT_CPU_LIST"
done

run_recursive() {
  local protocol="$1" worktree="$2" auth="$3" count="$4" fixture="$5"
  local threads="$6" cpu_list="$7" block="$8" kind="${9:-measure}"
  local tx_cache_hits pvm_cache_hits
  local log_name="recursive-${auth}-${count}mvm-1pvm-${protocol}.log"
  local profile_env=(
    RECURSION_PROFILE_PROVE=1
    RECURSION_PROFILE_PROVE_WARMUPS="$WARMUPS"
    RECURSION_PROFILE_PROVE_REPEATS="$REPEATS"
  )
  if [[ "$kind" == "prime" ]]; then
    profile_env=(RECURSION_PROFILE_ONLY=1)
  fi
  if [[ -n "$block" ]]; then
    log_name="recursive-${block}-t${threads}-${auth}-${count}mvm-1pvm-${protocol}.log"
  fi
  echo "[$kind] ${block:+$block / }$auth / $protocol / $count MVM + 1 PVM / $threads Rayon threads${cpu_list:+ / CPUs $cpu_list}"
  (
    cd "$worktree"
    run_with_affinity "$cpu_list" env \
      CARGO_TARGET_DIR="$BUILD_CACHE_ROOT/$protocol" \
      RAYON_NUM_THREADS="$threads" \
      CARGO_BUILD_JOBS="$BUILD_JOBS" \
      RECURSION_BENCH_MASM="$fixture" \
      RECURSION_BENCH_HASH="$protocol" \
      RECURSION_PVM_COMPARISON=1 \
      RECURSION_PROOF_COUNTS="$count" \
      RECURSION_BENCH_TX_PROOF_CACHE_DIR="$RUN_DIR/cache/$protocol/tx" \
      RECURSION_BENCH_PVM_PROOF_CACHE_DIR="$RUN_DIR/cache/$protocol/pvm" \
      "${profile_env[@]}" \
        cargo bench --locked -p miden-vm-synthetic-bench --bench recursive_verify --profile optimized
  ) 2>&1 | tee "$LOG_DIR/$log_name"
  if [[ "$kind" == "measure" ]]; then
    grep -q "^BENCH_RECURSION_PROOF_SUMMARY .* runs=$REPEATS " "$LOG_DIR/$log_name" ||
      die "recursive benchmark did not report $REPEATS measurements for $block"
  fi
  if [[ "$kind" == "measure" ]] && (( REQUIRE_CACHE_HITS == 1 )); then
    grep -q '^   Compiling ' "$LOG_DIR/$log_name" &&
      die "Cargo rebuilt code inside measured block $block"
    grep -q 'Blocking waiting for file lock' "$LOG_DIR/$log_name" &&
      die "Cargo waited for a build lock inside measured block $block"
    if grep -q 'proof_cache=miss' "$LOG_DIR/$log_name"; then
      die "proof cache miss inside measured block $block"
    fi
    tx_cache_hits="$(grep -c '^BENCH_TX_PROOF .*proof_cache=hit' "$LOG_DIR/$log_name" || true)"
    pvm_cache_hits="$(grep -c '^BENCH_PVM_PROOF .*proof_cache=hit' "$LOG_DIR/$log_name" || true)"
    [[ "$tx_cache_hits" == "$count" && "$pvm_cache_hits" == "1" ]] ||
      die "expected $count transaction cache hits and one PVM hit inside measured block $block"
  fi
}

run_headline_arm() {
  local protocol="$1" threads="$2" cpu_list="$3" block="$4" kind="${5:-measure}"
  local fixture="${RECURSIVE_FILES[0]}"
  case "$protocol" in
    poseidon2)
      run_recursive poseidon2 "$P2_ROOT" ecdsa 5 "$FIXTURE_ROOT/$fixture" \
        "$threads" "$cpu_list" "$block" "$kind"
      ;;
    eidos)
      run_recursive eidos "$EIDOS_ROOT" ecdsa 4 "$EIDOS_FIXTURES/$fixture" \
        "$threads" "$cpu_list" "$block" "$kind"
      ;;
    *) die "unknown headline protocol: $protocol" ;;
  esac
}

REQUIRE_CACHE_HITS=0
if [[ "$MODE" == "full" ]]; then
  echo "[full] recursive cases run in separate processes to release each proving setup"
  for index in "${!RECURSIVE_FILES[@]}"; do
    auth="${RECURSIVE_LABELS[$index]}"
    fixture="${RECURSIVE_FILES[$index]}"
    for count in 3 4 5 6 7 8 9; do
      run_recursive poseidon2 "$P2_ROOT" "$auth" "$count" "$FIXTURE_ROOT/$fixture" \
        "$DEFAULT_THREADS" "$DEFAULT_CPU_LIST" ""
    done
    for count in 3 4 5 6 7 8 9; do
      run_recursive eidos "$EIDOS_ROOT" "$auth" "$count" "$EIDOS_FIXTURES/$fixture" \
        "$DEFAULT_THREADS" "$DEFAULT_CPU_LIST" ""
    done
  done
elif [[ "$MODE" == "scaling" ]]; then
  PRIME_THREADS=64
  PRIME_CPU_LIST="$(cpu_list_for_threads "$PRIME_THREADS")"
  run_headline_arm poseidon2 "$PRIME_THREADS" "$PRIME_CPU_LIST" prime prime
  run_headline_arm eidos "$PRIME_THREADS" "$PRIME_CPU_LIST" prime prime
  REQUIRE_CACHE_HITS=1
  for block_index in "${!THREAD_PLAN[@]}"; do
    threads="${THREAD_PLAN[$block_index]}"
    cpu_list="$(cpu_list_for_threads "$threads")"
    printf -v block 'block%02d' "$((block_index + 1))"

    # Alternate the protocol order across scaling blocks to counter host drift.
    if (( block_index % 2 == 0 )); then
      run_headline_arm poseidon2 "$threads" "$cpu_list" "$block"
      run_headline_arm eidos "$threads" "$cpu_list" "$block"
    else
      run_headline_arm eidos "$threads" "$cpu_list" "$block"
      run_headline_arm poseidon2 "$threads" "$cpu_list" "$block"
    fi
  done
else
  run_headline_arm poseidon2 "$THREADS" "" ""
  run_headline_arm eidos "$THREADS" "" ""
fi

extract_row() {
  local field="$1" log="$2"
  grep -Eo "(^|[[:space:]{,])${field}: [0-9]+" "$log" | head -n 1 | sed -E 's/.*: //'
}

if ((${#FILES[@]} > 0)); then
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
    (( delta >= -32 && delta <= 32 )) ||
      die "native-hash rows are not approximately 2x for $label"
    calls="$(logical_hash_calls hperm "$FIXTURE_ROOT/${FILES[$index]}")"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$label" "$calls" "$p2_core" "$eidos_core" "$p2_hash" "$eidos_hash" "$delta" \
      >> "$RUN_DIR/trace-checks.tsv"
  done
fi

: > "$RUN_DIR/summaries.txt"
for log in "$LOG_DIR"/*.log; do
  grep -E '^BENCH_(MASM_SUMMARY|RECURSION_PROOF_SUMMARY) ' "$log" |
    sed "s|^|log=$(basename "$log") |" >> "$RUN_DIR/summaries.txt" || true
done

if [[ "$MODE" == "scaling" ]]; then
  printf 'block\trayon_threads\tposeidon2_5mvm_1pvm_median_ms\teidos_4mvm_1pvm_median_ms\teidos_over_poseidon2\n' \
    > "$RUN_DIR/scaling-blocks.tsv"
  for block_index in "${!THREAD_PLAN[@]}"; do
    printf -v block 'block%02d' "$((block_index + 1))"
    threads="${THREAD_PLAN[$block_index]}"
    p2_log="$LOG_DIR/recursive-${block}-t${threads}-ecdsa-5mvm-1pvm-poseidon2.log"
    eidos_log="$LOG_DIR/recursive-${block}-t${threads}-ecdsa-4mvm-1pvm-eidos.log"
    p2_ms="$(awk '/^BENCH_RECURSION_PROOF_SUMMARY / {
      for (i = 1; i <= NF; i++) if ($i ~ /^median_ms=/) { sub(/^median_ms=/, "", $i); print $i }
    }' "$p2_log")"
    eidos_ms="$(awk '/^BENCH_RECURSION_PROOF_SUMMARY / {
      for (i = 1; i <= NF; i++) if ($i ~ /^median_ms=/) { sub(/^median_ms=/, "", $i); print $i }
    }' "$eidos_log")"
    [[ -n "$p2_ms" && -n "$eidos_ms" ]] || die "could not parse scaling block $block"
    ratio="$(awk -v eidos="$eidos_ms" -v poseidon2="$p2_ms" \
      'BEGIN { printf "%.6f", eidos / poseidon2 }')"
    printf '%s\t%s\t%s\t%s\t%s\n' "$block" "$threads" "$p2_ms" "$eidos_ms" "$ratio" \
      >> "$RUN_DIR/scaling-blocks.tsv"
  done
  awk 'BEGIN {
      print "rayon_threads\tblocks\tposeidon2_mean_of_medians_ms\teidos_mean_of_medians_ms\teidos_over_poseidon2"
      split("8 16 32 64", order)
    }
    NR > 1 { count[$2]++; poseidon2[$2] += $3; eidos[$2] += $4 }
    END {
      for (i = 1; i <= 4; i++) {
        threads = order[i]
        p2 = poseidon2[threads] / count[threads]
        e = eidos[threads] / count[threads]
        printf "%s\t%d\t%.3f\t%.3f\t%.6f\n", threads, count[threads], p2, e, e / p2
      }
    }' "$RUN_DIR/scaling-blocks.tsv" > "$RUN_DIR/scaling-by-threads.tsv"

  if [[ -r "$CGROUP_STAT_DIR/cpu.stat" ]]; then
    cp "$CGROUP_STAT_DIR/cpu.stat" "$RUN_DIR/cgroup-cpu-stat-after.txt"
    before_throttled="$(awk '$1 == "nr_throttled" { print $2 }' \
      "$RUN_DIR/cgroup-cpu-stat-before.txt")"
    after_throttled="$(awk '$1 == "nr_throttled" { print $2 }' \
      "$RUN_DIR/cgroup-cpu-stat-after.txt")"
    if [[ -n "$before_throttled" && -n "$after_throttled" ]]; then
      throttled_delta=$((after_throttled - before_throttled))
      echo "cgroup_nr_throttled_delta=$throttled_delta" >> "$RUN_DIR/metadata.txt"
      (( throttled_delta == 0 )) || die "cgroup CPU throttling occurred during the campaign"
    fi
  fi
fi
echo "finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$RUN_DIR/metadata.txt"

echo
cat "$RUN_DIR/summaries.txt"
echo
echo "results: $RUN_DIR"
if ((${#FILES[@]} > 0)); then
  echo "trace checks: $RUN_DIR/trace-checks.tsv"
fi
if [[ "$MODE" == "scaling" ]]; then
  echo "scaling summary: $RUN_DIR/scaling-by-threads.tsv"
fi
