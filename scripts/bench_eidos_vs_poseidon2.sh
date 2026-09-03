#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
BASE_COMMIT="5e6ea2ef6828c47267df98f6f4bafe016b164fe8"
EIDOS_REV="${EIDOS_REV:-HEAD}"
EIDOS_REV_EXPLICIT=0
AWS_CAMPAIGN_EIDOS_REV="da4e59adae00a6a8af53fb691afdbcdd652e6f51"
FIXTURE_ROOT="$ROOT/bench-baselines/fixtures/bench-tx"
MODE=""
# Keep the historical #3306/#3307 comparison default; override it for the host with --threads.
THREADS="${RAYON_NUM_THREADS:-16}"
THREADS_EXPLICIT=0
MVM_COUNTS_RAW=""
WARMUPS_OVERRIDE=""
REPEATS_OVERRIDE=""
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
PROFILE_ENABLED="${EIDOS_BENCH_PROFILE:-0}"
PROFILE_EVENTS="${EIDOS_BENCH_PERF_EVENTS:-}"

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
  scripts/bench_eidos_vs_poseidon2.sh --aws-campaign [OPTIONS]
  scripts/bench_eidos_vs_poseidon2.sh --aws-profile  [OPTIONS]

--smoke  One measured create-one ECDSA proof in each arm, followed by the
         headline Poseidon2 5 MVM + 1 PVM versus Eidos 4 MVM + 1 PVM case.
--headline
         Run only the recursive headline pair at one selected thread count.
--scaling
         Run the headline pair at 8,16,32,64,64,32,16,8 Rayon threads by
         default. Linux guest topology selects one allowed vCPU per visible
         core, spreads the pool across NUMA/LLC domains, and interleaves memory
         across its nodes.
--full   One warmup and ten measurements for all six Falcon/ECDSA transaction
         fixtures and the ECDSA/Falcon 3..9 MVM + 1 PVM recursive curves.
         High-count Eidos compositions require substantial memory; full mode
         intentionally retains them for larger machines.
--aws-campaign
         Run the complete AWS scaling matrix. Every host runs native code with
         malloc huge pages disabled and enabled. x86_64 hosts additionally run
         x86-64-v3 and x86-64-v4 with huge pages enabled. The mode configures
         kernel THP to madvise when necessary and creates one compact archive
         containing the metadata, summaries, TSV files, and logs from all arms.
--aws-profile
         Profile the native, huge-page-enabled recursive scaling matrix at up
         to 64 physical cores. The script installs Linux perf tooling when
         needed, records prover span timings and hardware/resource counters,
         and emits one compact archive for the host.

--threads N            Rayon/build threads. Default: 16, matching #3306/#3307.
                       With scaling or an AWS campaign, cap the symmetric
                       scaling plan at N physical cores, using one SMT sibling
                       per core. When omitted, use up to 64 detected physical
                       cores.
--mvm-counts LIST      Benchmark both hashes at these MVM counts, e.g. 4,5.
                       Supported by smoke, headline, and full modes.
--warmups N            Override the mode's number of warmup runs.
--repeats N            Override the mode's number of measured runs.
--cpu-profile PROFILE  Rust target CPU: native, x86-64-v3, or x86-64-v4.
                       Default: native.
--dry-run              Validate a scaling host or AWS campaign matrix without
                       creating worktrees or running benchmarks.
--eidos-rev REV        Eidos commit or branch. Default: current HEAD.
                       AWS campaign/profile default: the pinned production candidate.

The script benchmarks detached temporary worktrees at the pinned PR #3467 base
and the selected Eidos revision. It does not modify either production tree.

Scaling campaigns require an explicit malloc huge-page arm on every host:
  GLIBC_TUNABLES=glibc.malloc.hugetlb=0  # requested off
  GLIBC_TUNABLES=glibc.malloc.hugetlb=1  # requested on
Kernel THP must be set to madvise so these two arms remain interpretable.
EOF
}

run_aws_campaign() {
  [[ "$(uname -s)" == "Linux" ]] || die "--aws-campaign requires Linux"
  case "$(uname -m)" in
    aarch64|x86_64) ;;
    *) die "--aws-campaign supports only aarch64 and x86_64 hosts" ;;
  esac
  for command in git lscpu tar tee; do
    command -v "$command" >/dev/null 2>&1 || die "--aws-campaign requires $command"
  done

  local thp_policy="/sys/kernel/mm/transparent_hugepage/enabled"
  [[ -r "$thp_policy" ]] || die "cannot read $thp_policy"
  if ! grep -q '\[madvise\]' "$thp_policy"; then
    command -v sudo >/dev/null 2>&1 ||
      die "transparent huge pages are not in madvise mode and sudo is unavailable"
    echo "[campaign] setting kernel transparent huge pages to madvise"
    sudo sh -c "echo madvise > '$thp_policy'" ||
      die "could not set transparent huge pages to madvise"
  fi

  local campaign_id campaign_dir campaign_archive driver_commit
  campaign_id="$(date -u +%Y%m%d-%H%M%S)-$$"
  campaign_dir="$ROOT/target/eidos-vs-poseidon2/aws-campaign-$campaign_id"
  campaign_archive="$campaign_dir.tar.gz"
  driver_commit="$(git -C "$ROOT" rev-parse HEAD)"
  mkdir -p "$campaign_dir/arms"

  {
    echo "started=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "driver_commit=$driver_commit"
    echo "eidos_revision=$EIDOS_REV"
    echo "architecture=$(uname -m)"
    echo "hostname=$(hostname)"
    echo "thp_policy=$(cat "$thp_policy")"
  } > "$campaign_dir/metadata.txt"
  LC_ALL=C lscpu > "$campaign_dir/lscpu.txt"
  cp /proc/meminfo "$campaign_dir/memory.txt"

  local arms=("hugetlb0-native:0:native" "hugetlb1-native:1:native")
  if [[ "$(uname -m)" == "x86_64" ]]; then
    arms+=("hugetlb1-x86-64-v3:1:x86-64-v3")
    arms+=("hugetlb1-x86-64-v4:1:x86-64-v4")
  fi

  local arm label hugetlb profile arm_log run_dir artifact_dir path
  local child_args=()
  for arm in "${arms[@]}"; do
    IFS=: read -r label hugetlb profile <<< "$arm"
    arm_log="$campaign_dir/$label.log"
    echo "[campaign] starting $label"
    child_args=(--scaling --cpu-profile "$profile" --eidos-rev "$EIDOS_REV")
    (( THREADS_EXPLICIT == 0 )) || child_args+=(--threads "$THREADS")
    [[ -z "$WARMUPS_OVERRIDE" ]] || child_args+=(--warmups "$WARMUPS_OVERRIDE")
    [[ -z "$REPEATS_OVERRIDE" ]] || child_args+=(--repeats "$REPEATS_OVERRIDE")
    (( DRY_RUN == 0 )) || child_args+=(--dry-run)
    GLIBC_TUNABLES="glibc.malloc.hugetlb=$hugetlb" \
      "$ROOT/scripts/bench_eidos_vs_poseidon2.sh" \
        "${child_args[@]}" \
        2>&1 | tee "$arm_log"

    if (( DRY_RUN == 1 )); then
      echo "[campaign] preflight passed for $label"
      continue
    fi
    run_dir="$(sed -n 's/^results: //p' "$arm_log" | tail -n 1)"
    [[ -n "$run_dir" && -d "$run_dir" ]] ||
      die "could not locate the result directory for $label"
    artifact_dir="$campaign_dir/arms/$label"
    mkdir -p "$artifact_dir"
    printf '%s\n' "$run_dir" > "$artifact_dir/source-result-directory.txt"
    for path in \
      metadata.txt rust-target-cfg.txt rustc-vV.txt lscpu.txt cpu-topology.txt \
      numa-hardware.txt numa-parent-policy.txt memory.txt summaries.txt \
      trace-checks.tsv scaling-blocks.tsv scaling-by-threads.tsv logs; do
      [[ ! -e "$run_dir/$path" ]] || cp -R "$run_dir/$path" "$artifact_dir/"
    done
    echo "[campaign] finished $label"
  done

  echo "finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$campaign_dir/metadata.txt"
  tar -czf "$campaign_archive" -C "$(dirname "$campaign_dir")" "$(basename "$campaign_dir")"
  echo "campaign results: $campaign_dir"
  echo "campaign archive: $campaign_archive"
}

PROFILE_PERF_PARANOID_ORIGINAL=""
PROFILE_PERF_PARANOID_CHANGED=0

run_as_root() {
  if (( EUID == 0 )); then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    return 127
  fi
}

restore_profile_sysctl() {
  if (( PROFILE_PERF_PARANOID_CHANGED == 1 )); then
    run_as_root sysctl -q -w \
      "kernel.perf_event_paranoid=$PROFILE_PERF_PARANOID_ORIGINAL" || true
  fi
}

profile_perf_works() {
  command -v perf >/dev/null 2>&1 && perf --version 2>/dev/null | grep -q '^perf version'
}

install_profile_tools() {
  local need_packages=0
  profile_perf_works || need_packages=1
  command -v numactl >/dev/null 2>&1 || need_packages=1
  [[ -x /usr/bin/time ]] || need_packages=1
  (( need_packages == 0 )) && return

  (( EUID == 0 )) || command -v sudo >/dev/null 2>&1 ||
    die "profiling tools are missing and neither root nor sudo access is available"

  if command -v apt-get >/dev/null 2>&1; then
    echo "[profile] installing perf, numactl, and GNU time with apt"
    run_as_root apt-get update
    run_as_root apt-get install -y linux-tools-common numactl time
    if ! profile_perf_works; then
      run_as_root apt-get install -y "linux-tools-$(uname -r)" ||
        run_as_root apt-get install -y linux-tools-aws
    fi
  elif command -v dnf >/dev/null 2>&1; then
    echo "[profile] installing perf, numactl, and GNU time with dnf"
    run_as_root dnf install -y perf numactl time
  elif command -v yum >/dev/null 2>&1; then
    echo "[profile] installing perf, numactl, and GNU time with yum"
    run_as_root yum install -y perf numactl time
  else
    die "profiling needs perf, numactl, and GNU time; unsupported package manager"
  fi

  profile_perf_works || die "perf is unavailable after package installation"
  command -v numactl >/dev/null 2>&1 || die "numactl is unavailable after package installation"
  [[ -x /usr/bin/time ]] || die "GNU time is unavailable after package installation"
}

profile_event_works() {
  local event="$1" output
  output="$(mktemp /tmp/miden-perf-event.XXXXXX)"
  if perf stat -x ';' -e "$event" -o "$output" -- true >/dev/null 2>&1 &&
    ! grep -Eq '<not supported>|<not counted>|No permission|not permitted' "$output"; then
    rm -f "$output"
    return 0
  fi
  rm -f "$output"
  return 1
}

select_profile_events() {
  local event
  local software_events=(task-clock context-switches cpu-migrations page-faults)
  local hardware_events=(
    cycles:u instructions:u branches:u branch-misses:u
    cache-references:u cache-misses:u
    dTLB-loads:u dTLB-load-misses:u
    LLC-loads:u LLC-load-misses:u
    stalled-cycles-frontend:u stalled-cycles-backend:u
  )
  local selected=()

  if ! profile_event_works cycles:u && [[ -r /proc/sys/kernel/perf_event_paranoid ]]; then
    PROFILE_PERF_PARANOID_ORIGINAL="$(< /proc/sys/kernel/perf_event_paranoid)"
    if run_as_root sysctl -q -w kernel.perf_event_paranoid=1; then
      PROFILE_PERF_PARANOID_CHANGED=1
      trap restore_profile_sysctl EXIT
    fi
  fi

  for event in "${software_events[@]}" "${hardware_events[@]}"; do
    if profile_event_works "$event"; then
      selected+=("$event")
    else
      echo "[profile] perf event unavailable: $event" >&2
    fi
  done
  ((${#selected[@]} > 0)) || die "perf exposes none of the requested profiling events"
  PROFILE_EVENTS="$(IFS=,; echo "${selected[*]}")"
}

run_aws_profile() {
  [[ "$(uname -s)" == "Linux" ]] || die "--aws-profile requires Linux"
  case "$(uname -m)" in
    aarch64|x86_64) ;;
    *) die "--aws-profile supports only aarch64 and x86_64 hosts" ;;
  esac
  for command in git lscpu tar tee; do
    command -v "$command" >/dev/null 2>&1 || die "--aws-profile requires $command"
  done
  install_profile_tools
  select_profile_events

  local thp_policy="/sys/kernel/mm/transparent_hugepage/enabled"
  [[ -r "$thp_policy" ]] || die "cannot read $thp_policy"
  if ! grep -q '\[madvise\]' "$thp_policy"; then
    (( EUID == 0 )) || command -v sudo >/dev/null 2>&1 ||
      die "transparent huge pages are not in madvise mode and root access is unavailable"
    echo "[profile] setting kernel transparent huge pages to madvise"
    run_as_root sh -c "echo madvise > '$thp_policy'" ||
      die "could not set transparent huge pages to madvise"
  fi

  local profile_id profile_dir profile_archive profile_log run_dir path driver_commit
  profile_id="$(date -u +%Y%m%d-%H%M%S)-$$"
  profile_dir="$ROOT/target/eidos-vs-poseidon2/aws-profile-$profile_id"
  profile_archive="$profile_dir.tar.gz"
  profile_log="$profile_dir/profile.log"
  driver_commit="$(git -C "$ROOT" rev-parse HEAD)"
  mkdir -p "$profile_dir/results"

  {
    echo "started=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "driver_commit=$driver_commit"
    echo "eidos_revision=$EIDOS_REV"
    echo "architecture=$(uname -m)"
    echo "hostname=$(hostname)"
    echo "thp_policy=$(cat "$thp_policy")"
    echo "perf=$(perf --version)"
    echo "perf_events=$PROFILE_EVENTS"
    echo "perf_event_paranoid_original=${PROFILE_PERF_PARANOID_ORIGINAL:-unchanged}"
    if [[ -r /proc/sys/kernel/perf_event_paranoid ]]; then
      echo "perf_event_paranoid=$(< /proc/sys/kernel/perf_event_paranoid)"
    fi
  } > "$profile_dir/metadata.txt"
  LC_ALL=C lscpu > "$profile_dir/lscpu.txt"
  cp /proc/meminfo "$profile_dir/memory.txt"
  perf list > "$profile_dir/perf-list.txt" 2>&1 || true

  local child_args=(--scaling --cpu-profile native --eidos-rev "$EIDOS_REV")
  (( THREADS_EXPLICIT == 0 )) || child_args+=(--threads "$THREADS")
  child_args+=(--warmups "${WARMUPS_OVERRIDE:-1}")
  child_args+=(--repeats "${REPEATS_OVERRIDE:-3}")
  (( DRY_RUN == 0 )) || child_args+=(--dry-run)

  EIDOS_BENCH_PROFILE=1 \
    EIDOS_BENCH_PERF_EVENTS="$PROFILE_EVENTS" \
    GLIBC_TUNABLES=glibc.malloc.hugetlb=1 \
    "$ROOT/scripts/bench_eidos_vs_poseidon2.sh" "${child_args[@]}" 2>&1 | tee "$profile_log"

  if (( DRY_RUN == 1 )); then
    echo "[profile] preflight passed"
    return
  fi
  run_dir="$(sed -n 's/^results: //p' "$profile_log" | tail -n 1)"
  [[ -n "$run_dir" && -d "$run_dir" ]] ||
    die "could not locate the profiling result directory"
  printf '%s\n' "$run_dir" > "$profile_dir/results/source-result-directory.txt"
  for path in \
    metadata.txt rust-target-cfg.txt rustc-vV.txt lscpu.txt cpu-topology.txt \
    numa-hardware.txt numa-parent-policy.txt memory.txt summaries.txt \
    trace-checks.tsv scaling-blocks.tsv scaling-by-threads.tsv \
    perf resource-usage phase-spans.log logs; do
    [[ ! -e "$run_dir/$path" ]] || cp -R "$run_dir/$path" "$profile_dir/results/"
  done
  echo "finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$profile_dir/metadata.txt"
  tar -czf "$profile_archive" -C "$(dirname "$profile_dir")" "$(basename "$profile_dir")"
  tar -tzf "$profile_archive" >/dev/null
  echo "profile results: $profile_dir"
  echo "profile archive: $profile_archive"
}

while (( $# > 0 )); do
  case "$1" in
    --smoke|--headline|--scaling|--full|--aws-campaign|--aws-profile)
      [[ -z "$MODE" ]] ||
        die "select exactly one benchmark mode"
      MODE="${1#--}"
      shift
      ;;
    --threads)
      (( $# >= 2 )) || die "--threads requires a value"
      THREADS="$2"
      THREADS_EXPLICIT=1
      shift 2
      ;;
    --mvm-counts)
      (( $# >= 2 )) || die "--mvm-counts requires a comma-separated list"
      MVM_COUNTS_RAW="$2"
      shift 2
      ;;
    --warmups)
      (( $# >= 2 )) || die "--warmups requires a value"
      WARMUPS_OVERRIDE="$2"
      shift 2
      ;;
    --repeats)
      (( $# >= 2 )) || die "--repeats requires a value"
      REPEATS_OVERRIDE="$2"
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
      EIDOS_REV_EXPLICIT=1
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
  die "select a benchmark mode"
}
[[ "$THREADS" =~ ^[1-9][0-9]*$ ]] || die "--threads must be a positive integer"
[[ -z "$WARMUPS_OVERRIDE" || "$WARMUPS_OVERRIDE" =~ ^[0-9]+$ ]] ||
  die "--warmups must be a non-negative integer"
[[ -z "$REPEATS_OVERRIDE" || "$REPEATS_OVERRIDE" =~ ^[1-9][0-9]*$ ]] ||
  die "--repeats must be a positive integer"
if [[ "$MODE" == "aws-campaign" ]]; then
  [[ -z "$MVM_COUNTS_RAW" ]] || die "--aws-campaign does not accept --mvm-counts"
  [[ "$CPU_PROFILE" == "native" ]] || die "--aws-campaign selects CPU profiles automatically"
  (( EIDOS_REV_EXPLICIT == 1 )) || EIDOS_REV="$AWS_CAMPAIGN_EIDOS_REV"
  run_aws_campaign
  exit 0
fi
if [[ "$MODE" == "aws-profile" ]]; then
  [[ -z "$MVM_COUNTS_RAW" ]] || die "--aws-profile does not accept --mvm-counts"
  [[ "$CPU_PROFILE" == "native" ]] || die "--aws-profile uses the native CPU profile"
  (( EIDOS_REV_EXPLICIT == 1 )) || EIDOS_REV="$AWS_CAMPAIGN_EIDOS_REV"
  run_aws_profile
  exit 0
fi
[[ "$PROFILE_ENABLED" == "0" || "$PROFILE_ENABLED" == "1" ]] ||
  die "EIDOS_BENCH_PROFILE must be 0 or 1"
if (( PROFILE_ENABLED == 1 )); then
  [[ "$MODE" == "scaling" ]] || die "EIDOS_BENCH_PROFILE requires --scaling"
  [[ -n "$PROFILE_EVENTS" ]] || die "EIDOS_BENCH_PERF_EVENTS is required for profiling"
  command -v perf >/dev/null 2>&1 || die "profiling requires perf"
  [[ -x /usr/bin/time ]] || die "profiling requires GNU time at /usr/bin/time"
fi
MVM_COUNTS=()
if [[ -n "$MVM_COUNTS_RAW" ]]; then
  [[ "$MODE" != "scaling" ]] || die "--mvm-counts cannot be combined with --scaling"
  [[ "$MVM_COUNTS_RAW" =~ ^[1-9][0-9]*(,[1-9][0-9]*)*$ ]] ||
    die "--mvm-counts must be a comma-separated list of positive integers"
  IFS=, read -r -a MVM_COUNTS <<< "$MVM_COUNTS_RAW"
  seen_counts=,
  for count in "${MVM_COUNTS[@]}"; do
    [[ "$seen_counts" != *",$count,"* ]] || die "duplicate MVM count: $count"
    seen_counts+="$count,"
  done
fi
case "$CPU_PROFILE" in
  native|x86-64-v3|x86-64-v4) ;;
  *) die "--cpu-profile must be native, x86-64-v3, or x86-64-v4" ;;
esac
if [[ "$CPU_PROFILE" != "native" && "$(uname -m)" != "x86_64" ]]; then
  die "$CPU_PROFILE requires an x86_64 host"
fi
if [[ "$MODE" != "scaling" ]]; then
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
git -C "$ROOT" cat-file -e "$BASE_COMMIT^{commit}" 2>/dev/null ||
  die "pinned base $BASE_COMMIT is unavailable"
CANDIDATE_COMMIT="$(git -C "$ROOT" rev-parse --verify "$EIDOS_REV^{commit}" 2>/dev/null)" ||
  die "Eidos revision $EIDOS_REV is unavailable"
git -C "$ROOT" merge-base --is-ancestor "$BASE_COMMIT" "$CANDIDATE_COMMIT" ||
  die "pinned base is not an ancestor of Eidos revision $EIDOS_REV"

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
    REPEATS=1
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

[[ -z "$WARMUPS_OVERRIDE" ]] || WARMUPS="$WARMUPS_OVERRIDE"
[[ -z "$REPEATS_OVERRIDE" ]] || REPEATS="$REPEATS_OVERRIDE"

configure_scaling_plan() {
  ASCENDING_THREAD_PLAN=()
  if (( SCALING_MAX_THREADS < 8 )); then
    ASCENDING_THREAD_PLAN=("$SCALING_MAX_THREADS")
  else
    for thread_point in 8 16 32 64; do
      (( thread_point <= SCALING_MAX_THREADS )) || break
      ASCENDING_THREAD_PLAN+=("$thread_point")
    done
    if (( ASCENDING_THREAD_PLAN[${#ASCENDING_THREAD_PLAN[@]} - 1] != SCALING_MAX_THREADS )); then
      ASCENDING_THREAD_PLAN+=("$SCALING_MAX_THREADS")
    fi
  fi
  THREAD_PLAN=("${ASCENDING_THREAD_PLAN[@]}")
  for ((thread_index = ${#ASCENDING_THREAD_PLAN[@]} - 1; thread_index >= 0; thread_index--)); do
    THREAD_PLAN+=("${ASCENDING_THREAD_PLAN[$thread_index]}")
  done
  BUILD_JOBS="$SCALING_MAX_THREADS"
}

if [[ "$MODE" == "scaling" ]]; then
  SCALING_MAX_THREADS=64
  (( THREADS_EXPLICIT == 0 )) || SCALING_MAX_THREADS="$THREADS"
  configure_scaling_plan
else
  SCALING_MAX_THREADS=0
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

  ((${#candidate_cpus[@]} > 0)) || die "--scaling found no allowed guest-visible cores"
  if (( THREADS_EXPLICIT == 0 && ${#candidate_cpus[@]} < SCALING_MAX_THREADS )); then
    SCALING_MAX_THREADS="${#candidate_cpus[@]}"
    configure_scaling_plan
  fi
  ((${#candidate_cpus[@]} >= SCALING_MAX_THREADS)) ||
    die "--scaling needs $SCALING_MAX_THREADS allowed guest-visible cores; found ${#candidate_cpus[@]}"
  ((${#node_order[@]} <= THREAD_PLAN[0])) ||
    die "--scaling cannot spread its ${THREAD_PLAN[0]}-thread point across ${#node_order[@]} NUMA nodes"
  LLC_DOMAIN_COUNT="${#raw_domains[@]}"

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
  while ((${#CPU_POOL[@]} < SCALING_MAX_THREADS)); do
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
      ((${#CPU_POOL[@]} >= SCALING_MAX_THREADS)) && break
    done
    (( added == 1 )) || break
    ordinal=$((ordinal + 1))
  done
  ((${#CPU_POOL[@]} == SCALING_MAX_THREADS)) ||
    die "could not construct a $SCALING_MAX_THREADS-core LLC/NUMA-spread pool"

  NUMA_NODES="$(IFS=,; echo "${node_order[*]}")"

  local pool
  pool="$(cpu_list_for_threads "$SCALING_MAX_THREADS")"
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
BUILD_CACHE_ROOT="$ROOT/target/eidos-vs-poseidon2-build/$CPU_PROFILE_KEY"

export RAYON_NUM_THREADS="${THREAD_PLAN[0]}"
export CARGO_BUILD_JOBS="$BUILD_JOBS"
unset CARGO_ENCODED_RUSTFLAGS
export RUSTFLAGS="-C target-cpu=$CPU_PROFILE"
unset RECURSION_BENCH_STACK RECURSION_MASM_WRITE RECURSION_PROFILE_ONLY
unset RECURSION_PROFILE_PROVE RECURSION_PROOF_COUNTS RECURSION_PVM_COMPARISON
unset RECURSION_PROFILE_TRACING
unset RECURSION_BENCH_HASH RECURSION_BENCH_MASM
unset RECURSION_BENCH_TX_PROOF_CACHE_DIR RECURSION_BENCH_PVM_PROOF_CACHE_DIR
unset SYNTH_BENCH_AXES SYNTH_MASM_WRITE SYNTH_SCENARIO SYNTH_SNAPSHOT

if (( DRY_RUN == 1 )); then
  echo "Poseidon2 commit: $BASE_COMMIT"
  echo "Eidos commit:     $CANDIDATE_COMMIT"
  echo "CPU profile:      $CPU_PROFILE"
  echo "Rayon plan:       $(IFS=,; echo "${THREAD_PLAN[*]}")"
  echo "guest CPU pool:   $(cpu_list_for_threads "$SCALING_MAX_THREADS")"
  echo "physical cores:   ${#CPU_POOL[@]} (one logical CPU selected per core)"
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
mkdir -p "$LOG_DIR" "$EIDOS_FIXTURES" "$RUN_DIR/cache"

cleanup() {
  git -C "$ROOT" worktree remove --force "$P2_ROOT" >/dev/null 2>&1 || true
  git -C "$ROOT" worktree remove --force "$EIDOS_ROOT" >/dev/null 2>&1 || true
  git -C "$ROOT" worktree prune >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ -n "$(git -C "$ROOT" status --porcelain)" ]]; then
  echo "warning: benchmark code uses committed Eidos revision $CANDIDATE_COMMIT; the live runner remains an input and its hash is recorded" >&2
fi
echo "[setup] Poseidon2 $BASE_COMMIT"
echo "[setup] Eidos $CANDIDATE_COMMIT ($EIDOS_REV)"
echo "[setup] results $RUN_DIR"
git -C "$ROOT" worktree add --detach "$P2_ROOT" "$BASE_COMMIT"
git -C "$ROOT" worktree add --detach "$EIDOS_ROOT" "$CANDIDATE_COMMIT"

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
    let has_line = |opcode: &str| source.lines().any(|line| line.trim() == opcode);
    if protocol == "eidos" {
        assert!(has_line("compress"));
        assert!(!has_line("hperm"));
        assert!(!has_line("bcompress"));
    } else {
        assert!(has_line("hperm") || has_line("bcompress"));
        assert!(!has_line("compress"));
    }
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
  local lockfile="$worktree/Cargo.lock"
  local manifest="$worktree/benches/synthetic-bench/Cargo.toml"
  local recursive="$worktree/benches/synthetic-bench/benches/recursive_verify.rs"
  local config="$worktree/benches/synthetic-bench/benches/recursive_verify/config.rs"
  local measurements="$worktree/benches/synthetic-bench/benches/recursive_verify/measurements.rs"

  if (( PROFILE_ENABLED == 1 )); then
    perl -0pi -e '
      s/(miden-verifier\s*= \{ workspace = true, features = \["std"\] \}\n)/$1tracing-subscriber = { workspace = true }\n/
        or die "unexpected recursive benchmark manifest\n";
    ' "$manifest"
    perl -0pi -e '
      s/(\[\[package\]\]\nname = "miden-vm-synthetic-bench"\n.*?\n "thiserror",\n)/$1 "tracing-subscriber",\n/s
        or die "unexpected synthetic benchmark lock entry\n";
    ' "$lockfile"
    perl -0pi -e '
      s/use std::\{fmt::Write as _, path::PathBuf, time::Duration\};/use std::{fmt::Write as _, path::PathBuf, sync::Once, time::Duration};/
        or die "unexpected recursive imports for tracing\n";
      s/(use miden_vm::\{Assembler, Program\};\n)/$1use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan, prelude::*};\n/
        or die "unexpected recursive VM import for tracing\n";
      s/(\#\[derive\(Clone\)\]\nstruct RecursionCase)/static PROFILE_TRACING: Once = Once::new();\n\nfn init_profile_tracing() {\n    if std::env::var_os("RECURSION_PROFILE_TRACING").is_none() {\n        return;\n    }\n    PROFILE_TRACING.call_once(|| {\n        let layer = tracing_subscriber::fmt::layer()\n            .with_level(false)\n            .with_target(false)\n            .with_thread_names(false)\n            .with_span_events(FmtSpan::CLOSE)\n            .with_ansi(false)\n            .compact();\n        let _ = tracing_subscriber::registry()\n            .with(EnvFilter::new("miden_lifted_stark=info,miden_prover=info"))\n            .with(layer)\n            .try_init();\n    });\n}\n\n$1/
        or die "unexpected recursion case for tracing\n";
      s/(fn bench_recursive_verify\(c: &mut Criterion\) \{\n)/$1    init_profile_tracing();\n/
        or die "unexpected recursive benchmark entry for tracing\n";
    ' "$recursive"
  fi

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
  local path="$1"
  perl -ne '
    $repeat = $1 if /^\s*repeat\.(\d+)\s*$/;
    if (/^\s*(hperm|bcompress)\s*$/) {
      die "native-hash opcode is not directly inside repeat.N\n" unless defined $repeat;
      $calls += $repeat;
      undef $repeat;
    }
    END { print(($calls // 0), "\n") }
  ' "$path"
}

write_eidos_fixture() {
  local source_path="$1" eidos_path="$2"
  perl -pe 's/\b(hperm|bcompress)\b/compress/g' "$source_path" > "$eidos_path"
}

assert_only_native_hash_changed() {
  local source_path="$1" eidos_path="$2" label="$3"
  local source_norm="$RUN_DIR/fixtures/source-normalized.masm"
  local eidos_norm="$RUN_DIR/fixtures/eidos-normalized.masm"
  perl -pe 's/\b(hperm|bcompress)\b/__NATIVE_HASH__/g' "$source_path" > "$source_norm"
  perl -pe 's/(?<![A-Za-z0-9_])compress(?![A-Za-z0-9_])/__NATIVE_HASH__/g' \
    "$eidos_path" > "$eidos_norm"
  cmp -s "$source_norm" "$eidos_norm" ||
    die "$label fixture changed beyond native hash opcode normalization"
  rm -f "$source_norm" "$eidos_norm"
}

for index in "${!FILES[@]}"; do
  source_path="$FIXTURE_ROOT/${FILES[$index]}"
  eidos_path="$EIDOS_FIXTURES/${FILES[$index]}"
  write_eidos_fixture "$source_path" "$eidos_path"
  assert_only_native_hash_changed "$source_path" "$eidos_path" "${FILES[$index]}"
done

RECURSIVE_FIXTURE_INDEXES=(0)
if [[ "$MODE" == "full" ]]; then
  RECURSIVE_FIXTURE_INDEXES=(0 1)
fi
for index in "${RECURSIVE_FIXTURE_INDEXES[@]}"; do
  auth="${RECURSIVE_LABELS[$index]}"
  fixture="${RECURSIVE_FILES[$index]}"
  eidos_fixture="$EIDOS_FIXTURES/$fixture"
  if [[ ! -f "$eidos_fixture" ]]; then
    write_eidos_fixture "$FIXTURE_ROOT/$fixture" "$eidos_fixture"
  fi
  assert_only_native_hash_changed "$FIXTURE_ROOT/$fixture" "$eidos_fixture" "recursive $auth"
done

{
  echo "mode=$MODE"
  echo "poseidon2_commit=$BASE_COMMIT"
  echo "eidos_commit=$CANDIDATE_COMMIT"
  echo "eidos_revision=$EIDOS_REV"
  echo "rayon_thread_plan=$(IFS=,; echo "${THREAD_PLAN[*]}")"
  if [[ "$MODE" != "scaling" ]]; then
    echo "threads=$THREADS"
  fi
  if ((${#CPU_POOL[@]} > 0)); then
    echo "selected_vcpus=$(cpu_list_for_threads "$SCALING_MAX_THREADS")"
    echo "selected_physical_cores=${#CPU_POOL[@]}"
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
  echo "mvm_counts=${MVM_COUNTS_RAW:-mode-default}"
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
  echo "profiling_enabled=$PROFILE_ENABLED"
  if (( PROFILE_ENABLED == 1 )); then
    echo "perf_events=$PROFILE_EVENTS"
  fi
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
  local tx_cache_hits pvm_cache_hits profile_stem perf_output resource_output
  local log_name="recursive-${auth}-${count}mvm-1pvm-${protocol}.log"
  local profile_env=(
    RECURSION_PROFILE_PROVE=1
    RECURSION_PROFILE_PROVE_WARMUPS="$WARMUPS"
    RECURSION_PROFILE_PROVE_REPEATS="$REPEATS"
  )
  if [[ "$kind" == "prime" ]]; then
    profile_env=(RECURSION_PROFILE_ONLY=1)
  elif (( PROFILE_ENABLED == 1 )); then
    profile_env+=(RECURSION_PROFILE_TRACING=1)
  fi
  if [[ -n "$block" ]]; then
    log_name="recursive-${block}-t${threads}-${auth}-${count}mvm-1pvm-${protocol}.log"
  fi
  echo "[$kind] ${block:+$block / }$auth / $protocol / $count MVM + 1 PVM / $threads Rayon threads${cpu_list:+ / CPUs $cpu_list}"
  local command_prefix=()
  if (( PROFILE_ENABLED == 1 )) && [[ "$kind" == "measure" ]]; then
    mkdir -p "$RUN_DIR/perf" "$RUN_DIR/resource-usage"
    profile_stem="${log_name%.log}"
    perf_output="$RUN_DIR/perf/$profile_stem.tsv"
    resource_output="$RUN_DIR/resource-usage/$profile_stem.txt"
    command_prefix=(
      /usr/bin/time -v -o "$resource_output"
      perf stat --no-big-num -x ';' -o "$perf_output" -e "$PROFILE_EVENTS" --
    )
  fi
  (
    cd "$worktree"
    run_with_affinity "$cpu_list" "${command_prefix[@]}" env \
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
  if (( PROFILE_ENABLED == 1 )) && [[ "$kind" == "measure" ]]; then
    [[ -s "$perf_output" ]] || die "perf did not produce counters for $block / $protocol"
    [[ -s "$resource_output" ]] ||
      die "GNU time did not produce resource usage for $block / $protocol"
  fi
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
  if ((${#MVM_COUNTS[@]} == 0)); then
    MVM_COUNTS=(3 4 5 6 7 8 9)
  fi
  for index in "${!RECURSIVE_FILES[@]}"; do
    auth="${RECURSIVE_LABELS[$index]}"
    fixture="${RECURSIVE_FILES[$index]}"
    for count in "${MVM_COUNTS[@]}"; do
      run_recursive poseidon2 "$P2_ROOT" "$auth" "$count" "$FIXTURE_ROOT/$fixture" \
        "$DEFAULT_THREADS" "$DEFAULT_CPU_LIST" ""
    done
    for count in "${MVM_COUNTS[@]}"; do
      run_recursive eidos "$EIDOS_ROOT" "$auth" "$count" "$EIDOS_FIXTURES/$fixture" \
        "$DEFAULT_THREADS" "$DEFAULT_CPU_LIST" ""
    done
  done
elif [[ "$MODE" == "scaling" ]]; then
  PRIME_THREADS="$SCALING_MAX_THREADS"
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
elif ((${#MVM_COUNTS[@]} > 0)); then
  fixture="${RECURSIVE_FILES[0]}"
  for count in "${MVM_COUNTS[@]}"; do
    run_recursive poseidon2 "$P2_ROOT" ecdsa "$count" "$FIXTURE_ROOT/$fixture" \
      "$THREADS" "" ""
    run_recursive eidos "$EIDOS_ROOT" ecdsa "$count" "$EIDOS_FIXTURES/$fixture" \
      "$THREADS" "" ""
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
    eidos_hash="$(extract_row eidos_compression_rows "$eidos_log")"
    [[ -n "$p2_core" && -n "$eidos_core" && -n "$p2_hash" && -n "$eidos_hash" ]] ||
      die "could not parse trace shape for $label"
    [[ "$p2_core" == "$eidos_core" ]] || die "core rows differ for $label"
    delta=$(( eidos_hash - (2 * p2_hash) ))
    (( delta >= -32 && delta <= 32 )) ||
      die "native-hash rows are not approximately 2x for $label"
    calls="$(logical_hash_calls "$FIXTURE_ROOT/${FILES[$index]}")"
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
if (( PROFILE_ENABLED == 1 )); then
  : > "$RUN_DIR/phase-spans.log"
  for log in "$LOG_DIR"/*.log; do
    grep ' close time.busy=' "$log" |
      sed "s|^|log=$(basename "$log") |" >> "$RUN_DIR/phase-spans.log" || true
  done
  [[ -s "$RUN_DIR/phase-spans.log" ]] || die "profiling produced no prover phase spans"
fi
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
    }
    NR > 1 {
      if (!seen[$2]++) order[++num_threads] = $2
      count[$2]++
      poseidon2[$2] += $3
      eidos[$2] += $4
    }
    END {
      for (i = 1; i <= num_threads; i++) {
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
