#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH="$ROOT/scripts/bench_eidos_vs_poseidon2.sh"

die() {
  echo "error: $*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  scripts/bench_eidos_scaling_campaign.sh

Runs the canonical scaling campaign for the detected CPU architecture. Every
arm is preflighted before any benchmark starts, then the arms run sequentially.

  aarch64: native/hugetlb=0, native/hugetlb=1
  x86_64:  native/0, native/1, x86-64-v3/1, x86-64-v4/1

Run this script concurrently on separate hosts, never concurrently twice on the
same host. Each benchmark arm writes its own result directory under target/.
EOF
}

if (( $# == 1 )) && [[ "$1" == "-h" || "$1" == "--help" ]]; then
  usage
  exit 0
fi
(( $# == 0 )) || {
  usage >&2
  die "this campaign auto-detects the host and accepts no arguments"
}

for command in git lscpu flock; do
  command -v "$command" >/dev/null 2>&1 || die "missing required command: $command"
done
[[ -x "$BENCH" ]] || die "benchmark runner is not executable: $BENCH"
[[ "$(uname -s)" == "Linux" ]] || die "scaling campaigns require Linux"
[[ -z "${EIDOS_REV+x}" ]] ||
  die "EIDOS_REV must be unset; the campaign uses the checked-out Eidos HEAD"

ACTUAL_ARCH="$(uname -m)"
LSCPU_SUMMARY="$(LC_ALL=C lscpu)"
ACTUAL_VENDOR="$(awk -F: '/^Vendor ID:/ {
  value=$2; gsub(/^[ \t]+|[ \t]+$/, "", value); print value; exit
}' <<< "$LSCPU_SUMMARY")"
ACTUAL_MODEL="$(awk -F: '/^Model name:/ {
  value=$2; gsub(/^[ \t]+|[ \t]+$/, "", value); print value; exit
}' <<< "$LSCPU_SUMMARY")"
THREADS_PER_CORE="$(awk -F: '/^Thread\(s\) per core:/ {
  value=$2; gsub(/^[ \t]+|[ \t]+$/, "", value); print value; exit
}' <<< "$LSCPU_SUMMARY")"
ONLINE_CPUS="$(
  LC_ALL=C lscpu --parse=CPU |
    awk '$1 ~ /^[0-9]+$/ { count++ } END { print count + 0 }'
)"

case "$ACTUAL_ARCH" in
  aarch64)
    HOST_KIND="aarch64"
    ARMS=("0 native" "1 native")
    ;;
  x86_64)
    HOST_KIND="x86_64"
    ARMS=("0 native" "1 native" "1 x86-64-v3" "1 x86-64-v4")
    ;;
  *)
    die "unsupported host: arch=$ACTUAL_ARCH vendor=${ACTUAL_VENDOR:-unknown} model=${ACTUAL_MODEL:-unknown}"
    ;;
esac

[[ "$ONLINE_CPUS" == "64" ]] ||
  die "$HOST_KIND campaign requires exactly 64 online CPUs; found $ONLINE_CPUS"
[[ "$THREADS_PER_CORE" == "1" ]] ||
  die "$HOST_KIND campaign requires one thread per core; found ${THREADS_PER_CORE:-unknown}"

CAMPAIGN_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
ensure_source_unchanged() {
  [[ "$(git -C "$ROOT" rev-parse HEAD)" == "$CAMPAIGN_COMMIT" ]] ||
    die "HEAD changed during the campaign"
  [[ -z "$(git -C "$ROOT" status --porcelain)" ]] ||
    die "campaign requires a clean worktree"
}
ensure_source_unchanged

mkdir -p "$ROOT/target"
exec 9> "$ROOT/target/eidos-scaling-campaign.lock"
flock -n 9 || die "another scaling campaign is already running in this worktree"

CAMPAIGN_ID="$(date -u +%Y%m%d-%H%M%S)-$$-$HOST_KIND"
CAMPAIGN_DIR="$ROOT/target/eidos-scaling-campaign/$CAMPAIGN_ID"
mkdir -p "$CAMPAIGN_DIR"
MANIFEST="$CAMPAIGN_DIR/campaign.tsv"
printf 'order\thost\tcpu_profile\tmalloc_hugetlb\tresult_dir\n' > "$MANIFEST"

AVAILABLE_GIB="$(df -Pk "$ROOT" | awk 'NR == 2 { printf "%d", $4 / 1024 / 1024 }')"
RECOMMENDED_GIB=200
[[ "$HOST_KIND" == "aarch64" ]] && RECOMMENDED_GIB=60
if (( AVAILABLE_GIB < RECOMMENDED_GIB )); then
  echo "warning: ${AVAILABLE_GIB} GiB free; ${RECOMMENDED_GIB} GiB is recommended for $HOST_KIND" >&2
fi

run_arm() {
  local hugetlb="$1" profile="$2"
  shift 2
  echo "[$HOST_KIND] malloc_hugetlb=$hugetlb cpu_profile=$profile${*:+ $*}"
  env GLIBC_TUNABLES="glibc.malloc.hugetlb=$hugetlb" \
    "$BENCH" --scaling --cpu-profile "$profile" "$@"
}

echo "[campaign] host=$HOST_KIND commit=$CAMPAIGN_COMMIT"
echo "[campaign] cpu=$ACTUAL_MODEL online_cpus=$ONLINE_CPUS threads_per_core=$THREADS_PER_CORE"
echo "[campaign] artifacts=$CAMPAIGN_DIR available_disk_gib=$AVAILABLE_GIB"
echo "[campaign] preflighting ${#ARMS[@]} arms before measurement"
for arm_index in "${!ARMS[@]}"; do
  arm="${ARMS[$arm_index]}"
  read -r hugetlb profile <<< "$arm"
  printf -v order '%02d' "$((arm_index + 1))"
  ensure_source_unchanged
  run_arm "$hugetlb" "$profile" --dry-run 2>&1 |
    tee "$CAMPAIGN_DIR/preflight-$order-$profile-hp$hugetlb.log"
done

echo "[campaign] all preflights passed; starting sequential measurements"
for arm_index in "${!ARMS[@]}"; do
  arm="${ARMS[$arm_index]}"
  read -r hugetlb profile <<< "$arm"
  printf -v order '%02d' "$((arm_index + 1))"
  run_log="$CAMPAIGN_DIR/run-$order-$profile-hp$hugetlb.log"
  ensure_source_unchanged
  run_arm "$hugetlb" "$profile" 2>&1 | tee "$run_log"
  result_dir="$(sed -n 's/^results: //p' "$run_log" | tail -n 1)"
  [[ -d "$result_dir" ]] || die "could not locate the result directory for arm $order"
  for artifact in metadata.txt scaling-blocks.tsv scaling-by-threads.tsv; do
    [[ -f "$result_dir/$artifact" ]] ||
      die "arm $order result is missing $artifact: $result_dir"
  done
  grep -qx "cpu_profile=$profile" "$result_dir/metadata.txt" ||
    die "arm $order metadata recorded the wrong CPU profile"
  grep -qx "glibc_tunables_requested=glibc.malloc.hugetlb=$hugetlb" \
    "$result_dir/metadata.txt" ||
    die "arm $order metadata recorded the wrong malloc hugetlb setting"
  grep -qx "eidos_commit=$CAMPAIGN_COMMIT" "$result_dir/metadata.txt" ||
    die "arm $order metadata recorded the wrong Eidos commit"
  printf '%s\t%s\t%s\t%s\t%s\n' \
    "$order" "$HOST_KIND" "$profile" "$hugetlb" "$result_dir" >> "$MANIFEST"
done

echo "[campaign] complete: $HOST_KIND"
echo "[campaign] manifest: $MANIFEST"
