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
  scripts/bench_eidos_scaling_campaign.sh --isa-attribution

Runs the canonical scaling campaign for the detected CPU architecture. Every
arm is preflighted before any benchmark starts, then the arms run sequentially.

  aarch64: native/hugetlb=0, native/hugetlb=1
  x86_64:  native/0, native/1, x86-64-v3/1, x86-64-v4/1

--isa-attribution runs an x86-only, drift-balanced profile comparison with
hugetlb=1 throughout: x86-64-v3, x86-64-v4, x86-64-v4, x86-64-v3.

Run this script concurrently on separate hosts, never concurrently twice on the
same host. Each benchmark arm writes its own result directory under target/.
On success, the script prints one complete archive to send back.
EOF
}

if (( $# == 1 )) && [[ "$1" == "-h" || "$1" == "--help" ]]; then
  usage
  exit 0
fi
CAMPAIGN_KIND="cross-architecture"
if (( $# == 1 )) && [[ "$1" == "--isa-attribution" ]]; then
  CAMPAIGN_KIND="isa-attribution"
  shift
fi
(( $# == 0 )) || {
  usage >&2
  die "unexpected campaign argument"
}

for command in git lscpu flock find tar gzip sha256sum mktemp realpath; do
  command -v "$command" >/dev/null 2>&1 || die "missing required command: $command"
done
[[ -x "$BENCH" ]] || die "benchmark runner is not executable: $BENCH"
[[ "$(uname -s)" == "Linux" ]] || die "scaling campaigns require Linux"
[[ -z "${EIDOS_REV+x}" ]] ||
  die "EIDOS_REV must be unset; the campaign uses the revision pinned by the runner"

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
    if [[ "$CAMPAIGN_KIND" == "isa-attribution" ]]; then
      ARMS=("1 x86-64-v3" "1 x86-64-v4" "1 x86-64-v4" "1 x86-64-v3")
    else
      ARMS=("0 native" "1 native" "1 x86-64-v3" "1 x86-64-v4")
    fi
    ;;
  *)
    die "unsupported host: arch=$ACTUAL_ARCH vendor=${ACTUAL_VENDOR:-unknown} model=${ACTUAL_MODEL:-unknown}"
    ;;
esac

[[ "$CAMPAIGN_KIND" != "isa-attribution" || "$HOST_KIND" == "x86_64" ]] ||
  die "--isa-attribution requires an x86_64 host"

[[ "$ONLINE_CPUS" == "64" ]] ||
  die "$HOST_KIND campaign requires exactly 64 online CPUs; found $ONLINE_CPUS"
[[ "$THREADS_PER_CORE" == "1" ]] ||
  die "$HOST_KIND campaign requires one thread per core; found ${THREADS_PER_CORE:-unknown}"

CAMPAIGN_COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
ensure_source_unchanged() {
  [[ "$(git -C "$ROOT" rev-parse HEAD)" == "$CAMPAIGN_COMMIT" ]] ||
    die "HEAD changed during the campaign"
  [[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ]] ||
    die "campaign requires clean tracked and staged files"
}
ensure_source_unchanged

mkdir -p "$ROOT/target"
exec 9> "$ROOT/target/eidos-scaling-campaign.lock"
flock -n 9 || die "another scaling campaign is already running in this worktree"

CAMPAIGN_ID="$(date -u +%Y%m%d-%H%M%S)-$$-$HOST_KIND-$CAMPAIGN_KIND"
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

echo "[campaign] kind=$CAMPAIGN_KIND host=$HOST_KIND commit=$CAMPAIGN_COMMIT"
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
  printf '%s\t%s\t%s\t%s\t%s\n' \
    "$order" "$HOST_KIND" "$profile" "$hugetlb" "$result_dir" >> "$MANIFEST"
done

PACKAGE_STAGING=""
PACKAGE_PARTIAL=""
cleanup_package() {
  if [[ -n "$PACKAGE_PARTIAL" && "$PACKAGE_PARTIAL" == "$CAMPAIGN_DIR"/*.partial ]]; then
    rm -f -- "$PACKAGE_PARTIAL"
  fi
  if [[ -n "$PACKAGE_STAGING" && "$PACKAGE_STAGING" == "$CAMPAIGN_DIR"/.package.* ]]; then
    rm -rf -- "$PACKAGE_STAGING"
  fi
}
trap cleanup_package EXIT

package_campaign() {
  local bundle_name bundle_dir summary result_root
  local header order host profile hugetlb result_dir extra
  local expected_order expected_hugetlb expected_profile canonical_result
  local arm_dir file_list log_list artifact canonical_logs row_count=0

  ensure_source_unchanged
  [[ -d "$ROOT/target/eidos-vs-poseidon2" ]] || die "benchmark result root is missing"
  result_root="$(realpath "$ROOT/target/eidos-vs-poseidon2")"
  PACKAGE_STAGING="$(mktemp -d "$CAMPAIGN_DIR/.package.XXXXXX")"
  bundle_name="eidos-scaling-campaign-$CAMPAIGN_ID"
  bundle_dir="$PACKAGE_STAGING/$bundle_name"
  mkdir -p "$bundle_dir/arms"
  cp -p -- "$MANIFEST" "$bundle_dir/campaign.tsv"
  printf 'campaign_kind=%s\ncampaign_commit=%s\nhost=%s\n' \
    "$CAMPAIGN_KIND" "$CAMPAIGN_COMMIT" "$HOST_KIND" > "$bundle_dir/campaign-metadata.txt"

  summary="$bundle_dir/campaign-by-threads.tsv"
  printf 'order\thost\tcpu_profile\tmalloc_hugetlb\tresult_dir\trayon_threads\tblocks\tposeidon2_mean_of_medians_ms\teidos_mean_of_medians_ms\teidos_over_poseidon2\n' \
    > "$summary"

  {
    IFS= read -r header || die "could not read campaign manifest header"
    [[ "$header" == $'order\thost\tcpu_profile\tmalloc_hugetlb\tresult_dir' ]] ||
      die "unexpected campaign manifest header"

    while IFS=$'\t' read -r order host profile hugetlb result_dir extra; do
      row_count=$((row_count + 1))
      (( row_count <= ${#ARMS[@]} )) ||
        die "campaign manifest contains more than ${#ARMS[@]} arms"
      printf -v expected_order '%02d' "$row_count"
      read -r expected_hugetlb expected_profile <<< "${ARMS[$((row_count - 1))]}"
      [[ "$order" == "$expected_order" && "$host" == "$HOST_KIND" && \
         "$profile" == "$expected_profile" && "$hugetlb" == "$expected_hugetlb" && \
         -n "$result_dir" && -z "$extra" ]] ||
        die "unexpected campaign manifest row $row_count"

      [[ -d "$result_dir" ]] || die "arm $order result directory is missing: $result_dir"
      canonical_result="$(realpath "$result_dir")"
      [[ "$canonical_result" == "$result_root"/* ]] ||
        die "arm $order result is outside the benchmark result root: $canonical_result"
      for artifact in metadata.txt scaling-blocks.tsv scaling-by-threads.tsv; do
        [[ -f "$canonical_result/$artifact" ]] ||
          die "arm $order result is missing $artifact: $canonical_result"
      done
      grep -qx "cpu_profile=$profile" "$canonical_result/metadata.txt" ||
        die "arm $order metadata recorded the wrong CPU profile"
      grep -qx "glibc_tunables_requested=glibc.malloc.hugetlb=$hugetlb" \
        "$canonical_result/metadata.txt" ||
        die "arm $order metadata recorded the wrong malloc hugetlb setting"

      arm_dir="$bundle_dir/arms/$order-$host-$profile-hp$hugetlb"
      mkdir -p "$arm_dir"
      file_list="$PACKAGE_STAGING/top-level-$order.files"
      find "$canonical_result" -maxdepth 1 -type f -print0 > "$file_list" ||
        die "could not enumerate arm $order result artifacts"
      while IFS= read -r -d '' artifact; do
        cp -p -- "$artifact" "$arm_dir/"
      done < "$file_list"

      [[ -d "$canonical_result/logs" ]] || die "arm $order raw log directory is missing"
      canonical_logs="$(realpath "$canonical_result/logs")"
      [[ -d "$canonical_logs" && "$canonical_logs" == "$canonical_result"/* ]] ||
        die "arm $order logs are missing or outside the result directory"
      mkdir -p "$arm_dir/logs"
      log_list="$PACKAGE_STAGING/logs-$order.files"
      find "$canonical_logs" -maxdepth 1 -type f -print0 > "$log_list" ||
        die "could not enumerate arm $order raw logs"
      [[ -s "$log_list" ]] || die "arm $order contains no raw logs"
      while IFS= read -r -d '' artifact; do
        cp -p -- "$artifact" "$arm_dir/logs/"
      done < "$log_list"

      awk -F '\t' -v order="$order" -v host="$host" -v profile="$profile" \
        -v hugetlb="$hugetlb" -v result_dir="$canonical_result" '
          BEGIN { OFS = "\t" }
          NR > 1 { print order, host, profile, hugetlb, result_dir, $1, $2, $3, $4, $5 }
        ' "$canonical_result/scaling-by-threads.tsv" >> "$summary"
    done
  } < "$MANIFEST"

  (( row_count == ${#ARMS[@]} )) ||
    die "campaign manifest contains $row_count arms; expected ${#ARMS[@]}"

  ARCHIVE="$CAMPAIGN_DIR/$CAMPAIGN_ID-complete.tar.gz"
  PACKAGE_PARTIAL="$ARCHIVE.partial"
  [[ ! -e "$ARCHIVE" && ! -e "$PACKAGE_PARTIAL" ]] ||
    die "campaign archive already exists"
  tar -C "$PACKAGE_STAGING" -czf "$PACKAGE_PARTIAL" "$bundle_name"
  tar -tzf "$PACKAGE_PARTIAL" >/dev/null
  mv -- "$PACKAGE_PARTIAL" "$ARCHIVE"
  PACKAGE_PARTIAL=""
  ARCHIVE_SHA256="$(sha256sum "$ARCHIVE" | awk '{ print $1 }')"

  rm -rf -- "$PACKAGE_STAGING"
  PACKAGE_STAGING=""
}

package_campaign
trap - EXIT

echo "[campaign] complete: $HOST_KIND"
echo "[campaign] manifest: $MANIFEST"
echo "[campaign] send this archive: $ARCHIVE"
echo "[campaign] archive sha256: $ARCHIVE_SHA256"
