#!/usr/bin/env bash

die() {
  echo "error: $*" >&2
  exit 1
}

detect_build_jobs() {
  if command -v getconf >/dev/null 2>&1; then
    getconf _NPROCESSORS_ONLN 2>/dev/null && return
  fi
  if command -v sysctl >/dev/null 2>&1; then
    sysctl -n hw.logicalcpu 2>/dev/null && return
  fi
  echo "${RAYON_NUM_THREADS:-16}"
}

require_uint() {
  local name="$1"
  local value="$2"

  [[ "$value" =~ ^[0-9]+$ ]] || die "$name must be an unsigned integer"
}

require_positive_uint() {
  local name="$1"
  local value="$2"

  require_uint "$name" "$value"
  (( value > 0 )) || die "$name must be positive"
}

abs_dir() {
  mkdir -p "$1"
  (cd "$1" && pwd)
}

split_csv() {
  local csv="$1"
  local _split_csv_items
  local item

  IFS=',' read -r -a _split_csv_items <<< "$csv"
  for item in "${_split_csv_items[@]}"; do
    item="$(printf '%s' "$item" | tr -d '[:space:]')"
    [[ -n "$item" ]] && printf '%s\n' "$item"
  done
}

fixture_meta() {
  local fixture_root="$1"
  local name="$2"

  case "$name" in
    create-single-p2id-note|create-single-p2id|create-single-p2id-note-falcon|create-single-p2id-falcon)
      echo "create-single-p2id-note-falcon|$fixture_root/synthetic_bench_bench-tx__create-single-p2id-note-with-falcon-signing.masm|131072|524288"
      ;;
    create-single-p2id-note-ecdsa|create-single-p2id-ecdsa)
      echo "create-single-p2id-note-ecdsa|$fixture_root/synthetic_bench_bench-tx__create-single-p2id-note-with-ecdsa-signing.masm|32768|524288"
      ;;
    consume-single-p2id-note|consume-single-p2id|consume-single-p2id-note-falcon|consume-single-p2id-falcon)
      echo "consume-single-p2id-note-falcon|$fixture_root/synthetic_bench_bench-tx__consume-single-p2id-note-with-falcon-signing.masm|131072|524288"
      ;;
    consume-single-p2id-note-ecdsa|consume-single-p2id-ecdsa)
      echo "consume-single-p2id-note-ecdsa|$fixture_root/synthetic_bench_bench-tx__consume-single-p2id-note-with-ecdsa-signing.masm|32768|524288"
      ;;
    consume-two-p2id-notes|consume-two-p2id|consume-two-p2id-notes-falcon|consume-two-p2id-falcon)
      echo "consume-two-p2id-notes-falcon|$fixture_root/synthetic_bench_bench-tx__consume-two-p2id-notes-with-falcon-signing.masm|131072|524288"
      ;;
    consume-two-p2id-notes-ecdsa|consume-two-p2id-ecdsa)
      echo "consume-two-p2id-notes-ecdsa|$fixture_root/synthetic_bench_bench-tx__consume-two-p2id-notes-with-ecdsa-signing.masm|32768|524288"
      ;;
    consume-claim-note-l1-to-miden|consume-claim-l1)
      echo "consume-claim-note-l1-to-miden|$fixture_root/synthetic_bench_bench-tx__consume-claim-note-l1-to-miden.masm|65536|524288"
      ;;
    consume-claim-note-l2-to-miden|consume-claim-l2)
      echo "consume-claim-note-l2-to-miden|$fixture_root/synthetic_bench_bench-tx__consume-claim-note-l2-to-miden.masm|65536|524288"
      ;;
    consume-b2agg-note-bridge-out|consume-b2agg|b2agg)
      echo "consume-b2agg-note-bridge-out|$fixture_root/synthetic_bench_bench-tx__consume-b2agg-note-bridge-out.masm|262144|4194304"
      ;;
    *.masm)
      local abs
      abs="$(cd "$(dirname "$name")" && pwd)/$(basename "$name")"
      echo "$(basename "$name" .masm)|$abs||"
      ;;
    *)
      die "unknown fixture alias: $name"
      ;;
  esac
}

write_blakeg_fixture() {
  local fixture="$1"
  local source_path="$2"
  local output_dir="$3"

  mkdir -p "$output_dir"
  local output_path="$output_dir/${fixture}.masm"
  perl -pe 's/\bhperm\b/bcompress/g' "$source_path" > "$output_path"
  echo "$output_path"
}

extract_field() {
  local key="$1"
  local line="$2"

  printf '%s\n' "$line" | tr ' ' '\n' | awk -F= -v k="$key" '$1 == k { print $2; exit }'
}

duration_to_ms() {
  local raw="$1"
  local micro_unit
  micro_unit="$(printf '\302\265s')"

  awk -v raw="$raw" -v micro_unit="$micro_unit" '
    BEGIN {
      gsub(/[[:space:]]/, "", raw);
      if (raw ~ /ms$/) {
        sub(/ms$/, "", raw);
        printf "%.3f", raw + 0;
      } else if (raw ~ micro_unit "$" || raw ~ /us$/) {
        sub(micro_unit "$", "", raw);
        sub(/us$/, "", raw);
        printf "%.3f", (raw + 0) / 1000.0;
      } else if (raw ~ /ns$/) {
        sub(/ns$/, "", raw);
        printf "%.6f", (raw + 0) / 1000000.0;
      } else if (raw ~ /s$/) {
        sub(/s$/, "", raw);
        printf "%.3f", (raw + 0) * 1000.0;
      } else {
        printf "%.3f", raw + 0;
      }
    }
  '
}

git_meta() {
  local root="$1"
  local label="$2"

  {
    echo "[$label]"
    echo "root=$(cd "$root" && pwd)"
    echo "branch=$(git -C "$root" branch --show-current 2>/dev/null || true)"
    echo "commit=$(git -C "$root" rev-parse --short HEAD 2>/dev/null || true)"
    echo "dirty_lines=$(git -C "$root" status --short 2>/dev/null | wc -l | tr -d ' ')"
    git -C "$root" status --short 2>/dev/null | sed 's/^/status=/' || true
    echo
  }
}

tsv_field_values() {
  local file="$1"
  local fixture_col="$2"
  local fixture="$3"
  local proof_col="$4"
  local proof="$5"
  local value_col="$6"

  awk -F '\t' \
    -v fixture_col="$fixture_col" \
    -v fixture="$fixture" \
    -v proof_col="$proof_col" \
    -v proof="$proof" \
    -v value_col="$value_col" \
    'NR > 1 && $fixture_col == fixture && (proof_col == "" || $proof_col == proof) {
      print $value_col;
    }' "$file"
}

median_tsv_field() {
  local file="$1"
  local fixture_col="$2"
  local fixture="$3"
  local proof_col="$4"
  local proof="$5"
  local value_col="$6"
  local values=()
  local value

  while IFS= read -r value; do
    [[ -n "$value" ]] && values+=("$value")
  done < <(tsv_field_values "$file" "$fixture_col" "$fixture" "$proof_col" "$proof" "$value_col" | sort -n)

  local count="${#values[@]}"
  (( count > 0 )) || die "no values for $fixture column $value_col in $file"

  if (( count % 2 == 1 )); then
    echo "${values[$((count / 2))]}"
  else
    awk -v a="${values[$((count / 2 - 1))]}" -v b="${values[$((count / 2))]}" \
      'BEGIN { printf "%.3f", (a + b) / 2 }'
  fi
}

avg_tsv_field() {
  local file="$1"
  local fixture_col="$2"
  local fixture="$3"
  local proof_col="$4"
  local proof="$5"
  local value_col="$6"

  tsv_field_values "$file" "$fixture_col" "$fixture" "$proof_col" "$proof" "$value_col" |
    awk '{ sum += $1; count += 1 } END { if (count == 0) exit 1; printf "%.3f", sum / count }' \
    || die "no values for $fixture column $value_col in $file"
}

minmax_tsv_field() {
  local file="$1"
  local fixture_col="$2"
  local fixture="$3"
  local proof_col="$4"
  local proof="$5"
  local value_col="$6"

  tsv_field_values "$file" "$fixture_col" "$fixture" "$proof_col" "$proof" "$value_col" |
    awk '{
      value = $1 + 0;
      if (count == 0 || value < min) min = value;
      if (count == 0 || value > max) max = value;
      count += 1;
    }
    END {
      if (count == 0) exit 1;
      printf "%.3f-%.3f", min, max;
    }' || die "no values for $fixture column $value_col in $file"
}

first_tsv_field() {
  local file="$1"
  local fixture_col="$2"
  local fixture="$3"
  local proof_col="$4"
  local proof="$5"
  local value_col="$6"

  tsv_field_values "$file" "$fixture_col" "$fixture" "$proof_col" "$proof" "$value_col" | head -n 1
}
