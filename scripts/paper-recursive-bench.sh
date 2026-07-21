#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
k="${1:-${SIG_BATCH_BENCH_MIN_K:-0}}"
runs="${SIG_BATCH_BENCH_RUNS:-1}"
features="${MIDEN_VM_BENCH_FEATURES:-metal}"

export SIG_BATCH_BENCH_MIN_K="$k"
export SIG_BATCH_BENCH_MAX_K="$k"
export SIG_BATCH_BENCH_RUNS="$runs"

vm_branch="$(git -C "$repo_root" rev-parse --abbrev-ref HEAD)"
sig_dep="$(awk '/miden-signature = / { sub(/^[[:space:]]*/, ""); print; exit }' "$repo_root/crates/lib/core/Cargo.toml")"

echo "# VM branch: $vm_branch @ $(git -C "$repo_root" rev-parse --short HEAD)"
echo "# signature dependency: $sig_dep"
echo "# recursive benchmark: k=$SIG_BATCH_BENCH_MIN_K signatures=$((1 << SIG_BATCH_BENCH_MIN_K))"

cmd=(
  cargo test --release -p miden-core-lib --features "$features"
  prove_verify_sig_batch_shared_message_once -- --ignored --nocapture
)

if [[ "$(uname -s)" == "Darwin" && -x /usr/bin/time ]]; then
  cd "$repo_root"
  /usr/bin/time -l "${cmd[@]}"
elif [[ -x /usr/bin/time ]]; then
  cd "$repo_root"
  /usr/bin/time -v "${cmd[@]}"
else
  cd "$repo_root"
  "${cmd[@]}"
fi
