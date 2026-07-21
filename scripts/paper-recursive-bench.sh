#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
k="${1:-${SIG_BATCH_BENCH_MIN_K:-0}}"
runs="${SIG_BATCH_BENCH_RUNS:-1}"
features="${MIDEN_VM_BENCH_FEATURES:-metal}"

export SIG_BATCH_BENCH_MIN_K="$k"
export SIG_BATCH_BENCH_MAX_K="$k"
export SIG_BATCH_BENCH_RUNS="$runs"

sig_repo="${MIDEN_SIGNATURE_REPO:-$(awk -F'"' '/miden-signature = .*path/ { print $2; exit }' "$repo_root/crates/lib/core/Cargo.toml")}"
vm_branch="$(git -C "$repo_root" rev-parse --abbrev-ref HEAD)"

echo "# VM branch: $vm_branch @ $(git -C "$repo_root" rev-parse --short HEAD)"
if [[ -n "$sig_repo" && -d "$sig_repo/.git" ]]; then
  sig_branch="$(git -C "$sig_repo" rev-parse --abbrev-ref HEAD)"
  echo "# signature branch: $sig_branch @ $(git -C "$sig_repo" rev-parse --short HEAD)"

  case "$vm_branch" in
    al/rpo-permutation-air|paper/sig-recursion-rpo-native)
      expected="al/rpo-suite-for-vm-bench paper/signature-rpo-bcs"
      ;;
    al/sig-verifier-next|paper/sig-recursion-poseidon2-native)
      expected="single-tree-iop paper/signature-poseidon2-bcs"
      ;;
    *)
      expected=""
      ;;
  esac

  if [[ -n "$expected" && " $expected " != *" $sig_branch "* && "${ALLOW_SIGNATURE_BRANCH_MISMATCH:-0}" != "1" ]]; then
    echo "wrong miden-signature branch for this VM branch: expected one of [$expected]" >&2
    exit 1
  fi
else
  echo "# signature repo: not found at '${sig_repo}'"
fi
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
