#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT
printf '[tag]\n\tgpgsign = true\n' > "$test_root/global.gitconfig"
export GIT_CONFIG_GLOBAL="$test_root/global.gitconfig"

test_repo="$test_root/repo"
mkdir -p "$test_repo/scripts" "$test_repo/crates/lib/core/asm" "$test_root/bin"
git init -q "$test_repo"
git -C "$test_repo" config user.name "MAST root gate test"
git -C "$test_repo" config user.email "mast-root-gate@example.invalid"
git -C "$test_repo" config commit.gpgsign false
git -C "$test_repo" config tag.gpgsign false

cp "$repo_root/scripts/check-masm-root-stability.sh" "$test_repo/scripts/"
printf '// tag = "v0.35.0"\n' > "$test_repo/scripts/check-masm-export-digests.rs"
printf '[package]\nname = "miden-core"\nversion = "0.35.0"\n' \
    > "$test_repo/crates/lib/core/asm/miden-project.toml"
printf '[workspace.package]\nversion = "0.35.0"\n' > "$test_repo/Cargo.toml"
git -C "$test_repo" add Cargo.toml scripts crates/lib/core/asm/miden-project.toml
git -C "$test_repo" commit -qm 'Create release baseline'
git -C "$test_repo" tag v0.35.0

cat > "$test_root/bin/rustup" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[[ "$#" -eq 7 && "$1" == run && "$2" == nightly && "$3" == cargo && "$4" == -Zscript ]]
[[ -f "$5" && -f "$6" && -f "$7" ]]
printf '%s\n' "$*" > "$ROOT_CHECK_STUB_LOG"
exit "$ROOT_CHECK_STUB_STATUS"
STUB
chmod +x "$test_root/bin/rustup"
export PATH="$test_root/bin:$PATH"
export ROOT_CHECK_STUB_LOG="$test_root/comparator-called"

set_version() {
    printf '[workspace.package]\nversion = "%s"\n' "$1" > "$test_repo/Cargo.toml"
    git -C "$test_repo" add Cargo.toml
    git -C "$test_repo" commit -qm "Set workspace version to $1"
}

check_result() {
    local expected_status="$1"
    local actual_status
    rm -f "$ROOT_CHECK_STUB_LOG"
    if (cd "$test_repo" && ROOT_CHECK_STUB_STATUS="$expected_status" \
        bash scripts/check-masm-root-stability.sh) > "$test_root/output" 2>&1; then
        actual_status=0
    else
        actual_status=$?
    fi
    if [[ "$actual_status" -ne "$expected_status" || ! -f "$ROOT_CHECK_STUB_LOG" ]]; then
        cat "$test_root/output" >&2
        echo "Expected comparator status $expected_status, got $actual_status" >&2
        exit 1
    fi
}

set_version 0.36.0
check_result 7
check_result 0

set_version 0.35.1
check_result 7

set_version 1.0.0
rm -f "$ROOT_CHECK_STUB_LOG"
(cd "$test_repo" && ROOT_CHECK_STUB_STATUS=7 \
    bash scripts/check-masm-root-stability.sh) > "$test_root/output" 2>&1
if [[ -f "$ROOT_CHECK_STUB_LOG" ]]; then
    echo 'The 0.x to 1.0.0 transition unexpectedly ran the comparator' >&2
    exit 1
fi

set_version 1.1.0
check_result 7

echo 'MAST root release gate tests passed'
