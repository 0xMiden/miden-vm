#!/bin/bash
# Regression tests for check-changelog.sh.
#
# There is no shell test framework wired up for scripts/ in this repo yet,
# so this is a small, self-contained script: each case runs
# check-changelog.sh in a throwaway git repo and checks its exit code and
# output. Run directly: ./scripts/check-changelog.test.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK_SCRIPT="${SCRIPT_DIR}/check-changelog.sh"
failures=0

# Sets up a throwaway repo with a base branch and a "PR" branch checked out,
# so `origin/base` resolves the same way it would in CI.
setup_repo() {
    local dir
    dir="$(mktemp -d)"
    (
        cd "${dir}" || exit 1
        git init -q
        git config user.email test@example.com
        git config user.name test
        git remote add origin .
        echo "existing changelog" > CHANGELOG.md
        git add . && git commit -qm init
        git branch base
        git branch pr
        git checkout -q pr
        git update-ref refs/remotes/origin/base refs/heads/base
    )
    echo "${dir}"
}

assert_exit_code() {
    local description="$1" expected="$2" actual="$3"
    if [ "${actual}" -eq "${expected}" ]; then
        echo "ok - ${description}"
    else
        echo "FAIL - ${description} (expected exit ${expected}, got ${actual})"
        failures=$((failures + 1))
    fi
}

# Case 1: changelog untouched on a real BASE_REF -> should fail (exit 1),
# same as before this fix.
repo="$(setup_repo)"
(cd "${repo}" && BASE_REF=base "${CHECK_SCRIPT}" > /tmp/out.$$ 2>&1)
status=$?
assert_exit_code "unchanged changelog is rejected" 1 "${status}"
rm -rf "${repo}" /tmp/out.$$

# Case 2: changelog updated on a real BASE_REF -> should pass (exit 0),
# same as before this fix.
repo="$(setup_repo)"
(cd "${repo}" && echo "new entry" >> CHANGELOG.md && git add . && git commit -qm "update changelog" \
    && BASE_REF=base "${CHECK_SCRIPT}" > /tmp/out.$$ 2>&1)
status=$?
assert_exit_code "updated changelog is accepted" 0 "${status}"
rm -rf "${repo}" /tmp/out.$$

# Case 3 (regression): BASE_REF that doesn't exist on origin -> `git diff`
# itself fails (exit 128), which must now be a hard failure instead of a
# silent pass.
repo="$(setup_repo)"
(cd "${repo}" && BASE_REF=does-not-exist "${CHECK_SCRIPT}" > /tmp/out.$$ 2>&1)
status=$?
assert_exit_code "a bad BASE_REF fails loudly instead of passing silently" 1 "${status}"
if grep -q "Failed to diff" /tmp/out.$$; then
    echo "ok - failure message explains the git error"
else
    echo "FAIL - expected output to explain the git error, got:"
    cat /tmp/out.$$
    failures=$((failures + 1))
fi
rm -rf "${repo}" /tmp/out.$$

if [ "${failures}" -gt 0 ]; then
    echo "${failures} test(s) failed"
    exit 1
fi
echo "all tests passed"
