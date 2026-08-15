#!/bin/bash
# Regression tests for version_cmp() in release-plan-common.sh.
#
# There is no shell test framework wired up for scripts/ in this repo yet
# (see scripts/check-changelog.test.sh for the same pattern), so this is a
# small, self-contained script. Run directly:
#   ./scripts/lib/release-plan-common.test.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./release-plan-common.sh
source "${SCRIPT_DIR}/release-plan-common.sh"

failures=0

assert_cmp() {
    local description="$1" left="$2" right="$3" expected="$4" actual
    actual="$(version_cmp "$left" "$right")"
    if [ "${actual}" -eq "${expected}" ]; then
        echo "ok - ${description}"
    else
        echo "FAIL - ${description} (version_cmp \"${left}\" \"${right}\": expected ${expected}, got ${actual})"
        failures=$((failures + 1))
    fi
}

# Plain release versions: unaffected by this fix, kept as a baseline.
assert_cmp "equal versions" "1.2.3" "1.2.3" 0
assert_cmp "higher patch" "1.2.4" "1.2.3" 1
assert_cmp "higher major beats higher minor/patch on the other side" "2.0.0" "1.9.9" 1
assert_cmp "build metadata is ignored" "1.2.3+build.5" "1.2.3" 0

# Regression cases: a version's own prerelease must sort strictly before it, and
# prereleases must be compared by their identifiers, not discarded outright.
assert_cmp "a stable release outranks its own prerelease" "1.5.0" "1.5.0-alpha.3" 1
assert_cmp "a prerelease sits below its own stable release" "1.5.0-alpha.3" "1.5.0" -1
assert_cmp "prerelease numeric identifiers compare numerically" "1.5.0-alpha.1" "1.5.0-alpha.2" -1
assert_cmp "prerelease numeric identifiers: 2 vs 10 (not lexical)" "1.5.0-alpha.2" "1.5.0-alpha.10" -1
assert_cmp "prerelease non-numeric identifiers compare lexically" "1.5.0-alpha" "1.5.0-beta" -1
assert_cmp "fewer prerelease identifiers is lower precedence" "1.5.0-alpha" "1.5.0-alpha.1" -1
assert_cmp "identical prereleases are equal" "1.2.3-alpha.1" "1.2.3-alpha.1" 0

if [ "${failures}" -gt 0 ]; then
    echo "${failures} test(s) failed"
    exit 1
fi
echo "all tests passed"
