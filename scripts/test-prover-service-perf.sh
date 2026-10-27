#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT
mkdir "$test_root/bin"
cat > "$test_root/bin/cargo" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[[ $RAYON_NUM_THREADS == 8 ]]
if [[ $* == *--no-run* ]]; then exit "${PROVER_PERF_TEST_STATUS:-0}"; fi
axis=''
for argument in "$@"; do
    case "$argument" in tiny_proof/*) axis=${argument#tiny_proof/} ;; esac
done
[[ -n $axis ]]
printf '%s\n' "$axis" >> "$PROVER_PERF_TEST_CALLS"
values="${PROVER_PERF_TEST_NATIVE:-1e8 9.9e7 1.01e8}"
if [[ $axis == grpc ]]; then
    values=$PROVER_PERF_TEST_FORWARD
    if [[ $CRITERION_HOME == */reverse ]]; then values=$PROVER_PERF_TEST_REVERSE; fi
fi
file="$CRITERION_HOME/tiny_proof/$axis/new/estimates.json"
mkdir -p "$(dirname "$file")"
case ${PROVER_PERF_TEST_BAD-} in
    missing) exit 0 ;;
    malformed) printf '{' > "$file"; exit 0 ;;
esac
read -r point lower upper <<< "$values"
printf '{"mean":{"point_estimate":%s,"confidence_interval":{"lower_bound":%s,"upper_bound":%s,"confidence_level":%s}}}\n' \
    "$point" "$lower" "$upper" "${PROVER_PERF_TEST_LEVEL:-0.95}" > "$file"
if [[ ${PROVER_PERF_TEST_BAD-} == multiple ]]; then printf '{}\n' >> "$file"; fi
STUB
chmod +x "$test_root/bin/cargo"
export PATH="$test_root/bin:$PATH"
export PROVER_PERF_TEST_CALLS="$test_root/calls"
check_case() {
    local expected=$1 forward=$2 reverse=$3 order=$4 classification=$5 actual
    shift 5
    : > "$PROVER_PERF_TEST_CALLS"
    if PROVER_PERF_TEST_FORWARD="$forward" PROVER_PERF_TEST_REVERSE="$reverse" \
        bash "$repo_root/scripts/prover-service-perf.sh" "$test_root/results space" "$@" > "$test_root/output" 2>&1; then
        actual=0
    else
        actual=$?
    fi
    if [[ $actual != "$expected" || $(cat "$PROVER_PERF_TEST_CALLS") != "$order" ]]; then
        cat "$test_root/output" >&2
        echo "Expected status $expected and order [$order], got $actual and [$(cat "$PROVER_PERF_TEST_CALLS")]" >&2
        exit 1
    fi
    if [[ -n $classification ]]; then
        local enforcement=advisory warning='' summary
        if [[ ${1-} == --enforce ]]; then enforcement=enabled; fi
        if [[ $classification != 'Point estimate within budget' ]]; then
            warning="::warning::$classification. Inspect the timing intervals and raw results."
        fi
        summary="$(sed -n 's/^Results: //p' "$test_root/output")/summary.md"
        if ! grep -Fxq "$classification. Enforcement is $enforcement." "$summary" \
            || [[ $(sed -n '/^::warning::/p' "$test_root/output") != "$warning" ]]; then
            cat "$test_root/output" >&2
            echo "Expected $classification with enforcement $enforcement and warning [$warning]" >&2
            exit 1
        fi
    fi
}
forward=$'native\ngrpc'
reverse=$'native\ngrpc\ngrpc\nnative'
within='Point estimate within budget'
confirmed='Confirmed regression'
inconclusive='Inconclusive breach'
check_case 0 '1.02e8 1.01e8 1.03e8' '1.02e8 1.01e8 1.03e8' "$forward" "$within" --enforce
grep -Fxq '| forward | 100 [99, 101] | 102 [101, 103] | 1.02 | false |' "$test_root/output"
check_case 0 '1.05e8 1.04e8 1.06e8' '1.05e8 1.04e8 1.06e8' "$forward" "$within" --enforce
check_case 1 '1.2e8 1.19e8 1.21e8' '1.2e8 1.19e8 1.21e8' "$reverse" "$confirmed" --enforce
grep -Fxq '| reverse | 100 [99, 101] | 120 [119, 121] | 1.2 | true |' "$test_root/output"
check_case 0 '1.2e8 1.19e8 1.21e8' '1.2e8 1.19e8 1.21e8' "$reverse" "$confirmed"
check_case 0 '1.08e8 9.9e7 1.15e8' '1.08e8 9.9e7 1.15e8' "$reverse" "$inconclusive" --enforce
check_case 0 '1.2e8 1.19e8 1.21e8' '1.02e8 1.01e8 1.03e8' "$reverse" "$inconclusive" --enforce
check_case 0 '1.07e8 1.0605e8 1.08e8' '1.07e8 1.0605e8 1.08e8' "$reverse" "$inconclusive" --enforce
for values in '0 0 0' 'true 1 2' 'NaN 1 2' 'Infinity 1 2' '1e999 1 2' '1 2 3' '1 0.5 1e999'; do
    PROVER_PERF_TEST_NATIVE="$values" check_case 1 '1.02e8 1.01e8 1.03e8' '1.02e8 1.01e8 1.03e8' "$forward" ''
done
PROVER_PERF_TEST_LEVEL=0.5 check_case 1 '1.02e8 1.01e8 1.03e8' '1.02e8 1.01e8 1.03e8' "$forward" ''
for mode in missing malformed multiple; do
    PROVER_PERF_TEST_BAD=$mode check_case 1 '1.02e8 1.01e8 1.03e8' '1.02e8 1.01e8 1.03e8' "$forward" ''
done
PROVER_PERF_TEST_STATUS=42 check_case 42 '1.02e8 1.01e8 1.03e8' '1.02e8 1.01e8 1.03e8' '' ''
echo 'Prover service performance comparison tests passed'
