#!/usr/bin/env bash
# Compare service latency with native proving at the same revision.
# The 5% budget is advisory. Use --enforce to reject confirmed regressions.
set -euo pipefail

if (( $# < 1 || $# > 2 )) || [[ ${2-} != '' && ${2-} != --enforce ]]; then
    echo "Usage: $0 RESULTS [--enforce]" >&2
    exit 2
fi
for tool in cargo jq timeout; do
    command -v "$tool" >/dev/null || { echo "Required command not found: $tool" >&2; exit 1; }
done
budget=1.05
enforcement=advisory
if [[ ${2-} == --enforce ]]; then enforcement=enabled; fi
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p -- "$1"
directory="$(mktemp -d "$1/run-XXXXXX")"
directory="$(cd "$directory" && pwd)"
cd "$repo_root"
export RAYON_NUM_THREADS=8
bench_command=(cargo bench --locked --profile optimized -p miden-prover-service --bench proving_service)
# GNU timeout covers Cargo and its compiler and benchmark children as one process group.
timeout --kill-after=10s 1800s "${bench_command[@]}" --no-run

cat > "$directory/summary.md" <<SUMMARY
# Proving service performance

Times are milliseconds with Criterion's 95% marginal intervals. Budget: RPC/native <= $budget.

| Order | Native | RPC | RPC/native | Clear breach |
| --- | --- | --- | --- | --- |
SUMMARY
breaches=()
for order in forward reverse; do
    axes=(native grpc)
    if [[ $order == reverse ]]; then axes=(grpc native); fi
    export CRITERION_HOME="$directory/$order"
    for axis in "${axes[@]}"; do
        timeout --kill-after=10s 600s "${bench_command[@]}" -- "tiny_proof/$axis" --exact --noplot
    done
    comparison="$(jq -ern --argjson budget "$budget" \
        --slurpfile native "$CRITERION_HOME/tiny_proof/native/new/estimates.json" \
        --slurpfile grpc "$CRITERION_HOME/tiny_proof/grpc/new/estimates.json" '
        def estimate($axis; $files):
            if ($files | length) != 1 then error("Expected one \($axis) estimate") else $files[0].mean end
            | .confidence_interval as $interval
            | [.point_estimate, $interval.lower_bound, $interval.upper_bound] as $values
            | if ($values | all(type == "number" and isfinite and (isnan | not)))
                and $values[1] > 0 and $values[1] <= $values[0] and $values[0] <= $values[2]
                and $interval.confidence_level == 0.95
              then $values else error("Invalid \($axis) estimate: \(.)") end;
        def ms: . / 10000 | round / 100;
        def format: "\(.[0] | ms) [\(.[1] | ms), \(.[2] | ms)]";
        estimate("native"; $native) as $n | estimate("grpc"; $grpc) as $g
        | ($g[0] / $n[0]) as $ratio
        | [($ratio * 1000 | round / 1000), ($ratio <= $budget),
           ($g[1] > $budget * $n[2]), ($n | format), ($g | format)] | @tsv
    ')" || exit 1
    IFS=$'\t' read -r ratio within clear native grpc <<< "$comparison"
    breaches+=("$clear")
    printf '| %s | %s | %s | %s | %s |\n' "$order" "$native" "$grpc" "$ratio" "$clear" >> "$directory/summary.md"
    if [[ $order == forward && $within == true ]]; then break; fi
done
status='Point estimate within budget'
if (( ${#breaches[@]} == 2 )); then
    status='Inconclusive breach'
    # Marginal bounds provide a decision margin, not a confidence interval for the ratio.
    if [[ ${breaches[0]} == true && ${breaches[1]} == true ]]; then status='Confirmed regression'; fi
    echo "::warning::$status. Inspect the timing intervals and raw results."
fi
printf '\n%s. Enforcement is %s.\n' "$status" "$enforcement" >> "$directory/summary.md"
cat "$directory/summary.md"
echo "Results: $directory"
if [[ $status == 'Confirmed regression' && $enforcement == enabled ]]; then exit 1; fi
