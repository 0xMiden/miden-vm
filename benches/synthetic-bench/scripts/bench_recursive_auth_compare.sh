#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CRATE_DIR="$ROOT_DIR/benches/synthetic-bench"
FIXTURE_DIR="$CRATE_DIR/fixtures/recursive-auth"

PROOF_COUNTS="${PROOF_COUNTS:-2,3,4,5,6,7,8}"
PROVE_REPEATS="${PROVE_REPEATS:-10}"
PROVE_WARMUPS="${PROVE_WARMUPS:-1}"
CARGO_PROFILE="${CARGO_PROFILE:-optimized}"
OUTPUT_DIR="${OUTPUT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/miden-recursive-auth-bench.XXXXXX")}"

mkdir -p "$OUTPUT_DIR"/{cache,logs}

run_case() {
    local auth="$1"
    local fixture="$2"
    local cache_dir="$OUTPUT_DIR/cache/$auth"
    local log_file="$OUTPUT_DIR/logs/$auth.log"

    rm -rf "$cache_dir"
    mkdir -p "$cache_dir"

    echo "==> $auth"
    echo "    fixture: $fixture"
    echo "    log:     $log_file"

    RECURSION_BENCH_MASM="$fixture" \
    RECURSION_PROOF_COUNTS="$PROOF_COUNTS" \
    RECURSION_PROFILE_PROVE=1 \
    RECURSION_PROFILE_PROVE_REPEATS="$PROVE_REPEATS" \
    RECURSION_PROFILE_PROVE_WARMUPS="$PROVE_WARMUPS" \
    RECURSION_BENCH_TX_PROOF_CACHE_DIR="$cache_dir" \
    cargo bench -p miden-vm-synthetic-bench --bench recursive_verify --profile "$CARGO_PROFILE" -- --test \
        2>&1 | tee "$log_file"
}

summarize() {
    local ecdsa_log="$OUTPUT_DIR/logs/ecdsa.log"
    local falcon_log="$OUTPUT_DIR/logs/falcon.log"

    awk -v proof_counts="$PROOF_COUNTS" '
        function value(line, key, pattern) {
            pattern = key "=[^ ]+"
            if (match(line, pattern)) {
                return substr(line, RSTART + length(key) + 1, RLENGTH - length(key) - 1)
            }
            return ""
        }

        FILENAME == ARGV[1] { auth = "ECDSA" }
        FILENAME == ARGV[2] { auth = "Falcon" }

        /BENCH_TX_SHAPE index=0/ {
            tx_core[auth] = value($0, "core_rows")
            tx_chiplets[auth] = value($0, "chiplets_rows")
            tx_p2[auth] = value($0, "poseidon2_permutation_rows")
            tx_padded[auth] = value($0, "max_padded_rows")
        }

        /BENCH_RECURSION_SHAPE/ {
            proofs = value($0, "proofs")
            core[auth, proofs] = value($0, "core_rows")
            chiplets[auth, proofs] = value($0, "chiplets_rows")
            p2[auth, proofs] = value($0, "poseidon2_permutation_rows")
            padded[auth, proofs] = value($0, "max_padded_rows")
        }

        /BENCH_RECURSION_PROOF_SUMMARY/ {
            proofs = value($0, "proofs")
            median[auth, proofs] = value($0, "median_ms")
            min_ms[auth, proofs] = value($0, "min_ms")
            max_ms[auth, proofs] = value($0, "max_ms")
        }

        END {
            print ""
            print "Inner transaction shape"
            print "| auth | core | chiplets | P2 perm | padded |"
            print "|---|---:|---:|---:|---:|"
            printf "| Falcon | %d | %d | %d | %d |\n", tx_core["Falcon"], tx_chiplets["Falcon"], tx_p2["Falcon"], tx_padded["Falcon"]
            printf "| ECDSA | %d | %d | %d | %d |\n", tx_core["ECDSA"], tx_chiplets["ECDSA"], tx_p2["ECDSA"], tx_padded["ECDSA"]

            print ""
            print "Recursive verifier comparison"
            print "| proofs | ECDSA core | Falcon core | ECDSA P2 | Falcon P2 | ECDSA padded | Falcon padded | ECDSA median s | Falcon median s | time delta |"
            print "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"

            num_counts = split(proof_counts, counts, ",")
            for (i = 1; i <= num_counts; i++) {
                proofs = counts[i]
                e_median_s = median["ECDSA", proofs] / 1000.0
                f_median_s = median["Falcon", proofs] / 1000.0
                time_delta = 100.0 * (e_median_s - f_median_s) / f_median_s

                printf "| %d | %d | %d | %d | %d | %d | %d | %.2f | %.2f | %+0.1f%% |\n",
                    proofs,
                    core["ECDSA", proofs],
                    core["Falcon", proofs],
                    p2["ECDSA", proofs],
                    p2["Falcon", proofs],
                    padded["ECDSA", proofs],
                    padded["Falcon", proofs],
                    e_median_s,
                    f_median_s,
                    time_delta
            }
        }
    ' "$ecdsa_log" "$falcon_log"
}

echo "output: $OUTPUT_DIR"
echo "proof counts: $PROOF_COUNTS"
echo "prove repeats: $PROVE_REPEATS"
echo "prove warmups: $PROVE_WARMUPS"
echo

run_case "ecdsa" "$FIXTURE_DIR/consume-single-p2id-note-with-ecdsa-signing.masm"
run_case "falcon" "$FIXTURE_DIR/consume-single-p2id-note-with-falcon-signing.masm"
summarize | tee "$OUTPUT_DIR/summary.md"

echo
echo "summary: $OUTPUT_DIR/summary.md"
