#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf "$test_root"' EXIT

write_project() {
    local name="$1"
    mkdir -p "$test_root/$name"
    cat > "$test_root/$name/miden-project.toml" <<EOF
[package]
name = "$name"
version = "0.0.0"

[lib]
namespace = "advice_lint_test::$name"
path = "mod.masm"
EOF
}

check_result() {
    local name="$1" expected_status="$2" diagnostic="${3:-}" actual_status verbose_status
    if bash "$repo_root/scripts/check-masm-advice-taint.sh" \
        "${@:4}" "$test_root/$name/miden-project.toml" > "$test_root/$name/output" 2>&1; then
        actual_status=0
    else
        actual_status=$?
    fi
    if [[ "$actual_status" -ne "$expected_status" ]] || \
        { [[ -n "$diagnostic" ]] && ! grep -Fq "$diagnostic" "$test_root/$name/output"; }; then
        cat "$test_root/$name/output" >&2
        echo "$name: expected status $expected_status and diagnostic '$diagnostic', got $actual_status" >&2
        exit 1
    fi
    if bash "$repo_root/scripts/check-masm-advice-taint.sh" \
        --verbose "${@:4}" "$test_root/$name/miden-project.toml" > "$test_root/$name/verbose-output" 2>&1; then
        verbose_status=0
    else
        verbose_status=$?
    fi
    if [[ "$verbose_status" -ne "$actual_status" ]] || \
        { [[ -n "$diagnostic" ]] && ! grep -Fq "$diagnostic" "$test_root/$name/verbose-output"; }; then
        cat "$test_root/$name/verbose-output" >&2
        echo "$name: verbose mode changed the status or lost the diagnostic" >&2
        exit 1
    fi
    grep '^midenc-masm-lint:' "$test_root/$name/output" > "$test_root/$name/counts"
    grep '^midenc-masm-lint:' "$test_root/$name/verbose-output" > "$test_root/$name/verbose-counts"
    if ! cmp -s "$test_root/$name/counts" "$test_root/$name/verbose-counts"; then
        echo "$name: verbosity changed diagnostic or coverage counts" >&2
        exit 1
    fi
    if [[ "$expected_status" -eq 0 ]] && ! grep -Fxq \
        'midenc-masm-lint: 0 finding(s), 0 skipped procedure(s), analysis complete' \
        "$test_root/$name/output"; then
        cat "$test_root/$name/output" >&2
        echo "$name: successful analysis must have zero findings and full coverage" >&2
        exit 1
    fi
    if grep -Fq 'MASM lint skipped procedure' "$test_root/$name/output"; then
        echo "$name: default output includes individual skip diagnostics" >&2
        exit 1
    fi
    echo "$name: passed (default and verbose)"
}

check_error() {
    local name="$1" context="$2" diagnostic="$3" mode actual_status
    shift 3
    for mode in default verbose; do
        if [[ "$mode" == verbose ]]; then
            set -- --verbose "$@"
        fi
        if bash "$repo_root/scripts/check-masm-advice-taint.sh" \
            "$@" > "$test_root/$name-$mode-output" 2>&1; then
            actual_status=0
        else
            actual_status=$?
        fi
        if [[ "$actual_status" -ne 2 ]] || \
            ! grep -Fq "$context" "$test_root/$name-$mode-output" || \
            ! grep -Fq "$diagnostic" "$test_root/$name-$mode-output"; then
            cat "$test_root/$name-$mode-output" >&2
            echo "$name: expected status 2 and diagnostic '$diagnostic', got $actual_status" >&2
            exit 1
        fi
    done
    echo "$name: passed (default and verbose)"
}

check_error invalid_arguments "unexpected argument: --unknown" \
    "usage: midenc-masm-lint" --unknown
check_error missing_target_name "expected a target name after --target" \
    "usage: midenc-masm-lint" --target

for help_flag in --help -h; do
    for mode in --verbose -v; do
        bash "$repo_root/scripts/check-masm-advice-taint.sh" "$mode" "$help_flag" \
            > "$test_root/help-output" 2>&1
        grep -Fq 'usage: midenc-masm-lint' "$test_root/help-output"
        grep -Fq -- '--target <name>' "$test_root/help-output"
        if grep -Fq 'Gate ' "$test_root/help-output"; then
            echo 'Help must exit without analyzing a project' >&2
            exit 1
        fi
    done
done
echo 'help: passed'

check_error missing_project "failed to analyze '$test_root/missing/miden-project.toml'" \
    "No such file or directory (os error 2)" \
    "$test_root/missing/miden-project.toml"

write_project malformed_project
printf 'invalid = [\n' > "$test_root/malformed_project/miden-project.toml"
check_error malformed_project "failed to analyze '$test_root/malformed_project/miden-project.toml'" \
    "unclosed array, expected \`]\`" \
    "$test_root/malformed_project/miden-project.toml"

write_project clean
cat > "$test_root/clean/mod.masm" <<'EOF'
pub proc entry(value: u32) -> u32
    push.1
    u32wrapping_add
end
EOF
check_result clean 0

# Truncation and comparison results are constrained even when their inputs are advice.
write_project u32cast
cat > "$test_root/u32cast/mod.masm" <<'EOF'
pub proc entry() -> u32
    adv_push u32cast push.1 u32wrapping_add
end
EOF
check_result u32cast 0

write_project comparison
cat > "$test_root/comparison/mod.masm" <<'EOF'
pub proc entry() -> u32
    adv_push eq.0 push.1 u32wrapping_add
end
EOF
check_result comparison 0

# Deferred-data registration preserves each stack slot and its original advice source.
write_project event_clean_top
cat > "$test_root/event_clean_top/mod.masm" <<'EOF'
pub proc entry() -> u32
    adv_push push.1.1.1.1.1
    adv.register_deferred_data
    push.1 u32wrapping_add movdn.5 dropw drop
end
EOF
check_result event_clean_top 0

write_project event_tainted_top
cat > "$test_root/event_tainted_top/mod.masm" <<'EOF'
pub proc entry() -> u32
    push.1.1.1.1.1 adv_push
    adv.register_deferred_data
    push.1 u32wrapping_add movdn.5 dropw drop
end
EOF
check_result event_tainted_top 1 "reaches operation requiring"
grep -Fq 'origin mod.masm:2:20]' "$test_root/event_tainted_top/output"

# Memory operations must carry stored advice to the arithmetic sink.
write_project mem_stream
cat > "$test_root/mem_stream/mod.masm" <<'EOF'
pub proc entry() -> u32
    adv_pushw mem_storew_le.0 dropw
    adv_pushw mem_storew_le.4 dropw
    push.0 padw padw padw mem_stream
    push.1 u32wrapping_add
    movdn.12 dropw dropw dropw
end
EOF
check_result mem_stream 1 "reaches operation requiring"

write_project crypto_stream
cat > "$test_root/crypto_stream/mod.masm" <<'EOF'
pub proc entry() -> u32
    adv_push mem_store.0
    push.64 push.0 padw padw padw crypto_stream
    dropw dropw dropw drop drop
    mem_load.64 push.1 u32wrapping_add
end
EOF
check_result crypto_stream 1 "reaches operation requiring"

# The second stream reads the next memory block, which contains the advice.
write_project consecutive_streams
cat > "$test_root/consecutive_streams/mod.masm" <<'EOF'
pub proc entry() -> u32
    adv_push mem_store.8
    push.0 padw padw padw mem_stream mem_stream
    push.1 u32wrapping_add movdn.12 dropw dropw dropw
end
EOF
check_result consecutive_streams 1 "reaches operation requiring"

for operation in horner_eval_base horner_eval_ext; do
    write_project "$operation"
    cat > "$test_root/$operation/mod.masm" <<EOF
pub proc entry() -> u32
    adv_push mem_store.0
    padw padw push.1.1.1.1 push.1.1.1.1 $operation
    dropw dropw dropw drop drop
    push.1 u32wrapping_add swap drop
end
EOF
    check_result "$operation" 1 "reaches operation requiring"
done

# Each tainted example has one arithmetic finding and complete procedure coverage.
for name in event_tainted_top mem_stream crypto_stream consecutive_streams \
    horner_eval_base horner_eval_ext; do
    grep -Fq '[sink arith.add;' "$test_root/$name/output"
    grep -Fxq 'midenc-masm-lint: 1 finding(s), 0 skipped procedure(s), analysis complete' \
        "$test_root/$name/output"
done

# The default library and an explicit executable have different analysis results.
write_project target_selection
cat >> "$test_root/target_selection/miden-project.toml" <<'EOF'

[[bin]]
name = "unsafe"
path = "unsafe.masm"
EOF
cat > "$test_root/target_selection/mod.masm" <<'EOF'
#! Returns a constant without reading advice.
#!
#! Inputs:  []
#! Outputs: [result]
#!
#! Where:
#! - result is one.
#!
#! Invocation: exec
pub proc entry() -> felt
    push.1
end
EOF
cat > "$test_root/target_selection/unsafe.masm" <<'EOF'
begin
    adv_push push.1 u32wrapping_add drop
end
EOF
check_result target_selection 0
grep -Fq "target 'advice_lint_test::target_selection'" "$test_root/target_selection/output"
grep -Fq "target 'advice_lint_test::target_selection'" "$test_root/target_selection/verbose-output"
check_result target_selection 1 'reaches operation requiring' --target unsafe
grep -Fq "target 'unsafe'" "$test_root/target_selection/output"
grep -Fq "target 'unsafe'" "$test_root/target_selection/verbose-output"
check_result target_selection 0 '' --target advice_lint_test::target_selection
check_error unknown_target "failed to analyze '$test_root/target_selection/miden-project.toml'" \
    "project has no target named 'missing'" \
    --target missing "$test_root/target_selection/miden-project.toml"

mkdir -p "$test_root/executable_default"
cat > "$test_root/executable_default/miden-project.toml" <<'EOF'
[package]
name = "executable_default"
version = "0.0.0"

[[bin]]
name = "first"
path = "first.masm"

[[bin]]
name = "unsafe"
path = "unsafe.masm"
EOF
cat > "$test_root/executable_default/first.masm" <<'EOF'
begin
    push.1 drop
end
EOF
cp "$test_root/target_selection/unsafe.masm" "$test_root/executable_default/unsafe.masm"
check_result executable_default 0
grep -Fq "target 'first'" "$test_root/executable_default/output"
check_result executable_default 1 'reaches operation requiring' --target unsafe

# A module-index file can also contain procedures. The gate must analyze them.
write_project unconstrained
cat > "$test_root/unconstrained/mod.masm" <<'EOF'
pub mod helper

pub proc entry() -> u32
    adv_push
    push.1
    u32wrapping_add
end
EOF
cat > "$test_root/unconstrained/helper.masm" <<'EOF'
pub proc clean() -> felt
    push.1
end
EOF
check_result unconstrained 1 "reaches operation requiring"

# Compact output groups a procedure's return advisories without losing findings.
write_project returns
cat > "$test_root/returns/mod.masm" <<'EOF'
pub proc entry() -> word
    adv_pushw
end
EOF
check_result returns 1 "returns unconstrained advice"
grep -Fq '4 finding(s)' "$test_root/returns/output"
grep -Fq 'results [0, 1, 2, 3]' "$test_root/returns/output"
if [[ "$(grep -Fc 'return advisory:' "$test_root/returns/output")" -ne 1 ]]; then
    echo 'The return advisories were not grouped by procedure' >&2
    exit 1
fi

# Exercise advice passed through a declared word signature into a callee's sink.
write_project word_call
cat > "$test_root/word_call/mod.masm" <<'EOF'
proc consume(value: word) -> word
    push.1
    u32wrapping_add
end

pub proc entry() -> word
    adv_pushw
    exec.consume
end
EOF
check_result word_call 1 "reaches operation requiring"
if ! grep -Fq "Coverage full" "$test_root/word_call/output"; then
    cat "$test_root/word_call/output" >&2
    echo 'The word-call taint control unexpectedly skipped a procedure' >&2
    exit 1
fi

# A pointer annotation must not sanitize an advice-derived memory address.
write_project pointer_call
cat > "$test_root/pointer_call/mod.masm" <<'EOF'
proc load(pointer: ptr<felt>) -> felt
    mem_load
end

pub proc entry() -> felt
    adv_push
    exec.load
end
EOF
check_result pointer_call 1 "reaches operation requiring"
if ! grep -Fq "Coverage full" "$test_root/pointer_call/output"; then
    cat "$test_root/pointer_call/output" >&2
    echo 'The pointer-call taint control unexpectedly skipped a procedure' >&2
    exit 1
fi

# Preparation failures must reject the run even when all lifted code is clean.
write_project skipped
cat > "$test_root/skipped/mod.masm" <<'EOF'
pub proc clean() -> felt
    push.1
end

@locals(1)
pub proc bad() -> felt
    push.7 drop
    loc_load.1
end

pub proc caller() -> felt
    exec.bad
end
EOF
check_result skipped 1 "Coverage partial"
grep -Fq "invalid local index 1" "$test_root/skipped/verbose-output"
grep -Fq "depends on skipped procedure" "$test_root/skipped/verbose-output"
grep -Fq "1 root failures, 1 dependent callers" "$test_root/skipped/output"

# A child module with no lifted procedures must fail cleanly instead of panicking.
mkdir -p "$test_root/empty_module"
cp "$repo_root/scripts/fixtures/masm-advice-taint-empty-module/miden-project.toml" \
    "$repo_root/scripts/fixtures/masm-advice-taint-empty-module/mod.masm" \
    "$repo_root/scripts/fixtures/masm-advice-taint-empty-module/broken.masm" \
    "$test_root/empty_module/"
check_result empty_module 1 "Coverage partial"
grep -Fq "MASM lint skipped procedure" "$test_root/empty_module/verbose-output"

# Every procedure is supported and below the per-procedure limits, but together
# they exceed the compiler's fixed dataflow budget. Findings alone cannot decide success.
write_project incomplete
cat > "$test_root/incomplete/mod.masm" <<'EOF'
proc duplicate(value: u32) -> (u32, u32)
    dup
end

EOF
for ((procedure = 0; procedure < 150; procedure++)); do
    printf 'pub proc work_%s(value: u32) -> u32\n' "$procedure"
    for ((operation = 0; operation < 32; operation++)); do
        printf '    exec.duplicate u32wrapping_add\n'
    done
    printf 'end\n\n'
done >> "$test_root/incomplete/mod.masm"
check_result incomplete 1 "MASM advice taint analysis incomplete"
if ! grep -Fq "Coverage full" "$test_root/incomplete/output"; then
    cat "$test_root/incomplete/output" >&2
    echo 'The budget fixture unexpectedly skipped a procedure' >&2
    exit 1
fi

echo 'MASM advice-taint gate tests passed'
