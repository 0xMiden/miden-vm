use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

fn temp_dir(name: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("masm-lint-{name}-{}-{suffix}", std::process::id()));
    fs::create_dir_all(&path).expect("failed to create temporary test directory");
    path
}

fn run_masm_lint(cwd: &Path, input: &Path) -> Output {
    run_masm_lint_with_args(cwd, &[], input)
}

fn run_masm_lint_with_args(cwd: &Path, args: &[&str], input: &Path) -> Output {
    run_masm_lint_with_inputs(cwd, args, &[input])
}

fn run_masm_lint_with_inputs(cwd: &Path, args: &[&str], inputs: &[&Path]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_masm-lint"))
        .arg("--no-color")
        .args(args)
        .args(inputs)
        .current_dir(cwd)
        .output()
        .expect("failed to run masm-lint")
}

#[test]
fn broken_input_file_returns_non_zero() {
    let dir = temp_dir("broken-input");
    let file = dir.join("broken.masm");
    fs::write(&file, "begin\n    invalid.op\nend\n").expect("failed to write MASM fixture");

    let output = run_masm_lint(&dir, &file);

    assert!(!output.status.success(), "broken MASM input unexpectedly passed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to load"),
        "stderr did not report load failure: {stderr}"
    );
}

#[test]
fn grouped_advice_output_reports_root_cause_fanout() {
    let dir = temp_dir("grouped-advice");
    let file = dir.join("grouped_advice.masm");
    fs::write(
        &file,
        "\
pub proc test(seed: felt) -> felt
    adv_pushw
    u32wrapping_add
    drop drop drop
end
",
    )
    .expect("failed to write MASM fixture");

    let output = run_masm_lint_with_args(&dir, &["--group-by-origin"], &file);

    assert!(
        !output.status.success(),
        "grouped advice source unexpectedly passed: {output:?}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let output_text = format!("{stdout}\n{stderr}");
    assert!(
        output_text.contains("unconstrained advice introduced here reaches")
            && output_text.contains("downstream sink(s)"),
        "grouped advice output did not report root-cause fanout: {output_text}"
    );
}

#[test]
fn advice_used_as_memory_address_is_reported() {
    let dir = temp_dir("advice-address");
    let file = dir.join("advice_address.masm");
    fs::write(
        &file,
        "\
pub proc test(seed: felt) -> felt
    adv_push
    mem_load
    drop
end
",
    )
    .expect("failed to write MASM fixture");

    let output = run_masm_lint(&dir, &file);

    assert!(
        !output.status.success(),
        "advice memory address unexpectedly passed: {output:?}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let output_text = format!("{stdout}\n{stderr}");
    assert!(
        output_text.contains("unconstrained advice used as memory address"),
        "advice memory address did not emit a warning: {output_text}"
    );
}

#[test]
fn u32asserted_advice_memory_address_is_reported() {
    let dir = temp_dir("u32asserted-advice-address");
    let file = dir.join("u32asserted_advice_address.masm");
    fs::write(
        &file,
        "\
pub proc test(seed: felt) -> felt
    adv_push
    u32assert
    mem_load
    drop
end
",
    )
    .expect("failed to write MASM fixture");

    let output = run_masm_lint(&dir, &file);

    assert!(
        !output.status.success(),
        "u32asserted advice memory address unexpectedly passed: {output:?}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let output_text = format!("{stdout}\n{stderr}");
    assert!(
        output_text.contains("unconstrained advice used as memory address"),
        "u32asserted advice memory address did not emit a warning: {output_text}"
    );
}

#[test]
fn u32testw_is_lifted_as_supported_instruction() {
    let dir = temp_dir("u32testw");
    let file = dir.join("u32testw.masm");
    fs::write(
        &file,
        "\
pub proc test(a: felt, b: felt, c: felt, d: felt) -> felt
    u32testw
    movdn.4
    dropw
end
",
    )
    .expect("failed to write MASM fixture");

    let output = run_masm_lint(&dir, &file);

    assert!(output.status.success(), "u32testw MASM input failed: {output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("warning"),
        "u32testw with felt inputs emitted a warning: {stderr}"
    );
    assert!(
        !stderr.contains("unsupported instruction"),
        "u32testw was still reported unsupported: {stderr}"
    );
}

#[test]
fn core_u32_ops_are_lifted_as_supported_instructions() {
    let dir = temp_dir("core-u32-ops");
    let file = dir.join("core_u32_ops.masm");
    fs::write(
        &file,
        "\
pub proc test(seed: felt) -> felt
    u32assert
    push.16
    u32max
    u32popcnt
    u32div.4
    u32rotl.1
end
",
    )
    .expect("failed to write MASM fixture");

    let output = run_masm_lint(&dir, &file);

    assert!(output.status.success(), "core U32 op MASM input failed: {output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("unsupported instruction"),
        "core U32 op was reported unsupported: {stderr}"
    );
}

#[test]
fn absolute_inputs_outside_cwd_do_not_share_fallback_module_path() {
    let cwd = temp_dir("fallback-cwd");
    let inputs_dir = temp_dir("fallback-inputs");
    let clean = inputs_dir.join("clean.masm");
    fs::write(
        &clean,
        "\
pub proc clean(seed: felt) -> felt
    push.1
    add
end
",
    )
    .expect("failed to write clean MASM fixture");

    let warning = inputs_dir.join("warning.masm");
    fs::write(
        &warning,
        "\
pub proc warning(seed: felt) -> felt
    adv_push
    u32wrapping_add
end
",
    )
    .expect("failed to write warning MASM fixture");

    let output = run_masm_lint_with_inputs(&cwd, &[], &[&clean, &warning]);

    assert!(!output.status.success(), "second standalone MASM input was skipped: {output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let output_text = format!("{stdout}\n{stderr}");
    assert!(
        output_text.contains("unconstrained advice reaches a u32 operation"),
        "second standalone MASM input did not emit its warning: {output_text}"
    );
}

#[test]
fn core_intrinsics_are_lifted_as_supported_instructions() {
    let dir = temp_dir("core-intrinsics");
    let eval_file = dir.join("eval_circuit.masm");
    fs::write(
        &eval_file,
        "\
pub proc eval(a: felt, b: felt, c: felt) -> (felt, felt, felt)
    eval_circuit
end
",
    )
    .expect("failed to write eval_circuit fixture");

    let log_file = dir.join("log_precompile.masm");
    fs::write(
        &log_file,
        "\
pub proc log(
    a: felt, b: felt, c: felt, d: felt,
    e: felt, f: felt, g: felt, h: felt,
    i: felt, j: felt, k: felt, l: felt
) -> (
    felt, felt, felt, felt,
    felt, felt, felt, felt,
    felt, felt, felt, felt
)
    log_precompile
end
",
    )
    .expect("failed to write log_precompile fixture");

    for file in [&eval_file, &log_file] {
        let output = run_masm_lint(&dir, file);

        assert!(output.status.success(), "core intrinsic MASM input failed: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("unsupported instruction"),
            "core intrinsic was reported unsupported: {stderr}"
        );
    }
}

#[test]
fn adv_pushw_outputs_are_reported_as_unconstrained_advice() {
    let dir = temp_dir("adv-pushw");
    let file = dir.join("adv_pushw.masm");
    fs::write(
        &file,
        "\
pub proc test(seed: felt) -> felt
    adv_pushw
    u32wrapping_add
    drop drop drop
end
",
    )
    .expect("failed to write MASM fixture");

    let output = run_masm_lint(&dir, &file);

    assert!(
        !output.status.success(),
        "adv_pushw advice source unexpectedly passed: {output:?}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let output_text = format!("{stdout}\n{stderr}");
    assert!(
        output_text.contains("unconstrained advice reaches a u32 operation")
            || output_text.contains("unconstrained advice reaches a u32 intrinsic"),
        "adv_pushw advice source did not emit a u32 warning: {output_text}"
    );
}

#[test]
fn mem_stream_preserves_advice_provenance_in_sponge_capacity() {
    let dir = temp_dir("mem-stream-preserves-capacity");
    let file = dir.join("mem_stream_preserves_capacity.masm");
    fs::write(
        &file,
        "\
pub proc test() -> felt
    push.0
    adv_pushw
    push.0 push.0 push.0 push.0
    push.0 push.0 push.0 push.0
    mem_stream
    dropw
    dropw
    u32wrapping_add
    drop drop drop
end
",
    )
    .expect("failed to write MASM fixture");

    let output = run_masm_lint(&dir, &file);

    assert!(
        !output.status.success(),
        "mem_stream preserved advice source unexpectedly passed: {output:?}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let output_text = format!("{stdout}\n{stderr}");
    assert!(
        output_text.contains("unconstrained advice reaches a u32 operation"),
        "mem_stream preserved capacity did not emit a u32 warning: {output_text}"
    );
}

#[test]
fn u32assert_preserves_advice_provenance_for_nonzero_sinks() {
    let dir = temp_dir("u32assert-advice-nonzero");
    let file = dir.join("u32assert_advice_nonzero.masm");
    fs::write(
        &file,
        "\
pub proc test() -> felt
    adv_push
    u32assert
    inv
end
",
    )
    .expect("failed to write MASM fixture");

    let output = run_masm_lint(&dir, &file);

    assert!(
        !output.status.success(),
        "u32assert advice nonzero sink unexpectedly passed: {output:?}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let output_text = format!("{stdout}\n{stderr}");
    assert!(
        output_text.contains("unconstrained advice reaches a divisor or `inv` input"),
        "u32assert advice nonzero sink did not emit a warning: {output_text}"
    );
}

#[test]
fn branch_merged_u32asserted_advice_is_not_reported_as_u32_sink() {
    let dir = temp_dir("branch-merged-u32assert-advice");
    let file = dir.join("branch_merged_u32assert_advice.masm");
    fs::write(
        &file,
        "\
pub proc test(flag: felt) -> felt
    if.true
        adv_push
        u32assert
    else
        adv_push
        u32assert
    end
    push.1
    u32wrapping_add
end
",
    )
    .expect("failed to write MASM fixture");

    let output = run_masm_lint(&dir, &file);

    assert!(output.status.success(), "branch-merged u32asserted advice failed: {output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("unconstrained advice reaches a u32 operation"),
        "branch-merged u32asserted advice emitted a u32 warning: {stderr}"
    );
}

#[test]
fn u32div_checks_advice_divisor_after_u32assert() {
    let dir = temp_dir("u32div-advice-divisor");
    let file = dir.join("u32div_advice_divisor.masm");
    fs::write(
        &file,
        "\
pub proc test() -> felt
    push.10
    adv_push
    u32assert
    u32div
end
",
    )
    .expect("failed to write MASM fixture");

    let output = run_masm_lint(&dir, &file);

    assert!(
        !output.status.success(),
        "u32div advice divisor unexpectedly passed: {output:?}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let output_text = format!("{stdout}\n{stderr}");
    assert!(
        output_text.contains("unconstrained advice reaches a divisor or `inv` input"),
        "u32div advice divisor did not emit a warning: {output_text}"
    );
}

#[test]
fn u32div_immediate_does_not_treat_advice_dividend_as_divisor() {
    let dir = temp_dir("u32div-imm-advice-dividend");
    let file = dir.join("u32div_imm_advice_dividend.masm");
    fs::write(
        &file,
        "\
pub proc test() -> felt
    adv_push
    u32assert
    u32div.4
end
",
    )
    .expect("failed to write MASM fixture");

    let output = run_masm_lint(&dir, &file);

    assert!(
        output.status.success(),
        "u32div immediate advice dividend unexpectedly failed: {output:?}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let output_text = format!("{stdout}\n{stderr}");
    assert!(
        !output_text.contains("unconstrained advice reaches a divisor or `inv` input"),
        "u32div immediate advice dividend emitted a non-zero warning: {output_text}"
    );
}

#[test]
fn advice_used_as_merkle_root_is_reported() {
    let dir = temp_dir("advice-merkle-root");
    let file = dir.join("advice_merkle_root.masm");
    fs::write(
        &file,
        "\
pub proc test() -> (felt, felt, felt, felt)
    adv_pushw
    push.0
    push.1
    mtree_get
end
",
    )
    .expect("failed to write MASM fixture");

    let output = run_masm_lint(&dir, &file);

    assert!(!output.status.success(), "advice Merkle root unexpectedly passed: {output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let output_text = format!("{stdout}\n{stderr}");
    assert!(
        output_text.contains("unconstrained advice used as Merkle tree root"),
        "advice Merkle root did not emit a warning: {output_text}"
    );
}

#[test]
fn advice_used_as_merkle_depth_is_reported_as_u32_sink() {
    let dir = temp_dir("advice-merkle-depth");
    let file = dir.join("advice_merkle_depth.masm");
    fs::write(
        &file,
        "\
pub proc test() -> (felt, felt, felt, felt)
    push.0 push.0 push.0 push.0
    push.0
    adv_push
    mtree_get
end
",
    )
    .expect("failed to write MASM fixture");

    let output = run_masm_lint(&dir, &file);

    assert!(!output.status.success(), "advice Merkle depth unexpectedly passed: {output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let output_text = format!("{stdout}\n{stderr}");
    assert!(
        output_text.contains("unconstrained advice reaches a u32 intrinsic"),
        "advice Merkle depth did not emit a u32 warning: {output_text}"
    );
}

#[test]
fn advice_provenance_flows_across_exec_calls() {
    let dir = temp_dir("interprocedural-advice");
    let file = dir.join("interprocedural_advice.masm");
    fs::write(
        &file,
        "\
proc source() -> felt
    adv_push
end

pub proc test(seed: felt) -> felt
    exec.source
    u32wrapping_add
end
",
    )
    .expect("failed to write MASM fixture");

    let output = run_masm_lint(&dir, &file);

    assert!(
        !output.status.success(),
        "interprocedural advice source unexpectedly passed: {output:?}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let output_text = format!("{stdout}\n{stderr}");
    assert!(
        output_text.contains("unconstrained advice reaches a u32 operation"),
        "interprocedural advice source did not emit a u32 warning: {output_text}"
    );
}

#[test]
fn advice_provenance_survives_repeat_blocks() {
    let dir = temp_dir("repeat-advice");
    let file = dir.join("repeat_advice.masm");
    fs::write(
        &file,
        "\
pub proc test(seed: felt) -> felt
    adv_push
    repeat.2
        push.1
        add
    end
    push.1
    u32wrapping_add
end
",
    )
    .expect("failed to write MASM fixture");

    let output = run_masm_lint(&dir, &file);

    assert!(
        !output.status.success(),
        "repeat-carried advice unexpectedly passed: {output:?}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let output_text = format!("{stdout}\n{stderr}");
    assert!(
        output_text.contains("unconstrained advice reaches a u32 operation"),
        "repeat-carried advice did not emit a u32 warning: {output_text}"
    );
}

#[test]
fn while_blocks_are_lifted_for_clean_inputs() {
    let dir = temp_dir("while-clean");
    let file = dir.join("while_clean.masm");
    fs::write(
        &file,
        "\
pub proc test(flag: felt) -> felt
    while.true
        push.0
    end
    push.1
end
",
    )
    .expect("failed to write MASM fixture");

    let output = run_masm_lint(&dir, &file);

    assert!(output.status.success(), "while block MASM input failed: {output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("unsupported construct") && !stderr.contains("unsupported instruction"),
        "while block was reported unsupported: {stderr}"
    );
}
