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
    Command::new(env!("CARGO_BIN_EXE_masm-lint"))
        .arg("--no-color")
        .args(args)
        .arg(input)
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
