use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
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

fn run_masm_lint(cwd: &Path, input: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_masm-lint"))
        .arg("--no-color")
        .arg(input)
        .current_dir(cwd)
        .output()
        .expect("run masm-lint")
}

#[test]
fn clean_inputs_exit_with_code_zero() {
    let dir = temp_dir("clean-exit");
    let file = dir.join("clean.masm");
    fs::write(
        &file,
        "\
pub proc clean(seed: felt) -> felt
    push.1
    add
end
",
    )
    .expect("failed to write clean MASM fixture");

    let output = run_masm_lint(&dir, &file);

    assert_eq!(output.status.code(), Some(0), "clean input output: {output:?}");
}

#[test]
fn clean_inputs_exit_with_code_zero_with_debug_tracing_enabled() {
    let dir = temp_dir("clean-exit-debug-tracing");
    let file = dir.join("clean.masm");
    fs::write(
        &file,
        "\
pub proc clean(seed: felt) -> felt
    push.1
    add
end
",
    )
    .expect("failed to write clean MASM fixture");

    let output = Command::new(env!("CARGO_BIN_EXE_masm-lint"))
        .arg("--no-color")
        .arg(&file)
        .current_dir(&dir)
        .env("MIDEN_LOG", "debug")
        .output()
        .expect("run masm-lint");

    assert_eq!(output.status.code(), Some(0), "clean input with tracing output: {output:?}");
}

#[test]
fn warning_inputs_exit_with_code_one() {
    let dir = temp_dir("warning-exit");
    let file = dir.join("warning.masm");
    fs::write(
        &file,
        "\
pub proc warning(seed: felt) -> felt
    adv_push
    u32wrapping_add
end
",
    )
    .expect("failed to write warning MASM fixture");

    let output = run_masm_lint(&dir, &file);

    assert_eq!(output.status.code(), Some(1), "warning input output: {output:?}");
}

#[test]
fn hard_errors_exit_with_code_two() {
    let status = Command::new(env!("CARGO_BIN_EXE_masm-lint"))
        .arg("__missing_masm_lint_input__.masm")
        .status()
        .expect("run masm-lint");

    assert_eq!(status.code(), Some(2));
}
