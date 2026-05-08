use std::process::Command;

#[test]
fn hard_errors_exit_with_code_two() {
    let status = Command::new(env!("CARGO_BIN_EXE_masm-lint"))
        .arg("__missing_masm_lint_input__.masm")
        .status()
        .expect("run masm-lint");

    assert_eq!(status.code(), Some(2));
}
