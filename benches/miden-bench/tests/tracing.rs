use std::process::{Command, Output};

fn run_benchmark(rust_log: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_miden-bench"));
    command.arg("blake3:8").env_remove("RUST_LOG");
    if let Some(value) = rust_log {
        command.env("RUST_LOG", value);
    }
    command.output().unwrap()
}

#[test]
fn rust_log_overrides_are_validated() {
    let default = run_benchmark(None);
    assert!(default.status.success(), "{}", String::from_utf8_lossy(&default.stderr));

    let invalid = run_benchmark(Some("miden::vm::prove=invalid"));
    assert!(!invalid.status.success());
    let stderr = String::from_utf8(invalid.stderr).unwrap();
    assert!(stderr.contains("invalid RUST_LOG"), "{stderr}");
}

#[test]
fn verbose_batch_keeps_backend_spans() {
    let output = Command::new(env!("CARGO_BIN_EXE_miden-bench"))
        .env_remove("RUST_LOG")
        .args(["-v", "-m", "batch", "-H", "blake3", "blake3:8"])
        .output()
        .unwrap();
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "{logs}");
    assert!(logs.contains("compute quotient"), "{logs}");
}
