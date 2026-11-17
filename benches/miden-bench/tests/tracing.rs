use std::process::{Command, Output};

fn run_benchmark(rust_log: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_miden-bench"));
    command.arg("poseidon2:8").env_remove("RUST_LOG");
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
