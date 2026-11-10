#![cfg(all(
    feature = "std",
    feature = "script",
    feature = "flamegraph",
    feature = "repl"
))]

use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core::serde::Serializable;

fn command(directory: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_miden-debug"));
    command
        .current_dir(directory)
        .env_remove("MIDEN_SYSROOT")
        .env_remove("MIDENC_TRACE_TIMING")
        .env_remove("MIDENC_TRACE");
    command
}

fn package() -> Vec<u8> {
    Assembler::new(std::sync::Arc::new(DefaultSourceManager::default()))
        .assemble_program("cli-test", "begin push.7 add end")
        .unwrap()
        .to_bytes()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn batch_cli_executes_compiled_packages_and_accepts_all_timestamp_precisions() {
    let directory = tempfile::tempdir().unwrap();
    let artifact = directory.path().join("program.masp");
    let commands = directory.path().join("commands.txt");
    std::fs::write(&artifact, package()).unwrap();
    std::fs::write(&commands, "continue\nstack\nvars all\nquit\n").unwrap();
    for precision in ["s", "ms", "us", "ns"] {
        let output = command(directory.path())
            .env("MIDENC_TRACE_TIMING", precision)
            .arg(&artifact)
            .arg("--commands")
            .arg(&commands)
            .args(["--", "5"])
            .output()
            .unwrap();
        assert_success(&output);
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("Program terminated successfully"));
        assert!(stdout.contains("[0] 12 (0xc)"));
        assert!(stdout.contains("Program has terminated; no live variables"));
    }
    let output = command(directory.path())
        .env("MIDENC_TRACE_TIMING", "invalid")
        .arg(&artifact)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid MIDENC_TRACE_TIMING"));
}

#[test]
fn cli_reads_compiled_packages_from_stdin() {
    let directory = tempfile::tempdir().unwrap();
    let commands = directory.path().join("commands.txt");
    std::fs::write(&commands, "continue\nstack\nquit\n").unwrap();
    let mut child = command(directory.path())
        .arg("-")
        .arg("--commands")
        .arg(commands)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&package()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert_success(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("[0] 7 (0x7)"));
}

#[test]
fn repl_cli_accepts_commands_from_a_pipe_without_terminal_io() {
    let directory = tempfile::tempdir().unwrap();
    let artifact = directory.path().join("program.masp");
    std::fs::write(&artifact, package()).unwrap();
    let mut child = command(directory.path())
        .arg(&artifact)
        .arg("--repl")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"\ninvalid-command\ncontinue\nstack\nquit\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Miden Debugger REPL"));
    assert!(stdout.contains("[0] 7 (0x7)"));
    assert!(stdout.contains("Goodbye!"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown command"));
}

#[test]
fn flamegraph_cli_writes_svg_and_folded_profiles_for_compiled_packages() {
    let directory = tempfile::tempdir().unwrap();
    let artifact = directory.path().join("program.masp");
    std::fs::write(&artifact, package()).unwrap();
    for (filename, svg) in [("profile.svg", true), ("profile.folded", false)] {
        let path = directory.path().join(filename);
        let output = command(directory.path())
            .arg("flamegraph")
            .arg(&artifact)
            .arg("-o")
            .arg(&path)
            .output()
            .unwrap();
        assert_success(&output);
        let profile = std::fs::read_to_string(path).unwrap();
        assert!(!profile.is_empty());
        assert_eq!(profile.contains("<svg"), svg);
    }
}
