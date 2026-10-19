use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use assert_cmd::prelude::*;
use miden_mast_package::Package;
use predicates::prelude::*;
use tempfile::TempDir;

fn bin_under_test(working_dir: &Path) -> Command {
    let binary = env::var("NEXTEST_BIN_EXE_miden_vm")
        .or_else(|_| env::var("CARGO_BIN_EXE_miden-vm"))
        .expect("the test runner should provide the path to the miden-vm binary");
    let mut command = Command::new(binary);
    command.current_dir(working_dir);
    command
}

fn fixture(path: impl AsRef<Path>) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

#[test]
fn advice_budget_is_checked_before_merkle_loading_in_run_and_prove() {
    let working_dir = TempDir::new().unwrap();
    let source = "begin push.1 drop end";
    let masm_path = working_dir.path().join("budget.masm");
    let masp_path = working_dir.path().join("budget.masp");
    fs::write(&masm_path, source).unwrap();
    miden_assembly::Assembler::default()
        .assemble_program("budget", source)
        .unwrap()
        .write_to_file(&masp_path)
        .unwrap();

    // The map alone fills the default allowance before accounting for its key and the
    // default Merkle store. A legacy parser decodes the malformed SMT leaf first instead.
    let values = "0,".repeat(miden_vm::ExecutionOptions::DEFAULT_MAX_ADVICE_SIZE_BYTES / 8);
    let key = format!("0x{}", "00".repeat(32));
    let json = format!(
        "{{\"operand_stack\":[],\"advice_map\":{{\"{key}\":[{values}0]}},\
         \"merkle_store\":[{{\"sparse_merkle_tree\":[[0,\"not-a-word\"]]}}]}}"
    );
    fs::write(working_dir.path().join("budget.inputs"), json).unwrap();

    for command in ["run", "prove"] {
        for program in [&masm_path, &masp_path] {
            let mut cmd = bin_under_test(working_dir.path());
            cmd.arg(command).arg(program);
            cmd.assert()
                .failure()
                .stderr(predicate::str::contains("advice provider size budget exceeded"))
                .stderr(predicate::str::contains("failed to decode").not());
        }
    }

    // Both run entrypoints must still accept a valid sparse tree, including the maximum index.
    let leaf = format!("0x01{}", "00".repeat(31));
    fs::write(
        working_dir.path().join("budget.inputs"),
        format!(
            "{{\"operand_stack\":[],\"merkle_store\":[{{\"sparse_merkle_tree\":[[{},\"{leaf}\"]]}}]}}",
            u64::MAX,
        ),
    )
    .unwrap();
    for program in [&masm_path, &masp_path] {
        let mut cmd = bin_under_test(working_dir.path());
        cmd.arg("run").arg(program);
        cmd.assert().success();
    }
}

#[test]
// Tt test might be an overkill to test only that the 'run' cli command
// outputs steps and ms.
fn cli_run() {
    let working_dir = TempDir::new().unwrap();
    let mut cmd = bin_under_test(working_dir.path());

    cmd.arg("run")
        .arg(fixture("masm-examples/fib/fib.masm"))
        .arg("-n")
        .arg("1")
        .arg("-m")
        .arg("8192")
        .arg("-e")
        .arg("8192");

    let output = cmd.unwrap();

    // This tests what we want. Actually it outputs X steps in Y ms.
    // However we the X and the Y can change in future versions.
    // There is no other 'steps in' in the output
    output.assert().stdout(predicate::str::contains("VM cycles"));
}

#[test]
fn run_rejects_missing_inferred_inputs_file() {
    let working_dir = TempDir::new().unwrap();
    let program_path = working_dir.path().join("miden-vm-cli-missing-run-inputs-test.masm");
    fs::write(&program_path, "begin push.1 end").unwrap();

    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("run").arg(&program_path);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Failed to open input file"))
        .stderr(predicate::str::contains("miden-vm-cli-missing-run-"))
        .stderr(predicate::str::contains("test.inputs"))
        .stderr(predicate::str::contains("No such file or directory"));
}

#[test]
fn prove_rejects_missing_inferred_inputs_file() {
    let working_dir = TempDir::new().unwrap();
    let program_path = working_dir.path().join("miden-vm-cli-missing-prove-inputs-test.masm");
    fs::write(&program_path, "begin push.1 end").unwrap();

    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("prove").arg(&program_path);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Failed to open input file"))
        .stderr(predicate::str::contains("miden-vm-cli-missing-prove-"))
        .stderr(predicate::str::contains("test.inputs"))
        .stderr(predicate::str::contains("No such file or directory"));
}

#[test]
fn prove_rejects_invalid_program_extension_before_inferred_inputs_file() {
    let working_dir = TempDir::new().unwrap();
    let program_path = working_dir.path().join("miden-vm-cli-invalid-prove-extension-test.txt");
    fs::write(&program_path, "begin push.1 end").unwrap();

    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("prove").arg(&program_path);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains(
            "The provided file must have a .masm or .masp extension",
        ))
        .stderr(predicate::str::contains("Failed to open input file").not());
}

#[test]
fn cli_bundle_debug() {
    let working_dir = TempDir::new().unwrap();
    let output_file = working_dir.path().join("cli_bundle_debug.masp");

    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("bundle")
        .arg(fixture("tests/integration/cli/data/lib/mod.masm"))
        .arg("--namespace")
        .arg("lib")
        .arg("--output")
        .arg(output_file.as_path());
    cmd.assert().success();

    let lib = Package::deserialize_from_file_trusted(&output_file).unwrap();
    // If there are any package-owned AssemblyOps, the bundle is in debug mode.
    let found_one_asm_op =
        lib.debug_info()
            .expect("package debug info should decode")
            .is_some_and(|debug_info| {
                debug_info.nodes().iter().any(|source_node| !source_node.asm_ops.is_empty())
            });
    assert!(found_one_asm_op);
}

#[test]
fn rejects_oversized_kernel_packages_in_run_prove_and_verify() {
    let working_dir = TempDir::new().unwrap();
    let program_path = working_dir.path().join("program.masm");
    let kernel_path = working_dir.path().join("kernel.masp");
    fs::write(&program_path, "begin push.1 drop end").unwrap();
    fs::write(program_path.with_extension("inputs"), r#"{"operand_stack":[]}"#).unwrap();

    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("bundle")
        .arg(fixture("tests/integration/cli/data/kernel_main.masm"))
        .arg("--kernel")
        .arg("--output")
        .arg(&kernel_path);
    cmd.assert().success();

    // Exercise both loaders successfully with a valid kernel before checking their size limits.
    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("prove").arg(&program_path).arg("--kernel").arg(&kernel_path);
    let stdout = String::from_utf8(cmd.assert().success().get_output().stdout.clone()).unwrap();
    let program_hash = stdout
        .lines()
        .find_map(|line| line.strip_prefix("Proving program with hash "))
        .and_then(|line| line.strip_suffix("..."))
        .expect("prove prints the program hash");

    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("verify")
        .arg("--proof")
        .arg(program_path.with_extension("proof"))
        .arg("--program-hash")
        .arg(program_hash)
        .arg("--kernel")
        .arg(&kernel_path);
    cmd.assert().success();

    fs::OpenOptions::new()
        .write(true)
        .open(&kernel_path)
        .unwrap()
        .set_len(Package::MAX_FILE_SIZE as u64 + 1)
        .unwrap();
    let oversized_error = |stderr: &str| {
        // The diagnostic renderer can wrap the message after the file path.
        stderr
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .contains("file exceeds size limit of 536870912 bytes")
    };
    for command in ["run", "prove"] {
        let mut cmd = bin_under_test(working_dir.path());
        cmd.arg(command).arg(&program_path).arg("--kernel").arg(&kernel_path);
        cmd.assert().failure().stderr(predicate::function(oversized_error));
    }

    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("verify")
        .arg("--proof")
        .arg(program_path.with_extension("proof"))
        .arg("--program-hash")
        .arg(program_hash)
        .arg("--kernel")
        .arg(&kernel_path);
    cmd.assert().failure().stderr(predicate::function(oversized_error));
}

#[cfg(unix)]
#[test]
fn atomic_artifact_writes_preserve_existing_files_on_io_failure() {
    let working_dir = TempDir::new().unwrap();
    let program_path = working_dir.path().join("program.masm");
    let proof_path = working_dir.path().join("program.proof");
    let outputs_path = working_dir.path().join("program.outputs");
    fs::write(&program_path, "begin push.1 drop end").unwrap();
    fs::write(program_path.with_extension("inputs"), r#"{"operand_stack":[]}"#).unwrap();
    fs::write(&proof_path, b"stale proof").unwrap();
    fs::write(&outputs_path, b"stale outputs").unwrap();

    // Bare filenames exercise temporary-file creation in the current directory.
    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("prove").arg("program.masm");
    let stdout = String::from_utf8(cmd.assert().success().get_output().stdout.clone()).unwrap();
    let program_hash = stdout
        .lines()
        .find_map(|line| line.strip_prefix("Proving program with hash "))
        .and_then(|line| line.strip_suffix("..."))
        .expect("prove prints the program hash");
    let previous_proof = fs::read(&proof_path).unwrap();
    let previous_outputs = fs::read(&outputs_path).unwrap();

    let binary = bin_under_test(working_dir.path()).get_program().to_owned();
    for (args, diagnostic) in [
        (
            ["run", "program.masm", "--output", "program.outputs"],
            "Failed to write output file `program.outputs`",
        ),
        (
            ["prove", "program.masm", "--proof", "program.proof"],
            "Failed to write proof file `program.proof`",
        ),
    ] {
        // Ignore SIGXFSZ so the kernel returns a write error to the CLI. The limit applies only
        // to this child process and forbids any file data from being written.
        let mut cmd = Command::new("sh");
        cmd.current_dir(working_dir.path())
            .args(["-c", "set -eu; trap '' XFSZ; ulimit -f 0; exec \"$@\"", "sh"])
            .arg(&binary)
            .args(args);
        cmd.assert().failure().stderr(predicate::str::contains(diagnostic));

        assert_eq!(fs::read(&proof_path).unwrap(), previous_proof);
        assert_eq!(fs::read(&outputs_path).unwrap(), previous_outputs);
        assert_eq!(fs::read_dir(working_dir.path()).unwrap().count(), 4);
    }

    // The old artifacts remain usable after both write failures.
    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("verify")
        .arg("--proof")
        .arg("program.proof")
        .arg("--program-hash")
        .arg(program_hash);
    cmd.assert().success();
}

#[test]
fn cli_bundle_release_strips_debug_info() {
    let working_dir = TempDir::new().unwrap();
    let cases = [
        (
            "library",
            fixture("tests/integration/cli/data/lib/mod.masm"),
            vec!["--namespace", "lib"],
        ),
        (
            "kernel",
            fixture("tests/integration/cli/data/kernel_main.masm"),
            vec!["--kernel"],
        ),
    ];

    for (name, source, extra_args) in cases {
        let debug_output = working_dir.path().join(format!("{name}-debug.masp"));
        let release_output = working_dir.path().join(format!("{name}-release.masp"));

        let mut cmd = bin_under_test(working_dir.path());
        cmd.arg("bundle")
            .arg(&source)
            .args(&extra_args)
            .arg("--output")
            .arg(&debug_output);
        cmd.assert().success();

        let mut cmd = bin_under_test(working_dir.path());
        cmd.arg("bundle")
            .arg(&source)
            .args(&extra_args)
            .arg("--release")
            .arg("--output")
            .arg(&release_output);
        cmd.assert().success();

        let debug_bytes = fs::read(&debug_output).unwrap();
        let release_bytes = fs::read(&release_output).unwrap();
        let source_path = source.to_string_lossy();

        assert_ne!(debug_bytes, release_bytes, "{name} bundles should differ");
        assert!(
            debug_bytes
                .windows(source_path.len())
                .any(|bytes| bytes == source_path.as_bytes()),
            "debug {name} bundle should contain its source path"
        );
        assert!(
            !release_bytes
                .windows(source_path.len())
                .any(|bytes| bytes == source_path.as_bytes()),
            "release {name} bundle should omit its source path"
        );

        let debug_package = Package::deserialize_from_file_trusted(&debug_output).unwrap();
        let release_package = Package::deserialize_from_file_trusted(&release_output).unwrap();

        assert!(
            debug_package.debug_info().unwrap().is_some(),
            "debug {name} bundle should contain package debug info"
        );
        assert!(
            release_package.debug_info().unwrap().is_none(),
            "release {name} bundle should omit package debug info"
        );
        assert_eq!(
            debug_package.mast_forest_commitment(),
            release_package.mast_forest_commitment(),
            "release mode should preserve the {name} MAST digest"
        );
    }
}

#[test]
fn cli_bundle_version() {
    let working_dir = TempDir::new().unwrap();
    let cases = [
        (
            "library",
            fixture("tests/integration/cli/data/lib/mod.masm"),
            vec!["--namespace", "lib"],
        ),
        (
            "kernel",
            fixture("tests/integration/cli/data/kernel_main.masm"),
            vec!["--kernel"],
        ),
    ];

    for (name, source, extra_args) in cases {
        let requested_output = working_dir.path().join(format!("{name}-versioned.masp"));
        let default_output = working_dir.path().join(format!("{name}-default-version.masp"));

        let mut cmd = bin_under_test(working_dir.path());
        cmd.arg("bundle")
            .arg(&source)
            .args(&extra_args)
            .arg("--version")
            .arg("1.2.3")
            .arg("--output")
            .arg(&requested_output);
        cmd.assert().success();

        let package = Package::deserialize_from_file_trusted(&requested_output).unwrap();
        assert_eq!(package.version, "1.2.3".parse().unwrap());

        let mut cmd = bin_under_test(working_dir.path());
        cmd.arg("bundle")
            .arg(&source)
            .args(&extra_args)
            .arg("--output")
            .arg(&default_output);
        cmd.assert().success();

        let package = Package::deserialize_from_file_trusted(&default_output).unwrap();
        assert_eq!(package.version, "0.1.0".parse().unwrap());
    }

    let invalid_output = working_dir.path().join("invalid-version.masp");
    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("bundle")
        .arg(fixture("tests/integration/cli/data/lib/mod.masm"))
        .arg("--namespace")
        .arg("lib")
        .arg("--version")
        .arg("not-a-version")
        .arg("--output")
        .arg(&invalid_output);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("invalid value 'not-a-version'"))
        .stderr(predicate::str::contains("--version <VERSION>"));
    assert!(!invalid_output.exists());
}

#[test]
fn cli_bundle_no_exports() {
    let working_dir = TempDir::new().unwrap();
    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("bundle")
        .arg("--namespace")
        .arg("lib")
        .arg(fixture("tests/integration/cli/data/lib_noexports/mod.masm"));
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("package must contain at least one exported procedure"));
}

#[test]
fn cli_bundle_kernel() {
    let working_dir = TempDir::new().unwrap();
    let output_file = working_dir.path().join("cli_bundle_kernel.masp");

    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("bundle")
        .arg(fixture("tests/integration/cli/data/kernel_main.masm"))
        .arg("--kernel")
        .arg("--output")
        .arg(output_file.as_path());
    cmd.assert().success();
}

/// A kernel can bundle with a library w/o exports.
#[test]
fn cli_bundle_kernel_noexports() {
    let working_dir = TempDir::new().unwrap();
    let output_file = working_dir.path().join("cli_bundle_kernel_noexports.masp");

    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("bundle")
        .arg(fixture("tests/integration/cli/data/kernel_noexports.masm"))
        .arg("--kernel")
        .arg("--output")
        .arg(output_file.as_path());
    cmd.assert().success();
}

#[test]
fn cli_bundle_output() {
    let working_dir = TempDir::new().unwrap();
    let output_file = working_dir.path().join("cli_bundle_output.masp");
    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("bundle")
        .arg(fixture("tests/integration/cli/data/lib/mod.masm"))
        .arg("--namespace")
        .arg("lib")
        .arg("--output")
        .arg("cli_bundle_output.masp");
    cmd.assert().success();
    assert!(output_file.exists());
}

// First compile a library to a .masp file, then run a program that uses it.
#[test]
fn cli_run_with_lib() {
    let working_dir = TempDir::new().unwrap();
    let output_file = working_dir.path().join("cli_run_with_lib.masp");
    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("bundle")
        .arg(fixture("tests/integration/cli/data/lib/mod.masm"))
        .arg("--namespace")
        .arg("lib")
        .arg("--output")
        .arg("cli_run_with_lib.masp");
    cmd.assert().success();

    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("run")
        .arg(fixture("tests/integration/cli/data/main.masm"))
        .arg("-l")
        .arg(&output_file);
    cmd.assert().success();
}

#[test]
fn test_advmap_cli() {
    let working_dir = TempDir::new().unwrap();
    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("run").arg(fixture("tests/integration/cli/data/adv_map.masm"));
    cmd.assert().success();
}
