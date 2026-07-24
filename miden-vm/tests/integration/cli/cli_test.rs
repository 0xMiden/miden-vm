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
                debug_info
                    .source_map()
                    .is_some_and(|source_map| !source_map.asm_ops().is_empty())
            });
    assert!(found_one_asm_op);
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
