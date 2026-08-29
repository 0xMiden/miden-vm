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
fn prove_writes_outputs_next_to_a_custom_proof_file() {
    let working_dir = TempDir::new().unwrap();
    let program_path = working_dir.path().join("program.masm");
    fs::write(&program_path, "begin add end").unwrap();
    fs::write(working_dir.path().join("program.inputs"), r#"{ "operand_stack": [] }"#).unwrap();

    let proof_dir = working_dir.path().join("out");
    fs::create_dir(&proof_dir).unwrap();

    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("prove")
        .arg(&program_path)
        .arg("--proof")
        .arg(proof_dir.join("custom.proof"));
    cmd.assert().success();

    assert!(proof_dir.join("custom.proof").exists(), "the proof belongs where --proof asked");
    assert!(
        proof_dir.join("custom.outputs").exists(),
        "the outputs belong next to the proof, which is where `verify` looks for them"
    );
    assert!(
        !working_dir.path().join("program.outputs").exists(),
        "the outputs should not be left behind next to the program"
    );
}

#[test]
fn prove_rejects_a_proof_file_that_the_outputs_would_overwrite() {
    let working_dir = TempDir::new().unwrap();
    let program_path = working_dir.path().join("program.masm");
    fs::write(&program_path, "begin add end").unwrap();
    fs::write(working_dir.path().join("program.inputs"), r#"{ "operand_stack": [] }"#).unwrap();
    let proof_path = working_dir.path().join("custom.outputs");

    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("prove").arg(&program_path).arg("--proof").arg(&proof_path);
    cmd.assert()
        .failure()
        // The diagnostic renderer hard-wraps long messages, so match single words that cannot
        // be split across lines (the same reason the tests above match the path in fragments).
        .stderr(predicate::str::contains("overwrite"))
        .stdout(predicate::str::contains("Proving program with hash").not());

    assert!(!proof_path.exists(), "nothing should be written when the paths collide");
}

#[test]
fn prove_accepts_an_outputs_shaped_proof_file_when_output_is_explicit() {
    let working_dir = TempDir::new().unwrap();
    let program_path = working_dir.path().join("program.masm");
    fs::write(&program_path, "begin add end").unwrap();
    fs::write(working_dir.path().join("program.inputs"), r#"{ "operand_stack": [] }"#).unwrap();
    let proof_path = working_dir.path().join("custom.outputs");
    let output_path = working_dir.path().join("elsewhere.outputs");

    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("prove")
        .arg(&program_path)
        .arg("--proof")
        .arg(&proof_path)
        .arg("--output")
        .arg(&output_path);
    cmd.assert().success();

    assert!(proof_path.exists(), "the proof should survive an explicit --output");
    assert!(output_path.exists(), "the outputs should go where --output asked");
}

#[test]
fn prove_rejects_a_proof_file_that_collides_only_by_extension_case() {
    let working_dir = TempDir::new().unwrap();
    let program_path = working_dir.path().join("program.masm");
    fs::write(&program_path, "begin add end").unwrap();
    fs::write(working_dir.path().join("program.inputs"), r#"{ "operand_stack": [] }"#).unwrap();
    let proof_path = working_dir.path().join("custom.OUTPUTS");

    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("prove").arg(&program_path).arg("--proof").arg(&proof_path);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("overwrite"))
        .stdout(predicate::str::contains("Proving program with hash").not());

    assert!(!proof_path.exists(), "nothing should be written when the paths collide");
}

#[test]
fn prove_rejects_an_explicit_output_that_repeats_the_proof_path() {
    let working_dir = TempDir::new().unwrap();
    let program_path = working_dir.path().join("program.masm");
    fs::write(&program_path, "begin add end").unwrap();
    fs::write(working_dir.path().join("program.inputs"), r#"{ "operand_stack": [] }"#).unwrap();
    let proof_path = working_dir.path().join("custom.proof");

    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("prove")
        .arg(&program_path)
        .arg("--proof")
        .arg(&proof_path)
        .arg("--output")
        .arg(&proof_path);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("overwrite"))
        .stdout(predicate::str::contains("Proving program with hash").not());

    assert!(!proof_path.exists(), "nothing should be written when the paths collide");
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
