use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use assert_cmd::prelude::*;
use miden_mast_package::Package;
use predicates::prelude::*;

fn bin_under_test() -> escargot::CargoRun {
    escargot::CargoBuild::new()
        .bin("miden-vm")
        .features("executable")
        .current_release()
        .current_target()
        .run()
        .unwrap_or_else(|err| {
            // Process the error string to add borders.
            let formatted_err = err.to_string()
                .lines()
                // Add a "│" prefix to each line.
                .map(|line| format!("│\t{line}"))
                .collect::<Vec<_>>()
                .join("\n");

            // Print the error message that provides context and a specific command.
            panic!(
                "\n\
                Failed to build `miden-vm.\n\
                Original cargo error:\n\
                ┌──────────────────────────────────────────────────\n\
                {formatted_err}\n\
                └──────────────────────────────────────────────────\n\
                To reproduce this failure manually, run the following command:\n\
                $ cargo build -p miden-vm --no-default-features --features \"executable,internal\"\n\n"
            );
        })
}

fn test_file_path(name: &str) -> PathBuf {
    let id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("miden-vm-cli-{name}-{id}"))
}

#[test]
// Tt test might be an overkill to test only that the 'run' cli command
// outputs steps and ms.
fn cli_run() {
    let mut cmd = bin_under_test().command();

    cmd.arg("run")
        .arg("./masm-examples/fib/fib.masm")
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
    let program_path = test_file_path("missing-run-inputs").with_extension("masm");
    fs::write(&program_path, "begin push.1 end").unwrap();

    let mut cmd = bin_under_test().command();
    cmd.arg("run").arg(&program_path);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Failed to open input file"))
        .stderr(predicate::str::contains("miden-vm-cli-missing-run-inputs-"))
        .stderr(predicate::str::contains(".inputs"))
        .stderr(predicate::str::contains("No such file or directory"));

    fs::remove_file(program_path).unwrap();
}

#[test]
fn prove_rejects_missing_inferred_inputs_file() {
    let program_path = test_file_path("missing-prove-inputs").with_extension("masm");
    fs::write(&program_path, "begin push.1 end").unwrap();

    let mut cmd = bin_under_test().command();
    cmd.arg("prove").arg(&program_path);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Failed to open input file"))
        .stderr(predicate::str::contains("miden-vm-cli-missing-prove-inputs-"))
        .stderr(predicate::str::contains(".inputs"))
        .stderr(predicate::str::contains("No such file or directory"));

    fs::remove_file(program_path).unwrap();
}

#[test]
fn cli_bundle_debug() {
    let output_file = std::env::temp_dir().join("cli_bundle_debug.masp");

    let mut cmd = bin_under_test().command();
    cmd.arg("bundle")
        .arg("./tests/integration/cli/data/lib/mod.masm")
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
    fs::remove_file(&output_file).unwrap();
}

#[test]
fn cli_bundle_no_exports() {
    let mut cmd = bin_under_test().command();
    cmd.arg("bundle")
        .arg("--namespace")
        .arg("lib")
        .arg("./tests/integration/cli/data/lib_noexports/mod.masm");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("package must contain at least one exported procedure"));
}

#[test]
fn cli_bundle_kernel() {
    let output_file = std::env::temp_dir().join("cli_bundle_kernel.masp");

    let mut cmd = bin_under_test().command();
    cmd.arg("bundle")
        .arg("./tests/integration/cli/data/kernel_main.masm")
        .arg("--kernel")
        .arg("--output")
        .arg(output_file.as_path());
    cmd.assert().success();
    fs::remove_file(&output_file).unwrap()
}

/// A kernel can bundle with a library w/o exports.
#[test]
fn cli_bundle_kernel_noexports() {
    let output_file = std::env::temp_dir().join("cli_bundle_kernel_noexports.masp");

    let mut cmd = bin_under_test().command();
    cmd.arg("bundle")
        .arg("./tests/integration/cli/data/kernel_noexports.masm")
        .arg("--kernel")
        .arg("--output")
        .arg(output_file.as_path());
    cmd.assert().success();
    fs::remove_file(&output_file).unwrap()
}

#[test]
fn cli_bundle_output() {
    let mut cmd = bin_under_test().command();
    cmd.arg("bundle")
        .arg("./tests/integration/cli/data/lib/mod.masm")
        .arg("--namespace")
        .arg("lib")
        .arg("--output")
        .arg("cli_bundle_output.masp");
    cmd.assert().success();
    assert!(Path::new("cli_bundle_output.masp").exists());
    fs::remove_file("cli_bundle_output.masp").unwrap()
}

// First compile a library to a .masp file, then run a program that uses it.
#[test]
fn cli_run_with_lib() {
    let mut cmd = bin_under_test().command();
    cmd.arg("bundle")
        .arg("./tests/integration/cli/data/lib/mod.masm")
        .arg("--namespace")
        .arg("lib")
        .arg("--output")
        .arg("cli_run_with_lib.masp");
    cmd.assert().success();

    let mut cmd = bin_under_test().command();
    cmd.arg("run")
        .arg("./tests/integration/cli/data/main.masm")
        .arg("-l")
        .arg("./cli_run_with_lib.masp");
    cmd.assert().success();

    fs::remove_file("cli_run_with_lib.masp").unwrap();
}

#[test]
fn test_advmap_cli() {
    let mut cmd = bin_under_test().command();
    cmd.arg("run").arg("./tests/integration/cli/data/adv_map.masm");
    cmd.assert().success();
}
