use std::{fs, path::Path};

use assert_cmd::prelude::*;
use predicates::prelude::*;
extern crate escargot;

fn bin_under_test() -> escargot::CargoRun {
    escargot::CargoBuild::new()
        .bin("miden")
        .features("executable internal")
        .current_release()
        .current_target()
        .run()
        .unwrap_or_else(|err| {
            eprintln!("{err}");
            panic!("failed to build `miden`");
        })
}

#[test]
#[ignore = "fix-prover"]
// Tt test might be an overkill to test only that the 'run' cli command
// outputs steps and ms.
fn cli_run() -> Result<(), Box<dyn std::error::Error>> {
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

    Ok(())
}

#[test]
#[ignore = "fix-prover"]
fn cli_run_masp() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = bin_under_test().command();

    cmd.arg("run")
        .arg("./tests/integration/cli/data/masp/is_prime.masp")
        .arg("-i")
        .arg("./tests/integration/cli/data/masp/is_prime.inputs");

    let output = cmd.unwrap();

    output.assert().stdout(predicate::str::contains("VM cycles"));

    Ok(())
}

#[test]
#[ignore = "fix-prover"]
fn cli_prove_masp() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = bin_under_test().command();

    cmd.arg("prove")
        .arg("./tests/integration/cli/data/masp/is_prime.masp")
        .arg("-i")
        .arg("./tests/integration/cli/data/masp/is_prime.inputs");

    let output = cmd.unwrap();

    output.assert().stdout(predicate::str::contains("proved in"));

    fs::remove_file("./tests/integration/cli/data/masp/is_prime.proof").unwrap();
    fs::remove_file("./tests/integration/cli/data/masp/is_prime.outputs").unwrap();

    Ok(())
}

use assembly::Library;
use vm_core::Decorator;

#[test]
#[ignore = "fix-prover"]
fn cli_bundle_debug() {
    let mut cmd = bin_under_test().command();
    cmd.arg("bundle").arg("--debug").arg("./tests/integration/cli/data/lib");
    cmd.assert().success();

    let lib = Library::deserialize_from_file("./tests/integration/cli/data/out.masl").unwrap();
    // If there are any AsmOp decorators in the forest, the bundle is in debug mode.
    let found_one_asm_op =
        lib.mast_forest().decorators().iter().any(|d| matches!(d, Decorator::AsmOp(_)));
    assert!(found_one_asm_op);
    fs::remove_file("./tests/integration/cli/data/out.masl").unwrap();
}

#[test]
#[ignore = "fix-prover"]
fn cli_bundle_no_exports() {
    let mut cmd = bin_under_test().command();
    cmd.arg("bundle").arg("./tests/integration/cli/data/lib_noexports");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("library must contain at least one exported procedure"));
}

#[test]
#[ignore = "fix-prover"]
fn cli_bundle_kernel() {
    let mut cmd = bin_under_test().command();
    cmd.arg("bundle")
        .arg("./tests/integration/cli/data/lib")
        .arg("--kernel")
        .arg("./tests/integration/cli/data/kernel_main.masm");
    cmd.assert().success();
    fs::remove_file("./tests/integration/cli/data/out.masl").unwrap()
}

/// A kernel can bundle with a library w/o exports.
#[test]
#[ignore = "fix-prover"]
fn cli_bundle_kernel_noexports() {
    let mut cmd = bin_under_test().command();
    cmd.arg("bundle")
        .arg("./tests/integration/cli/data/lib_noexports")
        .arg("--kernel")
        .arg("./tests/integration/cli/data/kernel_main.masm");
    cmd.assert().success();
    fs::remove_file("./tests/integration/cli/data/out.masl").unwrap()
}

#[test]
#[ignore = "fix-prover"]
fn cli_bundle_output() {
    let mut cmd = bin_under_test().command();
    cmd.arg("bundle")
        .arg("./tests/integration/cli/data/lib")
        .arg("--output")
        .arg("test.masl");
    cmd.assert().success();
    assert!(Path::new("test.masl").exists());
    fs::remove_file("test.masl").unwrap()
}

#[test]
#[ignore = "fix-prover"]
// First compile a library to a .masl file, then run a program that uses it.
fn cli_run_with_lib() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = bin_under_test().command();
    cmd.arg("bundle")
        .arg("./tests/integration/cli/data/lib")
        .arg("--output")
        .arg("lib.masl");
    cmd.assert().success();

    let mut cmd = bin_under_test().command();
    cmd.arg("run")
        .arg("./tests/integration/cli/data/main.masm")
        .arg("-l")
        .arg("./lib.masl");
    cmd.assert().success();

    fs::remove_file("lib.masl").unwrap();
    Ok(())
}

#[test]
#[ignore = "fix-prover"]
fn cli_analyze_masp() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = bin_under_test().command();

    cmd.arg("analyze")
        .arg("./tests/integration/cli/data/masp/is_prime.masp")
        .arg("-i")
        .arg("./tests/integration/cli/data/masp/is_prime.inputs");

    let output = cmd.unwrap();

    output.assert().stdout(predicate::str::contains("Total number of NOOPs"));

    Ok(())
}

#[test]
#[ignore = "fix-prover"]
fn cli_debug_masp() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = bin_under_test().command();

    cmd.arg("debug")
        .arg("./tests/integration/cli/data/masp/is_prime.masp")
        .arg("-i")
        .arg("./tests/integration/cli/data/masp/is_prime.inputs");

    let output = cmd.unwrap();

    output.assert().stdout(predicate::str::contains("Debugging program"));

    Ok(())
}
