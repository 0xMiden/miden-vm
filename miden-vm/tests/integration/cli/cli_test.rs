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

/// Builds a working directory holding a program and its inputs, and a `prove` command that runs
/// inside it against that program. Each test then adds only the paths it is about.
fn prove_command() -> (TempDir, Command) {
    let working_dir = TempDir::new().unwrap();
    let program_path = working_dir.path().join("program.masm");
    fs::write(&program_path, "begin add end").unwrap();
    fs::write(working_dir.path().join("program.inputs"), r#"{ "operand_stack": [] }"#).unwrap();

    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("prove").arg(&program_path);

    (working_dir, cmd)
}

/// Asserts that `proof_path` holds a proof and not the outputs file that used to replace it.
///
/// The outputs are a couple of hundred bytes of JSON; a proof is tens of kilobytes of binary.
fn assert_proof_survived(proof_path: &Path) {
    let proof = fs::read(proof_path).expect("the proof should have been written");
    assert!(
        proof.len() > 1024 && !proof.starts_with(b"{"),
        "the proof was replaced by a {} byte outputs file",
        proof.len()
    );
}

/// Returns true when the filesystem under `dir` treats `name` and `alias` as one file.
///
/// Case-insensitive and normalization-insensitive filesystems do; ext4 does not, and there the
/// aliasing branch of the tests below cannot be reached.
fn filesystem_aliases(dir: &Path, name: &str, alias: &str) -> bool {
    let probe_dir = dir.join("alias-probe");
    fs::create_dir(&probe_dir).unwrap();
    fs::write(probe_dir.join(name), "probe").unwrap();
    let aliased = probe_dir.join(alias).exists();
    fs::remove_dir_all(&probe_dir).unwrap();
    aliased
}

#[test]
fn prove_writes_outputs_next_to_a_custom_proof_file() {
    let (working_dir, mut cmd) = prove_command();
    let proof_dir = working_dir.path().join("out");
    fs::create_dir(&proof_dir).unwrap();

    cmd.arg("--proof").arg(proof_dir.join("custom.proof"));
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
fn prove_keeps_a_proof_file_that_the_outputs_would_overwrite() {
    let (working_dir, mut cmd) = prove_command();
    let proof_path = working_dir.path().join("custom.outputs");

    cmd.arg("--proof").arg(&proof_path);
    cmd.assert()
        .failure()
        // The diagnostic renderer hard-wraps long messages, so match single words that cannot
        // be split across lines (the same reason the tests above match the path in fragments).
        .stderr(predicate::str::contains("overwrite"));

    assert_proof_survived(&proof_path);
}

#[test]
fn prove_accepts_an_outputs_shaped_proof_file_when_output_is_explicit() {
    let (working_dir, mut cmd) = prove_command();
    let proof_path = working_dir.path().join("custom.outputs");
    let output_path = working_dir.path().join("elsewhere.outputs");

    cmd.arg("--proof").arg(&proof_path).arg("--output").arg(&output_path);
    cmd.assert().success();

    assert_proof_survived(&proof_path);
    assert!(output_path.exists(), "the outputs should go where --output asked");
}

#[test]
fn prove_handles_an_outputs_path_that_differs_from_the_proof_only_in_case() {
    let (working_dir, mut cmd) = prove_command();
    let proof_path = working_dir.path().join("custom.OUTPUTS");
    let output_path = working_dir.path().join("custom.outputs");

    cmd.arg("--proof").arg(&proof_path);

    if filesystem_aliases(working_dir.path(), "custom.OUTPUTS", "custom.outputs") {
        cmd.assert().failure().stderr(predicate::str::contains("overwrite"));
        assert_proof_survived(&proof_path);
    } else {
        cmd.assert().success();
        assert_proof_survived(&proof_path);
        assert!(output_path.exists(), "the two names are separate files here");
    }
}

#[test]
fn prove_handles_an_outputs_path_that_differs_from_the_proof_only_in_unicode_normalization() {
    let (working_dir, mut cmd) = prove_command();
    // The same grapheme twice: composed, then decomposed as `e` plus a combining acute accent.
    let composed = "\u{e9}.proof";
    let decomposed = "e\u{301}.proof";
    let proof_path = working_dir.path().join(decomposed);
    let output_path = working_dir.path().join(composed);

    cmd.arg("--proof").arg(&proof_path).arg("--output").arg(&output_path);

    if filesystem_aliases(working_dir.path(), decomposed, composed) {
        cmd.assert().failure().stderr(predicate::str::contains("overwrite"));
        assert_proof_survived(&proof_path);
    } else {
        cmd.assert().success();
        assert_proof_survived(&proof_path);
        assert!(output_path.exists(), "the two spellings are separate files here");
    }
}

#[test]
fn prove_keeps_the_proof_when_an_explicit_output_repeats_its_path() {
    let (working_dir, mut cmd) = prove_command();
    let proof_path = working_dir.path().join("same.proof");

    cmd.arg("--proof").arg(&proof_path).arg("--output").arg(&proof_path);
    cmd.assert().failure().stderr(predicate::str::contains("overwrite"));

    assert_proof_survived(&proof_path);
}

#[test]
fn prove_keeps_the_proof_when_an_explicit_output_collides_through_dot_dot_components() {
    let (working_dir, mut cmd) = prove_command();
    fs::create_dir(working_dir.path().join("sub")).unwrap();
    let proof_path = working_dir.path().join("same.proof");
    let aliased_proof_path = working_dir.path().join("./sub/../same.proof");

    cmd.arg("--proof").arg(&aliased_proof_path).arg("--output").arg(&proof_path);
    cmd.assert().failure().stderr(predicate::str::contains("overwrite"));

    assert_proof_survived(&proof_path);
}

#[test]
fn prove_keeps_the_proof_when_an_explicit_output_repeats_its_path_in_absolute_form() {
    let (working_dir, mut cmd) = prove_command();
    let proof_path = working_dir.path().join("same.proof");

    // The command runs with `working_dir` as its current directory, so the relative --proof and
    // the absolute --output name the same file.
    cmd.arg("--proof").arg("same.proof").arg("--output").arg(&proof_path);
    cmd.assert().failure().stderr(predicate::str::contains("overwrite"));

    assert_proof_survived(&proof_path);
}

#[cfg(unix)]
#[test]
fn prove_keeps_the_proof_when_an_explicit_output_is_reached_through_a_symlinked_proof_path() {
    let (working_dir, mut cmd) = prove_command();
    let proof_path = working_dir.path().join("same.proof");
    std::os::unix::fs::symlink(&proof_path, working_dir.path().join("alias.proof")).unwrap();

    cmd.arg("--proof").arg("alias.proof").arg("--output").arg(&proof_path);
    cmd.assert().failure().stderr(predicate::str::contains("overwrite"));

    assert_proof_survived(&proof_path);
}

#[cfg(unix)]
#[test]
fn prove_keeps_the_proof_when_the_default_output_is_a_symlink_to_it() {
    let (working_dir, mut cmd) = prove_command();
    let proof_path = working_dir.path().join("custom.proof");
    let output_path = working_dir.path().join("custom.outputs");
    // The link dangles until the proof is written, which is what the check has to survive.
    std::os::unix::fs::symlink("custom.proof", &output_path).unwrap();

    cmd.arg("--proof").arg(&proof_path);
    cmd.assert().failure().stderr(predicate::str::contains("overwrite"));

    assert_proof_survived(&proof_path);
    assert!(output_path.is_symlink(), "the alias should be left untouched");
}

#[cfg(unix)]
#[test]
fn prove_keeps_the_proof_when_an_explicit_output_crosses_a_symlink_with_dot_dot() {
    let (working_dir, mut cmd) = prove_command();
    let real_dir = working_dir.path().join("real");
    fs::create_dir(&real_dir).unwrap();
    fs::create_dir(real_dir.join("sub")).unwrap();
    std::os::unix::fs::symlink(real_dir.join("sub"), working_dir.path().join("alias")).unwrap();

    let proof_path = real_dir.join("same.proof");
    let output_path = working_dir.path().join("alias/../same.proof");

    cmd.arg("--proof").arg(&proof_path).arg("--output").arg(&output_path);
    cmd.assert().failure().stderr(predicate::str::contains("overwrite"));

    assert_proof_survived(&proof_path);
}

#[test]
fn prove_keeps_the_proof_when_the_default_output_is_a_hard_link_to_it() {
    let (working_dir, mut cmd) = prove_command();
    let proof_path = working_dir.path().join("custom.proof");
    let output_path = working_dir.path().join("custom.outputs");
    // A hard link needs an existing target, so start from a stale proof. The new proof is written
    // over it in place, which keeps both names on the one file.
    fs::write(&proof_path, "stale proof").unwrap();
    fs::hard_link(&proof_path, &output_path).unwrap();

    cmd.arg("--proof").arg(&proof_path);
    cmd.assert().failure().stderr(predicate::str::contains("overwrite"));

    assert_proof_survived(&proof_path);
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
