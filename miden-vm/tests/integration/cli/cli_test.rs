use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

use assert_cmd::prelude::*;
use miden_assembly::{Assembler, DefaultSourceManager};
use miden_mast_package::Package;
use miden_wasm_event_handlers::{
    WasmHandlerLimits, section_from_module, test_append_manifest_section,
};
use predicates::prelude::*;
use tempfile::TempDir;

pub(super) fn bin_under_test(working_dir: &Path) -> Command {
    let binary = env::var("NEXTEST_BIN_EXE_miden-vm")
        .ok()
        .or_else(|| option_env!("CARGO_BIN_EXE_miden-vm").map(str::to_owned))
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
    Assembler::default()
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
fn cli_advice_budget_is_configurable_for_run_and_prove() {
    let working_dir = TempDir::new().unwrap();
    let program_path = working_dir.path().join("advice-budget.masm");
    fs::write(&program_path, "begin push.1 end").unwrap();
    fs::write(program_path.with_extension("inputs"), r#"{"operand_stack":[]}"#).unwrap();

    for command in ["run", "prove"] {
        let mut cmd = bin_under_test(working_dir.path());
        cmd.arg(command).arg(&program_path).args(["--max-advice-size", "0"]);
        cmd.assert()
            .failure()
            .stderr(predicate::str::contains("advice provider size budget"));
    }
}

#[test]
// The exact row counts and elapsed time can change, so this checks only the stable labels printed
// by the `run` command.
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

    output
        .assert()
        .stdout(predicate::str::contains("Executed the program with hash"))
        .stdout(predicate::str::contains("VM trace rows:"))
        .stdout(predicate::str::contains("Core rows:"))
        .stdout(predicate::str::contains("Byte-pair lookup rows:"));
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
fn prove_keeps_the_proof_when_atomic_write_separates_a_symlink_alias() {
    let (working_dir, mut cmd) = prove_command();
    let output_path = working_dir.path().join("same.proof");
    let proof_path = working_dir.path().join("alias.proof");
    std::os::unix::fs::symlink(&output_path, &proof_path).unwrap();

    cmd.arg("--proof").arg(&proof_path).arg("--output").arg(&output_path);
    cmd.assert().success();

    assert_proof_survived(&proof_path);
    assert!(!proof_path.is_symlink(), "the proof replaces the symlink atomically");
    assert!(fs::read_to_string(&output_path).unwrap().contains("\"stack\""));
}

#[cfg(unix)]
#[test]
fn prove_keeps_the_proof_when_atomic_write_replaces_an_output_symlink_to_it() {
    let (working_dir, mut cmd) = prove_command();
    let proof_path = working_dir.path().join("custom.proof");
    let output_path = working_dir.path().join("custom.outputs");
    // The link dangles until the proof is written, which is what the check has to survive.
    std::os::unix::fs::symlink("custom.proof", &output_path).unwrap();

    cmd.arg("--proof").arg(&proof_path);
    cmd.assert().success();

    assert_proof_survived(&proof_path);
    assert!(!output_path.is_symlink());
    assert!(fs::read_to_string(&output_path).unwrap().contains("\"stack\""));
}

#[cfg(unix)]
#[test]
fn prove_replaces_an_unresolvable_output_symlink_without_losing_the_proof() {
    let (working_dir, mut cmd) = prove_command();
    let proof_path = working_dir.path().join("custom.proof");
    let output_path = working_dir.path().join("custom.outputs");
    std::os::unix::fs::symlink("custom.outputs", &output_path).unwrap();

    cmd.arg("--proof").arg(&proof_path);
    cmd.assert().success();

    assert_proof_survived(&proof_path);
    assert!(!output_path.is_symlink());
    assert!(fs::read_to_string(&output_path).unwrap().contains("\"stack\""));
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
fn prove_keeps_the_proof_when_atomic_write_separates_a_hard_link() {
    let (working_dir, mut cmd) = prove_command();
    let proof_path = working_dir.path().join("custom.proof");
    let output_path = working_dir.path().join("custom.outputs");
    // Replacing the proof atomically leaves the outputs name on the stale inode.
    fs::write(&proof_path, "stale proof").unwrap();
    fs::hard_link(&proof_path, &output_path).unwrap();

    cmd.arg("--proof").arg(&proof_path);
    cmd.assert().success();

    assert_proof_survived(&proof_path);
    assert!(fs::read_to_string(&output_path).unwrap().contains("\"stack\""));
}

#[cfg(unix)]
#[test]
fn prove_keeps_a_write_only_proof_when_atomic_write_separates_a_hard_link() {
    use std::os::unix::fs::PermissionsExt;

    let (working_dir, mut cmd) = prove_command();
    let proof_path = working_dir.path().join("custom.proof");
    let output_path = working_dir.path().join("custom.outputs");
    fs::write(&proof_path, "stale proof").unwrap();
    fs::hard_link(&proof_path, &output_path).unwrap();
    fs::set_permissions(&proof_path, fs::Permissions::from_mode(0o200)).unwrap();

    cmd.arg("--proof").arg(&proof_path);
    cmd.assert().success();

    fs::set_permissions(&proof_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_proof_survived(&proof_path);
    assert!(fs::read_to_string(&output_path).unwrap().contains("\"stack\""));
}

#[cfg(unix)]
#[test]
fn prove_writes_outputs_into_a_distinct_write_only_file() {
    use std::os::unix::fs::PermissionsExt;

    let (working_dir, mut cmd) = prove_command();
    let proof_path = working_dir.path().join("custom.proof");
    let output_path = working_dir.path().join("custom.outputs");
    fs::write(&output_path, "stale outputs").unwrap();
    fs::set_permissions(&output_path, fs::Permissions::from_mode(0o200)).unwrap();

    cmd.arg("--proof").arg(&proof_path).arg("--output").arg(&output_path);
    cmd.assert().success();

    fs::set_permissions(&output_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(fs::read_to_string(&output_path).unwrap().contains("\"stack\""));
    assert_proof_survived(&proof_path);
}

#[cfg(unix)]
#[test]
fn prove_rejects_a_fifo_output_without_blocking_or_losing_the_proof() {
    let (working_dir, cmd) = prove_command();
    let proof_path = working_dir.path().join("custom.proof");
    let fifo_path = working_dir.path().join("custom.fifo");
    assert!(Command::new("mkfifo").arg(&fifo_path).status().unwrap().success());

    let mut cmd = assert_cmd::Command::from_std(cmd);
    cmd.arg("--proof").arg(&proof_path).arg("--output").arg(&fifo_path);
    cmd.timeout(std::time::Duration::from_secs(60))
        .assert()
        .failure()
        .stderr(predicate::str::contains("regular"));

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

/// Bundles the `kernel_main.masm` fixture into `<working_dir>/<name>` as a kernel package.
fn bundle_kernel_package(working_dir: &Path, name: &str) -> PathBuf {
    let output_file = working_dir.join(name);
    let mut cmd = bin_under_test(working_dir);
    cmd.arg("bundle")
        .arg(fixture("tests/integration/cli/data/kernel_main.masm"))
        .arg("--kernel")
        .arg("--output")
        .arg(&output_file);
    cmd.assert().success();
    output_file
}

#[test]
fn run_rejects_kernel_for_masp_package() {
    let working_dir = TempDir::new().unwrap();
    let package_path = bundle_kernel_package(working_dir.path(), "prog.masp");

    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("run")
        .arg(&package_path)
        .arg("--kernel")
        .arg(fixture("tests/integration/cli/data/kernel_main.masm"));
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("does not apply to a `.masp` package"));
}

#[test]
fn prove_rejects_kernel_for_masp_package() {
    let working_dir = TempDir::new().unwrap();
    let package_path = bundle_kernel_package(working_dir.path(), "prog.masp");
    // `prove` reads the inferred inputs file before it looks at the program kind.
    fs::write(working_dir.path().join("prog.inputs"), r#"{"operand_stack":[]}"#).unwrap();

    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("prove")
        .arg(&package_path)
        .arg("--kernel")
        .arg(fixture("tests/integration/cli/data/kernel_main.masm"));
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("does not apply to a `.masp` package"));
}

/// A `.masp` kernel is registered with the host, so its procedures are reachable from a `syscall`.
#[test]
fn run_masm_program_honors_a_masp_kernel() {
    let working_dir = TempDir::new().unwrap();
    let kernel_path = bundle_kernel_package(working_dir.path(), "kernel.masp");

    let program_path = working_dir.path().join("program.masm");
    // `kernel_proc` runs `caller`, which requires a `call` frame under the `syscall`.
    fs::write(
        &program_path,
        "proc bar\n    syscall.kernel_proc\nend\n\nbegin\n    call.bar\nend\n",
    )
    .unwrap();
    fs::write(working_dir.path().join("program.inputs"), r#"{"operand_stack":[]}"#).unwrap();

    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("run")
        .arg(&program_path)
        .arg("--kernel")
        .arg(&kernel_path)
        .arg("-n")
        .arg("1");
    cmd.assert().success();
}

/// A handler module the loader accepts: it exports linear memory and a `() -> ()` handler.
const HANDLER_WAT: &str = r#"(module
  (memory (export "memory") 1)
  (func (export "handler")))"#;

/// A project attaches one handler section to every target it builds, so an executable and the
/// project kernel it embeds carry the identical section. The CLI must run such a package: it
/// registers the handlers once and takes only the MAST forest of the second package.
#[test]
fn run_loads_a_masp_whose_kernel_shares_the_handler_section() {
    let working_dir = TempDir::new().unwrap();

    // The section a project build would attach to both targets.
    let wasm = test_append_manifest_section(
        wat::parse_str(HANDLER_WAT).expect("the fixture WAT parses"),
        &[("test::cli::event", "handler")],
    );
    let section = section_from_module(wasm, WasmHandlerLimits::default())
        .expect("the handler module derives a section");

    // The kernel carries the section before it is embedded, so the executable's kernel dependency
    // commits to the kernel package the CLI later reads back.
    let source_manager = Arc::new(DefaultSourceManager::default());
    let kernel = Assembler::new(source_manager.clone())
        .assemble_kernel_from_root("kernel", fixture("tests/integration/cli/data/kernel_main.masm"))
        .expect("the kernel assembles");
    let kernel = Arc::new(
        kernel
            .with_event_handlers(&section)
            .expect("the kernel package takes the section"),
    );

    // Assembling against the kernel package embeds it and records the matching kernel dependency,
    // the way a project build does.
    let mut package = Assembler::with_kernel(source_manager, kernel)
        .expect("the assembler takes the kernel package")
        .assemble_program("program", "begin push.1 drop end")
        .expect("the program assembles");
    package
        .attach_event_handlers(&section)
        .expect("the executable package takes the section");

    let package_path = working_dir.path().join("prog.masp");
    package.write_to_file(&package_path).unwrap();
    fs::write(working_dir.path().join("prog.inputs"), r#"{"operand_stack":[]}"#).unwrap();

    // The run below exercises the handler deduplication only if the round-tripped package
    // still yields its embedded kernel — a digest-pairing break would surface as an error
    // there and skip the second handler load. Pin that precondition, so this test cannot
    // pass vacuously.
    let round_tripped = Package::deserialize_from_file(&package_path).unwrap();
    let embedded_kernel = round_tripped
        .try_embedded_kernel_package()
        .expect("the embedded kernel must decode with a matching dependency digest")
        .expect("the package must embed its kernel");
    assert_eq!(
        embedded_kernel.event_handlers().expect("the kernel section decodes"),
        Some(section),
        "the embedded kernel must carry the same handler section as the outer package",
    );

    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("run").arg(&package_path).arg("-n").arg("1");
    cmd.assert().success();
}

#[test]
fn test_advmap_cli() {
    let working_dir = TempDir::new().unwrap();
    let mut cmd = bin_under_test(working_dir.path());
    cmd.arg("run").arg(fixture("tests/integration/cli/data/adv_map.masm"));
    cmd.assert().success();
}
