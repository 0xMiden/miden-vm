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
