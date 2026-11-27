use std::{
    fs, io,
    path::{Path, PathBuf},
    time::Instant,
};

use clap::Parser;
use miden_assembly::diagnostics::{IntoDiagnostic, Report, WrapErr};
use miden_core_lib::CoreLibrary;
use miden_processor::{DefaultHost, PackageSourceDebugContext};
use miden_vm::{PrecompileStatus, Processor, WitnessOutput, internal::InputFile};

use super::{
    ProofMode,
    config::Settings,
    data::{Libraries, OutputFile, ProofFile},
    utils::{
        get_masm_program, get_masp_package, load_package_with_handlers,
        load_program_package_with_handlers,
    },
};

#[derive(Debug, Clone, Parser)]
pub struct ProveCmd {
    /// Path to a .masm assembly file or a .masp package file
    #[arg(value_parser)]
    program_file: PathBuf,

    /// Path to input file
    #[arg(short = 'i', long = "input", value_parser)]
    input_file: Option<PathBuf>,

    /// Paths to .masp library files
    #[arg(short = 'l', long = "libraries", value_parser)]
    library_paths: Vec<PathBuf>,

    /// Path to output file
    #[arg(short = 'o', long = "output", value_parser)]
    output_file: Option<PathBuf>,

    /// Path to proof file
    #[arg(short = 'p', long = "proof", value_parser)]
    proof_file: Option<PathBuf>,

    /// Path to a file (.masm or .masp) containing the kernel to be loaded with the program
    #[arg(long = "kernel", value_parser)]
    kernel_file: Option<PathBuf>,
}

impl ProveCmd {
    pub(crate) fn execute(&self, settings: &Settings, mode: ProofMode) -> Result<(), Report> {
        println!("===============================================================================");
        println!("Prove program: {}", self.program_file.display());
        println!("-------------------------------------------------------------------------------");

        // determine file type based on extension
        let ext = self
            .program_file
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        if !matches!(ext.as_str(), "masm" | "masp") {
            return Err(Report::msg("The provided file must have a .masm or .masp extension"));
        }

        // load libraries from files
        let libraries = Libraries::new(&self.library_paths)?;

        // validate kernel file if provided
        if let Some(ref kernel_path) = self.kernel_file
            && !kernel_path.is_file()
        {
            return Err(Report::msg(format!(
                "Kernel file `{}` must be a file.",
                kernel_path.display()
            )));
        }

        let input_data = InputFile::read(&self.input_file, &self.program_file)?;

        let mut host = DefaultHost::default().with_library(&CoreLibrary::default())?;
        // Use a single match expression to load the program.
        let (program, package_debug_info, entrypoint_source_node) = match ext.as_str() {
            "masp" => {
                if self.kernel_file.is_some() {
                    return Err(Report::msg(
                        "The `--kernel` option does not apply to a `.masp` package: the package fixes its own kernel.",
                    ));
                }
                let package = get_masp_package(&self.program_file)?;
                let program = package.try_into_program()?;
                load_program_package_with_handlers(&mut host, &package, &mut Vec::new())?;
                (program, None, None)
            },
            "masm" => {
                let (
                    program,
                    package_debug_info,
                    entrypoint_source_node,
                    source_manager,
                    kernel_package,
                ) = get_masm_program(&self.program_file, &libraries, self.kernel_file.as_deref())?;
                host = host.with_source_manager(source_manager);
                let mut loaded_handler_sections = Vec::new();
                for library in &libraries.libraries {
                    load_package_with_handlers(&mut host, library, &mut loaded_handler_sections)?;
                }
                if let Some(kernel_package) = &kernel_package {
                    load_package_with_handlers(
                        &mut host,
                        kernel_package,
                        &mut loaded_handler_sections,
                    )?;
                }
                (program, package_debug_info, entrypoint_source_node)
            },
            _ => unreachable!("program file extension was validated above"),
        };

        let program_hash: [u8; 32] = program.hash().into();
        println!("Proving program with hash {}...", hex::encode(program_hash));
        let now = Instant::now();

        // fetch the stack and program inputs from the arguments
        let stack_inputs = input_data.parse_stack_inputs().map_err(Report::msg)?;
        let advice_inputs = input_data
            .parse_advice_inputs_with_options(&settings.execution)
            .map_err(Report::msg)?;

        let source = package_debug_info
            .as_ref()
            .map(|info| PackageSourceDebugContext::new_optional(info, entrypoint_source_node));
        let WitnessOutput { claim, witness, .. } = Processor::new(&program)
            .with_options(settings.execution.clone())
            .with_stack_inputs(stack_inputs)
            .with_advice(advice_inputs)
            .with_source_context(source)
            .record_witness()
            .run_sync(&mut host)
            .wrap_err("Failed to execute program")?;
        let stack_outputs = *claim.stack_outputs();
        let proof = match mode {
            ProofMode::Deferred => settings.prover.prove(witness),
            ProofMode::Complete => settings.prover.prove_full(witness).map(Into::into),
        }
        .into_diagnostic()
        .wrap_err("Failed to prove program")?;

        println!("Program proved in {} ms", now.elapsed().as_millis());
        if matches!(proof.precompile(), PrecompileStatus::Deferred(_)) {
            println!("Proof status: deferred");
            println!("Precompile witness: exported; may reveal private advice inputs");
            println!("Precompile STARK: not supplied");
            println!("Outstanding precompile root: {}", proof.vm().precompile_root);
        } else {
            println!("Proof status: complete");
        }

        // write proof to file
        ProofFile::write(proof, &self.proof_file, &self.program_file).map_err(Report::msg)?;

        // Whether the outputs path names the proof is a question only the filesystem can answer,
        // and only now that the proof exists: comparing file identity sees through symlinks, `..`
        // components, case-insensitive names, Unicode normalization and hard links in one step.
        let proof_path = self.resolved_proof_path();
        let output_path = self.output_file.clone().unwrap_or_else(|| self.default_output_path());
        let collides = resolve_to_same_file(&output_path, &proof_path).map_err(|err| {
            Report::msg(format!(
                "Could not tell whether the outputs file `{}` is the proof file `{}`: {err}. The \
                 proof was kept; re-run with a different --proof or --output path to get the \
                 outputs.",
                output_path.display(),
                proof_path.display()
            ))
        })?;
        if collides {
            return Err(Report::msg(format!(
                "The outputs file `{}` would overwrite the proof file `{}`. The proof was kept; \
                 re-run with a different --proof or --output path to get the outputs.",
                output_path.display(),
                proof_path.display()
            )));
        }

        OutputFile::write(&stack_outputs, &output_path).map_err(Report::msg)?;

        // without --output the outputs file is not where the user is looking, so print the stack
        if self.output_file.is_none() {
            let stack = stack_outputs.get_num_elements(settings.num_outputs).to_vec();
            println!("Output: {stack:?}");
        }

        Ok(())
    }

    /// Resolves the proof path the same way as ProofFile::write.
    fn resolved_proof_path(&self) -> PathBuf {
        ProofFile::resolve_path(&self.proof_file, &self.program_file)
    }

    /// Derives verify's default outputs path from the resolved proof path.
    fn default_output_path(&self) -> PathBuf {
        self.resolved_proof_path().with_extension("outputs")
    }
}

/// Returns true when writing outputs would replace the proof file.
///
/// This runs after the proof has been written, so the proof side always exists. An outputs path
/// that does not exist yet cannot be the proof, and neither can a FIFO or device. Identity is
/// taken from each path's metadata, so neither file is opened: opening a FIFO blocks until a
/// writer appears, and opening for reading fails on a write-only file that is still a valid
/// destination. A final output symlink is replaced atomically without touching its target.
/// Other metadata errors leave the question unanswered and are returned.
fn resolve_to_same_file(output_path: &Path, proof_path: &Path) -> io::Result<bool> {
    let output_metadata = match fs::symlink_metadata(output_path) {
        Ok(metadata) if metadata.is_symlink() => return Ok(false),
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };
    let proof_metadata = fs::metadata(proof_path)?;
    if !output_metadata.is_file() || !proof_metadata.is_file() {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        Ok(output_metadata.dev() == proof_metadata.dev()
            && output_metadata.ino() == proof_metadata.ino())
    }
    // `is_same_file` opens with no access rights on Windows, so permissions do not get in the way.
    #[cfg(not(unix))]
    {
        same_file::is_same_file(output_path, proof_path)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, sync::Arc};

    use miden_core::deferred::{DeferredState, Node, PrecompileRegistry, TRUE_DIGEST};
    use miden_vm::{PrecompileLimits, Prover, ProverError, default_verification_precompile_limits};

    use super::*;

    fn prove_cmd(program_file: &str, proof_file: Option<&str>) -> ProveCmd {
        let mut command = ProveCmd::try_parse_from(["prove", program_file]).unwrap();
        command.proof_file = proof_file.map(PathBuf::from);
        command
    }

    #[test]
    fn default_output_path_follows_the_program_when_no_proof_is_given() {
        assert_eq!(
            prove_cmd("dir/program.masm", None).default_output_path(),
            PathBuf::from("dir/program.outputs")
        );
    }

    #[test]
    fn default_output_path_follows_a_custom_proof_path() {
        assert_eq!(
            prove_cmd("dir/program.masm", Some("out/custom.proof")).default_output_path(),
            PathBuf::from("out/custom.outputs")
        );
    }

    #[test]
    fn default_output_path_handles_an_extensionless_proof_path() {
        assert_eq!(
            prove_cmd("dir/program.masm", Some("out/custom")).default_output_path(),
            PathBuf::from("out/custom.outputs")
        );
    }

    #[test]
    fn default_output_path_collides_with_a_proof_path_that_is_already_an_outputs_path() {
        assert_eq!(
            prove_cmd("dir/program.masm", Some("out/custom.outputs")).default_output_path(),
            PathBuf::from("out/custom.outputs")
        );
    }

    #[test]
    fn resolve_to_same_file_distinguishes_final_and_parent_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let proof_path = dir.path().join("same.proof");
        fs::write(&proof_path, "proof").unwrap();

        #[cfg(unix)]
        {
            let alias_path = dir.path().join("alias.proof");
            std::os::unix::fs::symlink(&proof_path, &alias_path).unwrap();
            assert!(!resolve_to_same_file(&alias_path, &proof_path).unwrap());

            let parent_alias = dir.path().join("parent");
            std::os::unix::fs::symlink(dir.path(), &parent_alias).unwrap();
            assert!(resolve_to_same_file(&parent_alias.join("same.proof"), &proof_path).unwrap());
        }

        // negative control: with `sub` missing there is nothing to resolve `..` against
        assert!(
            !resolve_to_same_file(&dir.path().join("./sub/../same.proof"), &proof_path).unwrap()
        );

        fs::create_dir(dir.path().join("sub")).unwrap();
        assert!(
            resolve_to_same_file(&dir.path().join("./sub/../same.proof"), &proof_path).unwrap()
        );
    }

    #[test]
    fn resolve_to_same_file_sees_through_a_hard_link() {
        let dir = tempfile::tempdir().unwrap();
        let proof_path = dir.path().join("same.proof");
        fs::write(&proof_path, "proof").unwrap();

        // negative control: a copy has the same contents but is a different file
        let copy_path = dir.path().join("copy.proof");
        fs::copy(&proof_path, &copy_path).unwrap();
        assert!(!resolve_to_same_file(&copy_path, &proof_path).unwrap());

        let link_path = dir.path().join("link.proof");
        fs::hard_link(&proof_path, &link_path).unwrap();
        assert!(resolve_to_same_file(&link_path, &proof_path).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn resolve_to_same_file_sees_through_a_hard_link_it_cannot_read() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let proof_path = dir.path().join("same.proof");
        fs::write(&proof_path, "proof").unwrap();
        let link_path = dir.path().join("link.proof");
        fs::hard_link(&proof_path, &link_path).unwrap();
        fs::set_permissions(&proof_path, fs::Permissions::from_mode(0o200)).unwrap();

        assert!(resolve_to_same_file(&link_path, &proof_path).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn resolve_to_same_file_accepts_a_distinct_file_it_cannot_read() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let proof_path = dir.path().join("same.proof");
        fs::write(&proof_path, "proof").unwrap();
        let output_path = dir.path().join("same.outputs");
        fs::write(&output_path, "stale outputs").unwrap();
        fs::set_permissions(&output_path, fs::Permissions::from_mode(0o200)).unwrap();

        assert!(!resolve_to_same_file(&output_path, &proof_path).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn resolve_to_same_file_does_not_open_a_fifo() {
        let dir = tempfile::tempdir().unwrap();
        let proof_path = dir.path().join("same.proof");
        fs::write(&proof_path, "proof").unwrap();
        let fifo_path = dir.path().join("same.outputs");
        let status = std::process::Command::new("mkfifo").arg(&fifo_path).status().unwrap();
        assert!(status.success());

        // opening the FIFO would block this thread forever, so run the check where it can time out
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(resolve_to_same_file(&fifo_path, &proof_path).unwrap()));
        let same = rx.recv_timeout(std::time::Duration::from_secs(10)).expect("the check blocked");
        assert!(!same);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_to_same_file_distinguishes_final_and_parent_symlink_loops() {
        let dir = tempfile::tempdir().unwrap();
        let proof_path = dir.path().join("same.proof");
        fs::write(&proof_path, "proof").unwrap();

        let output_path = dir.path().join("same.outputs");
        std::os::unix::fs::symlink("same.outputs", &output_path).unwrap();
        assert!(!resolve_to_same_file(&output_path, &proof_path).unwrap());

        let parent_path = dir.path().join("parent");
        std::os::unix::fs::symlink("parent", &parent_path).unwrap();
        assert!(resolve_to_same_file(&parent_path.join("same.outputs"), &proof_path).is_err());
    }

    #[test]
    fn resolve_to_same_file_ignores_an_outputs_path_that_does_not_exist_yet() {
        let dir = tempfile::tempdir().unwrap();
        let proof_path = dir.path().join("same.proof");
        fs::write(&proof_path, "proof").unwrap();

        assert!(!resolve_to_same_file(&dir.path().join("same.outputs"), &proof_path).unwrap());
    }

    #[test]
    fn memory_budget_preserves_defaults_or_overrides_both_stages() {
        for (assignments, vm, precompile) in [
            (
                vec![],
                Prover::DEFAULT_MAX_PROVER_MEMORY_BYTES,
                Prover::DEFAULT_MAX_PRECOMPILE_PROVER_MEMORY_BYTES,
            ),
            (vec![String::from("resources.max-prover-memory=2Mi")], 2 << 20, 2 << 20),
        ] {
            let prover = Settings::from_overrides(&assignments).unwrap().prover;
            assert_eq!(prover.max_prover_memory_bytes(), vm);
            assert_eq!(prover.max_precompile_prover_memory_bytes(), precompile);
        }
    }

    #[test]
    fn prover_receives_verification_admission_and_memory_policies() {
        let mut state = DeferredState::new(
            Arc::new(PrecompileRegistry::new()),
            PrecompileLimits::new(u64::MAX),
        )
        .unwrap();
        let statement = state.register(Node::and(TRUE_DIGEST, TRUE_DIGEST)).unwrap();
        state.log_statement(statement).unwrap();
        let witness =
            state.into_witness(&default_verification_precompile_limits()).unwrap().unwrap();
        for (assignment, cause) in [
            ("resources.max-prover-memory=1", "MemoryBudgetExceeded"),
            ("verification.precompiles.max-elements=0", "Preparation"),
        ] {
            let prover = Settings::from_overrides(&[String::from(assignment)]).unwrap().prover;
            let error = prover.prove_precompiles(vec![witness.clone()]).unwrap_err();
            assert!(matches!(error, ProverError::PrecompileProofGeneration(_)));
            let message = format!("{error:?}");
            assert!(message.contains(cause), "{message}");
        }
    }
}
