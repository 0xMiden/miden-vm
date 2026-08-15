use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use miden_assembly::{
    Assembler, Path as LibraryPath, SourceMap,
    ast::{Module, ModuleKind},
    diagnostics::{Report, SourceNamespace, WrapErr},
    serde::Deserializable,
};
use miden_core::{Felt, field::QuotientMap};
use miden_core_lib::CoreLibrary;
use miden_mast_package::Package;
use miden_vm::{
    ExecutionProof, Program, StackOutputs, Word,
    diagnostics::{DiagnosticCollector, Outcome},
    serde::SliceReader,
};
use serde::{Deserialize, Serialize};
use tracing::{field::Empty, instrument};

// HELPERS
// ================================================================================================

// OUTPUT FILE
// ================================================================================================

/// Output file struct
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct OutputFile {
    pub stack: Vec<String>,
}

/// Helper methods to interact with the output file
impl OutputFile {
    /// Returns a new [OutputFile] from the specified outputs vectors
    pub fn new(stack_outputs: &StackOutputs) -> Self {
        Self {
            stack: stack_outputs.iter().map(|&v| v.to_string()).collect::<Vec<String>>(),
        }
    }

    /// Read the output file
    #[instrument(name = "read_output_file",
        fields(path = %outputs_path.clone().unwrap_or(program_path.with_extension("outputs")).display()), skip_all)]
    pub fn read(outputs_path: &Option<PathBuf>, program_path: &Path) -> Result<Self, String> {
        // If outputs_path has been provided then use this as path.  Alternatively we will
        // replace the program_path extension with `.outputs` and use this as a default.
        let path = match outputs_path {
            Some(path) => path.clone(),
            None => program_path.with_extension("outputs"),
        };

        // read outputs file to string
        let outputs_file = fs::read_to_string(&path)
            .map_err(|err| format!("Failed to open outputs file `{}` - {}", path.display(), err))?;

        // deserialize outputs data
        let outputs: OutputFile = serde_json::from_str(&outputs_file)
            .map_err(|err| format!("Failed to deserialize outputs data - {err}"))?;

        Ok(outputs)
    }

    /// Write the output file
    #[instrument(name = "write_data_to_output_file", fields(path = %path.display()), skip_all)]
    pub fn write(stack_outputs: &StackOutputs, path: &PathBuf) -> Result<(), String> {
        // if path provided, create output file
        let file = fs::File::create(path).map_err(|err| {
            format!("Failed to create output file `{}` - {}", path.display(), err)
        })?;

        // write outputs to output file
        serde_json::to_writer_pretty(file, &Self::new(stack_outputs))
            .map_err(|err| format!("Failed to write output data - {err}"))
    }

    /// Converts stack output vector to [StackOutputs].
    pub fn stack_outputs(&self) -> Result<StackOutputs, String> {
        let stack: Vec<Felt> = self
            .stack
            .iter()
            .map(|v| {
                let value = v.parse::<u64>().map_err(|e| e.to_string())?;
                Felt::from_canonical_checked(value)
                    .ok_or_else(|| format!("failed to convert stack input value '{v}' to Felt"))
            })
            .collect::<Result<_, _>>()
            .map_err(|err| format!("Failed to parse stack output as u64 - {err}"))?;

        StackOutputs::new(&stack).map_err(|e| format!("Construct stack outputs failed {e}"))
    }
}

// PROGRAM FILE
// ================================================================================================

pub struct ProgramFile {
    ast: Box<Module>,
    sources: SourceMap,
}

impl ProgramFile {
    /// Reads the masm file at the specified path and parses it into a [ProgramFile].
    pub fn read(path: impl AsRef<Path>) -> Outcome<Self> {
        let namespace = SourceNamespace::fresh()
            .expect("failed to allocate a source namespace for the program file");
        Self::read_with(path, SourceMap::new(namespace))
    }

    /// Reads the MASM file using an existing source session.
    #[instrument(name = "read_program_file", skip(sources), fields(path = %path.as_ref().display()))]
    pub fn read_with(path: impl AsRef<Path>, mut sources: SourceMap) -> Outcome<Self> {
        // parse the program into an AST
        let path = path.as_ref();
        let mut parser = Module::parser(Some(ModuleKind::Executable));
        let Outcome { result, diagnostics } =
            parser.parse_file(Some(LibraryPath::exec_path()), path, &mut sources);
        let diagnostics = diagnostics.attach_session_sources(Arc::new(sources.clone()));
        let result = result.map(|ast| Self { ast, sources });

        Outcome { result, diagnostics }
    }

    /// Compiles this program file into an executable [Package].
    #[instrument(name = "compile_package", skip_all)]
    pub fn compile_package<I>(&self, libraries: I) -> Outcome<Box<Package>>
    where
        I: IntoIterator<Item = Arc<Package>>,
    {
        let mut diagnostics = DiagnosticCollector::default();
        let mut assembler = Assembler::with_sources(self.sources.clone());
        let mut linked = diagnostics
            .capture(
                assembler
                    .link_package(
                        CoreLibrary::default().package(),
                        miden_assembly::Linkage::Dynamic,
                    )
                    .wrap_err("Failed to load core library"),
            )
            .is_some();

        for library in libraries {
            linked &= diagnostics
                .capture(
                    assembler
                        .link_package(library, miden_assembly::Linkage::Dynamic)
                        .wrap_err("Failed to load libraries"),
                )
                .is_some();
        }

        let result = if linked {
            let Outcome { result, diagnostics: program_diags } =
                assembler.assemble_program("program", self.ast.clone());

            diagnostics.merge(program_diags);

            result
        } else {
            Err(())
        };

        Outcome {
            result,
            diagnostics: diagnostics.finish(),
        }
    }

    /// Compiles this program file into a [Program].
    #[instrument(name = "compile_program", skip_all)]
    pub fn compile<I>(&self, libraries: I) -> Outcome<Program>
    where
        I: IntoIterator<Item = Arc<Package>>,
    {
        self.compile_package(libraries).map(|pkg| pkg.unwrap_program())
    }

    /// Returns the source session for this program file.
    pub fn sources(&self) -> &SourceMap {
        &self.sources
    }

    /// Returns a reference to the AST module.
    pub fn ast(&self) -> &Module {
        &self.ast
    }
}

// PROOF FILE
// ================================================================================================

pub struct ProofFile;

/// Helper methods to interact with proof file
impl ProofFile {
    /// Read stark proof from file
    #[instrument(name = "read_proof_file",
        fields(path = %proof_path.clone().unwrap_or(program_path.with_extension("proof")).display()), skip_all)]
    pub fn read(
        proof_path: &Option<PathBuf>,
        program_path: &Path,
    ) -> Result<ExecutionProof, String> {
        // If proof_path has been provided then use this as path.  Alternatively we will
        // replace the program_path extension with `.proof` and use this as a default.
        let path = match proof_path {
            Some(path) => path.clone(),
            None => program_path.with_extension("proof"),
        };

        // read the file to bytes
        let file = fs::read(&path)
            .map_err(|err| format!("Failed to open proof file `{}` - {}", path.display(), err))?;

        // deserialize bytes into an execution proof
        ExecutionProof::read_from_bytes(&file)
            .map_err(|err| format!("Failed to decode proof data - {err}"))
    }

    /// Write stark proof to file
    #[instrument(name = "write_data_to_proof_file",
                 fields(
                    path = %proof_path.clone().unwrap_or(program_path.with_extension("proof")).display(),
                    size = Empty), skip_all)]
    pub fn write(
        proof: ExecutionProof,
        proof_path: &Option<PathBuf>,
        program_path: &Path,
    ) -> Result<(), String> {
        // If proof_path has been provided then use this as path.  Alternatively we will
        // replace the program_path extension with `.proof` and use this as a default.
        let path = match proof_path {
            Some(path) => path.clone(),
            None => program_path.with_extension("proof"),
        };

        let proof_bytes = proof.to_bytes();
        tracing::Span::current()
            .record("size", tracing::field::display(format!("{} KB", proof_bytes.len() / 1024)));

        // create output file
        let mut file = fs::File::create(&path)
            .map_err(|err| format!("Failed to create proof file `{}` - {}", path.display(), err))?;

        // write proof bytes to file
        file.write_all(&proof_bytes)
            .map_err(|err| format!("Failed to write proof file `{}` - {}", path.display(), err))?;

        Ok(())
    }
}

// PROGRAM HASH
// ================================================================================================

pub struct ProgramHash;

/// Helper method to parse program hash from hex
impl ProgramHash {
    #[instrument(name = "read_program_hash", skip_all)]
    pub fn read(hash_hex_string: &str) -> Result<Word, String> {
        // decode hex to bytes
        let program_hash_bytes = hex::decode(hash_hex_string)
            .map_err(|err| format!("Failed to convert program hash to bytes {err}"))?;

        // create slice reader from bytes
        let mut program_hash_slice = SliceReader::new(&program_hash_bytes);

        // create hash digest from slice
        let program_hash = Word::read_from(&mut program_hash_slice)
            .map_err(|err| format!("Failed to deserialize program hash from bytes - {err}"))?;

        Ok(program_hash)
    }
}

// LIBRARY FILE
// ================================================================================================
pub struct Libraries {
    pub libraries: Vec<Arc<Package>>,
}

impl Libraries {
    /// Creates a new instance of [Libraries] from a list of library paths.
    #[instrument(name = "read_library_files", skip_all)]
    pub fn new<P, I>(paths: I) -> Result<Self, Report>
    where
        P: AsRef<Path>,
        I: IntoIterator<Item = P>,
    {
        let mut libraries = Vec::new();

        for path in paths {
            let path_str = path.as_ref().to_string_lossy().into_owned();

            let library = Package::deserialize_from_file(path).map(Arc::new).map_err(|err| {
                Report::msg(format!("Failed to read package from file `{path_str}`: {err}"))
            })?;

            libraries.push(library);
        }

        Ok(Self { libraries })
    }
}
