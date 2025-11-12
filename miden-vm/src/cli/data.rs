use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

use miden_assembly::{
    Assembler, DefaultSourceManager, Library, Path as LibraryPath, SourceManager,
    ast::{Module, ModuleKind},
    diagnostics::{Report, WrapErr},
    report,
    utils::Deserializable,
};
use miden_stdlib::StdLibrary;
use miden_vm::{ExecutionProof, Program, StackOutputs, Word, utils::SliceReader};
use serde::{Deserialize, Serialize};
use tracing::instrument;

// HELPERS
// ================================================================================================

/// Indicates whether debug mode is on or off.
pub enum Debug {
    On,
    Off,
}

impl Debug {
    /// Returns true if debug mode is on.
    fn is_on(&self) -> bool {
        matches!(self, Self::On)
    }
}

impl From<bool> for Debug {
    fn from(value: bool) -> Self {
        match value {
            true => Debug::On,
            false => Debug::Off,
        }
    }
}

// OUTPUT FILE
// ================================================================================================

/// Output file struct
#[derive(Deserialize, Serialize, Debug)]
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
        let stack = self
            .stack
            .iter()
            .map(|v| v.parse::<u64>())
            .collect::<Result<Vec<u64>, _>>()
            .map_err(|err| format!("Failed to parse stack output as u64 - {err}"))?;

        StackOutputs::try_from_ints(stack)
            .map_err(|e| format!("Construct stack outputs failed {e}"))
    }
}

// PROGRAM FILE
// ================================================================================================

pub struct ProgramFile<S: SourceManager = DefaultSourceManager> {
    ast: Box<Module>,
    source_manager: Arc<S>,
}

impl ProgramFile {
    /// Reads the masm file at the specified path and parses it into a [ProgramFile].
    pub fn read(path: impl AsRef<Path>) -> Result<Self, Report> {
        let source_manager = Arc::new(miden_assembly::DefaultSourceManager::default());
        Self::read_with(path, source_manager)
    }
}

/// Helper methods to interact with masm program file.
impl<S> ProgramFile<S>
where
    S: SourceManager + 'static,
{
    /// Reads the masm file at the specified path and parses it into a [ProgramFile], using the
    /// provided [miden_assembly::SourceManager] implementation.
    #[instrument(name = "read_program_file", skip(source_manager), fields(path = %path.as_ref().display()))]
    pub fn read_with(path: impl AsRef<Path>, source_manager: Arc<S>) -> Result<Self, Report> {
        // parse the program into an AST
        let path = path.as_ref();
        let mut parser = Module::parser(ModuleKind::Executable);
        let ast = parser
            .parse_file(LibraryPath::exec_path(), path, &source_manager)
            .wrap_err_with(|| format!("Failed to parse program file `{}`", path.display()))?;

        Ok(Self { ast, source_manager })
    }

    /// Compiles this program file into a [Program].
    #[instrument(name = "compile_program", skip_all)]
    pub fn compile<'a, I>(&self, debug: Debug, libraries: I) -> Result<Program, Report>
    where
        I: IntoIterator<Item = &'a Library>,
    {
        // compile program
        let mut assembler =
            Assembler::new(self.source_manager.clone()).with_debug_mode(debug.is_on());
        assembler
            .link_dynamic_library(StdLibrary::default())
            .wrap_err("Failed to load stdlib")?;

        for library in libraries {
            assembler.link_dynamic_library(library).wrap_err("Failed to load libraries")?;
        }

        let program: Program = assembler
            .assemble_program(self.ast.as_ref())
            .wrap_err("Failed to compile program")?;

        Ok(program)
    }

    /// Returns the source manager for this program file.
    pub fn source_manager(&self) -> &Arc<S> {
        &self.source_manager
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

        // deserialize bytes into a stark proof
        ExecutionProof::from_bytes(&file)
            .map_err(|err| format!("Failed to decode proof data - {err}"))
    }

    /// Write stark proof to file
    #[instrument(name = "write_data_to_proof_file",
                 fields(
                    path = %proof_path.clone().unwrap_or(program_path.with_extension("proof")).display(),
                    size = format!("{} KB", proof.to_bytes().len() / 1024)), skip_all)]
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

        // create output fille
        let mut file = fs::File::create(&path)
            .map_err(|err| format!("Failed to create proof file `{}` - {}", path.display(), err))?;

        let proof_bytes = proof.to_bytes();

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
    pub libraries: Vec<Library>,
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

            let library = Library::deserialize_from_file(path).map_err(|err| {
                report!("Failed to read library from file `{}`: {}", path_str, err)
            })?;

            libraries.push(library);
        }

        Ok(Self { libraries })
    }
}

// TESTS
// ================================================================================================
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_debug_from_true() {
        let debug_mode: Debug = true.into(); // true.into() will also test Debug.from(true)
        assert!(matches!(debug_mode, Debug::On));
    }

    #[test]
    fn test_debug_from_false() {
        let debug_mode: Debug = false.into(); // false.into() will also test Debug.from(false)
        assert!(matches!(debug_mode, Debug::Off));
    }
}
