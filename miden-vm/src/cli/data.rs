use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use miden_assembly::{
    Assembler, DefaultSourceManager, Path as LibraryPath, SourceManager,
    ast::{Module, ModuleKind},
    diagnostics::{Report, WrapErr},
    report,
    serde::Deserializable,
};
use miden_core::{Felt, field::QuotientMap, serde::read_file_bounded};
use miden_core_lib::CoreLibrary;
use miden_mast_package::Package;
use miden_vm::{ExecutionProof, Program, StackOutputs, Word, serde::SliceReader};
use serde::{Deserialize, Serialize};
use tracing::{field::Empty, instrument};

// HELPERS
// ================================================================================================

/// Writes and syncs a sibling temporary file before replacing the destination.
///
/// A write or file-sync failure leaves the destination intact. Persist errors drop the temporary
/// file along with the error wrapper. On Unix, the containing directory is synced after
/// replacement; an error at that stage reports that replacement has already committed.
fn write_file_atomically(
    path: &Path,
    write: impl FnOnce(&mut fs::File) -> io::Result<()>,
) -> io::Result<()> {
    write_file_atomically_with_sync(path, write, fs::File::sync_all, sync_directory)
}

fn write_file_atomically_with_sync(
    path: &Path,
    write: impl FnOnce(&mut fs::File) -> io::Result<()>,
    sync_file: impl FnOnce(&fs::File) -> io::Result<()>,
    sync_directory: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() && !metadata.is_symlink() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected a regular artifact file",
            ));
        },
        Ok(_) => (),
        Err(err) if err.kind() == io::ErrorKind::NotFound => (),
        Err(err) => return Err(err),
    }
    let builder = tempfile::Builder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::PermissionsExt;

        let mut builder = builder;
        // New files and replacements use ordinary creation permissions and umask.
        builder.permissions(fs::Permissions::from_mode(0o666));
        builder
    };
    let mut temporary = builder.tempfile_in(parent)?;
    write(temporary.as_file_mut())?;
    sync_file(temporary.as_file())?;
    temporary.persist(path).map_err(|err| err.error)?;
    sync_directory(parent).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "Artifact `{}` was replaced. Failed to sync destination directory `{}`: {err}",
                path.display(),
                parent.display()
            ),
        )
    })?;
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    // Directory syncing through std::fs::File is supported on Unix.
    Ok(())
}

// OUTPUT FILE
// ================================================================================================

/// Output file struct
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct OutputFile {
    pub stack: Vec<String>,
}

/// Helper methods to interact with the output file
impl OutputFile {
    /// Maximum output JSON file size in bytes (64 KiB).
    pub const MAX_FILE_SIZE: usize = 64 * 1024;

    /// Returns a new [OutputFile] from the specified outputs vectors
    pub fn new(stack_outputs: &StackOutputs) -> Self {
        Self {
            stack: stack_outputs.iter().map(|&v| v.to_string()).collect::<Vec<String>>(),
        }
    }

    /// Reads output JSON from a regular file of at most [`Self::MAX_FILE_SIZE`] bytes.
    /// Symlinks to regular files are accepted.
    #[instrument(name = "read_output_file",
        fields(path = %outputs_path.clone().unwrap_or(program_path.with_extension("outputs")).display()), skip_all)]
    pub fn read(outputs_path: &Option<PathBuf>, program_path: &Path) -> Result<Self, String> {
        // If outputs_path has been provided then use this as path.  Alternatively we will
        // replace the program_path extension with `.outputs` and use this as a default.
        let path = match outputs_path {
            Some(path) => path.clone(),
            None => program_path.with_extension("outputs"),
        };

        // Bound the file before deserializing any JSON collections.
        let outputs_file = read_file_bounded(&path, Self::MAX_FILE_SIZE)
            .map_err(|err| format!("Failed to open outputs file `{}` - {}", path.display(), err))?;
        let outputs_file = String::from_utf8(outputs_file)
            .map_err(|err| format!("Failed to open outputs file `{}` - {err}", path.display()))?;

        // deserialize outputs data
        let outputs: OutputFile = serde_json::from_str(&outputs_file)
            .map_err(|err| format!("Failed to deserialize outputs data - {err}"))?;

        Ok(outputs)
    }

    /// Writes output JSON through a temporary file and atomically replaces the destination.
    #[instrument(name = "write_data_to_output_file", fields(path = %path.display()), skip_all)]
    pub fn write(stack_outputs: &StackOutputs, path: &Path) -> Result<(), String> {
        write_file_atomically(path, |file| {
            serde_json::to_writer_pretty(file, &Self::new(stack_outputs)).map_err(io::Error::from)
        })
        .map_err(|err| format!("Failed to write output file `{}` - {err}", path.display()))
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

pub struct ProgramFile<S: SourceManager = DefaultSourceManager> {
    ast: Box<Module>,
    source_manager: Arc<S>,
}

impl ProgramFile {
    /// Reads the masm file at the specified path and parses it into a [ProgramFile].
    pub fn read(path: impl AsRef<Path>) -> Result<Self, Report> {
        let source_manager = Arc::new(DefaultSourceManager::default());
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
        let mut parser = Module::parser(Some(ModuleKind::Executable));
        let ast = parser
            .parse_file(Some(LibraryPath::exec_path()), path, source_manager.clone())
            .wrap_err_with(|| format!("Failed to parse program file `{}`", path.display()))?;

        Ok(Self { ast, source_manager })
    }

    /// Compiles this program file into an executable [Package].
    #[instrument(name = "compile_package", skip_all)]
    pub fn compile_package<I>(&self, libraries: I) -> Result<Box<Package>, Report>
    where
        I: IntoIterator<Item = Arc<Package>>,
    {
        let mut assembler = Assembler::new(self.source_manager.clone());
        assembler
            .link_package(CoreLibrary::default().package(), miden_assembly::Linkage::Dynamic)
            .wrap_err("Failed to load core library")?;

        for library in libraries {
            assembler
                .link_package(library, miden_assembly::Linkage::Dynamic)
                .wrap_err("Failed to load libraries")?;
        }

        assembler
            .assemble_program("program", self.ast.clone())
            .wrap_err("Failed to compile program")
    }

    /// Compiles this program file into a [Program].
    #[instrument(name = "compile_program", skip_all)]
    pub fn compile<I>(&self, libraries: I) -> Result<Program, Report>
    where
        I: IntoIterator<Item = Arc<Package>>,
    {
        Ok(self.compile_package(libraries)?.unwrap_program())
    }

    /// Returns the source manager for this program file.
    pub fn source_manager(&self) -> &Arc<S> {
        &self.source_manager
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

        // deserialize bytes into a versioned execution proof
        ExecutionProof::read_from_bytes(&file)
            .map_err(|err| format!("Failed to decode proof data - {err}"))
    }

    /// Writes the proof through a temporary file and atomically replaces the destination.
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

        write_file_atomically(&path, |file| file.write_all(&proof_bytes))
            .map_err(|err| format!("Failed to write proof file `{}` - {err}", path.display()))
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
                report!("Failed to read package from file `{}`: {}", path_str, err)
            })?;

            libraries.push(library);
        }

        Ok(Self { libraries })
    }
}

#[cfg(test)]
mod output_file_tests {
    use super::*;

    #[test]
    fn output_file_read_accepts_the_limit_and_rejects_an_extra_byte() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let json = br#"{"stack":["7"]}"#;
        file.write_all(json).unwrap();
        file.write_all(&vec![b' '; OutputFile::MAX_FILE_SIZE - json.len()]).unwrap();
        let path = Some(file.path().to_path_buf());
        let outputs = OutputFile::read(&path, file.path()).unwrap();
        assert_eq!(outputs.stack, ["7"]);
        assert!(outputs.stack_outputs().is_ok());

        file.write_all(b" ").unwrap();
        let err = OutputFile::read(&path, file.path()).unwrap_err();
        assert!(err.contains("size limit of 65536 bytes"), "{err}");
    }

    #[test]
    fn output_file_read_rejects_invalid_utf8_in_ignored_fields() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"{\"stack\":[],\"ignored\":\"\xff\"}").unwrap();
        let err = OutputFile::read(&Some(file.path().to_path_buf()), file.path()).unwrap_err();
        assert!(err.contains("utf-8"));
    }

    #[test]
    fn output_file_read_reports_malformed_json_and_non_regular_files() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"invalid JSON").unwrap();
        let err = OutputFile::read(&Some(file.path().to_path_buf()), file.path()).unwrap_err();
        assert!(err.contains("Failed to deserialize outputs data"));

        let dir = tempfile::tempdir().unwrap();
        let err = OutputFile::read(&Some(dir.path().to_path_buf()), dir.path()).unwrap_err();
        assert!(err.contains("expected a regular file"));
    }
}

#[cfg(test)]
mod atomic_write_tests {
    use super::*;

    #[test]
    fn partial_write_failure_preserves_existing_artifacts_and_removes_temporary_files() {
        for extension in ["outputs", "proof"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(format!("program.{extension}"));
            fs::write(&path, b"previous complete artifact").unwrap();

            let err = write_file_atomically(&path, |file| {
                file.write_all(b"partial replacement")?;
                assert_eq!(fs::read(&path).unwrap(), b"previous complete artifact");
                Err(io::Error::new(io::ErrorKind::StorageFull, "injected disk full"))
            })
            .unwrap_err();

            assert_eq!(err.kind(), io::ErrorKind::StorageFull);
            assert_eq!(err.to_string(), "injected disk full");
            assert_eq!(fs::read(&path).unwrap(), b"previous complete artifact");
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }

    #[test]
    fn partial_write_failure_leaves_a_missing_destination_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("program.proof");
        let err = write_file_atomically(&path, |file| {
            file.write_all(b"partial proof")?;
            Err(io::Error::new(io::ErrorKind::StorageFull, "injected disk full"))
        })
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::StorageFull);
        assert_eq!(err.to_string(), "injected disk full");
        assert!(!path.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn file_sync_failure_preserves_destination_and_removes_temporary_file() {
        for exists in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("program.proof");
            if exists {
                fs::write(&path, b"previous proof").unwrap();
            }
            let err = write_file_atomically_with_sync(
                &path,
                |file| file.write_all(b"complete replacement"),
                |file| {
                    assert_eq!(file.metadata()?.len(), b"complete replacement".len() as u64);
                    Err(io::Error::new(io::ErrorKind::StorageFull, "injected file sync failure"))
                },
                |_| panic!("directory sync must not run after file sync fails"),
            )
            .unwrap_err();

            assert_eq!(err.kind(), io::ErrorKind::StorageFull);
            assert_eq!(err.to_string(), "injected file sync failure");
            if exists {
                assert_eq!(fs::read(&path).unwrap(), b"previous proof");
            } else {
                assert!(!path.exists());
            }
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), usize::from(exists));
        }
    }

    #[test]
    fn replacement_failure_preserves_destination_and_removes_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("program.proof");
        let err = write_file_atomically(&path, |file| {
            file.write_all(b"complete proof")?;
            // Create a conflicting destination after the initial metadata check.
            fs::create_dir(&path)?;
            fs::write(path.join("existing"), b"keep me")
        })
        .unwrap_err();

        assert!(err.raw_os_error().is_some(), "replacement should return the OS error: {err}");
        assert_eq!(fs::read(path.join("existing")).unwrap(), b"keep me");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);

        let err = write_file_atomically(&path, |_| panic!("must reject the existing directory"))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(fs::read(path.join("existing")).unwrap(), b"keep me");
    }

    #[test]
    fn directory_sync_failure_reports_that_replacement_has_committed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("program.proof");
        fs::write(&path, b"previous proof").unwrap();

        let err = write_file_atomically_with_sync(
            &path,
            |file| file.write_all(b"complete replacement"),
            fs::File::sync_all,
            |parent| {
                assert_eq!(parent, dir.path());
                assert_eq!(fs::read(&path).unwrap(), b"complete replacement");
                Err(io::Error::new(io::ErrorKind::StorageFull, "injected directory sync failure"))
            },
        )
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::StorageFull);
        assert_eq!(
            err.to_string(),
            format!(
                "Artifact `{}` was replaced. Failed to sync destination directory `{}`: injected directory sync failure",
                path.display(),
                dir.path().display()
            )
        );
        assert_eq!(fs::read(&path).unwrap(), b"complete replacement");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn output_file_write_creates_and_replaces_readable_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("program.outputs");
        for value in [7, 8] {
            let outputs = StackOutputs::new(&[Felt::from_u32(value)]).unwrap();
            OutputFile::write(&outputs, &path).unwrap();
            let loaded = OutputFile::read(&Some(path.clone()), &path).unwrap();
            assert_eq!(loaded, OutputFile::new(&outputs));
            assert_eq!(
                fs::read(&path).unwrap(),
                serde_json::to_vec_pretty(&OutputFile::new(&outputs)).unwrap()
            );
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }

    #[cfg(unix)]
    #[test]
    fn new_and_replaced_artifacts_use_ordinary_file_creation_permissions() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let reference = dir.path().join("ordinary");
        let path = dir.path().join("program.outputs");
        fs::write(&reference, b"ordinary file").unwrap();
        let expected = fs::metadata(reference).unwrap();
        for replace in [false, true] {
            if replace {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
            }
            write_file_atomically(&path, |file| file.write_all(b"new artifact")).unwrap();
            let actual = fs::metadata(&path).unwrap();
            assert_eq!(actual.permissions().mode() & 0o777, expected.permissions().mode() & 0o777);
            assert_eq!(actual.uid(), expected.uid());
            assert_eq!(actual.gid(), expected.gid());
            assert_eq!(fs::read(&path).unwrap(), b"new artifact");
        }
    }

    #[cfg(unix)]
    #[test]
    fn successful_replacement_replaces_symlink_and_preserves_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.outputs");
        let directory = dir.path().join("target-directory");
        let loop_path = dir.path().join("loop.outputs");
        let missing = dir.path().join("missing");
        fs::write(&target, b"previous target").unwrap();
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("keep"), b"keep me").unwrap();

        for (name, destination) in [
            ("program.outputs", &target),
            ("directory.outputs", &directory),
            ("loop.outputs", &loop_path),
            ("missing.outputs", &missing),
        ] {
            let path = dir.path().join(name);
            std::os::unix::fs::symlink(destination, &path).unwrap();
            write_file_atomically(&path, |file| file.write_all(b"replacement")).unwrap();
            assert!(fs::symlink_metadata(&path).unwrap().is_file());
            assert_eq!(fs::read(path).unwrap(), b"replacement");
        }
        assert_eq!(fs::read(target).unwrap(), b"previous target");
        assert_eq!(fs::read(directory.join("keep")).unwrap(), b"keep me");
        assert!(!missing.exists());
    }
}
