//! A self-contained snapshot of a recorded execution, sufficient to replay it in the debugger
//! without the original host.
//!
//! A live execution (e.g. a transaction driven through the DAP executor) resolves two kinds of
//! host interaction that a bare debugger host cannot reproduce on its own: the advice mutations
//! returned by event handlers, and the MAST forests resolved for `call`/`dyncall` targets (account
//! code, note scripts, etc.). A [ReplaySnapshot] captures both, alongside the program and its
//! inputs, so the same execution can be re-run later by feeding the recorded event log into an
//! event-replay debugger host (see `Executor::into_debug_with_replay` and
//! `State::new_for_transaction`).

use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_core::{
    mast::MastForest,
    program::StackInputs,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};
use miden_debug_types::Uri;
use miden_mast_package::{Package, debug_info::PackageDebugInfo};
use miden_processor::{
    ExecutionOptions, LoadedMastForest,
    advice::{AdviceInputs, AdviceMutation},
};
use miden_utils_sync::RwLock;

use super::advice::{read_event_log, write_event_log};

/// A shared, cloneable log of the MAST forests a host resolved during execution.
///
/// The debugger's event-replay host serves recorded advice mutations for `on_event`, but it still
/// has to resolve the code for `call`/`dyncall` targets itself. Recording the forests the live
/// host returned — deduplicated, since the same forest is resolved for many nodes — lets the
/// replay host load exactly that set and reach the same targets.
#[derive(Clone, Default)]
pub struct MastForestRecorder {
    forests: Arc<RwLock<Vec<LoadedMastForest>>>,
}

impl MastForestRecorder {
    /// Create a new, empty recorder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a copy of the recorded forests.
    pub fn snapshot(&self) -> Vec<LoadedMastForest> {
        self.forests.read().clone()
    }

    /// Record a forest resolved by the host, ignoring forests already recorded this run.
    pub(crate) fn record(&self, forest: LoadedMastForest) {
        let mut guard = self.forests.write();
        if !guard
            .iter()
            .any(|existing| Arc::ptr_eq(existing.mast_forest(), forest.mast_forest()))
        {
            guard.push(forest);
        }
    }

    /// Discard everything recorded so far, e.g. when execution restarts from the beginning.
    #[cfg(feature = "dap")]
    pub(crate) fn clear(&self) {
        self.forests.write().clear();
    }
}

/// Successful replay snapshot write metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplaySnapshotWrite {
    pub path: Uri,
    pub event_count: usize,
    pub forest_count: usize,
}

/// Error metadata for a failed replay snapshot write.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("failed to write replay snapshot to {}: {}", path, message)]
pub struct ReplaySnapshotWriteError {
    pub path: Uri,
    pub message: String,
}

/// Shared status handle for a configured replay snapshot write.
#[derive(Clone, Debug, Default)]
pub struct ReplaySnapshotRecorder {
    status: Arc<RwLock<Option<Result<ReplaySnapshotWrite, ReplaySnapshotWriteError>>>>,
}

impl ReplaySnapshotRecorder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the last snapshot write status, leaving the handle empty.
    pub fn take(&self) -> Option<Result<ReplaySnapshotWrite, ReplaySnapshotWriteError>> {
        self.status.write().take()
    }

    #[cfg(feature = "dap")]
    pub(crate) fn record_success(&self, write: ReplaySnapshotWrite) {
        *self.status.write() = Some(Ok(write));
    }

    #[cfg(feature = "dap")]
    pub(crate) fn record_error(&self, path: Uri, err: impl ToString) {
        *self.status.write() = Some(Err(ReplaySnapshotWriteError {
            path,
            message: err.to_string(),
        }));
    }
}

/// Magic bytes identifying a replay snapshot file, followed by a format version. Bumping the
/// version invalidates older snapshots, whose serialized shape may differ.
const SNAPSHOT_MAGIC: [u8; 6] = *b"MDNSNP";
const SNAPSHOT_VERSION: u8 = 4;

/// Everything needed to replay a recorded execution in the debugger.
pub struct ReplaySnapshot {
    /// The program that was executed (for a transaction, the transaction kernel).
    pub package: Arc<Package>,
    /// The operand stack inputs the program started with.
    pub stack_inputs: StackInputs,
    /// The advice inputs the program started with.
    pub advice_inputs: AdviceInputs,
    /// The VM execution options used by the recorded run.
    pub options: ExecutionOptions,
    /// The MAST forests resolved by the host during execution (account code, note scripts, ...),
    /// which the replay host must be able to resolve for the same `call`/`dyncall` targets.
    pub mast_forests: Vec<LoadedMastForest>,
    /// The advice mutations produced by event handlers, one entry per `on_event` invocation, in
    /// execution order — the event replay queue.
    pub event_log: Vec<Vec<AdviceMutation>>,
}

impl ReplaySnapshot {
    /// Serialize the snapshot to `path`.
    ///
    /// Returns `InvalidInput` without changing the file when either precompile policy is custom.
    #[cfg(feature = "std")]
    pub fn write_to_file(&self, path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        let bytes = self
            .to_bytes()
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
        std::fs::write(path, bytes)
    }

    /// Read and deserialize a snapshot from `path`.
    #[cfg(feature = "std")]
    pub fn read_from_file(path: impl AsRef<std::path::Path>) -> Result<Self, ReplaySnapshotError> {
        let bytes = std::fs::read(path).map_err(ReplaySnapshotError::Io)?;
        Self::read_from_bytes(&bytes).map_err(ReplaySnapshotError::Deserialization)
    }

    /// Serialize the snapshot to a byte vector.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ReplaySnapshotEncodeError> {
        let mut bytes = Vec::new();
        self.write_into(&mut bytes)?;
        Ok(bytes)
    }

    /// Deserialize a snapshot from bytes.
    pub fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let mut reader = miden_core::serde::SliceReader::new(bytes);
        Self::read_from(&mut reader)
    }

    /// Serialize the snapshot, rejecting custom precompile policies before writing any bytes.
    ///
    /// Miden VM 1.0.0-rc.0 cannot serialize these policies through its public API. Restoring
    /// defaults for a custom policy would change replay behavior, so only defaults are supported.
    pub fn write_into<W: ByteWriter>(
        &self,
        target: &mut W,
    ) -> Result<(), ReplaySnapshotEncodeError> {
        let defaults = ExecutionOptions::default();
        if self.options.execution_precompile_limits() != defaults.execution_precompile_limits()
            || self.options.verification_precompile_limits()
                != defaults.verification_precompile_limits()
        {
            return Err(ReplaySnapshotEncodeError::UnsupportedPrecompileLimits);
        }

        target.write_bytes(&SNAPSHOT_MAGIC);
        target.write_u8(SNAPSHOT_VERSION);
        self.package.write_into(target);
        self.stack_inputs.write_into(target);
        self.advice_inputs.write_into(target);
        write_execution_options(&self.options, target);
        target.write_usize(self.mast_forests.len());
        for forest in &self.mast_forests {
            forest.mast_forest().as_ref().write_into(target);
            match forest.package_debug_info().ok().flatten() {
                Some(debug_info) => {
                    target.write_bool(true);
                    debug_info.as_ref().write_into(target);
                }
                None => {
                    target.write_bool(false);
                }
            }
        }
        write_event_log(&self.event_log, target);
        Ok(())
    }
}

impl Deserializable for ReplaySnapshot {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let magic: [u8; 6] = source.read_array()?;
        if magic != SNAPSHOT_MAGIC {
            return Err(DeserializationError::InvalidValue(
                "not a Miden debugger replay snapshot (bad magic)".to_string(),
            ));
        }
        let version = source.read_u8()?;
        if version != SNAPSHOT_VERSION {
            return Err(DeserializationError::InvalidValue(format!(
                "unsupported replay snapshot version {version} (expected {SNAPSHOT_VERSION})"
            )));
        }
        let package = Arc::new(Package::read_from_trusted(source)?);
        let stack_inputs = StackInputs::read_from(source)?;
        let advice_inputs = AdviceInputs::read_from(source)?;
        let options = read_execution_options(source)?;
        let forest_count = source.read_usize()?;
        let mut mast_forests = Vec::with_capacity(forest_count);
        for _ in 0..forest_count {
            let mast_forest = Arc::new(MastForest::read_from(source)?);
            mast_forests.push(if source.read_bool()? {
                let debug_info = Some(PackageDebugInfo::read_from(source)?);
                LoadedMastForest::with_package_debug_info(mast_forest, Ok(debug_info))
            } else {
                LoadedMastForest::new(mast_forest)
            });
        }
        let event_log = read_event_log(source)?;
        Ok(Self {
            package,
            stack_inputs,
            advice_inputs,
            options,
            mast_forests,
            event_log,
        })
    }
}

fn write_execution_options<W: ByteWriter>(options: &ExecutionOptions, target: &mut W) {
    target.write_u32(options.max_cycles());
    target.write_u32(options.expected_cycles());
    target.write_usize(options.core_trace_fragment_size());
    target.write_usize(options.max_advice_size_bytes());
    target.write_usize(options.max_hash_len_bytes());
    target.write_bool(options.overlapped_trace_build());
    target.write_usize(options.max_num_continuations());
    target.write_usize(options.max_stack_depth());
    target.write_usize(options.max_memory_elements());
}

fn read_execution_options<R: ByteReader>(
    source: &mut R,
) -> Result<ExecutionOptions, DeserializationError> {
    let max_cycles = source.read_u32()?;
    let expected_cycles = source.read_u32()?;
    let core_trace_fragment_size = source.read_usize()?;
    let max_advice_size_bytes = source.read_usize()?;
    let max_hash_len_bytes = source.read_usize()?;
    let overlapped_trace_build = source.read_bool()?;
    let max_num_continuations = source.read_usize()?;
    let max_stack_depth = source.read_usize()?;
    let max_memory_elements = source.read_usize()?;

    ExecutionOptions::new(Some(max_cycles), expected_cycles, core_trace_fragment_size)
        .map_err(|err| {
            DeserializationError::InvalidValue(format!("invalid execution options: {err}"))
        })
        .and_then(|options| {
            options
                .with_max_advice_size_bytes(max_advice_size_bytes)
                .with_max_hash_len_bytes(max_hash_len_bytes)
                .with_overlapped_trace_build(overlapped_trace_build)
                .with_max_num_continuations(max_num_continuations)
                .with_max_memory_elements(max_memory_elements)
                .with_max_stack_depth(max_stack_depth)
                .map_err(|err| {
                    DeserializationError::InvalidValue(format!("invalid execution options: {err}"))
                })
        })
}

/// Error encoding a [ReplaySnapshot].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReplaySnapshotEncodeError {
    #[error("replay snapshots do not support custom precompile limits with Miden VM 1.0.0-rc.0")]
    UnsupportedPrecompileLimits,
}

/// Error reading a [ReplaySnapshot] from a file.
#[derive(Debug, thiserror::Error)]
#[cfg(feature = "std")]
pub enum ReplaySnapshotError {
    #[error("failed to read replay snapshot file: {0}")]
    Io(std::io::Error),
    #[error("failed to deserialize replay snapshot: {0}")]
    Deserialization(DeserializationError),
}

#[cfg(test)]
mod tests;
