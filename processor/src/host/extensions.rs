use alloc::boxed::Box;
use core::error::Error;

use super::{FutureMaybeSend, Host, LoadedMastForest, SyncHost};
use crate::Word;

/// A source error returned when a host cannot load a MAST forest.
pub type MastForestLoadError = Box<dyn Error + Send + Sync + 'static>;

/// A forest, a genuine absence, or a loading failure.
pub type MastForestLoadResult = Result<Option<LoadedMastForest>, MastForestLoadError>;

/// Fallible MAST forest loading used by [`crate::FastProcessor::execute_fallible`].
///
/// Existing [`Host`] implementations and execution methods remain unchanged. Implement this trait
/// and call a fallible execution method to report loading errors.
///
/// # Example
///
/// Given an existing `DatabaseHost: Host`, expose its asynchronous `read_forest` method through
/// [`FallibleHost`]. The method returns `io::Result<Option<LoadedMastForest>>`. In this
/// example, the database call fails, and execution preserves the I/O error as its source.
///
/// ```
/// use std::io;
/// use miden_processor::{
///     ExecutionError, FastProcessor, FallibleHost, MastForestLoadError, MastForestLoadResult,
///     StackInputs, Word,
/// };
/// # use std::sync::Arc;
/// # use miden_debug_types::{Location, SourceFile, SourceSpan};
/// # use miden_processor::{BaseHost, FutureMaybeSend, Host, LoadedMastForest, ProcessorState};
/// # use miden_processor::{advice::AdviceMutation, event::EventError};
/// # struct DatabaseHost;
/// # impl DatabaseHost {
/// #     async fn read_forest(&self, _: &Word) -> io::Result<Option<LoadedMastForest>> {
/// #         tokio::task::yield_now().await;
/// #         Err(io::Error::other("database unavailable"))
/// #     }
/// # }
/// # impl BaseHost for DatabaseHost {
/// #     fn get_label_and_source_file(&self, _: &Location) -> (SourceSpan, Option<Arc<SourceFile>>) {
/// #         (SourceSpan::UNKNOWN, None)
/// #     }
/// # }
/// # impl Host for DatabaseHost {
/// #     fn get_mast_forest(&self, _: &Word) -> impl FutureMaybeSend<Option<LoadedMastForest>> {
/// #         async { unreachable!("use fallible execution for database lookups") }
/// #     }
/// #     fn on_event(&mut self, _: &ProcessorState<'_>)
/// #         -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
/// #         async { Ok(Vec::new()) }
/// #     }
/// # }
///
/// impl FallibleHost for DatabaseHost {
///     async fn try_get_mast_forest(&self, root: &Word) -> MastForestLoadResult {
///         self.read_forest(root).await.map_err(|error| Box::new(error) as MastForestLoadError)
///     }
/// }
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() {
/// # let program = miden_assembly::Assembler::default()
/// #     .assemble_program("program", "begin dynexec end").unwrap().unwrap_program();
/// let mut host = DatabaseHost;
/// let error = FastProcessor::new(StackInputs::default())
///     .execute_fallible(&program, &mut host)
///     .await
///     .unwrap_err();
///
/// let ExecutionError::MastForestError { root_digest, error, .. } = error else {
///     panic!("expected the database error");
/// };
/// assert_eq!(root_digest, Word::default());
/// assert!(error.downcast_ref::<io::Error>().is_some());
/// assert_eq!(error.to_string(), "database unavailable");
/// # }
/// ```
pub trait FallibleHost: Host {
    /// Loads a forest, returning `Ok(None)` only when the requested procedure is absent.
    ///
    /// # Cancellation safety
    ///
    /// Dropping a pending lookup must leave shared host and datastore state valid and permit
    /// another lookup without losing stored forests. Implementations must arrange any required
    /// cleanup before affected resources are reused.
    fn try_get_mast_forest(&self, root: &Word) -> impl FutureMaybeSend<MastForestLoadResult>;
}

/// Synchronous counterpart of [`FallibleHost`], used by
/// [`crate::FastProcessor::execute_fallible_sync`].
///
/// Follow the [`FallibleHost`] example with a method returning [`MastForestLoadResult`] directly.
pub trait FallibleSyncHost: SyncHost {
    /// Loads a forest, returning `Ok(None)` only when the requested procedure is absent.
    fn try_get_mast_forest(&self, root: &Word) -> MastForestLoadResult;
}

// Static lookup strategies let existing execution methods retain their original host bounds.
pub(crate) struct LegacyForestLoader;
pub(crate) struct FallibleForestLoader;

pub(crate) trait AsyncForestLookup<H: Host> {
    fn load(host: &H, root: &Word) -> impl FutureMaybeSend<MastForestLoadResult>;
}

pub(crate) trait SyncForestLookup<H: SyncHost> {
    fn load(host: &H, root: &Word) -> MastForestLoadResult;
}

impl<H: Host> AsyncForestLookup<H> for LegacyForestLoader {
    fn load(host: &H, root: &Word) -> impl FutureMaybeSend<MastForestLoadResult> {
        let future = host.get_mast_forest(root);
        async move { Ok(future.await) }
    }
}

impl<H: FallibleHost> AsyncForestLookup<H> for FallibleForestLoader {
    fn load(host: &H, root: &Word) -> impl FutureMaybeSend<MastForestLoadResult> {
        host.try_get_mast_forest(root)
    }
}

impl<H: SyncHost> SyncForestLookup<H> for LegacyForestLoader {
    fn load(host: &H, root: &Word) -> MastForestLoadResult {
        Ok(host.get_mast_forest(root))
    }
}

impl<H: FallibleSyncHost> SyncForestLookup<H> for FallibleForestLoader {
    fn load(host: &H, root: &Word) -> MastForestLoadResult {
        host.try_get_mast_forest(root)
    }
}
