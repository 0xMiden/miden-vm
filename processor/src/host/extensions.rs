//! Prototype: optional forest-loading capabilities discovered through the host.

use alloc::boxed::Box;
use core::{error::Error, pin::Pin};

use super::{FutureMaybeSend, LoadedMastForest};
use crate::Word;

/// A source error returned when a host cannot load a MAST forest.
pub type MastForestLoadError = Box<dyn Error + Send + Sync + 'static>;

/// A forest, a genuine absence, or a loading failure.
pub type MastForestLoadResult = Result<Option<LoadedMastForest>, MastForestLoadError>;

/// Erased asynchronous lookup, with the same native/Wasm Send rules as host callbacks.
pub type MastForestLoadFuture<'a> = Pin<Box<dyn FutureMaybeSend<MastForestLoadResult> + 'a>>;

/// Optional asynchronous forest loading advertised by [`super::Host::forest_loader`].
///
/// Returning an extension opts all execution paths into fallible loading. An error is propagated
/// without retrying the legacy lookup. The extension can borrow a separate store owned by the host.
/// Only extension lookups box their futures; legacy callbacks retain their concrete futures.
///
/// Dropping a lookup must leave host and store state valid. Completed host effects are not rolled
/// back when execution is cancelled.
///
/// # Example
///
/// Advertise the loader on the host, then use the ordinary execution method.
///
/// ```
/// use miden_processor::{
///     AsyncForestLoader, BaseHost, ExecutionError, FastProcessor, FutureMaybeSend, Host,
///     LoadedMastForest, MastForestLoadFuture, ProcessorState, StackInputs, Word,
///     advice::AdviceMutation, event::EventError,
/// };
/// # use std::sync::Arc;
/// # use miden_debug_types::{Location, SourceFile, SourceSpan};
///
/// struct DatabaseHost;
/// # impl BaseHost for DatabaseHost {
/// #     fn get_label_and_source_file(&self, _: &Location) -> (SourceSpan, Option<Arc<SourceFile>>) {
/// #         (SourceSpan::UNKNOWN, None)
/// #     }
/// # }
///
/// impl Host for DatabaseHost {
///     fn forest_loader(&self) -> Option<&dyn AsyncForestLoader> {
///         Some(self)
///     }
/// #     fn get_mast_forest(&self, _: &Word) -> impl FutureMaybeSend<Option<LoadedMastForest>> {
/// #         async { unreachable!("use the advertised loader") }
/// #     }
/// #     fn on_event(&mut self, _: &ProcessorState<'_>)
/// #         -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
/// #         async { Ok(Vec::new()) }
/// #     }
/// }
///
/// impl AsyncForestLoader for DatabaseHost {
///     fn load<'a>(&'a self, _root: &'a Word) -> MastForestLoadFuture<'a> {
///         Box::pin(async move {
///             // Await your datastore lookup here. This example returns a storage error.
///             Err(std::io::Error::other("database unavailable").into())
///         })
///     }
/// }
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() {
/// # let program = miden_assembly::Assembler::default()
/// #     .assemble_program("program", "begin dynexec end").unwrap().unwrap_program();
/// let mut host = DatabaseHost;
/// let error = FastProcessor::new(StackInputs::default())
///     .execute(&program, &mut host).await.unwrap_err();
/// assert!(matches!(error, ExecutionError::MastForestError { .. }));
/// # }
/// ```
pub trait AsyncForestLoader {
    fn load<'a>(&'a self, root: &'a Word) -> MastForestLoadFuture<'a>;
}

/// Optional synchronous forest loading advertised by [`super::SyncHost::forest_loader`].
///
/// The asynchronous supertrait allows the blanket synchronous-to-asynchronous host adapter to
/// forward this capability through trait upcasting. Implementing this trait supplies that adapter
/// automatically, so a synchronous loader only implements `load_sync`.
///
/// # Example
///
/// The same host reports storage errors through synchronous and asynchronous execution.
///
/// ```
/// use std::sync::Arc;
///
/// use miden_assembly::Assembler;
/// use miden_debug_types::{Location, SourceFile, SourceSpan};
/// use miden_processor::{
///     BaseHost, ExecutionError, FastProcessor, LoadedMastForest, MastForestLoadResult,
///     ProcessorState, StackInputs, SyncForestLoader, SyncHost, Word, advice::AdviceMutation,
///     event::EventError,
/// };
///
/// struct DatabaseHost;
///
/// impl BaseHost for DatabaseHost {
///     fn get_label_and_source_file(&self, _: &Location) -> (SourceSpan, Option<Arc<SourceFile>>) {
///         (SourceSpan::UNKNOWN, None)
///     }
/// }
///
/// impl SyncHost for DatabaseHost {
///     fn forest_loader(&self) -> Option<&dyn SyncForestLoader> {
///         Some(self)
///     }
///
///     fn get_mast_forest(&self, _: &Word) -> Option<LoadedMastForest> {
///         unreachable!("this host advertises a fallible loader")
///     }
///
///     fn on_event(&mut self, _: &ProcessorState<'_>) -> Result<Vec<AdviceMutation>, EventError> {
///         Ok(Vec::new())
///     }
/// }
///
/// impl SyncForestLoader for DatabaseHost {
///     fn load_sync(&self, _: &Word) -> MastForestLoadResult {
///         Err(std::io::Error::other("database unavailable").into())
///     }
/// }
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() {
/// let program = Assembler::default()
///     .assemble_program("program", "begin dynexec end")
///     .unwrap()
///     .unwrap_program();
/// let mut host = DatabaseHost;
/// let sync_error = FastProcessor::new(StackInputs::default())
///     .execute_sync(&program, &mut host)
///     .unwrap_err();
/// let async_error = FastProcessor::new(StackInputs::default())
///     .execute(&program, &mut host)
///     .await
///     .unwrap_err();
/// for error in [sync_error, async_error] {
///     let ExecutionError::MastForestError { error, .. } = error else {
///         panic!("expected the database error");
///     };
///     assert_eq!(
///         error.downcast_ref::<std::io::Error>().unwrap().to_string(),
///         "database unavailable"
///     );
/// }
/// # }
/// ```
pub trait SyncForestLoader: AsyncForestLoader {
    fn load_sync(&self, root: &Word) -> MastForestLoadResult;
}

impl<T: SyncForestLoader + ?Sized> AsyncForestLoader for T {
    fn load<'a>(&'a self, root: &'a Word) -> MastForestLoadFuture<'a> {
        let result = self.load_sync(root);
        Box::pin(async move { result })
    }
}
