use alloc::{boxed::Box, sync::Arc, vec::Vec};

use miden_core::Word;
use miden_debug_types::{Location, SourceFile, SourceSpan};
use miden_processor::{
    AsyncForestLoader, BaseHost, FutureMaybeSend, Host, LoadedMastForest, MastForestLoadFuture,
    ProcessorState,
    advice::AdviceMutation,
    event::{EventError, EventId, EventName, TraceError},
};

use super::{EventMutationRecorder, MastForestRecorder, advice::clone_advice_mutations};

/// A host wrapper that records advice mutations and resolved MAST forests, so the execution can
/// be replayed later from a [`ReplaySnapshot`](super::ReplaySnapshot).
///
/// A recorder left unset is not recorded into.
///
/// # Example
///
/// Pass the recording host to a diagnostic executor, then retrieve the forests for replay.
///
/// ```
/// use miden_debug_engine::exec::{DiagnosticExecutor, MastForestRecorder, RecordingHost};
/// use miden_processor::{ExecutionOptions, StackInputs, advice::AdviceInputs};
/// # use miden_processor::{ExecutionError, Host, Program};
/// # async fn example(program: &Program, host: &mut (impl Host + Send)) -> Result<(), ExecutionError> {
/// let forests = MastForestRecorder::new();
/// let mut recording = RecordingHost::new(host, None, Some(forests.clone()));
/// let executor = DiagnosticExecutor::new(
///     StackInputs::default(), AdviceInputs::default(), ExecutionOptions::default(),
/// );
/// let output = executor.execute_async(program, &mut recording).await?;
/// let loaded_forests = forests.snapshot();
/// # let _ = (output, loaded_forests);
/// # Ok(())
/// # }
/// ```
pub struct RecordingHost<'a, H> {
    inner: &'a mut H,
    /// When set, the advice mutations produced by each `on_event` invocation of the inner host
    /// are recorded here, in execution order, so they can be replayed later (e.g. transaction
    /// debugging with event replay).
    event_recorder: Option<EventMutationRecorder>,
    /// When set, the MAST forests the inner host resolves are recorded here, so a replay session
    /// can load the same code for `call`/`dyncall` targets.
    forest_recorder: Option<MastForestRecorder>,
}

impl<'a, H> RecordingHost<'a, H> {
    pub fn new(
        inner: &'a mut H,
        event_recorder: Option<EventMutationRecorder>,
        forest_recorder: Option<MastForestRecorder>,
    ) -> Self {
        Self { inner, event_recorder, forest_recorder }
    }
}

impl<H: Host> BaseHost for RecordingHost<'_, H> {
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        self.inner.get_label_and_source_file(location)
    }

    fn resolve_event(&self, event_id: EventId) -> Option<&EventName> {
        self.inner.resolve_event(event_id)
    }

    fn resolve_trace(&self, trace_id: EventId) -> Option<&EventName> {
        self.inner.resolve_trace(trace_id)
    }
}

impl<H: Host> AsyncForestLoader for RecordingHost<'_, H> {
    fn load<'a>(&'a self, root: &'a Word) -> MastForestLoadFuture<'a> {
        let recorder = self.forest_recorder.clone();
        let future = match self.inner.forest_loader() {
            Some(loader) => loader.load(root),
            None => {
                let future = self.inner.get_mast_forest(root);
                Box::pin(async move { Ok(future.await) })
            },
        };
        Box::pin(async move {
            let forest = future.await?;
            if let (Some(recorder), Some(forest)) = (&recorder, &forest) {
                recorder.record(forest.clone());
            }
            Ok(forest)
        })
    }
}

impl<H: Host> Host for RecordingHost<'_, H> {
    fn forest_loader(&self) -> Option<&dyn AsyncForestLoader> {
        self.inner.forest_loader().map(|_| self as &dyn AsyncForestLoader)
    }

    fn get_mast_forest(
        &self,
        node_digest: &Word,
    ) -> impl FutureMaybeSend<Option<LoadedMastForest>> {
        // Record every forest the inner host resolves, so a replay session can load the same
        // code for `call`/`dyncall` targets. The recorder deduplicates.
        let forest_recorder = self.forest_recorder.clone();
        let fut = self.inner.get_mast_forest(node_digest);
        async move {
            let forest = fut.await;
            if let (Some(recorder), Some(forest)) = (&forest_recorder, &forest) {
                recorder.record(forest.clone());
            }
            forest
        }
    }

    fn on_event(
        &mut self,
        process: &ProcessorState<'_>,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
        // Every invocation is recorded, including empty mutation sets: event replay pops one
        // entry per event, so the log must stay aligned with the event stream.
        let recorder = self.event_recorder.clone();
        let fut = self.inner.on_event(process);
        async move {
            let result = fut.await;
            if let (Some(recorder), Ok(mutations)) = (&recorder, &result) {
                recorder.record(clone_advice_mutations(mutations));
            }
            result
        }
    }

    fn on_trace(
        &mut self,
        process: &ProcessorState<'_>,
    ) -> impl FutureMaybeSend<Result<(), TraceError>> {
        self.inner.on_trace(process)
    }
}

#[cfg(test)]
mod tests;
