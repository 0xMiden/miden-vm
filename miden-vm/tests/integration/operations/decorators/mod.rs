use std::sync::Arc;

use miden_core::DebugOptions;
use miden_debug_types::{DefaultSourceManager, Location, SourceFile, SourceManager, SourceSpan};
use miden_processor::{
    AdviceMutation, AsyncHost, BaseHost, EventError, ExecutionError, MastForest, ProcessState,
    SyncHost,
};
use miden_prover::Word;

mod advice;
mod asmop;
mod events;

// TEST HOST
// ================================================================================================
#[derive(Debug, Clone, Default)]
pub struct TestHost {
    pub event_handler: Vec<u32>,
    pub trace_handler: Vec<u32>,
    pub debug_handler: Vec<String>,
    pub source_manager: Arc<DefaultSourceManager>,
}

impl BaseHost for TestHost {
    fn get_mast_forest(&self, _node_digest: &Word) -> Option<Arc<MastForest>> {
        // Empty MAST forest store
        None
    }

    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        let maybe_file = self.source_manager.get_by_uri(location.uri());
        let span = self.source_manager.location_to_span(location.clone()).unwrap_or_default();
        (span, maybe_file)
    }

    fn on_debug(
        &mut self,
        _process: &mut ProcessState,
        options: &DebugOptions,
    ) -> Result<(), ExecutionError> {
        self.debug_handler.push(options.to_string());
        Ok(())
    }

    fn on_trace(
        &mut self,
        _process: &mut ProcessState,
        trace_id: u32,
    ) -> Result<(), ExecutionError> {
        self.trace_handler.push(trace_id);
        Ok(())
    }
}

impl SyncHost for TestHost {
    fn on_event(
        &mut self,
        _process: &ProcessState,
        event_id: u32,
    ) -> Result<Vec<AdviceMutation>, EventError> {
        self.event_handler.push(event_id);
        Ok(Vec::new())
    }
}

impl AsyncHost for TestHost {
    fn on_event(
        &mut self,
        _process: &ProcessState<'_>,
        event_id: u32,
    ) -> impl Future<Output = Result<Vec<AdviceMutation>, EventError>> + Send {
        self.event_handler.push(event_id);
        async move { Ok(Vec::new()) }
    }
}
