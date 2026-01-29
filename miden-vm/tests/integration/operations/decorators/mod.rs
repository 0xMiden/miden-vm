use std::sync::Arc;

use miden_core::DebugOptions;
use miden_debug_types::{DefaultSourceManager, Location, SourceFile, SourceManager, SourceSpan};
use miden_processor::{
    AdviceMutation, DebugError, EventError, FutureMaybeSend, Host, MastForest, ProcessorState,
    TraceError,
};
use miden_prover::Word;
use miden_utils_testing::PrimeField64;

mod advice;
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

impl Host for TestHost {
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        let maybe_file = self.source_manager.get_by_uri(location.uri());
        let span = self.source_manager.location_to_span(location.clone()).unwrap_or_default();
        (span, maybe_file)
    }

    fn get_mast_forest(
        &self,
        _node_digest: &Word,
    ) -> impl FutureMaybeSend<Option<Arc<MastForest>>> {
        async move { None }
    }

    fn on_event(
        &mut self,
        process: &ProcessorState<'_>,
    ) -> impl FutureMaybeSend<Result<Vec<AdviceMutation>, EventError>> {
        let event_id = process.get_stack_item(0).as_canonical_u64().try_into().unwrap();
        self.event_handler.push(event_id);
        async move { Ok(Vec::new()) }
    }

    fn on_debug(
        &mut self,
        _process: &mut ProcessorState,
        options: &DebugOptions,
    ) -> Result<(), DebugError> {
        self.debug_handler.push(options.to_string());
        Ok(())
    }

    fn on_trace(&mut self, _process: &mut ProcessorState, trace_id: u32) -> Result<(), TraceError> {
        self.trace_handler.push(trace_id);
        Ok(())
    }
}
