use std::sync::Arc;

use miden_core::DebugOptions;
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
}

impl BaseHost for TestHost {
    fn on_debug(
        &mut self,
        _process: &ProcessState,
        options: &DebugOptions,
    ) -> Result<(), ExecutionError> {
        self.debug_handler.push(options.to_string());
        Ok(())
    }

    fn on_trace(&mut self, _process: &ProcessState, trace_id: u32) -> Result<(), ExecutionError> {
        self.trace_handler.push(trace_id);
        Ok(())
    }
}

impl SyncHost for TestHost {
    fn get_mast_forest(&self, _node_digest: &Word) -> Option<Arc<MastForest>> {
        // Empty MAST forest store
        None
    }

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
    async fn get_mast_forest(&self, _node_digest: &Word) -> Option<Arc<MastForest>> {
        // Empty MAST forest store
        None
    }

    fn on_event(
        &mut self,
        _process: &ProcessState<'_>,
        event_id: u32,
    ) -> impl Future<Output = Result<Vec<AdviceMutation>, EventError>> + Send {
        self.event_handler.push(event_id);
        async move { Ok(Vec::new()) }
    }
}
