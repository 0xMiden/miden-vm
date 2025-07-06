use std::sync::Arc;

use processor::{
    AsyncHost, BaseHost, ErrorContext, ExecutionError, MastForest, ProcessState, SyncHost,
};
use prover::Word;
use vm_core::DebugOptions;

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
    fn get_mast_forest(&self, _node_digest: &Word) -> Option<Arc<MastForest>> {
        // Empty MAST forest store
        None
    }

    fn on_event(
        &mut self,
        _process: &mut ProcessState,
        event_id: u32,
        _err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        self.event_handler.push(event_id);
        Ok(())
    }
}

impl AsyncHost for TestHost {
    async fn get_mast_forest(&self, _node_digest: &Word) -> Option<Arc<MastForest>> {
        // Empty MAST forest store
        None
    }

    fn on_event(
        &mut self,
        _process: &mut ProcessState,
        event_id: u32,
        _err_ctx: &impl ErrorContext,
    ) -> impl Future<Output = Result<(), ExecutionError>> + Send {
        self.event_handler.push(event_id);

        async move { Ok(()) }
    }
}
