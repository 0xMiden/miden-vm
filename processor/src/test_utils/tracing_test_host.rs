use alloc::{sync::Arc, vec::Vec};

use miden_debug_types::{DefaultSourceManager, Location, SourceFile, SourceManager, SourceSpan};

use crate::{
    BaseHost, LoadedMastForest, ProcessorState, SyncHost, Word, advice::AdviceMutation,
    event::EventError, host::handlers::TraceError,
};

/// A minimal testing host that records trace events.
///
/// Intended only for running self-contained programs built directly from source. It resolves no
/// external MAST forests, loads no kernels, and produces no advice mutations.
///
/// Trace events are triggered by emitting `SystemEvent::TraceEvent` identifier and the id of the
/// trace event is expected below that on the stack.
#[derive(Debug, Clone)]
pub struct TracingTestHost {
    /// Regular host event IDs received via [`SyncHost::on_event`], in emission order.
    pub events: Vec<u32>,
    /// Trace event IDs received via [`SyncHost::on_trace`], in emission order.
    pub traces: Vec<u32>,
    source_manager: Arc<DefaultSourceManager>,
}

impl TracingTestHost {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            traces: Vec::new(),
            source_manager: Arc::new(DefaultSourceManager::default()),
        }
    }
}

impl Default for TracingTestHost {
    fn default() -> Self {
        Self::new()
    }
}

impl BaseHost for TracingTestHost {
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        let maybe_file = self.source_manager.get_by_uri(location.uri());
        let span = self.source_manager.location_to_span(location.clone()).unwrap_or_default();
        (span, maybe_file)
    }
}

impl SyncHost for TracingTestHost {
    fn get_mast_forest(&self, _node_digest: &Word) -> Option<LoadedMastForest> {
        // This host only runs self-contained programs; external MAST forests are not resolved.
        None
    }

    fn on_event(&mut self, process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        let event_id: u32 = process.get_stack_item(0).as_canonical_u64().try_into().unwrap();
        self.events.push(event_id);
        Ok(Vec::new())
    }

    fn on_trace(&mut self, process: &ProcessorState) -> Result<(), TraceError> {
        let trace_event_id: u32 = process.get_stack_item(1).as_canonical_u64().try_into().unwrap();
        self.traces.push(trace_event_id);
        Ok(())
    }
}

/// A minimal testing host that records regular events.
///
/// It does *not* implement `on_trace`, to represent hosts in the wild which might not implement
/// it either. Still they must be able to handle traces without error, by way of the no-op default
/// implementation of `on_trace`.
///
/// Intended only for running self-contained programs built directly from source. It resolves no
/// external MAST forests, loads no kernels, and produces no advice mutations.
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct NonTracingTestHost {
    /// Regular host event IDs received via [`SyncHost::on_event`], in emission order.
    pub events: Vec<u32>,
    source_manager: Arc<DefaultSourceManager>,
}

#[cfg(test)]
impl NonTracingTestHost {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            source_manager: Arc::new(DefaultSourceManager::default()),
        }
    }
}

#[cfg(test)]
impl Default for NonTracingTestHost {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl BaseHost for NonTracingTestHost {
    fn get_label_and_source_file(
        &self,
        location: &Location,
    ) -> (SourceSpan, Option<Arc<SourceFile>>) {
        let maybe_file = self.source_manager.get_by_uri(location.uri());
        let span = self.source_manager.location_to_span(location.clone()).unwrap_or_default();
        (span, maybe_file)
    }
}

#[cfg(test)]
impl SyncHost for NonTracingTestHost {
    fn get_mast_forest(&self, _node_digest: &Word) -> Option<LoadedMastForest> {
        // This host only runs self-contained programs; external MAST forests are not resolved.
        None
    }

    fn on_event(&mut self, process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        let event_id: u32 = process.get_stack_item(0).as_canonical_u64().try_into().unwrap();
        self.events.push(event_id);
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use miden_assembly::Assembler;

    use super::NonTracingTestHost;
    use crate::{AdviceInputs, ExecutionOptions, Program, StackInputs, event::SystemEvent};

    /// A host which does not implement `on_trace` should still execute trace events gracefully via
    /// the default no-op implementation, and trace events must not be routed to `on_event`.
    #[test]
    fn non_tracing_host_ignores_trace_events() {
        const REGULAR_EVENT_ID_1: u32 = 3000;
        const REGULAR_EVENT_ID_2: u32 = 4000;
        const TRACE_ID: u32 = 1000;
        let trace_sys_event_id = SystemEvent::TraceEvent.event_id().as_u64();

        let source = format!(
            "\
    begin
        push.{REGULAR_EVENT_ID_1}
        emit
        drop
        push.{TRACE_ID}
        push.{trace_sys_event_id}
        emit
        drop
        drop
        push.{REGULAR_EVENT_ID_2}
        emit
        drop
    end"
        );
        let program: Program = Assembler::default()
            .assemble_program("program", &source)
            .unwrap()
            .unwrap_program();
        let mut host = NonTracingTestHost::default();
        crate::execute_sync(
            &program,
            StackInputs::default(),
            AdviceInputs::default(),
            &mut host,
            ExecutionOptions::default(),
        )
        .unwrap();

        assert_eq!(host.events, vec![REGULAR_EVENT_ID_1, REGULAR_EVENT_ID_2]);
    }
}
