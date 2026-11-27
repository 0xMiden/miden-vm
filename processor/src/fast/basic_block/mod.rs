use alloc::vec::Vec;
use core::ops::ControlFlow;

use miden_core::events::{EventId, SystemEvent};
use miden_mast_package::debug_info::{DebugSourceNodeId, PackageDebugInfo};

use crate::{
    BaseHost, Host, ProcessorError, SyncHost,
    advice::AdviceMutation,
    errors::PackageSourceDebugContext,
    event::EventError,
    fast::{BreakReason, FastProcessor},
    host::handlers::TraceError,
};

mod deferred_handlers;
mod sys_event_handlers;
use sys_event_handlers::handle_system_event;

impl FastProcessor {
    #[inline(always)]
    fn apply_host_event_mutations(
        &mut self,
        host: &impl BaseHost,
        event_id: EventId,
        mutations: Result<Vec<AdviceMutation>, EventError>,
    ) -> Result<(), ProcessorError> {
        let mutations = mutations.map_err(|source| ProcessorError::Event {
            event_id,
            event_name: host.resolve_event(event_id).cloned(),
            source,
        })?;
        self.advice.apply_mutations(mutations)?;
        Ok(())
    }

    /// `trace_id` refers to the event defined by the user, which is on the stack below
    /// `SystemEvent::TraceEvent`.
    fn handle_trace_result(
        host: &impl BaseHost,
        trace_id: EventId,
        result: Result<(), TraceError>,
    ) -> Result<(), ProcessorError> {
        result.map_err(|source| ProcessorError::Event {
            event_id: trace_id,
            event_name: host.resolve_trace(trace_id).cloned(),
            source,
        })
    }

    #[inline(always)]
    pub(super) fn op_emit_sync<F>(
        &mut self,
        host: &mut impl SyncHost,
        op_idx: usize,
        package_debug_info: Option<&PackageDebugInfo>,
        source_node_id: Option<DebugSourceNodeId>,
    ) -> ControlFlow<BreakReason<F>> {
        let event_id = EventId::from_felt(self.stack_get(0));
        let result = match SystemEvent::from_event_id(event_id) {
            // `SystemEvent::TraceEvent` is forwarded to the host's trace handler.
            Some(SystemEvent::TraceEvent) => {
                let result = host.on_trace(&self.state());
                // The trace id is below `SystemEvent::TraceEvent`.
                let trace_id = EventId::from_felt(self.stack_get(1));
                Self::handle_trace_result(host, trace_id, result)
            },
            Some(system_event) => handle_system_event(self, system_event),
            None => {
                let mutations = host.on_event(&self.state());
                self.apply_host_event_mutations(host, event_id, mutations)
            },
        };
        match result {
            Ok(()) => ControlFlow::Continue(()),
            Err(err) => ControlFlow::Break(BreakReason::Err(err.with_context(
                package_source_context(package_debug_info, source_node_id),
                host,
                Some(op_idx),
            ))),
        }
    }

    #[inline(always)]
    pub(super) async fn op_emit<F>(
        &mut self,
        host: &mut impl Host,
        op_idx: usize,
        package_debug_info: Option<&PackageDebugInfo>,
        source_node_id: Option<DebugSourceNodeId>,
    ) -> ControlFlow<BreakReason<F>> {
        let event_id = EventId::from_felt(self.stack_get(0));
        let result = match SystemEvent::from_event_id(event_id) {
            Some(SystemEvent::TraceEvent) => {
                let processor_state = self.state();
                let result = host.on_trace(&processor_state).await;
                let trace_id = EventId::from_felt(self.stack_get(1));
                Self::handle_trace_result(host, trace_id, result)
            },
            Some(system_event) => handle_system_event(self, system_event),
            None => {
                let processor_state = self.state();
                let mutations = host.on_event(&processor_state).await;
                self.apply_host_event_mutations(host, event_id, mutations)
            },
        };
        match result {
            Ok(()) => ControlFlow::Continue(()),
            Err(err) => ControlFlow::Break(BreakReason::Err(err.with_context(
                package_source_context(package_debug_info, source_node_id),
                host,
                Some(op_idx),
            ))),
        }
    }
}

fn package_source_context(
    package_debug_info: Option<&PackageDebugInfo>,
    source_node_id: Option<DebugSourceNodeId>,
) -> Option<PackageSourceDebugContext<'_>> {
    Some(PackageSourceDebugContext::new_optional(package_debug_info?, source_node_id))
}
