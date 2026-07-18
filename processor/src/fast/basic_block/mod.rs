use alloc::vec::Vec;
use core::ops::ControlFlow;

use miden_core::events::{EventId, SystemEvent};
use miden_mast_package::debug_info::{DebugSourceNodeId, PackageDebugInfo};

use crate::{
    BaseHost, Host, SyncHost,
    advice::AdviceMutation,
    errors::{
        MapExecErrWithOpIdx, PackageSourceDebugContext, advice_error_with_context,
        advice_error_with_package_source_context, event_error_with_context,
        event_error_with_package_source_context,
    },
    event::EventError,
    fast::{BreakReason, FastProcessor},
    host::handlers::TraceError,
};

mod deferred_handlers;
mod sys_event_handlers;
pub use sys_event_handlers::SystemEventError;
use sys_event_handlers::handle_system_event;

impl FastProcessor {
    #[inline(always)]
    fn handle_system_event<F>(
        &mut self,
        system_event: SystemEvent,
        host: &impl BaseHost,
        op_idx: usize,
        package_debug_info: Option<&PackageDebugInfo>,
        source_node_id: Option<DebugSourceNodeId>,
    ) -> ControlFlow<BreakReason<F>> {
        let context = package_source_context(package_debug_info, source_node_id);
        match handle_system_event(self, system_event)
            .map_exec_err_with_package_source_op_idx(context, host, op_idx)
        {
            Ok(()) => ControlFlow::Continue(()),
            Err(err) => ControlFlow::Break(BreakReason::Err(err)),
        }
    }

    #[inline(always)]
    fn apply_host_event_mutations<F>(
        &mut self,
        host: &impl BaseHost,
        op_idx: usize,
        event_id: EventId,
        mutations: Result<Vec<AdviceMutation>, EventError>,
        package_debug_info: Option<&PackageDebugInfo>,
        source_node_id: Option<DebugSourceNodeId>,
    ) -> ControlFlow<BreakReason<F>> {
        let mutations = match mutations {
            Ok(mutations) => mutations,
            Err(err) => {
                let event_name = host.resolve_event(event_id).cloned();
                let context = package_source_context(package_debug_info, source_node_id);
                if let Some(context) = context {
                    return ControlFlow::Break(BreakReason::Err(
                        event_error_with_package_source_context(
                            err,
                            context,
                            host,
                            Some(op_idx),
                            event_id,
                            event_name,
                        ),
                    ));
                }
                return ControlFlow::Break(BreakReason::Err(event_error_with_context(
                    err, event_id, event_name,
                )));
            },
        };

        match self.advice.apply_mutations(mutations) {
            Ok(()) => ControlFlow::Continue(()),
            Err(err) => {
                let context = package_source_context(package_debug_info, source_node_id);
                let err = if let Some(context) = context {
                    advice_error_with_package_source_context(err, context, host, Some(op_idx))
                } else {
                    advice_error_with_context(err)
                };
                ControlFlow::Break(BreakReason::Err(err))
            },
        }
    }

    /// `trace_id` refers to the event defined by the user, which is on the stack below
    /// `SystemEvent::TraceEvent`.
    #[inline(always)]
    fn handle_trace_result<F>(
        &mut self,
        host: &impl BaseHost,
        op_idx: usize,
        trace_id: EventId,
        result: Result<(), TraceError>,
        package_debug_info: Option<&PackageDebugInfo>,
        source_node_id: Option<DebugSourceNodeId>,
    ) -> ControlFlow<BreakReason<F>> {
        match result {
            Ok(()) => ControlFlow::Continue(()),
            Err(err) => {
                let event_name = host.resolve_trace(trace_id).cloned();
                let context = package_source_context(package_debug_info, source_node_id);
                if let Some(context) = context {
                    return ControlFlow::Break(BreakReason::Err(
                        event_error_with_package_source_context(
                            err,
                            context,
                            host,
                            Some(op_idx),
                            trace_id,
                            event_name,
                        ),
                    ));
                }
                ControlFlow::Break(BreakReason::Err(event_error_with_context(
                    err, trace_id, event_name,
                )))
            },
        }
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

        match SystemEvent::from_event_id(event_id) {
            // `SystemEvent::TraceEvent` is forwarded to the hosts trace handler.
            Some(SystemEvent::TraceEvent) => {
                let processor_state = self.state();
                let result = host.on_trace(&processor_state);
                // The trace id is below `SystemEvent::TraceEvent`.
                let trace_id = EventId::from_felt(self.stack_get(1));
                self.handle_trace_result(
                    host,
                    op_idx,
                    trace_id,
                    result,
                    package_debug_info,
                    source_node_id,
                )
            },
            // Other system events are handled directly.
            Some(system_event) => self.handle_system_event(
                system_event,
                host,
                op_idx,
                package_debug_info,
                source_node_id,
            ),
            // If it's not a system event, forward it to the host.
            None => {
                let processor_state = self.state();
                let mutations = host.on_event(&processor_state);
                self.apply_host_event_mutations(
                    host,
                    op_idx,
                    event_id,
                    mutations,
                    package_debug_info,
                    source_node_id,
                )
            },
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

        match SystemEvent::from_event_id(event_id) {
            // `SystemEvent::TraceEvent` is forwarded to the hosts trace handler.
            Some(SystemEvent::TraceEvent) => {
                let processor_state = self.state();
                let result = host.on_trace(&processor_state).await;
                // The trace id is below `SystemEvent::TraceEvent`.
                let trace_id = EventId::from_felt(self.stack_get(1));
                self.handle_trace_result(
                    host,
                    op_idx,
                    trace_id,
                    result,
                    package_debug_info,
                    source_node_id,
                )
            },
            // Other system events are handled directly.
            Some(system_event) => self.handle_system_event(
                system_event,
                host,
                op_idx,
                package_debug_info,
                source_node_id,
            ),
            // If it's not a system event, forward it to the host.
            None => {
                let processor_state = self.state();
                let mutations = host.on_event(&processor_state).await;
                self.apply_host_event_mutations(
                    host,
                    op_idx,
                    event_id,
                    mutations,
                    package_debug_info,
                    source_node_id,
                )
            },
        }
    }
}

fn package_source_context(
    package_debug_info: Option<&PackageDebugInfo>,
    source_node_id: Option<DebugSourceNodeId>,
) -> Option<PackageSourceDebugContext<'_>> {
    Some(PackageSourceDebugContext::new_optional(package_debug_info?, source_node_id))
}
