use alloc::vec::Vec;
use core::ops::ControlFlow;

use miden_core::{
    events::{EventId, SystemEvent},
    mast::{ExecutableMastForest, MastNodeId},
};
use miden_mast_package::debug_info::{DebugSourceMastNodeId, PackageDebugInfo};

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
};

mod sys_event_handlers;
pub use sys_event_handlers::SystemEventError;
use sys_event_handlers::handle_system_event;

impl FastProcessor {
    #[inline(always)]
    fn handle_system_event<F>(
        &mut self,
        system_event: SystemEvent,
        current_forest: &F,
        node_id: MastNodeId,
        host: &impl BaseHost,
        op_idx: usize,
        package_debug_info: Option<&PackageDebugInfo>,
        source_node: Option<DebugSourceMastNodeId>,
    ) -> ControlFlow<BreakReason<F>>
    where
        F: ExecutableMastForest,
    {
        let context = package_source_context(package_debug_info, source_node);
        match handle_system_event(self, system_event).map_exec_err_with_package_source_op_idx(
            context,
            current_forest,
            node_id,
            host,
            op_idx,
        ) {
            Ok(()) => ControlFlow::Continue(()),
            Err(err) => ControlFlow::Break(BreakReason::Err(err)),
        }
    }

    #[inline(always)]
    fn apply_host_event_mutations<F>(
        &mut self,
        current_forest: &F,
        node_id: MastNodeId,
        host: &impl BaseHost,
        op_idx: usize,
        event_id: EventId,
        mutations: Result<Vec<AdviceMutation>, EventError>,
        package_debug_info: Option<&PackageDebugInfo>,
        source_node: Option<DebugSourceMastNodeId>,
    ) -> ControlFlow<BreakReason<F>>
    where
        F: ExecutableMastForest,
    {
        let mutations = match mutations {
            Ok(mutations) => mutations,
            Err(err) => {
                let event_name = host.resolve_event(event_id).cloned();
                let context = package_source_context(package_debug_info, source_node);
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
                    err,
                    current_forest,
                    node_id,
                    host,
                    Some(op_idx),
                    event_id,
                    event_name,
                )));
            },
        };

        match self.advice.apply_mutations(mutations) {
            Ok(()) => ControlFlow::Continue(()),
            Err(err) => {
                let context = package_source_context(package_debug_info, source_node);
                let err = if let Some(context) = context {
                    advice_error_with_package_source_context(err, context, host, Some(op_idx))
                } else {
                    advice_error_with_context(err, current_forest, node_id, host, Some(op_idx))
                };
                ControlFlow::Break(BreakReason::Err(err))
            },
        }
    }

    #[inline(always)]
    pub(super) fn op_emit_sync<F>(
        &mut self,
        host: &mut impl SyncHost,
        current_forest: &F,
        node_id: MastNodeId,
        op_idx: usize,
        package_debug_info: Option<&PackageDebugInfo>,
        source_node: Option<DebugSourceMastNodeId>,
    ) -> ControlFlow<BreakReason<F>>
    where
        F: ExecutableMastForest,
    {
        let event_id = EventId::from_felt(self.stack_get(0));

        // If it's a system event, handle it directly. Otherwise, forward it to the host.
        if let Some(system_event) = SystemEvent::from_event_id(event_id) {
            return self.handle_system_event(
                system_event,
                current_forest,
                node_id,
                host,
                op_idx,
                package_debug_info,
                source_node,
            );
        }

        let processor_state = self.state();
        let mutations = host.on_event(&processor_state);
        self.apply_host_event_mutations(
            current_forest,
            node_id,
            host,
            op_idx,
            event_id,
            mutations,
            package_debug_info,
            source_node,
        )
    }

    #[inline(always)]
    pub(super) async fn op_emit<F>(
        &mut self,
        host: &mut impl Host,
        current_forest: &F,
        node_id: MastNodeId,
        op_idx: usize,
        package_debug_info: Option<&PackageDebugInfo>,
        source_node: Option<DebugSourceMastNodeId>,
    ) -> ControlFlow<BreakReason<F>>
    where
        F: ExecutableMastForest,
    {
        let event_id = EventId::from_felt(self.stack_get(0));

        if let Some(system_event) = SystemEvent::from_event_id(event_id) {
            return self.handle_system_event(
                system_event,
                current_forest,
                node_id,
                host,
                op_idx,
                package_debug_info,
                source_node,
            );
        }

        let processor_state = self.state();
        let mutations = host.on_event(&processor_state).await;
        self.apply_host_event_mutations(
            current_forest,
            node_id,
            host,
            op_idx,
            event_id,
            mutations,
            package_debug_info,
            source_node,
        )
    }
}

fn package_source_context(
    package_debug_info: Option<&PackageDebugInfo>,
    source_node: Option<DebugSourceMastNodeId>,
) -> Option<PackageSourceDebugContext<'_>> {
    Some(PackageSourceDebugContext::new(package_debug_info?, source_node?))
}
