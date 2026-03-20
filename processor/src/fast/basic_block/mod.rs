use alloc::{sync::Arc, vec::Vec};
use core::ops::ControlFlow;

use miden_core::{
    events::{EventId, SystemEvent},
    mast::{BasicBlockNode, MastForest, MastNodeId},
};

use crate::{
    BaseHost, Host, SyncHost,
    errors::{MapExecErrWithOpIdx, advice_error_with_context, event_error_with_context},
    fast::{BreakReason, FastProcessor, HostAdapter},
};

mod sys_event_handlers;
pub use sys_event_handlers::SystemEventError;
use sys_event_handlers::handle_system_event;

impl FastProcessor {
    #[inline(always)]
    fn handle_system_event(
        &mut self,
        system_event: SystemEvent,
        current_forest: &MastForest,
        node_id: MastNodeId,
        host: &impl BaseHost,
        op_idx: usize,
    ) -> ControlFlow<BreakReason> {
        match handle_system_event(self, system_event).map_exec_err_with_op_idx(
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
    fn apply_host_event_mutations(
        &mut self,
        current_forest: &MastForest,
        node_id: MastNodeId,
        host: &impl BaseHost,
        event_id: EventId,
        mutations: Result<Vec<crate::advice::AdviceMutation>, crate::event::EventError>,
    ) -> ControlFlow<BreakReason> {
        let mutations = match mutations {
            Ok(mutations) => mutations,
            Err(err) => {
                let event_name = host.resolve_event(event_id).cloned();
                return ControlFlow::Break(BreakReason::Err(event_error_with_context(
                    err,
                    current_forest,
                    node_id,
                    host,
                    event_id,
                    event_name,
                )));
            },
        };

        match self.advice.apply_mutations(mutations) {
            Ok(()) => ControlFlow::Continue(()),
            Err(err) => ControlFlow::Break(BreakReason::Err(advice_error_with_context(
                err,
                current_forest,
                node_id,
                host,
            ))),
        }
    }

    /// Executes any decorator in a basic block that is to be executed after all operations in the
    /// block. This only differs from [`Self::execute_after_exit_decorators`] in that these
    /// decorators are stored in the basic block node itself.
    #[inline(always)]
    pub(super) fn execute_end_of_block_decorators(
        &self,
        basic_block_node: &BasicBlockNode,
        node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        host: &mut impl BaseHost,
    ) -> ControlFlow<BreakReason> {
        if self.should_execute_decorators() {
            #[cfg(test)]
            self.record_decorator_retrieval();

            let num_ops = basic_block_node.num_operations() as usize;
            for decorator in current_forest.decorators_for_op(node_id, num_ops) {
                self.execute_decorator(decorator, host)?;
            }
        }

        ControlFlow::Continue(())
    }

    #[inline(always)]
    pub(super) fn op_emit(
        &mut self,
        host: &mut impl SyncHost,
        current_forest: &MastForest,
        node_id: MastNodeId,
        op_idx: usize,
    ) -> ControlFlow<BreakReason> {
        let event_id = EventId::from_felt(self.stack_get(0));

        // If it's a system event, handle it directly. Otherwise, forward it to the host.
        if let Some(system_event) = SystemEvent::from_event_id(event_id) {
            return self.handle_system_event(system_event, current_forest, node_id, host, op_idx);
        }

        let processor_state = self.state();
        let mutations = host.on_event(&processor_state);
        self.apply_host_event_mutations(current_forest, node_id, host, event_id, mutations)
    }

    #[inline(always)]
    pub(super) async fn op_emit_async(
        &mut self,
        host: &mut impl Host,
        current_forest: &MastForest,
        node_id: MastNodeId,
        op_idx: usize,
    ) -> ControlFlow<BreakReason> {
        let event_id = EventId::from_felt(self.stack_get(0));

        if let Some(system_event) = SystemEvent::from_event_id(event_id) {
            let host_adapter = HostAdapter::new(host);
            return self.handle_system_event(
                system_event,
                current_forest,
                node_id,
                &host_adapter,
                op_idx,
            );
        }

        let processor_state = self.state();
        let mutations = host.on_event(&processor_state).await;
        let host_adapter = HostAdapter::new(host);
        self.apply_host_event_mutations(current_forest, node_id, &host_adapter, event_id, mutations)
    }
}
