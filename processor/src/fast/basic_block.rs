use alloc::sync::Arc;
use core::ops::ControlFlow;

use miden_core::{
    events::{EventId, SystemEvent},
    mast::{BasicBlockNode, MastForest, MastNodeId},
};

use crate::{
    Host,
    errors::{MapExecErr, advice_error_with_context, event_error_with_context},
    fast::{BreakReason, FastProcessor},
    operations::sys_ops::sys_event_handlers::handle_system_event,
};

impl FastProcessor {
    // Executes any decorators which have not been executed during span ops execution; this can
    // happen for decorators appearing after all operations in a block. these decorators are
    // executed after BASIC BLOCK is closed to make sure the VM clock cycle advances beyond the last
    // clock cycle of the BASIC BLOCK ops. For the linked case, check for decorators at an operation
    // index beyond the last operation
    #[inline(always)]
    pub(super) fn execute_end_of_block_decorators(
        &mut self,
        basic_block_node: &BasicBlockNode,
        node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        host: &mut impl Host,
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
    pub(super) async fn op_emit(
        &mut self,
        host: &mut impl Host,
        current_forest: &MastForest,
        node_id: MastNodeId,
    ) -> ControlFlow<BreakReason> {
        let mut process = self.state();
        let event_id = EventId::from_felt(process.get_stack_item(0));

        // If it's a system event, handle it directly. Otherwise, forward it to the host.
        if let Some(system_event) = SystemEvent::from_event_id(event_id) {
            if let Err(err) = handle_system_event(&mut process, system_event).map_exec_err(
                current_forest,
                node_id,
                host,
            ) {
                return ControlFlow::Break(BreakReason::Err(err));
            }
        } else {
            let mutations = match host.on_event(&process).await {
                Ok(m) => m,
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
            if let Err(err) = self.advice.apply_mutations(mutations) {
                return ControlFlow::Break(BreakReason::Err(advice_error_with_context(
                    err,
                    current_forest,
                    node_id,
                    host,
                )));
            }
        }
        ControlFlow::Continue(())
    }
}
