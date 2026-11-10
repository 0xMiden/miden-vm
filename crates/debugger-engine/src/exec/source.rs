use alloc::{sync::Arc, vec::Vec};

use miden_assembly_syntax::ast::DebugVarInfo;
use miden_core::{
    mast::{MastNode, MastNodeId},
    operations::AssemblyOp,
};
use miden_mast_package::debug_info::{DebugSourceNode, DebugSourceNodeId, PackageDebugInfo};
use miden_processor::{Continuation, ResumeContext, operation::Operation};

use crate::debug::{ControlFlowOp, InlineCallFrame, inline_frames_for_operation};

/// Source metadata for one VM cycle, selected once for every debugger consumer.
pub(crate) struct SourceContext {
    pub cycle: CurrentCycleInfo,
    debug_info: Option<Arc<PackageDebugInfo>>,
    inline_frames: Vec<InlineCallFrame>,
}

impl SourceContext {
    /// Selects the cycle metadata against the context's own debug info.
    #[cfg(any(test, feature = "dap"))]
    pub fn new(context: &ResumeContext) -> Self {
        Self::with_debug_info(context, context.debug_info())
    }

    /// Selects the cycle metadata against `debug_info` instead of the context's own, which a
    /// context built from a bare program does not have before its first step.
    pub fn with_debug_info(
        context: &ResumeContext,
        debug_info: Option<Arc<PackageDebugInfo>>,
    ) -> Self {
        let cycle = extract_cycle(context, debug_info.as_deref());
        let inline_frames = inline_frames_for_operation(
            debug_info
                .as_deref()
                .zip(cycle.source_node_id)
                .map(|(info, source)| (info, source, cycle.op_idx.unwrap_or_default() as u32)),
            context.inherited_inline_call_contexts(),
        );
        Self {
            cycle,
            debug_info,
            inline_frames,
        }
    }

    pub fn debug_info(&self) -> Option<&Arc<PackageDebugInfo>> {
        self.debug_info.as_ref()
    }

    pub fn source_node(&self) -> Option<&DebugSourceNode> {
        let info = self.debug_info.as_deref()?;
        info.source_node(self.cycle.source_node_id?)
    }

    pub fn source_operation(&self) -> Option<(DebugSourceNodeId, u32)> {
        Some((self.cycle.source_node_id?, self.cycle.op_idx.unwrap_or_default() as u32))
    }

    /// The current source location, including the first operation on control-flow cycles.
    pub fn asmop(&self) -> Option<AssemblyOp> {
        self.source_node()?
            .asm_op_for_operation(self.cycle.op_idx.unwrap_or_default() as u32)?
            .to_assembly_op(self.debug_info.as_deref()?)
    }

    /// Operation-indexed metadata used by DAP stepping. SPAN/END cycles have no such operation;
    /// RESPAN retains its operation index, matching variable-event timing.
    #[cfg(any(feature = "dap", test))]
    pub fn executed_asmop(&self) -> Option<AssemblyOp> {
        self.cycle.op_idx?;
        self.asmop()
    }

    pub fn inline_frames(&self) -> &[InlineCallFrame] {
        &self.inline_frames
    }

    pub fn debug_vars(&self) -> Vec<DebugVarInfo> {
        let Some(((node, operation), info)) =
            self.source_node().zip(self.cycle.op_idx).zip(self.debug_info.as_deref())
        else {
            return Vec::new();
        };
        node.debug_infos_for_operation(operation as u32, info).collect()
    }
}

/// What the next continuation executes, as far as the forest and the debug info tell.
#[derive(Clone, Copy)]
pub(crate) struct CurrentCycleInfo {
    /// The operation the cycle executes; `None` on a control-flow cycle.
    pub op: Option<Operation>,
    /// The MAST node the cycle works on; `None` for a forest switch and when there is no
    /// continuation to run.
    pub exec_node: Option<MastNodeId>,
    /// The source occurrence of the node, when the debug info has one.
    pub source_node_id: Option<DebugSourceNodeId>,
    /// Whether `source_node_id` is the unique source root of the node rather than the
    /// occurrence the processor tracks: the processor tracks none for a context built from a
    /// bare program before its first step, and none at all for an invocation whose entry root
    /// it could not pick.
    pub source_node_inferred: bool,
    /// The padded index of the operation within its basic block; on a `RESPAN` cycle the
    /// index of the next batch's first operation.
    pub op_idx: Option<usize>,
    /// The control-flow operation of the cycle, when it is one the call stack tracks.
    pub control_flow_kind: Option<ControlFlowOp>,
}

/// Extract the current operation and assembly info from the continuation stack
/// before a step is executed. This lets us know what operation will run next.
pub(crate) fn extract_current_op(ctx: &ResumeContext) -> CurrentCycleInfo {
    extract_cycle(ctx, ctx.debug_info().as_deref())
}

fn extract_cycle(ctx: &ResumeContext, debug_info: Option<&PackageDebugInfo>) -> CurrentCycleInfo {
    let forest = ctx.current_forest();
    let continuation_stack = ctx.continuation_stack();
    for (cont, source_node_id) in
        continuation_stack.iter_continuations_for_next_clock_with_source_node_ids()
    {
        let exec_node = cont.exec_node();
        let tracked = source_node_id;
        // The processor tracks no source node before the first step of a context built from a
        // bare program, and none for an invocation whose entry root it could not pick; the
        // node's unique source root stands in, and the record says so.
        let source_node_id = tracked.or_else(|| {
            exec_node.zip(debug_info).and_then(|(exec_node, di)| {
                di.unique_source_root_for_exec_node(exec_node).ok().flatten()
            })
        });
        let source_node_inferred = tracked.is_none() && source_node_id.is_some();
        match cont {
            Continuation::ResumeBasicBlock {
                node_id,
                batch_index,
                op_idx_in_batch,
            } => {
                let MastNode::Block(block) = &forest[*node_id] else {
                    unreachable!()
                };
                // Compute global op index within the basic block
                let mut global_idx = 0;
                for batch in &block.op_batches()[..*batch_index] {
                    global_idx += batch.ops().len();
                }
                global_idx += op_idx_in_batch;
                let op = block.op_batches()[*batch_index].ops().get(*op_idx_in_batch).copied();
                return CurrentCycleInfo {
                    op,
                    exec_node,
                    source_node_id,
                    source_node_inferred,
                    op_idx: Some(global_idx),
                    control_flow_kind: None,
                };
            }
            Continuation::Respan {
                node_id,
                batch_index,
            } => {
                let node = &forest[*node_id];
                if let MastNode::Block(block) = node {
                    let mut global_idx = 0;
                    for batch in &block.op_batches()[..*batch_index] {
                        global_idx += batch.ops().len();
                    }
                    return CurrentCycleInfo {
                        op: None,
                        exec_node,
                        source_node_id,
                        source_node_inferred,
                        op_idx: Some(global_idx),
                        control_flow_kind: Some(ControlFlowOp::Respan),
                    };
                }
            }
            Continuation::StartNode(node_id) => {
                let control_flow_kind = match &forest[*node_id] {
                    MastNode::Block(_) => Some(ControlFlowOp::Span),
                    MastNode::Join(_) => Some(ControlFlowOp::Join),
                    MastNode::Split(_) => Some(ControlFlowOp::Split),
                    _ => None,
                };
                return CurrentCycleInfo {
                    op: None,
                    exec_node,
                    source_node_id,
                    source_node_inferred,
                    op_idx: None,
                    control_flow_kind,
                };
            }
            Continuation::FinishBasicBlock(_)
            | Continuation::FinishJoin(_)
            | Continuation::FinishSplit(_)
            | Continuation::FinishLoop { .. }
            | Continuation::FinishCall(_)
            | Continuation::FinishDyn(_) => {
                return CurrentCycleInfo {
                    op: None,
                    exec_node,
                    source_node_id,
                    source_node_inferred,
                    op_idx: None,
                    control_flow_kind: Some(ControlFlowOp::End),
                };
            }
            Continuation::EnterForest { .. } => {
                return CurrentCycleInfo {
                    op: None,
                    exec_node,
                    source_node_id,
                    source_node_inferred,
                    op_idx: None,
                    control_flow_kind: None,
                };
            }
        }
    }
    CurrentCycleInfo {
        op: None,
        exec_node: None,
        source_node_id: None,
        source_node_inferred: false,
        op_idx: None,
        control_flow_kind: None,
    }
}

#[cfg(test)]
mod tests;
