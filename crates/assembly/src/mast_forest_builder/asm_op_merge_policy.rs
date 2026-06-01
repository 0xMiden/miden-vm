use alloc::{string::ToString, vec::Vec};

use miden_core::{
    mast::{AsmOpId, DebugInfo, MastNode, MastNodeId},
    operations::AssemblyOp,
    utils::IndexVec,
};

use super::{
    AsmOpRef, MastForestBuilderError, MetadataRefAllocator, compute_operations_and_adjust_mappings,
};
use crate::diagnostics::Report;

/// Registers live assembly-op metadata while preserving ref-level deduplication.
pub(super) struct AsmOpMergePolicy<'a> {
    asm_op_ids: MetadataRefAllocator<'a, AsmOpRef, AssemblyOp, AsmOpId>,
}

impl<'a> AsmOpMergePolicy<'a> {
    pub(super) fn new(asm_op_by_ref: &'a IndexVec<AsmOpRef, AssemblyOp>) -> Self {
        Self {
            asm_op_ids: MetadataRefAllocator::new(asm_op_by_ref),
        }
    }

    pub(super) fn register_node(
        &mut self,
        debug_info: &mut DebugInfo,
        node: &MastNode,
        node_id: MastNodeId,
        asm_op_mappings: &[(usize, AsmOpRef)],
    ) -> Result<(), Report> {
        let (num_operations, adjusted_mappings) =
            compute_operations_and_adjust_mappings(node, asm_op_mappings.to_vec());
        let adjusted_mappings = adjusted_mappings
            .into_iter()
            .map(|(op_idx, asm_op_ref)| {
                self.asm_op_id(debug_info, node_id, asm_op_ref)
                    .map(|asm_op_id| (op_idx, asm_op_id))
            })
            .collect::<Result<Vec<_>, Report>>()?;

        debug_info
            .register_asm_ops(node_id, num_operations, adjusted_mappings)
            .map_err(|source| {
                Report::new(MastForestBuilderError::RegisterAsmOps {
                    node_id,
                    source_msg: source.to_string(),
                })
            })
    }

    fn asm_op_id(
        &mut self,
        debug_info: &mut DebugInfo,
        node_id: MastNodeId,
        asm_op_ref: AsmOpRef,
    ) -> Result<AsmOpId, Report> {
        self.asm_op_ids.get_or_insert(asm_op_ref, |asm_op| {
            debug_info
                .add_asm_op(asm_op)
                .map_err(|source| Report::new(MastForestBuilderError::AddAsmOp { node_id, source }))
        })
    }
}
