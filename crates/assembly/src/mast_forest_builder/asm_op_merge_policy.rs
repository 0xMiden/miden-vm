use alloc::{collections::BTreeMap, string::ToString, vec::Vec};

use miden_core::{
    mast::{AsmOpId, DebugInfo, MastNode, MastNodeId},
    operations::AssemblyOp,
    utils::IndexVec,
};

use super::{AsmOpRef, MastForestBuilderError, compute_operations_and_adjust_mappings};
use crate::diagnostics::Report;

pub(super) struct AsmOpMergePolicy<'a> {
    asm_op_by_ref: &'a IndexVec<AsmOpRef, AssemblyOp>,
    asm_op_id_by_ref: BTreeMap<AsmOpRef, AsmOpId>,
}

impl<'a> AsmOpMergePolicy<'a> {
    pub(super) fn new(asm_op_by_ref: &'a IndexVec<AsmOpRef, AssemblyOp>) -> Self {
        Self {
            asm_op_by_ref,
            asm_op_id_by_ref: BTreeMap::new(),
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
        if let Some(asm_op_id) = self.asm_op_id_by_ref.get(&asm_op_ref).copied() {
            return Ok(asm_op_id);
        }

        let asm_op_id = debug_info
            .add_asm_op(self.asm_op_by_ref[asm_op_ref].clone())
            .map_err(|source| Report::new(MastForestBuilderError::AddAsmOp { node_id, source }))?;
        self.asm_op_id_by_ref.insert(asm_op_ref, asm_op_id);

        Ok(asm_op_id)
    }
}
