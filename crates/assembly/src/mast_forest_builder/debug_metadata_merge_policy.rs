use alloc::{collections::BTreeMap, string::ToString, vec::Vec};

use miden_core::{
    mast::{DebugInfo, DebugVarId, MastNode, MastNodeId},
    operations::DebugVarInfo,
    utils::IndexVec,
};

use super::{DebugVarRef, MastForestBuilderError, compute_operations_and_adjust_mappings};
use crate::diagnostics::Report;

/// Registers live debug-variable metadata while preserving ref-level deduplication.
pub(super) struct DebugMetadataMergePolicy<'a> {
    debug_vars: &'a IndexVec<DebugVarRef, DebugVarInfo>,
    debug_var_id_by_ref: BTreeMap<DebugVarRef, DebugVarId>,
}

impl<'a> DebugMetadataMergePolicy<'a> {
    pub(super) fn new(debug_vars: &'a IndexVec<DebugVarRef, DebugVarInfo>) -> Self {
        Self {
            debug_vars,
            debug_var_id_by_ref: BTreeMap::new(),
        }
    }

    pub(super) fn register_node(
        &mut self,
        debug_info: &mut DebugInfo,
        node: &MastNode,
        node_id: MastNodeId,
        pending_debug_vars: &[(usize, DebugVarRef)],
    ) -> Result<(), Report> {
        let (_, pending_debug_vars) =
            compute_operations_and_adjust_mappings(node, pending_debug_vars.to_vec());
        let mut debug_var_ids = Vec::with_capacity(pending_debug_vars.len());
        for (op_idx, debug_var_ref) in pending_debug_vars {
            let debug_var_id = self.debug_var_id(debug_info, node_id, debug_var_ref)?;
            debug_var_ids.push((op_idx, debug_var_id));
        }

        debug_info
            .register_op_indexed_debug_vars(node_id, debug_var_ids)
            .map_err(|source| {
                Report::new(MastForestBuilderError::RegisterDebugVars {
                    node_id,
                    source_msg: source.to_string(),
                })
            })
    }

    fn debug_var_id(
        &mut self,
        debug_info: &mut DebugInfo,
        node_id: MastNodeId,
        debug_var_ref: DebugVarRef,
    ) -> Result<DebugVarId, Report> {
        if let Some(debug_var_id) = self.debug_var_id_by_ref.get(&debug_var_ref).copied() {
            return Ok(debug_var_id);
        }

        let debug_var_id = debug_info
            .add_debug_var(self.debug_vars[debug_var_ref].clone())
            .map_err(|source| {
                Report::new(MastForestBuilderError::AddDebugVar { node_id, source })
            })?;
        self.debug_var_id_by_ref.insert(debug_var_ref, debug_var_id);

        Ok(debug_var_id)
    }
}
