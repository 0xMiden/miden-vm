use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use miden_core::{
    Word,
    mast::{BasicBlockNode, MastNode, MastNodeExt, MastNodeId, SubtreeIterator},
    operations::{AssemblyOp, DebugVarInfo},
};

use super::{
    MastForestBuilder, MastNodeRef, PendingMastNodeDraft, PendingMastNodeKind, truncate_index_vec,
};
use crate::diagnostics::Report;

struct StaticImportMetadata {
    asm_ops: Vec<(usize, AssemblyOp)>,
    debug_vars: Vec<(usize, DebugVarInfo)>,
}

enum StaticRootLookup {
    Found(MastNodeId),
    Ambiguous,
    Missing,
}

impl StaticImportMetadata {
    fn from_source(builder: &MastForestBuilder, source_node_id: MastNodeId) -> Self {
        let asm_ops = builder.pending_asm_ops_for_statically_linked_source(source_node_id);
        let debug_vars = builder.pending_debug_vars_for_statically_linked_source(source_node_id);
        Self { asm_ops, debug_vars }
    }
}

impl MastForestBuilder {
    /// Copies a statically linked node into this builder while keeping source metadata in the
    /// pending record when a new node is created.
    pub(super) fn ensure_node_from_statically_linked_source_ref(
        &mut self,
        source_node_id: MastNodeId,
        source_node: MastNode,
        child_refs: Vec<MastNodeRef>,
    ) -> Result<MastNodeRef, Report> {
        let digest = source_node.digest();
        let mut draft = PendingMastNodeDraft::new(
            PendingMastNodeKind::from_node(source_node),
            digest,
            child_refs,
        );
        let dedup_key = self.dedup_key_for_pending_data(&draft);
        if let Some(node_ref) = self.find_reusable_node_ref_by_key(&dedup_key, &draft) {
            return Ok(node_ref);
        }

        let metadata = StaticImportMetadata::from_source(self, source_node_id);
        let asm_op_checkpoint = self.asm_op_by_ref.len();
        let debug_var_checkpoint = self.debug_vars.len();
        draft.asm_ops = self.indexed_asm_op_refs(metadata.asm_ops)?;
        draft.debug_vars = match self.indexed_debug_var_refs(metadata.debug_vars) {
            Ok(debug_vars) => debug_vars,
            Err(err) => {
                truncate_index_vec(&mut self.asm_op_by_ref, asm_op_checkpoint);
                truncate_index_vec(&mut self.debug_vars, debug_var_checkpoint);
                return Err(err);
            },
        };

        self.insert_pending_node_with_allocated_metadata_refs(
            dedup_key,
            draft,
            asm_op_checkpoint,
            debug_var_checkpoint,
        )
    }

    fn pending_asm_ops_for_statically_linked_source(
        &self,
        source_node_id: MastNodeId,
    ) -> Vec<(usize, AssemblyOp)> {
        let asm_ops = self.unadjust_source_block_indices(
            source_node_id,
            self.statically_linked_mast.debug_info().asm_ops_for_node(source_node_id),
        );
        let statically_linked_mast = Arc::clone(&self.statically_linked_mast);
        asm_ops
            .into_iter()
            .filter_map(|(op_idx, asm_op_id)| {
                statically_linked_mast
                    .debug_info()
                    .asm_op(asm_op_id)
                    .cloned()
                    .map(|asm_op| (op_idx, asm_op))
            })
            .collect()
    }

    fn pending_debug_vars_for_statically_linked_source(
        &self,
        source_node_id: MastNodeId,
    ) -> Vec<(usize, DebugVarInfo)> {
        let debug_vars = self.unadjust_source_block_indices(
            source_node_id,
            self.statically_linked_mast.debug_info().debug_vars_for_node(source_node_id),
        );
        let statically_linked_mast = Arc::clone(&self.statically_linked_mast);
        debug_vars
            .into_iter()
            .filter_map(|(op_idx, var_id)| {
                statically_linked_mast
                    .debug_info()
                    .debug_var(var_id)
                    .cloned()
                    .map(|debug_var| (op_idx, debug_var))
            })
            .collect()
    }

    fn unadjust_source_block_indices<T: Copy>(
        &self,
        source_node_id: MastNodeId,
        mappings: Vec<(usize, T)>,
    ) -> Vec<(usize, T)> {
        if let MastNode::Block(block) = &self.statically_linked_mast[source_node_id] {
            BasicBlockNode::unadjust_asm_op_indices(mappings, block.op_batches())
        } else {
            mappings
        }
    }

    /// Collects builder-local refs for a statically linked source node.
    pub(super) fn pending_refs_for_statically_linked_source(
        &self,
        node: &MastNode,
        node_refs_by_source_id: &BTreeMap<MastNodeId, MastNodeRef>,
    ) -> Vec<MastNodeRef> {
        let mut child_refs = Vec::new();
        node.for_each_child(|source_child_id| {
            let child_ref = *node_refs_by_source_id
                .get(&source_child_id)
                .expect("statically linked child must be copied before its parent");
            child_refs.push(child_ref);
        });

        child_refs
    }

    /// Adds an externally-linked procedure root and returns its builder-local [`MastNodeRef`].
    pub(crate) fn ensure_external_link_with_source_ref(
        &mut self,
        mast_root: Word,
        source_library_commitment: Option<Word>,
        source_root_id: Option<MastNodeId>,
    ) -> Result<MastNodeRef, Report> {
        if let Some(root_id) =
            self.find_statically_linked_root(source_library_commitment, source_root_id, mast_root)
        {
            return self.copy_statically_linked_subtree_ref(root_id);
        }

        self.intern_pending_node(PendingMastNodeDraft::new(
            PendingMastNodeKind::External,
            mast_root,
            Vec::new(),
        ))
    }

    fn find_statically_linked_root(
        &self,
        source_library_commitment: Option<Word>,
        source_root_id: Option<MastNodeId>,
        mast_root: Word,
    ) -> Option<MastNodeId> {
        if let (Some(source_library_commitment), Some(source_root_id)) =
            (source_library_commitment, source_root_id)
        {
            match self.find_exact_statically_linked_root(
                source_library_commitment,
                source_root_id,
                mast_root,
            ) {
                StaticRootLookup::Found(root_id) => return Some(root_id),
                // `MastForest::commitment()` does not include diagnostics metadata, so multiple
                // source forests can share a commitment while still carrying different metadata.
                // Without a non-colliding package identity, an ambiguous exact lookup must not
                // fall back to digest-only linking because that can import the wrong source node.
                StaticRootLookup::Ambiguous => return None,
                StaticRootLookup::Missing => {},
            }
        }

        self.statically_linked_mast.find_procedure_root(mast_root)
    }

    fn find_exact_statically_linked_root(
        &self,
        source_library_commitment: Word,
        source_root_id: MastNodeId,
        mast_root: Word,
    ) -> StaticRootLookup {
        let Some(forest_indices) = self
            .statically_linked_forest_indices_by_commitment
            .get(&source_library_commitment)
        else {
            return StaticRootLookup::Missing;
        };

        let mut matching_roots = forest_indices.iter().filter_map(|forest_idx| {
            self.statically_linked_root_map
                .map_root(*forest_idx, &source_root_id)
                .filter(|root_id| self.statically_linked_mast[*root_id].digest() == mast_root)
        });

        let Some(root_id) = matching_roots.next() else {
            return StaticRootLookup::Missing;
        };

        if matching_roots.next().is_some() {
            StaticRootLookup::Ambiguous
        } else {
            StaticRootLookup::Found(root_id)
        }
    }

    /// Copies a subtree from the statically linked forest into the builder's forest.
    fn copy_statically_linked_subtree_ref(
        &mut self,
        root_id: MastNodeId,
    ) -> Result<MastNodeRef, Report> {
        let mut node_refs_by_source_id = BTreeMap::new();
        for old_id in SubtreeIterator::new(&root_id, &self.statically_linked_mast.clone()) {
            let node = self.statically_linked_mast[old_id].clone();
            let child_refs =
                self.pending_refs_for_statically_linked_source(&node, &node_refs_by_source_id);
            let new_ref =
                self.ensure_node_from_statically_linked_source_ref(old_id, node, child_refs)?;
            node_refs_by_source_id.insert(old_id, new_ref);
        }
        Ok(*node_refs_by_source_id
            .get(&root_id)
            .expect("statically linked subtree root must be copied"))
    }
}
