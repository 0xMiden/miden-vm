use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use miden_core::{
    Word,
    mast::{BasicBlockNode, MastForest, MastNode, MastNodeExt, MastNodeId, SubtreeIterator},
    operations::{AssemblyOp, DebugVarInfo},
};
use miden_mast_package::debug_info::{DebugSourceMastNodeId, PackageDebugInfo};

use super::{
    MastForestBuilder, MastNodeRef, PendingMastNodeDraft, PendingMastNodeKind, truncate_index_vec,
};
use crate::diagnostics::Report;

#[derive(Clone, Copy)]
struct StaticSourceRoot {
    forest_idx: usize,
    source_root_id: MastNodeId,
    source_debug_root_id: Option<DebugSourceMastNodeId>,
}

struct StaticLinkedRoot {
    root_id: MastNodeId,
    source: Option<StaticSourceRoot>,
}

#[derive(Default)]
pub(super) struct StaticSourceMetadata {
    asm_ops: Vec<(usize, AssemblyOp)>,
    debug_vars: Vec<(usize, DebugVarInfo)>,
}

/// Result of resolving an exact static-library root provenance hint.
enum StaticRootLookup {
    /// Exactly one linked source forest maps the hinted source root to the requested digest.
    Found(StaticLinkedRoot),
    /// More than one linked source forest matches the hint, so importing by provenance would risk
    /// selecting metadata from the wrong forest.
    Ambiguous,
    /// The hint did not match any linked source forest/root pair.
    Missing,
}

impl MastForestBuilder {
    /// Creates a complete [`PendingMastNodeDraft`] for a node imported from a statically
    /// linked forest, including indexed assembly ops and debug variable metadata.
    fn pending_draft_for_statically_linked_source(
        &mut self,
        source_forest: &MastForest,
        source_node_id: MastNodeId,
        source_node: MastNode,
        child_refs: Vec<MastNodeRef>,
        source_metadata: Option<StaticSourceMetadata>,
    ) -> Result<(PendingMastNodeDraft, usize, usize), Report> {
        let digest = source_node.digest();
        let kind = PendingMastNodeKind::from_node(source_node);
        let (asm_ops, debug_vars) = source_metadata
            .map(|metadata| (metadata.asm_ops, metadata.debug_vars))
            .unwrap_or_else(|| {
                (
                    self.pending_asm_ops_for_statically_linked_source(
                        source_forest,
                        source_node_id,
                    ),
                    self.pending_debug_vars_for_statically_linked_source(
                        source_forest,
                        source_node_id,
                    ),
                )
            });

        let asm_op_checkpoint = self.asm_op_by_ref.len();
        let debug_var_checkpoint = self.debug_vars.len();
        let indexed_asm_ops = self.indexed_asm_op_refs(asm_ops)?;
        let indexed_debug_vars = match self.indexed_debug_var_refs(debug_vars) {
            Ok(vars) => vars,
            Err(err) => {
                truncate_index_vec(&mut self.asm_op_by_ref, asm_op_checkpoint);
                truncate_index_vec(&mut self.debug_vars, debug_var_checkpoint);
                return Err(err);
            },
        };

        Ok((
            PendingMastNodeDraft {
                digest,
                kind,
                child_refs,
                asm_ops: indexed_asm_ops,
                debug_vars: indexed_debug_vars,
            },
            asm_op_checkpoint,
            debug_var_checkpoint,
        ))
    }

    /// Copies a statically linked node into this builder while keeping source metadata in the
    /// pending record when a new node is created.
    pub(super) fn ensure_node_from_statically_linked_source_ref(
        &mut self,
        source_forest: &MastForest,
        source_node_id: MastNodeId,
        source_node: MastNode,
        child_refs: Vec<MastNodeRef>,
        source_metadata: Option<StaticSourceMetadata>,
    ) -> Result<MastNodeRef, Report> {
        let (draft, asm_op_checkpoint, debug_var_checkpoint) = self
            .pending_draft_for_statically_linked_source(
                source_forest,
                source_node_id,
                source_node,
                child_refs,
                source_metadata,
            )?;
        let dedup_key = self.dedup_key_for_pending_data(&draft);
        let source_child_refs = self.source_child_refs_for_node_refs(&draft.child_refs);
        if let Some(node_ref) = self.find_reusable_node_ref_by_key(&dedup_key, &draft) {
            self.record_source_occurrence(node_ref, source_child_refs, &draft)?;
            return Ok(node_ref);
        }

        let node_ref = self.insert_pending_node_with_allocated_metadata_refs(
            dedup_key,
            draft.clone(),
            asm_op_checkpoint,
            debug_var_checkpoint,
        )?;
        self.record_source_occurrence(node_ref, source_child_refs, &draft)?;
        Ok(node_ref)
    }

    fn pending_asm_ops_for_statically_linked_source(
        &self,
        _source_forest: &MastForest,
        _source_node_id: MastNodeId,
    ) -> Vec<(usize, AssemblyOp)> {
        Vec::new()
    }

    fn pending_debug_vars_for_statically_linked_source(
        &self,
        _source_forest: &MastForest,
        _source_node_id: MastNodeId,
    ) -> Vec<(usize, DebugVarInfo)> {
        Vec::new()
    }

    fn unadjust_source_block_indices<T>(
        &self,
        source_forest: &MastForest,
        source_node_id: MastNodeId,
        mappings: Vec<(usize, T)>,
    ) -> Vec<(usize, T)> {
        if let Some(MastNode::Block(block)) = source_forest.get_node_by_id(source_node_id) {
            let unadjusted_indices = BasicBlockNode::unadjust_asm_op_indices(
                mappings.iter().map(|(op_idx, _)| (*op_idx, ())).collect(),
                block.op_batches(),
            );
            unadjusted_indices
                .into_iter()
                .zip(mappings)
                .map(|((op_idx, ()), (_, value))| (op_idx, value))
                .collect()
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
        source_debug_root_id: Option<DebugSourceMastNodeId>,
    ) -> Result<MastNodeRef, Report> {
        if let Some(linked_root) = self.find_statically_linked_root(
            source_library_commitment,
            source_root_id,
            source_debug_root_id,
            mast_root,
        ) {
            return self.copy_statically_linked_subtree_ref(linked_root);
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
        source_debug_root_id: Option<DebugSourceMastNodeId>,
        mast_root: Word,
    ) -> Option<StaticLinkedRoot> {
        if let (Some(source_library_commitment), Some(source_root_id)) =
            (source_library_commitment, source_root_id)
        {
            match self.find_exact_statically_linked_root(
                source_library_commitment,
                source_root_id,
                source_debug_root_id,
                mast_root,
            ) {
                StaticRootLookup::Found(linked_root) => return Some(linked_root),
                // `MastForest::commitment()` does not include diagnostics metadata, so multiple
                // source forests can share a commitment while still carrying different metadata.
                // Without a non-colliding package identity, an ambiguous exact lookup must not
                // fall back to digest-only linking because that can import the wrong source node.
                StaticRootLookup::Ambiguous => return None,
                StaticRootLookup::Missing => {},
            }
        }

        self.statically_linked_mast
            .find_procedure_root(mast_root)
            .map(|root_id| StaticLinkedRoot { root_id, source: None })
    }

    fn find_exact_statically_linked_root(
        &self,
        source_library_commitment: Word,
        source_root_id: MastNodeId,
        source_debug_root_id: Option<DebugSourceMastNodeId>,
        mast_root: Word,
    ) -> StaticRootLookup {
        let Some(forest_indices) = self
            .statically_linked_forest_indices_by_commitment
            .get(&source_library_commitment)
        else {
            return StaticRootLookup::Missing;
        };

        let mut matching_roots = forest_indices.iter().filter_map(|forest_idx| {
            self.statically_linked_root_map.map_root(*forest_idx, &source_root_id).and_then(
                |root_id| {
                    (self.statically_linked_mast[root_id].digest() == mast_root).then_some(
                        StaticLinkedRoot {
                            root_id,
                            source: Some(StaticSourceRoot {
                                forest_idx: *forest_idx,
                                source_root_id,
                                source_debug_root_id,
                            }),
                        },
                    )
                },
            )
        });

        let Some(linked_root) = matching_roots.next() else {
            return StaticRootLookup::Missing;
        };

        if matching_roots.next().is_some() {
            StaticRootLookup::Ambiguous
        } else {
            StaticRootLookup::Found(linked_root)
        }
    }

    /// Copies a subtree from the statically linked forest into the builder's forest.
    fn copy_statically_linked_subtree_ref(
        &mut self,
        linked_root: StaticLinkedRoot,
    ) -> Result<MastNodeRef, Report> {
        if let Some(source) = linked_root.source
            && let Some(package_debug_info) = self
                .statically_linked_package_debug_info
                .get(source.forest_idx)
                .cloned()
                .flatten()
            && let Some(source_forest) =
                self.statically_linked_source_forests.get(source.forest_idx)
        {
            let source_forest = Arc::clone(source_forest);
            let source_debug_root_id =
                if let Some(source_debug_root_id) = source.source_debug_root_id {
                    Some(source_debug_root_id)
                } else {
                    package_debug_info
                    .unique_source_root_for_exec_node(source.source_root_id)
                    .map_err(|err| {
                        Report::msg(format!(
                            "ambiguous statically linked source root for {source_root_id:?}: {err}",
                            source_root_id = source.source_root_id
                        ))
                    })?
                };
            if let Some(source_debug_root_id) = source_debug_root_id {
                let source_node =
                    package_debug_info.source_node(source_debug_root_id).ok_or_else(|| {
                        Report::msg(format!(
                            "statically linked package export references missing source node {source_debug_root_id:?}"
                        ))
                    })?;
                if source_node.exec_node != source.source_root_id {
                    return Err(Report::msg(format!(
                        "statically linked package export source node {source_debug_root_id:?} maps to {:?}, expected {:?}",
                        source_node.exec_node, source.source_root_id
                    )));
                }
                return self.copy_package_debug_source_subtree_ref(
                    source_forest.as_ref(),
                    &package_debug_info,
                    source_debug_root_id,
                );
            }
        }

        let mut node_refs_by_source_id = BTreeMap::new();
        let source_forest = Arc::clone(&self.statically_linked_mast);
        for old_id in SubtreeIterator::new(&linked_root.root_id, source_forest.as_ref()) {
            let node = self.statically_linked_mast[old_id].clone();
            let child_refs =
                self.pending_refs_for_statically_linked_source(&node, &node_refs_by_source_id);
            let new_ref = self.ensure_node_from_statically_linked_source_ref(
                source_forest.as_ref(),
                old_id,
                node,
                child_refs,
                None,
            )?;
            node_refs_by_source_id.insert(old_id, new_ref);
        }
        Ok(*node_refs_by_source_id
            .get(&linked_root.root_id)
            .expect("statically linked subtree root must be copied"))
    }

    fn copy_package_debug_source_subtree_ref(
        &mut self,
        source_forest: &MastForest,
        package_debug_info: &PackageDebugInfo,
        source_root_id: DebugSourceMastNodeId,
    ) -> Result<MastNodeRef, Report> {
        let mut node_refs_by_source_id = BTreeMap::new();
        self.copy_package_debug_source_node_ref(
            source_forest,
            package_debug_info,
            source_root_id,
            &mut node_refs_by_source_id,
        )
    }

    fn copy_package_debug_source_node_ref(
        &mut self,
        source_forest: &MastForest,
        package_debug_info: &PackageDebugInfo,
        source_node_id: DebugSourceMastNodeId,
        node_refs_by_source_id: &mut BTreeMap<DebugSourceMastNodeId, MastNodeRef>,
    ) -> Result<MastNodeRef, Report> {
        if let Some(node_ref) = node_refs_by_source_id.get(&source_node_id).copied() {
            return Ok(node_ref);
        }

        let source_node = package_debug_info.source_node(source_node_id).ok_or_else(|| {
            Report::msg(format!(
                "statically linked package debug graph is missing source node {source_node_id:?}"
            ))
        })?;

        let mut child_refs = Vec::new();
        for child_source_node_id in source_node.children.iter().copied() {
            child_refs.push(self.copy_package_debug_source_node_ref(
                source_forest,
                package_debug_info,
                child_source_node_id,
                node_refs_by_source_id,
            )?);
        }

        let source_exec_node_id = source_node.exec_node;
        let source_exec_node = source_forest
            .get_node_by_id(source_exec_node_id)
            .ok_or_else(|| {
                Report::msg(format!(
                    "statically linked package debug graph references missing execution node {source_exec_node_id:?}"
                ))
            })?
            .clone();
        let metadata = self.package_source_metadata(
            source_forest,
            package_debug_info,
            source_node_id,
            source_exec_node_id,
        );
        let node_ref = self.ensure_node_from_statically_linked_source_ref(
            source_forest,
            source_exec_node_id,
            source_exec_node,
            child_refs,
            Some(metadata),
        )?;
        node_refs_by_source_id.insert(source_node_id, node_ref);
        Ok(node_ref)
    }

    fn package_source_metadata(
        &self,
        source_forest: &MastForest,
        package_debug_info: &PackageDebugInfo,
        source_node_id: DebugSourceMastNodeId,
        source_exec_node_id: MastNodeId,
    ) -> StaticSourceMetadata {
        let asm_ops = package_debug_info
            .asm_ops_for_source_node(source_node_id)
            .map(|row| {
                (
                    row.op_idx as usize,
                    AssemblyOp::new(
                        row.location.clone(),
                        row.context_name.clone(),
                        row.num_cycles,
                        row.op.clone(),
                    ),
                )
            })
            .collect();
        let debug_vars = package_debug_info
            .debug_vars_for_source_node(source_node_id)
            .map(|row| (row.op_idx as usize, row.var.clone()))
            .collect();

        StaticSourceMetadata {
            asm_ops: self.unadjust_source_block_indices(
                source_forest,
                source_exec_node_id,
                asm_ops,
            ),
            debug_vars: self.unadjust_source_block_indices(
                source_forest,
                source_exec_node_id,
                debug_vars,
            ),
        }
    }
}
