use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};

use miden_core::{
    advice::AdviceMap,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, DebugInfo, DynNodeBuilder, ExternalNodeBuilder,
        JoinNodeBuilder, LoopNodeBuilder, MastForest, MastForestContributor, MastForestError,
        MastNode, MastNodeBuilder, MastNodeId, SplitNodeBuilder,
    },
    operations::{AssemblyOp, DebugVarInfo},
    utils::IndexVec,
};

use super::{
    AsmOpMergePolicy, AsmOpRef, DebugMetadataMergePolicy, DebugVarRef, MastNodeRef,
    PendingMastNode, PendingMastNodeKind, PendingSourceMastNode, SourceDebugGraph, SourceMastNode,
    SourceMastNodeId, SourceMastNodeRef, compute_operations_and_adjust_mappings,
};
use crate::diagnostics::{Diagnostic, Report, miette};

/// Result of finalizing a [`super::MastForestBuilder`].
pub(crate) struct BuiltMastForest {
    mast_forest: MastForest,
    #[allow(dead_code)]
    source_graph: SourceDebugGraph,
    /// Final node IDs for builder refs retained in the finalized forest.
    node_id_by_ref: BTreeMap<MastNodeRef, MastNodeId>,
    /// Final source occurrence IDs for builder refs retained in the source graph.
    #[allow(dead_code)]
    source_id_by_ref: BTreeMap<SourceMastNodeRef, SourceMastNodeId>,
}

impl BuiltMastForest {
    pub(crate) fn into_parts(self) -> (MastForest, BTreeMap<MastNodeRef, MastNodeId>) {
        (self.mast_forest, self.node_id_by_ref)
    }

    #[allow(dead_code)]
    pub(crate) fn into_parts_with_source_graph(
        self,
    ) -> (
        MastForest,
        BTreeMap<MastNodeRef, MastNodeId>,
        SourceDebugGraph,
        BTreeMap<SourceMastNodeRef, SourceMastNodeId>,
    ) {
        (self.mast_forest, self.node_id_by_ref, self.source_graph, self.source_id_by_ref)
    }
}

/// Errors raised while converting builder-owned records into a finalized [`MastForest`].
#[derive(Debug, thiserror::Error, Diagnostic)]
pub(super) enum MastForestBuilderError {
    #[error("pending {node_kind} node {node_ref} has {actual} children, expected {expected}")]
    InvalidChildCount {
        node_ref: MastNodeRef,
        node_kind: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error(
        "pending {node_kind} node {node_ref} references child {child_ref} before the child was finalized"
    )]
    MissingFinalChild {
        node_ref: MastNodeRef,
        node_kind: &'static str,
        child_ref: MastNodeRef,
    },
    #[error("failed to build pending {node_kind} node {node_ref}: {source}")]
    BuildNode {
        node_ref: MastNodeRef,
        node_kind: &'static str,
        #[source]
        source: MastForestError,
    },
    #[error("failed to add finalized MAST node for pending node {node_ref}: {source}")]
    AddNode {
        node_ref: MastNodeRef,
        #[source]
        source: MastForestError,
    },
    #[error("failed to add assembly op metadata for node {node_id:?}: {source}")]
    AddAsmOp {
        node_id: MastNodeId,
        #[source]
        source: MastForestError,
    },
    #[error("failed to register assembly op metadata for node {node_id:?}: {source_msg}")]
    RegisterAsmOps { node_id: MastNodeId, source_msg: String },
    #[error("failed to add debug variable metadata for node {node_id:?}: {source}")]
    AddDebugVar {
        node_id: MastNodeId,
        #[source]
        source: MastForestError,
    },
    #[error("failed to register debug variable metadata for node {node_id:?}: {source_msg}")]
    RegisterDebugVars { node_id: MastNodeId, source_msg: String },
    #[error("procedure root {root_ref} was not retained in final MAST forest")]
    MissingProcedureRoot { root_ref: MastNodeRef },
    #[error(
        "source occurrence {source_ref} references child {child_ref} before the child was finalized"
    )]
    MissingFinalSourceChild {
        source_ref: SourceMastNodeRef,
        child_ref: SourceMastNodeRef,
    },
    #[error(
        "source occurrence {source_ref} references execution node {exec_ref} before it was finalized"
    )]
    MissingFinalSourceExec {
        source_ref: SourceMastNodeRef,
        exec_ref: MastNodeRef,
    },
    #[error("failed to add source occurrence {source_ref}: {source}")]
    AddSourceNode {
        source_ref: SourceMastNodeRef,
        #[source]
        source: MastForestError,
    },
    #[error("failed to finalize MAST forest: {source}")]
    FinalizeForest {
        #[source]
        source: MastForestError,
    },
}

/// Stateful finalization helper for converting live builder records into a [`MastForest`].
///
/// Methods are called in finalization order:
/// 1. materialize live nodes;
/// 2. register asm-op and debug-variable metadata for materialized node IDs;
/// 3. assemble the final forest.
///
/// The helper is private to finalization; keeping the order documented is sufficient because it is
/// not exposed as a reusable API.
pub(super) struct MastForestFinalizer {
    debug_info: DebugInfo,
    nodes: IndexVec<MastNodeId, MastNode>,
    node_id_by_ref: BTreeMap<MastNodeRef, MastNodeId>,
}

impl MastForestFinalizer {
    pub(super) fn new() -> Self {
        Self {
            debug_info: DebugInfo::new(),
            nodes: IndexVec::new(),
            node_id_by_ref: BTreeMap::new(),
        }
    }

    pub(super) fn materialize_live_nodes(
        &mut self,
        live_node_refs: &[MastNodeRef],
        pending_nodes: &IndexVec<MastNodeRef, PendingMastNode>,
    ) -> Result<(), Report> {
        for &node_ref in live_node_refs {
            let pending_node = &pending_nodes[node_ref];
            let builder =
                build_pending_node_with_final_ids(pending_node, node_ref, &self.node_id_by_ref)
                    .map_err(Report::new)?;

            let final_node_id =
                MastNodeId::new_unchecked(self.nodes.len().try_into().map_err(|_| {
                    Report::new(MastForestBuilderError::FinalizeForest {
                        source: MastForestError::TooManyNodes,
                    })
                })?);
            let node = builder.build_linked().map_err(|source| {
                Report::new(MastForestBuilderError::BuildNode {
                    node_ref,
                    node_kind: pending_node.kind.name(),
                    source,
                })
            })?;
            let inserted_node_id = self.nodes.push(node).map_err(|_| {
                Report::new(MastForestBuilderError::AddNode {
                    node_ref,
                    source: MastForestError::TooManyNodes,
                })
            })?;
            debug_assert_eq!(inserted_node_id, final_node_id);
            self.node_id_by_ref.insert(node_ref, final_node_id);
        }

        Ok(())
    }

    pub(super) fn register_live_asm_ops(
        &mut self,
        live_node_refs: &[MastNodeRef],
        pending_nodes: &IndexVec<MastNodeRef, PendingMastNode>,
        asm_op_by_ref: &IndexVec<AsmOpRef, AssemblyOp>,
    ) -> Result<(), Report> {
        let mut asm_op_policy = AsmOpMergePolicy::new(asm_op_by_ref);
        for &node_ref in live_node_refs {
            let pending_node = &pending_nodes[node_ref];
            if pending_node.asm_ops.is_empty() {
                continue;
            }

            let node_id = self.node_id_by_ref[&node_ref];
            asm_op_policy.register_node(
                &mut self.debug_info,
                &self.nodes[node_id],
                node_id,
                &pending_node.asm_ops,
            )?;
        }

        Ok(())
    }

    pub(super) fn register_live_debug_vars(
        &mut self,
        live_node_refs: &[MastNodeRef],
        pending_nodes: &IndexVec<MastNodeRef, PendingMastNode>,
        debug_vars: &IndexVec<DebugVarRef, DebugVarInfo>,
    ) -> Result<(), Report> {
        let mut debug_metadata_policy = DebugMetadataMergePolicy::new(debug_vars);
        for &node_ref in live_node_refs {
            let pending_node = &pending_nodes[node_ref];
            if pending_node.debug_vars.is_empty() {
                continue;
            }

            let node_id = self.node_id_by_ref[&node_ref];
            debug_metadata_policy.register_node(
                &mut self.debug_info,
                &self.nodes[node_id],
                node_id,
                &pending_node.debug_vars,
            )?;
        }

        Ok(())
    }

    pub(super) fn into_built_forest(
        mut self,
        procedure_root_refs: &[MastNodeRef],
        source_nodes: &IndexVec<SourceMastNodeRef, PendingSourceMastNode>,
        asm_op_by_ref: &IndexVec<AsmOpRef, AssemblyOp>,
        debug_vars: &IndexVec<DebugVarRef, DebugVarInfo>,
        advice_map: AdviceMap,
        error_codes: BTreeMap<u64, Arc<str>>,
    ) -> Result<BuiltMastForest, Report> {
        let mut roots = Vec::with_capacity(procedure_root_refs.len());
        for &root_ref in procedure_root_refs {
            let root_id = *self.node_id_by_ref.get(&root_ref).ok_or_else(|| {
                Report::new(MastForestBuilderError::MissingProcedureRoot { root_ref })
            })?;
            roots.push(root_id);
        }

        self.debug_info.extend_error_codes(error_codes);
        let (source_graph, source_id_by_ref) = self.finalize_source_graph(
            procedure_root_refs,
            source_nodes,
            asm_op_by_ref,
            debug_vars,
        )?;
        let mast_forest =
            MastForest::from_raw_parts(self.nodes, roots, advice_map, self.debug_info)
                .map_err(|source| Report::new(MastForestBuilderError::FinalizeForest { source }))?;

        Ok(BuiltMastForest {
            mast_forest,
            source_graph,
            node_id_by_ref: self.node_id_by_ref,
            source_id_by_ref,
        })
    }

    fn finalize_source_graph(
        &self,
        procedure_root_refs: &[MastNodeRef],
        source_nodes: &IndexVec<SourceMastNodeRef, PendingSourceMastNode>,
        asm_op_by_ref: &IndexVec<AsmOpRef, AssemblyOp>,
        debug_vars: &IndexVec<DebugVarRef, DebugVarInfo>,
    ) -> Result<(SourceDebugGraph, BTreeMap<SourceMastNodeRef, SourceMastNodeId>), Report> {
        let live_source_refs = source_nodes
            .as_slice()
            .iter()
            .enumerate()
            .filter_map(|(index, source_node)| {
                self.node_id_by_ref
                    .contains_key(&source_node.exec_ref)
                    .then_some(SourceMastNodeRef::from(index as u32))
            })
            .collect::<Vec<_>>();

        let mut source_id_by_ref = BTreeMap::new();
        for &source_ref in &live_source_refs {
            source_id_by_ref
                .insert(source_ref, SourceMastNodeId::from(source_id_by_ref.len() as u32));
        }

        let mut finalized_nodes = IndexVec::new();
        for &source_ref in &live_source_refs {
            let pending_source_node = &source_nodes[source_ref];
            let exec_node =
                *self.node_id_by_ref.get(&pending_source_node.exec_ref).ok_or_else(|| {
                    Report::new(MastForestBuilderError::MissingFinalSourceExec {
                        source_ref,
                        exec_ref: pending_source_node.exec_ref,
                    })
                })?;
            let children = pending_source_node
                .child_refs
                .iter()
                .map(|child_ref| {
                    source_id_by_ref.get(child_ref).copied().ok_or_else(|| {
                        Report::new(MastForestBuilderError::MissingFinalSourceChild {
                            source_ref,
                            child_ref: *child_ref,
                        })
                    })
                })
                .collect::<Result<Vec<_>, Report>>()?;
            let node = &self.nodes[exec_node];
            let (_, asm_op_refs) =
                compute_operations_and_adjust_mappings(node, pending_source_node.asm_ops.clone());
            let asm_ops = asm_op_refs
                .into_iter()
                .map(|(op_idx, asm_op_ref)| (op_idx, asm_op_by_ref[asm_op_ref].clone()))
                .collect();
            let (_, debug_var_refs) = compute_operations_and_adjust_mappings(
                node,
                pending_source_node.debug_vars.clone(),
            );
            let debug_vars = debug_var_refs
                .into_iter()
                .map(|(op_idx, debug_var_ref)| (op_idx, debug_vars[debug_var_ref].clone()))
                .collect();
            let inserted_id = finalized_nodes
                .push(SourceMastNode::new(exec_node, children, asm_ops, debug_vars))
                .map_err(|_| {
                    Report::new(MastForestBuilderError::AddSourceNode {
                        source_ref,
                        source: MastForestError::TooManyNodes,
                    })
                })?;
            debug_assert_eq!(inserted_id, source_id_by_ref[&source_ref]);
        }

        let roots = live_source_refs
            .iter()
            .filter_map(|source_ref| {
                let exec_ref = source_nodes[*source_ref].exec_ref;
                procedure_root_refs.contains(&exec_ref).then_some(source_id_by_ref[source_ref])
            })
            .collect();

        Ok((SourceDebugGraph::new(finalized_nodes, roots), source_id_by_ref))
    }
}

fn build_pending_node_with_final_ids(
    pending_node: &PendingMastNode,
    node_ref: MastNodeRef,
    final_node_id_by_ref: &BTreeMap<MastNodeRef, MastNodeId>,
) -> Result<MastNodeBuilder, MastForestBuilderError> {
    let builder = match &pending_node.kind {
        PendingMastNodeKind::BasicBlock { op_batches } => {
            ensure_child_count(node_ref, pending_node, 0)?;
            MastNodeBuilder::BasicBlock(BasicBlockNodeBuilder::from_op_batches_preserving_digest(
                op_batches.clone(),
                pending_node.digest,
            ))
        },
        PendingMastNodeKind::Join => {
            ensure_child_count(node_ref, pending_node, 2)?;
            let children = final_child_ids::<2>(node_ref, pending_node, final_node_id_by_ref)?;
            MastNodeBuilder::Join(JoinNodeBuilder::new(children).with_digest(pending_node.digest))
        },
        PendingMastNodeKind::Split => {
            ensure_child_count(node_ref, pending_node, 2)?;
            let branches = final_child_ids::<2>(node_ref, pending_node, final_node_id_by_ref)?;
            MastNodeBuilder::Split(SplitNodeBuilder::new(branches).with_digest(pending_node.digest))
        },
        PendingMastNodeKind::Loop => {
            ensure_child_count(node_ref, pending_node, 1)?;
            let [body] = final_child_ids::<1>(node_ref, pending_node, final_node_id_by_ref)?;
            MastNodeBuilder::Loop(LoopNodeBuilder::new(body).with_digest(pending_node.digest))
        },
        PendingMastNodeKind::Call { is_syscall } => {
            ensure_child_count(node_ref, pending_node, 1)?;
            let [callee] = final_child_ids::<1>(node_ref, pending_node, final_node_id_by_ref)?;
            let builder = if *is_syscall {
                CallNodeBuilder::new_syscall(callee)
            } else {
                CallNodeBuilder::new(callee)
            };
            MastNodeBuilder::Call(builder.with_digest(pending_node.digest))
        },
        PendingMastNodeKind::Dyn { is_dyncall } => {
            ensure_child_count(node_ref, pending_node, 0)?;
            let builder = if *is_dyncall {
                DynNodeBuilder::new_dyncall()
            } else {
                DynNodeBuilder::new_dyn()
            };
            MastNodeBuilder::Dyn(builder.with_digest(pending_node.digest))
        },
        PendingMastNodeKind::External => {
            ensure_child_count(node_ref, pending_node, 0)?;
            MastNodeBuilder::External(ExternalNodeBuilder::new(pending_node.digest))
        },
    };

    Ok(builder)
}

fn ensure_child_count(
    node_ref: MastNodeRef,
    pending_node: &PendingMastNode,
    expected: usize,
) -> Result<(), MastForestBuilderError> {
    let actual = pending_node.child_refs.len();
    if actual == expected {
        Ok(())
    } else {
        Err(MastForestBuilderError::InvalidChildCount {
            node_ref,
            node_kind: pending_node.kind.name(),
            expected,
            actual,
        })
    }
}

fn final_child_ids<const N: usize>(
    node_ref: MastNodeRef,
    pending_node: &PendingMastNode,
    final_node_id_by_ref: &BTreeMap<MastNodeRef, MastNodeId>,
) -> Result<[MastNodeId; N], MastForestBuilderError> {
    let node_kind = pending_node.kind.name();
    pending_node
        .child_refs
        .iter()
        .map(|child_ref| {
            final_node_id_by_ref.get(child_ref).copied().ok_or(
                MastForestBuilderError::MissingFinalChild {
                    node_ref,
                    node_kind,
                    child_ref: *child_ref,
                },
            )
        })
        .collect::<Result<Vec<_>, MastForestBuilderError>>()?
        .try_into()
        .map_err(|values: Vec<_>| MastForestBuilderError::InvalidChildCount {
            node_ref,
            node_kind,
            expected: N,
            actual: values.len(),
        })
}
