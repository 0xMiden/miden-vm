use alloc::{boxed::Box, collections::BTreeMap, format, vec::Vec};
use core::fmt::Debug;

use miden_core::{
    advice::AdviceMap,
    mast::{
        BasicBlockNode, BasicBlockNodeBuilder, CallNodeBuilder, DynNodeBuilder,
        ExternalNodeBuilder, JoinNodeBuilder, LoopNodeBuilder, MastForest, MastForestContributor,
        MastForestError, MastNode, MastNodeBuilder, MastNodeId, SplitNodeBuilder,
    },
    utils::IndexVec,
};
use miden_mast_package::debug_info::{
    DebugFieldInfo, DebugFileIdx, DebugFileInfo, DebugFunctionIdx, DebugInfo, DebugInfoBuilder,
    DebugLoc, DebugLocIdx, DebugSourceAsmOp, DebugSourceInlineCall, DebugSourceNodeId,
    DebugSourceVar, DebugStringIdx, DebugTypeIdx, DebugTypeInfo, DebugVariantInfo, FunctionInfo,
    PackageDebugInfo, PackageDebugInfoBuilder, SourceNode,
};

use super::{
    MastNodeRef, PendingMastNode, PendingMastNodeKind, SourceNodeRef,
    compute_operations_and_adjust_mappings,
};
use crate::diagnostics::{Diagnostic, Report, miette};

/// Result of finalizing a [`super::MastForestBuilder`].
pub(crate) struct BuiltMastForest {
    mast_forest: MastForest,
    debug_info: Box<PackageDebugInfo>,
    /// Final node IDs for builder refs retained in the finalized forest.
    node_id_by_ref: BTreeMap<MastNodeRef, MastNodeId>,
    /// Final source occurrence IDs for builder refs retained in the source graph.
    source_id_by_ref: BTreeMap<SourceNodeRef, DebugSourceNodeId>,
}

impl BuiltMastForest {
    #[cfg(test)]
    pub(crate) fn into_parts(self) -> (MastForest, BTreeMap<MastNodeRef, MastNodeId>) {
        (self.mast_forest, self.node_id_by_ref)
    }

    pub(crate) fn into_parts_with_debug_info(
        self,
    ) -> (
        MastForest,
        BTreeMap<MastNodeRef, MastNodeId>,
        Box<PackageDebugInfo>,
        BTreeMap<SourceNodeRef, DebugSourceNodeId>,
    ) {
        (self.mast_forest, self.node_id_by_ref, self.debug_info, self.source_id_by_ref)
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
    #[error("procedure root {root_ref} was not retained in final MAST forest")]
    MissingProcedureRoot { root_ref: MastNodeRef },
    #[error(
        "source occurrence {source_ref} references child {child_ref} before the child was finalized"
    )]
    MissingFinalSourceChild {
        source_ref: SourceNodeRef,
        child_ref: SourceNodeRef,
    },
    #[error(
        "source occurrence {source_ref} references execution node {exec_ref} before it was finalized"
    )]
    MissingFinalSourceExec {
        source_ref: SourceNodeRef,
        exec_ref: MastNodeRef,
    },
    #[error("failed to add source occurrence {source_ref}: {source}")]
    AddSourceNode {
        source_ref: SourceNodeRef,
        #[source]
        source: MastForestError,
    },
    #[error("failed to finalize MAST forest: {source}")]
    FinalizeForest {
        #[source]
        source: MastForestError,
    },
}

#[derive(Default)]
struct FinalDebugInfoTableMap {
    strings: BTreeMap<DebugStringIdx, DebugStringIdx>,
    files: BTreeMap<DebugFileIdx, DebugFileIdx>,
    locations: BTreeMap<DebugLocIdx, DebugLocIdx>,
    types: BTreeMap<DebugTypeIdx, DebugTypeIdx>,
    functions: BTreeMap<DebugFunctionIdx, DebugFunctionIdx>,
}

fn remapped<K, V>(map: &BTreeMap<K, V>, index: K, table: &str) -> Result<V, Report>
where
    K: Copy + Debug + Ord,
    V: Copy,
{
    map.get(&index).copied().ok_or_else(|| {
        Report::msg(format!("debug info references missing {table} index {index:?}"))
    })
}

fn remap_debug_type(
    ty: &DebugTypeInfo,
    tables: &FinalDebugInfoTableMap,
) -> Result<DebugTypeInfo, Report> {
    Ok(match ty {
        DebugTypeInfo::Primitive(primitive) => DebugTypeInfo::Primitive(*primitive),
        DebugTypeInfo::Pointer { pointee_type_idx } => DebugTypeInfo::Pointer {
            pointee_type_idx: remapped(&tables.types, *pointee_type_idx, "type")?,
        },
        DebugTypeInfo::Array { element_type_idx, count } => DebugTypeInfo::Array {
            element_type_idx: remapped(&tables.types, *element_type_idx, "type")?,
            count: *count,
        },
        DebugTypeInfo::Struct { name_idx, size, fields } => DebugTypeInfo::Struct {
            name_idx: remapped(&tables.strings, *name_idx, "string")?,
            size: *size,
            fields: fields
                .iter()
                .map(|field| {
                    Ok(DebugFieldInfo {
                        name_idx: remapped(&tables.strings, field.name_idx, "string")?,
                        type_idx: remapped(&tables.types, field.type_idx, "type")?,
                        offset: field.offset,
                    })
                })
                .collect::<Result<_, Report>>()?,
        },
        DebugTypeInfo::Function { return_type_idx, param_type_indices } => {
            DebugTypeInfo::Function {
                return_type_idx: return_type_idx
                    .map(|index| remapped(&tables.types, index, "type"))
                    .transpose()?,
                param_type_indices: param_type_indices
                    .iter()
                    .map(|index| remapped(&tables.types, *index, "type"))
                    .collect::<Result<_, _>>()?,
            }
        },
        DebugTypeInfo::Enum {
            name_idx,
            size,
            discriminant_type_idx,
            variants,
        } => DebugTypeInfo::Enum {
            name_idx: remapped(&tables.strings, *name_idx, "string")?,
            size: *size,
            discriminant_type_idx: remapped(&tables.types, *discriminant_type_idx, "type")?,
            variants: variants
                .iter()
                .map(|variant| {
                    Ok(DebugVariantInfo {
                        name_idx: remapped(&tables.strings, variant.name_idx, "string")?,
                        type_idx: variant
                            .type_idx
                            .map(|index| remapped(&tables.types, index, "type"))
                            .transpose()?,
                        payload_offset: variant.payload_offset,
                        discriminant: variant.discriminant,
                    })
                })
                .collect::<Result<_, Report>>()?,
        },
        DebugTypeInfo::Unknown => DebugTypeInfo::Unknown,
    })
}

fn remap_debug_tables(
    source: &DebugInfo<MastNodeRef, SourceNodeRef>,
    target: &mut PackageDebugInfoBuilder,
) -> Result<FinalDebugInfoTableMap, Report> {
    let mut tables = FinalDebugInfoTableMap::default();

    for (index, string) in source.strings().iter().enumerate() {
        let old = DebugStringIdx::from(index as u32);
        tables.strings.insert(old, target.add_string(string.clone()));
    }

    // The pending type table may contain forward or cyclic references. The final builder is empty,
    // and pending builders already unique types, so preserve row indices exactly and pre-seed the
    // complete mapping before rewriting any type payloads.
    assert!(target.debug_info().types().is_empty());
    for index in 0..source.types().len() {
        let index = DebugTypeIdx::from(index as u32);
        tables.types.insert(index, index);
    }
    for (index, ty) in source.types().iter().enumerate() {
        let old = DebugTypeIdx::from(index as u32);
        let ty = remap_debug_type(ty, &tables)?;
        let inserted = target.add_type(ty);
        if inserted != tables.types[&old] {
            return Err(Report::msg(
                "pending debug type table could not be finalized without changing row indices",
            ));
        }
    }

    for (index, file) in source.files().iter().enumerate() {
        let old = DebugFileIdx::from(index as u32);
        let path_idx = remapped(&tables.strings, file.path_idx, "string")?;
        let file =
            DebugFileInfo::new(path_idx).with_checksum(file.checksum().copied().unwrap_or([0; 32]));
        tables.files.insert(old, target.add_file_info(file));
    }

    for (index, location) in source.locations().iter().enumerate() {
        let old = DebugLocIdx::from(index as u32);
        let location = DebugLoc {
            file_idx: remapped(&tables.files, location.file_idx, "file")?,
            start: location.start,
            end: location.end,
        };
        tables.locations.insert(old, target.add_location_info(location));
    }

    for error_message in source.error_messages() {
        let message = remapped(&tables.strings, error_message.message, "string")?;
        target.add_error_message_with_index(error_message.err_code, message);
    }

    Ok(tables)
}

/// Stateful finalization helper for converting live builder records into a [`MastForest`].
///
/// Methods are called in finalization order:
/// 1. materialize live nodes;
/// 2. finalize source/debug occurrence rows from builder-local source records;
/// 3. assemble the final forest.
///
/// The helper is private to finalization; keeping the order documented is sufficient because it is
/// not exposed as a reusable API.
pub(super) struct MastForestFinalizer {
    nodes: IndexVec<MastNodeId, MastNode>,
    node_id_by_ref: BTreeMap<MastNodeRef, MastNodeId>,
}

impl MastForestFinalizer {
    pub(super) fn new() -> Self {
        Self {
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

    pub(super) fn into_built_forest(
        self,
        procedure_root_refs: &[MastNodeRef],
        advice_map: AdviceMap,
        debug_info: DebugInfoBuilder<MastNodeRef, SourceNodeRef>,
    ) -> Result<BuiltMastForest, Report> {
        let Self { nodes, mut node_id_by_ref } = self;

        let mut roots = Vec::with_capacity(procedure_root_refs.len());
        for &root_ref in procedure_root_refs {
            let root_id = *node_id_by_ref.get(&root_ref).ok_or_else(|| {
                Report::new(MastForestBuilderError::MissingProcedureRoot { root_ref })
            })?;
            roots.push(root_id);
        }

        let (mast_forest, final_id_remapping) =
            MastForest::from_raw_parts_with_id_map(nodes, roots, advice_map)
                .map_err(|source| Report::new(MastForestBuilderError::FinalizeForest { source }))?;

        // Source/debug references were recorded against builder-local node IDs. Rewrite them to
        // the finalized dense IDs before constructing the debug graph.
        for node_id in node_id_by_ref.values_mut() {
            *node_id = final_id_remapping.get(*node_id).ok_or_else(|| {
                Report::new(MastForestBuilderError::FinalizeForest {
                    source: MastForestError::NodeIdOverflow(*node_id, final_id_remapping.len()),
                })
            })?;
        }

        let (debug_info, source_id_by_ref) =
            Self::finalize_source_graph(&mast_forest, &node_id_by_ref, debug_info)?;

        Ok(BuiltMastForest {
            mast_forest,
            debug_info,
            node_id_by_ref,
            source_id_by_ref,
        })
    }

    fn finalize_source_graph(
        mast_forest: &MastForest,
        node_id_by_ref: &BTreeMap<MastNodeRef, MastNodeId>,
        debug_info: DebugInfoBuilder<MastNodeRef, SourceNodeRef>,
    ) -> Result<(Box<PackageDebugInfo>, BTreeMap<SourceNodeRef, DebugSourceNodeId>), Report> {
        let source_debug_info = debug_info.build();
        let mut debug_info = PackageDebugInfoBuilder::default();
        let mut tables = remap_debug_tables(&source_debug_info, &mut debug_info)?;
        let live_source_refs = source_debug_info
            .nodes()
            .iter()
            .enumerate()
            .filter_map(|(index, source_node)| {
                node_id_by_ref
                    .contains_key(&source_node.exec_node)
                    .then_some(SourceNodeRef::from(index as u32))
            })
            .collect::<Vec<_>>();

        let mut source_id_by_ref = BTreeMap::new();
        for &source_ref in &live_source_refs {
            source_id_by_ref
                .insert(source_ref, DebugSourceNodeId::from(source_id_by_ref.len() as u32));
        }

        for &source_ref in &live_source_refs {
            let pending_source_node = &source_debug_info[source_ref];
            let exec_node =
                *node_id_by_ref.get(&pending_source_node.exec_node).ok_or_else(|| {
                    Report::new(MastForestBuilderError::MissingFinalSourceExec {
                        source_ref,
                        exec_ref: pending_source_node.exec_node,
                    })
                })?;
            let children = pending_source_node
                .children
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
            let node = &mast_forest[exec_node];
            let (_, asm_op_indices) = compute_operations_and_adjust_mappings(
                node,
                pending_source_node
                    .asm_ops
                    .iter()
                    .map(|asm_op| asm_op.op_idx as usize)
                    .collect(),
            );
            let asm_ops = pending_source_node
                .asm_ops
                .iter()
                .zip(asm_op_indices)
                .map(|(asm_op, op_idx)| {
                    let location_idx = asm_op
                        .location_idx
                        .map(|index| remapped(&tables.locations, index, "location"))
                        .transpose()?;
                    let context_name_idx =
                        remapped(&tables.strings, asm_op.context_name_idx, "string")?;
                    let op_name_idx = remapped(&tables.strings, asm_op.op_name_idx, "string")?;
                    Ok(DebugSourceAsmOp {
                        op_idx: u32::try_from(op_idx).unwrap(),
                        location_idx,
                        context_name_idx,
                        op_name_idx,
                        num_cycles: asm_op.num_cycles,
                    })
                })
                .collect::<Result<Vec<_>, Report>>()?;
            let (_, debug_var_indices) = compute_operations_and_adjust_mappings(
                node,
                pending_source_node.debug_vars.iter().map(|dv| dv.op_idx as usize).collect(),
            );
            let debug_vars = pending_source_node
                .debug_vars
                .iter()
                .zip(debug_var_indices)
                .map(|(debug_var, op_idx)| {
                    let location_idx = debug_var
                        .location_idx
                        .map(|index| remapped(&tables.locations, index, "location"))
                        .transpose()?;
                    let name_idx = remapped(&tables.strings, debug_var.name_idx, "string")?;
                    Ok(DebugSourceVar {
                        op_idx: u32::try_from(op_idx).unwrap(),
                        name_idx,
                        type_id: debug_var.type_id,
                        arg_idx: debug_var.arg_idx,
                        location_idx,
                        value_location: debug_var.value_location.clone(),
                    })
                })
                .collect::<Result<Vec<_>, Report>>()?;
            let (op_start, op_end) = adjust_source_op_range(
                node,
                pending_source_node.op_start as usize,
                pending_source_node.op_end as usize,
            );
            let inserted_id = debug_info
                .add_node(SourceNode {
                    exec_node,
                    children,
                    op_start: u32::try_from(op_start).unwrap(),
                    op_end: u32::try_from(op_end).unwrap(),
                    asm_ops,
                    debug_vars,
                    inline_calls: vec![],
                })
                .map_err(|_| {
                    Report::new(MastForestBuilderError::AddSourceNode {
                        source_ref,
                        source: MastForestError::TooManyNodes,
                    })
                })?;
            debug_assert_eq!(inserted_id, source_id_by_ref[&source_ref]);
        }

        for source_ref in source_debug_info.roots() {
            let Some(source_id) = source_id_by_ref.get(source_ref).copied() else {
                continue;
            };
            debug_info.add_root(source_id);
        }

        for (index, function) in source_debug_info.functions().iter().enumerate() {
            let old_function_idx = DebugFunctionIdx::from(index as u32);
            // A function can outlive its source occurrence when unreachable MAST is pruned. Keep
            // the function record anchored by its MAST root, but clear the stale source-node link.
            let source_node = function
                .source_node
                .and_then(|source_ref| source_id_by_ref.get(&source_ref).copied());
            let name_idx = remapped(&tables.strings, function.name_idx, "string")?;
            let linkage_name_idx = function
                .linkage_name_idx
                .map(|index| remapped(&tables.strings, index, "string"))
                .transpose()?;
            let file_idx = remapped(&tables.files, function.file_idx, "file")?;
            let type_idx = function
                .type_idx
                .map(|index| remapped(&tables.types, index, "type"))
                .transpose()?;
            let new_function_idx = debug_info.add_function(FunctionInfo {
                source_node,
                name_idx,
                linkage_name_idx,
                file_idx,
                line: function.line,
                column: function.column,
                type_idx,
                mast_root: function.mast_root,
            });
            tables.functions.insert(old_function_idx, new_function_idx);
        }

        for &source_ref in &live_source_refs {
            let pending_source_node = &source_debug_info[source_ref];
            if pending_source_node.inline_calls.is_empty() {
                continue;
            }

            let source_id = source_id_by_ref[&source_ref];
            let exec_node = debug_info[source_id].exec_node;
            let (_, inline_call_indices) = compute_operations_and_adjust_mappings(
                &mast_forest[exec_node],
                pending_source_node
                    .inline_calls
                    .iter()
                    .map(|inline_call| inline_call.op_idx as usize)
                    .collect(),
            );
            let inline_calls = pending_source_node
                .inline_calls
                .iter()
                .zip(inline_call_indices)
                .map(|(inline_call, op_idx)| {
                    Ok(DebugSourceInlineCall {
                        op_idx: u32::try_from(op_idx).unwrap(),
                        callee_idx: remapped(
                            &tables.functions,
                            inline_call.callee_idx,
                            "function",
                        )?,
                        loc_idx: remapped(&tables.locations, inline_call.loc_idx, "location")?,
                    })
                })
                .collect::<Result<Vec<_>, Report>>()?;
            debug_info[source_id].inline_calls = inline_calls;
        }

        Ok((debug_info.build(), source_id_by_ref))
    }
}

fn adjust_source_op_range(node: &MastNode, op_start: usize, op_end: usize) -> (usize, usize) {
    if op_start == op_end {
        return (op_start, op_end);
    }

    match node {
        MastNode::Block(block) => {
            let adjusted = BasicBlockNode::adjust_asm_op_indices(
                vec![op_start, op_end - 1],
                block.op_batches(),
            );
            (adjusted[0], adjusted[1] + 1)
        },
        _ => (op_start, op_end),
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
