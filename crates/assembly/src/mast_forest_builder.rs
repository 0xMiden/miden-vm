use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};
use core::ops::Index;

use miden_core::{
    Felt, Word,
    advice::AdviceMap,
    mast::{
        AsmOpId, BasicBlockNode, BasicBlockNodeBuilder, ExternalNodeBuilder, JoinNodeBuilder,
        MastForest, MastForestContributor, MastNode, MastNodeBuilder, MastNodeExt, MastNodeId,
        Remapping, SubtreeIterator,
    },
    operations::{AssemblyOp, Operation},
};

use super::{GlobalItemIndex, LinkerError, Procedure};
use crate::{
    diagnostics::{IntoDiagnostic, Report, WrapErr},
    report,
};

// CONSTANTS
// ================================================================================================

/// Constant that decides how many operation batches disqualify a procedure from inlining.
const PROCEDURE_INLINING_THRESHOLD: usize = 32;

// MAST FOREST BUILDER
// ================================================================================================

/// Builder for a [`MastForest`].
///
/// The purpose of the builder is to ensure that the underlying MAST forest contains as little
/// information as possible needed to adequately describe the logical MAST forest. Specifically:
/// - The builder ensures that only one copy of nodes that have the same MAST root is added to the
///   MAST forest (i.e., two nodes that have the same MAST root will have the same [`MastNodeId`]).
/// - The builder tries to merge adjacent basic blocks and eliminate the source block whenever this
///   does not have an impact on other nodes in the forest.
#[derive(Clone, Debug, Default)]
pub struct MastForestBuilder {
    /// The MAST forest being built by this builder; this MAST forest is up-to-date - i.e., all
    /// nodes added to the MAST forest builder are also immediately added to the underlying MAST
    /// forest.
    pub(crate) mast_forest: MastForest,
    /// A map of all procedures added to the MAST forest indexed by their global procedure ID.
    /// This includes all local, exported, and re-exported procedures. In case multiple procedures
    /// with the same digest are added to the MAST forest builder, only the first procedure is
    /// added to the map, and all subsequent insertions are ignored.
    procedures: BTreeMap<GlobalItemIndex, Procedure>,
    /// A map from procedure MAST root to its global procedure index. Similar to the `procedures`
    /// map, this map contains only the first inserted procedure for procedures with the same MAST
    /// root.
    proc_gid_by_mast_root: BTreeMap<Word, GlobalItemIndex>,
    /// A map of MAST node digests to their corresponding positions in the MAST forest.
    node_id_by_digest: BTreeMap<Word, MastNodeId>,
    /// A set of IDs for basic blocks which have been merged into a bigger basic blocks. This is
    /// used as a candidate set of nodes that may be eliminated if the are not referenced by any
    /// other node in the forest and are not a root of any procedure.
    merged_basic_block_ids: BTreeSet<MastNodeId>,
    /// A MastForest that contains the MAST of all statically-linked libraries, it's used to find
    /// precompiled procedures and copy their subtrees instead of inserting external nodes.
    statically_linked_mast: Arc<MastForest>,
    /// Keeps track of the new ids assigned to nodes that are copied from the MAST of
    /// statically-linked libraries.
    statically_linked_mast_remapping: Remapping,
    /// Pending AssemblyOp mappings to be registered at build time.
    ///
    /// These are collected during assembly and registered all at once in sorted node order
    /// when `build()` is called. This is necessary because the CSR structure requires nodes
    /// to be added in sequential order, but nodes may be created in any order during assembly.
    pending_asm_op_mappings: Vec<(MastNodeId, Vec<(usize, AsmOpId)>)>,
    /// Pending debug variable mappings to be registered at build time.
    ///
    /// Like `pending_asm_op_mappings`, these are collected during assembly and registered all
    /// at once in sorted node order when `build()` is called. This avoids the crash that
    /// occurs when `register_debug_vars_for_node` is called with an out-of-order node ID
    /// (which happens when `ensure_block` deduplicates a basic block and returns an
    /// already-existing `MastNodeId`).
    pending_debug_var_mappings: Vec<(MastNodeId, Vec<(usize, miden_core::mast::DebugVarId)>)>,
}

impl MastForestBuilder {
    /// Creates a new builder which will transitively include the MAST of any procedures referenced
    /// in the provided set of statically-linked libraries.
    ///
    /// In all other cases, references to procedures not present in the main MastForest are assumed
    /// to be dynamically-linked, and are inserted as an external node. Dynamically-linked libraries
    /// must be provided separately to the processor at runtime.
    pub fn new<'a>(
        static_libraries: impl IntoIterator<Item = &'a MastForest>,
    ) -> Result<Self, Report> {
        // All statically-linked libraries are merged into a single MastForest.
        let forests = static_libraries.into_iter();
        let (statically_linked_mast, _remapping) = MastForest::merge(forests).into_diagnostic()?;
        // The AdviceMap of the statically-linked forest is copied to the forest being built.
        //
        // This might include excess advice map data in the built MastForest, but we currently do
        // not do any analysis to determine what advice map data is actually required by parts of
        // the library(s) that are actually linked into the output.
        let mut mast_forest = MastForest::default();
        *mast_forest.advice_map_mut() = statically_linked_mast.advice_map().clone();
        Ok(MastForestBuilder {
            mast_forest,
            statically_linked_mast: Arc::new(statically_linked_mast),
            ..Self::default()
        })
    }

    /// The builder keeps node identity independent from debug metadata.
    pub fn set_emit_debug_info(&mut self, _emit: bool) {}

    /// Removes the unused nodes that were created as part of the assembly process, and returns the
    /// resulting MAST forest.
    ///
    /// It also returns the map from old node IDs to new node IDs. Any [`MastNodeId`] used in
    /// reference to the old [`MastForest`] should be remapped using this map.
    pub fn build(mut self) -> (MastForest, BTreeMap<MastNodeId, MastNodeId>) {
        // Register all pending AssemblyOp mappings in sorted node order.
        // The CSR structure requires nodes to be added sequentially.
        // We must also merge mappings for duplicate node_ids (can happen when control flow nodes
        // like Call are deduplicated but still have asm_ops registered).
        let deduped_mappings =
            deduplicate_asm_op_mappings(core::mem::take(&mut self.pending_asm_op_mappings));

        for (node_id, asm_op_mappings) in deduped_mappings {
            let (num_operations, adjusted_mappings) =
                compute_operations_and_adjust_mappings(&self.mast_forest[node_id], asm_op_mappings);

            // Errors here are programming errors since we control the ordering.
            // Use expect to surface any issues during development.
            self.mast_forest
                .debug_info_mut()
                .register_asm_ops(node_id, num_operations, adjusted_mappings)
                .expect("failed to register AssemblyOps - internal ordering error");
        }

        // Register all pending debug variable mappings in sorted node order.
        // The CSR structure requires sequential node registration.
        // Debug vars do not affect node identity, so only the first metadata set for a
        // deduplicated node is registered.
        let debug_var_mappings =
            deduplicate_debug_var_mappings(core::mem::take(&mut self.pending_debug_var_mappings));

        for (node_id, debug_vars) in debug_var_mappings {
            self.mast_forest
                .debug_info_mut()
                .register_op_indexed_debug_vars(node_id, debug_vars)
                .expect("failed to register debug variables - internal ordering error");
        }

        let nodes_to_remove = get_nodes_to_remove(self.merged_basic_block_ids, &self.mast_forest);
        let id_remappings = self.mast_forest.remove_nodes(&nodes_to_remove);

        (self.mast_forest, id_remappings)
    }
}

/// Computes the number of operations for a node and adjusts AssemblyOp indices if needed.
///
/// For basic block nodes, adjusts indices to account for padding NOOPs in OpBatches.
/// For control flow nodes, computes the operation count from the maximum index.
fn compute_operations_and_adjust_mappings(
    node: &MastNode,
    asm_op_mappings: Vec<(usize, AsmOpId)>,
) -> (usize, Vec<(usize, AsmOpId)>) {
    match node {
        MastNode::Block(block) => (
            block.num_operations() as usize,
            BasicBlockNode::adjust_asm_op_indices(asm_op_mappings, block.op_batches()),
        ),
        _ => {
            let num_ops = asm_op_mappings.iter().map(|(idx, _)| idx + 1).max().unwrap_or(0);
            (num_ops, asm_op_mappings)
        },
    }
}

/// Deduplicates AssemblyOp mappings by node_id, keeping only the first registration.
///
/// Mappings are sorted by node_id, then deduplicated. This is necessary because control flow
/// nodes like Call can be deduplicated, resulting in multiple registrations for the same node_id.
fn deduplicate_asm_op_mappings(
    mut mappings: Vec<(MastNodeId, Vec<(usize, AsmOpId)>)>,
) -> Vec<(MastNodeId, Vec<(usize, AsmOpId)>)> {
    mappings.sort_by_key(|(node_id, _)| *node_id);

    let mut seen_node_ids = BTreeSet::new();
    mappings
        .into_iter()
        .filter(|(node_id, _)| seen_node_ids.insert(*node_id))
        .collect()
}

/// Deduplicates debug variable mappings by node_id (keeps first registration).
///
/// Debug vars do not affect node identity, so this keeps the first metadata set for a
/// deduplicated node.
fn deduplicate_debug_var_mappings(
    mut mappings: Vec<(MastNodeId, Vec<(usize, miden_core::mast::DebugVarId)>)>,
) -> Vec<(MastNodeId, Vec<(usize, miden_core::mast::DebugVarId)>)> {
    mappings.sort_by_key(|(node_id, _)| *node_id);

    let mut seen_node_ids = BTreeSet::new();
    mappings
        .into_iter()
        .filter(|(node_id, _)| seen_node_ids.insert(*node_id))
        .collect()
}

/// Takes the set of MAST node ids (all basic blocks) that were merged as part of the assembly
/// process (i.e. they were contiguous and were merged into a single basic block), and returns the
/// subset of nodes that can be removed from the MAST forest.
///
/// Specifically, MAST node ids can be reused, so merging a basic block doesn't mean it should be
/// removed (specifically in the case where another node refers to it). Hence, we cycle through all
/// nodes of the forest and only mark for removal those nodes that are not referenced by any node.
/// We also ensure that procedure roots are not removed.
fn get_nodes_to_remove(
    merged_node_ids: BTreeSet<MastNodeId>,
    mast_forest: &MastForest,
) -> BTreeSet<MastNodeId> {
    // make sure not to remove procedure roots
    let mut nodes_to_remove: BTreeSet<MastNodeId> = merged_node_ids
        .iter()
        .filter(|&&mast_node_id| !mast_forest.is_procedure_root(mast_node_id))
        .copied()
        .collect();

    for node in mast_forest.nodes() {
        node.for_each_child(|child_id| {
            if nodes_to_remove.contains(&child_id) {
                nodes_to_remove.remove(&child_id);
            }
        });
    }

    nodes_to_remove
}

// ------------------------------------------------------------------------------------------------
/// Public accessors
impl MastForestBuilder {
    /// Returns a reference to the procedure with the specified [`GlobalProcedureIndex`], or None
    /// if such a procedure is not present in this MAST forest builder.
    #[inline(always)]
    pub fn get_procedure(&self, gid: GlobalItemIndex) -> Option<&Procedure> {
        self.procedures.get(&gid)
    }

    /// Returns a reference to the procedure with the specified MAST root, or None
    /// if such a procedure is not present in this MAST forest builder.
    #[inline(always)]
    pub fn find_procedure_by_mast_root(&self, mast_root: &Word) -> Option<&Procedure> {
        self.proc_gid_by_mast_root
            .get(mast_root)
            .and_then(|gid| self.get_procedure(*gid))
    }

    /// Returns the [`MastNode`] for the provided MAST node ID, or None if a node with this ID is
    /// not present in this MAST forest builder.
    pub fn get_mast_node(&self, id: MastNodeId) -> Option<&MastNode> {
        self.mast_forest.get_node_by_id(id)
    }
}

// ------------------------------------------------------------------------------------------------
/// Procedure insertion
impl MastForestBuilder {
    /// Inserts a procedure into this MAST forest builder.
    ///
    /// If the procedure with the same ID already exists in this forest builder, this will have
    /// no effect.
    pub fn insert_procedure(
        &mut self,
        gid: GlobalItemIndex,
        procedure: Procedure,
    ) -> Result<(), Report> {
        // Check if an entry is already in this cache slot.
        //
        // If there is already a cache entry, but it conflicts with what we're trying to cache,
        // then raise an error.
        if self.procedures.contains_key(&gid) {
            // The global procedure index and the MAST root resolve to an already cached version of
            // this procedure, or an alias of it, nothing to do.
            //
            // TODO: We should emit a warning for this, because while it is not an error per se, it
            // does reflect that we're doing work we don't need to be doing. However, emitting a
            // warning only makes sense if this is controllable by the user, and it isn't yet
            // clear whether this edge case will ever happen in practice anyway.
            return Ok(());
        }

        // We don't have a cache entry yet, but we do want to make sure we don't have a conflicting
        // cache entry with the same MAST root:
        if let Some(cached) = self.find_procedure_by_mast_root(&procedure.mast_root()) {
            // Handle the case where a procedure with no locals is lowered to a MastForest
            // consisting only of an `External` node to another procedure which has one or more
            // locals. This will result in the calling procedure having the same digest as the
            // callee, but the two procedures having mismatched local counts. When this occurs,
            // we want to use the procedure with non-zero local count as the definition, and treat
            // the other procedure as an alias, which can be referenced like any other procedure,
            // but the MAST returned for it will be that of the "real" definition.
            let cached_locals = cached.num_locals();
            let procedure_locals = procedure.num_locals();
            let mismatched_locals = cached_locals != procedure_locals;
            let is_valid =
                !mismatched_locals || core::cmp::min(cached_locals, procedure_locals) == 0;
            if !is_valid {
                let first = cached.path();
                let second = procedure.path();
                return Err(report!(
                    "two procedures found with same mast root, but conflicting definitions ('{}' and '{}')",
                    first,
                    second
                ));
            }
        }

        self.mast_forest.make_root(procedure.body_node_id());
        self.proc_gid_by_mast_root.insert(procedure.mast_root(), gid);
        self.procedures.insert(gid, procedure);

        Ok(())
    }
}

// ------------------------------------------------------------------------------------------------
/// Joining nodes
impl MastForestBuilder {
    /// Builds a tree of `JOIN` operations to combine the provided MAST node IDs.
    ///
    /// If `asm_op` is provided, each created `JoinNode` will have the given [`AssemblyOp`]
    /// registered, enabling source-location diagnostics for errors that occur within join
    /// contexts (e.g., when an `ExternalNode` fails to resolve).
    pub fn join_nodes(
        &mut self,
        node_ids: Vec<MastNodeId>,
        asm_op: Option<AssemblyOp>,
    ) -> Result<MastNodeId, Report> {
        debug_assert!(!node_ids.is_empty(), "cannot combine empty MAST node id list");

        let mut node_ids = self.merge_contiguous_basic_blocks(node_ids)?;

        // build a binary tree of blocks joining them using JOIN blocks
        while node_ids.len() > 1 {
            let last_mast_node_id = if node_ids.len().is_multiple_of(2) {
                None
            } else {
                node_ids.pop()
            };

            let mut source_node_ids = Vec::new();
            core::mem::swap(&mut node_ids, &mut source_node_ids);

            let mut source_mast_node_iter = source_node_ids.drain(0..);
            while let (Some(left), Some(right)) =
                (source_mast_node_iter.next(), source_mast_node_iter.next())
            {
                let join_builder = JoinNodeBuilder::new([left, right]);
                let join_mast_node_id = if let Some(ref asm_op) = asm_op {
                    self.ensure_node_with_asm_op(join_builder, asm_op.clone())?
                } else {
                    self.ensure_node(join_builder)?
                };

                node_ids.push(join_mast_node_id);
            }
            if let Some(mast_node_id) = last_mast_node_id {
                node_ids.push(mast_node_id);
            }
        }

        Ok(node_ids.remove(0))
    }

    /// Returns a list of [`MastNodeId`]s built from merging the contiguous basic blocks
    /// found in the provided list of [`MastNodeId`]s.
    fn merge_contiguous_basic_blocks(
        &mut self,
        node_ids: Vec<MastNodeId>,
    ) -> Result<Vec<MastNodeId>, Report> {
        let mut merged_node_ids = Vec::with_capacity(node_ids.len());
        let mut contiguous_basic_block_ids: Vec<MastNodeId> = Vec::new();

        for mast_node_id in node_ids {
            if self.mast_forest[mast_node_id].is_basic_block() {
                contiguous_basic_block_ids.push(mast_node_id);
            } else {
                merged_node_ids.extend(self.merge_basic_blocks(&contiguous_basic_block_ids)?);
                contiguous_basic_block_ids.clear();

                merged_node_ids.push(mast_node_id);
            }
        }

        merged_node_ids.extend(self.merge_basic_blocks(&contiguous_basic_block_ids)?);

        Ok(merged_node_ids)
    }

    /// Creates a new basic block by appending all operations in the provided list of
    /// basic blocks (which are assumed to be contiguous).
    ///
    /// # Panics
    /// - Panics if a provided [`MastNodeId`] doesn't refer to a basic block node.
    fn merge_basic_blocks(
        &mut self,
        contiguous_basic_block_ids: &[MastNodeId],
    ) -> Result<Vec<MastNodeId>, Report> {
        if contiguous_basic_block_ids.is_empty() {
            return Ok(Vec::new());
        }
        if contiguous_basic_block_ids.len() == 1 {
            return Ok(contiguous_basic_block_ids.to_vec());
        }

        let mut operations: Vec<Operation> = Vec::new();
        // Track asm_ops and debug_vars being accumulated for merged blocks, with adjusted indices
        let mut merged_asm_ops: Vec<(usize, AsmOpId)> = Vec::new();
        let mut merged_debug_vars: Vec<(usize, miden_core::mast::DebugVarId)> = Vec::new();

        let mut merged_basic_blocks: Vec<MastNodeId> = Vec::new();

        for &basic_block_id in contiguous_basic_block_ids {
            // check if the block should be merged with other blocks
            if should_merge(
                self.mast_forest.is_procedure_root(basic_block_id),
                self.mast_forest[basic_block_id]
                    .get_basic_block()
                    .expect("merge_basic_blocks: expected BasicBlockNode")
                    .num_op_batches(),
            ) {
                // Collect operations from the block while still borrowing.
                // We need owned copies so we can drop the borrow before mutating self
                let block_ops = {
                    let basic_block_node =
                        self.mast_forest[basic_block_id].get_basic_block().unwrap();
                    basic_block_node
                        .op_batches()
                        .iter()
                        .flat_map(|b| b.raw_ops().copied())
                        .collect::<Vec<Operation>>()
                };
                let ops_offset = operations.len();

                // Transfer any pending asm_ops and debug_vars for this block to the merged result
                self.transfer_asm_ops_for_merge(basic_block_id, ops_offset, &mut merged_asm_ops);
                self.transfer_debug_vars_for_merge(
                    basic_block_id,
                    ops_offset,
                    &mut merged_debug_vars,
                );

                operations.extend(block_ops);
            } else {
                // If we don't want to merge this block, flush the buffer of operations into a
                // new block, and add the un-merged block after it.
                if !operations.is_empty() {
                    let block_ops = core::mem::take(&mut operations);
                    let block_asm_ops = core::mem::take(&mut merged_asm_ops);
                    let block_debug_vars = core::mem::take(&mut merged_debug_vars);
                    let merged_basic_block_id = self.ensure_block_with_asm_op_and_debug_var_ids(
                        block_ops,
                        block_asm_ops,
                        block_debug_vars,
                    )?;

                    merged_basic_blocks.push(merged_basic_block_id);
                }
                merged_basic_blocks.push(basic_block_id);
            }
        }

        // Mark the removed basic blocks as merged
        self.merged_basic_block_ids.extend(contiguous_basic_block_ids.iter());

        if !operations.is_empty() {
            let merged_basic_block = self.ensure_block_with_asm_op_and_debug_var_ids(
                operations,
                merged_asm_ops,
                merged_debug_vars,
            )?;
            merged_basic_blocks.push(merged_basic_block);
        }

        Ok(merged_basic_blocks)
    }

    /// Copies pending asm_ops from a source block into the merged list with adjusted indices.
    ///
    /// The source block's entries are left in `pending_asm_op_mappings` so that if it
    /// survives removal (e.g. it's a procedure root or referenced child), its metadata
    /// is still registered during `build()`.
    fn transfer_asm_ops_for_merge(
        &self,
        source_block_id: MastNodeId,
        ops_offset: usize,
        merged_asm_ops: &mut Vec<(usize, AsmOpId)>,
    ) {
        for (node_id, asm_ops) in &self.pending_asm_op_mappings {
            if *node_id == source_block_id {
                merged_asm_ops.extend(
                    asm_ops.iter().map(|(op_idx, asm_op_id)| (op_idx + ops_offset, *asm_op_id)),
                );
            }
        }
    }

    /// Copies pending debug_vars from a source block into the merged list with adjusted indices.
    ///
    /// Same as `transfer_asm_ops_for_merge`: source entries are kept so surviving blocks
    /// retain their metadata.
    fn transfer_debug_vars_for_merge(
        &self,
        source_block_id: MastNodeId,
        ops_offset: usize,
        merged_debug_vars: &mut Vec<(usize, miden_core::mast::DebugVarId)>,
    ) {
        for (node_id, debug_vars) in &self.pending_debug_var_mappings {
            if *node_id == source_block_id {
                merged_debug_vars.extend(
                    debug_vars.iter().map(|(op_idx, var_id)| (op_idx + ops_offset, *var_id)),
                );
            }
        }
    }

    /// Like ensure_block but takes pre-existing AsmOpIds and DebugVarIds instead of raw
    /// AssemblyOps. Used when merging blocks that already have their metadata registered.
    fn ensure_block_with_asm_op_and_debug_var_ids(
        &mut self,
        operations: Vec<Operation>,
        asm_op_ids: Vec<(usize, AsmOpId)>,
        debug_vars: Vec<(usize, miden_core::mast::DebugVarId)>,
    ) -> Result<MastNodeId, Report> {
        let block = BasicBlockNodeBuilder::new(operations);

        let (node_id, is_new) = self.ensure_node_exists(block)?;

        if is_new && !asm_op_ids.is_empty() {
            self.pending_asm_op_mappings.push((node_id, asm_op_ids));
        }
        if is_new && !debug_vars.is_empty() {
            self.pending_debug_var_mappings.push((node_id, debug_vars));
        }

        Ok(node_id)
    }
}

// ------------------------------------------------------------------------------------------------
/// Node inserters
impl MastForestBuilder {
    /// Adds a debug variable to the forest, and returns the [`DebugVarId`] associated with it.
    ///
    /// Debug variables are not deduplicated since each occurrence represents a specific point in
    /// program execution where the variable's location is being tracked.
    pub fn add_debug_var(
        &mut self,
        debug_var: miden_core::operations::DebugVarInfo,
    ) -> Result<miden_core::mast::DebugVarId, Report> {
        self.mast_forest
            .add_debug_var(debug_var)
            .into_diagnostic()
            .wrap_err("assembler failed to add debug variable")
    }

    /// Adds a node to the forest, and returns the [`MastNodeId`] associated with it.
    ///
    /// Note that only one copy of nodes with the same digest is added to the MAST forest.
    pub(crate) fn ensure_node(
        &mut self,
        builder: impl MastForestContributor,
    ) -> Result<MastNodeId, Report> {
        let (node_id, _is_new) = self.ensure_node_exists(builder)?;
        Ok(node_id)
    }

    /// Like [`Self::ensure_node`], but registers an AssemblyOp for the node if a new node is
    /// created.
    pub(crate) fn ensure_node_with_asm_op(
        &mut self,
        builder: impl MastForestContributor,
        asm_op: AssemblyOp,
    ) -> Result<MastNodeId, Report> {
        let (node_id, is_new) = self.ensure_node_exists(builder)?;
        if is_new {
            let asm_op_id = self
                .mast_forest
                .debug_info_mut()
                .add_asm_op(asm_op)
                .into_diagnostic()
                .wrap_err("failed to add AssemblyOp for control flow node")?;
            self.pending_asm_op_mappings.push((node_id, vec![(0, asm_op_id)]));
        }
        Ok(node_id)
    }

    /// Copies a statically linked node into this builder.
    fn ensure_node_from_statically_linked_source(
        &mut self,
        builder: impl MastForestContributor,
        source_node_id: MastNodeId,
    ) -> Result<MastNodeId, Report> {
        let (node_id, is_new) = self.ensure_node_exists(builder)?;
        if !is_new {
            return Ok(node_id);
        }

        let mut asm_ops = self.statically_linked_mast.debug_info().asm_ops_for_node(source_node_id);
        if let MastNode::Block(block) = &self.statically_linked_mast[source_node_id] {
            asm_ops = BasicBlockNode::unadjust_asm_op_indices(asm_ops, block.op_batches());
        }
        if !asm_ops.is_empty() {
            let mut remapped_asm_ops = Vec::with_capacity(asm_ops.len());
            for (op_idx, asm_op_id) in asm_ops {
                if let Some(asm_op) = self.statically_linked_mast.debug_info().asm_op(asm_op_id) {
                    let new_asm_op_id = self
                        .mast_forest
                        .debug_info_mut()
                        .add_asm_op(asm_op.clone())
                        .into_diagnostic()
                        .wrap_err("failed to copy AssemblyOp from statically linked forest")?;
                    remapped_asm_ops.push((op_idx, new_asm_op_id));
                }
            }
            if !remapped_asm_ops.is_empty() {
                self.pending_asm_op_mappings.push((node_id, remapped_asm_ops));
            }
        }

        let debug_vars =
            self.statically_linked_mast.debug_info().debug_vars_for_node(source_node_id);
        if !debug_vars.is_empty() {
            let mut remapped_debug_vars = Vec::with_capacity(debug_vars.len());
            for (op_idx, var_id) in debug_vars {
                if let Some(debug_var) = self.statically_linked_mast.debug_info().debug_var(var_id)
                {
                    let new_var_id = self
                        .mast_forest
                        .add_debug_var(debug_var.clone())
                        .into_diagnostic()
                        .wrap_err("failed to copy debug var from statically linked forest")?;
                    remapped_debug_vars.push((op_idx, new_var_id));
                }
            }
            if !remapped_debug_vars.is_empty() {
                self.pending_debug_var_mappings.push((node_id, remapped_debug_vars));
            }
        }

        Ok(node_id)
    }

    /// Adds a node to the forest if it doesn't already exist.
    ///
    /// Returns `(node_id, is_new)` where `is_new` is true if the node was newly added,
    /// or false if a duplicate node already existed.
    fn ensure_node_exists(
        &mut self,
        builder: impl MastForestContributor,
    ) -> Result<(MastNodeId, bool), Report> {
        let node_digest = builder
            .fingerprint_for_node(&self.mast_forest)
            .into_diagnostic()
            .wrap_err("assembler failed to compute node digest")?;

        if let Some(node_id) = self.node_id_by_digest.get(&node_digest) {
            // node already exists in the forest; return previously assigned id
            Ok((*node_id, false))
        } else {
            let new_node_id = builder
                .add_to_forest(&mut self.mast_forest)
                .into_diagnostic()
                .wrap_err("assembler failed to add new node")?;
            self.node_id_by_digest.insert(node_digest, new_node_id);

            Ok((new_node_id, true))
        }
    }

    /// Adds a basic block node to the forest, and returns the [`MastNodeId`] associated with it.
    ///
    /// The `asm_ops` parameter contains AssemblyOp metadata for operations in this block. Each
    /// entry is `(op_idx, AssemblyOp)` where `op_idx` is the operation index the AssemblyOp
    /// corresponds to.
    ///
    /// The `debug_vars` parameter contains debug variable metadata for operations in this block.
    /// Each entry is `(op_idx, DebugVarId)` where `op_idx` is the operation index the debug
    /// variable corresponds to.
    ///
    /// Note: AssemblyOps and debug variables are kept external to the block builder and do not
    /// affect node identity.
    ///
    /// The actual registration of both AssemblyOp and debug variable mappings is deferred until
    /// `build()` is called, to ensure nodes are registered in sequential order as required by
    /// the CSR structure.
    pub fn ensure_block(
        &mut self,
        operations: Vec<Operation>,
        asm_ops: Vec<(usize, AssemblyOp)>,
        debug_vars: Vec<(usize, miden_core::mast::DebugVarId)>,
    ) -> Result<MastNodeId, Report> {
        let block = BasicBlockNodeBuilder::new(operations);

        let (node_id, is_new) = self.ensure_node_exists(block)?;

        // Only register AssemblyOps for newly created nodes.
        // Deduplicated nodes already have their asm_ops registered from when they were first added.
        if is_new && !asm_ops.is_empty() {
            let mut asm_op_mappings = Vec::with_capacity(asm_ops.len());
            for (op_idx, asm_op) in asm_ops {
                let asm_op_id = self
                    .mast_forest
                    .debug_info_mut()
                    .add_asm_op(asm_op)
                    .into_diagnostic()
                    .wrap_err("failed to add AssemblyOp")?;
                asm_op_mappings.push((op_idx, asm_op_id));
            }
            // Defer registration until build() to ensure sequential node order.
            self.pending_asm_op_mappings.push((node_id, asm_op_mappings));
        }

        // Only register debug variables for newly created nodes. If the block is deduplicated,
        // the existing node keeps the metadata that was registered first.
        if is_new && !debug_vars.is_empty() {
            self.pending_debug_var_mappings.push((node_id, debug_vars));
        }

        Ok(node_id)
    }

    /// Builds a node builder with remapped children for copying from statically linked libraries.
    ///
    /// Delegates to the generic `build_node_with_remapped_ids` helper to avoid code duplication
    /// with `MastForestMerger`.
    fn build_with_remapped_ids(
        &self,
        node_id: MastNodeId,
        node: MastNode,
    ) -> Result<MastNodeBuilder, Report> {
        miden_core::mast::build_node_with_remapped_ids(
            node_id,
            node,
            &self.statically_linked_mast,
            &self.statically_linked_mast_remapping,
        )
        .into_diagnostic()
    }

    /// Adds a node corresponding to the given MAST root, according to how it is linked.
    ///
    /// * If statically-linked, then the entire subtree is copied, and the MastNodeId of the root of
    ///   the inserted subtree is returned.
    /// * If dynamically-linked, then an external node is inserted, and its MastNodeId is returned
    ///
    /// TODO(#2990): when multiple roots share the same digest but carry
    /// different metadata, this always picks the first match. Needs a source
    /// MastNodeId threaded from ProcedureInfo through the linker.
    pub fn ensure_external_link(&mut self, mast_root: Word) -> Result<MastNodeId, Report> {
        if let Some(root_id) = self.statically_linked_mast.find_procedure_root(mast_root) {
            self.copy_statically_linked_subtree(root_id)
        } else {
            self.ensure_node(ExternalNodeBuilder::new(mast_root))
        }
    }

    /// Copies a subtree from the statically linked forest into the builder's forest.
    fn copy_statically_linked_subtree(
        &mut self,
        root_id: MastNodeId,
    ) -> Result<MastNodeId, Report> {
        for old_id in SubtreeIterator::new(&root_id, &self.statically_linked_mast.clone()) {
            let node = self.statically_linked_mast[old_id].clone();
            let builder = self.build_with_remapped_ids(old_id, node)?;
            let new_id = self.ensure_node_from_statically_linked_source(builder, old_id)?;
            self.statically_linked_mast_remapping.insert(old_id, new_id);
        }
        Ok(root_id.remap(&self.statically_linked_mast_remapping))
    }
}

impl MastForestBuilder {
    /// Registers an error message in the MAST Forest and returns the
    /// corresponding error code as a Felt.
    pub fn register_error(&mut self, msg: Arc<str>) -> Felt {
        self.mast_forest.register_error(msg)
    }
}

impl Index<MastNodeId> for MastForestBuilder {
    type Output = MastNode;

    #[inline(always)]
    fn index(&self, node_id: MastNodeId) -> &Self::Output {
        &self.mast_forest[node_id]
    }
}

// ------------------------------------------------------------------------------------------------

impl MastForestBuilder {
    /// Merges an AdviceMap into the one being built within the MAST Forest.
    ///
    /// # Errors
    ///
    /// Returns `AdviceMapKeyCollisionOnMerge` if any of the keys of the AdviceMap being merged
    /// are already present with a different value in the AdviceMap of the Mast Forest. In
    /// case of error the AdviceMap of the Mast Forest remains unchanged.
    pub fn merge_advice_map(&mut self, other: &AdviceMap) -> Result<(), Report> {
        self.mast_forest
            .advice_map_mut()
            .merge(other)
            .map_err(|((key, prev_values), new_values)| LinkerError::AdviceMapKeyAlreadyPresent {
                key,
                prev_values: prev_values.to_vec(),
                new_values: new_values.to_vec(),
            })
            .into_diagnostic()
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Determines if we want to merge a block with other blocks. Currently, this works as follows:
/// - If the block is a procedure, we merge it only if the number of operation batches is smaller
///   then the threshold (currently set at 32). The reasoning is based on an estimate of the the
///   runtime penalty of not inlining the procedure. We assume that this penalty is roughly 3 extra
///   nodes in the MAST and so would require 3 additional hashes at runtime. Since hashing each
///   operation batch requires 1 hash, this basically implies that if the runtime penalty is more
///   than 10%, we inline the block, but if it is less than 10% we accept the penalty to make
///   deserialization faster.
/// - If the block is not a procedure, we always merge it because: (1) if it is a large block, it is
///   likely to be unique and, thus, the original block will be orphaned and removed later; (2) if
///   it is a small block, there is a large run-time benefit for inlining it.
fn should_merge(is_procedure: bool, num_op_batches: usize) -> bool {
    if is_procedure {
        num_op_batches < PROCEDURE_INLINING_THRESHOLD
    } else {
        true
    }
}

#[cfg(test)]
mod tests {
    use miden_core::mast::CallNodeBuilder;

    use super::*;

    #[test]
    fn test_merge_basic_blocks_keeps_non_mergeable_block_standalone() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let num_ops = PROCEDURE_INLINING_THRESHOLD * 1024;
        let large_ops = vec![Operation::Add; num_ops];
        let large_block_id = builder.ensure_block(large_ops, vec![], vec![]).unwrap();
        builder.mast_forest.make_root(large_block_id);

        let small_block_id = builder.ensure_block(vec![Operation::Add], vec![], vec![]).unwrap();

        let merged_blocks = builder.merge_basic_blocks(&[large_block_id, small_block_id]).unwrap();

        assert_eq!(merged_blocks.len(), 2);
        assert_eq!(merged_blocks[0], large_block_id);
        assert_eq!(merged_blocks[1], small_block_id);
    }

    #[test]
    fn test_ensure_block_dedups_identical_debug_var_payloads() {
        use miden_core::operations::{DebugVarInfo, DebugVarLocation};

        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let var_a = builder
            .add_debug_var(DebugVarInfo::new("x", DebugVarLocation::Stack(0)))
            .unwrap();
        let var_b = builder
            .add_debug_var(DebugVarInfo::new("x", DebugVarLocation::Stack(0)))
            .unwrap();

        let block_a = builder.ensure_block(vec![Operation::Add], vec![], vec![(0, var_a)]).unwrap();
        let block_b = builder.ensure_block(vec![Operation::Add], vec![], vec![(0, var_b)]).unwrap();

        assert_eq!(
            block_a, block_b,
            "same op stream plus same DebugVarInfo payload should dedup to one node"
        );
    }

    /// Same-ops blocks with different debug vars still alias. The first node's metadata wins.
    #[test]
    fn test_ensure_block_dedups_different_debug_vars() {
        use miden_core::operations::{DebugVarInfo, DebugVarLocation};

        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let var_x_id = builder
            .add_debug_var(DebugVarInfo::new("x", DebugVarLocation::Stack(0)))
            .unwrap();
        let var_y_id = builder
            .add_debug_var(DebugVarInfo::new("y", DebugVarLocation::Stack(1)))
            .unwrap();

        let block_a =
            builder.ensure_block(vec![Operation::Add], vec![], vec![(0, var_x_id)]).unwrap();
        let block_b =
            builder.ensure_block(vec![Operation::Add], vec![], vec![(0, var_y_id)]).unwrap();

        assert_eq!(block_a, block_b, "debug vars must not prevent dedup");

        let (forest, _remapping) = builder.build();
        let vars = forest.debug_info().debug_vars_for_node(block_a);

        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].1, var_x_id, "deduped node should keep first var");
    }

    /// Same-ops blocks with different AssemblyOps alias during assembly.
    #[test]
    fn test_ensure_block_dedups_different_asm_ops() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let block_a = builder
            .ensure_block(
                vec![Operation::Add],
                vec![(0, AssemblyOp::new(None, "ctx_a".into(), 1, "add".into()))],
                vec![],
            )
            .unwrap();
        let block_b = builder
            .ensure_block(
                vec![Operation::Add],
                vec![(0, AssemblyOp::new(None, "ctx_b".into(), 1, "add".into()))],
                vec![],
            )
            .unwrap();

        assert_eq!(block_a, block_b, "same op stream plus different AssemblyOp payload must dedup");

        let (forest, _remapping) = builder.build();
        assert_eq!(
            forest.debug_info().first_asm_op_for_node(block_a).unwrap().context_name(),
            "ctx_a"
        );
    }

    /// Non-block nodes with different AssemblyOps alias during assembly.
    #[test]
    fn test_non_block_nodes_dedup_different_asm_ops() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let callee = builder.ensure_block(vec![Operation::Add], vec![], vec![]).unwrap();
        let call_a = builder
            .ensure_node_with_asm_op(
                CallNodeBuilder::new(callee),
                AssemblyOp::new(None, "ctx_a".into(), 1, "call.foo".into()),
            )
            .unwrap();
        let call_b = builder
            .ensure_node_with_asm_op(
                CallNodeBuilder::new(callee),
                AssemblyOp::new(None, "ctx_b".into(), 1, "call.foo".into()),
            )
            .unwrap();

        assert_eq!(
            call_a, call_b,
            "same-structure non-block nodes with different AssemblyOps must dedup"
        );

        let (forest, _remapping) = builder.build();
        assert_eq!(
            forest.debug_info().first_asm_op_for_node(call_a).unwrap().context_name(),
            "ctx_a"
        );
    }

    #[test]
    fn test_merged_root_block_keeps_metadata() {
        use miden_core::operations::{AssemblyOp, DebugVarInfo, DebugVarLocation};

        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let var_id = builder
            .add_debug_var(DebugVarInfo::new("x", DebugVarLocation::Stack(0)))
            .unwrap();
        let asm_op = AssemblyOp::new(None, "test".into(), 1, "add".into());

        // Small block that will be a procedure root -- should_merge returns true for
        // small roots, so it will be folded into the merged block.
        let root_block = builder
            .ensure_block(vec![Operation::Add], vec![(0, asm_op)], vec![(0, var_id)])
            .unwrap();
        builder.mast_forest.make_root(root_block);

        // Second block to merge with.
        let other_block = builder.ensure_block(vec![Operation::Mul], vec![], vec![]).unwrap();

        let merged = builder.merge_basic_blocks(&[root_block, other_block]).unwrap();
        // Root was small enough to merge, so we get one merged block.
        assert_eq!(merged.len(), 1);
        let merged_id = merged[0];
        assert_ne!(merged_id, root_block);

        let (forest, remapping) = builder.build();

        // The root block survives removal (it's a procedure root).
        let final_root_id = remapping.get(&root_block).copied().unwrap_or(root_block);
        assert!(forest.is_procedure_root(final_root_id), "root should survive");

        // Root block must still have its debug vars.
        let root_vars = forest.debug_info().debug_vars_for_node(final_root_id);
        assert_eq!(root_vars.len(), 1, "root must keep its debug vars after merge");
        assert_eq!(root_vars[0].1, var_id);

        // Root block must still have its asm op.
        let root_asm = forest.debug_info().first_asm_op_for_node(final_root_id);
        assert!(root_asm.is_some(), "root must keep its asm op after merge");
    }
}
