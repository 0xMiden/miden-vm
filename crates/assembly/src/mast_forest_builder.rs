use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};
use core::ops::{Index, IndexMut};

#[cfg(test)]
use miden_core::mast::{LoopNodeBuilder, SplitNodeBuilder};
use miden_core::{
    AdviceMap, Decorator, DecoratorList, Felt, Operation, Word,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, DecoratorFingerprint, DecoratorId, DynNodeBuilder,
        ExternalNodeBuilder, JoinNodeBuilder, MastForest, MastForestContributor, MastForestError,
        MastNode, MastNodeBuilder, MastNodeExt, MastNodeFingerprint, MastNodeId, Remapping,
        SubtreeIterator,
    },
};

use super::{GlobalItemIndex, LinkerError, Procedure};
use crate::{
    Library,
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
/// - The builder ensures that only one copy of nodes that have the same MAST root and decorators is
///   added to the MAST forest (i.e., two nodes that have the same MAST root and decorators will
///   have the same [`MastNodeId`]).
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
    /// A map of MAST node fingerprints to their corresponding positions in the MAST forest.
    node_id_by_fingerprint: BTreeMap<MastNodeFingerprint, MastNodeId>,
    /// The reverse mapping of `node_id_by_fingerprint`. This map caches the fingerprints of all
    /// nodes (for performance reasons).
    hash_by_node_id: BTreeMap<MastNodeId, MastNodeFingerprint>,
    /// A map of decorator fingerprints to their corresponding positions in the MAST forest.
    decorator_id_by_fingerprint: BTreeMap<DecoratorFingerprint, DecoratorId>,
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
    /// Keeps track of the new ids assigned to decorators that are copied from the MAST of
    /// statically-linked libraries.
    statically_linked_decorator_remapping: BTreeMap<DecoratorId, DecoratorId>,
}

impl MastForestBuilder {
    /// Creates a new builder which will transitively include the MAST of any procedures referenced
    /// in the provided set of statically-linked libraries.
    ///
    /// In all other cases, references to procedures not present in the main MastForest are assumed
    /// to be dynamically-linked, and are inserted as an external node. Dynamically-linked libraries
    /// must be provided separately to the processor at runtime.
    pub fn new<'a>(
        static_libraries: impl IntoIterator<Item = &'a Library>,
    ) -> Result<Self, Report> {
        // All statically-linked libraries are merged into a single MastForest.
        let forests = static_libraries.into_iter().map(|lib| lib.mast_forest().as_ref());
        let (statically_linked_mast, _remapping) = MastForest::merge(forests).into_diagnostic()?;
        // The AdviceMap of the statically-linkeed forest is copied to the forest being built.
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

    /// Returns a reference to the underlying [`MastForest`].
    pub fn mast_forest(&self) -> &MastForest {
        &self.mast_forest
    }

    /// Removes the unused nodes that were created as part of the assembly process, and returns the
    /// resulting MAST forest.
    ///
    /// It also returns the map from old node IDs to new node IDs. Any [`MastNodeId`] used in
    /// reference to the old [`MastForest`] should be remapped using this map.
    pub fn build(mut self) -> (MastForest, BTreeMap<MastNodeId, MastNodeId>) {
        let nodes_to_remove = get_nodes_to_remove(self.merged_basic_block_ids, &self.mast_forest);
        let id_remappings = self.mast_forest.remove_nodes(&nodes_to_remove);

        (self.mast_forest, id_remappings)
    }
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
    pub fn join_nodes(&mut self, node_ids: Vec<MastNodeId>) -> Result<MastNodeId, Report> {
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
                let join_mast_node_id = self.ensure_join(left, right, vec![], vec![])?;

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

    /// Creates a new basic block by appending all operations and decorators in the provided list of
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
        let mut decorators = DecoratorList::new();

        let mut merged_basic_blocks: Vec<MastNodeId> = Vec::new();

        for &basic_block_id in contiguous_basic_block_ids {
            // It is safe to unwrap here, since we already checked that all IDs in
            // `contiguous_basic_block_ids` are `BasicBlockNode`s
            let basic_block_node = self.mast_forest[basic_block_id].get_basic_block().unwrap();

            // check if the block should be merged with other blocks
            if should_merge(
                self.mast_forest.is_procedure_root(basic_block_id),
                basic_block_node.num_op_batches(),
            ) {
                // Use forest-borrowing to get decorators from linked nodes
                for (op_idx, decorator) in basic_block_node.raw_decorator_iter(&self.mast_forest) {
                    decorators.push((op_idx + operations.len(), decorator));
                }
                for batch in basic_block_node.op_batches() {
                    operations.extend(batch.raw_ops());
                }
            } else {
                // if we don't want to merge this block, we flush the buffer of operations into a
                // new block, and add the un-merged block after it
                if !operations.is_empty() {
                    let block_ops = core::mem::take(&mut operations);
                    let block_decorators = core::mem::take(&mut decorators);
                    let merged_basic_block_id =
                        self.ensure_block(block_ops, block_decorators, vec![], vec![])?;

                    merged_basic_blocks.push(merged_basic_block_id);
                }
                merged_basic_blocks.push(basic_block_id);
            }
        }

        // Mark the removed basic blocks as merged
        self.merged_basic_block_ids.extend(contiguous_basic_block_ids.iter());

        if !operations.is_empty() || !decorators.is_empty() {
            let merged_basic_block = self.ensure_block(operations, decorators, vec![], vec![])?;
            merged_basic_blocks.push(merged_basic_block);
        }

        Ok(merged_basic_blocks)
    }
}

// ------------------------------------------------------------------------------------------------
/// Node inserters
impl MastForestBuilder {
    /// Adds a decorator to the forest, and returns the [`Decorator`] associated with it.
    pub fn ensure_decorator(&mut self, decorator: Decorator) -> Result<DecoratorId, Report> {
        let decorator_hash = decorator.fingerprint();

        if let Some(decorator_id) = self.decorator_id_by_fingerprint.get(&decorator_hash) {
            // decorator already exists in the forest; return previously assigned id
            Ok(*decorator_id)
        } else {
            let new_decorator_id = self
                .mast_forest
                .add_decorator(decorator)
                .into_diagnostic()
                .wrap_err("assembler failed to add new decorator")?;
            self.decorator_id_by_fingerprint.insert(decorator_hash, new_decorator_id);

            Ok(new_decorator_id)
        }
    }

    /// Adds a node to the forest, and returns the [`MastNodeId`] associated with it.
    ///
    /// Note that only one copy of nodes that have the same MAST root and decorators is added to the
    /// MAST forest; two nodes that have the same MAST root and decorators will have the same
    /// [`MastNodeId`].
    pub(crate) fn ensure_node(
        &mut self,
        builder: impl MastForestContributor,
    ) -> Result<MastNodeId, Report> {
        let node_fingerprint = builder
            .fingerprint_for_node(&self.mast_forest, &self.hash_by_node_id)
            .expect("hash_by_node_id should contain the fingerprints of all children of `node`");

        if let Some(node_id) = self.node_id_by_fingerprint.get(&node_fingerprint) {
            // node already exists in the forest; return previously assigned id
            Ok(*node_id)
        } else {
            let new_node_id = builder
                .add_to_forest(&mut self.mast_forest)
                .into_diagnostic()
                .wrap_err("assembler failed to add new node")?;
            self.node_id_by_fingerprint.insert(node_fingerprint, new_node_id);
            self.hash_by_node_id.insert(new_node_id, node_fingerprint);

            Ok(new_node_id)
        }
    }

    /// Adds a basic block node to the forest, and returns the [`MastNodeId`] associated with it.
    pub fn ensure_block(
        &mut self,
        operations: Vec<Operation>,
        decorators: DecoratorList,
        before_enter: Vec<DecoratorId>,
        after_exit: Vec<DecoratorId>,
    ) -> Result<MastNodeId, Report> {
        let block = BasicBlockNodeBuilder::new(operations, decorators)
            .with_before_enter(before_enter)
            .with_after_exit(after_exit);
        self.ensure_node(block)
    }

    /// Adds a join node to the forest, and returns the [`MastNodeId`] associated with it.
    pub fn ensure_join(
        &mut self,
        left_child: MastNodeId,
        right_child: MastNodeId,
        before_enter: Vec<DecoratorId>,
        after_exit: Vec<DecoratorId>,
    ) -> Result<MastNodeId, Report> {
        let join = JoinNodeBuilder::new([left_child, right_child])
            .with_before_enter(before_enter)
            .with_after_exit(after_exit);
        self.ensure_node(join)
    }

    /// Adds a call node to the forest, and returns the [`MastNodeId`] associated with it.
    pub fn ensure_call(
        &mut self,
        callee: MastNodeId,
        before_enter: Vec<DecoratorId>,
        after_exit: Vec<DecoratorId>,
    ) -> Result<MastNodeId, Report> {
        let call = CallNodeBuilder::new(callee)
            .with_before_enter(before_enter)
            .with_after_exit(after_exit);
        self.ensure_node(call)
    }

    /// Adds a split node to the forest, and returns the [`MastNodeId`] associated with it.
    // Kept for giving tests some consistency
    #[cfg(test)]
    pub fn ensure_split(
        &mut self,
        left_child: MastNodeId,
        right_child: MastNodeId,
        before_enter: Vec<DecoratorId>,
        after_exit: Vec<DecoratorId>,
    ) -> Result<MastNodeId, Report> {
        let split = SplitNodeBuilder::new([left_child, right_child])
            .with_before_enter(before_enter)
            .with_after_exit(after_exit);
        self.ensure_node(split)
    }

    /// Adds a loop node to the forest, and returns the [`MastNodeId`] associated with it.
    // Kept for giving tests some consistency
    #[cfg(test)]
    pub fn ensure_loop(
        &mut self,
        body: MastNodeId,
        before_enter: Vec<DecoratorId>,
        after_exit: Vec<DecoratorId>,
    ) -> Result<MastNodeId, Report> {
        let loop_node = LoopNodeBuilder::new(body)
            .with_before_enter(before_enter)
            .with_after_exit(after_exit);
        self.ensure_node(loop_node)
    }

    /// Adds a syscall node to the forest, and returns the [`MastNodeId`] associated with it.
    pub fn ensure_syscall(
        &mut self,
        callee: MastNodeId,
        before_enter: Vec<DecoratorId>,
        after_exit: Vec<DecoratorId>,
    ) -> Result<MastNodeId, Report> {
        let syscall = CallNodeBuilder::new_syscall(callee)
            .with_after_exit(after_exit)
            .with_before_enter(before_enter);
        self.ensure_node(syscall)
    }

    /// Adds a dyn node to the forest, and returns the [`MastNodeId`] associated with it.
    pub fn ensure_dyn(
        &mut self,
        before_enter: Vec<DecoratorId>,
        after_exit: Vec<DecoratorId>,
    ) -> Result<MastNodeId, Report> {
        self.ensure_node(
            DynNodeBuilder::new_dyn()
                .with_after_exit(after_exit)
                .with_before_enter(before_enter),
        )
    }

    /// Adds a dyncall node to the forest, and returns the [`MastNodeId`] associated with it.
    pub fn ensure_dyncall(
        &mut self,
        before_enter: Vec<DecoratorId>,
        after_exit: Vec<DecoratorId>,
    ) -> Result<MastNodeId, Report> {
        self.ensure_node(
            DynNodeBuilder::new_dyncall()
                .with_after_exit(after_exit)
                .with_before_enter(before_enter),
        )
    }

    /// Collects all decorators from a subtree in the statically linked forest and copies them
    /// to the target forest, populating the decorator remapping.
    ///
    /// This must be called before copying nodes from the subtree to ensure all decorator IDs
    /// can be properly remapped.
    fn collect_decorators_from_subtree(&mut self, root_id: &MastNodeId) -> Result<(), Report> {
        // Clear the decorator remapping for this subtree
        self.statically_linked_decorator_remapping.clear();

        // Iterate through all nodes in the subtree
        for node_id in SubtreeIterator::new(root_id, &self.statically_linked_mast.clone()) {
            // Get all decorator IDs used by this node
            let decorator_ids: Vec<DecoratorId> = {
                let mut ids = Vec::new();

                // Collect before_enter decorators
                ids.extend(self.statically_linked_mast.before_enter_decorators(node_id));

                // Collect after_exit decorators
                ids.extend(self.statically_linked_mast.after_exit_decorators(node_id));

                // For BasicBlockNode, also collect op-indexed decorators
                if let MastNode::Block(block_node) = &self.statically_linked_mast[node_id] {
                    for (_idx, decorator_id) in
                        block_node.indexed_decorator_iter(&self.statically_linked_mast)
                    {
                        ids.push(decorator_id);
                    }
                }

                ids
            };

            // Copy each decorator to the target forest if not already copied
            for old_decorator_id in decorator_ids {
                if !self.statically_linked_decorator_remapping.contains_key(&old_decorator_id) {
                    let decorator = self.statically_linked_mast[old_decorator_id].clone();
                    let new_decorator_id = self.ensure_decorator(decorator)?;
                    self.statically_linked_decorator_remapping
                        .insert(old_decorator_id, new_decorator_id);
                }
            }
        }

        Ok(())
    }

    /// Builds a node builder with remapped children and decorators for copying from statically
    /// linked libraries.
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
            &self.statically_linked_decorator_remapping,
        )
        .into_diagnostic()
    }

    /// Adds a node corresponding to the given MAST root, according to how it is linked.
    ///
    /// * If statically-linked, then the entire subtree is copied, and the MastNodeId of the root of
    ///   the inserted subtree is returned.
    /// * If dynamically-linked, then an external node is inserted, and its MastNodeId is returned
    pub fn ensure_external_link(&mut self, mast_root: Word) -> Result<MastNodeId, Report> {
        if let Some(root_id) = self.statically_linked_mast.find_procedure_root(mast_root) {
            // First, collect and copy all decorators from the subtree
            self.collect_decorators_from_subtree(&root_id)?;

            // Then copy all nodes with remapped children and decorators
            for old_id in SubtreeIterator::new(&root_id, &self.statically_linked_mast.clone()) {
                let node = self.statically_linked_mast[old_id].clone();
                let builder = self.build_with_remapped_ids(old_id, node)?;
                let new_id = self.ensure_node(builder)?;
                self.statically_linked_mast_remapping.insert(old_id, new_id);
            }
            Ok(root_id.remap(&self.statically_linked_mast_remapping))
        } else {
            self.ensure_node(ExternalNodeBuilder::new(mast_root))
        }
    }

    /// Adds a list of decorators to the provided node to be executed before the node executes.
    ///
    /// If other decorators are already present, the new decorators are added to the end of the
    /// list.
    pub fn append_before_enter(
        &mut self,
        node_id: MastNodeId,
        decorator_ids: Vec<DecoratorId>,
    ) -> Result<(), MastForestError> {
        // Extract the existing node and convert it to a builder
        let mut decorated_builder = self.mast_forest[node_id].clone().to_builder(&self.mast_forest);
        decorated_builder.append_before_enter(decorator_ids);
        let new_node_fingerprint =
            decorated_builder.fingerprint_for_node(&self.mast_forest, &self.hash_by_node_id)?;
        self.mast_forest[node_id] = decorated_builder.build(&self.mast_forest)?;

        self.hash_by_node_id.insert(node_id, new_node_fingerprint);
        self.node_id_by_fingerprint.insert(new_node_fingerprint, node_id);
        Ok(())
    }

    pub fn append_after_exit(
        &mut self,
        node_id: MastNodeId,
        decorator_ids: Vec<DecoratorId>,
    ) -> Result<(), MastForestError> {
        // Extract the existing node and convert it to a builder
        let mut decorated_builder = self.mast_forest[node_id].clone().to_builder(&self.mast_forest);
        decorated_builder.append_after_exit(decorator_ids);
        let new_node_fingerprint =
            decorated_builder.fingerprint_for_node(&self.mast_forest, &self.hash_by_node_id)?;
        self.mast_forest[node_id] = decorated_builder.build(&self.mast_forest)?;

        self.hash_by_node_id.insert(node_id, new_node_fingerprint);
        self.node_id_by_fingerprint.insert(new_node_fingerprint, node_id);
        Ok(())
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

impl Index<DecoratorId> for MastForestBuilder {
    type Output = Decorator;

    #[inline(always)]
    fn index(&self, decorator_id: DecoratorId) -> &Self::Output {
        &self.mast_forest[decorator_id]
    }
}

impl IndexMut<DecoratorId> for MastForestBuilder {
    #[inline(always)]
    fn index_mut(&mut self, decorator_id: DecoratorId) -> &mut Self::Output {
        &mut self.mast_forest[decorator_id]
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
                key: key.into(),
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
    use miden_core::Operation;

    use super::*;

    #[test]
    fn test_merge_basic_blocks_preserves_decorator_links_with_padding() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        // We need to create a benchmark with a removed Noop operation *in the middle* of the batch
        // (not at the end). That's because across batches, decorators are re-indexed (shifted) by
        // the amount of concrete operations in the previous batch in the sequence, and that
        // re-indexing remains valid whether or not *final* padding is elided.

        // Create first block with operations that will cause padding (ending with Push)
        // Block1: [Push(1), Drop, Drop, Drop, Drop, Drop, Drop, Push(2), Push(3)]
        // This will result in padding after Push(2) because Push operations get padded
        // Note: the following unpadded operations are 9 in number, indexed 0 to 8
        let block1_ops = vec![
            Operation::Push(Felt::new(1)),
            Operation::Drop,
            Operation::Drop,
            Operation::Drop,
            Operation::Drop,
            Operation::Drop,
            Operation::Drop,
            Operation::Push(Felt::new(2)),
            Operation::Push(Felt::new(3)),
        ]; // [push drop drop drop drop drop drop push noop] [1] [2] [push noop] [3] [noop] [noop] [noop]
        let block1_raw_ops_len = block1_ops.len();

        // Add decorators for each operation in block1
        let block1_decorator1 = builder.ensure_decorator(Decorator::Trace(1)).unwrap();
        let block1_decorator2 = builder.ensure_decorator(Decorator::Trace(2)).unwrap();
        let block1_decorator3 = builder.ensure_decorator(Decorator::Trace(3)).unwrap();
        let block1_decorators = vec![
            (0, block1_decorator1), // Decorator for Push(1)
            (7, block1_decorator2), // Decorator for Push(2)
            (8, block1_decorator3), // Decorator for Push(3) at index 8
        ];

        let block1_id = builder
            .ensure_block(block1_ops.clone(), block1_decorators, vec![], vec![])
            .unwrap();

        // Sanity check the test itself makes sense
        let block1 = builder.mast_forest[block1_id].get_basic_block().unwrap().clone();
        assert!(block1.operations().count() > block1_raw_ops_len); // this indeed generates padding, and thus a potential off-by-one
        assert_eq!(block1.raw_operations().count(), block1_raw_ops_len); // merging, which uses raw_ops, will elide padding

        // Create second block with operations
        // Block2: [Push(4), Mul]
        let block2_ops = vec![Operation::Push(Felt::new(4)), Operation::Mul];

        // Add decorators for each operation in block2
        let block2_decorator1 = builder.ensure_decorator(Decorator::Trace(4)).unwrap();
        let block2_decorator2 = builder.ensure_decorator(Decorator::Trace(5)).unwrap();
        let block2_decorators = vec![
            (0, block2_decorator1), // Decorator for Push(4)
            (1, block2_decorator2), // Decorator for Mul
        ]; // [push mul] [3]

        let block2_id = builder
            .ensure_block(block2_ops.clone(), block2_decorators, vec![], vec![])
            .unwrap();

        // Merge the blocks
        let merged_blocks = builder.merge_basic_blocks(&[block1_id, block2_id]).unwrap();

        // There should be one merged block
        assert_eq!(merged_blocks.len(), 1);
        let merged_block_id = merged_blocks[0];

        // Get the merged block from the forest (don't clone to preserve Linked decorators)
        let merged_block = builder.mast_forest[merged_block_id].get_basic_block().unwrap();

        // Merged block: two groups
        // [push drop drop drop drop drop drop push noop] [1] [2] [push push mul] [3] [4] [noop]
        // [noop]

        // Build mapping: original operation index -> decorator trace value
        // For block1: operation 0 -> Trace(1), operation 7 -> Trace(2), operation 9 -> Trace(3)
        // For block2: operation 0 -> Trace(4), operation 1 -> Trace(5)

        // Check each decorator in the merged block
        let decorators = merged_block.indexed_decorator_iter(&builder.mast_forest);
        let decorator_count = merged_block.indexed_decorator_iter(&builder.mast_forest).count();

        assert_eq!(decorator_count, 5); // 3 from block1 + 2 from block2

        // Create a map to track which trace values we've found
        let mut found_traces = std::collections::HashSet::new();

        // Check each decorator
        for (op_idx, decorator_id) in decorators {
            let decorator = &builder.mast_forest[decorator_id];

            match decorator {
                Decorator::Trace(trace_value) => {
                    // Record that we found this trace
                    found_traces.insert(*trace_value);

                    // Verify that the decorator points to the expected operation type
                    // Get the raw operations to check what's at this index
                    let merged_ops: Vec<Operation> = merged_block.operations().cloned().collect();

                    if op_idx < merged_ops.len() {
                        match op_idx {
                            0 => {
                                // Should be Push(1) from block1
                                match &merged_ops[op_idx] {
                                    Operation::Push(x) if *x == Felt::new(1) => {
                                        assert_eq!(
                                            *trace_value, 1,
                                            "Decorator for Push(1) should have trace value 1"
                                        );
                                    },
                                    _ => panic!("Expected Push operation at index 0"),
                                }
                            },
                            7 => {
                                // Should be Push(2) from block1
                                match &merged_ops[op_idx] {
                                    Operation::Push(x) if *x == Felt::new(2) => {
                                        assert_eq!(
                                            *trace_value, 2,
                                            "Decorator for Push(2) should have trace value 2"
                                        );
                                    },
                                    _ => panic!("Expected Push operation at index 7"),
                                }
                            },
                            9 => {
                                // Should be Push(3) from block1
                                match &merged_ops[op_idx] {
                                    Operation::Push(x) if *x == Felt::new(3) => {
                                        assert_eq!(
                                            *trace_value, 3,
                                            "Decorator for Push(3) should have trace value 3"
                                        );
                                    },
                                    _ => panic!("Expected Push operation at index 9"),
                                }
                            },
                            10 => {
                                // Should be Push(4) from block2
                                match &merged_ops[op_idx] {
                                    Operation::Push(x) if *x == Felt::new(4) => {
                                        assert_eq!(
                                            *trace_value, 4,
                                            "Decorator for Push(4) should have trace value 4"
                                        );
                                    },
                                    _ => panic!("Expected Push operation at index 10"),
                                }
                            },
                            11 => {
                                // Should be Mul from block2
                                match &merged_ops[op_idx] {
                                    Operation::Mul => {
                                        assert_eq!(
                                            *trace_value, 5,
                                            "Decorator for Mul should have trace value 5"
                                        );
                                    },
                                    _ => panic!("Expected Mul operation at index 11"),
                                }
                            },
                            _ => panic!(
                                "Unexpected operation index {} for {:?} pointing at {:?}",
                                op_idx, trace_value, merged_ops[op_idx]
                            ),
                        }
                    } else {
                        panic!("Operation index {} is out of bounds", op_idx);
                    }
                },
                _ => panic!("Expected Trace decorator"),
            }
        }

        // Verify we found all expected trace values
        let expected_traces = [1, 2, 3, 4, 5];
        for expected_trace in expected_traces {
            assert!(
                found_traces.contains(&expected_trace),
                "Missing trace value: {}",
                expected_trace
            );
        }

        // Verify we found exactly 5 trace values
        assert_eq!(found_traces.len(), 5, "Should have found exactly 5 trace values");
    }
}
