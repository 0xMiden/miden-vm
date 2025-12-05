use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};
use core::{
    fmt,
    ops::{Index, IndexMut},
};

pub use miden_utils_indexing::{IndexVec, IndexedVecError};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

mod node;
#[cfg(any(test, feature = "arbitrary"))]
pub use node::arbitrary;
pub use node::{
    BasicBlockNode, BasicBlockNodeBuilder, CallNode, CallNodeBuilder, DecoratedOpLink,
    DecoratorOpLinkIterator, DecoratorStore, DynNode, DynNodeBuilder, ExternalNode,
    ExternalNodeBuilder, JoinNode, JoinNodeBuilder, LoopNode, LoopNodeBuilder,
    MastForestContributor, MastNode, MastNodeBuilder, MastNodeErrorContext, MastNodeExt,
    OP_BATCH_SIZE, OP_GROUP_SIZE, OpBatch, OperationOrDecorator, SplitNode, SplitNodeBuilder,
};

use crate::{
    AdviceMap, Decorator, Felt, Idx, LexicographicWord, Word,
    crypto::hash::Hasher,
    utils::{ByteWriter, DeserializationError, Serializable, hash_string_to_word},
};

mod debuginfo;
pub use debuginfo::{
    DebugInfo, DecoratedLinks, DecoratedLinksIter, DecoratorIndexError, NodeToDecoratorIds,
    OpToDecoratorIds,
};

mod serialization;

mod merger;
pub(crate) use merger::MastForestMerger;
pub use merger::MastForestRootMap;

mod multi_forest_node_iterator;
pub(crate) use multi_forest_node_iterator::*;

mod node_fingerprint;
pub use node_fingerprint::{DecoratorFingerprint, MastNodeFingerprint};

#[cfg(test)]
mod tests;

// MAST FOREST
// ================================================================================================

/// Represents one or more procedures, represented as a collection of [`MastNode`]s.
///
/// A [`MastForest`] does not have an entrypoint, and hence is not executable. A [`crate::Program`]
/// can be built from a [`MastForest`] to specify an entrypoint.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MastForest {
    /// All of the nodes local to the trees comprising the MAST forest.
    nodes: IndexVec<MastNodeId, MastNode>,

    /// Roots of procedures defined within this MAST forest.
    roots: Vec<MastNodeId>,

    /// Advice map to be loaded into the VM prior to executing procedures from this MAST forest.
    advice_map: AdviceMap,

    /// Debug information including decorators and error codes.
    /// Always present (as per issue #1821), but can be empty for stripped builds.
    debug_info: DebugInfo,
}

// ------------------------------------------------------------------------------------------------
/// Constructors
impl MastForest {
    /// Creates a new empty [`MastForest`].
    pub fn new() -> Self {
        Self {
            nodes: IndexVec::new(),
            roots: Vec::new(),
            advice_map: AdviceMap::default(),
            debug_info: DebugInfo::new(),
        }
    }
}

// ------------------------------------------------------------------------------------------------
/// State mutators
impl MastForest {
    /// The maximum number of nodes that can be stored in a single MAST forest.
    const MAX_NODES: usize = (1 << 30) - 1;

    /// Marks the given [`MastNodeId`] as being the root of a procedure.
    ///
    /// If the specified node is already marked as a root, this will have no effect.
    ///
    /// # Panics
    /// - if `new_root_id`'s internal index is larger than the number of nodes in this forest (i.e.
    ///   clearly doesn't belong to this MAST forest).
    pub fn make_root(&mut self, new_root_id: MastNodeId) {
        assert!(new_root_id.to_usize() < self.nodes.len());

        if !self.roots.contains(&new_root_id) {
            self.roots.push(new_root_id);
        }
    }

    /// Removes all nodes in the provided set from the MAST forest. The nodes MUST be orphaned (i.e.
    /// have no parent). Otherwise, this parent's reference is considered "dangling" after the
    /// removal (i.e. will point to an incorrect node after the removal), and this removal operation
    /// would result in an invalid [`MastForest`].
    ///
    /// It also returns the map from old node IDs to new node IDs. Any [`MastNodeId`] used in
    /// reference to the old [`MastForest`] should be remapped using this map.
    pub fn remove_nodes(
        &mut self,
        nodes_to_remove: &BTreeSet<MastNodeId>,
    ) -> BTreeMap<MastNodeId, MastNodeId> {
        if nodes_to_remove.is_empty() {
            return BTreeMap::new();
        }

        let old_nodes = core::mem::replace(&mut self.nodes, IndexVec::new());
        let old_root_ids = core::mem::take(&mut self.roots);
        let (retained_nodes, id_remappings) = remove_nodes(old_nodes.into_inner(), nodes_to_remove);

        self.remap_and_add_nodes(retained_nodes, &id_remappings);
        self.remap_and_add_roots(old_root_ids, &id_remappings);
        id_remappings
    }

    /// Removes all decorators from this MAST forest.
    ///
    /// This method modifies the forest in-place, removing all decorator information
    /// including operation-indexed decorators, before-enter decorators, after-exit
    /// decorators, and error codes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_core::mast::MastForest;
    ///
    /// let mut forest = MastForest::new();
    /// // Add decorators and nodes to the forest
    /// forest.strip_decorators(); // forest is now stripped
    /// ```
    pub fn strip_decorators(&mut self) {
        // Clear all debug info (decorators and error codes)
        self.debug_info.clear();
    }

    /// Compacts the forest by merging duplicate nodes.
    ///
    /// This operation performs node deduplication by merging the forest with itself.
    /// The method assumes that decorators have already been stripped if that is desired.
    /// The operation modifies the forest in-place, updating all node references as needed.
    ///
    /// The process works by:
    /// 1. Merging the forest with itself to deduplicate identical nodes
    /// 2. Updating internal node references and remappings
    /// 3. Modifying the forest in-place with the compacted result
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_core::mast::MastForest;
    ///
    /// let mut forest = MastForest::new();
    /// // Add nodes to the forest
    ///
    /// // First strip decorators if needed
    /// forest.strip_decorators();
    ///
    /// // Then compact the forest
    /// let root_map = forest.compact();
    ///
    /// // Forest is now compacted with duplicate nodes merged
    /// ```
    pub fn compact(&mut self) -> MastForestRootMap {
        // Merge with itself to deduplicate nodes
        // Note: This cannot fail for a self-merge under normal conditions.
        // The only possible failures (TooManyNodes, TooManyDecorators) would require the
        // original forest to be at capacity limits, at which point compaction wouldn't help.
        let (compacted_forest, root_map) = MastForest::merge([&*self])
            .expect("Failed to compact MastForest: this should never happen during self-merge");

        // Replace current forest with compacted version
        *self = compacted_forest;

        root_map
    }

    /// Merges all `forests` into a new [`MastForest`].
    ///
    /// Merging two forests means combining all their constituent parts, i.e. [`MastNode`]s,
    /// [`Decorator`]s and roots. During this process, any duplicate or
    /// unreachable nodes are removed. Additionally, [`MastNodeId`]s of nodes as well as
    /// [`DecoratorId`]s of decorators may change and references to them are remapped to their new
    /// location.
    ///
    /// For example, consider this representation of a forest's nodes with all of these nodes being
    /// roots:
    ///
    /// ```text
    /// [Block(foo), Block(bar)]
    /// ```
    ///
    /// If we merge another forest into it:
    ///
    /// ```text
    /// [Block(bar), Call(0)]
    /// ```
    ///
    /// then we would expect this forest:
    ///
    /// ```text
    /// [Block(foo), Block(bar), Call(1)]
    /// ```
    ///
    /// - The `Call` to the `bar` block was remapped to its new index (now 1, previously 0).
    /// - The `Block(bar)` was deduplicated any only exists once in the merged forest.
    ///
    /// The function also returns a vector of [`MastForestRootMap`]s, whose length equals the number
    /// of passed `forests`. The indices in the vector correspond to the ones in `forests`. The map
    /// of a given forest contains the new locations of its roots in the merged forest. To
    /// illustrate, the above example would return a vector of two maps:
    ///
    /// ```text
    /// vec![{0 -> 0, 1 -> 1}
    ///      {0 -> 1, 1 -> 2}]
    /// ```
    ///
    /// - The root locations of the original forest are unchanged.
    /// - For the second forest, the `bar` block has moved from index 0 to index 1 in the merged
    ///   forest, and the `Call` has moved from index 1 to 2.
    ///
    /// If any forest being merged contains an `External(qux)` node and another forest contains a
    /// node whose digest is `qux`, then the external node will be replaced with the `qux` node,
    /// which is effectively deduplication. Decorators are ignored when it comes to merging
    /// External nodes. This means that an External node with decorators may be replaced by a node
    /// without decorators or vice versa.
    pub fn merge<'forest>(
        forests: impl IntoIterator<Item = &'forest MastForest>,
    ) -> Result<(MastForest, MastForestRootMap), MastForestError> {
        MastForestMerger::merge(forests)
    }
}

// ------------------------------------------------------------------------------------------------
/// Helpers
impl MastForest {
    /// Adds all provided nodes to the internal set of nodes, remapping all [`MastNodeId`]
    /// references in those nodes.
    ///
    /// # Panics
    /// - Panics if the internal set of nodes is not empty.
    fn remap_and_add_nodes(
        &mut self,
        nodes_to_add: Vec<MastNode>,
        id_remappings: &BTreeMap<MastNodeId, MastNodeId>,
    ) {
        assert!(self.nodes.is_empty());
        // extract decorator information from the nodes by converting them into builders
        let node_builders =
            nodes_to_add.into_iter().map(|node| node.to_builder(self)).collect::<Vec<_>>();

        // Clear decorator storage after extracting builders (builders contain decorator data)
        self.debug_info.clear_mappings();

        // Add each node to the new MAST forest, making sure to rewrite any outdated internal
        // `MastNodeId`s
        for live_node_builder in node_builders {
            live_node_builder.remap_children(id_remappings).add_to_forest(self).unwrap();
        }
    }

    /// Remaps and adds all old root ids to the internal set of roots.
    ///
    /// # Panics
    /// - Panics if the internal set of roots is not empty.
    fn remap_and_add_roots(
        &mut self,
        old_root_ids: Vec<MastNodeId>,
        id_remappings: &BTreeMap<MastNodeId, MastNodeId>,
    ) {
        assert!(self.roots.is_empty());

        for old_root_id in old_root_ids {
            let new_root_id = id_remappings.get(&old_root_id).copied().unwrap_or(old_root_id);
            self.make_root(new_root_id);
        }
    }
}

/// Returns the set of nodes that are live, as well as the mapping from "old ID" to "new ID" for all
/// live nodes.
fn remove_nodes(
    mast_nodes: Vec<MastNode>,
    nodes_to_remove: &BTreeSet<MastNodeId>,
) -> (Vec<MastNode>, BTreeMap<MastNodeId, MastNodeId>) {
    // Note: this allows us to safely use `usize as u32`, guaranteeing that it won't wrap around.
    assert!(mast_nodes.len() < u32::MAX as usize);

    let mut retained_nodes = Vec::with_capacity(mast_nodes.len());
    let mut id_remappings = BTreeMap::new();

    for (old_node_index, old_node) in mast_nodes.into_iter().enumerate() {
        let old_node_id: MastNodeId = MastNodeId(old_node_index as u32);

        if !nodes_to_remove.contains(&old_node_id) {
            let new_node_id: MastNodeId = MastNodeId(retained_nodes.len() as u32);
            id_remappings.insert(old_node_id, new_node_id);

            retained_nodes.push(old_node);
        }
    }

    (retained_nodes, id_remappings)
}

// ------------------------------------------------------------------------------------------------
/// Public accessors
impl MastForest {
    /// Returns the [`MastNode`] associated with the provided [`MastNodeId`] if valid, or else
    /// `None`.
    ///
    /// This is the fallible version of indexing (e.g. `mast_forest[node_id]`).
    #[inline(always)]
    pub fn get_node_by_id(&self, node_id: MastNodeId) -> Option<&MastNode> {
        self.nodes.get(node_id)
    }

    /// Returns the [`MastNodeId`] of the procedure associated with a given digest, if any.
    #[inline(always)]
    pub fn find_procedure_root(&self, digest: Word) -> Option<MastNodeId> {
        self.roots.iter().find(|&&root_id| self[root_id].digest() == digest).copied()
    }

    /// Returns true if a node with the specified ID is a root of a procedure in this MAST forest.
    pub fn is_procedure_root(&self, node_id: MastNodeId) -> bool {
        self.roots.contains(&node_id)
    }

    /// Returns an iterator over the digests of all procedures in this MAST forest.
    pub fn procedure_digests(&self) -> impl Iterator<Item = Word> + '_ {
        self.roots.iter().map(|&root_id| self[root_id].digest())
    }

    /// Returns an iterator over the digests of local procedures in this MAST forest.
    ///
    /// A local procedure is defined as a procedure which is not a single external node.
    pub fn local_procedure_digests(&self) -> impl Iterator<Item = Word> + '_ {
        self.roots.iter().filter_map(|&root_id| {
            let node = &self[root_id];
            if node.is_external() { None } else { Some(node.digest()) }
        })
    }

    /// Returns an iterator over the IDs of the procedures in this MAST forest.
    pub fn procedure_roots(&self) -> &[MastNodeId] {
        &self.roots
    }

    /// Returns the number of procedures in this MAST forest.
    pub fn num_procedures(&self) -> u32 {
        self.roots
            .len()
            .try_into()
            .expect("MAST forest contains more than 2^32 procedures.")
    }

    /// Returns the [Word] representing the content hash of a subset of [`MastNodeId`]s.
    ///
    /// # Panics
    /// This function panics if any `node_ids` is not a node of this forest.
    pub fn compute_nodes_commitment<'a>(
        &self,
        node_ids: impl IntoIterator<Item = &'a MastNodeId>,
    ) -> Word {
        let mut digests: Vec<Word> = node_ids.into_iter().map(|&id| self[id].digest()).collect();
        digests.sort_unstable_by_key(|word| LexicographicWord::from(*word));
        miden_crypto::hash::rpo::Rpo256::merge_many(&digests)
    }

    /// Returns the number of nodes in this MAST forest.
    pub fn num_nodes(&self) -> u32 {
        self.nodes.len() as u32
    }

    /// Returns the underlying nodes in this MAST forest.
    pub fn nodes(&self) -> &[MastNode] {
        self.nodes.as_slice()
    }

    pub fn advice_map(&self) -> &AdviceMap {
        &self.advice_map
    }

    pub fn advice_map_mut(&mut self) -> &mut AdviceMap {
        &mut self.advice_map
    }
}

// ------------------------------------------------------------------------------------------------
/// Decorator methods
impl MastForest {
    /// Returns a list of all decorators contained in this [MastForest].
    pub fn decorators(&self) -> &[Decorator] {
        self.debug_info.decorators()
    }

    /// Returns the [`Decorator`] associated with the provided [`DecoratorId`] if valid, or else
    /// `None`.
    ///
    /// This is the fallible version of indexing (e.g. `mast_forest[decorator_id]`).
    #[inline]
    pub fn decorator_by_id(&self, decorator_id: DecoratorId) -> Option<&Decorator> {
        self.debug_info.decorator(decorator_id)
    }

    /// Returns decorator indices for a specific operation within a node.
    ///
    /// This is the primary accessor for reading decorators from the centralized storage.
    /// Returns a slice of decorator IDs for the given operation.
    #[inline]
    pub(crate) fn decorator_indices_for_op(
        &self,
        node_id: MastNodeId,
        local_op_idx: usize,
    ) -> &[DecoratorId] {
        self.debug_info.decorators_for_operation(node_id, local_op_idx)
    }

    /// Returns an iterator over decorator references for a specific operation within a node.
    ///
    /// This is the preferred method for accessing decorators, as it provides direct
    /// references to the decorator objects.
    #[inline]
    pub fn decorators_for_op<'a>(
        &'a self,
        node_id: MastNodeId,
        local_op_idx: usize,
    ) -> impl Iterator<Item = &'a Decorator> + 'a {
        self.decorator_indices_for_op(node_id, local_op_idx)
            .iter()
            .map(move |&decorator_id| &self[decorator_id])
    }

    /// Returns the decorators to be executed before this node is executed.
    #[inline]
    pub fn before_enter_decorators(&self, node_id: MastNodeId) -> &[DecoratorId] {
        self.debug_info.before_enter_decorators(node_id)
    }

    /// Returns the decorators to be executed after this node is executed.
    #[inline]
    pub fn after_exit_decorators(&self, node_id: MastNodeId) -> &[DecoratorId] {
        self.debug_info.after_exit_decorators(node_id)
    }

    /// Returns decorator links for a node, including operation indices.
    ///
    /// This provides a flattened view of all decorators for a node with their operation indices.
    #[inline]
    pub(crate) fn decorator_links_for_node<'a>(
        &'a self,
        node_id: MastNodeId,
    ) -> Result<DecoratedLinks<'a>, DecoratorIndexError> {
        self.debug_info.decorator_links_for_node(node_id)
    }

    /// Adds a decorator to the forest, and returns the associated [`DecoratorId`].
    pub fn add_decorator(&mut self, decorator: Decorator) -> Result<DecoratorId, MastForestError> {
        self.debug_info.add_decorator(decorator)
    }

    /// Adds decorator IDs for a node to the storage.
    ///
    /// Used when building nodes for efficient decorator access during execution.
    ///
    /// # Note
    /// This method does not validate decorator IDs immediately. Validation occurs during
    /// operations that need to access the actual decorator data (e.g., merging, serialization).
    #[inline]
    pub(crate) fn register_node_decorators(
        &mut self,
        node_id: MastNodeId,
        before_enter: &[DecoratorId],
        after_exit: &[DecoratorId],
    ) {
        self.debug_info.register_node_decorators(node_id, before_enter, after_exit);
    }
}

// ------------------------------------------------------------------------------------------------
/// Error message methods
impl MastForest {
    /// Given an error code as a Felt, resolves it to its corresponding error message.
    pub fn resolve_error_message(&self, code: Felt) -> Option<Arc<str>> {
        let key = u64::from(code);
        self.debug_info.error_message(key)
    }

    /// Registers an error message in the MAST Forest and returns the corresponding error code as a
    /// Felt.
    pub fn register_error(&mut self, msg: Arc<str>) -> Felt {
        let code: Felt = error_code_from_msg(&msg);
        // we use u64 as keys for the map
        self.debug_info.insert_error_code(code.as_int(), msg);
        code
    }
}

// MAST FOREST INDEXING
// ------------------------------------------------------------------------------------------------

impl Index<MastNodeId> for MastForest {
    type Output = MastNode;

    #[inline(always)]
    fn index(&self, node_id: MastNodeId) -> &Self::Output {
        &self.nodes[node_id]
    }
}

impl IndexMut<MastNodeId> for MastForest {
    #[inline(always)]
    fn index_mut(&mut self, node_id: MastNodeId) -> &mut Self::Output {
        &mut self.nodes[node_id]
    }
}

impl Index<DecoratorId> for MastForest {
    type Output = Decorator;

    #[inline(always)]
    fn index(&self, decorator_id: DecoratorId) -> &Self::Output {
        self.debug_info.decorator(decorator_id).expect("DecoratorId out of bounds")
    }
}

impl IndexMut<DecoratorId> for MastForest {
    #[inline(always)]
    fn index_mut(&mut self, decorator_id: DecoratorId) -> &mut Self::Output {
        self.debug_info.decorator_mut(decorator_id).expect("DecoratorId out of bounds")
    }
}

// MAST NODE ID
// ================================================================================================

/// An opaque handle to a [`MastNode`] in some [`MastForest`]. It is the responsibility of the user
/// to use a given [`MastNodeId`] with the corresponding [`MastForest`].
///
/// Note that the [`MastForest`] does *not* ensure that equal [`MastNode`]s have equal
/// [`MastNodeId`] handles. Hence, [`MastNodeId`] equality must not be used to test for equality of
/// the underlying [`MastNode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub struct MastNodeId(u32);

/// Operations that mutate a MAST often produce this mapping between old and new NodeIds.
pub type Remapping = BTreeMap<MastNodeId, MastNodeId>;

impl MastNodeId {
    /// Returns a new `MastNodeId` with the provided inner value, or an error if the provided
    /// `value` is greater than the number of nodes in the forest.
    ///
    /// For use in deserialization.
    pub fn from_u32_safe(
        value: u32,
        mast_forest: &MastForest,
    ) -> Result<Self, DeserializationError> {
        Self::from_u32_with_node_count(value, mast_forest.nodes.len())
    }

    /// Returns a new [`MastNodeId`] with the provided `node_id`, or an error if `node_id` is
    /// greater than the number of nodes in the [`MastForest`] for which this ID is being
    /// constructed.
    pub fn from_usize_safe(
        node_id: usize,
        mast_forest: &MastForest,
    ) -> Result<Self, DeserializationError> {
        let node_id: u32 = node_id.try_into().map_err(|_| {
            DeserializationError::InvalidValue(format!(
                "node id '{node_id}' does not fit into a u32"
            ))
        })?;
        MastNodeId::from_u32_safe(node_id, mast_forest)
    }

    /// Returns a new [`MastNodeId`] from the given `value` without checking its validity.
    pub(crate) fn new_unchecked(value: u32) -> Self {
        Self(value)
    }

    /// Returns a new [`MastNodeId`] with the provided `id`, or an error if `id` is greater or equal
    /// to `node_count`. The `node_count` is the total number of nodes in the [`MastForest`] for
    /// which this ID is being constructed.
    ///
    /// This function can be used when deserializing an id whose corresponding node is not yet in
    /// the forest and [`Self::from_u32_safe`] would fail. For instance, when deserializing the ids
    /// referenced by the Join node in this forest:
    ///
    /// ```text
    /// [Join(1, 2), Block(foo), Block(bar)]
    /// ```
    ///
    /// Since it is less safe than [`Self::from_u32_safe`] and usually not needed it is not public.
    pub(super) fn from_u32_with_node_count(
        id: u32,
        node_count: usize,
    ) -> Result<Self, DeserializationError> {
        if (id as usize) < node_count {
            Ok(Self(id))
        } else {
            Err(DeserializationError::InvalidValue(format!(
                "Invalid deserialized MAST node ID '{id}', but {node_count} is the number of nodes in the forest",
            )))
        }
    }

    /// Remap the NodeId to its new position using the given [`Remapping`].
    pub fn remap(&self, remapping: &Remapping) -> Self {
        *remapping.get(self).unwrap_or(self)
    }
}

impl From<u32> for MastNodeId {
    fn from(value: u32) -> Self {
        MastNodeId::new_unchecked(value)
    }
}

impl Idx for MastNodeId {}

impl From<MastNodeId> for u32 {
    fn from(value: MastNodeId) -> Self {
        value.0
    }
}

impl fmt::Display for MastNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MastNodeId({})", self.0)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl proptest::prelude::Arbitrary for MastNodeId {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;
        any::<u32>().prop_map(MastNodeId).boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

// ITERATOR

/// Iterates over all the nodes a root depends on, in pre-order. The iteration can include other
/// roots in the same forest.
pub struct SubtreeIterator<'a> {
    forest: &'a MastForest,
    discovered: Vec<MastNodeId>,
    unvisited: Vec<MastNodeId>,
}
impl<'a> SubtreeIterator<'a> {
    pub fn new(root: &MastNodeId, forest: &'a MastForest) -> Self {
        let discovered = vec![];
        let unvisited = vec![*root];
        SubtreeIterator { forest, discovered, unvisited }
    }
}
impl Iterator for SubtreeIterator<'_> {
    type Item = MastNodeId;
    fn next(&mut self) -> Option<MastNodeId> {
        while let Some(id) = self.unvisited.pop() {
            let node = &self.forest[id];
            if !node.has_children() {
                return Some(id);
            } else {
                self.discovered.push(id);
                node.append_children_to(&mut self.unvisited);
            }
        }
        self.discovered.pop()
    }
}

// DECORATOR ID
// ================================================================================================

/// An opaque handle to a [`Decorator`] in some [`MastForest`]. It is the responsibility of the user
/// to use a given [`DecoratorId`] with the corresponding [`MastForest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct DecoratorId(u32);

impl DecoratorId {
    /// Returns a new `DecoratorId` with the provided inner value, or an error if the provided
    /// `value` is greater than the number of nodes in the forest.
    ///
    /// For use in deserialization.
    pub fn from_u32_safe(
        value: u32,
        mast_forest: &MastForest,
    ) -> Result<Self, DeserializationError> {
        Self::from_u32_bounded(value, mast_forest.debug_info.num_decorators())
    }

    /// Returns a new `DecoratorId` with the provided inner value, or an error if the provided
    /// `value` is greater than or equal to `bound`.
    ///
    /// For use in deserialization when the bound is known without needing the full MastForest.
    pub fn from_u32_bounded(value: u32, bound: usize) -> Result<Self, DeserializationError> {
        if (value as usize) < bound {
            Ok(Self(value))
        } else {
            Err(DeserializationError::InvalidValue(format!(
                "Invalid deserialized MAST decorator id '{}', but allows only {} decorators",
                value, bound,
            )))
        }
    }

    /// Creates a new [`DecoratorId`] without checking its validity.
    pub(crate) fn new_unchecked(value: u32) -> Self {
        Self(value)
    }
}

impl From<u32> for DecoratorId {
    fn from(value: u32) -> Self {
        DecoratorId::new_unchecked(value)
    }
}

impl Idx for DecoratorId {}

impl From<DecoratorId> for u32 {
    fn from(value: DecoratorId) -> Self {
        value.0
    }
}

impl fmt::Display for DecoratorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DecoratorId({})", self.0)
    }
}

impl Serializable for DecoratorId {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target)
    }
}

/// Derives an error code from an error message by hashing the message and returning the 0th element
/// of the resulting [`Word`].
pub fn error_code_from_msg(msg: impl AsRef<str>) -> Felt {
    // hash the message and return 0th felt of the resulting Word
    hash_string_to_word(msg.as_ref())[0]
}

// MAST FOREST ERROR
// ================================================================================================

/// Represents the types of errors that can occur when dealing with MAST forest.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum MastForestError {
    #[error("MAST forest decorator count exceeds the maximum of {} decorators", u32::MAX)]
    TooManyDecorators,
    #[error("MAST forest node count exceeds the maximum of {} nodes", MastForest::MAX_NODES)]
    TooManyNodes,
    #[error("node id {0} is greater than or equal to forest length {1}")]
    NodeIdOverflow(MastNodeId, usize),
    #[error("decorator id {0} is greater than or equal to decorator count {1}")]
    DecoratorIdOverflow(DecoratorId, usize),
    #[error("basic block cannot be created from an empty list of operations")]
    EmptyBasicBlock,
    #[error(
        "decorator root of child with node id {0} is missing but is required for fingerprint computation"
    )]
    ChildFingerprintMissing(MastNodeId),
    #[error("advice map key {0} already exists when merging forests")]
    AdviceMapKeyCollisionOnMerge(Word),
    #[error("decorator storage error: {0}")]
    DecoratorError(DecoratorIndexError),
    #[error("digest is required for deserialization")]
    DigestRequiredForDeserialization,
}

// Custom serde implementations for MastForest that handle linked decorators properly
// by delegating to the existing winter-utils serialization which already handles
// the conversion between linked and owned decorator formats.
#[cfg(feature = "serde")]
impl serde::Serialize for MastForest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Use the existing winter-utils serialization which already handles linked decorators
        let bytes = crate::utils::Serializable::to_bytes(self);
        serializer.serialize_bytes(&bytes)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for MastForest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize bytes, then use winter-utils Deserializable
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let mut slice_reader = winter_utils::SliceReader::new(&bytes);
        crate::utils::Deserializable::read_from(&mut slice_reader).map_err(serde::de::Error::custom)
    }
}
