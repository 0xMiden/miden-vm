//! MAST forest: a collection of procedures represented as Merkle trees.
//!
//! # Deserializing from untrusted sources
//!
//! When loading a `MastForest` from bytes you don't fully trust (network, user upload, etc.),
//! use [`UntrustedMastForest`] instead of calling `MastForest::read_from_bytes` directly:
//!
//! ```ignore
//! use miden_core::mast::UntrustedMastForest;
//!
//! let forest = UntrustedMastForest::read_from_bytes(&bytes)?
//!     .validate()?;
//! ```
//!
//! [`UntrustedMastForest::read_from_bytes`] applies default parsing and validation budgets derived
//! from the input size. Use [`UntrustedMastForest::read_from_bytes_with_options`] with
//! [`UntrustedMastForestReadOptions`] to tune the wire byte budget. This limits allocations driven
//! directly by wire counts while reading the payload. A separate validation helper budget is
//! derived from it for later allocations needed to materialize and check hashless payloads.
//!
//! ```ignore
//! use miden_core::mast::{UntrustedMastForest, UntrustedMastForestReadOptions};
//!
//! let options = UntrustedMastForestReadOptions::new()
//!     .with_wire_byte_budget(bytes.len());
//! let forest = UntrustedMastForest::read_from_bytes_with_options(&bytes, options)?
//!     .validate()?;
//! ```
//!
//! This recomputes all node hashes and checks structural invariants before returning a usable
//! `MastForest`. Direct deserialization via `MastForest::read_from_bytes` trusts the serialized
//! hashes and should only be used for data from trusted sources (e.g. compiled locally).
//!
//! In practice, the public entry points split into three policies:
//! - [`MastForest::read_from_bytes`]: trusted full deserialization; rejects hashless payloads and
//!   trusts serialized non-external digests.
//! - [`MastForestWireView::new`]: trusted wire-backed cache access; scans only the layout needed
//!   for random access and rejects hashless payloads.
//! - [`UntrustedMastForest::read_from_bytes`] and
//!   [`UntrustedMastForest::read_from_bytes_with_options`]: untrusted paths; parse with bounded
//!   readers and require [`UntrustedMastForest::validate`] before use.

#[cfg(test)]
use alloc::collections::BTreeSet;
use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::{fmt, ops::Index};

#[cfg(any(test, feature = "arbitrary"))]
use proptest::prelude::*;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serde")]
use crate::serde::{Deserializable, SliceReader};

mod node;
#[cfg(any(test, feature = "arbitrary"))]
pub use node::arbitrary;
pub(crate) use node::collect_immediate_placements;
pub use node::{
    BasicBlockNode, BasicBlockNodeBuilder, CallNode, CallNodeBuilder, DynNode, DynNodeBuilder,
    ExternalNode, ExternalNodeBuilder, JoinNode, JoinNodeBuilder, LoopNode, LoopNodeBuilder,
    MastForestContributor, MastNode, MastNodeBuilder, MastNodeContext, MastNodeExt, OP_BATCH_SIZE,
    OP_GROUP_SIZE, OpBatch, SplitNode, SplitNodeBuilder,
};

use crate::{
    Felt, Word,
    advice::AdviceMap,
    crypto::hash::Poseidon2,
    serde::{ByteWriter, DeserializationError, Serializable},
    utils::{DenseIdMap, Idx, IndexVec, hash_string_to_word},
};

mod serialization;
pub use serialization::{
    AdviceMapView, AdviceValueView, MastForestReadMode, MastForestReadView, MastForestView,
    MastForestWireView, MastNodeEntry, MastNodeInfo,
};

mod dense_builder;
pub use dense_builder::DenseMastForestBuilder;

mod untrusted;
pub use untrusted::{UntrustedMastForest, UntrustedMastForestReadOptions};

mod merger;
pub(crate) use merger::MastForestMerger;
pub use merger::MastForestRootMap;

mod multi_forest_node_iterator;
pub(crate) use multi_forest_node_iterator::*;

mod node_builder_utils;
pub use node_builder_utils::build_node_with_remapped_ids;

mod sparse;
pub use sparse::{MastForestId, SparseMastForest, SparseMastForestBuilder, VisitKind};

#[cfg(test)]
mod tests;

// MAST FOREST
// ================================================================================================

/// Represents one or more procedures, represented as a collection of [`MastNode`]s.
///
/// A [`MastForest`] does not have an entrypoint, and hence is not executable. A
/// [`crate::program::Program`] can be built from a [`MastForest`] to specify an entrypoint.
///
/// Finalized dense forests keep nodes in final dense order:
/// - external nodes first, sorted by digest, with no duplicate external digests;
/// - basic blocks next, in the input order seen by finalization;
/// - internal nodes last, with every child before its parent and finalization input order as the
///   tie-breaker.
///
/// Serialization expects this in-memory order and validates it before writing.
#[derive(Clone, Debug, Default)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true))
)]
pub struct MastForest {
    /// All of the nodes local to the trees comprising the MAST forest.
    nodes: IndexVec<MastNodeId, MastNode>,

    /// Roots of procedures defined within this MAST forest.
    roots: Vec<MastNodeId>,

    /// Advice map to be loaded into the VM prior to executing procedures from this MAST forest.
    advice_map: AdviceMap,

    /// Commitments to this MAST forest's roots, external dependencies, and advice map.
    commitment: MastForestCommitment,
}

/// Commitment values derived from a MAST forest.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct MastForestCommitment {
    /// Commitment to the forest's roots, external dependencies, and advice map.
    commitment: Word,

    /// Commitment to this MAST forest's public procedure roots.
    interface_commitment: Word,

    /// Commitment to this MAST forest's external dependencies.
    dependency_commitment: Word,

    /// Commitment to this MAST forest's advice map.
    advice_commitment: Word,
}

/// Complete parts needed to construct a finalized [`MastForest`].
pub(crate) struct MastForestParts {
    pub nodes: IndexVec<MastNodeId, MastNode>,
    pub roots: Vec<MastNodeId>,
    pub advice_map: AdviceMap,
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
            commitment: empty_mast_forest_commitment(),
        }
    }

    /// Builds a [`MastForest`] from raw parts and validates local structure.
    #[doc(hidden)]
    pub fn from_raw_parts(
        nodes: IndexVec<MastNodeId, MastNode>,
        roots: Vec<MastNodeId>,
        advice_map: AdviceMap,
    ) -> Result<Self, MastForestError> {
        Self::from_parts(MastForestParts { nodes, roots, advice_map })
    }

    /// Builds a [`MastForest`] from raw parts and returns the node ID remapping applied during
    /// canonicalization.
    #[doc(hidden)]
    pub fn from_raw_parts_with_id_map(
        nodes: IndexVec<MastNodeId, MastNode>,
        roots: Vec<MastNodeId>,
        advice_map: AdviceMap,
    ) -> Result<(Self, DenseIdMap<MastNodeId, MastNodeId>), MastForestError> {
        Self::from_parts_with_id_map(MastForestParts { nodes, roots, advice_map })
    }

    /// Builds a [`MastForest`] from completed parts.
    pub(crate) fn from_parts(parts: MastForestParts) -> Result<Self, MastForestError> {
        Self::from_parts_with_id_map(parts).map(|(forest, _remapping)| forest)
    }

    pub(crate) fn from_parts_with_id_map(
        parts: MastForestParts,
    ) -> Result<(Self, DenseIdMap<MastNodeId, MastNodeId>), MastForestError> {
        validate_mast_forest_parts_bounds(&parts)?;
        let (parts, id_remapping) = canonicalize_dense_parts(parts)?;

        let forest = Self {
            commitment: compute_mast_forest_commitment(
                &parts.nodes,
                &parts.roots,
                &parts.advice_map,
            ),
            nodes: parts.nodes,
            roots: parts.roots,
            advice_map: parts.advice_map,
        };

        forest.validate_dense_node_order()?;
        forest.validate()?;
        forest.validate_node_hashes()?;
        Ok((forest, id_remapping))
    }

    pub(in crate::mast) fn from_trusted_deserialization_parts(
        parts: MastForestParts,
    ) -> Result<Self, MastForestError> {
        validate_mast_forest_parts_bounds(&parts)?;
        // Trusted dense serialization is expected to have checked this already. Re-check the
        // cheap ordering invariant here as a precaution before accepting the finalized forest.
        validate_dense_node_order(&parts.nodes)?;
        Ok(Self {
            commitment: compute_mast_forest_commitment(
                &parts.nodes,
                &parts.roots,
                &parts.advice_map,
            ),
            nodes: parts.nodes,
            roots: parts.roots,
            advice_map: parts.advice_map,
        })
    }
}

fn validate_mast_forest_parts_bounds(parts: &MastForestParts) -> Result<(), MastForestError> {
    if parts.nodes.len() > MastForest::MAX_NODES {
        return Err(MastForestError::TooManyNodes);
    }

    let node_count = parts.nodes.len();
    for &root_id in &parts.roots {
        if root_id.to_usize() >= node_count {
            return Err(MastForestError::NodeIdOverflow(root_id, node_count));
        }
    }

    Ok(())
}

fn canonicalize_dense_parts(
    parts: MastForestParts,
) -> Result<(MastForestParts, DenseIdMap<MastNodeId, MastNodeId>), MastForestError> {
    let node_count = parts.nodes.len();
    let mut ordered_ids = (0..node_count)
        .map(|index| MastNodeId::new_unchecked(index as u32))
        .collect::<Vec<_>>();

    // Preserve old dense node-id order within basic blocks and internal nodes. This constructor
    // only moves nodes across the external/basic-block/internal partitions; callers must already
    // provide internal nodes in child-before-parent order.
    ordered_ids.sort_by(|&left, &right| {
        let left_node = &parts.nodes[left];
        let right_node = &parts.nodes[right];

        mast_node_order_class(left_node)
            .cmp(&mast_node_order_class(right_node))
            .then_with(|| match (left_node, right_node) {
                (MastNode::External(left), MastNode::External(right)) => {
                    left.digest().cmp(&right.digest())
                },
                _ => left.0.cmp(&right.0),
            })
    });

    let mut remapping = DenseIdMap::with_len(node_count);
    for (new_index, old_id) in ordered_ids.iter().copied().enumerate() {
        remapping.insert(old_id, MastNodeId::new_unchecked(new_index as u32));
    }

    if ordered_ids
        .iter()
        .enumerate()
        .all(|(index, &old_id)| old_id == MastNodeId::new_unchecked(index as u32))
    {
        validate_dense_node_order(&parts.nodes)?;
        return Ok((parts, remapping));
    }

    let mut nodes = IndexVec::with_capacity(node_count);
    let empty_forest = MastForest::new();
    for old_id in ordered_ids {
        let node = parts.nodes[old_id].clone();
        let remapped_node =
            node.to_builder(&empty_forest).remap_children(&remapping).build_linked()?;
        nodes.push(remapped_node).map_err(|_| MastForestError::TooManyNodes)?;
    }

    let roots = parts
        .roots
        .into_iter()
        .map(|root_id| {
            remapping
                .get(root_id)
                .ok_or(MastForestError::NodeIdOverflow(root_id, node_count))
        })
        .collect::<Result<Vec<_>, _>>()?;

    validate_dense_node_order(&nodes)?;

    Ok((
        MastForestParts {
            nodes,
            roots,
            advice_map: parts.advice_map,
        },
        remapping,
    ))
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum MastNodeOrderClass {
    External,
    BasicBlock,
    Internal,
}

fn mast_node_order_class(node: &MastNode) -> MastNodeOrderClass {
    if node.is_external() {
        MastNodeOrderClass::External
    } else if node.is_basic_block() {
        MastNodeOrderClass::BasicBlock
    } else {
        MastNodeOrderClass::Internal
    }
}

fn validate_dense_node_order(
    nodes: &IndexVec<MastNodeId, MastNode>,
) -> Result<(), MastForestError> {
    let mut previous_class = MastNodeOrderClass::External;
    let mut previous_external_digest = None;

    for (node_index, node) in nodes.iter().enumerate() {
        let node_id = MastNodeId::new_unchecked(node_index as u32);
        let node_class = mast_node_order_class(node);

        if node_class < previous_class {
            return Err(MastForestError::InvalidNodeOrder {
                node_id,
                reason: format!("node class {node_class:?} appears after {previous_class:?}"),
            });
        }
        previous_class = node_class;

        if let MastNode::External(external_node) = node {
            let digest = external_node.digest();
            if let Some(previous_digest) = previous_external_digest
                && previous_digest >= digest
            {
                return Err(MastForestError::InvalidNodeOrder {
                    node_id,
                    reason: "external node digests must be strictly increasing".into(),
                });
            }
            previous_external_digest = Some(digest);
        }

        let mut forward_child = None;
        node.for_each_child(|child_id| {
            if child_id.0 >= node_id.0 {
                forward_child = Some(child_id);
            }
        });
        if let Some(child_id) = forward_child {
            return Err(MastForestError::ForwardReference(node_id, child_id));
        }
    }

    Ok(())
}

// ------------------------------------------------------------------------------------------------
/// Equality implementations
impl PartialEq for MastForest {
    fn eq(&self, other: &Self) -> bool {
        self.nodes == other.nodes
            && self.roots == other.roots
            && self.advice_map == other.advice_map
    }
}

impl Eq for MastForest {}

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
    #[cfg(any(test, feature = "arbitrary"))]
    pub fn make_root(&mut self, new_root_id: MastNodeId) {
        assert!(new_root_id.to_usize() < self.nodes.len());

        if !self.roots.contains(&new_root_id) {
            self.roots.push(new_root_id);
            self.commitment = self.compute_mast_forest_commitment();
        }
    }

    /// Removes all nodes in the provided set from the MAST forest. The nodes MUST be orphaned (i.e.
    /// have no parent). Otherwise, this parent's reference is considered "dangling" after the
    /// removal (i.e. will point to an incorrect node after the removal), and this removal operation
    /// would result in an invalid [`MastForest`].
    ///
    /// It also returns the map from old node IDs to new node IDs. Any [`MastNodeId`] used in
    /// reference to the old [`MastForest`] should be remapped using this map.
    #[cfg(test)]
    pub fn remove_nodes(
        &mut self,
        nodes_to_remove: &BTreeSet<MastNodeId>,
    ) -> BTreeMap<MastNodeId, MastNodeId> {
        if nodes_to_remove.is_empty() {
            return BTreeMap::new();
        }

        self.assert_nodes_to_remove_are_orphaned(nodes_to_remove);

        let old_nodes = core::mem::replace(&mut self.nodes, IndexVec::new());
        let old_root_ids = core::mem::take(&mut self.roots);
        let (retained_nodes, id_remappings) = remove_nodes(old_nodes.into_inner(), nodes_to_remove);

        self.remap_and_add_nodes(retained_nodes, &id_remappings);
        self.remap_and_add_roots(old_root_ids, &id_remappings);

        self.commitment = self.compute_mast_forest_commitment();

        id_remappings
    }

    /// Compacts the forest by merging duplicate nodes.
    ///
    /// This operation performs node deduplication by merging the forest with itself.
    /// This method consumes the forest and returns a new compacted forest.
    ///
    /// The process works by:
    /// 1. Merging the forest with itself to deduplicate identical nodes
    /// 2. Updating internal node references and remappings
    /// 3. Returning the compacted forest and root map
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_core::mast::MastForest;
    ///
    /// let forest = MastForest::new();
    /// // Add nodes to the forest
    ///
    /// // Compact the forest (consumes the original)
    /// let (compacted_forest, root_map) = forest.compact();
    ///
    /// // compacted_forest is now compacted with duplicate nodes merged
    /// ```
    pub fn compact(self) -> (MastForest, MastForestRootMap) {
        // Merge with itself to deduplicate nodes
        // Note: This cannot fail for a self-merge under normal conditions.
        // The only possible failure (TooManyNodes) would require the original forest to be at a
        // capacity limit, at which point compaction wouldn't help.
        MastForest::merge([&self])
            .expect("Failed to compact MastForest: this should never happen during self-merge")
    }

    /// Merges all `forests` into a new [`MastForest`].
    ///
    /// Merging two forests means combining all their constituent parts, i.e. [`MastNode`]s and
    /// roots. During this process, any duplicate or unreachable nodes are removed. Additionally,
    /// [`MastNodeId`]s of nodes may change and references to them are remapped to their new
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
    /// which is effectively deduplication.
    pub fn merge<'forest>(
        forests: impl IntoIterator<Item = &'forest MastForest>,
    ) -> Result<(MastForest, MastForestRootMap), MastForestError> {
        MastForestMerger::merge(forests)
    }
}

// ------------------------------------------------------------------------------------------------
/// Helpers
impl MastForest {
    #[cfg(test)]
    fn assert_nodes_to_remove_are_orphaned(&self, nodes_to_remove: &BTreeSet<MastNodeId>) {
        for (node_idx, node) in self.nodes.iter().enumerate() {
            let node_id = MastNodeId::new_unchecked(node_idx.try_into().expect("too many nodes"));
            if nodes_to_remove.contains(&node_id) {
                continue;
            }

            node.for_each_child(|child_id| {
                assert!(
                    !nodes_to_remove.contains(&child_id),
                    "cannot remove node {child_id:?}; retained node {node_id:?} references it"
                );
            });
        }
    }

    /// Adds all provided nodes to the internal set of nodes, remapping all [`MastNodeId`]
    /// references in those nodes.
    ///
    /// # Panics
    /// - Panics if the internal set of nodes is not empty.
    #[cfg(test)]
    fn remap_and_add_nodes(
        &mut self,
        nodes_to_add: Vec<MastNode>,
        id_remappings: &BTreeMap<MastNodeId, MastNodeId>,
    ) {
        assert!(self.nodes.is_empty());
        let node_builders =
            nodes_to_add.into_iter().map(|node| node.to_builder(self)).collect::<Vec<_>>();

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
    #[cfg(test)]
    fn remap_and_add_roots(
        &mut self,
        old_root_ids: Vec<MastNodeId>,
        id_remappings: &BTreeMap<MastNodeId, MastNodeId>,
    ) {
        assert!(self.roots.is_empty());

        for old_root_id in old_root_ids {
            if let Some(new_root_id) = id_remappings.get(&old_root_id).copied() {
                self.make_root(new_root_id);
            }
        }
    }
}

/// Returns the set of nodes that are live, as well as the mapping from "old ID" to "new ID" for all
/// live nodes.
#[cfg(test)]
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

fn empty_mast_forest_commitment() -> MastForestCommitment {
    let interface_commitment = Poseidon2::merge_many(&[]);
    let dependency_commitment = Poseidon2::merge_many(&[]);
    let advice_commitment = AdviceMap::default().commitment();
    MastForestCommitment::new(interface_commitment, dependency_commitment, advice_commitment)
}

fn compute_nodes_commitment(
    nodes: &IndexVec<MastNodeId, MastNode>,
    node_ids: &[MastNodeId],
) -> Word {
    let mut digests: Vec<Word> = node_ids.iter().map(|&id| nodes[id].digest()).collect();
    digests.sort_unstable();
    Poseidon2::merge_many(&digests)
}

fn compute_dependency_commitment(nodes: &IndexVec<MastNodeId, MastNode>) -> Word {
    let mut digests: Vec<Word> = nodes
        .iter()
        .filter(|node| node.is_external())
        .map(MastNodeExt::digest)
        .collect();
    digests.sort_unstable();
    Poseidon2::merge_many(&digests)
}

impl MastForestCommitment {
    fn new(
        interface_commitment: Word,
        dependency_commitment: Word,
        advice_commitment: Word,
    ) -> Self {
        let commitment = Poseidon2::merge_many(&[
            interface_commitment,
            dependency_commitment,
            advice_commitment,
        ]);
        Self {
            commitment,
            interface_commitment,
            dependency_commitment,
            advice_commitment,
        }
    }
}

fn compute_mast_forest_commitment(
    nodes: &IndexVec<MastNodeId, MastNode>,
    roots: &[MastNodeId],
    advice_map: &AdviceMap,
) -> MastForestCommitment {
    let interface_commitment = compute_nodes_commitment(nodes, roots);
    let dependency_commitment = compute_dependency_commitment(nodes);
    let advice_commitment = advice_map.commitment();
    MastForestCommitment::new(interface_commitment, dependency_commitment, advice_commitment)
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

    /// Returns true if a node with the specified ID is a root of a procedure in this MAST forest,
    /// and the digest of that procedure is `digest`.
    ///
    /// This is primarily intended for use in confirming that procedure exports of a package,
    /// which declare their MAST node and digest, actually exist in the MAST.
    pub fn is_procedure_root_with_exact_digest(&self, node_id: MastNodeId, digest: Word) -> bool {
        self.is_procedure_root(node_id) && self[node_id].digest() == digest
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
        let node_ids = node_ids.into_iter().copied().collect::<Vec<_>>();
        compute_nodes_commitment(&self.nodes, &node_ids)
    }

    /// Returns the commitment to this MAST forest's public procedure roots.
    ///
    /// The commitment is computed as the sequential hash of all procedure root digests after
    /// sorting them by digest.
    pub fn interface_commitment(&self) -> Word {
        self.commitment.interface_commitment
    }

    /// Returns the commitment to this MAST forest's external dependencies.
    ///
    /// The commitment is computed as the sequential hash of all external node digests after
    /// sorting them by digest.
    pub fn dependency_commitment(&self) -> Word {
        self.commitment.dependency_commitment
    }

    /// Returns the commitment to this MAST forest's advice map.
    ///
    /// The commitment is computed over advice entries in key order.
    pub fn advice_commitment(&self) -> Word {
        self.commitment.advice_commitment
    }

    fn compute_mast_forest_commitment(&self) -> MastForestCommitment {
        compute_mast_forest_commitment(&self.nodes, &self.roots, &self.advice_map)
    }

    /// Returns the commitment to this MAST forest.
    ///
    /// The commitment is computed from the interface, dependency, and advice commitments.
    pub fn commitment(&self) -> Word {
        self.commitment.commitment
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

    /// Returns this forest with `advice_map` entries added.
    pub fn with_advice_map(mut self, advice_map: AdviceMap) -> Self {
        self.advice_map.extend(advice_map);
        self.commitment = self.compute_mast_forest_commitment();
        self
    }

    // SERIALIZATION
    // --------------------------------------------------------------------------------------------

    /// Serializes this MastForest with the HASHLESS flag set.
    ///
    /// Hashless forest bytes omit rebuildable internal node hashes. External node digests stay on
    /// the wire because they cannot be rebuilt from local structure. Trusted deserialization
    /// rejects this flag.
    ///
    /// Use this when producing data for untrusted validation.
    pub fn write_hashless<W: ByteWriter>(&self, target: &mut W) {
        serialization::write_hashless_into(self, target);
    }
}

/// Validation methods
impl MastForest {
    pub(in crate::mast) fn validate_dense_node_order(&self) -> Result<(), MastForestError> {
        validate_dense_node_order(&self.nodes)
    }

    fn validate_basic_block_invariants(&self) -> Result<(), MastForestError> {
        for (node_id_idx, node) in self.nodes.iter().enumerate() {
            let node_id =
                MastNodeId::new_unchecked(node_id_idx.try_into().expect("too many nodes"));
            if let MastNode::Block(basic_block) = node {
                basic_block.validate_batch_invariants().map_err(|error_msg| {
                    MastForestError::InvalidBatchPadding(node_id, error_msg)
                })?;
            }
        }

        Ok(())
    }

    /// Validates that all BasicBlockNodes in this forest satisfy the core invariants:
    /// 1. Power-of-two number of groups in each batch
    /// 2. No operation group ends with an operation requiring an immediate value
    /// 3. The last operation group in a batch cannot contain operations requiring immediate values
    /// 4. OpBatch structural consistency (num_groups <= BATCH_SIZE, group size <= GROUP_SIZE,
    ///    indptr integrity, bounds checking)
    ///
    /// This addresses the gap created by PR 2094, where padding NOOPs are now inserted
    /// at assembly time rather than dynamically during execution, and adds comprehensive
    /// structural validation to prevent deserialization-time panics.
    pub fn validate(&self) -> Result<(), MastForestError> {
        self.validate_basic_block_invariants()?;
        Ok(())
    }

    /// Validates that stored node digests match the hashes implied by local structure.
    ///
    /// For `External` nodes the digest is accepted as-is because it is externally provided and
    /// cannot be reconstructed from local structure alone.
    fn validate_node_hashes(&self) -> Result<(), MastForestError> {
        let computed_hashes = self.compute_node_hashes()?;
        for (node_idx, (node, computed_digest)) in
            self.nodes.iter().zip(computed_hashes).enumerate()
        {
            let expected_digest = node.digest();
            if expected_digest != computed_digest {
                return Err(MastForestError::HashMismatch {
                    node_id: MastNodeId::new_unchecked(node_idx as u32),
                    expected: expected_digest,
                    computed: computed_digest,
                });
            }
        }

        Ok(())
    }

    /// Computes node hashes in topological order.
    ///
    /// The returned vector is aligned with node indices, so `digests[node_id as usize]` is the
    /// digest of that node.
    ///
    /// For `External` nodes, the existing digest is returned unchanged.
    ///
    /// Returns [`MastForestError::ForwardReference`] if nodes are not in topological order.
    fn compute_node_hashes(&self) -> Result<Vec<Word>, MastForestError> {
        use crate::chiplets::hasher;

        /// Checks that child_id references a node that appears before node_id in topological order.
        fn check_no_forward_ref(
            node_id: MastNodeId,
            child_id: MastNodeId,
        ) -> Result<(), MastForestError> {
            if child_id.0 >= node_id.0 {
                return Err(MastForestError::ForwardReference(node_id, child_id));
            }
            Ok(())
        }

        let mut computed_hashes = Vec::with_capacity(self.nodes.len());
        for (node_idx, node) in self.nodes.iter().enumerate() {
            let node_id = MastNodeId::new_unchecked(node_idx as u32);

            // Check topological ordering and compute digest.
            let computed_digest = match node {
                MastNode::Block(block) => {
                    let op_groups: Vec<Felt> =
                        block.op_batches().iter().flat_map(|batch| *batch.groups()).collect();
                    hasher::hash_elements(&op_groups)
                },
                MastNode::Join(join) => {
                    let left_id = join.first();
                    let right_id = join.second();
                    check_no_forward_ref(node_id, left_id)?;
                    check_no_forward_ref(node_id, right_id)?;

                    let left_digest = computed_hashes[left_id.0 as usize];
                    let right_digest = computed_hashes[right_id.0 as usize];
                    hasher::merge_in_domain(&[left_digest, right_digest], JoinNode::DOMAIN)
                },
                MastNode::Split(split) => {
                    let true_id = split.on_true();
                    let false_id = split.on_false();
                    check_no_forward_ref(node_id, true_id)?;
                    check_no_forward_ref(node_id, false_id)?;

                    let true_digest = computed_hashes[true_id.0 as usize];
                    let false_digest = computed_hashes[false_id.0 as usize];
                    hasher::merge_in_domain(&[true_digest, false_digest], SplitNode::DOMAIN)
                },
                MastNode::Loop(loop_node) => {
                    let body_id = loop_node.body();
                    check_no_forward_ref(node_id, body_id)?;

                    let body_digest = computed_hashes[body_id.0 as usize];
                    hasher::merge_in_domain(&[body_digest, Word::default()], LoopNode::DOMAIN)
                },
                MastNode::Call(call) => {
                    let callee_id = call.callee();
                    check_no_forward_ref(node_id, callee_id)?;

                    let callee_digest = computed_hashes[callee_id.0 as usize];
                    let domain = if call.is_syscall() {
                        CallNode::SYSCALL_DOMAIN
                    } else {
                        CallNode::CALL_DOMAIN
                    };
                    hasher::merge_in_domain(&[callee_digest, Word::default()], domain)
                },
                MastNode::Dyn(dyn_node) => {
                    if dyn_node.is_dyncall() {
                        DynNode::DYNCALL_DEFAULT_DIGEST
                    } else {
                        DynNode::DYN_DEFAULT_DIGEST
                    }
                },
                MastNode::External(_) => {
                    // External nodes have externally-provided digests that cannot be recomputed.
                    node.digest()
                },
            };

            computed_hashes.push(computed_digest);
        }

        Ok(computed_hashes)
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

// EXECUTABLE MAST FOREST
// ================================================================================================

/// A MAST forest that can be used as the source of nodes during program execution.
///
/// Implemented by both [`MastForest`] (a dense forest containing all nodes) and
/// [`SparseMastForest`] (a sparse subset of a forest containing only the nodes visited during
/// some prior execution). The latter preserves the original [`MastNodeId`]s of its source forest,
/// which allows it to stand in for the dense forest during re-execution.
pub trait ExecutableMastForest {
    /// Returns the [`MastNode`] associated with the provided [`MastNodeId`] if present, or else
    /// `None`.
    fn get_node_by_id(&self, node_id: MastNodeId) -> Option<&MastNode>;

    /// Returns the digest of the node associated with the provided [`MastNodeId`] if present, or
    /// else `None`.
    ///
    /// For dense forests this is equivalent to `get_node_by_id(id).map(|n| n.digest())`. For
    /// [`SparseMastForest`], it additionally consults the digest-only entries — nodes that were
    /// referenced (but not entered) during execution and which were therefore stored as digest
    /// only. Use this method whenever only the digest of a referenced node is needed (e.g. when
    /// populating the hasher state of a parent's trace row).
    fn get_digest_by_id(&self, node_id: MastNodeId) -> Option<Word>;

    /// Returns the [`MastNodeId`] of the procedure associated with a given digest, if any.
    fn find_procedure_root(&self, digest: Word) -> Option<MastNodeId>;

    /// Returns the advice map associated with this forest.
    fn advice_map(&self) -> &AdviceMap;
}

impl ExecutableMastForest for MastForest {
    #[inline(always)]
    fn get_node_by_id(&self, node_id: MastNodeId) -> Option<&MastNode> {
        MastForest::get_node_by_id(self, node_id)
    }

    #[inline(always)]
    fn get_digest_by_id(&self, node_id: MastNodeId) -> Option<Word> {
        MastForest::get_node_by_id(self, node_id).map(MastNodeExt::digest)
    }

    #[inline(always)]
    fn find_procedure_root(&self, digest: Word) -> Option<MastNodeId> {
        MastForest::find_procedure_root(self, digest)
    }

    #[inline(always)]
    fn advice_map(&self) -> &AdviceMap {
        MastForest::advice_map(self)
    }
}

// Blanket impl: an `Arc<T>` is an `ExecutableMastForest` whenever the underlying `T` is, which
// allows the executor and tracer plumbing to be generic over a forest type while the live
// (`Arc<MastForest>`) and replay (`Arc<SparseMastForest>`) paths each pick a concrete instance.
impl<T> Index<MastNodeId> for Arc<T>
where
    T: Index<MastNodeId, Output = MastNode> + ?Sized,
{
    type Output = MastNode;

    #[inline(always)]
    fn index(&self, node_id: MastNodeId) -> &Self::Output {
        &(**self)[node_id]
    }
}

impl<T: ExecutableMastForest + ?Sized> ExecutableMastForest for Arc<T> {
    #[inline(always)]
    fn get_node_by_id(&self, node_id: MastNodeId) -> Option<&MastNode> {
        T::get_node_by_id(self, node_id)
    }

    #[inline(always)]
    fn get_digest_by_id(&self, node_id: MastNodeId) -> Option<Word> {
        T::get_digest_by_id(self, node_id)
    }

    #[inline(always)]
    fn find_procedure_root(&self, digest: Word) -> Option<MastNodeId> {
        T::find_procedure_root(self, digest)
    }

    #[inline(always)]
    fn advice_map(&self) -> &AdviceMap {
        T::advice_map(self)
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

    /// Returns a new [`MastNodeId`] from the given `value` without checking its validity.
    pub fn new_unchecked(value: u32) -> Self {
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

impl Serializable for MastNodeId {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        Serializable::write_into(&self.0, target);
    }
}

impl fmt::Display for MastNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MastNodeId({})", self.0)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl Arbitrary for MastNodeId {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;
        any::<u32>().prop_map(MastNodeId).boxed()
    }

    type Strategy = BoxedStrategy<Self>;
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

/// Derives an error code from an error message by hashing the message and returning the 0th element
/// of the resulting [`Word`].
pub fn error_code_from_msg(msg: impl AsRef<str>) -> Felt {
    // hash the message and return 0th felt of the resulting Word
    hash_string_to_word(msg.as_ref())[0]
}

// MAST FOREST ERROR
// ================================================================================================

/// Represents the types of errors that can occur when dealing with MAST forest.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MastForestError {
    #[error("MAST forest node count exceeds the maximum of {} nodes", MastForest::MAX_NODES)]
    TooManyNodes,
    #[error("node id {0} is greater than or equal to forest length {1}")]
    NodeIdOverflow(MastNodeId, usize),
    #[error("basic block cannot be created from an empty list of operations")]
    EmptyBasicBlock,
    #[error("advice map key {0} already exists when merging forests")]
    AdviceMapKeyCollisionOnMerge(Word),
    #[error("digest is required for deserialization")]
    DigestRequiredForDeserialization,
    #[error("invalid batch in basic block node {0:?}: {1}")]
    InvalidBatchPadding(MastNodeId, String),
    #[error("invalid node order at {node_id:?}: {reason}")]
    InvalidNodeOrder { node_id: MastNodeId, reason: String },
    #[error(
        "node {0:?} references child {1:?} which comes after it in the forest (forward reference)"
    )]
    ForwardReference(MastNodeId, MastNodeId),
    #[error("hash mismatch for node {node_id:?}: expected {expected:?}, computed {computed:?}")]
    HashMismatch {
        node_id: MastNodeId,
        expected: Word,
        computed: Word,
    },
    #[error("deserialization failed: {0}")]
    Deserialization(DeserializationError),
}

// Custom serde implementation for MastForest delegates to the binary serialization format.
#[cfg(feature = "serde")]
impl Serialize for MastForest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = Serializable::to_bytes(self);
        serializer.serialize_bytes(&bytes)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for MastForest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize bytes, then use miden-crypto Deserializable
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let mut slice_reader = SliceReader::new(&bytes);
        Deserializable::read_from(&mut slice_reader).map_err(serde::de::Error::custom)
    }
}
