use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::ToString,
    sync::Arc,
    vec::Vec,
};

use miden_utils_indexing::newtype_id;

use crate::{
    Word,
    advice::AdviceMap,
    mast::{
        ExecutableMastForest, MastForest, MastForestError, MastForestMergeSource,
        MastForestRootMap, MastNode, MastNodeExt, MastNodeId, MixedMastForestMerger,
    },
    serde::DeserializationError,
    utils::Idx,
};

// MAST FOREST ID
// ================================================================================================

// `MastForestId` is an opaque handle to a [`MastForest`] in some forest store such as an execution
// trace replay's `mast_forest_store`. It is not a content-derived or stable identity for a forest,
// and must not be compared or reused across stores or trace contexts. It is analogous to
// `MastNodeId`, which is meaningful only within one forest's node store.
newtype_id!(
    #[cfg_attr(
        all(feature = "arbitrary", test),
        miden_test_serialization_macros::serialization_test
    )]
    pub struct MastForestId;
);

#[cfg(all(feature = "arbitrary", test))]
use crate::serde::{Deserializable, Serializable};

#[cfg(any(test, feature = "arbitrary"))]
mod mast_forest_id_arbitrary {
    use proptest::prelude::*;

    use super::MastForestId;

    impl Arbitrary for MastForestId {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            // Opaque u32 handle; edge-biased to the 0 and u32::MAX bounds.
            prop_oneof![Just(0u32), Just(u32::MAX), any::<u32>()]
                .prop_map(Self::from)
                .boxed()
        }
    }
}

// SPARSE MAST FOREST
// ================================================================================================

/// A sparse replay view over a single source [`MastForest`]'s [`MastNodeId`] space, retaining only
/// the nodes visited during execution.
///
/// Unlike [`MastForest`], which stores nodes contiguously in an `IndexVec`, a [`SparseMastForest`]
/// uses a `BTreeMap` so that it can preserve the original [`MastNodeId`]s of the source forest
/// while omitting nodes that were not visited. A [`SparseMastForest`] is not an independent forest
/// shape: it shares its source forest's ID space, and is intended to back re-execution of the same
/// program. Lookups by the original [`MastNodeId`] continue to resolve to the correct
/// [`MastNode`]s.
///
/// In addition to the visited nodes, a [`SparseMastForest`] may also carry digest-only entries for
/// nodes that were referenced during execution but never actually entered (e.g. the not-taken
/// branch of a split, or the children of a join that only need to contribute their digests to the
/// parent's trace row). These entries let trace generation read the digest without having to copy
/// the full child node, and they make accidental entry into a pruned node a clean
/// `get_node_by_id` miss rather than a partially-populated node.
///
/// Its serialized form is a version-local replay format. The default reader checks full-node
/// hashes against available child digests. Digest-only entries and external nodes remain opaque:
/// these checks do not prove membership in a source forest. The explicit trusted reader skips
/// hash recomputation. This format must not be persisted across releases.
#[derive(Debug)]
pub struct SparseMastForest {
    /// Subset of the original forest's nodes, keyed by their original [`MastNodeId`].
    nodes: BTreeMap<MastNodeId, MastNode>,

    /// Digests of nodes that were referenced (but not entered) during execution, keyed by their
    /// original [`MastNodeId`]. Nodes present in [`Self::nodes`] are excluded from this map: a
    /// full-node entry implicitly carries its own digest via [`MastNodeExt::digest`].
    digests: BTreeMap<MastNodeId, Word>,

    /// Roots of procedures defined within the original MAST forest.
    roots: Vec<MastNodeId>,

    /// Advice map to be loaded into the VM prior to executing procedures from this MAST forest.
    advice_map: AdviceMap,
}

impl SparseMastForest {
    /// Extracts the complete subgraphs reachable from selected procedure roots.
    ///
    /// Every selected root must be exported by `source`. Node IDs and child references remain in
    /// the source forest's ID space, and repeated roots remain repeated in the result. All
    /// reachable nodes are copied in full, including both split branches and call targets.
    /// External and dynamic nodes are leaves. Advice data is not copied because sparse replay uses
    /// `AdviceReplay`.
    ///
    /// This constructor assumes that `source` is valid. It does not rebuild node hashes or route
    /// the nodes through a forest builder.
    pub fn from_procedure_roots(
        source: &MastForest,
        roots: &[MastNodeId],
    ) -> Result<Self, MastForestError> {
        for &root in roots {
            if !source.is_procedure_root(root) {
                return Err(MastForestError::NotAProcedureRoot(root));
            }
        }

        let mut nodes = BTreeMap::new();
        let mut unvisited = roots.to_vec();
        while let Some(node_id) = unvisited.pop() {
            if nodes.contains_key(&node_id) {
                continue;
            }

            let node = source.get_node_by_id(node_id).ok_or_else(|| {
                MastForestError::NodeIdOverflow(node_id, source.num_nodes() as usize)
            })?;
            node.append_children_to(&mut unvisited);
            nodes.insert(node_id, node.clone());
        }

        Ok(Self {
            nodes,
            digests: BTreeMap::new(),
            roots: roots.to_vec(),
            advice_map: AdviceMap::default(),
        })
    }

    /// Merges dense and sparse forests into a sparse forest.
    ///
    /// Full nodes are deduplicated after remapping their children. Digest-only entries remain
    /// opaque and are retained when no full node is available. Sparse replay forests cannot carry
    /// advice data, so this returns an error if any input has a non-empty advice map.
    pub fn merge<'forest, F>(
        forests: impl IntoIterator<Item = F>,
    ) -> Result<(Self, MastForestRootMap), MastForestError>
    where
        F: Into<MastForestMergeSource<'forest>>,
    {
        MixedMastForestMerger::merge_sparse(forests.into_iter().map(Into::into).collect())
    }

    pub(in crate::mast) fn from_merged_parts(
        nodes: BTreeMap<MastNodeId, MastNode>,
        digests: BTreeMap<MastNodeId, Word>,
        roots: Vec<MastNodeId>,
    ) -> Result<Self, MastForestError> {
        let forest = Self {
            nodes,
            digests,
            roots,
            advice_map: AdviceMap::default(),
        };
        forest.validate()?;
        Ok(forest)
    }

    /// Checks block invariants, child ordering, and full-node hashes.
    ///
    /// Digest-only entries and external nodes are opaque inputs to these checks. Their membership
    /// in a particular source forest must be checked separately against that source.
    pub fn validate(&self) -> Result<(), MastForestError> {
        for (&node_id, node) in &self.nodes {
            if let MastNode::Block(block) = node {
                block
                    .validate_batch_invariants()
                    .map_err(|message| MastForestError::InvalidBatchPadding(node_id, message))?;
            }
            let computed = node.compute_digest(|child_id| {
                if child_id >= node_id {
                    return Err(MastForestError::ForwardReference(node_id, child_id));
                }
                self.get_digest_by_id(child_id)
                    .ok_or_else(|| MastForestError::NodeIdOverflow(child_id, self.num_nodes()))
            })?;
            if computed != node.digest() {
                return Err(MastForestError::HashMismatch {
                    node_id,
                    expected: node.digest(),
                    computed,
                });
            }
        }
        Ok(())
    }

    /// Returns the underlying nodes of this sparse forest, keyed by their original
    /// [`MastNodeId`].
    pub fn nodes(&self) -> &BTreeMap<MastNodeId, MastNode> {
        &self.nodes
    }

    /// Returns the minimum node count needed to cover all IDs retained in this sparse replay view.
    ///
    /// This is *not* the number of visited nodes and may be smaller than the source
    /// [`MastForest`]'s node count when high source IDs were not needed during replay.
    pub fn num_nodes(&self) -> usize {
        self.nodes
            .keys()
            .chain(self.digests.keys())
            .chain(self.roots.iter())
            .map(|id| id.to_usize() + 1)
            .max()
            .unwrap_or(0)
    }

    /// Returns the roots of procedures defined within this sparse forest.
    pub fn procedure_roots(&self) -> &[MastNodeId] {
        &self.roots
    }

    /// Returns the empty advice map associated with this sparse forest.
    ///
    /// Sparse replay uses `AdviceReplay` for advice reads; this map remains empty to satisfy the
    /// shared [`ExecutableMastForest`] interface.
    pub fn advice_map(&self) -> &AdviceMap {
        &self.advice_map
    }

    /// Returns the digest-only entries associated with this sparse forest.
    pub(in crate::mast) fn digest_entries(&self) -> &BTreeMap<MastNodeId, Word> {
        &self.digests
    }

    /// Builds a sparse forest from trusted replay parts.
    pub(in crate::mast) fn from_serialized_parts(
        nodes: Vec<(MastNodeId, MastNode)>,
        digests: Vec<(MastNodeId, Word)>,
        roots: Vec<MastNodeId>,
        advice_map: AdviceMap,
    ) -> Result<Self, DeserializationError> {
        if !advice_map.is_empty() {
            return Err(DeserializationError::InvalidValue(
                "sparse MAST replay payload must not carry advice map entries".to_string(),
            ));
        }

        let nodes = collect_unique_nodes(nodes)?;
        let digests = collect_unique_digests(digests)?;

        for &root in &roots {
            validate_sparse_id(root, "procedure root")?;
        }

        for node_id in nodes.keys() {
            if digests.contains_key(node_id) {
                return Err(DeserializationError::InvalidValue(format!(
                    "sparse full-node id {} overlaps a digest-only entry",
                    node_id.0
                )));
            }
        }

        validate_full_node_child_digests(&nodes, &digests)?;

        Ok(Self {
            nodes,
            digests,
            roots,
            advice_map: AdviceMap::default(),
        })
    }
}

fn validate_sparse_id(id: MastNodeId, label: &str) -> Result<(), DeserializationError> {
    if id.to_usize() >= MastForest::MAX_NODES {
        return Err(DeserializationError::InvalidValue(format!(
            "{label} id {} exceeds maximum sparse MAST node id {}",
            id.0,
            MastForest::MAX_NODES - 1
        )));
    }
    Ok(())
}

fn collect_unique_nodes(
    nodes: Vec<(MastNodeId, MastNode)>,
) -> Result<BTreeMap<MastNodeId, MastNode>, DeserializationError> {
    let mut result = BTreeMap::new();
    for (id, node) in nodes {
        validate_sparse_id(id, "full node")?;
        if result.insert(id, node).is_some() {
            return Err(DeserializationError::InvalidValue(format!(
                "duplicate sparse full-node id {}",
                id.0
            )));
        }
    }
    Ok(result)
}

fn collect_unique_digests(
    digests: Vec<(MastNodeId, Word)>,
) -> Result<BTreeMap<MastNodeId, Word>, DeserializationError> {
    let mut result = BTreeMap::new();
    for (id, digest) in digests {
        validate_sparse_id(id, "digest-only node")?;
        if result.insert(id, digest).is_some() {
            return Err(DeserializationError::InvalidValue(format!(
                "duplicate sparse digest-only id {}",
                id.0
            )));
        }
    }
    Ok(result)
}

/// Checks that every child of a retained full node is available as either a full node or a
/// digest-only entry.
fn validate_full_node_child_digests(
    nodes: &BTreeMap<MastNodeId, MastNode>,
    digests: &BTreeMap<MastNodeId, Word>,
) -> Result<(), DeserializationError> {
    for (&node_id, node) in nodes {
        validate_sparse_id(node_id, "full node")?;

        match node {
            MastNode::Block(block) => {
                block.validate_batch_invariants().map_err(|error_msg| {
                    DeserializationError::InvalidValue(format!(
                        "invalid sparse basic block {}: {error_msg}",
                        node_id.0
                    ))
                })?;
            },
            MastNode::External(_) | MastNode::Dyn(_) => {},
            MastNode::Join(join) => {
                require_child_digest(node_id, join.first(), nodes, digests)?;
                require_child_digest(node_id, join.second(), nodes, digests)?;
            },
            MastNode::Split(split) => {
                require_child_digest(node_id, split.on_true(), nodes, digests)?;
                require_child_digest(node_id, split.on_false(), nodes, digests)?;
            },
            MastNode::Loop(loop_node) => {
                require_child_digest(node_id, loop_node.body(), nodes, digests)?;
            },
            MastNode::Call(call) => {
                require_child_digest(node_id, call.callee(), nodes, digests)?;
            },
        }
    }
    Ok(())
}

fn require_child_digest(
    parent_id: MastNodeId,
    child_id: MastNodeId,
    nodes: &BTreeMap<MastNodeId, MastNode>,
    digests: &BTreeMap<MastNodeId, Word>,
) -> Result<(), DeserializationError> {
    validate_sparse_id(child_id, "child")?;
    if child_id >= parent_id {
        return Err(DeserializationError::InvalidValue(format!(
            "sparse full node {} references non-preceding child {}",
            parent_id.0, child_id.0
        )));
    }
    if !nodes.contains_key(&child_id) && !digests.contains_key(&child_id) {
        return Err(DeserializationError::InvalidValue(format!(
            "sparse full node {} references child {} without a full node or digest-only entry",
            parent_id.0, child_id.0
        )));
    }
    Ok(())
}

impl ExecutableMastForest for SparseMastForest {
    #[inline(always)]
    fn get_node_by_id(&self, node_id: MastNodeId) -> Option<&MastNode> {
        self.nodes.get(&node_id)
    }

    #[inline(always)]
    fn get_digest_by_id(&self, node_id: MastNodeId) -> Option<Word> {
        if let Some(node) = self.nodes.get(&node_id) {
            return Some(node.digest());
        }
        self.digests.get(&node_id).copied()
    }

    #[inline(always)]
    fn find_procedure_root(&self, digest: Word) -> Option<MastNodeId> {
        // The `roots` list is copied wholesale from the source forest and may include roots that
        // were never visited (and thus aren't present in `nodes`). Skip those gracefully rather
        // than panicking via the `Index` impl.
        self.roots.iter().find_map(|&root_id| {
            let node = self.nodes.get(&root_id)?;
            (node.digest() == digest).then_some(root_id)
        })
    }

    #[inline(always)]
    fn advice_map(&self) -> &AdviceMap {
        &self.advice_map
    }
}

// SPARSE MAST FOREST BUILDER
// ================================================================================================

/// Describes how a node referenced during execution should be represented in the resulting
/// [`SparseMastForest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisitKind {
    /// The node was actually entered (or otherwise needs to be available in full at replay time).
    /// The full [`MastNode`] is copied into [`SparseMastForest::nodes`].
    FullVisit,
    /// Only the node's digest is required at replay time (e.g. a child of a control-flow node
    /// whose digest contributes to the parent's trace row, but which is itself never entered).
    /// The digest is copied into the digest-only map; the full node is omitted.
    DigestOnly,
}

/// Incrementally builds a [`SparseMastForest`] by collecting the [`MastNodeId`]s of nodes visited
/// during execution of a single source [`MastForest`].
///
/// The builder retains a strong reference to the source forest so that it can copy out the visited
/// nodes (and the source's roots, advice map, and debug info) at finalization time.
///
/// Each recorded id carries a [`VisitKind`] that controls whether the full node is copied or only
/// its digest. If the same id is recorded as both a [`VisitKind::FullVisit`] and a
/// [`VisitKind::DigestOnly`], the full-visit representation wins (the digest is recoverable from
/// the full node).
#[derive(Debug)]
pub struct SparseMastForestBuilder {
    /// The source forest whose nodes are being collected.
    source: Arc<MastForest>,

    /// IDs of nodes that were entered during execution. Their full [`MastNode`] is copied into the
    /// finalized forest's `nodes` map.
    full_visits: BTreeSet<MastNodeId>,

    /// IDs of nodes that were only referenced (not entered) during execution. At finalization,
    /// any id that also appears in [`Self::full_visits`] is excluded; the remainder contributes a
    /// digest-only entry to the finalized forest.
    digest_only_visits: BTreeSet<MastNodeId>,
}

impl SparseMastForestBuilder {
    /// Creates a new builder for the given source forest.
    pub fn new(source: Arc<MastForest>) -> Self {
        Self {
            source,
            full_visits: BTreeSet::new(),
            digest_only_visits: BTreeSet::new(),
        }
    }

    /// Records a visit to the node with the provided id. Idempotent.
    ///
    /// If the same id is recorded both as [`VisitKind::FullVisit`] and as
    /// [`VisitKind::DigestOnly`], the full-visit representation wins.
    pub fn record_visit(&mut self, node_id: MastNodeId, kind: VisitKind) {
        match kind {
            VisitKind::FullVisit => {
                self.full_visits.insert(node_id);
            },
            VisitKind::DigestOnly => {
                self.digest_only_visits.insert(node_id);
            },
        }
    }

    /// Returns a strong reference to the source forest backing this builder.
    pub fn source(&self) -> &Arc<MastForest> {
        &self.source
    }

    /// Consumes the builder and produces a [`SparseMastForest`] containing only the visited nodes
    /// from the source forest. The roots are cloned from the source in full. Advice data is not
    /// copied because sparse replay uses `AdviceReplay`.
    pub fn finalize(self) -> SparseMastForest {
        let SparseMastForestBuilder { source, full_visits, digest_only_visits } = self;

        let mut nodes = BTreeMap::new();
        for node_id in &full_visits {
            let node = source
                .get_node_by_id(*node_id)
                .expect("recorded full-visit id must exist in source forest");
            nodes.insert(*node_id, node.clone());
        }

        let mut digests = BTreeMap::new();
        for node_id in digest_only_visits {
            if full_visits.contains(&node_id) {
                continue;
            }
            let node = source
                .get_node_by_id(node_id)
                .expect("recorded digest-only id must exist in source forest");
            digests.insert(node_id, node.digest());
        }

        SparseMastForest {
            nodes,
            digests,
            roots: source.procedure_roots().to_vec(),
            advice_map: AdviceMap::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::{
        mast::{
            BasicBlockNodeBuilder, CallNodeBuilder, DynNodeBuilder, ExternalNodeBuilder,
            JoinNodeBuilder, LoopNodeBuilder, MastForestRead, SplitNodeBuilder,
        },
        operations::Operation,
    };

    #[test]
    fn extraction_rejects_non_roots_and_handles_empty_selection() {
        let mut source = MastForest::new();
        let node = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut source)
            .unwrap();

        let empty = SparseMastForest::from_procedure_roots(&source, &[]).unwrap();
        assert!(empty.nodes().is_empty());
        assert!(empty.digest_entries().is_empty());
        assert!(empty.procedure_roots().is_empty());
        assert_eq!(empty.num_nodes(), 0);

        assert_eq!(
            SparseMastForest::from_procedure_roots(&source, &[node]).unwrap_err(),
            MastForestError::NotAProcedureRoot(node)
        );
    }

    #[test]
    fn extraction_copies_the_complete_reachable_graph_once() {
        let mut source = MastForest::new();
        let shared = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut source)
            .unwrap();
        let other = BasicBlockNodeBuilder::new(vec![Operation::Mul])
            .add_to_forest(&mut source)
            .unwrap();
        let split = SplitNodeBuilder::new([shared, other]).add_to_forest(&mut source).unwrap();
        let call = CallNodeBuilder::new(split).add_to_forest(&mut source).unwrap();
        let root = JoinNodeBuilder::new([call, shared]).add_to_forest(&mut source).unwrap();
        source.make_root(root);

        let sparse = SparseMastForest::from_procedure_roots(&source, &[root]).unwrap();

        assert_eq!(sparse.procedure_roots(), &[root]);
        assert_eq!(sparse.nodes().len(), 5);
        assert!(sparse.digest_entries().is_empty());
        for node_id in [shared, other, split, call, root] {
            assert_eq!(sparse.get_node_by_id(node_id), source.get_node_by_id(node_id));
        }
        assert!(sparse.is_source_subset_of(&source));

        let repeated = SparseMastForest::from_procedure_roots(&source, &[root, root]).unwrap();
        assert_eq!(repeated.procedure_roots(), &[root, root]);
        assert_eq!(repeated.nodes().len(), sparse.nodes().len());
    }

    #[test]
    fn extraction_stops_at_external_and_dynamic_nodes() {
        let mut source = MastForest::new();
        let external =
            ExternalNodeBuilder::new(Word::default()).add_to_forest(&mut source).unwrap();
        let call = CallNodeBuilder::new(external).add_to_forest(&mut source).unwrap();
        let dynamic = DynNodeBuilder::new_dyn().add_to_forest(&mut source).unwrap();
        source.make_root(call);
        source.make_root(dynamic);

        let sparse = SparseMastForest::from_procedure_roots(&source, &[call, dynamic]).unwrap();

        assert_eq!(sparse.nodes().len(), 3);
        assert!(sparse.nodes().contains_key(&external));
        assert!(sparse.nodes().contains_key(&call));
        assert!(sparse.nodes().contains_key(&dynamic));
    }

    #[test]
    fn extraction_follows_loop_bodies_and_their_descendants() {
        let mut source = MastForest::new();
        let left = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut source)
            .unwrap();
        let right = BasicBlockNodeBuilder::new(vec![Operation::Mul])
            .add_to_forest(&mut source)
            .unwrap();
        let body = JoinNodeBuilder::new([left, right]).add_to_forest(&mut source).unwrap();
        let root = LoopNodeBuilder::new(body).add_to_forest(&mut source).unwrap();
        source.make_root(root);

        let sparse = SparseMastForest::from_procedure_roots(&source, &[root]).unwrap();

        assert_eq!(sparse.nodes().len(), 4);
        for node_id in [left, right, body, root] {
            assert_eq!(sparse.get_node_by_id(node_id), source.get_node_by_id(node_id));
        }
    }

    #[test]
    fn extraction_preserves_large_source_id_gaps() {
        let mut source = MastForest::new();
        for _ in 0..1_000 {
            BasicBlockNodeBuilder::new(vec![Operation::Add])
                .add_to_forest(&mut source)
                .unwrap();
        }
        let root = BasicBlockNodeBuilder::new(vec![Operation::Mul])
            .add_to_forest(&mut source)
            .unwrap();
        source.make_root(root);

        let sparse = SparseMastForest::from_procedure_roots(&source, &[root]).unwrap();

        assert_eq!(sparse.nodes().len(), 1);
        assert_eq!(sparse.num_nodes(), root.to_usize() + 1);
        assert_eq!(sparse.get_node_by_id(root), source.get_node_by_id(root));
    }

    #[test]
    fn extraction_handles_deep_call_chains_iteratively() {
        const DEPTH: usize = 16_384;

        let mut source = MastForest::new();
        let mut root = BasicBlockNodeBuilder::new(vec![Operation::Add])
            .add_to_forest(&mut source)
            .unwrap();
        for _ in 0..DEPTH {
            root = CallNodeBuilder::new(root).add_to_forest(&mut source).unwrap();
        }
        source.make_root(root);

        let sparse = SparseMastForest::from_procedure_roots(&source, &[root]).unwrap();

        assert_eq!(sparse.nodes().len(), DEPTH + 1);
        assert_eq!(sparse.procedure_roots(), &[root]);
    }
}
