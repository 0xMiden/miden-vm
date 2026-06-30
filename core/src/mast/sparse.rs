use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};

use miden_utils_indexing::newtype_id;

use crate::{
    Word,
    advice::AdviceMap,
    mast::{ExecutableMastForest, MastForest, MastNode, MastNodeExt, MastNodeId},
    utils::Idx,
};

// MAST FOREST ID
// ================================================================================================

// `MastForestId` is an opaque handle to a [`MastForest`] in some forest store such as the
// `TraceGenerationContext::mast_forest_store`. It is not a content-derived or stable identity for a
// forest, and must not be compared or reused across stores or trace contexts. It is analogous to
// `MastNodeId`, which is meaningful only within one forest's node store.
newtype_id!(MastForestId);

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
#[derive(Debug)]
pub struct SparseMastForest {
    /// Subset of the original forest's nodes, keyed by their original [`MastNodeId`].
    nodes: BTreeMap<MastNodeId, MastNode>,

    /// Digests of nodes that were referenced (but not entered) during execution, keyed by their
    /// original [`MastNodeId`]. Nodes present in [`Self::nodes`] are excluded from this map: a
    /// full-node entry implicitly carries its own digest via [`MastNodeExt::digest`].
    digests: BTreeMap<MastNodeId, Word>,

    /// Total number of nodes in the source [`MastForest`] from which this sparse forest was
    /// built. Note that this is *not* `nodes.len()` — it is the upper bound on the original
    /// [`MastNodeId`] space, preserved so that callers materializing dense-shaped state (e.g.
    /// allocating an `IndexVec` keyed by [`MastNodeId`]) know its required size.
    num_nodes: usize,

    /// Roots of procedures defined within the original MAST forest.
    roots: Vec<MastNodeId>,

    /// Advice map to be loaded into the VM prior to executing procedures from this MAST forest.
    advice_map: AdviceMap,

    /// Cached commitment to the original MAST forest (i.e. a commitment to all roots).
    commitment_cache: Word,
}

impl SparseMastForest {
    /// Returns the underlying nodes of this sparse forest, keyed by their original
    /// [`MastNodeId`].
    pub fn nodes(&self) -> &BTreeMap<MastNodeId, MastNode> {
        &self.nodes
    }

    /// Returns the total number of nodes in the source [`MastForest`] from which this sparse
    /// forest was built. This is *not* the number of visited (i.e. present) nodes — see
    /// [`Self::nodes`] for that.
    pub fn num_nodes(&self) -> usize {
        self.num_nodes
    }

    /// Returns the roots of procedures defined within this sparse forest.
    pub fn procedure_roots(&self) -> &[MastNodeId] {
        &self.roots
    }

    /// Returns the advice map associated with this sparse forest.
    pub fn advice_map(&self) -> &AdviceMap {
        &self.advice_map
    }

    /// Returns the digest-only entries associated with this sparse forest.
    pub(in crate::mast) fn digest_entries(&self) -> &BTreeMap<MastNodeId, Word> {
        &self.digests
    }

    /// Returns the commitment to this sparse forest, computed from the procedure roots.
    ///
    /// The commitment value is derived from the digests of the procedure roots in the original
    /// forest; it is therefore equal to the commitment of the source [`MastForest`] from which
    /// this sparse forest was built.
    pub fn commitment(&self) -> Word {
        self.commitment_cache
    }

    /// Builds a sparse forest from parts decoded from the sparse wire format.
    pub(in crate::mast) fn from_serialized_parts(
        nodes: Vec<(MastNodeId, MastNode)>,
        digests: Vec<(MastNodeId, Word)>,
        num_nodes: usize,
        roots: Vec<MastNodeId>,
        advice_map: AdviceMap,
        commitment_cache: Word,
    ) -> Result<Self, crate::serde::DeserializationError> {
        validate_sparse_node_bound(num_nodes)?;

        let nodes = collect_unique_nodes(nodes, num_nodes)?;
        let digests = collect_unique_digests(digests, num_nodes)?;

        for &root in &roots {
            validate_sparse_id(root, num_nodes, "procedure root")?;
        }

        for node_id in nodes.keys() {
            if digests.contains_key(node_id) {
                return Err(crate::serde::DeserializationError::InvalidValue(format!(
                    "sparse full-node id {} overlaps a digest-only entry",
                    node_id.0
                )));
            }
        }

        validate_full_node_child_digests(&nodes, &digests, num_nodes)?;

        Ok(Self {
            nodes,
            digests,
            num_nodes,
            roots,
            advice_map,
            commitment_cache,
        })
    }
}

fn validate_sparse_node_bound(num_nodes: usize) -> Result<(), crate::serde::DeserializationError> {
    if num_nodes > MastForest::MAX_NODES {
        return Err(crate::serde::DeserializationError::InvalidValue(format!(
            "sparse source node count {num_nodes} exceeds maximum allowed {}",
            MastForest::MAX_NODES
        )));
    }
    Ok(())
}

fn validate_sparse_id(
    id: MastNodeId,
    num_nodes: usize,
    label: &str,
) -> Result<(), crate::serde::DeserializationError> {
    if id.to_usize() >= num_nodes {
        return Err(crate::serde::DeserializationError::InvalidValue(format!(
            "{label} id {} is out of range for sparse source node count {num_nodes}",
            id.0
        )));
    }
    Ok(())
}

fn collect_unique_nodes(
    nodes: Vec<(MastNodeId, MastNode)>,
    num_nodes: usize,
) -> Result<BTreeMap<MastNodeId, MastNode>, crate::serde::DeserializationError> {
    let mut result = BTreeMap::new();
    for (id, node) in nodes {
        validate_sparse_id(id, num_nodes, "full node")?;
        if result.insert(id, node).is_some() {
            return Err(crate::serde::DeserializationError::InvalidValue(format!(
                "duplicate sparse full-node id {}",
                id.0
            )));
        }
    }
    Ok(result)
}

fn collect_unique_digests(
    digests: Vec<(MastNodeId, Word)>,
    num_nodes: usize,
) -> Result<BTreeMap<MastNodeId, Word>, crate::serde::DeserializationError> {
    let mut result = BTreeMap::new();
    for (id, digest) in digests {
        validate_sparse_id(id, num_nodes, "digest-only node")?;
        if result.insert(id, digest).is_some() {
            return Err(crate::serde::DeserializationError::InvalidValue(format!(
                "duplicate sparse digest-only id {}",
                id.0
            )));
        }
    }
    Ok(result)
}

fn validate_full_node_child_digests(
    nodes: &BTreeMap<MastNodeId, MastNode>,
    digests: &BTreeMap<MastNodeId, Word>,
    num_nodes: usize,
) -> Result<(), crate::serde::DeserializationError> {
    for (&node_id, node) in nodes {
        validate_sparse_id(node_id, num_nodes, "full node")?;

        match node {
            MastNode::Block(block) => {
                block.validate_batch_invariants().map_err(|error_msg| {
                    crate::serde::DeserializationError::InvalidValue(format!(
                        "invalid sparse basic block {}: {error_msg}",
                        node_id.0
                    ))
                })?;
            },
            MastNode::External(_) | MastNode::Dyn(_) => {},
            MastNode::Join(join) => {
                require_child_digest(node_id, join.first(), nodes, digests, num_nodes)?;
                require_child_digest(node_id, join.second(), nodes, digests, num_nodes)?;
            },
            MastNode::Split(split) => {
                require_child_digest(node_id, split.on_true(), nodes, digests, num_nodes)?;
                require_child_digest(node_id, split.on_false(), nodes, digests, num_nodes)?;
            },
            MastNode::Loop(loop_node) => {
                require_child_digest(node_id, loop_node.body(), nodes, digests, num_nodes)?;
            },
            MastNode::Call(call) => {
                require_child_digest(node_id, call.callee(), nodes, digests, num_nodes)?;
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
    num_nodes: usize,
) -> Result<(), crate::serde::DeserializationError> {
    validate_sparse_id(child_id, num_nodes, "child")?;
    if !nodes.contains_key(&child_id) && !digests.contains_key(&child_id) {
        return Err(crate::serde::DeserializationError::InvalidValue(format!(
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

    /// Total number of nodes in the source forest, captured at construction time. Propagated to
    /// the finalized [`SparseMastForest`] so consumers know the original [`MastNodeId`] space.
    num_nodes: usize,

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
        let num_nodes = source.nodes().len();
        Self {
            source,
            num_nodes,
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
    /// from the source forest. The roots, advice map, and debug info are cloned from the source
    /// in full (they are not yet trimmed to visited nodes only).
    pub fn finalize(self) -> SparseMastForest {
        let SparseMastForestBuilder {
            source,
            num_nodes,
            full_visits,
            digest_only_visits,
        } = self;

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
            num_nodes,
            roots: source.procedure_roots().to_vec(),
            advice_map: source.advice_map().clone(),
            commitment_cache: source.commitment(),
        }
    }
}
