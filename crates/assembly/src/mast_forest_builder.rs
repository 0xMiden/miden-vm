use alloc::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    sync::Arc,
    vec::Vec,
};
use core::fmt;

#[cfg(test)]
use miden_core::utils::LookupByIdx;
use miden_core::{
    Felt, Word,
    advice::AdviceMap,
    chiplets::hasher,
    crypto::hash::Blake3_256,
    mast::{
        BasicBlockNode, BasicBlockNodeBuilder, CallNode, CallNodeBuilder, DecoratorFingerprint,
        DecoratorId, DynNode, DynNodeBuilder, ExternalNodeBuilder, JoinNode, JoinNodeBuilder,
        LoopNode, LoopNodeBuilder, MastForest, MastForestContributor, MastForestRootMap, MastNode,
        MastNodeBuilder, MastNodeExt, MastNodeFingerprint, MastNodeId, OpBatch, Remapping,
        SplitNode, SplitNodeBuilder, SubtreeIterator, error_code_from_msg,
        fingerprint_from_fingerprints,
    },
    operations::{AssemblyOp, DebugVarInfo, Decorator, DecoratorList, Operation},
    serde::Serializable,
    utils::{Idx, IndexVec},
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

/// Stable assembly-time reference to a MAST node.
///
/// This is a builder-local dense arena handle, not a positional [`MastNodeId`] in the final
/// [`MastForest`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(transparent)]
pub(crate) struct MastNodeRef(u32);

impl From<u32> for MastNodeRef {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<MastNodeRef> for u32 {
    fn from(value: MastNodeRef) -> Self {
        value.0
    }
}

impl fmt::Display for MastNodeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MastNodeRef({})", self.0)
    }
}

impl Idx for MastNodeRef {}

/// Stable assembly-time reference to a decorator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(transparent)]
pub(crate) struct DecoratorRef(u32);

impl From<u32> for DecoratorRef {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<DecoratorRef> for u32 {
    fn from(value: DecoratorRef) -> Self {
        value.0
    }
}

impl Idx for DecoratorRef {}

/// Stable assembly-time reference to assembly operation metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(transparent)]
pub(crate) struct AsmOpRef(u32);

impl From<u32> for AsmOpRef {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<AsmOpRef> for u32 {
    fn from(value: AsmOpRef) -> Self {
        value.0
    }
}

impl Idx for AsmOpRef {}

/// Stable assembly-time reference to debug variable metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(transparent)]
pub(crate) struct DebugVarRef(u32);

impl From<u32> for DebugVarRef {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<DebugVarRef> for u32 {
    fn from(value: DebugVarRef) -> Self {
        value.0
    }
}

impl Idx for DebugVarRef {}

/// Result of finalizing a [`MastForestBuilder`].
pub(crate) struct BuiltMastForest {
    mast_forest: MastForest,
    /// Final node IDs for builder refs retained in the finalized forest.
    node_id_by_ref: BTreeMap<MastNodeRef, MastNodeId>,
}

impl BuiltMastForest {
    pub(crate) fn into_parts(self) -> (MastForest, BTreeMap<MastNodeRef, MastNodeId>) {
        (self.mast_forest, self.node_id_by_ref)
    }
}

#[derive(Clone, Debug)]
struct PendingMastNode {
    backing_id: MastNodeId,
    fingerprint: MastNodeFingerprint,
    node: MastNode,
    child_refs: Vec<MastNodeRef>,
    decorator_refs: PendingDecoratorRefs,
}

#[derive(Default)]
struct PendingNodeRefs {
    child_refs: Option<Vec<MastNodeRef>>,
    decorator_refs: Option<PendingDecoratorRefs>,
}

#[derive(Clone, Debug, Default)]
struct PendingDecoratorRefs {
    before_enter: Vec<DecoratorRef>,
    indexed: Vec<(usize, DecoratorRef)>,
    after_exit: Vec<DecoratorRef>,
}

impl PendingDecoratorRefs {
    fn refs(&self) -> impl Iterator<Item = DecoratorRef> + '_ {
        self.before_enter
            .iter()
            .chain(self.indexed.iter().map(|(_idx, decorator_ref)| decorator_ref))
            .chain(self.after_exit.iter())
            .copied()
    }
}

#[cfg(test)]
struct PendingNodeFingerprintLookup<'a> {
    nodes: &'a IndexVec<MastNodeRef, PendingMastNode>,
    node_ref_by_id: &'a BTreeMap<MastNodeId, MastNodeRef>,
}

#[cfg(test)]
impl LookupByIdx<MastNodeId, MastNodeFingerprint> for PendingNodeFingerprintLookup<'_> {
    fn get(&self, id: MastNodeId) -> Option<&MastNodeFingerprint> {
        let node_ref = self.node_ref_by_id.get(&id)?;
        Some(&self.nodes[*node_ref].fingerprint)
    }
}

#[derive(Clone, Debug)]
struct PendingDecorator {
    pending_id: Option<DecoratorId>,
    #[cfg(test)]
    backing_id: Option<DecoratorId>,
    decorator: Decorator,
}

#[derive(Clone, Debug)]
struct PendingDebugVar {
    debug_var: DebugVarInfo,
}

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
    /// The MAST forest being built by this builder.
    ///
    /// This is transitional while node construction still writes through to a live forest.
    #[cfg(test)]
    mast_forest: MastForest,
    /// Advice map entries registered while building this forest.
    advice_map: AdviceMap,
    /// A map of all procedures added to the MAST forest indexed by their global procedure ID.
    /// This includes all local, exported, and re-exported procedures. In case multiple procedures
    /// with the same digest are added to the MAST forest builder, only the first procedure is
    /// added to the map, and all subsequent insertions are ignored.
    procedures: BTreeMap<GlobalItemIndex, Procedure>,
    /// A map from procedure MAST root to its global procedure index. Similar to the `procedures`
    /// map, this map contains only the first inserted procedure for procedures with the same MAST
    /// root.
    proc_gid_by_mast_root: BTreeMap<Word, GlobalItemIndex>,
    /// Procedure roots recorded by builder-local node ref until finalization.
    procedure_root_refs: Vec<MastNodeRef>,
    /// A map of MAST node fingerprints to their corresponding builder-local node refs.
    node_ref_by_fingerprint: BTreeMap<MastNodeFingerprint, MastNodeRef>,
    /// Builder-owned dense storage for node refs.
    ///
    /// This is transitional while node construction still writes through to `mast_forest`
    /// immediately: each ref resolves to the current backing node ID until finalization assigns
    /// the final dense IDs.
    nodes: IndexVec<MastNodeRef, PendingMastNode>,
    /// Reverse lookup for the transitional backing node ID of each node ref.
    node_ref_by_id: BTreeMap<MastNodeId, MastNodeRef>,
    /// A map of decorator fingerprints to their corresponding builder-local decorator refs.
    decorator_ref_by_fingerprint: BTreeMap<DecoratorFingerprint, DecoratorRef>,
    /// Reverse lookup for the transitional decorator ID of each decorator ref.
    decorator_ref_by_id: BTreeMap<DecoratorId, DecoratorRef>,
    /// Builder-owned dense storage for decorator refs.
    decorators: IndexVec<DecoratorRef, PendingDecorator>,
    /// Builder-owned dense storage for assembly op refs.
    asm_op_by_ref: IndexVec<AsmOpRef, AssemblyOp>,
    /// Builder-owned dense storage for debug variable refs.
    debug_vars: IndexVec<DebugVarRef, PendingDebugVar>,
    /// Error codes registered while building this forest.
    error_codes: BTreeMap<u64, Arc<str>>,
    /// A set of refs for basic blocks which have been merged into a bigger basic blocks. This is
    /// used as a candidate set of nodes that may be eliminated if the are not referenced by any
    /// other node in the forest and are not a root of any procedure.
    merged_basic_block_refs: BTreeSet<MastNodeRef>,
    /// A MastForest that contains the MAST of all statically-linked libraries, it's used to find
    /// precompiled procedures and copy their subtrees instead of inserting external nodes.
    statically_linked_mast: Arc<MastForest>,
    /// Maps each statically linked source forest commitment to its position in the merged forest
    /// root map.
    statically_linked_forest_indices_by_commitment: BTreeMap<Word, usize>,
    /// Maps procedure roots from each source static library to their new root ID in the merged
    /// static forest.
    statically_linked_root_map: MastForestRootMap,
    /// Pending AssemblyOp mappings to be registered at build time.
    ///
    /// These are collected during assembly by builder-local node ref and registered all at once
    /// in sorted node order when `build()` is called. This is necessary because the CSR structure
    /// requires nodes to be added in sequential order, but nodes may be created in any order
    /// during assembly.
    pending_asm_op_mappings: Vec<(MastNodeRef, Vec<(usize, AsmOpRef)>)>,
    /// Pending debug variable mappings to be registered at build time.
    ///
    /// Like `pending_asm_op_mappings`, these are collected during assembly by builder-local node
    /// ref and registered all at once in sorted node order when `build()` is called. This avoids
    /// the crash that occurs when `register_debug_vars_for_node` is called with an out-of-order
    /// node ID (which happens when node deduplication returns an already-existing `MastNodeId`).
    pending_debug_var_mappings: Vec<(MastNodeRef, Vec<(usize, DebugVarRef)>)>,
    /// When false, asm ops and debug vars are not included in the dedup
    /// fingerprint. This avoids keeping duplicate nodes in stripped builds
    /// where the metadata that justified the split has been discarded.
    emit_debug_info: bool,
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
        let forests = static_libraries.into_iter().collect::<Vec<_>>();
        // TODO(#3067): `MastForest::commitment()` only hashes procedure root digests, so two
        // forests with identical roots but different debug metadata share the same commitment.
        // Using that commitment as a lookup key can point provenance from one static library at
        // another library's root map and still select the wrong diagnostics metadata.
        let statically_linked_forest_indices_by_commitment = forests
            .iter()
            .enumerate()
            .map(|(idx, forest)| (forest.commitment(), idx))
            .collect();
        let (statically_linked_mast, statically_linked_root_map) =
            MastForest::merge(forests.iter().copied()).into_diagnostic()?;
        // The AdviceMap of the statically-linked forest is copied to the forest being built.
        //
        // This might include excess advice map data in the built MastForest, but we currently do
        // not do any analysis to determine what advice map data is actually required by parts of
        // the library(s) that are actually linked into the output.
        Ok(MastForestBuilder {
            advice_map: statically_linked_mast.advice_map().clone(),
            statically_linked_mast: Arc::new(statically_linked_mast),
            statically_linked_forest_indices_by_commitment,
            statically_linked_root_map,
            emit_debug_info: true,
            ..Self::default()
        })
    }

    /// When set to true, asm ops and debug vars participate in the dedup
    /// fingerprint so nodes with different source metadata stay distinct.
    /// When false (release builds), only ops and decorators matter.
    pub fn set_emit_debug_info(&mut self, emit: bool) {
        self.emit_debug_info = emit;
    }

    /// Augments a fingerprint with metadata bytes only when debug info is
    /// being emitted. In stripped builds this is a no-op so identical-ops
    /// nodes collapse back to a single node.
    fn maybe_augment(&self, fp: MastNodeFingerprint, data: &[u8]) -> MastNodeFingerprint {
        if self.emit_debug_info {
            fp.augment_with_data(data)
        } else {
            fp
        }
    }

    #[cfg(test)]
    fn fingerprint_for_builder(&self, builder: &impl MastForestContributor) -> MastNodeFingerprint {
        let fingerprint_lookup = PendingNodeFingerprintLookup {
            nodes: &self.nodes,
            node_ref_by_id: &self.node_ref_by_id,
        };
        builder
            .fingerprint_for_node(&self.mast_forest, &fingerprint_lookup)
            .expect("pending nodes should contain the fingerprints of all children of `node`")
    }

    #[cfg(test)]
    fn intern_node_id(&mut self, node_id: MastNodeId) -> Result<MastNodeRef, Report> {
        if let Some(&node_ref) = self.node_ref_by_id.get(&node_id) {
            return Ok(node_ref);
        }

        let node = self.owned_pending_node(node_id);
        let fingerprint = self.fingerprint_for_node_id(node_id)?;
        self.push_node_ref(node_id, fingerprint, node, PendingNodeRefs::default())
    }

    #[cfg(test)]
    fn owned_pending_node(&self, node_id: MastNodeId) -> MastNode {
        self.mast_forest[node_id]
            .clone()
            .to_builder(&self.mast_forest)
            .build(&self.mast_forest)
            .expect("failed to build owned pending MAST node - internal error")
    }

    #[cfg(test)]
    fn fingerprint_for_node_id(&self, node_id: MastNodeId) -> Result<MastNodeFingerprint, Report> {
        let fingerprint_lookup = PendingNodeFingerprintLookup {
            nodes: &self.nodes,
            node_ref_by_id: &self.node_ref_by_id,
        };
        self.mast_forest[node_id]
            .clone()
            .to_builder(&self.mast_forest)
            .fingerprint_for_node(&self.mast_forest, &fingerprint_lookup)
            .into_diagnostic()
            .wrap_err("child node fingerprints must be interned before their parent")
    }

    #[cfg(test)]
    fn refresh_node_ref(
        &mut self,
        node_ref: MastNodeRef,
        backing_id: MastNodeId,
        fingerprint: MastNodeFingerprint,
        node: MastNode,
        refs: PendingNodeRefs,
    ) {
        let child_refs = refs.child_refs.unwrap_or_else(|| self.child_refs_for_node(&node));
        let decorator_refs =
            refs.decorator_refs.unwrap_or_else(|| self.decorator_refs_for_node(&node));
        self.nodes[node_ref] = PendingMastNode {
            backing_id,
            fingerprint,
            node,
            child_refs,
            decorator_refs,
        };
    }

    fn push_node_ref(
        &mut self,
        node_id: MastNodeId,
        fingerprint: MastNodeFingerprint,
        node: MastNode,
        refs: PendingNodeRefs,
    ) -> Result<MastNodeRef, Report> {
        let child_refs = refs.child_refs.unwrap_or_else(|| self.child_refs_for_node(&node));
        let decorator_refs =
            refs.decorator_refs.unwrap_or_else(|| self.decorator_refs_for_node(&node));
        let node_ref = self
            .nodes
            .push(PendingMastNode {
                backing_id: node_id,
                fingerprint,
                node,
                child_refs,
                decorator_refs,
            })
            .into_diagnostic()
            .wrap_err("assembler created too many MAST nodes")?;

        self.node_ref_by_id.insert(node_id, node_ref);
        Ok(node_ref)
    }

    fn next_pending_node_id(&self) -> Result<MastNodeId, Report> {
        let offset = u32::try_from(self.nodes.len())
            .into_diagnostic()
            .wrap_err("assembler created too many MAST nodes")?;
        let node_id = u32::MAX
            .checked_sub(offset)
            .ok_or_else(|| report!("assembler created too many MAST nodes"))?;
        Ok(MastNodeId::new_unchecked(node_id))
    }

    fn find_node_ref_by_fingerprint(
        &self,
        fingerprint: &MastNodeFingerprint,
    ) -> Option<MastNodeRef> {
        self.node_ref_by_fingerprint.get(fingerprint).copied()
    }

    fn child_refs_for_node(&self, node: &MastNode) -> Vec<MastNodeRef> {
        let mut child_refs = Vec::new();
        node.for_each_child(|child_id| {
            let child_ref = *self
                .node_ref_by_id
                .get(&child_id)
                .expect("child node must be interned before its parent");
            child_refs.push(child_ref);
        });
        child_refs
    }

    fn decorator_refs_for_node(&self, node: &MastNode) -> PendingDecoratorRefs {
        let empty_forest = MastForest::new();
        let decorator_ref = |decorator_id| {
            *self
                .decorator_ref_by_id
                .get(&decorator_id)
                .expect("node decorators must be interned before their node")
        };
        let before_enter =
            node.before_enter(&empty_forest).iter().copied().map(decorator_ref).collect();
        let indexed = if let MastNode::Block(block) = node {
            block
                .indexed_decorator_iter(&empty_forest)
                .map(|(op_idx, decorator_id)| (op_idx, decorator_ref(decorator_id)))
                .collect()
        } else {
            Vec::new()
        };
        let after_exit =
            node.after_exit(&empty_forest).iter().copied().map(decorator_ref).collect();
        PendingDecoratorRefs { before_enter, indexed, after_exit }
    }

    fn fingerprint_from_pending_refs(
        &self,
        node_digest: Word,
        child_refs: &[MastNodeRef],
        decorator_refs: &PendingDecoratorRefs,
    ) -> MastNodeFingerprint {
        fingerprint_from_fingerprints(
            decorator_refs
                .before_enter
                .iter()
                .map(|&decorator_ref| self.decorators[decorator_ref].decorator.fingerprint()),
            decorator_refs
                .after_exit
                .iter()
                .map(|&decorator_ref| self.decorators[decorator_ref].decorator.fingerprint()),
            child_refs.iter().map(|&child_ref| self.nodes[child_ref].fingerprint),
            node_digest,
        )
    }

    fn fingerprint_for_pending_node(
        &self,
        node: &MastNode,
        child_refs: &[MastNodeRef],
        decorator_refs: &PendingDecoratorRefs,
    ) -> MastNodeFingerprint {
        if let MastNode::Block(block) = node {
            self.fingerprint_for_pending_basic_block(block, decorator_refs)
        } else {
            self.fingerprint_from_pending_refs(node.digest(), child_refs, decorator_refs)
        }
    }

    fn fingerprint_for_pending_basic_block(
        &self,
        block: &BasicBlockNode,
        decorator_refs: &PendingDecoratorRefs,
    ) -> MastNodeFingerprint {
        let before_enter_bytes: Vec<[u8; 32]> = decorator_refs
            .before_enter
            .iter()
            .map(|&decorator_ref| {
                *self.decorators[decorator_ref].decorator.fingerprint().as_bytes()
            })
            .collect();

        let raw_indexed_decorators = BasicBlockNode::unadjust_asm_op_indices(
            decorator_refs.indexed.clone(),
            block.op_batches(),
        );
        let mut op_decorator_data = Vec::with_capacity(raw_indexed_decorators.len() * 40);
        for (raw_op_idx, decorator_ref) in &raw_indexed_decorators {
            op_decorator_data.extend_from_slice(&raw_op_idx.to_le_bytes());
            op_decorator_data.extend_from_slice(
                self.decorators[*decorator_ref].decorator.fingerprint().as_bytes(),
            );
        }

        let after_exit_bytes: Vec<[u8; 32]> = decorator_refs
            .after_exit
            .iter()
            .map(|&decorator_ref| {
                *self.decorators[decorator_ref].decorator.fingerprint().as_bytes()
            })
            .collect();

        let mut assert_data = Vec::new();
        for (op_idx, op) in block.op_batches().iter().flat_map(OpBatch::ops).enumerate() {
            if let Operation::U32assert2(inner_value)
            | Operation::Assert(inner_value)
            | Operation::MpVerify(inner_value) = op
            {
                let op_idx: u32 =
                    op_idx.try_into().expect("basic block contains more than 2^32 operations");

                assert_data.push(op.op_code());
                assert_data.extend_from_slice(&op_idx.to_le_bytes());
                assert_data.extend_from_slice(&inner_value.as_canonical_u64().to_le_bytes());
            }
        }

        if decorator_refs.before_enter.is_empty()
            && decorator_refs.after_exit.is_empty()
            && raw_indexed_decorators.is_empty()
            && assert_data.is_empty()
        {
            MastNodeFingerprint::new(block.digest())
        } else {
            let decorator_bytes_iter = before_enter_bytes
                .iter()
                .map(<[u8; 32]>::as_slice)
                .chain(core::iter::once(op_decorator_data.as_slice()))
                .chain(after_exit_bytes.iter().map(<[u8; 32]>::as_slice))
                .chain(core::iter::once(assert_data.as_slice()));
            let decorator_root = Blake3_256::hash_iter(decorator_bytes_iter);
            MastNodeFingerprint::with_decorator_root(block.digest(), decorator_root)
        }
    }

    pub(crate) fn node_id(&self, node_ref: MastNodeRef) -> MastNodeId {
        self.nodes[node_ref].backing_id
    }

    #[cfg(test)]
    pub(crate) fn node_ref(&self, node_id: MastNodeId) -> Option<MastNodeRef> {
        self.node_ref_by_id.get(&node_id).copied()
    }

    #[cfg(test)]
    fn pending_node(&self, node_id: MastNodeId) -> &MastNode {
        let node_ref = self.node_ref(node_id).expect("node must be interned in builder");
        &self.nodes[node_ref].node
    }

    fn push_decorator_ref(
        &mut self,
        decorator: Decorator,
        fingerprint: DecoratorFingerprint,
        decorator_id: Option<DecoratorId>,
    ) -> Result<DecoratorRef, Report> {
        let decorator_ref = self
            .decorators
            .push(PendingDecorator {
                pending_id: None,
                #[cfg(test)]
                backing_id: decorator_id,
                decorator,
            })
            .into_diagnostic()
            .wrap_err("assembler created too many decorators")?;
        self.decorator_ref_by_fingerprint.insert(fingerprint, decorator_ref);
        #[cfg(not(test))]
        let _ = decorator_id;
        #[cfg(test)]
        if let Some(decorator_id) = decorator_id {
            self.decorator_ref_by_id.insert(decorator_id, decorator_ref);
        }
        Ok(decorator_ref)
    }

    fn pending_decorator_id_for_ref(decorator_ref: DecoratorRef) -> DecoratorId {
        DecoratorId::from(u32::MAX - u32::from(decorator_ref))
    }

    fn pending_decorator_id(&mut self, decorator_ref: DecoratorRef) -> Result<DecoratorId, Report> {
        if let Some(decorator_id) = self.decorators[decorator_ref].pending_id {
            return Ok(decorator_id);
        }

        let decorator_id = Self::pending_decorator_id_for_ref(decorator_ref);
        self.decorators[decorator_ref].pending_id = Some(decorator_id);
        self.decorator_ref_by_id.insert(decorator_id, decorator_ref);
        Ok(decorator_id)
    }

    fn pending_decorator_ids(
        &mut self,
        decorator_refs: impl IntoIterator<Item = DecoratorRef>,
    ) -> Result<Vec<DecoratorId>, Report> {
        decorator_refs
            .into_iter()
            .map(|decorator_ref| self.pending_decorator_id(decorator_ref))
            .collect()
    }

    #[cfg(test)]
    fn materialize_decorator_id(
        &mut self,
        decorator_ref: DecoratorRef,
    ) -> Result<DecoratorId, Report> {
        if let Some(decorator_id) = self.decorators[decorator_ref].backing_id {
            return Ok(decorator_id);
        }

        let decorator_id = self
            .mast_forest
            .add_decorator(self.decorators[decorator_ref].decorator.clone())
            .into_diagnostic()
            .wrap_err("assembler failed to add new decorator")?;
        self.decorators[decorator_ref].backing_id = Some(decorator_id);
        self.decorator_ref_by_id.insert(decorator_id, decorator_ref);
        Ok(decorator_id)
    }

    pub(crate) fn add_asm_op_ref(&mut self, asm_op: AssemblyOp) -> Result<AsmOpRef, Report> {
        self.asm_op_by_ref
            .push(asm_op)
            .into_diagnostic()
            .wrap_err("assembler created too many assembly op refs")
    }

    pub(crate) fn asm_op(&self, asm_op_ref: AsmOpRef) -> &AssemblyOp {
        &self.asm_op_by_ref[asm_op_ref]
    }

    pub(crate) fn asm_ops(
        &self,
        asm_op_refs: impl IntoIterator<Item = (usize, AsmOpRef)>,
    ) -> Vec<(usize, AssemblyOp)> {
        asm_op_refs
            .into_iter()
            .map(|(op_idx, asm_op_ref)| (op_idx, self.asm_op(asm_op_ref).clone()))
            .collect()
    }

    fn push_debug_var_ref(&mut self, debug_var: DebugVarInfo) -> Result<DebugVarRef, Report> {
        self.debug_vars
            .push(PendingDebugVar { debug_var })
            .into_diagnostic()
            .wrap_err("assembler created too many debug variables")
    }

    /// Removes the unused nodes that were created as part of the assembly process, and returns the
    /// resulting MAST forest.
    ///
    /// It also returns the map from assembly-time node refs to final node IDs. Any [`MastNodeRef`]
    /// used in reference to this builder should be resolved using this map.
    pub(crate) fn build(mut self) -> BuiltMastForest {
        let procedure_root_refs = core::mem::take(&mut self.procedure_root_refs);

        let merged_basic_block_refs = core::mem::take(&mut self.merged_basic_block_refs);
        let node_refs_to_remove =
            get_node_refs_to_remove(merged_basic_block_refs, &procedure_root_refs, &self.nodes);

        let mut final_forest = MastForest::new();
        *final_forest.advice_map_mut() = self.advice_map;

        let live_node_refs = live_node_refs_in_final_order(&self.nodes, &node_refs_to_remove);
        let mut live_decorator_refs = BTreeSet::new();
        for node_ref in &live_node_refs {
            live_decorator_refs.extend(self.nodes[*node_ref].decorator_refs.refs());
        }

        let mut final_decorator_id_by_ref = BTreeMap::new();
        for decorator_ref in live_decorator_refs {
            let final_decorator_id = final_forest
                .add_decorator(self.decorators[decorator_ref].decorator.clone())
                .expect("failed to add decorator - internal ordering error");
            final_decorator_id_by_ref.insert(decorator_ref, final_decorator_id);
        }

        let mut node_id_by_ref = BTreeMap::new();
        for node_ref in live_node_refs {
            let pending_node = &self.nodes[node_ref];
            let builder = build_pending_node_with_final_ids(
                pending_node,
                &node_id_by_ref,
                &final_decorator_id_by_ref,
            )
            .expect("failed to remap MAST node - internal ordering error");
            let final_node_id = builder
                .add_to_forest(&mut final_forest)
                .expect("failed to add MAST node - internal ordering error");
            node_id_by_ref.insert(node_ref, final_node_id);
        }

        // Register all pending AssemblyOp mappings in sorted node order.
        // The CSR structure requires nodes to be added sequentially.
        // We must also merge mappings for duplicate node_ids (can happen when control flow nodes
        // like Call are deduplicated but still have asm_ops registered).
        let pending_asm_op_mappings = core::mem::take(&mut self.pending_asm_op_mappings)
            .into_iter()
            .filter_map(|(node_ref, asm_ops)| {
                node_id_by_ref.get(&node_ref).copied().map(|node_id| (node_id, asm_ops))
            })
            .collect();
        let deduped_mappings = deduplicate_asm_op_mappings(pending_asm_op_mappings);

        for (node_id, asm_op_mappings) in deduped_mappings {
            let (num_operations, adjusted_mappings) =
                compute_operations_and_adjust_mappings(&final_forest[node_id], asm_op_mappings);
            let adjusted_mappings = adjusted_mappings
                .into_iter()
                .map(|(op_idx, asm_op_ref)| {
                    let asm_op_id = final_forest
                        .debug_info_mut()
                        .add_asm_op(self.asm_op_by_ref[asm_op_ref].clone())
                        .expect("failed to add AssemblyOp - internal ordering error");
                    (op_idx, asm_op_id)
                })
                .collect();

            // Errors here are programming errors since we control the ordering.
            // Use expect to surface any issues during development.
            final_forest
                .debug_info_mut()
                .register_asm_ops(node_id, num_operations, adjusted_mappings)
                .expect("failed to register AssemblyOps - internal ordering error");
        }

        // Register all pending debug variable mappings in sorted node order.
        // The CSR structure requires sequential node registration.
        // Debug vars are included in the augmented dedup fingerprint, so blocks with
        // different debug vars are not deduplicated. The dedup here is only a safety measure.
        let pending_debug_var_mappings = core::mem::take(&mut self.pending_debug_var_mappings)
            .into_iter()
            .filter_map(|(node_ref, debug_vars)| {
                node_id_by_ref.get(&node_ref).copied().map(|node_id| (node_id, debug_vars))
            })
            .collect();
        let debug_var_mappings = deduplicate_debug_var_mappings(pending_debug_var_mappings);

        let mut debug_var_id_by_ref = BTreeMap::new();
        for (node_id, debug_vars) in debug_var_mappings {
            let mut debug_var_ids = Vec::with_capacity(debug_vars.len());
            for (op_idx, debug_var_ref) in debug_vars {
                let debug_var_id =
                    if let Some(debug_var_id) = debug_var_id_by_ref.get(&debug_var_ref).copied() {
                        debug_var_id
                    } else {
                        let debug_var_id = final_forest
                            .add_debug_var(self.debug_vars[debug_var_ref].debug_var.clone())
                            .expect("failed to add debug variable - internal ordering error");
                        debug_var_id_by_ref.insert(debug_var_ref, debug_var_id);
                        debug_var_id
                    };
                debug_var_ids.push((op_idx, debug_var_id));
            }
            final_forest
                .debug_info_mut()
                .register_op_indexed_debug_vars(node_id, debug_var_ids)
                .expect("failed to register debug variables - internal ordering error");
        }

        for &root_ref in &procedure_root_refs {
            let root_id = *node_id_by_ref
                .get(&root_ref)
                .expect("procedure root must be retained in final MAST forest");
            final_forest.make_root(root_id);
        }

        final_forest
            .debug_info_mut()
            .extend_error_codes(core::mem::take(&mut self.error_codes));
        BuiltMastForest {
            mast_forest: final_forest,
            node_id_by_ref,
        }
    }
}

/// Computes the number of operations for a node and adjusts AssemblyOp indices if needed.
///
/// For basic block nodes, adjusts indices to account for padding NOOPs in OpBatches.
/// For control flow nodes, computes the operation count from the maximum index.
fn compute_operations_and_adjust_mappings(
    node: &MastNode,
    asm_op_mappings: Vec<(usize, AsmOpRef)>,
) -> (usize, Vec<(usize, AsmOpRef)>) {
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

fn build_pending_node_with_final_ids(
    pending_node: &PendingMastNode,
    final_node_id_by_ref: &BTreeMap<MastNodeRef, MastNodeId>,
    final_decorator_id_by_ref: &BTreeMap<DecoratorRef, DecoratorId>,
) -> Result<MastNodeBuilder, miden_core::mast::MastForestError> {
    let mut node_remapping = Remapping::new();
    let mut child_refs = pending_node.child_refs.iter();
    pending_node.node.for_each_child(|source_child_id| {
        let child_ref = *child_refs
            .next()
            .expect("pending node child refs must match the node's children");
        let final_child_id = *final_node_id_by_ref
            .get(&child_ref)
            .expect("pending node children must be finalized before their parent");
        node_remapping.insert(source_child_id, final_child_id);
    });
    assert!(
        child_refs.next().is_none(),
        "pending node child refs must match the node's children"
    );

    let decorator_remapping = final_decorator_remapping(
        &pending_node.node,
        &pending_node.decorator_refs,
        final_decorator_id_by_ref,
    );

    let owned_node = miden_core::mast::OwnedMastNode::try_from(pending_node.node.clone())?;
    miden_core::mast::build_owned_node_with_remapped_ids(
        owned_node,
        &node_remapping,
        &decorator_remapping,
    )
}

fn final_decorator_remapping(
    node: &MastNode,
    decorator_refs: &PendingDecoratorRefs,
    final_decorator_id_by_ref: &BTreeMap<DecoratorRef, DecoratorId>,
) -> BTreeMap<DecoratorId, DecoratorId> {
    let empty_forest = MastForest::new();
    let mut decorator_remapping = BTreeMap::new();
    insert_final_decorator_ids(
        &mut decorator_remapping,
        node.before_enter(&empty_forest).iter().copied(),
        decorator_refs.before_enter.iter().copied(),
        final_decorator_id_by_ref,
        "pending node before-enter decorator refs must match the node's decorators",
    );
    if let MastNode::Block(block) = node {
        insert_final_indexed_decorator_ids(
            &mut decorator_remapping,
            block.indexed_decorator_iter(&empty_forest),
            decorator_refs.indexed.iter().copied(),
            final_decorator_id_by_ref,
        );
    } else {
        assert!(
            decorator_refs.indexed.is_empty(),
            "only basic blocks can have operation-indexed decorators"
        );
    }
    insert_final_decorator_ids(
        &mut decorator_remapping,
        node.after_exit(&empty_forest).iter().copied(),
        decorator_refs.after_exit.iter().copied(),
        final_decorator_id_by_ref,
        "pending node after-exit decorator refs must match the node's decorators",
    );
    decorator_remapping
}

fn insert_final_indexed_decorator_ids(
    decorator_remapping: &mut BTreeMap<DecoratorId, DecoratorId>,
    source_decorator_ids: impl IntoIterator<Item = (usize, DecoratorId)>,
    decorator_refs: impl IntoIterator<Item = (usize, DecoratorRef)>,
    final_decorator_id_by_ref: &BTreeMap<DecoratorRef, DecoratorId>,
) {
    let mut source_decorator_ids = source_decorator_ids.into_iter();
    let mut decorator_refs = decorator_refs.into_iter();
    loop {
        match (source_decorator_ids.next(), decorator_refs.next()) {
            (Some((source_op_idx, source_decorator_id)), Some((op_idx, decorator_ref))) => {
                assert_eq!(
                    source_op_idx, op_idx,
                    "pending node indexed decorator refs must match the node's decorators"
                );
                let final_decorator_id = *final_decorator_id_by_ref
                    .get(&decorator_ref)
                    .expect("pending node decorators must be finalized before their node");
                decorator_remapping.insert(source_decorator_id, final_decorator_id);
            },
            (None, None) => break,
            _ => panic!("pending node indexed decorator refs must match the node's decorators"),
        }
    }
}

fn insert_final_decorator_ids(
    decorator_remapping: &mut BTreeMap<DecoratorId, DecoratorId>,
    source_decorator_ids: impl IntoIterator<Item = DecoratorId>,
    decorator_refs: impl IntoIterator<Item = DecoratorRef>,
    final_decorator_id_by_ref: &BTreeMap<DecoratorRef, DecoratorId>,
    mismatch_message: &'static str,
) {
    let mut source_decorator_ids = source_decorator_ids.into_iter();
    let mut decorator_refs = decorator_refs.into_iter();
    loop {
        match (source_decorator_ids.next(), decorator_refs.next()) {
            (Some(source_decorator_id), Some(decorator_ref)) => {
                let final_decorator_id = *final_decorator_id_by_ref
                    .get(&decorator_ref)
                    .expect("pending node decorators must be finalized before their node");
                decorator_remapping.insert(source_decorator_id, final_decorator_id);
            },
            (None, None) => break,
            _ => panic!("{mismatch_message}"),
        }
    }
}

/// Deduplicates AssemblyOp mappings by node_id, keeping only the first registration.
///
/// Mappings are sorted by node_id, then deduplicated. This is necessary because control flow
/// nodes like Call can be deduplicated, resulting in multiple registrations for the same node_id.
fn deduplicate_asm_op_mappings(
    mut mappings: Vec<(MastNodeId, Vec<(usize, AsmOpRef)>)>,
) -> Vec<(MastNodeId, Vec<(usize, AsmOpRef)>)> {
    mappings.sort_by_key(|(node_id, _)| *node_id);

    let mut seen_node_ids = BTreeSet::new();
    mappings
        .into_iter()
        .filter(|(node_id, _)| seen_node_ids.insert(*node_id))
        .collect()
}

fn append_serialized_asm_op(data: &mut Vec<u8>, op_idx: usize, asm_op: &AssemblyOp) {
    data.extend_from_slice(&op_idx.to_le_bytes());
    asm_op.context_name().write_into(data);
    asm_op.op().write_into(data);
    asm_op.num_cycles().write_into(data);
    match asm_op.location() {
        Some(location) => {
            data.push(1);
            location.uri.write_into(data);
            data.extend_from_slice(&u32::from(location.start).to_le_bytes());
            data.extend_from_slice(&u32::from(location.end).to_le_bytes());
        },
        None => data.push(0),
    }
}

/// Serializes AssemblyOp content into bytes for fingerprint augmentation.
///
/// This uses the resolved [`AssemblyOp`] payload rather than raw `AsmOpId`s so dedup depends on
/// source-mapping semantics, not allocation order.
fn serialize_asm_ops(asm_ops: &[(usize, AssemblyOp)]) -> Vec<u8> {
    let mut data = Vec::new();
    for (op_idx, asm_op) in asm_ops {
        append_serialized_asm_op(&mut data, *op_idx, asm_op);
    }
    data
}

/// Serializes AssemblyOp content referenced by `AsmOpRef`s into bytes for fingerprint augmentation.
fn serialize_asm_op_refs(
    asm_op_by_ref: &IndexVec<AsmOpRef, AssemblyOp>,
    asm_op_refs: &[(usize, AsmOpRef)],
) -> Vec<u8> {
    let mut data = Vec::new();
    for (op_idx, asm_op_ref) in asm_op_refs {
        append_serialized_asm_op(&mut data, *op_idx, &asm_op_by_ref[*asm_op_ref]);
    }
    data
}

/// Looks up and serializes the asm ops for a given node from the pending mappings.
fn serialize_asm_ops_for_node(
    asm_op_by_ref: &IndexVec<AsmOpRef, AssemblyOp>,
    pending: &[(MastNodeRef, Vec<(usize, AsmOpRef)>)],
    node_ref: MastNodeRef,
) -> Vec<u8> {
    for (pending_node_ref, asm_ops) in pending {
        if *pending_node_ref == node_ref {
            return serialize_asm_op_refs(asm_op_by_ref, asm_ops);
        }
    }
    Vec::new()
}

/// Looks up and serializes the asm ops registered for a node in an existing forest.
fn serialize_asm_ops_from_forest_node(forest: &MastForest, node_id: MastNodeId) -> Vec<u8> {
    let mut entries = forest.debug_info().asm_ops_for_node(node_id);
    if entries.is_empty() {
        return Vec::new();
    }

    if let MastNode::Block(block) = &forest[node_id] {
        entries = BasicBlockNode::unadjust_asm_op_indices(entries, block.op_batches());
    }

    let mut data = Vec::new();
    for (op_idx, asm_op_id) in entries {
        if let Some(asm_op) = forest.debug_info().asm_op(asm_op_id) {
            append_serialized_asm_op(&mut data, op_idx, asm_op);
        }
    }
    data
}

fn serialize_debug_var_refs(
    debug_var_by_ref: &IndexVec<DebugVarRef, PendingDebugVar>,
    debug_vars: &[(usize, DebugVarRef)],
) -> Vec<u8> {
    let mut data = Vec::new();
    for (op_idx, debug_var_ref) in debug_vars {
        data.extend_from_slice(&op_idx.to_le_bytes());
        debug_var_by_ref[*debug_var_ref].debug_var.write_into(&mut data);
    }
    data
}

/// Looks up and serializes the debug vars for a given node from the pending mappings.
fn serialize_debug_vars_for_node(
    debug_vars: &IndexVec<DebugVarRef, PendingDebugVar>,
    pending: &[(MastNodeRef, Vec<(usize, DebugVarRef)>)],
    node_ref: MastNodeRef,
) -> Vec<u8> {
    for (pending_node_ref, vars) in pending {
        if *pending_node_ref == node_ref {
            return serialize_debug_var_refs(debug_vars, vars);
        }
    }
    Vec::new()
}

/// Looks up and serializes the debug vars registered for a node in an existing forest.
fn serialize_debug_vars_from_forest_node(forest: &MastForest, node_id: MastNodeId) -> Vec<u8> {
    let entries = forest.debug_info().debug_vars_for_node(node_id);
    if entries.is_empty() {
        return Vec::new();
    }

    let mut data = Vec::new();
    for (op_idx, var_id) in entries {
        data.extend_from_slice(&op_idx.to_le_bytes());
        if let Some(debug_var) = forest.debug_info().debug_var(var_id) {
            debug_var.write_into(&mut data);
        }
    }
    data
}

/// Deduplicates debug variable mappings by node_id (keeps first registration).
///
/// Debug vars are included in the augmented dedup fingerprint, so blocks with different
/// debug vars will not be deduplicated. This function is a safety measure to handle any
/// remaining duplicate registrations (e.g. from control flow node deduplication).
fn deduplicate_debug_var_mappings(
    mut mappings: Vec<(MastNodeId, Vec<(usize, DebugVarRef)>)>,
) -> Vec<(MastNodeId, Vec<(usize, DebugVarRef)>)> {
    mappings.sort_by_key(|(node_id, _)| *node_id);

    let mut seen_node_ids = BTreeSet::new();
    mappings
        .into_iter()
        .filter(|(node_id, _)| seen_node_ids.insert(*node_id))
        .collect()
}

/// Takes the set of MAST node refs (all basic blocks) that were merged as part of the assembly
/// process (i.e. they were contiguous and were merged into a single basic block), and returns the
/// subset of nodes that can be removed from the MAST forest.
///
/// Specifically, MAST node refs can be reused, so merging a basic block doesn't mean it should be
/// removed (specifically in the case where another node refers to it). Hence, we cycle through all
/// builder-local dependencies and only mark for removal those nodes that are not referenced.
/// We also ensure that procedure roots are not removed.
fn get_node_refs_to_remove(
    merged_node_refs: BTreeSet<MastNodeRef>,
    procedure_root_refs: &[MastNodeRef],
    nodes: &IndexVec<MastNodeRef, PendingMastNode>,
) -> BTreeSet<MastNodeRef> {
    // make sure not to remove procedure roots
    let mut nodes_to_remove: BTreeSet<MastNodeRef> = merged_node_refs
        .iter()
        .filter(|&&node_ref| !procedure_root_refs.contains(&node_ref))
        .copied()
        .collect();

    for node in nodes {
        for child_ref in &node.child_refs {
            if nodes_to_remove.contains(child_ref) {
                nodes_to_remove.remove(child_ref);
            }
        }
    }

    nodes_to_remove
}

fn live_node_refs_in_final_order(
    nodes: &IndexVec<MastNodeRef, PendingMastNode>,
    node_refs_to_remove: &BTreeSet<MastNodeRef>,
) -> Vec<MastNodeRef> {
    let mut live_node_refs = (0..nodes.len())
        .map(|index| MastNodeRef::from(index as u32))
        .filter(|node_ref| !node_refs_to_remove.contains(node_ref))
        .collect::<Vec<_>>();

    let live_node_ref_set = live_node_refs.iter().copied().collect::<BTreeSet<_>>();

    let mut external_node_refs = Vec::new();
    live_node_refs.retain(|node_ref| {
        if nodes[*node_ref].node.is_external() {
            external_node_refs.push(*node_ref);
            false
        } else {
            true
        }
    });
    external_node_refs.sort_by_key(|node_ref| (nodes[*node_ref].fingerprint, *node_ref));

    let mut final_order = external_node_refs;
    let mut emitted_node_refs = final_order.iter().copied().collect::<BTreeSet<_>>();
    let mut remaining_node_refs = live_node_refs.into_iter().collect::<BTreeSet<_>>();

    while !remaining_node_refs.is_empty() {
        let mut ready_node_refs = remaining_node_refs
            .iter()
            .copied()
            .filter(|node_ref| {
                nodes[*node_ref].child_refs.iter().all(|child_ref| {
                    !live_node_ref_set.contains(child_ref) || emitted_node_refs.contains(child_ref)
                })
            })
            .collect::<Vec<_>>();

        assert!(
            !ready_node_refs.is_empty(),
            "pending MAST nodes must form an acyclic dependency graph"
        );

        ready_node_refs.sort();
        for node_ref in ready_node_refs {
            remaining_node_refs.remove(&node_ref);
            emitted_node_refs.insert(node_ref);
            final_order.push(node_ref);
        }
    }

    final_order
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

    pub(crate) fn get_mast_node_by_ref(&self, node_ref: MastNodeRef) -> Option<&MastNode> {
        self.nodes.get(node_ref).map(|pending_node| &pending_node.node)
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

        self.record_procedure_root_ref(procedure.body_node_ref());
        self.proc_gid_by_mast_root.insert(procedure.mast_root(), gid);
        self.procedures.insert(gid, procedure);

        Ok(())
    }

    fn record_procedure_root_ref(&mut self, root_ref: MastNodeRef) {
        if !self.procedure_root_refs.contains(&root_ref) {
            self.procedure_root_refs.push(root_ref);
        }
    }

    fn is_procedure_root_ref(&self, node_ref: MastNodeRef) -> bool {
        self.procedure_root_refs.contains(&node_ref)
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
    #[cfg(all(test, feature = "std"))]
    pub fn join_nodes(
        &mut self,
        node_ids: Vec<MastNodeId>,
        asm_op: Option<AssemblyOp>,
    ) -> Result<MastNodeId, Report> {
        debug_assert!(!node_ids.is_empty(), "cannot combine empty MAST node id list");

        let node_refs = node_ids
            .into_iter()
            .map(|node_id| self.intern_node_id(node_id))
            .collect::<Result<Vec<_>, _>>()?;
        let node_ref = self.join_node_refs(node_refs, asm_op)?;

        Ok(self.node_id(node_ref))
    }

    pub(crate) fn join_node_refs(
        &mut self,
        node_refs: Vec<MastNodeRef>,
        asm_op: Option<AssemblyOp>,
    ) -> Result<MastNodeRef, Report> {
        debug_assert!(!node_refs.is_empty(), "cannot combine empty MAST node ref list");

        let mut node_refs = self.merge_contiguous_basic_block_refs(node_refs)?;

        // build a binary tree of blocks joining them using JOIN blocks
        while node_refs.len() > 1 {
            let last_mast_node_ref = if node_refs.len().is_multiple_of(2) {
                None
            } else {
                node_refs.pop()
            };

            let mut source_node_refs = Vec::new();
            core::mem::swap(&mut node_refs, &mut source_node_refs);

            let mut source_mast_node_iter = source_node_refs.drain(0..);
            while let (Some(left), Some(right)) =
                (source_mast_node_iter.next(), source_mast_node_iter.next())
            {
                let left_digest = *self.nodes[left].fingerprint.mast_root();
                let right_digest = *self.nodes[right].fingerprint.mast_root();
                let join_digest =
                    hasher::merge_in_domain(&[left_digest, right_digest], JoinNode::DOMAIN);
                let join_builder = JoinNodeBuilder::new([self.node_id(left), self.node_id(right)])
                    .with_before_enter(vec![])
                    .with_after_exit(vec![])
                    .with_digest(join_digest);
                let child_refs = vec![left, right];
                let decorator_refs = PendingDecoratorRefs::default();
                let base_fingerprint =
                    self.fingerprint_from_pending_refs(join_digest, &child_refs, &decorator_refs);
                let join_mast_node_ref = if let Some(ref asm_op) = asm_op {
                    self.ensure_node_with_asm_op_ref_and_pending_refs(
                        MastNodeBuilder::Join(join_builder),
                        asm_op.clone(),
                        base_fingerprint,
                        child_refs,
                        decorator_refs,
                    )?
                } else {
                    let (node_ref, _is_new) = self.ensure_node_exists_with_pending_refs(
                        MastNodeBuilder::Join(join_builder),
                        base_fingerprint,
                        child_refs,
                        decorator_refs,
                    )?;
                    node_ref
                };

                node_refs.push(join_mast_node_ref);
            }
            if let Some(mast_node_ref) = last_mast_node_ref {
                node_refs.push(mast_node_ref);
            }
        }

        Ok(node_refs.remove(0))
    }

    pub(crate) fn ensure_split_node_ref(
        &mut self,
        branches: [MastNodeRef; 2],
        before_enter: Option<Vec<DecoratorRef>>,
        asm_op: AssemblyOp,
    ) -> Result<MastNodeRef, Report> {
        let branch_ids = branches.map(|node_ref| self.node_id(node_ref));
        let mut split_builder = SplitNodeBuilder::new(branch_ids);
        let mut pending_decorator_refs = PendingDecoratorRefs::default();
        if let Some(decorator_refs) = before_enter {
            let decorator_ids = self.pending_decorator_ids(decorator_refs.iter().copied())?;
            pending_decorator_refs.before_enter = decorator_refs;
            split_builder.append_before_enter(decorator_ids);
        }
        let branch_digests = branches.map(|node_ref| *self.nodes[node_ref].fingerprint.mast_root());
        let split_digest = hasher::merge_in_domain(&branch_digests, SplitNode::DOMAIN);
        let split_builder = split_builder.with_digest(split_digest);
        let child_refs = Vec::from(branches);
        let base_fingerprint =
            self.fingerprint_from_pending_refs(split_digest, &child_refs, &pending_decorator_refs);

        self.ensure_node_with_asm_op_ref_and_pending_refs(
            MastNodeBuilder::Split(split_builder),
            asm_op,
            base_fingerprint,
            child_refs,
            pending_decorator_refs,
        )
    }

    pub(crate) fn ensure_loop_node_ref(
        &mut self,
        body: MastNodeRef,
        before_enter: Option<Vec<DecoratorRef>>,
        asm_op: AssemblyOp,
    ) -> Result<MastNodeRef, Report> {
        let mut loop_builder = LoopNodeBuilder::new(self.node_id(body));
        let mut pending_decorator_refs = PendingDecoratorRefs::default();
        if let Some(decorator_refs) = before_enter {
            let decorator_ids = self.pending_decorator_ids(decorator_refs.iter().copied())?;
            pending_decorator_refs.before_enter = decorator_refs;
            loop_builder.append_before_enter(decorator_ids);
        }
        let body_digest = *self.nodes[body].fingerprint.mast_root();
        let loop_digest =
            hasher::merge_in_domain(&[body_digest, Word::default()], LoopNode::DOMAIN);
        let loop_builder = loop_builder.with_digest(loop_digest);
        let child_refs = vec![body];
        let base_fingerprint =
            self.fingerprint_from_pending_refs(loop_digest, &child_refs, &pending_decorator_refs);

        self.ensure_node_with_asm_op_ref_and_pending_refs(
            MastNodeBuilder::Loop(loop_builder),
            asm_op,
            base_fingerprint,
            child_refs,
            pending_decorator_refs,
        )
    }

    pub(crate) fn ensure_call_node_ref(
        &mut self,
        callee: MastNodeRef,
        is_syscall: bool,
        asm_op: AssemblyOp,
    ) -> Result<MastNodeRef, Report> {
        let callee_id = self.node_id(callee);
        let call_builder = if is_syscall {
            CallNodeBuilder::new_syscall(callee_id)
        } else {
            CallNodeBuilder::new(callee_id)
        };
        let callee_digest = *self.nodes[callee].fingerprint.mast_root();
        let call_domain = if is_syscall {
            CallNode::SYSCALL_DOMAIN
        } else {
            CallNode::CALL_DOMAIN
        };
        let call_digest = hasher::merge_in_domain(&[callee_digest, Word::default()], call_domain);
        let child_refs = vec![callee];
        let decorator_refs = PendingDecoratorRefs::default();
        let base_fingerprint =
            self.fingerprint_from_pending_refs(call_digest, &child_refs, &decorator_refs);
        self.ensure_node_with_asm_op_ref_and_pending_refs(
            MastNodeBuilder::Call(
                call_builder
                    .with_before_enter(vec![])
                    .with_after_exit(vec![])
                    .with_digest(call_digest),
            ),
            asm_op,
            base_fingerprint,
            child_refs,
            decorator_refs,
        )
    }

    pub(crate) fn ensure_dyn_node_ref(
        &mut self,
        is_dyncall: bool,
        asm_op: AssemblyOp,
    ) -> Result<MastNodeRef, Report> {
        let dyn_builder = if is_dyncall {
            DynNodeBuilder::new_dyncall()
        } else {
            DynNodeBuilder::new_dyn()
        };
        let dyn_digest = if is_dyncall {
            DynNode::DYNCALL_DEFAULT_DIGEST
        } else {
            DynNode::DYN_DEFAULT_DIGEST
        };
        let child_refs = Vec::new();
        let decorator_refs = PendingDecoratorRefs::default();
        let base_fingerprint =
            self.fingerprint_from_pending_refs(dyn_digest, &child_refs, &decorator_refs);
        self.ensure_node_with_asm_op_ref_and_pending_refs(
            MastNodeBuilder::Dyn(
                dyn_builder
                    .with_before_enter(vec![])
                    .with_after_exit(vec![])
                    .with_digest(dyn_digest),
            ),
            asm_op,
            base_fingerprint,
            child_refs,
            decorator_refs,
        )
    }

    pub(crate) fn clone_node_with_before_enter_refs(
        &mut self,
        node_ref: MastNodeRef,
        decorator_refs: Vec<DecoratorRef>,
    ) -> Result<MastNodeRef, Report> {
        let decorator_ids = self.pending_decorator_ids(decorator_refs.iter().copied())?;
        let mut pending_decorator_refs = self.nodes[node_ref].decorator_refs.clone();
        pending_decorator_refs.before_enter = decorator_refs;
        let child_refs = self.nodes[node_ref].child_refs.clone();
        let base_fingerprint = self.fingerprint_for_pending_node(
            &self.nodes[node_ref].node,
            &child_refs,
            &pending_decorator_refs,
        );
        let empty_forest = MastForest::new();
        let decorated_builder = self.nodes[node_ref]
            .node
            .clone()
            .to_builder(&empty_forest)
            .with_before_enter(decorator_ids);

        self.ensure_node_preserving_debug_vars_ref_with_fingerprint(
            decorated_builder,
            base_fingerprint,
            node_ref,
            PendingNodeRefs {
                child_refs: Some(child_refs),
                decorator_refs: Some(pending_decorator_refs),
            },
        )
    }

    fn merge_contiguous_basic_block_refs(
        &mut self,
        node_refs: Vec<MastNodeRef>,
    ) -> Result<Vec<MastNodeRef>, Report> {
        let mut merged_node_refs = Vec::with_capacity(node_refs.len());
        let mut contiguous_basic_block_refs: Vec<MastNodeRef> = Vec::new();

        for node_ref in node_refs {
            if self.nodes[node_ref].node.is_basic_block() {
                contiguous_basic_block_refs.push(node_ref);
            } else {
                merged_node_refs.extend(self.merge_basic_block_refs(&contiguous_basic_block_refs)?);
                contiguous_basic_block_refs.clear();

                merged_node_refs.push(node_ref);
            }
        }

        merged_node_refs.extend(self.merge_basic_block_refs(&contiguous_basic_block_refs)?);

        Ok(merged_node_refs)
    }

    /// Creates a new basic block by appending all operations and decorators in the provided list of
    /// basic blocks (which are assumed to be contiguous).
    ///
    /// # Panics
    /// - Panics if a provided [`MastNodeId`] doesn't refer to a basic block node.
    #[cfg(test)]
    fn merge_basic_blocks(
        &mut self,
        contiguous_basic_block_ids: &[MastNodeId],
    ) -> Result<Vec<MastNodeId>, Report> {
        let contiguous_basic_block_refs = contiguous_basic_block_ids
            .iter()
            .copied()
            .map(|node_id| self.intern_node_id(node_id))
            .collect::<Result<Vec<_>, _>>()?;
        self.merge_basic_block_refs(&contiguous_basic_block_refs)
            .map(|node_refs| node_refs.into_iter().map(|node_ref| self.node_id(node_ref)).collect())
    }

    fn merge_basic_block_refs(
        &mut self,
        contiguous_basic_block_refs: &[MastNodeRef],
    ) -> Result<Vec<MastNodeRef>, Report> {
        if contiguous_basic_block_refs.is_empty() {
            return Ok(Vec::new());
        }
        if contiguous_basic_block_refs.len() == 1 {
            return Ok(contiguous_basic_block_refs.to_vec());
        }

        let mut operations: Vec<Operation> = Vec::new();
        let mut decorators = DecoratorList::new();
        let mut pending_after_exit = Vec::new();
        // Track asm_ops and debug_vars being accumulated for merged blocks, with adjusted indices
        let mut merged_asm_ops: Vec<(usize, AsmOpRef)> = Vec::new();
        let mut merged_debug_vars: Vec<(usize, DebugVarRef)> = Vec::new();

        let mut merged_basic_block_refs: Vec<MastNodeRef> = Vec::new();

        for &basic_block_ref in contiguous_basic_block_refs {
            // check if the block should be merged with other blocks
            if should_merge(
                self.is_procedure_root_ref(basic_block_ref),
                self.nodes[basic_block_ref]
                    .node
                    .get_basic_block()
                    .expect("merge_basic_blocks: expected BasicBlockNode")
                    .num_op_batches(),
            ) {
                // Collect decorators and operations from the block (while still borrowing)
                // We need owned copies so we can drop the borrow before mutating self
                let (block_decorators, block_before_enter, block_after_exit, block_ops) = {
                    let pending_basic_block_node = self.nodes[basic_block_ref]
                        .node
                        .get_basic_block()
                        .expect("merge_basic_blocks: expected BasicBlockNode");
                    let empty_forest = MastForest::new();
                    let block_decorators =
                        pending_basic_block_node.raw_op_indexed_decorators(&empty_forest);
                    let block_before_enter =
                        pending_basic_block_node.before_enter(&empty_forest).to_vec();
                    let block_after_exit =
                        pending_basic_block_node.after_exit(&empty_forest).to_vec();
                    let block_ops: Vec<Operation> = pending_basic_block_node
                        .op_batches()
                        .iter()
                        .flat_map(|b| b.raw_ops().copied())
                        .collect();
                    (block_decorators, block_before_enter, block_after_exit, block_ops)
                };
                let ops_offset = operations.len();

                for decorator in core::mem::take(&mut pending_after_exit) {
                    decorators.push((ops_offset, decorator));
                }
                for decorator in block_before_enter {
                    decorators.push((ops_offset, decorator));
                }

                // Transfer any pending asm_ops and debug_vars for this block to the merged result
                self.transfer_asm_ops_for_merge(basic_block_ref, ops_offset, &mut merged_asm_ops);
                self.transfer_debug_vars_for_merge(
                    basic_block_ref,
                    ops_offset,
                    &mut merged_debug_vars,
                );

                // Add operation-indexed decorators with adjusted indices.
                for (op_idx, decorator) in block_decorators {
                    decorators.push((op_idx + ops_offset, decorator));
                }
                pending_after_exit.extend(block_after_exit);
                operations.extend(block_ops);
            } else {
                // If we don't want to merge this block, flush the buffer of operations into a
                // new block, and add the un-merged block after it.
                if !operations.is_empty() {
                    let block_ops = core::mem::take(&mut operations);
                    let block_decorators = core::mem::take(&mut decorators);
                    let block_after_exit = core::mem::take(&mut pending_after_exit);
                    let block_asm_ops = core::mem::take(&mut merged_asm_ops);
                    let block_debug_vars = core::mem::take(&mut merged_debug_vars);
                    let merged_basic_block_ref = self.ensure_block_with_asm_op_and_debug_var_refs(
                        block_ops,
                        block_decorators,
                        block_asm_ops,
                        block_debug_vars,
                        vec![],
                        block_after_exit,
                    )?;

                    merged_basic_block_refs.push(merged_basic_block_ref);
                }
                merged_basic_block_refs.push(basic_block_ref);
            }
        }

        // Mark the removed basic blocks as merged
        self.merged_basic_block_refs.extend(contiguous_basic_block_refs.iter().copied());

        if !operations.is_empty() || !decorators.is_empty() || !pending_after_exit.is_empty() {
            let merged_basic_block = self.ensure_block_with_asm_op_and_debug_var_refs(
                operations,
                decorators,
                merged_asm_ops,
                merged_debug_vars,
                vec![],
                pending_after_exit,
            )?;
            merged_basic_block_refs.push(merged_basic_block);
        }

        Ok(merged_basic_block_refs)
    }

    /// Copies pending asm_ops from a source block into the merged list with adjusted indices.
    ///
    /// The source block's entries are left in `pending_asm_op_mappings` so that if it
    /// survives removal (e.g. it's a procedure root or referenced child), its metadata
    /// is still registered during `build()`.
    fn transfer_asm_ops_for_merge(
        &self,
        source_block_ref: MastNodeRef,
        ops_offset: usize,
        merged_asm_ops: &mut Vec<(usize, AsmOpRef)>,
    ) {
        for (node_ref, asm_ops) in &self.pending_asm_op_mappings {
            if *node_ref == source_block_ref {
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
        source_block_ref: MastNodeRef,
        ops_offset: usize,
        merged_debug_vars: &mut Vec<(usize, DebugVarRef)>,
    ) {
        for (node_ref, debug_vars) in &self.pending_debug_var_mappings {
            if *node_ref == source_block_ref {
                merged_debug_vars.extend(
                    debug_vars.iter().map(|(op_idx, var_id)| (op_idx + ops_offset, *var_id)),
                );
            }
        }
    }

    fn serialize_pending_asm_ops_for_node_ref(&self, node_ref: MastNodeRef) -> Vec<u8> {
        serialize_asm_ops_for_node(&self.asm_op_by_ref, &self.pending_asm_op_mappings, node_ref)
    }

    fn serialize_pending_debug_vars_for_node_ref(&self, node_ref: MastNodeRef) -> Vec<u8> {
        serialize_debug_vars_for_node(&self.debug_vars, &self.pending_debug_var_mappings, node_ref)
    }

    /// Like ensure_block but takes pre-existing AsmOpRefs and DebugVarRefs instead of raw
    /// AssemblyOps. Used when merging blocks that already have their metadata registered.
    fn ensure_block_with_asm_op_and_debug_var_refs(
        &mut self,
        operations: Vec<Operation>,
        decorators: DecoratorList,
        asm_op_refs: Vec<(usize, AsmOpRef)>,
        debug_vars: Vec<(usize, DebugVarRef)>,
        before_enter: Vec<DecoratorId>,
        after_exit: Vec<DecoratorId>,
    ) -> Result<MastNodeRef, Report> {
        let block = BasicBlockNodeBuilder::new(operations, decorators)
            .with_before_enter(before_enter)
            .with_after_exit(after_exit);
        let node = MastNodeBuilder::BasicBlock(block)
            .build_with_forced_digest()
            .into_diagnostic()
            .wrap_err("assembler failed to build new node")?;
        let pending_decorator_refs = self.decorator_refs_for_node(&node);

        let base_fingerprint =
            self.fingerprint_for_pending_node(&node, &[], &pending_decorator_refs);
        let dedup_fingerprint = self.maybe_augment(
            self.maybe_augment(
                base_fingerprint,
                &serialize_asm_op_refs(&self.asm_op_by_ref, &asm_op_refs),
            ),
            &serialize_debug_var_refs(&self.debug_vars, &debug_vars),
        );

        let (node_ref, is_new) =
            if let Some(node_ref) = self.find_node_ref_by_fingerprint(&dedup_fingerprint) {
                (node_ref, false)
            } else {
                let new_node_ref = self.insert_pending_node_ref(
                    node,
                    dedup_fingerprint,
                    PendingNodeRefs {
                        child_refs: Some(Vec::new()),
                        decorator_refs: Some(pending_decorator_refs),
                    },
                )?;
                (new_node_ref, true)
            };

        if is_new && !asm_op_refs.is_empty() {
            self.pending_asm_op_mappings.push((node_ref, asm_op_refs));
        }
        if is_new && !debug_vars.is_empty() {
            self.pending_debug_var_mappings.push((node_ref, debug_vars));
        }

        Ok(node_ref)
    }
}

// ------------------------------------------------------------------------------------------------
/// Node inserters
impl MastForestBuilder {
    /// Adds a decorator to the forest, and returns the [`Decorator`] associated with it.
    #[cfg(test)]
    pub fn ensure_decorator(&mut self, decorator: Decorator) -> Result<DecoratorId, Report> {
        let decorator_hash = decorator.fingerprint();

        let decorator_ref =
            if let Some(&decorator_ref) = self.decorator_ref_by_fingerprint.get(&decorator_hash) {
                // decorator already exists in the builder; return previously assigned id
                decorator_ref
            } else {
                self.push_decorator_ref(decorator, decorator_hash, None)?
            };

        self.materialize_decorator_id(decorator_ref)
    }

    /// Adds a decorator to the forest, and returns its builder-local [`DecoratorRef`].
    pub(crate) fn ensure_decorator_ref(
        &mut self,
        decorator: Decorator,
    ) -> Result<DecoratorRef, Report> {
        let decorator_hash = decorator.fingerprint();
        if let Some(&decorator_ref) = self.decorator_ref_by_fingerprint.get(&decorator_hash) {
            return Ok(decorator_ref);
        }

        self.push_decorator_ref(decorator, decorator_hash, None)
    }

    /// Adds a debug variable to the builder, and returns its builder-local [`DebugVarRef`].
    ///
    /// Unlike decorators, debug variables are not deduplicated since each occurrence
    /// represents a specific point in program execution where the variable's location
    /// is being tracked.
    pub(crate) fn add_debug_var_ref(
        &mut self,
        debug_var: DebugVarInfo,
    ) -> Result<DebugVarRef, Report> {
        self.push_debug_var_ref(debug_var)
    }

    /// Adds a node to the forest, and returns the [`MastNodeId`] associated with it.
    ///
    /// Note that only one copy of nodes that have the same MAST root and decorators is added to the
    /// MAST forest; two nodes that have the same MAST root and decorators will have the same
    /// [`MastNodeId`].
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn ensure_node(
        &mut self,
        builder: impl MastForestContributor,
    ) -> Result<MastNodeId, Report> {
        let node_fingerprint = self.fingerprint_for_builder(&builder);
        let node_ref = if let Some(node_ref) = self.find_node_ref_by_fingerprint(&node_fingerprint)
        {
            node_ref
        } else {
            self.insert_new_node_ref(
                builder,
                node_fingerprint,
                "assembler failed to add new node",
                PendingNodeRefs::default(),
            )?
        };
        Ok(self.node_id(node_ref))
    }

    /// Like [`Self::ensure_node`], but includes an AssemblyOp in the dedup fingerprint and
    /// registers it for the node if a new node is created.
    #[cfg(test)]
    pub(crate) fn ensure_node_with_asm_op(
        &mut self,
        builder: impl MastForestContributor,
        asm_op: AssemblyOp,
    ) -> Result<MastNodeId, Report> {
        let node_ref = self.ensure_node_with_asm_op_ref(builder, asm_op)?;
        Ok(self.node_id(node_ref))
    }

    /// Like [`Self::ensure_node_ref`], but includes an AssemblyOp in the dedup fingerprint and
    /// registers it for the node if a new node is created.
    #[cfg(test)]
    pub(crate) fn ensure_node_with_asm_op_ref(
        &mut self,
        builder: impl MastForestContributor,
        asm_op: AssemblyOp,
    ) -> Result<MastNodeRef, Report> {
        self.ensure_node_with_asm_op_ref_and_child_refs(builder, asm_op, None)
    }

    #[cfg(test)]
    fn ensure_node_with_asm_op_ref_and_child_refs(
        &mut self,
        builder: impl MastForestContributor,
        asm_op: AssemblyOp,
        child_refs: Option<Vec<MastNodeRef>>,
    ) -> Result<MastNodeRef, Report> {
        let base_fingerprint = self.fingerprint_for_builder(&builder);
        let dedup_fingerprint =
            self.maybe_augment(base_fingerprint, &serialize_asm_ops(&[(0, asm_op.clone())]));

        if let Some(node_ref) = self.find_node_ref_by_fingerprint(&dedup_fingerprint) {
            Ok(node_ref)
        } else {
            let new_node_ref = self.insert_new_node_ref(
                builder,
                dedup_fingerprint,
                "assembler failed to add new node",
                PendingNodeRefs { child_refs, ..Default::default() },
            )?;

            let asm_op_ref = self.add_asm_op_ref(asm_op)?;
            self.pending_asm_op_mappings.push((new_node_ref, vec![(0, asm_op_ref)]));

            Ok(new_node_ref)
        }
    }

    fn ensure_node_with_asm_op_ref_and_pending_refs(
        &mut self,
        builder: MastNodeBuilder,
        asm_op: AssemblyOp,
        base_fingerprint: MastNodeFingerprint,
        child_refs: Vec<MastNodeRef>,
        decorator_refs: PendingDecoratorRefs,
    ) -> Result<MastNodeRef, Report> {
        let dedup_fingerprint =
            self.maybe_augment(base_fingerprint, &serialize_asm_ops(&[(0, asm_op.clone())]));

        if let Some(node_ref) = self.find_node_ref_by_fingerprint(&dedup_fingerprint) {
            return Ok(node_ref);
        }

        let new_node_ref = self.insert_new_pending_node_ref(
            builder,
            dedup_fingerprint,
            "assembler failed to add new node",
            PendingNodeRefs {
                child_refs: Some(child_refs),
                decorator_refs: Some(decorator_refs),
            },
        )?;

        let asm_op_ref = self.add_asm_op_ref(asm_op)?;
        self.pending_asm_op_mappings.push((new_node_ref, vec![(0, asm_op_ref)]));

        Ok(new_node_ref)
    }

    /// Like [`Self::ensure_node`], but includes external metadata from `source_node_id` in the
    /// dedup fingerprint and copies it to the new node. Used when cloning a node (e.g. the
    /// repeat path) so that the rebuilt node keeps the same dedup semantics as the original.
    #[cfg(test)]
    pub(crate) fn ensure_node_preserving_debug_vars(
        &mut self,
        builder: MastNodeBuilder,
        source_node_id: MastNodeId,
    ) -> Result<MastNodeId, Report> {
        let source_node_ref = self.intern_node_id(source_node_id)?;
        let node_ref = self.ensure_node_preserving_debug_vars_ref_with_refs(
            builder,
            source_node_ref,
            PendingNodeRefs {
                child_refs: Some(self.nodes[source_node_ref].child_refs.clone()),
                ..Default::default()
            },
        )?;
        Ok(self.node_id(node_ref))
    }

    /// Like [`Self::ensure_node_ref`], but includes external metadata from `source_node_ref` in
    /// the dedup fingerprint and copies it to the new node.
    #[cfg(test)]
    fn ensure_node_preserving_debug_vars_ref_with_refs(
        &mut self,
        builder: MastNodeBuilder,
        source_node_ref: MastNodeRef,
        refs: PendingNodeRefs,
    ) -> Result<MastNodeRef, Report> {
        let base_fingerprint = self.fingerprint_for_builder(&builder);
        self.ensure_node_preserving_debug_vars_ref_with_fingerprint(
            builder,
            base_fingerprint,
            source_node_ref,
            refs,
        )
    }

    fn ensure_node_preserving_debug_vars_ref_with_fingerprint(
        &mut self,
        builder: MastNodeBuilder,
        base_fingerprint: MastNodeFingerprint,
        source_node_ref: MastNodeRef,
        refs: PendingNodeRefs,
    ) -> Result<MastNodeRef, Report> {
        // Augment with the source node's external metadata, matching ensure_block() semantics.
        let asm_ops_data = self.serialize_pending_asm_ops_for_node_ref(source_node_ref);
        let debug_vars_data = self.serialize_pending_debug_vars_for_node_ref(source_node_ref);
        let dedup_fingerprint = self
            .maybe_augment(self.maybe_augment(base_fingerprint, &asm_ops_data), &debug_vars_data);

        if let Some(node_ref) = self.find_node_ref_by_fingerprint(&dedup_fingerprint) {
            Ok(node_ref)
        } else {
            let new_node_ref = self.insert_new_pending_node_ref(
                builder,
                dedup_fingerprint,
                "assembler failed to add new node",
                refs,
            )?;

            // Carry over AssemblyOp registration from the source node.
            let asm_ops: Option<Vec<_>> = self
                .pending_asm_op_mappings
                .iter()
                .find(|(node_ref, _)| *node_ref == source_node_ref)
                .map(|(_, asm_ops)| asm_ops.clone());
            if let Some(asm_ops) = asm_ops
                && !asm_ops.is_empty()
            {
                self.pending_asm_op_mappings.push((new_node_ref, asm_ops));
            }

            // Carry over debug var registration from the source node.
            let debug_vars: Option<Vec<_>> = self
                .pending_debug_var_mappings
                .iter()
                .find(|(node_ref, _)| *node_ref == source_node_ref)
                .map(|(_, vars)| vars.clone());
            if let Some(vars) = debug_vars
                && !vars.is_empty()
            {
                self.pending_debug_var_mappings.push((new_node_ref, vars));
            }

            Ok(new_node_ref)
        }
    }

    /// Copies a statically linked node into this builder while keeping source metadata in the
    /// dedup fingerprint and remapping it into the target forest when a new node is created.
    #[cfg(test)]
    fn ensure_node_from_statically_linked_source(
        &mut self,
        builder: MastNodeBuilder,
        source_node_id: MastNodeId,
    ) -> Result<MastNodeId, Report> {
        let node_ref = self.ensure_node_from_statically_linked_source_ref(
            builder,
            source_node_id,
            None,
            None,
        )?;
        Ok(self.node_id(node_ref))
    }

    /// Copies a statically linked node into this builder while keeping source metadata in the
    /// dedup fingerprint and remapping it into the target forest when a new node is created.
    fn ensure_node_from_statically_linked_source_ref(
        &mut self,
        builder: MastNodeBuilder,
        source_node_id: MastNodeId,
        child_refs: Option<Vec<MastNodeRef>>,
        decorator_refs: Option<PendingDecoratorRefs>,
    ) -> Result<MastNodeRef, Report> {
        let node = builder
            .build_with_forced_digest()
            .into_diagnostic()
            .wrap_err("assembler failed to build new statically linked node")?;
        let child_refs = child_refs.unwrap_or_else(|| self.child_refs_for_node(&node));
        let decorator_refs = decorator_refs.unwrap_or_else(|| self.decorator_refs_for_node(&node));
        let base_fingerprint =
            self.fingerprint_for_pending_node(&node, &child_refs, &decorator_refs);
        let asm_ops_data =
            serialize_asm_ops_from_forest_node(&self.statically_linked_mast, source_node_id);
        let debug_vars_data =
            serialize_debug_vars_from_forest_node(&self.statically_linked_mast, source_node_id);
        let dedup_fingerprint = self
            .maybe_augment(self.maybe_augment(base_fingerprint, &asm_ops_data), &debug_vars_data);

        if let Some(node_ref) = self.find_node_ref_by_fingerprint(&dedup_fingerprint) {
            return Ok(node_ref);
        }

        let new_node_ref = self.insert_pending_node_ref(
            node,
            dedup_fingerprint,
            PendingNodeRefs {
                child_refs: Some(child_refs),
                decorator_refs: Some(decorator_refs),
            },
        )?;

        let mut asm_ops = self.statically_linked_mast.debug_info().asm_ops_for_node(source_node_id);
        if let MastNode::Block(block) = &self.statically_linked_mast[source_node_id] {
            asm_ops = BasicBlockNode::unadjust_asm_op_indices(asm_ops, block.op_batches());
        }
        if !asm_ops.is_empty() {
            let mut remapped_asm_ops = Vec::with_capacity(asm_ops.len());
            for (op_idx, asm_op_id) in asm_ops {
                if let Some(asm_op) = self.statically_linked_mast.debug_info().asm_op(asm_op_id) {
                    let new_asm_op_ref = self.add_asm_op_ref(asm_op.clone())?;
                    remapped_asm_ops.push((op_idx, new_asm_op_ref));
                }
            }
            if !remapped_asm_ops.is_empty() {
                self.pending_asm_op_mappings.push((new_node_ref, remapped_asm_ops));
            }
        }

        let debug_vars =
            self.statically_linked_mast.debug_info().debug_vars_for_node(source_node_id);
        if !debug_vars.is_empty() {
            let mut remapped_debug_vars = Vec::with_capacity(debug_vars.len());
            for (op_idx, var_id) in debug_vars {
                if let Some(debug_var) = self.statically_linked_mast.debug_info().debug_var(var_id)
                {
                    let new_var_ref = self.add_debug_var_ref(debug_var.clone())?;
                    remapped_debug_vars.push((op_idx, new_var_ref));
                }
            }
            if !remapped_debug_vars.is_empty() {
                self.pending_debug_var_mappings.push((new_node_ref, remapped_debug_vars));
            }
        }

        Ok(new_node_ref)
    }

    #[cfg(test)]
    fn insert_new_node_ref(
        &mut self,
        builder: impl MastForestContributor,
        fingerprint: MastNodeFingerprint,
        error_context: &'static str,
        refs: PendingNodeRefs,
    ) -> Result<MastNodeRef, Report> {
        let new_node_id = builder
            .add_to_forest(&mut self.mast_forest)
            .into_diagnostic()
            .wrap_err(error_context)?;
        let node_ref = if let Some(&node_ref) = self.node_ref_by_id.get(&new_node_id) {
            let node = self.owned_pending_node(new_node_id);
            self.refresh_node_ref(node_ref, new_node_id, fingerprint, node, refs);
            node_ref
        } else {
            let node = self.owned_pending_node(new_node_id);
            self.push_node_ref(new_node_id, fingerprint, node, refs)?
        };

        self.node_ref_by_fingerprint.insert(fingerprint, node_ref);
        Ok(node_ref)
    }

    fn insert_new_pending_node_ref(
        &mut self,
        builder: MastNodeBuilder,
        fingerprint: MastNodeFingerprint,
        error_context: &'static str,
        refs: PendingNodeRefs,
    ) -> Result<MastNodeRef, Report> {
        let node = builder.build_with_forced_digest().into_diagnostic().wrap_err(error_context)?;
        self.insert_pending_node_ref(node, fingerprint, refs)
    }

    fn insert_pending_node_ref(
        &mut self,
        node: MastNode,
        fingerprint: MastNodeFingerprint,
        refs: PendingNodeRefs,
    ) -> Result<MastNodeRef, Report> {
        let node_id = self.next_pending_node_id()?;
        let node_ref = self.push_node_ref(node_id, fingerprint, node, refs)?;

        self.node_ref_by_fingerprint.insert(fingerprint, node_ref);
        Ok(node_ref)
    }

    fn ensure_node_exists_with_pending_refs(
        &mut self,
        builder: MastNodeBuilder,
        node_fingerprint: MastNodeFingerprint,
        child_refs: Vec<MastNodeRef>,
        decorator_refs: PendingDecoratorRefs,
    ) -> Result<(MastNodeRef, bool), Report> {
        if let Some(node_ref) = self.find_node_ref_by_fingerprint(&node_fingerprint) {
            Ok((node_ref, false))
        } else {
            let new_node_ref = self.insert_new_pending_node_ref(
                builder,
                node_fingerprint,
                "assembler failed to add new node",
                PendingNodeRefs {
                    child_refs: Some(child_refs),
                    decorator_refs: Some(decorator_refs),
                },
            )?;

            Ok((new_node_ref, true))
        }
    }

    /// Adds a basic block node to the forest, and returns the [`MastNodeId`] associated with it.
    ///
    /// The `asm_ops` parameter contains AssemblyOp metadata for operations in this block. Each
    /// entry is `(op_idx, AssemblyOp)` where `op_idx` is the operation index the AssemblyOp
    /// corresponds to.
    ///
    /// The `debug_vars` parameter contains debug variable metadata for operations in this block.
    /// Each entry is `(op_idx, DebugVarRef)` where `op_idx` is the operation index the debug
    /// variable corresponds to.
    ///
    /// Note: AssemblyOps and debug variables are kept external to the block builder but are
    /// included in the dedup fingerprint so that blocks with identical operations but different
    /// metadata are not deduplicated.
    ///
    /// The actual registration of both AssemblyOp and debug variable mappings is deferred until
    /// `build()` is called, to ensure nodes are registered in sequential order as required by
    /// the CSR structure.
    #[cfg(test)]
    pub fn ensure_block(
        &mut self,
        operations: Vec<Operation>,
        decorators: DecoratorList,
        asm_ops: Vec<(usize, AssemblyOp)>,
        debug_vars: Vec<(usize, DebugVarRef)>,
        before_enter: Vec<DecoratorId>,
        after_exit: Vec<DecoratorId>,
    ) -> Result<MastNodeId, Report> {
        let node_ref = self.ensure_block_with_debug_var_refs_in_forest(
            operations,
            decorators,
            asm_ops,
            debug_vars,
            before_enter,
            after_exit,
        )?;
        Ok(self.node_id(node_ref))
    }

    #[cfg(test)]
    fn ensure_block_with_debug_var_refs_in_forest(
        &mut self,
        operations: Vec<Operation>,
        decorators: DecoratorList,
        asm_ops: Vec<(usize, AssemblyOp)>,
        debug_vars: Vec<(usize, DebugVarRef)>,
        before_enter: Vec<DecoratorId>,
        after_exit: Vec<DecoratorId>,
    ) -> Result<MastNodeRef, Report> {
        let block = BasicBlockNodeBuilder::new(operations, decorators)
            .with_before_enter(before_enter)
            .with_after_exit(after_exit);

        // Compute the base fingerprint from the builder, then augment with external metadata
        // so the dedup key stays sensitive to source mappings without storing them on the
        // builder itself.
        let base_fingerprint = self.fingerprint_for_builder(&block);
        let dedup_fingerprint = self.maybe_augment(
            self.maybe_augment(base_fingerprint, &serialize_asm_ops(&asm_ops)),
            &serialize_debug_var_refs(&self.debug_vars, &debug_vars),
        );

        let (node_ref, is_new) =
            if let Some(node_ref) = self.find_node_ref_by_fingerprint(&dedup_fingerprint) {
                (node_ref, false)
            } else {
                let new_node_ref = self.insert_new_node_ref(
                    block,
                    dedup_fingerprint,
                    "assembler failed to add new node",
                    PendingNodeRefs {
                        child_refs: Some(Vec::new()),
                        ..Default::default()
                    },
                )?;
                (new_node_ref, true)
            };

        // Only register AssemblyOps for newly created nodes.
        // Deduplicated nodes already have their asm_ops registered from when they were first added.
        if is_new && !asm_ops.is_empty() {
            let mut asm_op_mappings = Vec::with_capacity(asm_ops.len());
            for (op_idx, asm_op) in asm_ops {
                let asm_op_ref = self.add_asm_op_ref(asm_op)?;
                asm_op_mappings.push((op_idx, asm_op_ref));
            }
            // Defer registration until build() to ensure sequential node order.
            self.pending_asm_op_mappings.push((node_ref, asm_op_mappings));
        }

        // Only register debug variables for newly created nodes.
        // Blocks with different debug vars have different augmented fingerprints,
        // so deduplication only occurs when vars are truly identical.
        if is_new && !debug_vars.is_empty() {
            self.pending_debug_var_mappings.push((node_ref, debug_vars));
        }

        Ok(node_ref)
    }

    fn ensure_block_with_debug_var_refs(
        &mut self,
        operations: Vec<Operation>,
        decorators: DecoratorList,
        asm_ops: Vec<(usize, AssemblyOp)>,
        debug_vars: Vec<(usize, DebugVarRef)>,
        before_enter: Vec<DecoratorId>,
        after_exit: Vec<DecoratorId>,
    ) -> Result<MastNodeRef, Report> {
        let block = BasicBlockNodeBuilder::new(operations, decorators)
            .with_before_enter(before_enter)
            .with_after_exit(after_exit);
        let node = MastNodeBuilder::BasicBlock(block)
            .build_with_forced_digest()
            .into_diagnostic()
            .wrap_err("assembler failed to build new node")?;
        let pending_decorator_refs = self.decorator_refs_for_node(&node);

        let base_fingerprint =
            self.fingerprint_for_pending_node(&node, &[], &pending_decorator_refs);
        let dedup_fingerprint = self.maybe_augment(
            self.maybe_augment(base_fingerprint, &serialize_asm_ops(&asm_ops)),
            &serialize_debug_var_refs(&self.debug_vars, &debug_vars),
        );

        let (node_ref, is_new) =
            if let Some(node_ref) = self.find_node_ref_by_fingerprint(&dedup_fingerprint) {
                (node_ref, false)
            } else {
                let new_node_ref = self.insert_pending_node_ref(
                    node,
                    dedup_fingerprint,
                    PendingNodeRefs {
                        child_refs: Some(Vec::new()),
                        decorator_refs: Some(pending_decorator_refs),
                    },
                )?;
                (new_node_ref, true)
            };

        // Only register AssemblyOps for newly created nodes.
        // Deduplicated nodes already have their asm_ops registered from when they were first added.
        if is_new && !asm_ops.is_empty() {
            let mut asm_op_mappings = Vec::with_capacity(asm_ops.len());
            for (op_idx, asm_op) in asm_ops {
                let asm_op_ref = self.add_asm_op_ref(asm_op)?;
                asm_op_mappings.push((op_idx, asm_op_ref));
            }
            // Defer registration until build() to ensure sequential node order.
            self.pending_asm_op_mappings.push((node_ref, asm_op_mappings));
        }

        // Only register debug variables for newly created nodes.
        // Blocks with different debug vars have different augmented fingerprints,
        // so deduplication only occurs when vars are truly identical.
        if is_new && !debug_vars.is_empty() {
            self.pending_debug_var_mappings.push((node_ref, debug_vars));
        }

        Ok(node_ref)
    }

    /// Adds a basic block node to the forest, and returns its builder-local [`MastNodeRef`].
    pub(crate) fn ensure_block_ref(
        &mut self,
        operations: Vec<Operation>,
        decorators: Vec<(usize, DecoratorRef)>,
        asm_ops: Vec<(usize, AssemblyOp)>,
        debug_vars: Vec<(usize, DebugVarRef)>,
        before_enter: Vec<DecoratorId>,
        after_exit: Vec<DecoratorId>,
    ) -> Result<MastNodeRef, Report> {
        let decorators = decorators
            .into_iter()
            .map(|(op_idx, decorator_ref)| {
                self.pending_decorator_id(decorator_ref)
                    .map(|decorator_id| (op_idx, decorator_id))
            })
            .collect::<Result<DecoratorList, _>>()?;
        self.ensure_block_with_debug_var_refs(
            operations,
            decorators,
            asm_ops,
            debug_vars,
            before_enter,
            after_exit,
        )
    }

    /// Copies all decorators used by a statically linked source node into this builder.
    fn collect_decorators_from_node(
        &mut self,
        node_id: MastNodeId,
        decorator_refs_by_source_id: &mut BTreeMap<DecoratorId, DecoratorRef>,
    ) -> Result<(), Report> {
        let mut decorator_ids = Vec::new();
        decorator_ids.extend(self.statically_linked_mast.before_enter_decorators(node_id));
        decorator_ids.extend(self.statically_linked_mast.after_exit_decorators(node_id));
        if let MastNode::Block(block_node) = &self.statically_linked_mast[node_id] {
            for (_idx, decorator_id) in
                block_node.indexed_decorator_iter(&self.statically_linked_mast)
            {
                decorator_ids.push(decorator_id);
            }
        }

        for old_decorator_id in decorator_ids {
            if let Entry::Vacant(e) = decorator_refs_by_source_id.entry(old_decorator_id) {
                let decorator = self.statically_linked_mast[old_decorator_id].clone();
                let decorator_ref = self.ensure_decorator_ref(decorator)?;
                e.insert(decorator_ref);
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
        &mut self,
        node_id: MastNodeId,
        node: MastNode,
        node_refs_by_source_id: &BTreeMap<MastNodeId, MastNodeRef>,
        decorator_refs_by_source_id: &BTreeMap<DecoratorId, DecoratorRef>,
    ) -> Result<(MastNodeBuilder, Vec<MastNodeRef>, PendingDecoratorRefs), Report> {
        let mut node_remapping = Remapping::new();
        let mut child_refs = Vec::new();
        node.for_each_child(|source_child_id| {
            let child_ref = *node_refs_by_source_id
                .get(&source_child_id)
                .expect("statically linked child must be copied before its parent");
            node_remapping.insert(source_child_id, self.node_id(child_ref));
            child_refs.push(child_ref);
        });

        let mut decorator_remapping = BTreeMap::new();
        let mut decorator_refs = PendingDecoratorRefs::default();
        let before_enter_decorators =
            self.statically_linked_mast.before_enter_decorators(node_id).to_vec();
        for source_decorator_id in before_enter_decorators {
            let decorator_ref = *decorator_refs_by_source_id
                .get(&source_decorator_id)
                .expect("statically linked decorator must be interned before its node");
            decorator_refs.before_enter.push(decorator_ref);
            let target_decorator_id = self.pending_decorator_id(decorator_ref)?;
            decorator_remapping.insert(source_decorator_id, target_decorator_id);
        }
        if let MastNode::Block(block_node) = &node {
            let indexed_decorators: Vec<_> =
                block_node.indexed_decorator_iter(&self.statically_linked_mast).collect();
            for (op_idx, source_decorator_id) in indexed_decorators {
                let decorator_ref = *decorator_refs_by_source_id
                    .get(&source_decorator_id)
                    .expect("statically linked decorator must be interned before its node");
                decorator_refs.indexed.push((op_idx, decorator_ref));
                let target_decorator_id = self.pending_decorator_id(decorator_ref)?;
                decorator_remapping.insert(source_decorator_id, target_decorator_id);
            }
        }
        let after_exit_decorators =
            self.statically_linked_mast.after_exit_decorators(node_id).to_vec();
        for source_decorator_id in after_exit_decorators {
            let decorator_ref = *decorator_refs_by_source_id
                .get(&source_decorator_id)
                .expect("statically linked decorator must be interned before its node");
            decorator_refs.after_exit.push(decorator_ref);
            let target_decorator_id = self.pending_decorator_id(decorator_ref)?;
            decorator_remapping.insert(source_decorator_id, target_decorator_id);
        }

        let builder = miden_core::mast::build_node_with_remapped_ids(
            node_id,
            node,
            &self.statically_linked_mast,
            &node_remapping,
            &decorator_remapping,
        )
        .into_diagnostic()?;
        Ok((builder, child_refs, decorator_refs))
    }

    /// Adds a node corresponding to the given MAST root, according to how it is linked.
    ///
    /// * If statically-linked, then the entire subtree is copied, and the MastNodeId of the root of
    ///   the inserted subtree is returned.
    /// * If dynamically-linked, then an external node is inserted, and its MastNodeId is returned
    ///
    /// Adds a node corresponding to the given MAST root, preferring an exact source root when
    /// provenance from a statically-linked library is available.
    #[cfg(test)]
    pub fn ensure_external_link_with_source(
        &mut self,
        mast_root: Word,
        source_library_commitment: Option<Word>,
        source_root_id: Option<MastNodeId>,
    ) -> Result<MastNodeId, Report> {
        let node_ref = self.ensure_external_link_with_source_ref(
            mast_root,
            source_library_commitment,
            source_root_id,
        )?;
        Ok(self.node_id(node_ref))
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

        let child_refs = Vec::new();
        let decorator_refs = PendingDecoratorRefs::default();
        let fingerprint =
            self.fingerprint_from_pending_refs(mast_root, &child_refs, &decorator_refs);
        if let Some(node_ref) = self.find_node_ref_by_fingerprint(&fingerprint) {
            return Ok(node_ref);
        }

        self.insert_new_pending_node_ref(
            MastNodeBuilder::External(ExternalNodeBuilder::new(mast_root)),
            fingerprint,
            "assembler failed to add new node",
            PendingNodeRefs {
                child_refs: Some(child_refs),
                decorator_refs: Some(decorator_refs),
            },
        )
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
            let exact_root = self
                .statically_linked_forest_indices_by_commitment
                .get(&source_library_commitment)
                .and_then(|forest_idx| {
                    self.statically_linked_root_map.map_root(*forest_idx, &source_root_id)
                });

            if let Some(exact_root) = exact_root
                .filter(|root_id| self.statically_linked_mast[*root_id].digest() == mast_root)
            {
                return Some(exact_root);
            }
        }

        self.statically_linked_mast.find_procedure_root(mast_root)
    }

    /// Copies a subtree from the statically linked forest into the builder's forest.
    fn copy_statically_linked_subtree_ref(
        &mut self,
        root_id: MastNodeId,
    ) -> Result<MastNodeRef, Report> {
        let mut node_refs_by_source_id = BTreeMap::new();
        let mut decorator_refs_by_source_id = BTreeMap::new();

        for old_id in SubtreeIterator::new(&root_id, &self.statically_linked_mast.clone()) {
            self.collect_decorators_from_node(old_id, &mut decorator_refs_by_source_id)?;
            let node = self.statically_linked_mast[old_id].clone();
            let (builder, child_refs, decorator_refs) = self.build_with_remapped_ids(
                old_id,
                node,
                &node_refs_by_source_id,
                &decorator_refs_by_source_id,
            )?;
            let new_ref = self.ensure_node_from_statically_linked_source_ref(
                builder,
                old_id,
                Some(child_refs),
                Some(decorator_refs),
            )?;
            node_refs_by_source_id.insert(old_id, new_ref);
        }
        Ok(*node_refs_by_source_id
            .get(&root_id)
            .expect("statically linked subtree root must be copied"))
    }

    pub(crate) fn append_before_enter_refs(
        &mut self,
        node_ref: MastNodeRef,
        decorator_refs: Vec<DecoratorRef>,
    ) -> Result<MastNodeRef, Report> {
        let decorator_ids = self.pending_decorator_ids(decorator_refs.iter().copied())?;
        let mut pending_decorator_refs = self.nodes[node_ref].decorator_refs.clone();
        pending_decorator_refs.before_enter.extend(decorator_refs);
        let child_refs = self.nodes[node_ref].child_refs.clone();
        let base_fingerprint = self.fingerprint_for_pending_node(
            &self.nodes[node_ref].node,
            &child_refs,
            &pending_decorator_refs,
        );
        let empty_forest = MastForest::new();
        let mut decorated_builder = self.nodes[node_ref].node.clone().to_builder(&empty_forest);
        decorated_builder.append_before_enter(decorator_ids);

        self.ensure_node_preserving_debug_vars_ref_with_fingerprint(
            decorated_builder,
            base_fingerprint,
            node_ref,
            PendingNodeRefs {
                child_refs: Some(child_refs),
                decorator_refs: Some(pending_decorator_refs),
            },
        )
    }

    pub(crate) fn append_after_exit_refs(
        &mut self,
        node_ref: MastNodeRef,
        decorator_refs: Vec<DecoratorRef>,
    ) -> Result<MastNodeRef, Report> {
        let decorator_ids = self.pending_decorator_ids(decorator_refs.iter().copied())?;
        let mut pending_decorator_refs = self.nodes[node_ref].decorator_refs.clone();
        pending_decorator_refs.after_exit.extend(decorator_refs);
        let child_refs = self.nodes[node_ref].child_refs.clone();
        let base_fingerprint = self.fingerprint_for_pending_node(
            &self.nodes[node_ref].node,
            &child_refs,
            &pending_decorator_refs,
        );
        let empty_forest = MastForest::new();
        let mut decorated_builder = self.nodes[node_ref].node.clone().to_builder(&empty_forest);
        decorated_builder.append_after_exit(decorator_ids);

        self.ensure_node_preserving_debug_vars_ref_with_fingerprint(
            decorated_builder,
            base_fingerprint,
            node_ref,
            PendingNodeRefs {
                child_refs: Some(child_refs),
                decorator_refs: Some(pending_decorator_refs),
            },
        )
    }
}

impl MastForestBuilder {
    /// Registers an error message in the MAST Forest and returns the
    /// corresponding error code as a Felt.
    pub fn register_error(&mut self, msg: Arc<str>) -> Felt {
        let code = error_code_from_msg(&msg);
        self.error_codes.insert(code.as_canonical_u64(), msg);
        code
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
        self.advice_map
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
    use miden_core::{mast::CallNodeBuilder, operations::Operation};

    use super::*;

    fn record_test_root(builder: &mut MastForestBuilder, node_id: MastNodeId) -> MastNodeRef {
        let node_ref = builder.node_ref(node_id).unwrap();
        builder.record_procedure_root_ref(node_ref);
        node_ref
    }

    fn test_word(value: u64) -> Word {
        Word::from([Felt::new_unchecked(value), Felt::ZERO, Felt::ZERO, Felt::ZERO])
    }

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
            Operation::Push(Felt::new_unchecked(1)),
            Operation::Drop,
            Operation::Drop,
            Operation::Drop,
            Operation::Drop,
            Operation::Drop,
            Operation::Drop,
            Operation::Push(Felt::new_unchecked(2)),
            Operation::Push(Felt::new_unchecked(3)),
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
            .ensure_block(block1_ops, block1_decorators, vec![], vec![], vec![], vec![])
            .unwrap();

        // Sanity check the test itself makes sense
        let block1 = builder.pending_node(block1_id).get_basic_block().unwrap().clone();
        assert!(block1.operations().count() > block1_raw_ops_len); // this indeed generates padding, and thus a potential off-by-one
        assert_eq!(block1.raw_operations().count(), block1_raw_ops_len); // merging, which uses raw_ops, will elide padding

        // Create second block with operations
        // Block2: [Push(4), Mul]
        let block2_ops = vec![Operation::Push(Felt::new_unchecked(4)), Operation::Mul];

        // Add decorators for each operation in block2
        let block2_decorator1 = builder.ensure_decorator(Decorator::Trace(4)).unwrap();
        let block2_decorator2 = builder.ensure_decorator(Decorator::Trace(5)).unwrap();
        let block2_decorators = vec![
            (0, block2_decorator1), // Decorator for Push(4)
            (1, block2_decorator2), // Decorator for Mul
        ]; // [push mul] [3]

        let block2_id = builder
            .ensure_block(block2_ops, block2_decorators, vec![], vec![], vec![], vec![])
            .unwrap();

        // Merge the blocks
        let merged_blocks = builder.merge_basic_blocks(&[block1_id, block2_id]).unwrap();

        // There should be one merged block
        assert_eq!(merged_blocks.len(), 1);
        let merged_block_id = merged_blocks[0];

        let merged_block = builder.pending_node(merged_block_id).get_basic_block().unwrap();

        // Merged block: two groups
        // [push drop drop drop drop drop drop push noop] [1] [2] [push push mul] [3] [4] [noop]
        // [noop]

        // Build mapping: original operation index -> decorator trace value
        // For block1: operation 0 -> Trace(1), operation 7 -> Trace(2), operation 9 -> Trace(3)
        // For block2: operation 0 -> Trace(4), operation 1 -> Trace(5)

        // Check each decorator in the merged block
        let empty_forest = MastForest::new();
        let decorators = merged_block.indexed_decorator_iter(&empty_forest);
        let decorator_count = merged_block.indexed_decorator_iter(&empty_forest).count();

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
                                    Operation::Push(x) if *x == Felt::new_unchecked(1) => {
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
                                    Operation::Push(x) if *x == Felt::new_unchecked(2) => {
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
                                    Operation::Push(x) if *x == Felt::new_unchecked(3) => {
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
                                    Operation::Push(x) if *x == Felt::new_unchecked(4) => {
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
                        panic!("Operation index {op_idx} is out of bounds");
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
                "Missing trace value: {expected_trace}"
            );
        }

        // Verify we found exactly 5 trace values
        assert_eq!(found_traces.len(), 5, "Should have found exactly 5 trace values");
    }

    #[test]
    fn test_merge_basic_blocks_keeps_non_mergeable_block_standalone() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let num_ops = PROCEDURE_INLINING_THRESHOLD * 1024;
        let large_ops = vec![Operation::Add; num_ops];
        let large_block_id = builder
            .ensure_block(large_ops, Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();
        record_test_root(&mut builder, large_block_id);

        let small_block_id = builder
            .ensure_block(vec![Operation::Add], Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();

        let merged_blocks = builder.merge_basic_blocks(&[large_block_id, small_block_id]).unwrap();

        assert_eq!(merged_blocks.len(), 2);
        assert_eq!(merged_blocks[0], large_block_id);
        assert_eq!(merged_blocks[1], small_block_id);
    }

    #[test]
    fn test_merge_basic_blocks_preserves_trailing_after_exit_decorator() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let first_block_id = builder
            .ensure_block(vec![Operation::Add], Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();
        let after_exit_decorator = builder.ensure_decorator(Decorator::Trace(7)).unwrap();
        let second_block_id = builder
            .ensure_block(
                vec![Operation::Mul],
                Vec::new(),
                vec![],
                vec![],
                vec![],
                vec![after_exit_decorator],
            )
            .unwrap();

        let merged_blocks = builder.merge_basic_blocks(&[first_block_id, second_block_id]).unwrap();

        assert_eq!(merged_blocks.len(), 1);
        let merged_block_id = merged_blocks[0];
        let merged_block = builder.mast_forest[merged_block_id].unwrap_basic_block();

        assert!(merged_block.indexed_decorator_iter(&builder.mast_forest).next().is_none());
        assert_eq!(
            builder.mast_forest.after_exit_decorators(merged_block_id),
            &[after_exit_decorator],
        );
    }

    #[test]
    fn test_merge_basic_blocks_places_boundary_after_exit_before_next_before_enter() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let first_after_exit = builder.ensure_decorator(Decorator::Trace(1)).unwrap();
        let first_block_id = builder
            .ensure_block(
                vec![Operation::Add],
                Vec::new(),
                vec![],
                vec![],
                vec![],
                vec![first_after_exit],
            )
            .unwrap();

        let second_before_enter = builder.ensure_decorator(Decorator::Trace(2)).unwrap();
        let second_block_id = builder
            .ensure_block(
                vec![Operation::Mul],
                Vec::new(),
                vec![],
                vec![],
                vec![second_before_enter],
                vec![],
            )
            .unwrap();

        let merged_blocks = builder.merge_basic_blocks(&[first_block_id, second_block_id]).unwrap();

        assert_eq!(merged_blocks.len(), 1);
        let merged_block_id = merged_blocks[0];
        let merged_block = builder.mast_forest[merged_block_id].unwrap_basic_block();
        let decorators: Vec<_> =
            merged_block.indexed_decorator_iter(&builder.mast_forest).collect();

        assert_eq!(decorators, vec![(1, first_after_exit), (1, second_before_enter)]);
        assert!(builder.mast_forest.after_exit_decorators(merged_block_id).is_empty());
    }

    #[test]
    fn ensure_block_rejects_decorator_index_beyond_operation_count_without_panicking() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();
        let decorator_id = builder.ensure_decorator(Decorator::Trace(42)).unwrap();

        let result = builder.ensure_block(
            vec![Operation::Add],
            vec![(2, decorator_id)],
            vec![],
            vec![],
            vec![],
            vec![],
        );

        assert!(result.is_err());
    }

    #[test]
    fn ensure_block_rejects_post_last_decorator_index_without_panicking() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();
        let decorator_id = builder.ensure_decorator(Decorator::Trace(42)).unwrap();

        let result = builder.ensure_block(
            vec![Operation::Add],
            vec![(1, decorator_id)],
            vec![],
            vec![],
            vec![],
            vec![],
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_build_keeps_existing_forest_root_after_merge() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let root_block_id = builder
            .ensure_block(vec![Operation::Add], Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();
        let root_block_ref = record_test_root(&mut builder, root_block_id);
        let root_digest = builder.pending_node(root_block_id).digest();

        let tail_block_id = builder
            .ensure_block(vec![Operation::Mul], Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();

        let merged_blocks = builder.merge_basic_blocks(&[root_block_id, tail_block_id]).unwrap();
        assert_eq!(merged_blocks.len(), 1);
        assert_ne!(merged_blocks[0], root_block_id);

        let (forest, remapping) = builder.build().into_parts();
        let final_root_id = remapping[&root_block_ref];

        assert!(forest.is_procedure_root(final_root_id));
        assert_eq!(forest[final_root_id].digest(), root_digest);
    }

    #[test]
    fn test_build_orders_external_nodes_before_non_external_nodes() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let block_id = builder
            .ensure_block(vec![Operation::Add], Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();
        record_test_root(&mut builder, block_id);

        let external_a =
            builder.ensure_external_link_with_source_ref(test_word(2), None, None).unwrap();
        let external_b =
            builder.ensure_external_link_with_source_ref(test_word(1), None, None).unwrap();
        builder.record_procedure_root_ref(external_a);
        builder.record_procedure_root_ref(external_b);

        let mut expected_external_refs = [
            (external_a, builder.nodes[external_a].fingerprint),
            (external_b, builder.nodes[external_b].fingerprint),
        ];
        expected_external_refs.sort_by_key(|(_, fingerprint)| *fingerprint);

        let (forest, remapping) = builder.build().into_parts();

        assert_eq!(remapping[&expected_external_refs[0].0], MastNodeId::new_unchecked(0));
        assert_eq!(remapping[&expected_external_refs[1].0], MastNodeId::new_unchecked(1));
        assert!(forest[MastNodeId::new_unchecked(0)].is_external());
        assert!(forest[MastNodeId::new_unchecked(1)].is_external());
    }

    #[test]
    fn test_build_preserves_multiple_control_decorators() {
        fn before_enter_traces(forest: &MastForest, node_id: MastNodeId) -> Vec<u32> {
            forest
                .before_enter_decorators(node_id)
                .iter()
                .map(|&decorator_id| match forest[decorator_id] {
                    Decorator::Trace(trace_id) => trace_id,
                    ref decorator => panic!("expected trace decorator, got {decorator:?}"),
                })
                .collect()
        }

        fn after_exit_traces(forest: &MastForest, node_id: MastNodeId) -> Vec<u32> {
            forest
                .after_exit_decorators(node_id)
                .iter()
                .map(|&decorator_id| match forest[decorator_id] {
                    Decorator::Trace(trace_id) => trace_id,
                    ref decorator => panic!("expected trace decorator, got {decorator:?}"),
                })
                .collect()
        }

        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let true_id = builder
            .ensure_block(vec![Operation::Add], Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();
        let false_id = builder
            .ensure_block(vec![Operation::Mul], Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();
        let true_ref = builder.node_ref(true_id).unwrap();
        let false_ref = builder.node_ref(false_id).unwrap();

        let first_decorator_ref = builder.ensure_decorator_ref(Decorator::Trace(10)).unwrap();
        let second_decorator_ref = builder.ensure_decorator_ref(Decorator::Trace(20)).unwrap();
        let third_decorator_ref = builder.ensure_decorator_ref(Decorator::Trace(30)).unwrap();
        let decorator_refs = vec![first_decorator_ref, second_decorator_ref];

        let split_ref = builder
            .ensure_split_node_ref(
                [true_ref, false_ref],
                Some(decorator_refs.clone()),
                AssemblyOp::new(None, "test".into(), 1, "if.true".into()),
            )
            .unwrap();
        let split_ref =
            builder.append_after_exit_refs(split_ref, vec![third_decorator_ref]).unwrap();
        builder.record_procedure_root_ref(split_ref);

        let loop_ref = builder
            .ensure_loop_node_ref(
                true_ref,
                Some(decorator_refs),
                AssemblyOp::new(None, "test".into(), 1, "while.true".into()),
            )
            .unwrap();
        let loop_ref =
            builder.append_before_enter_refs(loop_ref, vec![third_decorator_ref]).unwrap();
        builder.record_procedure_root_ref(loop_ref);

        let (forest, remapping) = builder.build().into_parts();

        assert_eq!(before_enter_traces(&forest, remapping[&split_ref]), vec![10, 20]);
        assert_eq!(after_exit_traces(&forest, remapping[&split_ref]), vec![30]);
        assert_eq!(before_enter_traces(&forest, remapping[&loop_ref]), vec![10, 20, 30]);
    }

    #[test]
    fn test_merge_basic_blocks_keeps_recorded_root_block_standalone() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let num_ops = PROCEDURE_INLINING_THRESHOLD * 1024;
        let large_ops = vec![Operation::Add; num_ops];
        let large_block_id = builder
            .ensure_block(large_ops, Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();
        let large_block_ref = builder.node_ref(large_block_id).unwrap();
        builder.record_procedure_root_ref(large_block_ref);

        let small_block_id = builder
            .ensure_block(vec![Operation::Add], Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();

        let merged_blocks = builder.merge_basic_blocks(&[large_block_id, small_block_id]).unwrap();

        assert_eq!(merged_blocks.len(), 2);
        assert_eq!(merged_blocks[0], large_block_id);
        assert_eq!(merged_blocks[1], small_block_id);
    }

    /// Cloning a block with debug vars via `to_builder().with_before_enter()` must
    /// propagate those vars to the new node (exercises the assembler repeat path).
    #[test]
    fn test_ensure_node_preserving_debug_vars_on_cloned_block() {
        use miden_core::operations::{DebugVarInfo, DebugVarLocation};

        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let var_ref = builder
            .add_debug_var_ref(DebugVarInfo::new("x", DebugVarLocation::Stack(0)))
            .unwrap();

        let block_id = builder
            .ensure_block(
                vec![Operation::Add],
                Vec::new(),
                vec![],
                vec![(0, var_ref)],
                vec![],
                vec![],
            )
            .unwrap();

        let decorator_id = builder.ensure_decorator(Decorator::Trace(42)).unwrap();

        // Simulate the repeat path: clone + add before_enter + preserve debug vars.
        let empty_forest = MastForest::new();
        let rebuilt_builder = builder
            .pending_node(block_id)
            .clone()
            .to_builder(&empty_forest)
            .with_before_enter(vec![decorator_id]);
        let cloned_id =
            builder.ensure_node_preserving_debug_vars(rebuilt_builder, block_id).unwrap();

        assert_ne!(cloned_id, block_id);

        let block_ref = builder.node_ref(block_id).unwrap();
        let cloned_ref = builder.node_ref(cloned_id).unwrap();
        let (forest, remapping) = builder.build().into_parts();
        let final_block_id = remapping[&block_ref];
        let final_cloned_id = remapping[&cloned_ref];

        let cloned_vars = forest.debug_info().debug_vars_for_node(final_cloned_id);
        assert_eq!(cloned_vars.len(), 1, "cloned node should have debug vars");
        assert_eq!(forest.debug_info().debug_var(cloned_vars[0].1).unwrap().name(), "x");

        let original_vars = forest.debug_info().debug_vars_for_node(final_block_id);
        assert_eq!(original_vars.len(), 1, "original should keep its debug vars");
        assert_eq!(forest.debug_info().debug_var(original_vars[0].1).unwrap().name(), "x");
    }

    /// Same-ops blocks with different debug vars must not alias after clone + before_enter.
    #[test]
    fn test_ensure_node_preserving_debug_vars_prevents_aliasing() {
        use miden_core::operations::{DebugVarInfo, DebugVarLocation};

        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let var_x_ref = builder
            .add_debug_var_ref(DebugVarInfo::new("x", DebugVarLocation::Stack(0)))
            .unwrap();
        let var_y_ref = builder
            .add_debug_var_ref(DebugVarInfo::new("y", DebugVarLocation::Stack(1)))
            .unwrap();

        // Same ops, different debug vars -- should not dedup.
        let block_a = builder
            .ensure_block(
                vec![Operation::Add],
                Vec::new(),
                vec![],
                vec![(0, var_x_ref)],
                vec![],
                vec![],
            )
            .unwrap();
        let block_b = builder
            .ensure_block(
                vec![Operation::Add],
                Vec::new(),
                vec![],
                vec![(0, var_y_ref)],
                vec![],
                vec![],
            )
            .unwrap();

        assert_ne!(block_a, block_b);

        let decorator_id = builder.ensure_decorator(Decorator::Trace(1)).unwrap();

        let empty_forest = MastForest::new();
        let rebuilt_a = builder
            .pending_node(block_a)
            .clone()
            .to_builder(&empty_forest)
            .with_before_enter(vec![decorator_id]);
        let cloned_a = builder.ensure_node_preserving_debug_vars(rebuilt_a, block_a).unwrap();

        let rebuilt_b = builder
            .pending_node(block_b)
            .clone()
            .to_builder(&empty_forest)
            .with_before_enter(vec![decorator_id]);
        let cloned_b = builder.ensure_node_preserving_debug_vars(rebuilt_b, block_b).unwrap();

        assert_ne!(cloned_a, cloned_b, "different debug vars must prevent dedup");

        let cloned_a_ref = builder.node_ref(cloned_a).unwrap();
        let cloned_b_ref = builder.node_ref(cloned_b).unwrap();
        let (forest, remapping) = builder.build().into_parts();
        let final_cloned_a = remapping[&cloned_a_ref];
        let final_cloned_b = remapping[&cloned_b_ref];
        let vars_a = forest.debug_info().debug_vars_for_node(final_cloned_a);
        let vars_b = forest.debug_info().debug_vars_for_node(final_cloned_b);

        assert_eq!(vars_a.len(), 1);
        assert_eq!(forest.debug_info().debug_var(vars_a[0].1).unwrap().name(), "x");
        assert_eq!(vars_b.len(), 1);
        assert_eq!(forest.debug_info().debug_var(vars_b[0].1).unwrap().name(), "y");
    }

    /// Same-content debug vars should not prevent block dedup just because they
    /// were allocated different builder refs.
    #[test]
    fn test_ensure_block_dedups_identical_debug_var_payloads() {
        use miden_core::operations::{DebugVarInfo, DebugVarLocation};

        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let var_a = builder
            .add_debug_var_ref(DebugVarInfo::new("x", DebugVarLocation::Stack(0)))
            .unwrap();
        let var_b = builder
            .add_debug_var_ref(DebugVarInfo::new("x", DebugVarLocation::Stack(0)))
            .unwrap();

        let block_a = builder
            .ensure_block(
                vec![Operation::Add],
                Vec::new(),
                vec![],
                vec![(0, var_a)],
                vec![],
                vec![],
            )
            .unwrap();
        let block_b = builder
            .ensure_block(
                vec![Operation::Add],
                Vec::new(),
                vec![],
                vec![(0, var_b)],
                vec![],
                vec![],
            )
            .unwrap();

        assert_eq!(
            block_a, block_b,
            "same op stream plus same DebugVarInfo payload should dedup to one node"
        );
    }

    #[test]
    fn test_build_assigns_final_debug_var_ids_to_used_refs() {
        use miden_core::operations::{DebugVarInfo, DebugVarLocation};

        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let _unused_var = builder
            .add_debug_var_ref(DebugVarInfo::new("unused", DebugVarLocation::Stack(0)))
            .unwrap();
        let used_var = builder
            .add_debug_var_ref(DebugVarInfo::new("used", DebugVarLocation::Stack(1)))
            .unwrap();
        let block = builder
            .ensure_block(
                vec![Operation::Add],
                Vec::new(),
                vec![],
                vec![(0, used_var)],
                vec![],
                vec![],
            )
            .unwrap();

        let block_ref = builder.node_ref(block).unwrap();
        let (forest, remapping) = builder.build().into_parts();
        let final_block_id = remapping[&block_ref];
        let vars = forest.debug_info().debug_vars_for_node(final_block_id);

        assert_eq!(forest.debug_info().num_debug_vars(), 1);
        assert_eq!(vars.len(), 1);
        assert_eq!(forest.debug_info().debug_var(vars[0].1).unwrap().name(), "used");
    }

    /// Same-ops blocks with different AssemblyOps must not alias during assembly.
    #[test]
    fn test_ensure_block_keeps_different_asm_ops_distinct() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let block_a = builder
            .ensure_block(
                vec![Operation::Add],
                Vec::new(),
                vec![(0, AssemblyOp::new(None, "ctx_a".into(), 1, "add".into()))],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();
        let block_b = builder
            .ensure_block(
                vec![Operation::Add],
                Vec::new(),
                vec![(0, AssemblyOp::new(None, "ctx_b".into(), 1, "add".into()))],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();

        assert_ne!(
            block_a, block_b,
            "same op stream plus different AssemblyOp payload must not dedup"
        );

        let block_a_ref = builder.node_ref(block_a).unwrap();
        let block_b_ref = builder.node_ref(block_b).unwrap();
        let (forest, remapping) = builder.build().into_parts();
        let final_block_a = remapping[&block_a_ref];
        let final_block_b = remapping[&block_b_ref];
        assert_eq!(
            forest.debug_info().first_asm_op_for_node(final_block_a).unwrap().context_name(),
            "ctx_a"
        );
        assert_eq!(
            forest.debug_info().first_asm_op_for_node(final_block_b).unwrap().context_name(),
            "ctx_b"
        );
    }

    /// Non-block nodes with different AssemblyOps must not alias during assembly.
    #[test]
    fn test_non_block_nodes_keep_different_asm_ops_distinct() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let callee = builder
            .ensure_block(vec![Operation::Add], Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();
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

        assert_ne!(
            call_a, call_b,
            "same-structure non-block nodes with different AssemblyOps must not dedup"
        );

        let call_a_ref = builder.node_ref(call_a).unwrap();
        let call_b_ref = builder.node_ref(call_b).unwrap();
        let (forest, remapping) = builder.build().into_parts();
        let final_call_a = remapping[&call_a_ref];
        let final_call_b = remapping[&call_b_ref];
        assert_eq!(
            forest.debug_info().first_asm_op_for_node(final_call_a).unwrap().context_name(),
            "ctx_a"
        );
        assert_eq!(
            forest.debug_info().first_asm_op_for_node(final_call_b).unwrap().context_name(),
            "ctx_b"
        );
    }

    /// Cloning a block with AssemblyOps via `to_builder().with_before_enter()` must
    /// preserve those asm ops on the new node.
    #[test]
    fn test_ensure_node_preserving_debug_vars_on_cloned_block_keeps_asm_ops() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let block_id = builder
            .ensure_block(
                vec![Operation::Add],
                Vec::new(),
                vec![(0, AssemblyOp::new(None, "ctx".into(), 1, "add".into()))],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();

        let decorator_id = builder.ensure_decorator(Decorator::Trace(7)).unwrap();

        let empty_forest = MastForest::new();
        let rebuilt_builder = builder
            .pending_node(block_id)
            .clone()
            .to_builder(&empty_forest)
            .with_before_enter(vec![decorator_id]);
        let cloned_id =
            builder.ensure_node_preserving_debug_vars(rebuilt_builder, block_id).unwrap();

        assert_ne!(cloned_id, block_id);

        let block_ref = builder.node_ref(block_id).unwrap();
        let cloned_ref = builder.node_ref(cloned_id).unwrap();
        let (forest, remapping) = builder.build().into_parts();
        let final_block_id = remapping[&block_ref];
        let final_cloned_id = remapping[&cloned_ref];

        assert_eq!(
            forest
                .debug_info()
                .first_asm_op_for_node(final_cloned_id)
                .unwrap()
                .context_name(),
            "ctx"
        );
        assert_eq!(
            forest
                .debug_info()
                .first_asm_op_for_node(final_block_id)
                .unwrap()
                .context_name(),
            "ctx"
        );
    }

    /// Statically linked nodes must keep source metadata in the dedup fingerprint so copied
    /// nodes do not alias local nodes with different source mappings.
    #[test]
    fn test_statically_linked_nodes_preserve_metadata_in_dedup() {
        use miden_core::operations::{DebugVarInfo, DebugVarLocation};

        let mut static_forest = MastForest::new();
        let static_asm_op_id = static_forest
            .debug_info_mut()
            .add_asm_op(AssemblyOp::new(None, "lib_ctx".into(), 1, "add".into()))
            .unwrap();
        let static_var_id = static_forest
            .add_debug_var(DebugVarInfo::new("x", DebugVarLocation::Stack(0)))
            .unwrap();
        let static_block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
            .add_to_forest(&mut static_forest)
            .unwrap();
        static_forest
            .debug_info_mut()
            .register_asm_ops(static_block_id, 1, vec![(0, static_asm_op_id)])
            .unwrap();
        static_forest
            .debug_info_mut()
            .register_op_indexed_debug_vars(static_block_id, vec![(0, static_var_id)])
            .unwrap();
        static_forest.make_root(static_block_id);

        let mut builder = MastForestBuilder::new([&static_forest]).unwrap();
        let copied_block_id = builder
            .ensure_external_link_with_source(static_forest[static_block_id].digest(), None, None)
            .unwrap();

        let local_var_ref = builder
            .add_debug_var_ref(DebugVarInfo::new("y", DebugVarLocation::Stack(1)))
            .unwrap();
        let local_block_id = builder
            .ensure_block(
                vec![Operation::Add],
                Vec::new(),
                vec![(0, AssemblyOp::new(None, "local_ctx".into(), 1, "add".into()))],
                vec![(0, local_var_ref)],
                vec![],
                vec![],
            )
            .unwrap();

        assert_ne!(
            copied_block_id, local_block_id,
            "statically linked nodes must not alias local nodes with different metadata"
        );

        let copied_block_ref = builder.node_ref(copied_block_id).unwrap();
        let local_block_ref = builder.node_ref(local_block_id).unwrap();
        let (forest, remapping) = builder.build().into_parts();
        let final_copied_block_id = remapping[&copied_block_ref];
        let final_local_block_id = remapping[&local_block_ref];
        assert_eq!(
            forest
                .debug_info()
                .first_asm_op_for_node(final_copied_block_id)
                .unwrap()
                .context_name(),
            "lib_ctx"
        );
        assert_eq!(
            forest
                .debug_info()
                .first_asm_op_for_node(final_local_block_id)
                .unwrap()
                .context_name(),
            "local_ctx"
        );

        let copied_vars = forest.debug_info().debug_vars_for_node(final_copied_block_id);
        let local_vars = forest.debug_info().debug_vars_for_node(final_local_block_id);
        assert_eq!(forest.debug_info().debug_var(copied_vars[0].1).unwrap().name(), "x");
        assert_eq!(forest.debug_info().debug_var(local_vars[0].1).unwrap().name(), "y");
    }

    #[test]
    fn test_statically_linked_padded_block_dedups_with_equivalent_local_block() {
        let mut source_builder = MastForestBuilder::new(&[]).unwrap();
        let ops = vec![
            Operation::Push(Felt::from_u32(1)),
            Operation::Drop,
            Operation::Drop,
            Operation::Drop,
            Operation::Drop,
            Operation::Drop,
            Operation::Drop,
            Operation::Push(Felt::from_u32(2)),
            Operation::Push(Felt::from_u32(3)),
        ];
        let asm_op = AssemblyOp::new(None, "padded_ctx".into(), 1, "push.3".into());

        let static_block = source_builder
            .ensure_block(
                ops.clone(),
                Vec::new(),
                vec![(8, asm_op.clone())],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();
        let static_block_ref = record_test_root(&mut source_builder, static_block);

        let (static_forest, source_remapping) = source_builder.build().into_parts();
        let final_static_block = source_remapping[&static_block_ref];
        let expected_padded_idx =
            static_forest.debug_info().asm_ops_for_node(final_static_block)[0].0;

        let mut builder = MastForestBuilder::new([&static_forest]).unwrap();
        let copied_block_id = builder
            .ensure_external_link_with_source(
                static_forest[final_static_block].digest(),
                None,
                None,
            )
            .unwrap();
        let copied_block_ref = builder.node_ref(copied_block_id).unwrap();
        let local_block_id = builder
            .ensure_block(ops, Vec::new(), vec![(8, asm_op)], vec![], vec![], vec![])
            .unwrap();

        assert_eq!(
            copied_block_id, local_block_id,
            "copied padded blocks should dedup with equivalent local blocks",
        );

        let (forest, remapping) = builder.build().into_parts();
        let final_block_id = remapping.get(&copied_block_ref).copied().unwrap_or(copied_block_id);

        assert!(
            forest
                .debug_info()
                .asm_op_for_operation(final_block_id, expected_padded_idx - 1)
                .is_none(),
            "the asm op must not be attached before its padded operation index",
        );
        assert_eq!(
            forest
                .debug_info()
                .asm_op_for_operation(final_block_id, expected_padded_idx)
                .unwrap()
                .context_name(),
            "padded_ctx",
        );
    }

    /// A small procedure root that gets merged into a larger block must keep its own
    /// debug vars and asm ops, since the root node survives removal.
    #[test]
    fn test_merged_root_block_keeps_metadata() {
        use miden_core::operations::{AssemblyOp, DebugVarInfo, DebugVarLocation};

        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let var_ref = builder
            .add_debug_var_ref(DebugVarInfo::new("x", DebugVarLocation::Stack(0)))
            .unwrap();
        let asm_op = AssemblyOp::new(None, "test".into(), 1, "add".into());

        // Small block that will be a procedure root -- should_merge returns true for
        // small roots, so it will be folded into the merged block.
        let root_block = builder
            .ensure_block(
                vec![Operation::Add],
                Vec::new(),
                vec![(0, asm_op)],
                vec![(0, var_ref)],
                vec![],
                vec![],
            )
            .unwrap();
        let root_block_ref = record_test_root(&mut builder, root_block);

        // Second block to merge with.
        let other_block = builder
            .ensure_block(vec![Operation::Mul], Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();

        let merged = builder.merge_basic_blocks(&[root_block, other_block]).unwrap();
        // Root was small enough to merge, so we get one merged block.
        assert_eq!(merged.len(), 1);
        let merged_id = merged[0];
        assert_ne!(merged_id, root_block);

        let (forest, remapping) = builder.build().into_parts();

        // The root block survives removal (it's a procedure root).
        let final_root_id = remapping.get(&root_block_ref).copied().unwrap_or(root_block);
        assert!(forest.is_procedure_root(final_root_id), "root should survive");

        // Root block must still have its debug vars.
        let root_vars = forest.debug_info().debug_vars_for_node(final_root_id);
        assert_eq!(root_vars.len(), 1, "root must keep its debug vars after merge");
        assert_eq!(forest.debug_info().debug_var(root_vars[0].1).unwrap().name(), "x");

        // Root block must still have its asm op.
        let root_asm = forest.debug_info().first_asm_op_for_node(final_root_id);
        assert!(root_asm.is_some(), "root must keep its asm op after merge");
    }

    /// Two same-digest roots with different asm ops stay distinct when
    /// linked by exact node ID.
    #[test]
    fn test_static_link_exact_node_preserves_alias_metadata() {
        let mut source_builder = MastForestBuilder::new(&[]).unwrap();

        let alias_a = source_builder
            .ensure_block(
                vec![Operation::Add],
                Vec::new(),
                vec![(0, AssemblyOp::new(None, "alias_a".into(), 1, "add".into()))],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();
        let alias_b = source_builder
            .ensure_block(
                vec![Operation::Add],
                Vec::new(),
                vec![(0, AssemblyOp::new(None, "alias_b".into(), 1, "add".into()))],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();
        let alias_a_ref = record_test_root(&mut source_builder, alias_a);
        let alias_b_ref = record_test_root(&mut source_builder, alias_b);

        let (static_forest, source_remapping) = source_builder.build().into_parts();
        let final_alias_a = source_remapping[&alias_a_ref];
        let final_alias_b = source_remapping[&alias_b_ref];
        assert_eq!(static_forest[final_alias_a].digest(), static_forest[final_alias_b].digest());

        // Exact path via internal API — gets alias_b's metadata.
        let mut exact_builder = MastForestBuilder::new([&static_forest]).unwrap();
        let exact_alias_b = {
            let node = exact_builder.statically_linked_mast[final_alias_b].clone();
            let node_refs_by_source_id = BTreeMap::new();
            let decorator_refs_by_source_id = BTreeMap::new();
            let (builder, _child_refs, _decorator_refs) = exact_builder
                .build_with_remapped_ids(
                    final_alias_b,
                    node,
                    &node_refs_by_source_id,
                    &decorator_refs_by_source_id,
                )
                .unwrap();
            exact_builder
                .ensure_node_from_statically_linked_source(builder, final_alias_b)
                .unwrap()
        };
        let exact_alias_b_ref = exact_builder.node_ref(exact_alias_b).unwrap();
        let (exact_forest, exact_remapping) = exact_builder.build().into_parts();
        let final_exact_alias_b = exact_remapping[&exact_alias_b_ref];
        assert_eq!(
            exact_forest
                .debug_info()
                .first_asm_op_for_node(final_exact_alias_b)
                .unwrap()
                .context_name(),
            "alias_b"
        );
    }

    /// Digest-based linking imports only the selected alias, not all
    /// same-digest roots. The unselected alias must not leak into the forest.
    #[test]
    fn test_static_link_by_digest_imports_only_selected_alias() {
        let mut source_builder = MastForestBuilder::new(&[]).unwrap();

        let alias_a = source_builder
            .ensure_block(
                vec![Operation::Add],
                Vec::new(),
                vec![(0, AssemblyOp::new(None, "alias_a".into(), 1, "add".into()))],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();
        let alias_b = source_builder
            .ensure_block(
                vec![Operation::Add],
                Vec::new(),
                vec![(0, AssemblyOp::new(None, "alias_b".into(), 1, "add".into()))],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();
        let alias_a_ref = record_test_root(&mut source_builder, alias_a);
        record_test_root(&mut source_builder, alias_b);

        let (static_forest, source_remapping) = source_builder.build().into_parts();
        let final_alias_a = source_remapping[&alias_a_ref];

        let mut builder = MastForestBuilder::new([&static_forest]).unwrap();
        let linked = builder
            .ensure_external_link_with_source(static_forest[final_alias_a].digest(), None, None)
            .unwrap();
        let linked_ref = record_test_root(&mut builder, linked);
        let (forest, remapping) = builder.build().into_parts();
        let final_linked = remapping[&linked_ref];

        // Only one node should be in the forest — the selected alias.
        assert_eq!(forest.num_nodes(), 1, "only the selected alias should be imported");
        assert_eq!(
            forest.debug_info().first_asm_op_for_node(final_linked).unwrap().context_name(),
            "alias_a",
        );
    }

    #[test]
    fn test_static_link_preserves_decorated_subtree() {
        fn trace_values<'a>(
            forest: &'a MastForest,
            decorator_ids: impl IntoIterator<Item = &'a DecoratorId>,
        ) -> Vec<u32> {
            decorator_ids
                .into_iter()
                .map(|&decorator_id| match forest[decorator_id] {
                    Decorator::Trace(trace_id) => trace_id,
                    ref decorator => panic!("expected trace decorator, got {decorator:?}"),
                })
                .collect()
        }

        let mut source_builder = MastForestBuilder::new(&[]).unwrap();
        let indexed_decorator = source_builder.ensure_decorator(Decorator::Trace(1)).unwrap();
        let true_id = source_builder
            .ensure_block(
                vec![Operation::Add],
                vec![(0, indexed_decorator)],
                vec![],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();
        let false_id = source_builder
            .ensure_block(vec![Operation::Mul], Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();
        let true_ref = source_builder.node_ref(true_id).unwrap();
        let false_ref = source_builder.node_ref(false_id).unwrap();
        let first_decorator_ref =
            source_builder.ensure_decorator_ref(Decorator::Trace(10)).unwrap();
        let second_decorator_ref =
            source_builder.ensure_decorator_ref(Decorator::Trace(20)).unwrap();
        let split_ref = source_builder
            .ensure_split_node_ref(
                [true_ref, false_ref],
                Some(vec![first_decorator_ref, second_decorator_ref]),
                AssemblyOp::new(None, "static".into(), 1, "if.true".into()),
            )
            .unwrap();
        source_builder.record_procedure_root_ref(split_ref);

        let (static_forest, source_remapping) = source_builder.build().into_parts();
        let static_split_id = source_remapping[&split_ref];

        let mut builder = MastForestBuilder::new([&static_forest]).unwrap();
        let linked_id = builder
            .ensure_external_link_with_source(
                static_forest[static_split_id].digest(),
                Some(static_forest.commitment()),
                Some(static_split_id),
            )
            .unwrap();
        let linked_ref = record_test_root(&mut builder, linked_id);

        let (forest, remapping) = builder.build().into_parts();
        let final_split_id = remapping[&linked_ref];

        assert_eq!(
            trace_values(&forest, forest.before_enter_decorators(final_split_id)),
            vec![10, 20]
        );

        let mut children = Vec::new();
        forest[final_split_id].for_each_child(|child_id| children.push(child_id));
        let true_block = forest[children[0]].get_basic_block().unwrap();
        let indexed_traces = true_block
            .indexed_decorator_iter(&forest)
            .map(|(_op_idx, decorator_id)| match forest[decorator_id] {
                Decorator::Trace(trace_id) => trace_id,
                ref decorator => panic!("expected trace decorator, got {decorator:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(indexed_traces, vec![1]);
    }

    /// Provenance-aware static linking can select the exact same-digest root instead of falling
    /// back to the first digest match.
    #[test]
    fn test_static_link_with_source_root_preserves_selected_alias_metadata() {
        let mut source_builder = MastForestBuilder::new(&[]).unwrap();

        let alias_a = source_builder
            .ensure_block(
                vec![Operation::Add],
                Vec::new(),
                vec![(0, AssemblyOp::new(None, "alias_a".into(), 1, "add".into()))],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();
        let alias_b = source_builder
            .ensure_block(
                vec![Operation::Add],
                Vec::new(),
                vec![(0, AssemblyOp::new(None, "alias_b".into(), 1, "add".into()))],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();
        let alias_a_ref = record_test_root(&mut source_builder, alias_a);
        let alias_b_ref = record_test_root(&mut source_builder, alias_b);

        let (static_forest, source_remapping) = source_builder.build().into_parts();
        let final_alias_a = source_remapping[&alias_a_ref];
        let final_alias_b = source_remapping[&alias_b_ref];
        assert_eq!(static_forest[final_alias_a].digest(), static_forest[final_alias_b].digest());

        let mut exact_builder = MastForestBuilder::new([&static_forest]).unwrap();
        let exact_alias_b = {
            let node = exact_builder.statically_linked_mast[final_alias_b].clone();
            let node_refs_by_source_id = BTreeMap::new();
            let decorator_refs_by_source_id = BTreeMap::new();
            let (builder, _child_refs, _decorator_refs) = exact_builder
                .build_with_remapped_ids(
                    final_alias_b,
                    node,
                    &node_refs_by_source_id,
                    &decorator_refs_by_source_id,
                )
                .unwrap();
            exact_builder
                .ensure_node_from_statically_linked_source(builder, final_alias_b)
                .unwrap()
        };
        let exact_alias_b_ref = exact_builder.node_ref(exact_alias_b).unwrap();
        let (exact_forest, exact_remapping) = exact_builder.build().into_parts();
        let final_exact_alias_b = exact_remapping[&exact_alias_b_ref];

        let mut provenance_builder = MastForestBuilder::new([&static_forest]).unwrap();
        let linked_alias_b = provenance_builder
            .ensure_external_link_with_source(
                static_forest[final_alias_b].digest(),
                Some(static_forest.commitment()),
                Some(final_alias_b),
            )
            .unwrap();
        let linked_alias_b_ref = provenance_builder.node_ref(linked_alias_b).unwrap();
        let (linked_forest, linked_remapping) = provenance_builder.build().into_parts();
        let final_linked_alias_b = linked_remapping[&linked_alias_b_ref];

        assert_eq!(
            exact_forest
                .debug_info()
                .first_asm_op_for_node(final_exact_alias_b)
                .unwrap()
                .context_name(),
            "alias_b"
        );
        assert_eq!(
            linked_forest
                .debug_info()
                .first_asm_op_for_node(final_linked_alias_b)
                .unwrap()
                .context_name(),
            "alias_b",
            "provenance-aware linking should preserve the selected same-digest root metadata",
        );
    }
}
