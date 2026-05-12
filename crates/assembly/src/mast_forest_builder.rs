use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::fmt;

use miden_core::{
    Felt, Word,
    advice::AdviceMap,
    chiplets::hasher,
    crypto::hash::Blake3_256,
    mast::{
        BasicBlockNode, BasicBlockNodeBuilder, CallNode, CallNodeBuilder, DebugInfo,
        DecoratorFingerprint, DecoratorId, DynNode, DynNodeBuilder, ExternalNodeBuilder, JoinNode,
        JoinNodeBuilder, LoopNode, LoopNodeBuilder, MastForest, MastForestContributor,
        MastForestError, MastForestParts, MastForestRootMap, MastNode, MastNodeBuilder,
        MastNodeExt, MastNodeFingerprint, MastNodeId, OpBatch, SplitNode, SplitNodeBuilder,
        SubtreeIterator, error_code_from_msg, fingerprint_from_fingerprints,
    },
    operations::{AssemblyOp, DebugVarInfo, Decorator, DecoratorList, Operation},
    serde::Serializable,
    utils::{Idx, IndexVec},
};

use super::{GlobalItemIndex, LinkerError, Procedure};
use crate::{
    diagnostics::{Diagnostic, IntoDiagnostic, Report, WrapErr, miette},
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

#[derive(Debug, thiserror::Error, Diagnostic)]
enum MastForestBuilderError {
    #[error("failed to add decorator {decorator_ref:?} while finalizing MAST forest: {source}")]
    AddDecorator {
        decorator_ref: DecoratorRef,
        #[source]
        source: MastForestError,
    },
    #[error("pending {node_kind} node {node_ref} has {actual} children, expected {expected}")]
    InvalidChildCount {
        node_ref: MastNodeRef,
        node_kind: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("pending {node_kind} node {node_ref} has indexed decorators")]
    InvalidIndexedDecorators {
        node_ref: MastNodeRef,
        node_kind: &'static str,
    },
    #[error(
        "pending {node_kind} node {node_ref} references child {child_ref} before the child was finalized"
    )]
    MissingFinalChild {
        node_ref: MastNodeRef,
        node_kind: &'static str,
        child_ref: MastNodeRef,
    },
    #[error("pending node {node_ref} references decorator {decorator_ref:?} before finalization")]
    MissingFinalDecorator {
        node_ref: MastNodeRef,
        decorator_ref: DecoratorRef,
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
    #[error("failed to finalize MAST forest: {source}")]
    FinalizeForest {
        #[source]
        source: MastForestError,
    },
    #[error("failed to register decorators for node {node_id:?}: {source_msg}")]
    RegisterDecorators { node_id: MastNodeId, source_msg: String },
}

#[derive(Clone, Debug)]
struct PendingMastNode {
    fingerprint: MastNodeFingerprint,
    digest: Word,
    kind: PendingMastNodeKind,
    child_refs: Vec<MastNodeRef>,
    decorator_refs: PendingDecoratorRefs,
    asm_ops: Vec<(usize, AsmOpRef)>,
    debug_vars: Vec<(usize, DebugVarRef)>,
}

impl PendingMastNode {
    fn to_draft(&self) -> PendingMastNodeDraft {
        PendingMastNodeDraft {
            digest: self.digest,
            kind: self.kind.clone(),
            child_refs: self.child_refs.clone(),
            decorator_refs: self.decorator_refs.clone(),
            asm_ops: self.asm_ops.clone(),
            debug_vars: self.debug_vars.clone(),
        }
    }
}

#[derive(Clone, Debug)]
enum PendingMastNodeKind {
    BasicBlock { op_batches: Vec<OpBatch> },
    Join,
    Split,
    Loop,
    Call { is_syscall: bool },
    Dyn { is_dyncall: bool },
    External,
}

impl PendingMastNodeKind {
    fn name(&self) -> &'static str {
        match self {
            Self::BasicBlock { .. } => "basic block",
            Self::Join => "join",
            Self::Split => "split",
            Self::Loop => "loop",
            Self::Call { .. } => "call",
            Self::Dyn { .. } => "dyn",
            Self::External => "external",
        }
    }

    fn from_node(node: MastNode) -> Self {
        match node {
            MastNode::Block(node) => Self::BasicBlock { op_batches: node.op_batches().to_vec() },
            MastNode::Join(_) => Self::Join,
            MastNode::Split(_) => Self::Split,
            MastNode::Loop(_) => Self::Loop,
            MastNode::Call(node) => Self::Call { is_syscall: node.is_syscall() },
            MastNode::Dyn(node) => Self::Dyn { is_dyncall: node.is_dyncall() },
            MastNode::External(_) => Self::External,
        }
    }

    fn basic_block_op_batches(&self) -> Option<&[OpBatch]> {
        match self {
            Self::BasicBlock { op_batches } => Some(op_batches),
            _ => None,
        }
    }

    fn is_basic_block(&self) -> bool {
        matches!(self, Self::BasicBlock { .. })
    }

    fn is_external(&self) -> bool {
        matches!(self, Self::External)
    }
}

struct PendingMastNodeDraft {
    digest: Word,
    kind: PendingMastNodeKind,
    child_refs: Vec<MastNodeRef>,
    decorator_refs: PendingDecoratorRefs,
    asm_ops: Vec<(usize, AsmOpRef)>,
    debug_vars: Vec<(usize, DebugVarRef)>,
}

impl PendingMastNodeDraft {
    fn new(
        kind: PendingMastNodeKind,
        digest: Word,
        child_refs: Vec<MastNodeRef>,
        decorator_refs: PendingDecoratorRefs,
    ) -> Self {
        Self {
            digest,
            kind,
            child_refs,
            decorator_refs,
            asm_ops: Vec::new(),
            debug_vars: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct PendingDecoratorRefs {
    before_enter: Vec<DecoratorRef>,
    indexed: Vec<(usize, DecoratorRef)>,
    after_exit: Vec<DecoratorRef>,
}

impl PendingDecoratorRefs {
    fn with_before_enter(before_enter: Option<Vec<DecoratorRef>>) -> Self {
        Self {
            before_enter: before_enter.unwrap_or_default(),
            ..Self::default()
        }
    }

    fn refs(&self) -> impl Iterator<Item = DecoratorRef> + '_ {
        self.before_enter
            .iter()
            .chain(self.indexed.iter().map(|(_idx, decorator_ref)| decorator_ref))
            .chain(self.after_exit.iter())
            .copied()
    }
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
    nodes: IndexVec<MastNodeRef, PendingMastNode>,
    /// A map of decorator fingerprints to their corresponding builder-local decorator refs.
    decorator_ref_by_fingerprint: BTreeMap<DecoratorFingerprint, DecoratorRef>,
    /// Builder-owned dense storage for decorator refs.
    decorators: IndexVec<DecoratorRef, Decorator>,
    /// Builder-owned dense storage for assembly op refs.
    asm_op_by_ref: IndexVec<AsmOpRef, AssemblyOp>,
    /// Builder-owned dense storage for debug variable refs.
    debug_vars: IndexVec<DebugVarRef, DebugVarInfo>,
    /// Error codes registered while building this forest.
    error_codes: BTreeMap<u64, Arc<str>>,
    /// A set of refs for basic blocks which have been merged into a bigger basic blocks. This is
    /// used as a candidate set of nodes that may be eliminated if the are not referenced by any
    /// other node in the forest and are not a root of any procedure.
    merged_basic_block_refs: BTreeSet<MastNodeRef>,
    /// A set of refs replaced by decorated clones during assembly. These nodes may be eliminated
    /// when the original ref is not retained as a procedure root or referenced by another node.
    superseded_node_refs: BTreeSet<MastNodeRef>,
    /// A MastForest that contains the MAST of all statically-linked libraries, it's used to find
    /// precompiled procedures and copy their subtrees instead of inserting external nodes.
    statically_linked_mast: Arc<MastForest>,
    /// Maps each statically linked source forest commitment to its position in the merged forest
    /// root map.
    statically_linked_forest_indices_by_commitment: BTreeMap<Word, usize>,
    /// Maps procedure roots from each source static library to their new root ID in the merged
    /// static forest.
    statically_linked_root_map: MastForestRootMap,
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

    fn push_pending_node_record_ref(
        &mut self,
        fingerprint: MastNodeFingerprint,
        draft: PendingMastNodeDraft,
    ) -> Result<MastNodeRef, Report> {
        let node_ref = self
            .nodes
            .push(PendingMastNode {
                fingerprint,
                digest: draft.digest,
                kind: draft.kind,
                child_refs: draft.child_refs,
                decorator_refs: draft.decorator_refs,
                asm_ops: draft.asm_ops,
                debug_vars: draft.debug_vars,
            })
            .into_diagnostic()
            .wrap_err("assembler created too many MAST nodes")?;

        Ok(node_ref)
    }

    fn dedup_fingerprint_for_pending_data(
        &self,
        draft: &PendingMastNodeDraft,
    ) -> MastNodeFingerprint {
        let base_fingerprint = self.fingerprint_for_pending_record(
            draft.digest,
            &draft.kind,
            &draft.child_refs,
            &draft.decorator_refs,
        );
        let asm_ops_data = serialize_asm_op_refs(&self.asm_op_by_ref, &draft.asm_ops);
        let debug_vars_data = serialize_debug_var_refs(&self.debug_vars, &draft.debug_vars);
        self.maybe_augment(self.maybe_augment(base_fingerprint, &asm_ops_data), &debug_vars_data)
    }

    fn intern_pending_node(&mut self, draft: PendingMastNodeDraft) -> Result<MastNodeRef, Report> {
        let dedup_fingerprint = self.dedup_fingerprint_for_pending_data(&draft);
        if let Some(node_ref) = self.find_node_ref_by_fingerprint(&dedup_fingerprint) {
            Ok(node_ref)
        } else {
            self.insert_pending_node_record_ref(dedup_fingerprint, draft)
        }
    }

    fn intern_pending_node_with_metadata_payloads(
        &mut self,
        mut draft: PendingMastNodeDraft,
        asm_ops: Vec<(usize, AssemblyOp)>,
        debug_vars: Vec<(usize, DebugVarInfo)>,
    ) -> Result<MastNodeRef, Report> {
        let base_fingerprint = self.fingerprint_for_pending_record(
            draft.digest,
            &draft.kind,
            &draft.child_refs,
            &draft.decorator_refs,
        );
        let asm_ops_data = serialize_asm_op_payloads(&asm_ops);
        let debug_vars_data = serialize_debug_var_payloads(&debug_vars);
        let dedup_fingerprint = self
            .maybe_augment(self.maybe_augment(base_fingerprint, &asm_ops_data), &debug_vars_data);

        if let Some(node_ref) = self.find_node_ref_by_fingerprint(&dedup_fingerprint) {
            return Ok(node_ref);
        }

        draft.asm_ops = asm_ops
            .into_iter()
            .map(|(op_idx, asm_op)| {
                self.add_asm_op_ref(asm_op).map(|asm_op_ref| (op_idx, asm_op_ref))
            })
            .collect::<Result<Vec<_>, Report>>()?;
        draft.debug_vars = debug_vars
            .into_iter()
            .map(|(op_idx, debug_var)| {
                self.add_debug_var_ref(debug_var).map(|debug_var_ref| (op_idx, debug_var_ref))
            })
            .collect::<Result<Vec<_>, Report>>()?;

        self.insert_pending_node_record_ref(dedup_fingerprint, draft)
    }

    fn find_node_ref_by_fingerprint(
        &self,
        fingerprint: &MastNodeFingerprint,
    ) -> Option<MastNodeRef> {
        self.node_ref_by_fingerprint.get(fingerprint).copied()
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
                .map(|&decorator_ref| self.decorators[decorator_ref].fingerprint()),
            decorator_refs
                .after_exit
                .iter()
                .map(|&decorator_ref| self.decorators[decorator_ref].fingerprint()),
            child_refs.iter().map(|&child_ref| self.nodes[child_ref].fingerprint),
            node_digest,
        )
    }

    fn fingerprint_for_pending_record(
        &self,
        digest: Word,
        kind: &PendingMastNodeKind,
        child_refs: &[MastNodeRef],
        decorator_refs: &PendingDecoratorRefs,
    ) -> MastNodeFingerprint {
        if let Some(op_batches) = kind.basic_block_op_batches() {
            self.fingerprint_for_pending_basic_block(digest, op_batches, decorator_refs)
        } else {
            self.fingerprint_from_pending_refs(digest, child_refs, decorator_refs)
        }
    }

    fn fingerprint_for_pending_basic_block(
        &self,
        block_digest: Word,
        op_batches: &[OpBatch],
        decorator_refs: &PendingDecoratorRefs,
    ) -> MastNodeFingerprint {
        let before_enter_bytes: Vec<[u8; 32]> = decorator_refs
            .before_enter
            .iter()
            .map(|&decorator_ref| *self.decorators[decorator_ref].fingerprint().as_bytes())
            .collect();

        let raw_indexed_decorators =
            BasicBlockNode::unadjust_asm_op_indices(decorator_refs.indexed.clone(), op_batches);
        let mut op_decorator_data = Vec::with_capacity(raw_indexed_decorators.len() * 40);
        for (raw_op_idx, decorator_ref) in &raw_indexed_decorators {
            op_decorator_data.extend_from_slice(&raw_op_idx.to_le_bytes());
            op_decorator_data
                .extend_from_slice(self.decorators[*decorator_ref].fingerprint().as_bytes());
        }

        let after_exit_bytes: Vec<[u8; 32]> = decorator_refs
            .after_exit
            .iter()
            .map(|&decorator_ref| *self.decorators[decorator_ref].fingerprint().as_bytes())
            .collect();

        let mut assert_data = Vec::new();
        for (op_idx, op) in op_batches.iter().flat_map(OpBatch::ops).enumerate() {
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
            MastNodeFingerprint::new(block_digest)
        } else {
            let decorator_bytes_iter = before_enter_bytes
                .iter()
                .map(<[u8; 32]>::as_slice)
                .chain(core::iter::once(op_decorator_data.as_slice()))
                .chain(after_exit_bytes.iter().map(<[u8; 32]>::as_slice))
                .chain(core::iter::once(assert_data.as_slice()));
            let decorator_root = Blake3_256::hash_iter(decorator_bytes_iter);
            MastNodeFingerprint::with_decorator_root(block_digest, decorator_root)
        }
    }

    fn push_decorator_ref(
        &mut self,
        decorator: Decorator,
        fingerprint: DecoratorFingerprint,
    ) -> Result<DecoratorRef, Report> {
        let decorator_ref = self
            .decorators
            .push(decorator)
            .into_diagnostic()
            .wrap_err("assembler created too many decorators")?;
        self.decorator_ref_by_fingerprint.insert(fingerprint, decorator_ref);
        Ok(decorator_ref)
    }

    pub(crate) fn add_asm_op_ref(&mut self, asm_op: AssemblyOp) -> Result<AsmOpRef, Report> {
        self.asm_op_by_ref
            .push(asm_op)
            .into_diagnostic()
            .wrap_err("assembler created too many assembly op refs")
    }

    fn push_debug_var_ref(&mut self, debug_var: DebugVarInfo) -> Result<DebugVarRef, Report> {
        self.debug_vars
            .push(debug_var)
            .into_diagnostic()
            .wrap_err("assembler created too many debug variables")
    }

    /// Removes the unused nodes that were created as part of the assembly process, and returns the
    /// resulting MAST forest.
    ///
    /// It also returns the map from assembly-time node refs to final node IDs. Any [`MastNodeRef`]
    /// used in reference to this builder should be resolved using this map.
    pub(crate) fn build(mut self) -> Result<BuiltMastForest, Report> {
        let procedure_root_refs = core::mem::take(&mut self.procedure_root_refs);

        let mut removable_node_refs = core::mem::take(&mut self.merged_basic_block_refs);
        removable_node_refs.append(&mut self.superseded_node_refs);
        let node_refs_to_remove =
            get_node_refs_to_remove(removable_node_refs, &procedure_root_refs, &self.nodes);

        let live_node_refs = live_node_refs_in_final_order(&self.nodes, &node_refs_to_remove);
        let mut live_decorator_refs = BTreeSet::new();
        for node_ref in &live_node_refs {
            live_decorator_refs.extend(self.nodes[*node_ref].decorator_refs.refs());
        }

        let mut debug_info = DebugInfo::new();
        let mut final_decorator_id_by_ref = BTreeMap::new();
        for decorator_ref in live_decorator_refs {
            let final_decorator_id = debug_info
                .add_decorator(self.decorators[decorator_ref].clone())
                .map_err(|source| {
                    Report::new(MastForestBuilderError::AddDecorator { decorator_ref, source })
                })?;
            final_decorator_id_by_ref.insert(decorator_ref, final_decorator_id);
        }

        let mut nodes = IndexVec::new();
        let mut node_id_by_ref = BTreeMap::new();
        for &node_ref in &live_node_refs {
            let pending_node = &self.nodes[node_ref];
            let builder = build_pending_node_with_final_ids(
                pending_node,
                node_ref,
                &node_id_by_ref,
                &final_decorator_id_by_ref,
            )
            .map_err(Report::new)?;

            let final_node_id =
                MastNodeId::new_unchecked(nodes.len().try_into().map_err(|_| {
                    Report::new(MastForestBuilderError::FinalizeForest {
                        source: MastForestError::TooManyNodes,
                    })
                })?);
            let node = builder.build_linked(final_node_id).map_err(|source| {
                Report::new(MastForestBuilderError::BuildNode {
                    node_ref,
                    node_kind: pending_node.kind.name(),
                    source,
                })
            })?;
            register_pending_node_decorators(
                &mut debug_info,
                final_node_id,
                node_ref,
                pending_node,
                &final_decorator_id_by_ref,
            )
            .map_err(Report::new)?;
            let inserted_node_id = nodes.push(node).map_err(|_| {
                Report::new(MastForestBuilderError::AddNode {
                    node_ref,
                    source: MastForestError::TooManyNodes,
                })
            })?;
            debug_assert_eq!(inserted_node_id, final_node_id);
            node_id_by_ref.insert(node_ref, final_node_id);
        }

        // Register owned AssemblyOp metadata in final node order. The CSR structure requires
        // nodes to be registered sequentially.
        let mut asm_op_id_by_ref = BTreeMap::new();
        for &node_ref in &live_node_refs {
            let asm_op_mappings = self.nodes[node_ref].asm_ops.clone();
            if asm_op_mappings.is_empty() {
                continue;
            }

            let node_id = node_id_by_ref[&node_ref];
            let (num_operations, adjusted_mappings) =
                compute_operations_and_adjust_mappings(&nodes[node_id], asm_op_mappings);
            let adjusted_mappings = adjusted_mappings
                .into_iter()
                .map(|(op_idx, asm_op_ref)| {
                    let asm_op_id = if let Some(asm_op_id) =
                        asm_op_id_by_ref.get(&asm_op_ref).copied()
                    {
                        asm_op_id
                    } else {
                        let asm_op_id = debug_info
                            .add_asm_op(self.asm_op_by_ref[asm_op_ref].clone())
                            .map_err(|source| {
                                Report::new(MastForestBuilderError::AddAsmOp { node_id, source })
                            })?;
                        asm_op_id_by_ref.insert(asm_op_ref, asm_op_id);
                        asm_op_id
                    };
                    Ok((op_idx, asm_op_id))
                })
                .collect::<Result<Vec<_>, Report>>()?;

            debug_info
                .register_asm_ops(node_id, num_operations, adjusted_mappings)
                .map_err(|source| {
                    Report::new(MastForestBuilderError::RegisterAsmOps {
                        node_id,
                        source_msg: source.to_string(),
                    })
                })?;
        }

        let mut debug_var_id_by_ref = BTreeMap::new();
        for &node_ref in &live_node_refs {
            let debug_vars = self.nodes[node_ref].debug_vars.clone();
            if debug_vars.is_empty() {
                continue;
            }

            let node_id = node_id_by_ref[&node_ref];
            let mut debug_var_ids = Vec::with_capacity(debug_vars.len());
            for (op_idx, debug_var_ref) in debug_vars {
                let debug_var_id =
                    if let Some(debug_var_id) = debug_var_id_by_ref.get(&debug_var_ref).copied() {
                        debug_var_id
                    } else {
                        let debug_var_id = debug_info
                            .add_debug_var(self.debug_vars[debug_var_ref].clone())
                            .map_err(|source| {
                                Report::new(MastForestBuilderError::AddDebugVar { node_id, source })
                            })?;
                        debug_var_id_by_ref.insert(debug_var_ref, debug_var_id);
                        debug_var_id
                    };
                debug_var_ids.push((op_idx, debug_var_id));
            }
            debug_info.register_op_indexed_debug_vars(node_id, debug_var_ids).map_err(
                |source| {
                    Report::new(MastForestBuilderError::RegisterDebugVars {
                        node_id,
                        source_msg: source.to_string(),
                    })
                },
            )?;
        }

        let mut roots = Vec::with_capacity(procedure_root_refs.len());
        for &root_ref in &procedure_root_refs {
            let root_id = *node_id_by_ref.get(&root_ref).ok_or_else(|| {
                Report::new(MastForestBuilderError::MissingProcedureRoot { root_ref })
            })?;
            roots.push(root_id);
        }

        debug_info.extend_error_codes(core::mem::take(&mut self.error_codes));
        let final_forest = MastForest::from_parts(MastForestParts {
            nodes,
            roots,
            advice_map: self.advice_map,
            debug_info,
        })
        .map_err(|source| Report::new(MastForestBuilderError::FinalizeForest { source }))?;

        Ok(BuiltMastForest {
            mast_forest: final_forest,
            node_id_by_ref,
        })
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

fn batch_basic_block_operations(
    operations: Vec<Operation>,
) -> Result<(Vec<OpBatch>, Word), Report> {
    let block = BasicBlockNodeBuilder::new(operations, Vec::new())
        .build()
        .into_diagnostic()
        .wrap_err("assembler failed to build new basic block")?;
    Ok((block.op_batches().to_vec(), block.digest()))
}

fn build_pending_node_with_final_ids(
    pending_node: &PendingMastNode,
    node_ref: MastNodeRef,
    final_node_id_by_ref: &BTreeMap<MastNodeRef, MastNodeId>,
    final_decorator_id_by_ref: &BTreeMap<DecoratorRef, DecoratorId>,
) -> Result<MastNodeBuilder, MastForestBuilderError> {
    let before_enter = final_decorator_ids_from_refs(
        node_ref,
        &pending_node.decorator_refs.before_enter,
        final_decorator_id_by_ref,
    )?;
    let after_exit = final_decorator_ids_from_refs(
        node_ref,
        &pending_node.decorator_refs.after_exit,
        final_decorator_id_by_ref,
    )?;

    let builder = match &pending_node.kind {
        PendingMastNodeKind::BasicBlock { op_batches } => {
            ensure_child_count(node_ref, pending_node, 0)?;
            let decorators = final_indexed_decorator_ids_from_refs(
                node_ref,
                &pending_node.decorator_refs.indexed,
                final_decorator_id_by_ref,
            )?;
            MastNodeBuilder::BasicBlock(
                BasicBlockNodeBuilder::from_op_batches_preserving_digest(
                    op_batches.clone(),
                    decorators,
                    pending_node.digest,
                )
                .with_before_enter(before_enter)
                .with_after_exit(after_exit),
            )
        },
        PendingMastNodeKind::Join => {
            ensure_child_count(node_ref, pending_node, 2)?;
            ensure_no_indexed_decorators(node_ref, pending_node)?;
            let children = final_child_ids::<2>(node_ref, pending_node, final_node_id_by_ref)?;
            MastNodeBuilder::Join(
                JoinNodeBuilder::new(children)
                    .with_before_enter(before_enter)
                    .with_after_exit(after_exit)
                    .with_digest(pending_node.digest),
            )
        },
        PendingMastNodeKind::Split => {
            ensure_child_count(node_ref, pending_node, 2)?;
            ensure_no_indexed_decorators(node_ref, pending_node)?;
            let branches = final_child_ids::<2>(node_ref, pending_node, final_node_id_by_ref)?;
            MastNodeBuilder::Split(
                SplitNodeBuilder::new(branches)
                    .with_before_enter(before_enter)
                    .with_after_exit(after_exit)
                    .with_digest(pending_node.digest),
            )
        },
        PendingMastNodeKind::Loop => {
            ensure_child_count(node_ref, pending_node, 1)?;
            ensure_no_indexed_decorators(node_ref, pending_node)?;
            let [body] = final_child_ids::<1>(node_ref, pending_node, final_node_id_by_ref)?;
            MastNodeBuilder::Loop(
                LoopNodeBuilder::new(body)
                    .with_before_enter(before_enter)
                    .with_after_exit(after_exit)
                    .with_digest(pending_node.digest),
            )
        },
        PendingMastNodeKind::Call { is_syscall } => {
            ensure_child_count(node_ref, pending_node, 1)?;
            ensure_no_indexed_decorators(node_ref, pending_node)?;
            let [callee] = final_child_ids::<1>(node_ref, pending_node, final_node_id_by_ref)?;
            let builder = if *is_syscall {
                CallNodeBuilder::new_syscall(callee)
            } else {
                CallNodeBuilder::new(callee)
            };
            MastNodeBuilder::Call(
                builder
                    .with_before_enter(before_enter)
                    .with_after_exit(after_exit)
                    .with_digest(pending_node.digest),
            )
        },
        PendingMastNodeKind::Dyn { is_dyncall } => {
            ensure_child_count(node_ref, pending_node, 0)?;
            ensure_no_indexed_decorators(node_ref, pending_node)?;
            let builder = if *is_dyncall {
                DynNodeBuilder::new_dyncall()
            } else {
                DynNodeBuilder::new_dyn()
            };
            MastNodeBuilder::Dyn(
                builder
                    .with_before_enter(before_enter)
                    .with_after_exit(after_exit)
                    .with_digest(pending_node.digest),
            )
        },
        PendingMastNodeKind::External => {
            ensure_child_count(node_ref, pending_node, 0)?;
            ensure_no_indexed_decorators(node_ref, pending_node)?;
            MastNodeBuilder::External(
                ExternalNodeBuilder::new(pending_node.digest)
                    .with_before_enter(before_enter)
                    .with_after_exit(after_exit),
            )
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

fn ensure_no_indexed_decorators(
    node_ref: MastNodeRef,
    pending_node: &PendingMastNode,
) -> Result<(), MastForestBuilderError> {
    if pending_node.decorator_refs.indexed.is_empty() {
        Ok(())
    } else {
        Err(MastForestBuilderError::InvalidIndexedDecorators {
            node_ref,
            node_kind: pending_node.kind.name(),
        })
    }
}

fn register_pending_node_decorators(
    debug_info: &mut DebugInfo,
    node_id: MastNodeId,
    node_ref: MastNodeRef,
    pending_node: &PendingMastNode,
    final_decorator_id_by_ref: &BTreeMap<DecoratorRef, DecoratorId>,
) -> Result<(), MastForestBuilderError> {
    let before_enter = final_decorator_ids_from_refs(
        node_ref,
        &pending_node.decorator_refs.before_enter,
        final_decorator_id_by_ref,
    )?;
    let after_exit = final_decorator_ids_from_refs(
        node_ref,
        &pending_node.decorator_refs.after_exit,
        final_decorator_id_by_ref,
    )?;
    if !before_enter.is_empty() || !after_exit.is_empty() {
        debug_info.register_node_decorators(node_id, &before_enter, &after_exit);
    }

    if pending_node.kind.is_basic_block() {
        let indexed_decorators = final_indexed_decorator_ids_from_refs(
            node_ref,
            &pending_node.decorator_refs.indexed,
            final_decorator_id_by_ref,
        )?;
        debug_info.register_op_indexed_decorators(node_id, indexed_decorators).map_err(
            |source| MastForestBuilderError::RegisterDecorators {
                node_id,
                source_msg: source.to_string(),
            },
        )?;
    } else if !pending_node.decorator_refs.indexed.is_empty() {
        return Err(MastForestBuilderError::InvalidIndexedDecorators {
            node_ref,
            node_kind: pending_node.kind.name(),
        });
    }

    Ok(())
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

fn final_decorator_ids_from_refs(
    node_ref: MastNodeRef,
    decorator_refs: &[DecoratorRef],
    final_decorator_id_by_ref: &BTreeMap<DecoratorRef, DecoratorId>,
) -> Result<Vec<DecoratorId>, MastForestBuilderError> {
    decorator_refs
        .iter()
        .map(|decorator_ref| {
            final_decorator_id_by_ref.get(decorator_ref).copied().ok_or(
                MastForestBuilderError::MissingFinalDecorator {
                    node_ref,
                    decorator_ref: *decorator_ref,
                },
            )
        })
        .collect()
}

fn final_indexed_decorator_ids_from_refs(
    node_ref: MastNodeRef,
    decorator_refs: &[(usize, DecoratorRef)],
    final_decorator_id_by_ref: &BTreeMap<DecoratorRef, DecoratorId>,
) -> Result<DecoratorList, MastForestBuilderError> {
    decorator_refs
        .iter()
        .map(|(op_idx, decorator_ref)| {
            let decorator_id = *final_decorator_id_by_ref.get(decorator_ref).ok_or(
                MastForestBuilderError::MissingFinalDecorator {
                    node_ref,
                    decorator_ref: *decorator_ref,
                },
            )?;
            Ok((*op_idx, decorator_id))
        })
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

/// Serializes pending AssemblyOp content into bytes for fingerprint augmentation.
fn serialize_asm_op_refs(
    asm_op_by_ref: &IndexVec<AsmOpRef, AssemblyOp>,
    asm_ops: &[(usize, AsmOpRef)],
) -> Vec<u8> {
    let mut data = Vec::new();
    for (op_idx, asm_op_ref) in asm_ops {
        append_serialized_asm_op(&mut data, *op_idx, &asm_op_by_ref[*asm_op_ref]);
    }
    data
}

fn serialize_asm_op_payloads(asm_ops: &[(usize, AssemblyOp)]) -> Vec<u8> {
    let mut data = Vec::new();
    for (op_idx, asm_op) in asm_ops {
        append_serialized_asm_op(&mut data, *op_idx, asm_op);
    }
    data
}

fn serialize_debug_var_refs(
    debug_var_by_ref: &IndexVec<DebugVarRef, DebugVarInfo>,
    debug_vars: &[(usize, DebugVarRef)],
) -> Vec<u8> {
    let mut data = Vec::new();
    for (op_idx, debug_var_ref) in debug_vars {
        data.extend_from_slice(&op_idx.to_le_bytes());
        debug_var_by_ref[*debug_var_ref].write_into(&mut data);
    }
    data
}

fn serialize_debug_var_payloads(debug_vars: &[(usize, DebugVarInfo)]) -> Vec<u8> {
    let mut data = Vec::new();
    for (op_idx, debug_var) in debug_vars {
        data.extend_from_slice(&op_idx.to_le_bytes());
        debug_var.write_into(&mut data);
    }
    data
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
    candidate_node_refs: BTreeSet<MastNodeRef>,
    procedure_root_refs: &[MastNodeRef],
    nodes: &IndexVec<MastNodeRef, PendingMastNode>,
) -> BTreeSet<MastNodeRef> {
    // make sure not to remove procedure roots
    let mut nodes_to_remove: BTreeSet<MastNodeRef> = candidate_node_refs
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
        if nodes[*node_ref].kind.is_external() {
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

    pub(crate) fn mast_root_for_ref(&self, node_ref: MastNodeRef) -> Option<Word> {
        self.nodes.get(node_ref).map(|pending_node| pending_node.digest)
    }

    fn pending_node_mast_root(&self, node_ref: MastNodeRef) -> Word {
        *self.nodes[node_ref].fingerprint.mast_root()
    }

    fn pending_node_is_basic_block(&self, node_ref: MastNodeRef) -> bool {
        self.nodes[node_ref].kind.is_basic_block()
    }

    fn pending_basic_block_op_batches(&self, node_ref: MastNodeRef) -> Option<&[OpBatch]> {
        self.nodes[node_ref].kind.basic_block_op_batches()
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
                let left_digest = self.pending_node_mast_root(left);
                let right_digest = self.pending_node_mast_root(right);
                let join_digest =
                    hasher::merge_in_domain(&[left_digest, right_digest], JoinNode::DOMAIN);
                let child_refs = vec![left, right];
                let decorator_refs = PendingDecoratorRefs::default();
                let draft = PendingMastNodeDraft::new(
                    PendingMastNodeKind::Join,
                    join_digest,
                    child_refs,
                    decorator_refs,
                );
                let join_mast_node_ref = if let Some(ref asm_op) = asm_op {
                    self.intern_pending_node_with_metadata_payloads(
                        draft,
                        vec![(0, asm_op.clone())],
                        Vec::new(),
                    )?
                } else {
                    self.intern_pending_node(draft)?
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
        let pending_decorator_refs = PendingDecoratorRefs::with_before_enter(before_enter);
        let branch_digests = branches.map(|node_ref| self.pending_node_mast_root(node_ref));
        let split_digest = hasher::merge_in_domain(&branch_digests, SplitNode::DOMAIN);
        let child_refs = Vec::from(branches);

        self.intern_pending_node_with_metadata_payloads(
            PendingMastNodeDraft::new(
                PendingMastNodeKind::Split,
                split_digest,
                child_refs,
                pending_decorator_refs,
            ),
            vec![(0, asm_op)],
            Vec::new(),
        )
    }

    pub(crate) fn ensure_loop_node_ref(
        &mut self,
        body: MastNodeRef,
        before_enter: Option<Vec<DecoratorRef>>,
        asm_op: AssemblyOp,
    ) -> Result<MastNodeRef, Report> {
        let pending_decorator_refs = PendingDecoratorRefs::with_before_enter(before_enter);
        let body_digest = self.pending_node_mast_root(body);
        let loop_digest =
            hasher::merge_in_domain(&[body_digest, Word::default()], LoopNode::DOMAIN);
        let child_refs = vec![body];

        self.intern_pending_node_with_metadata_payloads(
            PendingMastNodeDraft::new(
                PendingMastNodeKind::Loop,
                loop_digest,
                child_refs,
                pending_decorator_refs,
            ),
            vec![(0, asm_op)],
            Vec::new(),
        )
    }

    pub(crate) fn ensure_call_node_ref(
        &mut self,
        callee: MastNodeRef,
        is_syscall: bool,
        asm_op: AssemblyOp,
    ) -> Result<MastNodeRef, Report> {
        let callee_digest = self.pending_node_mast_root(callee);
        let call_domain = if is_syscall {
            CallNode::SYSCALL_DOMAIN
        } else {
            CallNode::CALL_DOMAIN
        };
        let call_digest = hasher::merge_in_domain(&[callee_digest, Word::default()], call_domain);
        let child_refs = vec![callee];
        let decorator_refs = PendingDecoratorRefs::default();
        self.intern_pending_node_with_metadata_payloads(
            PendingMastNodeDraft::new(
                PendingMastNodeKind::Call { is_syscall },
                call_digest,
                child_refs,
                decorator_refs,
            ),
            vec![(0, asm_op)],
            Vec::new(),
        )
    }

    pub(crate) fn ensure_dyn_node_ref(
        &mut self,
        is_dyncall: bool,
        asm_op: AssemblyOp,
    ) -> Result<MastNodeRef, Report> {
        let dyn_digest = if is_dyncall {
            DynNode::DYNCALL_DEFAULT_DIGEST
        } else {
            DynNode::DYN_DEFAULT_DIGEST
        };
        let child_refs = Vec::new();
        let decorator_refs = PendingDecoratorRefs::default();
        self.intern_pending_node_with_metadata_payloads(
            PendingMastNodeDraft::new(
                PendingMastNodeKind::Dyn { is_dyncall },
                dyn_digest,
                child_refs,
                decorator_refs,
            ),
            vec![(0, asm_op)],
            Vec::new(),
        )
    }

    pub(crate) fn clone_node_with_before_enter_refs(
        &mut self,
        node_ref: MastNodeRef,
        decorator_refs: Vec<DecoratorRef>,
    ) -> Result<MastNodeRef, Report> {
        let mut draft = self.nodes[node_ref].to_draft();
        draft.decorator_refs.before_enter = decorator_refs;

        let cloned_ref = self.intern_pending_node(draft)?;
        if cloned_ref != node_ref {
            self.superseded_node_refs.insert(node_ref);
        }
        Ok(cloned_ref)
    }

    fn merge_contiguous_basic_block_refs(
        &mut self,
        node_refs: Vec<MastNodeRef>,
    ) -> Result<Vec<MastNodeRef>, Report> {
        let mut merged_node_refs = Vec::with_capacity(node_refs.len());
        let mut contiguous_basic_block_refs: Vec<MastNodeRef> = Vec::new();

        for node_ref in node_refs {
            if self.pending_node_is_basic_block(node_ref) {
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
        let mut decorators = Vec::new();
        let mut pending_after_exit = Vec::new();
        // Track asm_ops and debug_vars being accumulated for merged blocks, with adjusted indices
        let mut merged_asm_ops: Vec<(usize, AsmOpRef)> = Vec::new();
        let mut merged_debug_vars: Vec<(usize, DebugVarRef)> = Vec::new();

        let mut merged_basic_block_refs: Vec<MastNodeRef> = Vec::new();

        for &basic_block_ref in contiguous_basic_block_refs {
            // check if the block should be merged with other blocks
            if should_merge(
                self.is_procedure_root_ref(basic_block_ref),
                self.pending_basic_block_op_batches(basic_block_ref)
                    .expect("merge_basic_blocks: expected BasicBlockNode")
                    .len(),
            ) {
                // Collect decorators and operations from the block (while still borrowing)
                // We need owned copies so we can drop the borrow before mutating self
                let (block_decorators, block_before_enter, block_after_exit, block_ops) = {
                    let pending_node = &self.nodes[basic_block_ref];
                    let op_batches = pending_node
                        .kind
                        .basic_block_op_batches()
                        .expect("merge_basic_blocks: expected BasicBlockNode");
                    let block_decorators = BasicBlockNode::unadjust_asm_op_indices(
                        pending_node.decorator_refs.indexed.clone(),
                        op_batches,
                    );
                    let block_before_enter = pending_node.decorator_refs.before_enter.clone();
                    let block_after_exit = pending_node.decorator_refs.after_exit.clone();
                    let block_ops: Vec<Operation> =
                        op_batches.iter().flat_map(|b| b.raw_ops().copied()).collect();
                    (block_decorators, block_before_enter, block_after_exit, block_ops)
                };
                let ops_offset = operations.len();

                for decorator in core::mem::take(&mut pending_after_exit) {
                    decorators.push((ops_offset, decorator));
                }
                for decorator in block_before_enter {
                    decorators.push((ops_offset, decorator));
                }

                let pending_node = &self.nodes[basic_block_ref];
                merged_asm_ops.extend(
                    pending_node
                        .asm_ops
                        .iter()
                        .map(|(op_idx, asm_op_id)| (op_idx + ops_offset, *asm_op_id)),
                );
                merged_debug_vars.extend(
                    pending_node
                        .debug_vars
                        .iter()
                        .map(|(op_idx, var_id)| (op_idx + ops_offset, *var_id)),
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
                    let merged_basic_block_ref = self.ensure_block_ref(
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
            let merged_basic_block = self.ensure_block_ref(
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

    /// Adds a basic block node to the forest, and returns its builder-local [`MastNodeRef`].
    pub(crate) fn ensure_block_ref(
        &mut self,
        operations: Vec<Operation>,
        decorators: Vec<(usize, DecoratorRef)>,
        asm_op_refs: Vec<(usize, AsmOpRef)>,
        debug_vars: Vec<(usize, DebugVarRef)>,
        before_enter: Vec<DecoratorRef>,
        after_exit: Vec<DecoratorRef>,
    ) -> Result<MastNodeRef, Report> {
        let operation_count = operations.len();
        if let Some((operation_idx, _)) =
            decorators.iter().find(|(operation_idx, _)| *operation_idx >= operation_count)
        {
            return Err(report!(
                "decorator operation index {} out of bounds for basic block with {} operations",
                operation_idx,
                operation_count
            ));
        }

        let (op_batches, digest) = batch_basic_block_operations(operations)?;
        let pending_decorator_refs = PendingDecoratorRefs {
            before_enter,
            indexed: BasicBlockNode::adjust_asm_op_indices(decorators, &op_batches),
            after_exit,
        };
        let kind = PendingMastNodeKind::BasicBlock { op_batches };
        self.intern_pending_node(PendingMastNodeDraft {
            kind,
            digest,
            child_refs: Vec::new(),
            decorator_refs: pending_decorator_refs,
            asm_ops: asm_op_refs,
            debug_vars,
        })
    }
}

// ------------------------------------------------------------------------------------------------
/// Node inserters
impl MastForestBuilder {
    /// Adds a decorator to the forest, and returns its builder-local [`DecoratorRef`].
    pub(crate) fn ensure_decorator_ref(
        &mut self,
        decorator: Decorator,
    ) -> Result<DecoratorRef, Report> {
        let decorator_hash = decorator.fingerprint();
        if let Some(&decorator_ref) = self.decorator_ref_by_fingerprint.get(&decorator_hash) {
            return Ok(decorator_ref);
        }

        self.push_decorator_ref(decorator, decorator_hash)
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

    /// Copies a statically linked node into this builder while keeping source metadata in the
    /// dedup fingerprint and remapping it into the target forest when a new node is created.
    fn ensure_node_from_statically_linked_source_ref(
        &mut self,
        source_node_id: MastNodeId,
        source_node: MastNode,
        child_refs: Vec<MastNodeRef>,
        decorator_refs: PendingDecoratorRefs,
    ) -> Result<MastNodeRef, Report> {
        let digest = source_node.digest();
        let kind = PendingMastNodeKind::from_node(source_node);
        let mut asm_ops = self.statically_linked_mast.debug_info().asm_ops_for_node(source_node_id);
        if let MastNode::Block(block) = &self.statically_linked_mast[source_node_id] {
            asm_ops = BasicBlockNode::unadjust_asm_op_indices(asm_ops, block.op_batches());
        }
        let statically_linked_mast = Arc::clone(&self.statically_linked_mast);
        let pending_asm_ops = asm_ops
            .into_iter()
            .filter_map(|(op_idx, asm_op_id)| {
                statically_linked_mast
                    .debug_info()
                    .asm_op(asm_op_id)
                    .cloned()
                    .map(|asm_op| (op_idx, asm_op))
            })
            .collect::<Vec<_>>();

        let debug_vars =
            self.statically_linked_mast.debug_info().debug_vars_for_node(source_node_id);
        let statically_linked_mast = Arc::clone(&self.statically_linked_mast);
        let pending_debug_vars = debug_vars
            .into_iter()
            .filter_map(|(op_idx, var_id)| {
                statically_linked_mast
                    .debug_info()
                    .debug_var(var_id)
                    .cloned()
                    .map(|debug_var| (op_idx, debug_var))
            })
            .collect::<Vec<_>>();

        self.intern_pending_node_with_metadata_payloads(
            PendingMastNodeDraft {
                kind,
                digest,
                child_refs,
                decorator_refs,
                asm_ops: Vec::new(),
                debug_vars: Vec::new(),
            },
            pending_asm_ops,
            pending_debug_vars,
        )
    }

    fn insert_pending_node_record_ref(
        &mut self,
        fingerprint: MastNodeFingerprint,
        draft: PendingMastNodeDraft,
    ) -> Result<MastNodeRef, Report> {
        let node_ref = self.push_pending_node_record_ref(fingerprint, draft)?;

        self.node_ref_by_fingerprint.insert(fingerprint, node_ref);
        Ok(node_ref)
    }

    fn ensure_statically_linked_decorator_ref(
        &mut self,
        source_decorator_id: DecoratorId,
        decorator_refs_by_source_id: &mut BTreeMap<DecoratorId, DecoratorRef>,
    ) -> Result<DecoratorRef, Report> {
        if let Some(&decorator_ref) = decorator_refs_by_source_id.get(&source_decorator_id) {
            return Ok(decorator_ref);
        }

        let decorator = self.statically_linked_mast[source_decorator_id].clone();
        let decorator_ref = self.ensure_decorator_ref(decorator)?;
        decorator_refs_by_source_id.insert(source_decorator_id, decorator_ref);
        Ok(decorator_ref)
    }

    /// Collects builder-local refs for a statically linked source node.
    fn pending_refs_for_statically_linked_source(
        &mut self,
        node_id: MastNodeId,
        node: &MastNode,
        node_refs_by_source_id: &BTreeMap<MastNodeId, MastNodeRef>,
        decorator_refs_by_source_id: &mut BTreeMap<DecoratorId, DecoratorRef>,
    ) -> Result<(Vec<MastNodeRef>, PendingDecoratorRefs), Report> {
        let mut child_refs = Vec::new();
        node.for_each_child(|source_child_id| {
            let child_ref = *node_refs_by_source_id
                .get(&source_child_id)
                .expect("statically linked child must be copied before its parent");
            child_refs.push(child_ref);
        });

        let mut decorator_refs = PendingDecoratorRefs::default();
        let before_enter_decorators =
            self.statically_linked_mast.before_enter_decorators(node_id).to_vec();
        for source_decorator_id in before_enter_decorators {
            let decorator_ref = self.ensure_statically_linked_decorator_ref(
                source_decorator_id,
                decorator_refs_by_source_id,
            )?;
            decorator_refs.before_enter.push(decorator_ref);
        }
        if let MastNode::Block(block_node) = &node {
            let indexed_decorators: Vec<_> =
                block_node.indexed_decorator_iter(&self.statically_linked_mast).collect();
            for (op_idx, source_decorator_id) in indexed_decorators {
                let decorator_ref = self.ensure_statically_linked_decorator_ref(
                    source_decorator_id,
                    decorator_refs_by_source_id,
                )?;
                decorator_refs.indexed.push((op_idx, decorator_ref));
            }
        }
        let after_exit_decorators =
            self.statically_linked_mast.after_exit_decorators(node_id).to_vec();
        for source_decorator_id in after_exit_decorators {
            let decorator_ref = self.ensure_statically_linked_decorator_ref(
                source_decorator_id,
                decorator_refs_by_source_id,
            )?;
            decorator_refs.after_exit.push(decorator_ref);
        }

        Ok((child_refs, decorator_refs))
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

        self.intern_pending_node(PendingMastNodeDraft::new(
            PendingMastNodeKind::External,
            mast_root,
            child_refs,
            decorator_refs,
        ))
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
            let node = self.statically_linked_mast[old_id].clone();
            let (child_refs, decorator_refs) = self.pending_refs_for_statically_linked_source(
                old_id,
                &node,
                &node_refs_by_source_id,
                &mut decorator_refs_by_source_id,
            )?;
            let new_ref = self.ensure_node_from_statically_linked_source_ref(
                old_id,
                node,
                child_refs,
                decorator_refs,
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
        let mut draft = self.nodes[node_ref].to_draft();
        draft.decorator_refs.before_enter.extend(decorator_refs);

        let decorated_ref = self.intern_pending_node(draft)?;
        if decorated_ref != node_ref {
            self.superseded_node_refs.insert(node_ref);
        }
        Ok(decorated_ref)
    }

    pub(crate) fn append_after_exit_refs(
        &mut self,
        node_ref: MastNodeRef,
        decorator_refs: Vec<DecoratorRef>,
    ) -> Result<MastNodeRef, Report> {
        let mut draft = self.nodes[node_ref].to_draft();
        draft.decorator_refs.after_exit.extend(decorator_refs);

        let decorated_ref = self.intern_pending_node(draft)?;
        if decorated_ref != node_ref {
            self.superseded_node_refs.insert(node_ref);
        }
        Ok(decorated_ref)
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
    !is_procedure || num_op_batches < PROCEDURE_INLINING_THRESHOLD
}

#[cfg(test)]
mod tests {
    use miden_core::operations::{DebugVarLocation, Operation};
    use proptest::prelude::*;

    use super::*;

    fn record_test_root(builder: &mut MastForestBuilder, node_ref: MastNodeRef) -> MastNodeRef {
        builder.record_procedure_root_ref(node_ref);
        node_ref
    }

    fn add_test_asm_op(builder: &mut MastForestBuilder, asm_op: AssemblyOp) -> AsmOpRef {
        builder.add_asm_op_ref(asm_op).unwrap()
    }

    fn test_asm_op(context: impl Into<String>, op: impl Into<String>) -> AssemblyOp {
        AssemblyOp::new(None, context.into(), 1, op.into())
    }

    fn test_word(value: u64) -> Word {
        Word::from([Felt::new_unchecked(value), Felt::ZERO, Felt::ZERO, Felt::ZERO])
    }

    #[derive(Debug, Clone)]
    struct GeneratedBuildStep {
        tag: u8,
        first: usize,
        second: usize,
        flags: u8,
    }

    fn generated_build_steps() -> impl Strategy<Value = Vec<GeneratedBuildStep>> {
        proptest::collection::vec((0u8..5, any::<usize>(), any::<usize>(), any::<u8>()), 1..24)
            .prop_map(|steps| {
                steps
                    .into_iter()
                    .map(|(tag, first, second, flags)| GeneratedBuildStep {
                        tag,
                        first,
                        second,
                        flags,
                    })
                    .collect()
            })
    }

    fn assert_finalization_invariants(
        forest: &MastForest,
        remapping: &BTreeMap<MastNodeRef, MastNodeId>,
    ) {
        let mut final_ids = BTreeSet::new();
        let node_count = forest.num_nodes() as usize;
        for &node_id in remapping.values() {
            assert!(node_id.to_usize() < node_count, "final node ID {node_id} must be in bounds");
            assert!(final_ids.insert(node_id), "final node ID {node_id} must resolve once");
        }

        for &root_id in forest.procedure_roots() {
            assert!(root_id.to_usize() < node_count, "procedure root {root_id} must be in bounds");
        }

        for node_idx in 0..forest.num_nodes() {
            let node_id = MastNodeId::new_unchecked(node_idx);
            let mut children = Vec::new();
            forest[node_id].append_children_to(&mut children);
            for child_id in children {
                assert!(
                    child_id.to_usize() < node_idx as usize,
                    "child {child_id} must precede parent {node_id}"
                );
            }

            for (_, asm_op_id) in forest.debug_info().asm_ops_for_node(node_id) {
                assert!(
                    forest.debug_info().asm_op(asm_op_id).is_some(),
                    "AssemblyOp ID {asm_op_id} must resolve"
                );
            }

            for (_, debug_var_id) in forest.debug_info().debug_vars_for_node(node_id) {
                assert!(
                    forest.debug_info().debug_var(debug_var_id).is_some(),
                    "debug variable ID {debug_var_id:?} must resolve"
                );
            }
        }

        let mut asm_payloads = BTreeSet::new();
        for asm_op in forest.debug_info().asm_ops() {
            let payload =
                format!("{}:{}:{}", asm_op.context_name(), asm_op.op(), asm_op.num_cycles());
            assert!(asm_payloads.insert(payload), "AssemblyOp payloads should not duplicate");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn finalization_invariants_hold_for_generated_builder_shapes(
            steps in generated_build_steps()
        ) {
            let mut builder = MastForestBuilder::new(&[]).unwrap();
            let shared_asm_op = add_test_asm_op(&mut builder, test_asm_op("generated::shared", "add"));
            let shared_debug_var = builder
                .add_debug_var_ref(DebugVarInfo::new(
                    "shared",
                    DebugVarLocation::Stack(0),
                ))
                .unwrap();

            let seed_ref = builder
                .ensure_block_ref(
                    vec![Operation::Add, Operation::Mul],
                    Vec::new(),
                    vec![(0, shared_asm_op), (1, shared_asm_op)],
                    vec![(0, shared_debug_var)],
                    vec![],
                    vec![],
                )
                .unwrap();
            record_test_root(&mut builder, seed_ref);

            let mut node_refs = vec![seed_ref];
            for (step_idx, step) in steps.iter().enumerate() {
                let first_ref = node_refs[step.first % node_refs.len()];
                let second_ref = node_refs[step.second % node_refs.len()];
                let context = format!("generated::{step_idx}");
                let next_ref = match step.tag {
                    0 => {
                        let asm_op = add_test_asm_op(
                            &mut builder,
                            test_asm_op(context.clone(), "add"),
                        );
                        builder
                            .ensure_block_ref(
                                vec![Operation::Add],
                                Vec::new(),
                                vec![(0, asm_op)],
                                vec![],
                                vec![],
                                vec![],
                            )
                            .unwrap()
                    },
                    1 => builder
                        .ensure_split_node_ref(
                            [first_ref, second_ref],
                            None,
                            test_asm_op(context.clone(), "if.true"),
                        )
                        .unwrap(),
                    2 => builder
                        .ensure_loop_node_ref(
                            first_ref,
                            None,
                            test_asm_op(context.clone(), "begin"),
                        )
                        .unwrap(),
                    3 => builder
                        .ensure_call_node_ref(
                            first_ref,
                            step.flags & 1 == 1,
                            test_asm_op(context.clone(), "call"),
                        )
                        .unwrap(),
                    _ => builder
                        .join_node_refs(
                            vec![first_ref, second_ref],
                            Some(test_asm_op(context.clone(), "begin")),
                        )
                        .unwrap(),
                };

                if step.flags & 2 == 2 {
                    record_test_root(&mut builder, next_ref);
                }
                node_refs.push(next_ref);
            }

            record_test_root(&mut builder, *node_refs.last().unwrap());

            let (forest, remapping) = builder.build().unwrap().into_parts();
            assert_finalization_invariants(&forest, &remapping);
        }
    }

    #[test]
    fn deterministic_stress_builds_deep_repeated_metadata_forest() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();
        let shared_asm_op = add_test_asm_op(&mut builder, test_asm_op("stress::shared", "base"));
        let shared_debug_var = builder
            .add_debug_var_ref(DebugVarInfo::new("shared", DebugVarLocation::Stack(0)))
            .unwrap();
        let shared_decorator = builder.ensure_decorator_ref(Decorator::Trace(1)).unwrap();

        let base_ref = builder
            .ensure_block_ref(
                vec![Operation::Add, Operation::Mul],
                vec![(0, shared_decorator)],
                vec![(0, shared_asm_op), (1, shared_asm_op)],
                vec![(0, shared_debug_var)],
                vec![],
                vec![],
            )
            .unwrap();

        let mut alias_refs = Vec::new();
        for idx in 0..48 {
            let decorator = builder.ensure_decorator_ref(Decorator::Trace(1_000 + idx)).unwrap();
            let alias_ref =
                builder.clone_node_with_before_enter_refs(base_ref, vec![decorator]).unwrap();
            if idx.is_multiple_of(12) {
                record_test_root(&mut builder, alias_ref);
            }
            alias_refs.push(alias_ref);
        }

        let wide_ref = builder.join_node_refs(alias_refs, None).unwrap();
        record_test_root(&mut builder, wide_ref);

        let mut deep_ref = wide_ref;
        for idx in 0..96 {
            let decorator = builder.ensure_decorator_ref(Decorator::Trace(2_000 + idx)).unwrap();
            let context = format!("stress::deep::{idx}");
            deep_ref = match idx % 3 {
                0 => builder
                    .ensure_loop_node_ref(
                        deep_ref,
                        Some(vec![decorator]),
                        test_asm_op(context, "while.true"),
                    )
                    .unwrap(),
                1 => builder
                    .ensure_call_node_ref(deep_ref, false, test_asm_op(context, "call"))
                    .unwrap(),
                _ => builder
                    .ensure_split_node_ref(
                        [deep_ref, base_ref],
                        Some(vec![decorator]),
                        test_asm_op(context, "if.true"),
                    )
                    .unwrap(),
            };
            if idx.is_multiple_of(24) {
                record_test_root(&mut builder, deep_ref);
            }
        }
        record_test_root(&mut builder, deep_ref);

        let superseded_asm_op =
            add_test_asm_op(&mut builder, test_asm_op("stress::superseded", "base"));
        let superseded_debug_var = builder
            .add_debug_var_ref(DebugVarInfo::new("superseded", DebugVarLocation::Stack(1)))
            .unwrap();
        let superseded_seed = builder
            .ensure_block_ref(
                vec![Operation::Add],
                Vec::new(),
                vec![(0, superseded_asm_op)],
                vec![(0, superseded_debug_var)],
                vec![],
                vec![],
            )
            .unwrap();

        let mut superseded_cursor = superseded_seed;
        let mut expected_removed_refs = Vec::new();
        for idx in 0..32 {
            let decorator = builder.ensure_decorator_ref(Decorator::Trace(3_000 + idx)).unwrap();
            let next_ref =
                builder.append_before_enter_refs(superseded_cursor, vec![decorator]).unwrap();
            expected_removed_refs.push(superseded_cursor);
            superseded_cursor = next_ref;
        }
        record_test_root(&mut builder, superseded_cursor);

        let pending_node_count = builder.nodes.len();
        let pending_decorator_count = builder.decorators.len();
        let (forest, remapping) = builder.build().unwrap().into_parts();

        assert_finalization_invariants(&forest, &remapping);
        assert!(forest.num_nodes() as usize > 100);
        assert!((forest.num_nodes() as usize) < pending_node_count);
        assert!(forest.debug_info().asm_ops().len() >= 98);
        assert_eq!(forest.debug_info().num_debug_vars(), 2);
        assert_eq!(forest.debug_info().num_decorators(), 145);
        assert!(forest.debug_info().num_decorators() < pending_decorator_count);
        assert!(remapping.contains_key(&superseded_cursor));
        for removed_ref in expected_removed_refs {
            assert!(
                !remapping.contains_key(&removed_ref),
                "superseded ref {removed_ref} should not be materialized"
            );
        }
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
        let block1_decorator1 = builder.ensure_decorator_ref(Decorator::Trace(1)).unwrap();
        let block1_decorator2 = builder.ensure_decorator_ref(Decorator::Trace(2)).unwrap();
        let block1_decorator3 = builder.ensure_decorator_ref(Decorator::Trace(3)).unwrap();
        let block1_decorators = vec![
            (0, block1_decorator1), // Decorator for Push(1)
            (7, block1_decorator2), // Decorator for Push(2)
            (8, block1_decorator3), // Decorator for Push(3) at index 8
        ];

        let block1_ref = builder
            .ensure_block_ref(block1_ops, block1_decorators, vec![], vec![], vec![], vec![])
            .unwrap();

        // Sanity check the test itself makes sense.
        let block1_op_batches = builder.nodes[block1_ref]
            .kind
            .basic_block_op_batches()
            .expect("expected basic block");
        assert!(block1_op_batches.iter().flat_map(OpBatch::ops).count() > block1_raw_ops_len);
        assert_eq!(block1_op_batches.iter().flat_map(OpBatch::raw_ops).count(), block1_raw_ops_len); // merging, which uses raw_ops, will elide padding

        // Create second block with operations
        // Block2: [Push(4), Mul]
        let block2_ops = vec![Operation::Push(Felt::new_unchecked(4)), Operation::Mul];

        // Add decorators for each operation in block2
        let block2_decorator1 = builder.ensure_decorator_ref(Decorator::Trace(4)).unwrap();
        let block2_decorator2 = builder.ensure_decorator_ref(Decorator::Trace(5)).unwrap();
        let block2_decorators = vec![
            (0, block2_decorator1), // Decorator for Push(4)
            (1, block2_decorator2), // Decorator for Mul
        ]; // [push mul] [3]

        let block2_ref = builder
            .ensure_block_ref(block2_ops, block2_decorators, vec![], vec![], vec![], vec![])
            .unwrap();

        // Merge the blocks
        let merged_blocks = builder.merge_basic_block_refs(&[block1_ref, block2_ref]).unwrap();

        // There should be one merged block
        assert_eq!(merged_blocks.len(), 1);
        let merged_block_ref = merged_blocks[0];

        let merged_block_op_batches = builder.nodes[merged_block_ref]
            .kind
            .basic_block_op_batches()
            .expect("expected basic block");

        // Merged block: two groups
        // [push drop drop drop drop drop drop push noop] [1] [2] [push push mul] [3] [4] [noop]
        // [noop]

        // Build mapping: original operation index -> decorator trace value
        // For block1: operation 0 -> Trace(1), operation 7 -> Trace(2), operation 8 -> Trace(3)
        // For block2: operation 0 -> Trace(4), operation 1 -> Trace(5)

        // Check each decorator in the merged block.
        let decorators = BasicBlockNode::unadjust_asm_op_indices(
            builder.nodes[merged_block_ref].decorator_refs.indexed.clone(),
            merged_block_op_batches,
        );
        let decorator_count = decorators.len();

        assert_eq!(decorator_count, 5); // 3 from block1 + 2 from block2

        // Create a map to track which trace values we've found
        let mut found_traces = std::collections::HashSet::new();

        // Check each decorator
        for (op_idx, decorator_ref) in decorators {
            let decorator = &builder.decorators[decorator_ref];

            match decorator {
                Decorator::Trace(trace_value) => {
                    // Record that we found this trace
                    found_traces.insert(*trace_value);

                    // Verify that the decorator points to the expected operation type
                    // Get the raw operations to check what's at this index
                    let merged_ops: Vec<Operation> = merged_block_op_batches
                        .iter()
                        .flat_map(OpBatch::raw_ops)
                        .copied()
                        .collect();

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
                            8 => {
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
                            9 => {
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
                            10 => {
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
        let large_block_ref = builder
            .ensure_block_ref(large_ops, Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();
        builder.record_procedure_root_ref(large_block_ref);

        let small_block_ref = builder
            .ensure_block_ref(vec![Operation::Add], Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();

        let merged_blocks =
            builder.merge_basic_block_refs(&[large_block_ref, small_block_ref]).unwrap();

        assert_eq!(merged_blocks.len(), 2);
        assert_eq!(merged_blocks[0], large_block_ref);
        assert_eq!(merged_blocks[1], small_block_ref);
    }

    #[test]
    fn test_merge_basic_blocks_preserves_trailing_after_exit_decorator() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let first_block_ref = builder
            .ensure_block_ref(vec![Operation::Add], Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();
        let after_exit_decorator = builder.ensure_decorator_ref(Decorator::Trace(7)).unwrap();
        let second_block_ref = builder
            .ensure_block_ref(
                vec![Operation::Mul],
                Vec::new(),
                vec![],
                vec![],
                vec![],
                vec![after_exit_decorator],
            )
            .unwrap();

        let merged_blocks =
            builder.merge_basic_block_refs(&[first_block_ref, second_block_ref]).unwrap();

        assert_eq!(merged_blocks.len(), 1);
        let merged_block_ref = merged_blocks[0];
        let (forest, remapping) = builder.build().unwrap().into_parts();
        let merged_block_id = remapping[&merged_block_ref];
        let merged_block = forest[merged_block_id].unwrap_basic_block();

        assert!(merged_block.indexed_decorator_iter(&forest).next().is_none());
        let after_exit_traces = forest
            .after_exit_decorators(merged_block_id)
            .iter()
            .map(|&decorator_id| match forest[decorator_id] {
                Decorator::Trace(value) => value,
                ref decorator => panic!("expected trace decorator, got {decorator:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(after_exit_traces, vec![7]);
    }

    #[test]
    fn test_merge_basic_blocks_places_boundary_after_exit_before_next_before_enter() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let first_after_exit = builder.ensure_decorator_ref(Decorator::Trace(1)).unwrap();
        let first_block_ref = builder
            .ensure_block_ref(
                vec![Operation::Add],
                Vec::new(),
                vec![],
                vec![],
                vec![],
                vec![first_after_exit],
            )
            .unwrap();

        let second_before_enter = builder.ensure_decorator_ref(Decorator::Trace(2)).unwrap();
        let second_block_ref = builder
            .ensure_block_ref(
                vec![Operation::Mul],
                Vec::new(),
                vec![],
                vec![],
                vec![second_before_enter],
                vec![],
            )
            .unwrap();

        let merged_blocks =
            builder.merge_basic_block_refs(&[first_block_ref, second_block_ref]).unwrap();

        assert_eq!(merged_blocks.len(), 1);
        let merged_block_ref = merged_blocks[0];
        let (forest, remapping) = builder.build().unwrap().into_parts();
        let merged_block_id = remapping[&merged_block_ref];
        let merged_block = forest[merged_block_id].unwrap_basic_block();
        let decorator_traces = merged_block
            .indexed_decorator_iter(&forest)
            .map(|(op_idx, decorator_id)| {
                let trace = match forest[decorator_id] {
                    Decorator::Trace(value) => value,
                    ref decorator => panic!("expected trace decorator, got {decorator:?}"),
                };
                (op_idx, trace)
            })
            .collect::<Vec<_>>();

        assert_eq!(decorator_traces, vec![(1, 1), (1, 2)]);
        assert!(forest.after_exit_decorators(merged_block_id).is_empty());
    }

    #[test]
    fn ensure_block_rejects_decorator_index_beyond_operation_count_without_panicking() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();
        let decorator_ref = builder.ensure_decorator_ref(Decorator::Trace(42)).unwrap();

        let result = builder.ensure_block_ref(
            vec![Operation::Add],
            vec![(2, decorator_ref)],
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
        let decorator_ref = builder.ensure_decorator_ref(Decorator::Trace(42)).unwrap();

        let result = builder.ensure_block_ref(
            vec![Operation::Add],
            vec![(1, decorator_ref)],
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

        let root_block_ref = builder
            .ensure_block_ref(vec![Operation::Add], Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();
        builder.record_procedure_root_ref(root_block_ref);
        let root_digest = builder.nodes[root_block_ref].digest;

        let tail_block_ref = builder
            .ensure_block_ref(vec![Operation::Mul], Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();

        let merged_blocks =
            builder.merge_basic_block_refs(&[root_block_ref, tail_block_ref]).unwrap();
        assert_eq!(merged_blocks.len(), 1);
        assert_ne!(merged_blocks[0], root_block_ref);

        let (forest, remapping) = builder.build().unwrap().into_parts();
        let final_root_id = remapping[&root_block_ref];

        assert!(forest.is_procedure_root(final_root_id));
        assert_eq!(forest[final_root_id].digest(), root_digest);
    }

    #[test]
    fn test_build_orders_external_nodes_before_non_external_nodes() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let block_ref = builder
            .ensure_block_ref(vec![Operation::Add], Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();
        record_test_root(&mut builder, block_ref);

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

        let (forest, remapping) = builder.build().unwrap().into_parts();

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

        let true_ref = builder
            .ensure_block_ref(vec![Operation::Add], Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();
        let false_ref = builder
            .ensure_block_ref(vec![Operation::Mul], Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();

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

        let (forest, remapping) = builder.build().unwrap().into_parts();

        assert_eq!(before_enter_traces(&forest, remapping[&split_ref]), vec![10, 20]);
        assert_eq!(after_exit_traces(&forest, remapping[&split_ref]), vec![30]);
        assert_eq!(before_enter_traces(&forest, remapping[&loop_ref]), vec![10, 20, 30]);
    }

    #[test]
    fn test_merge_basic_blocks_keeps_recorded_root_block_standalone() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let num_ops = PROCEDURE_INLINING_THRESHOLD * 1024;
        let large_ops = vec![Operation::Add; num_ops];
        let large_block_ref = builder
            .ensure_block_ref(large_ops, Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();
        builder.record_procedure_root_ref(large_block_ref);

        let small_block_ref = builder
            .ensure_block_ref(vec![Operation::Add], Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();

        let merged_blocks =
            builder.merge_basic_block_refs(&[large_block_ref, small_block_ref]).unwrap();

        assert_eq!(merged_blocks.len(), 2);
        assert_eq!(merged_blocks[0], large_block_ref);
        assert_eq!(merged_blocks[1], small_block_ref);
    }

    /// Cloning a block with debug vars and new before-enter decorators must propagate those vars
    /// to the new node (exercises the assembler repeat path).
    #[test]
    fn test_ensure_node_preserving_debug_vars_on_cloned_block() {
        use miden_core::operations::{DebugVarInfo, DebugVarLocation};

        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let var_ref = builder
            .add_debug_var_ref(DebugVarInfo::new("x", DebugVarLocation::Stack(0)))
            .unwrap();

        let block_ref = builder
            .ensure_block_ref(
                vec![Operation::Add],
                Vec::new(),
                vec![],
                vec![(0, var_ref)],
                vec![],
                vec![],
            )
            .unwrap();

        let decorator_ref = builder.ensure_decorator_ref(Decorator::Trace(42)).unwrap();

        // Simulate the repeat path: clone + add before_enter + preserve debug vars.
        let cloned_ref = builder
            .clone_node_with_before_enter_refs(block_ref, vec![decorator_ref])
            .unwrap();

        assert_ne!(cloned_ref, block_ref);

        let (forest, remapping) = builder.build().unwrap().into_parts();
        let final_cloned_id = remapping[&cloned_ref];

        let cloned_vars = forest.debug_info().debug_vars_for_node(final_cloned_id);
        assert_eq!(cloned_vars.len(), 1, "cloned node should have debug vars");
        assert_eq!(forest.debug_info().debug_var(cloned_vars[0].1).unwrap().name(), "x");
        assert!(!remapping.contains_key(&block_ref), "unreachable source node should be removed");
    }

    #[test]
    fn test_decorated_replacement_drops_unreachable_source_node() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let block_ref = builder
            .ensure_block_ref(vec![Operation::Add], Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();
        let decorator_ref = builder.ensure_decorator_ref(Decorator::Trace(42)).unwrap();
        let decorated_ref =
            builder.append_before_enter_refs(block_ref, vec![decorator_ref]).unwrap();
        builder.record_procedure_root_ref(decorated_ref);

        let (_forest, remapping) = builder.build().unwrap().into_parts();
        assert!(remapping.contains_key(&decorated_ref));
        assert!(!remapping.contains_key(&block_ref));
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
        let block_a_ref = builder
            .ensure_block_ref(
                vec![Operation::Add],
                Vec::new(),
                vec![],
                vec![(0, var_x_ref)],
                vec![],
                vec![],
            )
            .unwrap();
        let block_b_ref = builder
            .ensure_block_ref(
                vec![Operation::Add],
                Vec::new(),
                vec![],
                vec![(0, var_y_ref)],
                vec![],
                vec![],
            )
            .unwrap();

        assert_ne!(block_a_ref, block_b_ref);

        let decorator_ref = builder.ensure_decorator_ref(Decorator::Trace(1)).unwrap();

        let cloned_a_ref = builder
            .clone_node_with_before_enter_refs(block_a_ref, vec![decorator_ref])
            .unwrap();
        let cloned_b_ref = builder
            .clone_node_with_before_enter_refs(block_b_ref, vec![decorator_ref])
            .unwrap();

        assert_ne!(cloned_a_ref, cloned_b_ref, "different debug vars must prevent dedup");

        let (forest, remapping) = builder.build().unwrap().into_parts();
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
            .ensure_block_ref(
                vec![Operation::Add],
                Vec::new(),
                vec![],
                vec![(0, var_a)],
                vec![],
                vec![],
            )
            .unwrap();
        let block_b = builder
            .ensure_block_ref(
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
        let block_ref = builder
            .ensure_block_ref(
                vec![Operation::Add],
                Vec::new(),
                vec![],
                vec![(0, used_var)],
                vec![],
                vec![],
            )
            .unwrap();

        let (forest, remapping) = builder.build().unwrap().into_parts();
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

        let asm_op_a =
            add_test_asm_op(&mut builder, AssemblyOp::new(None, "ctx_a".into(), 1, "add".into()));
        let asm_op_b =
            add_test_asm_op(&mut builder, AssemblyOp::new(None, "ctx_b".into(), 1, "add".into()));

        let block_a_ref = builder
            .ensure_block_ref(
                vec![Operation::Add],
                Vec::new(),
                vec![(0, asm_op_a)],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();
        let block_b_ref = builder
            .ensure_block_ref(
                vec![Operation::Add],
                Vec::new(),
                vec![(0, asm_op_b)],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();

        assert_ne!(
            block_a_ref, block_b_ref,
            "same op stream plus different AssemblyOp payload must not dedup"
        );

        let (forest, remapping) = builder.build().unwrap().into_parts();
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

        let callee_ref = builder
            .ensure_block_ref(vec![Operation::Add], Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();
        let call_a_ref = builder
            .ensure_call_node_ref(
                callee_ref,
                false,
                AssemblyOp::new(None, "ctx_a".into(), 1, "call.foo".into()),
            )
            .unwrap();
        let call_b_ref = builder
            .ensure_call_node_ref(
                callee_ref,
                false,
                AssemblyOp::new(None, "ctx_b".into(), 1, "call.foo".into()),
            )
            .unwrap();

        assert_ne!(
            call_a_ref, call_b_ref,
            "same-structure non-block nodes with different AssemblyOps must not dedup"
        );

        let (forest, remapping) = builder.build().unwrap().into_parts();
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

    /// Cloning a block with AssemblyOps and new before-enter decorators must preserve those asm
    /// ops on the new node.
    #[test]
    fn test_ensure_node_preserving_debug_vars_on_cloned_block_keeps_asm_ops() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let asm_op_ref =
            add_test_asm_op(&mut builder, AssemblyOp::new(None, "ctx".into(), 1, "add".into()));

        let block_ref = builder
            .ensure_block_ref(
                vec![Operation::Add],
                Vec::new(),
                vec![(0, asm_op_ref)],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();

        let decorator_ref = builder.ensure_decorator_ref(Decorator::Trace(7)).unwrap();

        let cloned_ref = builder
            .clone_node_with_before_enter_refs(block_ref, vec![decorator_ref])
            .unwrap();

        assert_ne!(cloned_ref, block_ref);

        let (forest, remapping) = builder.build().unwrap().into_parts();
        let final_cloned_id = remapping[&cloned_ref];

        assert_eq!(
            forest
                .debug_info()
                .first_asm_op_for_node(final_cloned_id)
                .unwrap()
                .context_name(),
            "ctx"
        );
        assert!(!remapping.contains_key(&block_ref), "unreachable source node should be removed");
    }

    /// Statically linked nodes must keep source metadata in the dedup fingerprint so copied
    /// nodes do not alias local nodes with different source mappings.
    #[test]
    fn test_statically_linked_nodes_preserve_metadata_in_dedup() {
        use miden_core::operations::{DebugVarInfo, DebugVarLocation};

        let mut debug_info = DebugInfo::new();
        let static_asm_op_id = debug_info
            .add_asm_op(AssemblyOp::new(None, "lib_ctx".into(), 1, "add".into()))
            .unwrap();
        let static_var_id = debug_info
            .add_debug_var(DebugVarInfo::new("x", DebugVarLocation::Stack(0)))
            .unwrap();
        let static_block_id = MastNodeId::new_unchecked(0);
        debug_info
            .register_asm_ops(static_block_id, 1, vec![(0, static_asm_op_id)])
            .unwrap();
        debug_info
            .register_op_indexed_debug_vars(static_block_id, vec![(0, static_var_id)])
            .unwrap();

        let mut nodes = IndexVec::new();
        let inserted_node_id = nodes
            .push(
                MastNodeBuilder::BasicBlock(BasicBlockNodeBuilder::new(
                    vec![Operation::Add],
                    Vec::new(),
                ))
                .build_linked(static_block_id)
                .unwrap(),
            )
            .unwrap();
        assert_eq!(inserted_node_id, static_block_id);
        let static_forest = MastForest::from_parts(MastForestParts {
            nodes,
            roots: vec![static_block_id],
            advice_map: AdviceMap::default(),
            debug_info,
        })
        .unwrap();

        let mut builder = MastForestBuilder::new([&static_forest]).unwrap();
        let copied_block_ref = builder
            .ensure_external_link_with_source_ref(
                static_forest[static_block_id].digest(),
                None,
                None,
            )
            .unwrap();

        let local_var_ref = builder
            .add_debug_var_ref(DebugVarInfo::new("y", DebugVarLocation::Stack(1)))
            .unwrap();
        let local_asm_op_ref = add_test_asm_op(
            &mut builder,
            AssemblyOp::new(None, "local_ctx".into(), 1, "add".into()),
        );
        let local_block_ref = builder
            .ensure_block_ref(
                vec![Operation::Add],
                Vec::new(),
                vec![(0, local_asm_op_ref)],
                vec![(0, local_var_ref)],
                vec![],
                vec![],
            )
            .unwrap();

        assert_ne!(
            copied_block_ref, local_block_ref,
            "statically linked nodes must not alias local nodes with different metadata"
        );

        let (forest, remapping) = builder.build().unwrap().into_parts();
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

        let static_asm_op_ref = add_test_asm_op(&mut source_builder, asm_op.clone());
        let static_block_ref = source_builder
            .ensure_block_ref(
                ops.clone(),
                Vec::new(),
                vec![(8, static_asm_op_ref)],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();
        record_test_root(&mut source_builder, static_block_ref);

        let (static_forest, source_remapping) = source_builder.build().unwrap().into_parts();
        let final_static_block = source_remapping[&static_block_ref];
        let expected_padded_idx =
            static_forest.debug_info().asm_ops_for_node(final_static_block)[0].0;

        let mut builder = MastForestBuilder::new([&static_forest]).unwrap();
        let copied_block_ref = builder
            .ensure_external_link_with_source_ref(
                static_forest[final_static_block].digest(),
                None,
                None,
            )
            .unwrap();
        let local_asm_op_ref = add_test_asm_op(&mut builder, asm_op);
        let local_block_ref = builder
            .ensure_block_ref(ops, Vec::new(), vec![(8, local_asm_op_ref)], vec![], vec![], vec![])
            .unwrap();

        assert_eq!(
            copied_block_ref, local_block_ref,
            "copied padded blocks should dedup with equivalent local blocks",
        );

        let (forest, remapping) = builder.build().unwrap().into_parts();
        let final_block_id = remapping[&copied_block_ref];

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
        let asm_op_ref =
            add_test_asm_op(&mut builder, AssemblyOp::new(None, "test".into(), 1, "add".into()));

        // Small block that will be a procedure root -- should_merge returns true for
        // small roots, so it will be folded into the merged block.
        let root_block_ref = builder
            .ensure_block_ref(
                vec![Operation::Add],
                Vec::new(),
                vec![(0, asm_op_ref)],
                vec![(0, var_ref)],
                vec![],
                vec![],
            )
            .unwrap();
        builder.record_procedure_root_ref(root_block_ref);

        // Second block to merge with.
        let other_block_ref = builder
            .ensure_block_ref(vec![Operation::Mul], Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();

        let merged = builder.merge_basic_block_refs(&[root_block_ref, other_block_ref]).unwrap();
        // Root was small enough to merge, so we get one merged block.
        assert_eq!(merged.len(), 1);
        let merged_ref = merged[0];
        assert_ne!(merged_ref, root_block_ref);

        let (forest, remapping) = builder.build().unwrap().into_parts();

        // The root block survives removal (it's a procedure root).
        let final_root_id = remapping[&root_block_ref];
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

        let alias_a_asm_op = add_test_asm_op(
            &mut source_builder,
            AssemblyOp::new(None, "alias_a".into(), 1, "add".into()),
        );
        let alias_b_asm_op = add_test_asm_op(
            &mut source_builder,
            AssemblyOp::new(None, "alias_b".into(), 1, "add".into()),
        );
        let alias_a_ref = source_builder
            .ensure_block_ref(
                vec![Operation::Add],
                Vec::new(),
                vec![(0, alias_a_asm_op)],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();
        let alias_b_ref = source_builder
            .ensure_block_ref(
                vec![Operation::Add],
                Vec::new(),
                vec![(0, alias_b_asm_op)],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();
        record_test_root(&mut source_builder, alias_a_ref);
        record_test_root(&mut source_builder, alias_b_ref);

        let (static_forest, source_remapping) = source_builder.build().unwrap().into_parts();
        let final_alias_a = source_remapping[&alias_a_ref];
        let final_alias_b = source_remapping[&alias_b_ref];
        assert_eq!(static_forest[final_alias_a].digest(), static_forest[final_alias_b].digest());

        // Exact path via internal API — gets alias_b's metadata.
        let mut exact_builder = MastForestBuilder::new([&static_forest]).unwrap();
        let exact_alias_b_ref = {
            let node = exact_builder.statically_linked_mast[final_alias_b].clone();
            let node_refs_by_source_id = BTreeMap::new();
            let mut decorator_refs_by_source_id = BTreeMap::new();
            let (child_refs, decorator_refs) = exact_builder
                .pending_refs_for_statically_linked_source(
                    final_alias_b,
                    &node,
                    &node_refs_by_source_id,
                    &mut decorator_refs_by_source_id,
                )
                .unwrap();
            exact_builder
                .ensure_node_from_statically_linked_source_ref(
                    final_alias_b,
                    node,
                    child_refs,
                    decorator_refs,
                )
                .unwrap()
        };
        let (exact_forest, exact_remapping) = exact_builder.build().unwrap().into_parts();
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

        let alias_a_asm_op = add_test_asm_op(
            &mut source_builder,
            AssemblyOp::new(None, "alias_a".into(), 1, "add".into()),
        );
        let alias_b_asm_op = add_test_asm_op(
            &mut source_builder,
            AssemblyOp::new(None, "alias_b".into(), 1, "add".into()),
        );
        let alias_a_ref = source_builder
            .ensure_block_ref(
                vec![Operation::Add],
                Vec::new(),
                vec![(0, alias_a_asm_op)],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();
        let alias_b_ref = source_builder
            .ensure_block_ref(
                vec![Operation::Add],
                Vec::new(),
                vec![(0, alias_b_asm_op)],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();
        record_test_root(&mut source_builder, alias_a_ref);
        record_test_root(&mut source_builder, alias_b_ref);

        let (static_forest, source_remapping) = source_builder.build().unwrap().into_parts();
        let final_alias_a = source_remapping[&alias_a_ref];

        let mut builder = MastForestBuilder::new([&static_forest]).unwrap();
        let linked_ref = builder
            .ensure_external_link_with_source_ref(static_forest[final_alias_a].digest(), None, None)
            .unwrap();
        record_test_root(&mut builder, linked_ref);
        let (forest, remapping) = builder.build().unwrap().into_parts();
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
        let indexed_decorator = source_builder.ensure_decorator_ref(Decorator::Trace(1)).unwrap();
        let true_ref = source_builder
            .ensure_block_ref(
                vec![Operation::Add],
                vec![(0, indexed_decorator)],
                vec![],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();
        let false_ref = source_builder
            .ensure_block_ref(vec![Operation::Mul], Vec::new(), vec![], vec![], vec![], vec![])
            .unwrap();
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

        let (static_forest, source_remapping) = source_builder.build().unwrap().into_parts();
        let static_split_id = source_remapping[&split_ref];

        let mut builder = MastForestBuilder::new([&static_forest]).unwrap();
        let linked_ref = builder
            .ensure_external_link_with_source_ref(
                static_forest[static_split_id].digest(),
                Some(static_forest.commitment()),
                Some(static_split_id),
            )
            .unwrap();
        record_test_root(&mut builder, linked_ref);

        let (forest, remapping) = builder.build().unwrap().into_parts();
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

        let alias_a_asm_op = add_test_asm_op(
            &mut source_builder,
            AssemblyOp::new(None, "alias_a".into(), 1, "add".into()),
        );
        let alias_b_asm_op = add_test_asm_op(
            &mut source_builder,
            AssemblyOp::new(None, "alias_b".into(), 1, "add".into()),
        );
        let alias_a_ref = source_builder
            .ensure_block_ref(
                vec![Operation::Add],
                Vec::new(),
                vec![(0, alias_a_asm_op)],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();
        let alias_b_ref = source_builder
            .ensure_block_ref(
                vec![Operation::Add],
                Vec::new(),
                vec![(0, alias_b_asm_op)],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();
        record_test_root(&mut source_builder, alias_a_ref);
        record_test_root(&mut source_builder, alias_b_ref);

        let (static_forest, source_remapping) = source_builder.build().unwrap().into_parts();
        let final_alias_a = source_remapping[&alias_a_ref];
        let final_alias_b = source_remapping[&alias_b_ref];
        assert_eq!(static_forest[final_alias_a].digest(), static_forest[final_alias_b].digest());

        let mut exact_builder = MastForestBuilder::new([&static_forest]).unwrap();
        let exact_alias_b_ref = {
            let node = exact_builder.statically_linked_mast[final_alias_b].clone();
            let node_refs_by_source_id = BTreeMap::new();
            let mut decorator_refs_by_source_id = BTreeMap::new();
            let (child_refs, decorator_refs) = exact_builder
                .pending_refs_for_statically_linked_source(
                    final_alias_b,
                    &node,
                    &node_refs_by_source_id,
                    &mut decorator_refs_by_source_id,
                )
                .unwrap();
            exact_builder
                .ensure_node_from_statically_linked_source_ref(
                    final_alias_b,
                    node,
                    child_refs,
                    decorator_refs,
                )
                .unwrap()
        };
        let (exact_forest, exact_remapping) = exact_builder.build().unwrap().into_parts();
        let final_exact_alias_b = exact_remapping[&exact_alias_b_ref];

        let mut provenance_builder = MastForestBuilder::new([&static_forest]).unwrap();
        let linked_alias_b_ref = provenance_builder
            .ensure_external_link_with_source_ref(
                static_forest[final_alias_b].digest(),
                Some(static_forest.commitment()),
                Some(final_alias_b),
            )
            .unwrap();
        let (linked_forest, linked_remapping) = provenance_builder.build().unwrap().into_parts();
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
