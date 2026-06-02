use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use miden_core::{
    Felt, Word,
    advice::AdviceMap,
    chiplets::hasher,
    mast::{
        BasicBlockNode, BasicBlockNodeBuilder, CallNode, DynNode, JoinNode, LoopNode, MastForest,
        MastForestRootMap, MastNode, MastNodeExt, OpBatch, SplitNode, error_code_from_msg,
    },
    operations::{AssemblyOp, DebugVarInfo, Operation},
    serde::Serializable,
    utils::{Idx, IndexVec, bytes_to_packed_u32_elements},
};
use miden_mast_package::debug_info::PackageDebugInfo;

use super::{GlobalItemIndex, LinkerError, Procedure};
use crate::{
    diagnostics::{IntoDiagnostic, Report, WrapErr},
    report,
};

mod finalizer;
use finalizer::{BuiltMastForest, MastForestFinalizer};
mod node_identity_policy;
use node_identity_policy::FinalForestLayout;
mod pending_record;
pub(crate) use pending_record::{AsmOpRef, DebugVarRef, MastNodeRef, SourceMastNodeRef};
use pending_record::{
    MastNodeKey, PendingMastNode, PendingMastNodeDraft, PendingMastNodeKind, PendingSourceMastNode,
};
mod source_debug_graph;
pub(crate) use source_debug_graph::{SourceDebugGraph, SourceMastNode, SourceMastNodeId};
mod static_import;

// CONSTANTS
// ================================================================================================

/// Constant that decides how many operation batches disqualify a procedure from inlining.
const PROCEDURE_INLINING_THRESHOLD: usize = 32;

/// Domain used when basic-block interning keys must include execution-visible error codes.
const BASIC_BLOCK_ERROR_CODE_KEY_DOMAIN: Felt = Felt::new_unchecked(0x2473_0001);
/// Domain used when control-node interning keys must include child keys.
const CHILD_KEY_DOMAIN: Felt = Felt::new_unchecked(0x2473_0002);

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
    /// Procedure roots recorded by builder-local source/debug occurrence ref until finalization.
    procedure_source_root_refs: Vec<SourceMastNodeRef>,
    /// Number of source/debug occurrences already selected as procedure roots per execution ref.
    procedure_source_root_count_by_node_ref: BTreeMap<MastNodeRef, usize>,
    /// A map of MAST node interning keys to their corresponding builder-local node refs.
    node_ref_by_key: BTreeMap<MastNodeKey, MastNodeRef>,
    /// Builder-owned dense storage for node refs.
    nodes: IndexVec<MastNodeRef, PendingMastNode>,
    /// Builder-owned dense storage for source/debug occurrences.
    source_nodes: IndexVec<SourceMastNodeRef, PendingSourceMastNode>,
    /// Most recent source occurrence for each execution node ref.
    latest_source_ref_by_node_ref: BTreeMap<MastNodeRef, SourceMastNodeRef>,
    /// Source occurrences recorded for each execution node ref, in creation order.
    source_refs_by_node_ref: BTreeMap<MastNodeRef, Vec<SourceMastNodeRef>>,
    /// Builder-owned dense storage for assembly op refs.
    asm_op_by_ref: IndexVec<AsmOpRef, AssemblyOp>,
    /// Builder-owned dense storage for debug variable refs.
    debug_vars: IndexVec<DebugVarRef, DebugVarInfo>,
    /// Error codes registered while building this forest.
    error_codes: BTreeMap<u64, Arc<str>>,
    /// A MastForest that contains the MAST of all statically-linked libraries, it's used to find
    /// precompiled procedures and copy their subtrees instead of inserting external nodes.
    statically_linked_mast: Arc<MastForest>,
    /// Original statically-linked library forests, parallel to the inputs used to build
    /// `statically_linked_mast`.
    statically_linked_source_forests: Vec<Arc<MastForest>>,
    /// Package-owned debug info decoded from each statically-linked package, when available.
    statically_linked_package_debug_info: Vec<Option<PackageDebugInfo>>,
    /// Maps each statically linked source forest commitment to its positions in the merged forest
    /// root map.
    statically_linked_forest_indices_by_commitment: BTreeMap<Word, Vec<usize>>,
    /// Maps procedure roots from each source static library to their new root ID in the merged
    /// static forest.
    statically_linked_root_map: MastForestRootMap,
}

/// Statically-linked library data used by [`MastForestBuilder`].
pub(crate) struct StaticLibrary<'a> {
    pub(crate) mast: &'a MastForest,
    pub(crate) debug_info: Option<PackageDebugInfo>,
}

impl<'a> StaticLibrary<'a> {
    pub(crate) fn new(mast: &'a MastForest, debug_info: Option<PackageDebugInfo>) -> Self {
        Self { mast, debug_info }
    }
}

impl MastForestBuilder {
    /// Creates a new builder which will transitively include the MAST of any procedures referenced
    /// in the provided set of statically-linked libraries.
    ///
    /// In all other cases, references to procedures not present in the main MastForest are assumed
    /// to be dynamically-linked, and are inserted as an external node. Dynamically-linked libraries
    /// must be provided separately to the processor at runtime.
    #[allow(dead_code)]
    pub fn new<'a>(
        static_libraries: impl IntoIterator<Item = &'a MastForest>,
    ) -> Result<Self, Report> {
        Self::new_with_static_libraries(
            static_libraries.into_iter().map(|mast| StaticLibrary::new(mast, None)),
        )
    }

    pub(crate) fn new_with_static_libraries<'a>(
        static_libraries: impl IntoIterator<Item = StaticLibrary<'a>>,
    ) -> Result<Self, Report> {
        // All statically-linked libraries are merged into a single MastForest.
        let static_libraries = static_libraries.into_iter().collect::<Vec<_>>();
        let forests = static_libraries.iter().map(|library| library.mast).collect::<Vec<_>>();
        let statically_linked_source_forests = static_libraries
            .iter()
            .map(|library| Arc::new(library.mast.clone()))
            .collect::<Vec<_>>();
        let statically_linked_package_debug_info = static_libraries
            .into_iter()
            .map(|library| library.debug_info)
            .collect::<Vec<_>>();
        let mut statically_linked_forest_indices_by_commitment = BTreeMap::new();
        for (idx, forest) in forests.iter().enumerate() {
            statically_linked_forest_indices_by_commitment
                .entry(forest.commitment())
                .or_insert_with(Vec::new)
                .push(idx);
        }
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
            statically_linked_source_forests,
            statically_linked_package_debug_info,
            statically_linked_forest_indices_by_commitment,
            statically_linked_root_map,
            ..Self::default()
        })
    }

    fn push_pending_node_record_ref(
        &mut self,
        key: MastNodeKey,
        draft: PendingMastNodeDraft,
    ) -> Result<MastNodeRef, Report> {
        let node_ref = self
            .nodes
            .push(PendingMastNode {
                key,
                digest: draft.digest,
                kind: draft.kind,
                child_refs: draft.child_refs,
                asm_ops: draft.asm_ops,
                debug_vars: draft.debug_vars,
            })
            .into_diagnostic()
            .wrap_err("assembler created too many MAST nodes")?;

        Ok(node_ref)
    }

    fn insert_pending_node_record_ref(
        &mut self,
        key: MastNodeKey,
        draft: PendingMastNodeDraft,
    ) -> Result<MastNodeRef, Report> {
        let node_ref = self.push_pending_node_record_ref(key, draft)?;

        self.node_ref_by_key.insert(key, node_ref);
        Ok(node_ref)
    }

    fn dedup_key_for_pending_data(&self, draft: &PendingMastNodeDraft) -> MastNodeKey {
        self.key_for_pending_record(draft.digest, &draft.kind, &draft.child_refs)
    }

    fn intern_pending_node(&mut self, draft: PendingMastNodeDraft) -> Result<MastNodeRef, Report> {
        let dedup_key = self.dedup_key_for_pending_data(&draft);
        let source_child_refs = self.source_child_refs_for_node_refs(&draft.child_refs);
        let node_ref = if let Some(node_ref) = self.find_node_ref_by_key(&dedup_key) {
            if self.should_replace_pending_node(node_ref, &draft) {
                self.replace_pending_node_record_ref(node_ref, dedup_key, draft.clone());
            }
            node_ref
        } else {
            self.insert_pending_node_record_ref(dedup_key, draft.clone())?
        };

        self.record_source_occurrence(node_ref, source_child_refs, &draft)?;
        Ok(node_ref)
    }

    fn insert_pending_node_with_allocated_metadata_refs(
        &mut self,
        dedup_key: MastNodeKey,
        draft: PendingMastNodeDraft,
        asm_op_checkpoint: usize,
        debug_var_checkpoint: usize,
    ) -> Result<MastNodeRef, Report> {
        match self.insert_or_replace_pending_node_record_ref(dedup_key, draft) {
            Ok(node_ref) => Ok(node_ref),
            Err(err) => {
                truncate_index_vec(&mut self.asm_op_by_ref, asm_op_checkpoint);
                truncate_index_vec(&mut self.debug_vars, debug_var_checkpoint);
                Err(err)
            },
        }
    }

    fn find_node_ref_by_key(&self, key: &MastNodeKey) -> Option<MastNodeRef> {
        self.node_ref_by_key.get(key).copied()
    }

    fn find_reusable_node_ref_by_key(
        &self,
        key: &MastNodeKey,
        draft: &PendingMastNodeDraft,
    ) -> Option<MastNodeRef> {
        self.find_node_ref_by_key(key)
            .filter(|&node_ref| !self.should_replace_pending_node(node_ref, draft))
    }

    fn should_replace_pending_node(
        &self,
        existing_ref: MastNodeRef,
        draft: &PendingMastNodeDraft,
    ) -> bool {
        self.nodes[existing_ref].kind.is_external() && !draft.kind.is_external()
    }

    fn replace_pending_node_record_ref(
        &mut self,
        node_ref: MastNodeRef,
        key: MastNodeKey,
        draft: PendingMastNodeDraft,
    ) {
        self.nodes[node_ref] = PendingMastNode {
            key,
            digest: draft.digest,
            kind: draft.kind,
            child_refs: draft.child_refs,
            asm_ops: draft.asm_ops,
            debug_vars: draft.debug_vars,
        };
        self.node_ref_by_key.insert(key, node_ref);
    }

    fn insert_or_replace_pending_node_record_ref(
        &mut self,
        key: MastNodeKey,
        draft: PendingMastNodeDraft,
    ) -> Result<MastNodeRef, Report> {
        if let Some(node_ref) = self.find_node_ref_by_key(&key) {
            if self.should_replace_pending_node(node_ref, &draft) {
                self.replace_pending_node_record_ref(node_ref, key, draft);
            }
            Ok(node_ref)
        } else {
            self.insert_pending_node_record_ref(key, draft)
        }
    }

    fn key_from_pending_refs(&self, node_digest: Word, child_refs: &[MastNodeRef]) -> MastNodeKey {
        let mut has_non_digest_child = false;
        let mut elements = Vec::with_capacity(1 + 4 + child_refs.len() * 4);
        elements.push(CHILD_KEY_DOMAIN);
        elements.extend_from_slice(node_digest.as_elements());

        for &child_ref in child_refs {
            let child = &self.nodes[child_ref];
            has_non_digest_child |= child.key != child.digest;
            elements.extend_from_slice(child.key.as_elements());
        }

        if has_non_digest_child {
            hasher::hash_elements(&elements)
        } else {
            node_digest
        }
    }

    fn key_for_pending_record(
        &self,
        digest: Word,
        kind: &PendingMastNodeKind,
        child_refs: &[MastNodeRef],
    ) -> MastNodeKey {
        if let Some(op_batches) = kind.basic_block_op_batches() {
            self.key_for_pending_basic_block(digest, op_batches)
        } else {
            self.key_from_pending_refs(digest, child_refs)
        }
    }

    fn key_for_pending_basic_block(
        &self,
        block_digest: Word,
        op_batches: &[OpBatch],
    ) -> MastNodeKey {
        debug_assert!(!op_batches.is_empty());
        let error_code_data = serialize_basic_block_error_codes(op_batches);
        if error_code_data.is_empty() {
            return block_digest;
        }

        let data_len = error_code_data.len() as u64;
        let mut elements = Vec::with_capacity(7 + error_code_data.len().div_ceil(4));
        elements.push(BASIC_BLOCK_ERROR_CODE_KEY_DOMAIN);
        elements.extend_from_slice(block_digest.as_elements());
        elements.push(Felt::from_u32(data_len as u32));
        elements.push(Felt::from_u32((data_len >> 32) as u32));
        elements.extend(bytes_to_packed_u32_elements(&error_code_data));
        hasher::hash_elements(&elements)
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

    fn indexed_asm_op_refs(
        &mut self,
        asm_ops: Vec<(usize, AssemblyOp)>,
    ) -> Result<Vec<(usize, AsmOpRef)>, Report> {
        asm_ops
            .into_iter()
            .map(|(op_idx, asm_op)| self.add_asm_op_ref(asm_op).map(|asm_ref| (op_idx, asm_ref)))
            .collect()
    }

    fn indexed_debug_var_refs(
        &mut self,
        debug_vars: Vec<(usize, DebugVarInfo)>,
    ) -> Result<Vec<(usize, DebugVarRef)>, Report> {
        debug_vars
            .into_iter()
            .map(|(op_idx, debug_var)| {
                self.add_debug_var_ref(debug_var).map(|debug_var_ref| (op_idx, debug_var_ref))
            })
            .collect()
    }

    fn intern_pending_node_with_asm_op(
        &mut self,
        mut draft: PendingMastNodeDraft,
        asm_op: AssemblyOp,
    ) -> Result<MastNodeRef, Report> {
        let dedup_key = self.dedup_key_for_pending_data(&draft);
        let source_child_refs = self.source_child_refs_for_node_refs(&draft.child_refs);

        let asm_op_checkpoint = self.asm_op_by_ref.len();
        let debug_var_checkpoint = self.debug_vars.len();
        draft.asm_ops = self.indexed_asm_op_refs(vec![(0, asm_op)])?;
        let node_ref =
            if let Some(node_ref) = self.find_reusable_node_ref_by_key(&dedup_key, &draft) {
                node_ref
            } else {
                self.insert_pending_node_with_allocated_metadata_refs(
                    dedup_key,
                    draft.clone(),
                    asm_op_checkpoint,
                    debug_var_checkpoint,
                )?
            };

        if let Err(err) = self.record_source_occurrence(node_ref, source_child_refs, &draft) {
            truncate_index_vec(&mut self.asm_op_by_ref, asm_op_checkpoint);
            truncate_index_vec(&mut self.debug_vars, debug_var_checkpoint);
            return Err(err);
        }

        Ok(node_ref)
    }

    fn source_child_refs_for_node_refs(
        &self,
        child_refs: &[MastNodeRef],
    ) -> Vec<SourceMastNodeRef> {
        let mut child_counts = BTreeMap::<MastNodeRef, usize>::new();
        for child_ref in child_refs {
            *child_counts.entry(*child_ref).or_default() += 1;
        }

        let mut child_seen = BTreeMap::<MastNodeRef, usize>::new();
        child_refs
            .iter()
            .map(|child_ref| {
                let history = self
                    .source_refs_by_node_ref
                    .get(child_ref)
                    .expect("child execution ref must have a source occurrence");
                let needed = child_counts[child_ref];
                let seen = child_seen.entry(*child_ref).or_default();
                let source_ref = history
                    .get(history.len().checked_sub(needed).expect(
                        "child execution ref must have enough source occurrences for this parent",
                    ) + *seen)
                    .copied()
                    .expect(
                        "child execution ref must have enough source occurrences for this parent",
                    );
                *seen += 1;
                source_ref
            })
            .collect()
    }

    fn record_source_occurrence(
        &mut self,
        exec_ref: MastNodeRef,
        child_refs: Vec<SourceMastNodeRef>,
        draft: &PendingMastNodeDraft,
    ) -> Result<SourceMastNodeRef, Report> {
        let (op_start, op_end) = self.source_op_range_for_draft(draft);
        self.push_source_occurrence(
            exec_ref,
            child_refs,
            op_start,
            op_end,
            draft.asm_ops.clone(),
            draft.debug_vars.clone(),
            true,
        )
    }

    fn source_op_range_for_draft(&self, draft: &PendingMastNodeDraft) -> (usize, usize) {
        let op_count = if let Some(op_batches) = draft.kind.basic_block_op_batches() {
            op_batches.iter().flat_map(OpBatch::raw_ops).count()
        } else {
            draft
                .asm_ops
                .iter()
                .map(|(op_idx, _)| op_idx + 1)
                .chain(draft.debug_vars.iter().map(|(op_idx, _)| op_idx + 1))
                .max()
                .unwrap_or(0)
        };

        (0, op_count)
    }

    fn push_source_occurrence(
        &mut self,
        exec_ref: MastNodeRef,
        child_refs: Vec<SourceMastNodeRef>,
        op_start: usize,
        op_end: usize,
        asm_ops: Vec<(usize, AsmOpRef)>,
        debug_vars: Vec<(usize, DebugVarRef)>,
        update_latest: bool,
    ) -> Result<SourceMastNodeRef, Report> {
        let source_ref = self
            .source_nodes
            .push(PendingSourceMastNode {
                exec_ref,
                child_refs,
                op_start,
                op_end,
                asm_ops,
                debug_vars,
            })
            .into_diagnostic()
            .wrap_err("assembler created too many source MAST node refs")?;
        if update_latest {
            self.latest_source_ref_by_node_ref.insert(exec_ref, source_ref);
        }
        self.source_refs_by_node_ref.entry(exec_ref).or_default().push(source_ref);
        Ok(source_ref)
    }

    /// Removes the unused nodes that were created as part of the assembly process, and returns the
    /// resulting MAST forest.
    ///
    /// Finalization preserves every recorded procedure root and every pending node reachable from
    /// those roots. Pending records which are unreachable from all roots are pruned.
    ///
    /// External nodes are emitted before non-external nodes. This preserves the positional
    /// convention used by externally linked procedure roots while still keeping final node IDs
    /// local to the resulting forest.
    ///
    /// Finalization must happen in the order used below: plan the live layout first, materialize
    /// live nodes so builder-local refs have final node IDs, then register metadata against those
    /// final IDs before assembling the immutable forest.
    ///
    /// It also returns the map from assembly-time node refs to final node IDs. Any [`MastNodeRef`]
    /// used in reference to this builder should be resolved using this map.
    pub(crate) fn build(mut self) -> Result<BuiltMastForest, Report> {
        let procedure_root_refs = core::mem::take(&mut self.procedure_root_refs);
        let procedure_source_root_refs = core::mem::take(&mut self.procedure_source_root_refs);

        let layout = FinalForestLayout::plan(procedure_root_refs, &self.nodes);

        let mut finalizer = MastForestFinalizer::new();
        finalizer.materialize_live_nodes(&layout.live_node_refs, &self.nodes)?;

        finalizer.into_built_forest(
            &layout.procedure_root_refs,
            &procedure_source_root_refs,
            &self.source_nodes,
            &self.asm_op_by_ref,
            &self.debug_vars,
            self.advice_map,
            core::mem::take(&mut self.error_codes),
        )
    }
}

/// Computes the number of operations for a node and adjusts AssemblyOp indices if needed.
///
/// For basic block nodes, adjusts indices to account for padding NOOPs in OpBatches.
/// For control flow nodes, computes the operation count from the maximum index.
fn compute_operations_and_adjust_mappings<T: Copy>(
    node: &MastNode,
    mappings: Vec<(usize, T)>,
) -> (usize, Vec<(usize, T)>) {
    match node {
        MastNode::Block(block) => (
            block.num_operations() as usize,
            BasicBlockNode::adjust_asm_op_indices(mappings, block.op_batches()),
        ),
        _ => {
            let num_ops = mappings.iter().map(|(idx, _)| idx + 1).max().unwrap_or(0);
            (num_ops, mappings)
        },
    }
}

fn batch_basic_block_operations(
    operations: Vec<Operation>,
) -> Result<(Vec<OpBatch>, Word), Report> {
    let block = BasicBlockNodeBuilder::new(operations)
        .build()
        .into_diagnostic()
        .wrap_err("assembler failed to build new basic block")?;
    Ok((block.op_batches().to_vec(), block.digest()))
}

fn serialize_basic_block_error_codes(op_batches: &[OpBatch]) -> Vec<u8> {
    let mut data = Vec::new();

    for (raw_op_idx, op) in op_batches.iter().flat_map(OpBatch::raw_ops).enumerate() {
        if matches!(op, Operation::Assert(_) | Operation::U32assert2(_) | Operation::MpVerify(_)) {
            data.extend_from_slice(&(raw_op_idx as u64).to_le_bytes());
            op.write_into(&mut data);
        }
    }

    data
}

fn truncate_index_vec<I: Idx, T>(items: &mut IndexVec<I, T>, len: usize) {
    while items.len() > len {
        items.swap_remove(items.len() - 1);
    }
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

    pub(crate) fn latest_source_ref_for_node_ref(
        &self,
        node_ref: MastNodeRef,
    ) -> Option<SourceMastNodeRef> {
        self.latest_source_ref_by_node_ref.get(&node_ref).copied()
    }

    fn pending_node_mast_root(&self, node_ref: MastNodeRef) -> Word {
        self.nodes[node_ref].digest
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
    /// If the procedure with the same ID already exists in this forest builder, this will have no
    /// effect.
    pub fn insert_procedure(
        &mut self,
        gid: GlobalItemIndex,
        procedure: Procedure,
    ) -> Result<(), Report> {
        // Check if an entry is already in this cache slot.
        //
        // If there is already a cache entry, but it conflicts with what we're trying to cache,
        // then raise an error.
        if let Some(cached) = self.procedures.get(&gid) {
            if cached.mast_root() != procedure.mast_root() {
                return Err(report!(
                    "procedure '{}' was compiled more than once with different MAST roots",
                    procedure.path()
                ));
            }

            log::warn!(
                target: "assembler::mast_forest_builder",
                "procedure '{}' was compiled more than once; reusing the cached MAST root",
                procedure.path(),
            );
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

    pub(crate) fn record_procedure_root_ref(&mut self, root_ref: MastNodeRef) {
        if !self.procedure_root_refs.contains(&root_ref) {
            self.procedure_root_refs.push(root_ref);
        }
        if let Some(history) = self.source_refs_by_node_ref.get(&root_ref)
            && let Some(source_ref) = history
                .get(*self.procedure_source_root_count_by_node_ref.entry(root_ref).or_default())
                .copied()
                .or_else(|| history.last().copied())
            && !self.procedure_source_root_refs.contains(&source_ref)
        {
            self.procedure_source_root_refs.push(source_ref);
            *self.procedure_source_root_count_by_node_ref.entry(root_ref).or_default() += 1;
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
                let draft =
                    PendingMastNodeDraft::new(PendingMastNodeKind::Join, join_digest, child_refs);
                let join_mast_node_ref = if let Some(ref asm_op) = asm_op {
                    self.intern_pending_node_with_asm_op(draft, asm_op.clone())?
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
        asm_op: AssemblyOp,
    ) -> Result<MastNodeRef, Report> {
        let branch_digests = branches.map(|node_ref| self.pending_node_mast_root(node_ref));
        let split_digest = hasher::merge_in_domain(&branch_digests, SplitNode::DOMAIN);
        let child_refs = Vec::from(branches);

        self.intern_pending_node_with_asm_op(
            PendingMastNodeDraft::new(PendingMastNodeKind::Split, split_digest, child_refs),
            asm_op,
        )
    }

    pub(crate) fn ensure_loop_node_ref(
        &mut self,
        body: MastNodeRef,
        asm_op: AssemblyOp,
    ) -> Result<MastNodeRef, Report> {
        let body_digest = self.pending_node_mast_root(body);
        let loop_digest =
            hasher::merge_in_domain(&[body_digest, Word::default()], LoopNode::DOMAIN);
        let child_refs = vec![body];

        self.intern_pending_node_with_asm_op(
            PendingMastNodeDraft::new(PendingMastNodeKind::Loop, loop_digest, child_refs),
            asm_op,
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
        self.intern_pending_node_with_asm_op(
            PendingMastNodeDraft::new(
                PendingMastNodeKind::Call { is_syscall },
                call_digest,
                child_refs,
            ),
            asm_op,
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
        self.intern_pending_node_with_asm_op(
            PendingMastNodeDraft::new(
                PendingMastNodeKind::Dyn { is_dyncall },
                dyn_digest,
                child_refs,
            ),
            asm_op,
        )
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

    fn record_merged_source_occurrences(
        &mut self,
        merged_ref: MastNodeRef,
        merged_source_occurrences: &[(SourceMastNodeRef, usize)],
    ) -> Result<(), Report> {
        for &(source_ref, new_start) in merged_source_occurrences {
            let source_node = self.source_nodes[source_ref].clone();
            let old_start = source_node.op_start;
            let op_len = source_node.op_end.saturating_sub(old_start);
            let remap_op_idx = |op_idx: usize| {
                debug_assert!(op_idx >= old_start);
                op_idx - old_start + new_start
            };

            self.push_source_occurrence(
                merged_ref,
                source_node.child_refs,
                new_start,
                new_start + op_len,
                source_node
                    .asm_ops
                    .into_iter()
                    .map(|(op_idx, asm_op_ref)| (remap_op_idx(op_idx), asm_op_ref))
                    .collect(),
                source_node
                    .debug_vars
                    .into_iter()
                    .map(|(op_idx, debug_var_ref)| (remap_op_idx(op_idx), debug_var_ref))
                    .collect(),
                false,
            )?;
        }

        Ok(())
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
        // Track asm_ops and debug_vars being accumulated for merged blocks, with adjusted indices
        let mut merged_asm_ops: Vec<(usize, AsmOpRef)> = Vec::new();
        let mut merged_debug_vars: Vec<(usize, DebugVarRef)> = Vec::new();
        let mut merged_source_occurrences: Vec<(SourceMastNodeRef, usize)> = Vec::new();

        let mut merged_basic_block_refs: Vec<MastNodeRef> = Vec::new();

        for &basic_block_ref in contiguous_basic_block_refs {
            // check if the block should be merged with other blocks
            if should_merge(
                self.is_procedure_root_ref(basic_block_ref),
                self.pending_basic_block_op_batches(basic_block_ref)
                    .expect("merge_basic_blocks: expected BasicBlockNode")
                    .len(),
            ) {
                // Collect operations from the block while the node is still immutably borrowed.
                let block_ops = {
                    let pending_node = &self.nodes[basic_block_ref];
                    let op_batches = pending_node
                        .kind
                        .basic_block_op_batches()
                        .expect("merge_basic_blocks: expected BasicBlockNode");
                    op_batches.iter().flat_map(|b| b.raw_ops().copied()).collect::<Vec<_>>()
                };
                let ops_offset = operations.len();

                if let Some(source_ref) = self.latest_source_ref_by_node_ref.get(&basic_block_ref) {
                    merged_source_occurrences.push((*source_ref, ops_offset));
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

                operations.extend(block_ops);
            } else {
                // If we don't want to merge this block, flush the buffer of operations into a
                // new block, and add the un-merged block after it.
                if !operations.is_empty() {
                    let block_ops = core::mem::take(&mut operations);
                    let block_asm_ops = core::mem::take(&mut merged_asm_ops);
                    let block_debug_vars = core::mem::take(&mut merged_debug_vars);
                    let block_source_occurrences = core::mem::take(&mut merged_source_occurrences);
                    let merged_basic_block_ref =
                        self.ensure_block_ref(block_ops, block_asm_ops, block_debug_vars)?;
                    self.record_merged_source_occurrences(
                        merged_basic_block_ref,
                        &block_source_occurrences,
                    )?;

                    merged_basic_block_refs.push(merged_basic_block_ref);
                }
                merged_basic_block_refs.push(basic_block_ref);
            }
        }

        if !operations.is_empty() {
            let merged_basic_block =
                self.ensure_block_ref(operations, merged_asm_ops, merged_debug_vars)?;
            self.record_merged_source_occurrences(merged_basic_block, &merged_source_occurrences)?;
            merged_basic_block_refs.push(merged_basic_block);
        }

        Ok(merged_basic_block_refs)
    }

    /// Adds a basic block node to the forest, and returns its builder-local [`MastNodeRef`].
    pub(crate) fn ensure_block_ref(
        &mut self,
        operations: Vec<Operation>,
        asm_op_refs: Vec<(usize, AsmOpRef)>,
        debug_vars: Vec<(usize, DebugVarRef)>,
    ) -> Result<MastNodeRef, Report> {
        let (op_batches, digest) = batch_basic_block_operations(operations)?;
        let kind = PendingMastNodeKind::BasicBlock { op_batches };
        self.intern_pending_node(PendingMastNodeDraft {
            kind,
            digest,
            child_refs: Vec::new(),
            asm_ops: asm_op_refs,
            debug_vars,
        })
    }
}

// ------------------------------------------------------------------------------------------------
/// Node inserters
impl MastForestBuilder {
    /// Adds a debug variable to the builder, and returns its builder-local [`DebugVarRef`].
    ///
    /// Debug variables are not deduplicated since each occurrence represents a specific point in
    /// program execution where the variable's location is being tracked.
    pub(crate) fn add_debug_var_ref(
        &mut self,
        debug_var: DebugVarInfo,
    ) -> Result<DebugVarRef, Report> {
        self.push_debug_var_ref(debug_var)
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
    use alloc::{
        collections::BTreeSet,
        string::{String, ToString},
    };

    use miden_core::{
        mast::{MastNodeBuilder, MastNodeId},
        operations::{DebugVarLocation, Operation},
    };
    use miden_mast_package::debug_info::{
        DEBUG_SOURCE_GRAPH_VERSION, DEBUG_SOURCE_MAP_VERSION, DebugSourceAsmOp,
        DebugSourceGraphSection, DebugSourceMapSection, DebugSourceMastNode, DebugSourceMastNodeId,
        DebugSourceVar, PackageDebugInfo,
    };
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

    fn source_nodes_for_exec(
        source_graph: &SourceDebugGraph,
        exec_node: MastNodeId,
    ) -> Vec<&SourceMastNode> {
        source_graph
            .source_nodes_for_exec_node(exec_node)
            .map(|(_, source_node)| source_node)
            .collect()
    }

    fn source_debug_var_names(
        source_graph: &SourceDebugGraph,
        exec_node: MastNodeId,
    ) -> Vec<String> {
        source_nodes_for_exec(source_graph, exec_node)
            .into_iter()
            .flat_map(|source_node| {
                source_node
                    .debug_vars()
                    .iter()
                    .map(|(_, debug_var)| debug_var.name().to_string())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    fn source_asm_contexts(source_graph: &SourceDebugGraph, exec_node: MastNodeId) -> Vec<String> {
        source_nodes_for_exec(source_graph, exec_node)
            .into_iter()
            .flat_map(|source_node| {
                source_node
                    .asm_ops()
                    .iter()
                    .map(|(_, asm_op)| asm_op.context_name().to_string())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    fn package_debug_info_from_source_graph(source_graph: &SourceDebugGraph) -> PackageDebugInfo {
        let source_nodes = source_graph
            .nodes()
            .as_slice()
            .iter()
            .map(|source_node| {
                DebugSourceMastNode::new(
                    source_node.exec_node(),
                    source_node
                        .children()
                        .iter()
                        .map(|child| DebugSourceMastNodeId::from(u32::from(*child)))
                        .collect(),
                    source_node.op_start() as u32,
                    source_node.op_end() as u32,
                )
            })
            .collect();
        let roots = source_graph
            .roots()
            .iter()
            .map(|root| DebugSourceMastNodeId::from(u32::from(*root)))
            .collect();

        let mut asm_ops = Vec::new();
        let mut debug_vars = Vec::new();
        for (source_idx, source_node) in source_graph.nodes().as_slice().iter().enumerate() {
            let source_node_id = DebugSourceMastNodeId::from(source_idx as u32);
            asm_ops.extend(source_node.asm_ops().iter().map(|(op_idx, asm_op)| {
                DebugSourceAsmOp::new(
                    source_node_id,
                    *op_idx as u32,
                    asm_op.location().cloned(),
                    asm_op.context_name().to_string(),
                    asm_op.op().to_string(),
                    asm_op.num_cycles(),
                )
            }));
            debug_vars.extend(source_node.debug_vars().iter().map(|(op_idx, debug_var)| {
                DebugSourceVar::new(source_node_id, *op_idx as u32, debug_var.clone())
            }));
        }

        PackageDebugInfo {
            source_graph: Some(DebugSourceGraphSection {
                version: DEBUG_SOURCE_GRAPH_VERSION,
                nodes: source_nodes,
                roots,
            }),
            source_map: Some(DebugSourceMapSection {
                version: DEBUG_SOURCE_MAP_VERSION,
                asm_ops,
                debug_vars,
            }),
            ..PackageDebugInfo::default()
        }
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
                    vec![(0, shared_asm_op), (1, shared_asm_op)],
                    vec![(0, shared_debug_var)],
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
                                vec![(0, asm_op)],
                                vec![],
                            )
                            .unwrap()
                    },
                    1 => builder
                        .ensure_split_node_ref(
                            [first_ref, second_ref],
                            test_asm_op(context.clone(), "if.true"),
                        )
                        .unwrap(),
                    2 => builder
                        .ensure_loop_node_ref(
                            first_ref,
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
    fn test_build_without_roots_prunes_all_nodes() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let dead_ref = builder.ensure_block_ref(vec![Operation::Add], vec![], vec![]).unwrap();

        let (forest, remapping) = builder.build().unwrap().into_parts();

        assert!(!remapping.contains_key(&dead_ref));
        assert_eq!(forest.num_nodes(), 0);
        assert_eq!(forest.procedure_roots().len(), 0);
    }

    #[test]
    fn test_build_prunes_unreachable_nodes() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let root_ref = builder.ensure_block_ref(vec![Operation::Add], vec![], vec![]).unwrap();
        let dead_ref = builder.ensure_block_ref(vec![Operation::Mul], vec![], vec![]).unwrap();
        builder.record_procedure_root_ref(root_ref);

        let (forest, remapping) = builder.build().unwrap().into_parts();

        assert!(remapping.contains_key(&root_ref));
        assert!(!remapping.contains_key(&dead_ref));
        assert_eq!(forest.num_nodes(), 1);
        assert_eq!(forest.procedure_roots().len(), 1);
    }

    #[test]
    fn test_merge_basic_blocks_keeps_non_mergeable_block_standalone() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let num_ops = PROCEDURE_INLINING_THRESHOLD * 1024;
        let large_ops = vec![Operation::Add; num_ops];
        let large_block_ref = builder.ensure_block_ref(large_ops, vec![], vec![]).unwrap();
        builder.record_procedure_root_ref(large_block_ref);

        let small_block_ref =
            builder.ensure_block_ref(vec![Operation::Add], vec![], vec![]).unwrap();

        let merged_blocks =
            builder.merge_basic_block_refs(&[large_block_ref, small_block_ref]).unwrap();

        assert_eq!(merged_blocks.len(), 2);
        assert_eq!(merged_blocks[0], large_block_ref);
        assert_eq!(merged_blocks[1], small_block_ref);
    }

    #[test]
    fn test_build_keeps_existing_forest_root_after_merge() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let root_block_ref =
            builder.ensure_block_ref(vec![Operation::Add], vec![], vec![]).unwrap();
        builder.record_procedure_root_ref(root_block_ref);
        let root_digest = builder.nodes[root_block_ref].digest;

        let tail_block_ref =
            builder.ensure_block_ref(vec![Operation::Mul], vec![], vec![]).unwrap();

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
    fn test_source_graph_preserves_pre_merge_block_ranges() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let first_asm_op = add_test_asm_op(&mut builder, test_asm_op("merge::first", "add"));
        let second_asm_op = add_test_asm_op(&mut builder, test_asm_op("merge::second", "mul"));
        let first_block_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![(0, first_asm_op)], vec![])
            .unwrap();
        let second_block_ref = builder
            .ensure_block_ref(vec![Operation::Mul], vec![(0, second_asm_op)], vec![])
            .unwrap();

        let merged_blocks =
            builder.merge_basic_block_refs(&[first_block_ref, second_block_ref]).unwrap();
        assert_eq!(merged_blocks.len(), 1);
        let merged_ref = record_test_root(&mut builder, merged_blocks[0]);

        let (_, remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_source_graph();
        let final_merged_id = remapping[&merged_ref];
        let source_nodes = source_graph
            .source_nodes_for_exec_node(final_merged_id)
            .map(|(_, source_node)| source_node)
            .collect::<Vec<_>>();

        assert_eq!(
            source_graph.roots().len(),
            1,
            "pre-merge source blocks should not become procedure roots",
        );
        assert!(
            source_nodes.iter().any(|source_node| {
                source_node.op_start() == 0
                    && source_node.op_end() == 1
                    && source_node
                        .asm_ops()
                        .iter()
                        .any(|(_, asm_op)| asm_op.context_name() == "merge::first")
            }),
            "first pre-merge source block should survive as range 0..1",
        );
        assert!(
            source_nodes.iter().any(|source_node| {
                source_node.op_start() == 1
                    && source_node.op_end() == 2
                    && source_node
                        .asm_ops()
                        .iter()
                        .any(|(_, asm_op)| asm_op.context_name() == "merge::second")
            }),
            "second pre-merge source block should survive as range 1..2",
        );
    }

    #[test]
    fn test_build_orders_external_nodes_before_non_external_nodes() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let block_ref = builder.ensure_block_ref(vec![Operation::Add], vec![], vec![]).unwrap();
        record_test_root(&mut builder, block_ref);

        let external_a = builder
            .ensure_external_link_with_source_ref(test_word(2), None, None, None)
            .unwrap();
        let external_b = builder
            .ensure_external_link_with_source_ref(test_word(1), None, None, None)
            .unwrap();
        builder.record_procedure_root_ref(external_a);
        builder.record_procedure_root_ref(external_b);

        let mut expected_external_refs = [
            (external_a, builder.nodes[external_a].key),
            (external_b, builder.nodes[external_b].key),
        ];
        expected_external_refs.sort_by_key(|(_, key)| *key);

        let (forest, remapping) = builder.build().unwrap().into_parts();

        assert_eq!(remapping[&expected_external_refs[0].0], MastNodeId::new_unchecked(0));
        assert_eq!(remapping[&expected_external_refs[1].0], MastNodeId::new_unchecked(1));
        assert!(forest[MastNodeId::new_unchecked(0)].is_external());
        assert!(forest[MastNodeId::new_unchecked(1)].is_external());
    }

    #[test]
    fn test_concrete_node_replaces_same_digest_external_placeholder() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();
        let block_digest =
            BasicBlockNodeBuilder::new(vec![Operation::Add]).build().unwrap().digest();

        let external_ref = builder
            .ensure_external_link_with_source_ref(block_digest, None, None, None)
            .unwrap();
        builder.record_procedure_root_ref(external_ref);

        let concrete_ref = builder.ensure_block_ref(vec![Operation::Add], vec![], vec![]).unwrap();
        assert_eq!(external_ref, concrete_ref);
        assert!(!builder.nodes[external_ref].kind.is_external());

        let (forest, remapping) = builder.build().unwrap().into_parts();
        let final_root = remapping[&external_ref];

        assert!(forest.is_procedure_root(final_root));
        assert!(matches!(forest[final_root], MastNode::Block(_)));
    }

    #[test]
    fn test_merge_basic_blocks_keeps_recorded_root_block_standalone() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let num_ops = PROCEDURE_INLINING_THRESHOLD * 1024;
        let large_ops = vec![Operation::Add; num_ops];
        let large_block_ref = builder.ensure_block_ref(large_ops, vec![], vec![]).unwrap();
        builder.record_procedure_root_ref(large_block_ref);

        let small_block_ref =
            builder.ensure_block_ref(vec![Operation::Add], vec![], vec![]).unwrap();

        let merged_blocks =
            builder.merge_basic_block_refs(&[large_block_ref, small_block_ref]).unwrap();

        assert_eq!(merged_blocks.len(), 2);
        assert_eq!(merged_blocks[0], large_block_ref);
        assert_eq!(merged_blocks[1], small_block_ref);
    }

    /// Same-ops blocks with different debug vars use the same execution node identity.
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

        // Same ops, different debug vars dedup to the same execution node.
        let block_a_ref = builder
            .ensure_block_ref(vec![Operation::Add], Vec::new(), vec![(0, var_x_ref)])
            .unwrap();
        let block_b_ref = builder
            .ensure_block_ref(vec![Operation::Add], Vec::new(), vec![(0, var_y_ref)])
            .unwrap();

        assert_eq!(block_a_ref, block_b_ref);

        record_test_root(&mut builder, block_a_ref);
        let (_forest, remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_source_graph();
        let final_block_a = remapping[&block_a_ref];
        let final_block_b = remapping[&block_b_ref];
        let var_names = source_debug_var_names(&source_graph, final_block_a);

        assert_eq!(var_names, vec!["x", "y"]);
        assert_eq!(final_block_a, final_block_b);
    }

    #[test]
    fn test_source_graph_distinguishes_same_exec_debug_var_occurrences() {
        use miden_core::operations::{DebugVarInfo, DebugVarLocation};

        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let var_x_ref = builder
            .add_debug_var_ref(DebugVarInfo::new("x", DebugVarLocation::Stack(0)))
            .unwrap();
        let var_y_ref = builder
            .add_debug_var_ref(DebugVarInfo::new("y", DebugVarLocation::Stack(1)))
            .unwrap();

        let block_a_ref = builder
            .ensure_block_ref(vec![Operation::Add], Vec::new(), vec![(0, var_x_ref)])
            .unwrap();
        let block_b_ref = builder
            .ensure_block_ref(vec![Operation::Add], Vec::new(), vec![(0, var_y_ref)])
            .unwrap();

        assert_eq!(block_a_ref, block_b_ref);

        record_test_root(&mut builder, block_a_ref);
        let (forest, remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_source_graph();
        let final_block = remapping[&block_a_ref];
        let debug_var_names = source_graph
            .source_nodes_for_exec_node(final_block)
            .flat_map(|(_, source_node)| {
                source_node
                    .debug_vars()
                    .iter()
                    .map(|(_, debug_var)| debug_var.name().to_string())
            })
            .collect::<BTreeSet<_>>();

        assert_eq!(final_block, remapping[&block_b_ref]);
        assert_eq!(forest.num_nodes(), 1);
        assert_eq!(source_graph.roots().len(), 1);
        assert_eq!(debug_var_names, BTreeSet::from(["x".to_string(), "y".to_string()]));
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
            .ensure_block_ref(vec![Operation::Add], Vec::new(), vec![(0, var_a)])
            .unwrap();
        let block_b = builder
            .ensure_block_ref(vec![Operation::Add], Vec::new(), vec![(0, var_b)])
            .unwrap();

        assert_eq!(
            block_a, block_b,
            "same op stream plus same DebugVarInfo payload should dedup to one node"
        );
    }

    #[test]
    fn test_error_code_bearing_basic_blocks_do_not_dedup_by_digest_only() {
        fn error_code_for_final_block(forest: &MastForest, node_id: MastNodeId) -> Felt {
            let MastNode::Block(block) = &forest[node_id] else {
                panic!("expected a basic block")
            };

            let op = block
                .op_batches()
                .iter()
                .flat_map(OpBatch::raw_ops)
                .next()
                .expect("expected one operation");

            match op {
                Operation::Assert(code)
                | Operation::U32assert2(code)
                | Operation::MpVerify(code) => *code,
                other => panic!("expected error-code-bearing operation, got {other:?}"),
            }
        }

        for make_op in [
            Operation::Assert as fn(Felt) -> Operation,
            Operation::U32assert2 as fn(Felt) -> Operation,
            Operation::MpVerify as fn(Felt) -> Operation,
        ] {
            let mut builder = MastForestBuilder::new(&[]).unwrap();
            let first_code = Felt::from_u32(1);
            let second_code = Felt::from_u32(2);

            let first_ref = builder
                .ensure_block_ref(vec![make_op(first_code)], Vec::new(), Vec::new())
                .unwrap();
            let duplicate_first_ref = builder
                .ensure_block_ref(vec![make_op(first_code)], Vec::new(), Vec::new())
                .unwrap();
            let second_ref = builder
                .ensure_block_ref(vec![make_op(second_code)], Vec::new(), Vec::new())
                .unwrap();

            assert_eq!(first_ref, duplicate_first_ref);
            assert_ne!(
                first_ref, second_ref,
                "same-digest blocks with different runtime error codes must remain distinct",
            );

            record_test_root(&mut builder, first_ref);
            record_test_root(&mut builder, second_ref);
            let (forest, remapping) = builder.build().unwrap().into_parts();
            let final_first_id = remapping[&first_ref];
            let final_second_id = remapping[&second_ref];

            assert_ne!(final_first_id, final_second_id);
            assert_eq!(forest[final_first_id].digest(), forest[final_second_id].digest());
            assert_eq!(error_code_for_final_block(&forest, final_first_id), first_code);
            assert_eq!(error_code_for_final_block(&forest, final_second_id), second_code);
        }
    }

    #[test]
    fn test_control_nodes_include_child_error_code_keys() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let first_block = builder
            .ensure_block_ref(vec![Operation::Assert(Felt::from_u32(1))], Vec::new(), Vec::new())
            .unwrap();
        let second_block = builder
            .ensure_block_ref(vec![Operation::Assert(Felt::from_u32(2))], Vec::new(), Vec::new())
            .unwrap();

        assert_eq!(
            builder.pending_node_mast_root(first_block),
            builder.pending_node_mast_root(second_block)
        );

        let first_call = builder
            .ensure_call_node_ref(first_block, false, test_asm_op("test", "call"))
            .unwrap();
        let second_call = builder
            .ensure_call_node_ref(second_block, false, test_asm_op("test", "call"))
            .unwrap();

        assert_ne!(
            first_call, second_call,
            "same-digest control nodes must not dedup when their children differ by runtime error code",
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
            .ensure_block_ref(vec![Operation::Add], Vec::new(), vec![(0, used_var)])
            .unwrap();

        record_test_root(&mut builder, block_ref);
        let (_forest, remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_source_graph();
        let final_block_id = remapping[&block_ref];
        let var_names = source_debug_var_names(&source_graph, final_block_id);

        assert_eq!(var_names, vec!["used"]);
    }

    /// Same-ops blocks with different AssemblyOps use the same execution node identity.
    #[test]
    fn test_ensure_block_keeps_different_asm_ops_distinct() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let asm_op_a =
            add_test_asm_op(&mut builder, AssemblyOp::new(None, "ctx_a".into(), 1, "add".into()));
        let asm_op_b =
            add_test_asm_op(&mut builder, AssemblyOp::new(None, "ctx_b".into(), 1, "add".into()));

        let block_a_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![(0, asm_op_a)], Vec::new())
            .unwrap();
        let block_b_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![(0, asm_op_b)], Vec::new())
            .unwrap();

        assert_eq!(
            block_a_ref, block_b_ref,
            "AssemblyOp payload must not affect execution node identity"
        );

        record_test_root(&mut builder, block_a_ref);
        let (_forest, remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_source_graph();
        let final_block_a = remapping[&block_a_ref];
        assert!(source_asm_contexts(&source_graph, final_block_a).contains(&"ctx_a".to_string()));
        assert_eq!(final_block_a, remapping[&block_b_ref]);
    }

    #[test]
    fn test_source_graph_distinguishes_same_exec_asm_op_occurrences() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let asm_op_a =
            add_test_asm_op(&mut builder, AssemblyOp::new(None, "ctx_a".into(), 1, "add".into()));
        let asm_op_b =
            add_test_asm_op(&mut builder, AssemblyOp::new(None, "ctx_b".into(), 1, "add".into()));

        let block_a_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![(0, asm_op_a)], Vec::new())
            .unwrap();
        let block_b_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![(0, asm_op_b)], Vec::new())
            .unwrap();

        assert_eq!(block_a_ref, block_b_ref);

        record_test_root(&mut builder, block_a_ref);
        let (forest, remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_source_graph();
        let final_block = remapping[&block_a_ref];
        let asm_contexts = source_graph
            .source_nodes_for_exec_node(final_block)
            .flat_map(|(_, source_node)| {
                source_node
                    .asm_ops()
                    .iter()
                    .map(|(_, asm_op)| asm_op.context_name().to_string())
            })
            .collect::<BTreeSet<_>>();

        assert_eq!(final_block, remapping[&block_b_ref]);
        assert_eq!(forest.num_nodes(), 1);
        assert_eq!(source_graph.roots().len(), 1);
        assert_eq!(asm_contexts, BTreeSet::from(["ctx_a".to_string(), "ctx_b".to_string()]));
    }

    #[test]
    fn test_source_graph_preserves_repeated_same_exec_child_occurrences() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let asm_op_a =
            add_test_asm_op(&mut builder, AssemblyOp::new(None, "ctx_a".into(), 1, "add".into()));
        let asm_op_b =
            add_test_asm_op(&mut builder, AssemblyOp::new(None, "ctx_b".into(), 1, "add".into()));
        let block_a_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![(0, asm_op_a)], Vec::new())
            .unwrap();
        let block_b_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![(0, asm_op_b)], Vec::new())
            .unwrap();
        assert_eq!(block_a_ref, block_b_ref);

        let split_ref = builder
            .ensure_split_node_ref(
                [block_a_ref, block_b_ref],
                AssemblyOp::new(None, "split".into(), 1, "if.true".into()),
            )
            .unwrap();
        record_test_root(&mut builder, split_ref);

        let (_forest, _remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_source_graph();
        let root = source_graph.roots()[0];
        let child_contexts = source_graph.nodes()[root]
            .children()
            .iter()
            .map(|child| {
                let child_node = &source_graph.nodes()[*child];
                child_node.asm_ops()[0].1.context_name().to_string()
            })
            .collect::<Vec<_>>();

        assert_eq!(child_contexts, vec!["ctx_a".to_string(), "ctx_b".to_string()]);
    }

    /// Non-block nodes with different AssemblyOps use the same execution node identity.
    #[test]
    fn test_non_block_nodes_keep_different_asm_ops_distinct() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let callee_ref = builder.ensure_block_ref(vec![Operation::Add], vec![], vec![]).unwrap();
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

        assert_eq!(
            call_a_ref, call_b_ref,
            "AssemblyOp payload must not affect execution node identity"
        );

        record_test_root(&mut builder, call_a_ref);
        let (_forest, remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_source_graph();
        let final_call_a = remapping[&call_a_ref];
        assert!(source_asm_contexts(&source_graph, final_call_a).contains(&"ctx_a".to_string()));
        assert_eq!(final_call_a, remapping[&call_b_ref]);
    }

    /// Statically linked nodes dedup with local nodes that have the same execution shape.
    #[test]
    fn test_statically_linked_nodes_preserve_metadata_in_dedup() {
        use miden_core::operations::{DebugVarInfo, DebugVarLocation};

        let static_block_id = MastNodeId::new_unchecked(0);

        let mut nodes = IndexVec::new();
        let inserted_node_id = nodes
            .push(
                MastNodeBuilder::BasicBlock(BasicBlockNodeBuilder::new(vec![Operation::Add]))
                    .build_linked()
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(inserted_node_id, static_block_id);
        let static_forest =
            MastForest::from_raw_parts(nodes, vec![static_block_id], AdviceMap::default()).unwrap();

        let mut builder = MastForestBuilder::new([&static_forest]).unwrap();
        let copied_block_ref = builder
            .ensure_external_link_with_source_ref(
                static_forest[static_block_id].digest(),
                None,
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
                vec![(0, local_asm_op_ref)],
                vec![(0, local_var_ref)],
            )
            .unwrap();

        assert_eq!(
            copied_block_ref, local_block_ref,
            "source metadata must not affect execution node identity"
        );

        record_test_root(&mut builder, copied_block_ref);
        let (_forest, remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_source_graph();
        let final_copied_block_id = remapping[&copied_block_ref];
        assert_eq!(final_copied_block_id, remapping[&local_block_ref]);
        assert!(
            source_asm_contexts(&source_graph, final_copied_block_id)
                .contains(&"local_ctx".to_string())
        );
        assert!(
            source_debug_var_names(&source_graph, final_copied_block_id).contains(&"y".to_string())
        );
    }

    #[test]
    fn test_statically_linked_padded_block_dedups_with_equivalent_local_block() {
        use miden_core::operations::{DebugVarInfo, DebugVarLocation};

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
        let debug_var = DebugVarInfo::new("padded_var", DebugVarLocation::Stack(0));

        let static_asm_op_ref = add_test_asm_op(&mut source_builder, asm_op.clone());
        let static_debug_var_ref = source_builder.add_debug_var_ref(debug_var).unwrap();
        let static_block_ref = source_builder
            .ensure_block_ref(
                ops.clone(),
                vec![(8, static_asm_op_ref)],
                vec![(8, static_debug_var_ref)],
            )
            .unwrap();
        record_test_root(&mut source_builder, static_block_ref);

        let (static_forest, source_remapping, static_source_graph, _) =
            source_builder.build().unwrap().into_parts_with_source_graph();
        let final_static_block = source_remapping[&static_block_ref];
        let static_source_root = static_source_graph.roots()[0];
        let expected_padded_idx = static_source_graph.nodes()[static_source_root].asm_ops()[0].0;
        assert_eq!(
            static_source_graph.nodes()[static_source_root].debug_vars()[0].0,
            expected_padded_idx
        );
        let package_debug_info = package_debug_info_from_source_graph(&static_source_graph);

        let mut builder = MastForestBuilder::new_with_static_libraries([StaticLibrary::new(
            &static_forest,
            Some(package_debug_info),
        )])
        .unwrap();
        let copied_block_ref = builder
            .ensure_external_link_with_source_ref(
                static_forest[final_static_block].digest(),
                Some(static_forest.commitment()),
                Some(final_static_block),
                Some(DebugSourceMastNodeId::from(u32::from(static_source_root))),
            )
            .unwrap();
        let local_asm_op_ref = add_test_asm_op(&mut builder, asm_op);
        let local_block_ref =
            builder.ensure_block_ref(ops, vec![(8, local_asm_op_ref)], vec![]).unwrap();

        assert_eq!(
            copied_block_ref, local_block_ref,
            "copied padded blocks should dedup with equivalent local blocks",
        );

        record_test_root(&mut builder, copied_block_ref);
        let (_forest, remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_source_graph();
        let final_block_id = remapping[&copied_block_ref];
        let source_nodes = source_nodes_for_exec(&source_graph, final_block_id);
        assert!(source_nodes.iter().any(|source_node| {
            source_node.asm_ops().iter().any(|(op_idx, asm_op)| {
                *op_idx == expected_padded_idx && asm_op.context_name() == "padded_ctx"
            })
        }));
        assert!(source_nodes.iter().any(|source_node| {
            source_node.debug_vars().iter().any(|(op_idx, debug_var)| {
                *op_idx == expected_padded_idx && debug_var.name() == "padded_var"
            })
        }));
    }

    #[test]
    fn test_statically_linked_package_source_range_is_preserved() {
        let mut source_builder = MastForestBuilder::new(&[]).unwrap();
        let ops = vec![
            Operation::Push(Felt::from_u32(1)),
            Operation::Drop,
            Operation::Drop,
            Operation::Drop,
            Operation::Push(Felt::from_u32(2)),
        ];
        let asm_op = AssemblyOp::new(None, "partial_ctx".into(), 1, "push.2".into());
        let static_asm_op_ref = add_test_asm_op(&mut source_builder, asm_op);
        let static_block_ref = source_builder
            .ensure_block_ref(ops, vec![(4, static_asm_op_ref)], vec![])
            .unwrap();
        record_test_root(&mut source_builder, static_block_ref);

        let (static_forest, source_remapping, static_source_graph, _) =
            source_builder.build().unwrap().into_parts_with_source_graph();
        let final_static_block = source_remapping[&static_block_ref];
        let static_source_root = static_source_graph.roots()[0];
        let expected_partial_start = static_source_graph.nodes()[static_source_root].asm_ops()[0].0;
        let mut package_debug_info = package_debug_info_from_source_graph(&static_source_graph);
        let package_source_root = DebugSourceMastNodeId::from(u32::from(static_source_root));
        let package_source_graph = package_debug_info
            .source_graph
            .as_mut()
            .expect("source graph should be present");
        package_source_graph.nodes[u32::from(package_source_root) as usize].op_start =
            expected_partial_start as u32;
        package_source_graph.nodes[u32::from(package_source_root) as usize].op_end =
            expected_partial_start as u32 + 1;

        let mut builder = MastForestBuilder::new_with_static_libraries([StaticLibrary::new(
            &static_forest,
            Some(package_debug_info),
        )])
        .unwrap();
        let copied_block_ref = builder
            .ensure_external_link_with_source_ref(
                static_forest[final_static_block].digest(),
                Some(static_forest.commitment()),
                Some(final_static_block),
                Some(package_source_root),
            )
            .unwrap();

        record_test_root(&mut builder, copied_block_ref);
        let (_forest, remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_source_graph();
        let final_block_id = remapping[&copied_block_ref];
        let linked_source_node = source_nodes_for_exec(&source_graph, final_block_id)
            .into_iter()
            .find(|source_node| {
                source_node
                    .asm_ops()
                    .iter()
                    .any(|(_, asm_op)| asm_op.context_name() == "partial_ctx")
            })
            .expect("linked source node should preserve package metadata");

        assert_eq!(linked_source_node.op_start(), expected_partial_start);
        assert_eq!(linked_source_node.op_end(), expected_partial_start + 1);
    }

    #[test]
    fn test_static_link_rejects_package_debug_child_exec_mismatch() {
        let mut source_builder = MastForestBuilder::new(&[]).unwrap();
        let left_ref =
            source_builder.ensure_block_ref(vec![Operation::Add], vec![], vec![]).unwrap();
        let right_ref =
            source_builder.ensure_block_ref(vec![Operation::Mul], vec![], vec![]).unwrap();
        let split_ref = source_builder
            .ensure_split_node_ref(
                [left_ref, right_ref],
                AssemblyOp::new(None, "split_ctx".into(), 1, "if.true".into()),
            )
            .unwrap();
        record_test_root(&mut source_builder, split_ref);

        let (static_forest, source_remapping, static_source_graph, _) =
            source_builder.build().unwrap().into_parts_with_source_graph();
        let final_split = source_remapping[&split_ref];
        let package_source_root =
            DebugSourceMastNodeId::from(u32::from(static_source_graph.roots()[0]));
        let mut package_debug_info = package_debug_info_from_source_graph(&static_source_graph);
        package_debug_info.source_graph.as_mut().unwrap().nodes
            [u32::from(package_source_root) as usize]
            .children
            .swap(0, 1);

        let mut builder = MastForestBuilder::new_with_static_libraries([StaticLibrary::new(
            &static_forest,
            Some(package_debug_info),
        )])
        .unwrap();
        let error = builder
            .ensure_external_link_with_source_ref(
                static_forest[final_split].digest(),
                Some(static_forest.commitment()),
                Some(final_split),
                Some(package_source_root),
            )
            .expect_err("statically linked package debug graph with swapped children is invalid");

        assert!(error.to_string().contains("child 0 maps"), "unexpected error: {error}");
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
            .ensure_block_ref(vec![Operation::Add], vec![(0, asm_op_ref)], vec![(0, var_ref)])
            .unwrap();
        builder.record_procedure_root_ref(root_block_ref);

        // Second block to merge with.
        let other_block_ref =
            builder.ensure_block_ref(vec![Operation::Mul], vec![], vec![]).unwrap();

        let merged = builder.merge_basic_block_refs(&[root_block_ref, other_block_ref]).unwrap();
        // Root was small enough to merge, so we get one merged block.
        assert_eq!(merged.len(), 1);
        let merged_ref = merged[0];
        assert_ne!(merged_ref, root_block_ref);

        let (forest, remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_source_graph();

        // The root block survives removal (it's a procedure root).
        let final_root_id = remapping[&root_block_ref];
        assert!(forest.is_procedure_root(final_root_id), "root should survive");

        // Root block must still have its debug vars.
        let root_vars = source_debug_var_names(&source_graph, final_root_id);
        assert_eq!(root_vars, vec!["x"], "root must keep its debug vars after merge");

        // Root block must still have its asm op.
        assert!(
            source_asm_contexts(&source_graph, final_root_id).contains(&"test".to_string()),
            "root must keep its asm op after merge"
        );
    }

    /// Two same-digest roots with different asm ops share execution node identity.
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
            .ensure_block_ref(vec![Operation::Add], vec![(0, alias_a_asm_op)], vec![])
            .unwrap();
        let alias_b_ref = source_builder
            .ensure_block_ref(vec![Operation::Add], vec![(0, alias_b_asm_op)], vec![])
            .unwrap();
        record_test_root(&mut source_builder, alias_a_ref);
        record_test_root(&mut source_builder, alias_b_ref);

        let (static_forest, source_remapping) = source_builder.build().unwrap().into_parts();
        let final_alias_a = source_remapping[&alias_a_ref];
        let final_alias_b = source_remapping[&alias_b_ref];
        assert_eq!(static_forest[final_alias_a].digest(), static_forest[final_alias_b].digest());

        // Exact-path linking still uses execution identity, so the first retained metadata wins.
        let mut exact_builder = MastForestBuilder::new([&static_forest]).unwrap();
        let exact_alias_b_ref = {
            let source_forest = Arc::clone(&exact_builder.statically_linked_mast);
            let node = source_forest[final_alias_b].clone();
            let node_refs_by_source_id = BTreeMap::new();
            let child_refs = exact_builder
                .pending_refs_for_statically_linked_source(&node, &node_refs_by_source_id);
            exact_builder
                .ensure_node_from_statically_linked_source_ref(
                    source_forest.as_ref(),
                    final_alias_b,
                    node,
                    child_refs,
                    None,
                )
                .unwrap()
        };
        record_test_root(&mut exact_builder, exact_alias_b_ref);
        let (_exact_forest, exact_remapping, exact_source_graph, _) =
            exact_builder.build().unwrap().into_parts_with_source_graph();
        let final_exact_alias_b = exact_remapping[&exact_alias_b_ref];
        assert!(source_asm_contexts(&exact_source_graph, final_exact_alias_b).is_empty());
    }

    #[test]
    fn test_source_graph_distinguishes_same_digest_alias_roots() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let alias_a_asm_op =
            add_test_asm_op(&mut builder, AssemblyOp::new(None, "alias_a".into(), 1, "add".into()));
        let alias_b_asm_op =
            add_test_asm_op(&mut builder, AssemblyOp::new(None, "alias_b".into(), 1, "add".into()));
        let alias_a_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![(0, alias_a_asm_op)], vec![])
            .unwrap();
        let alias_b_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![(0, alias_b_asm_op)], vec![])
            .unwrap();
        record_test_root(&mut builder, alias_a_ref);
        record_test_root(&mut builder, alias_b_ref);

        let (forest, remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_source_graph();
        let final_alias_a = remapping[&alias_a_ref];
        let final_alias_b = remapping[&alias_b_ref];
        let root_contexts = source_graph
            .roots()
            .iter()
            .flat_map(|source_root| source_graph.nodes()[*source_root].asm_ops())
            .map(|(_, asm_op)| asm_op.context_name().to_string())
            .collect::<BTreeSet<_>>();

        assert_eq!(final_alias_a, final_alias_b);
        assert_eq!(forest.num_nodes(), 1);
        assert_eq!(source_graph.roots().len(), 2);
        assert_eq!(root_contexts, BTreeSet::from(["alias_a".to_string(), "alias_b".to_string()]));
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
            .ensure_block_ref(vec![Operation::Add], vec![(0, alias_a_asm_op)], vec![])
            .unwrap();
        let alias_b_ref = source_builder
            .ensure_block_ref(vec![Operation::Add], vec![(0, alias_b_asm_op)], vec![])
            .unwrap();
        record_test_root(&mut source_builder, alias_a_ref);
        record_test_root(&mut source_builder, alias_b_ref);

        let (static_forest, source_remapping) = source_builder.build().unwrap().into_parts();
        let final_alias_a = source_remapping[&alias_a_ref];

        let mut builder = MastForestBuilder::new([&static_forest]).unwrap();
        let linked_ref = builder
            .ensure_external_link_with_source_ref(
                static_forest[final_alias_a].digest(),
                None,
                None,
                None,
            )
            .unwrap();
        record_test_root(&mut builder, linked_ref);
        let (forest, remapping) = builder.build().unwrap().into_parts();
        let final_linked = remapping[&linked_ref];

        // Only one node should be in the forest — the selected alias.
        assert_eq!(forest.num_nodes(), 1, "only the selected alias should be imported");
        assert_eq!(final_linked, MastNodeId::new_unchecked(0));
    }

    #[test]
    fn test_static_link_ambiguous_same_commitment_source_root_stays_external() {
        let mut source_a_builder = MastForestBuilder::new(&[]).unwrap();
        let source_a_asm_op = add_test_asm_op(
            &mut source_a_builder,
            AssemblyOp::new(None, "source_a".into(), 1, "add".into()),
        );
        let source_a_ref = source_a_builder
            .ensure_block_ref(vec![Operation::Add], vec![(0, source_a_asm_op)], vec![])
            .unwrap();
        record_test_root(&mut source_a_builder, source_a_ref);
        let (source_a_forest, source_a_remapping) = source_a_builder.build().unwrap().into_parts();
        let source_a_root = source_a_remapping[&source_a_ref];

        let mut source_b_builder = MastForestBuilder::new(&[]).unwrap();
        let source_b_asm_op = add_test_asm_op(
            &mut source_b_builder,
            AssemblyOp::new(None, "source_b".into(), 1, "add".into()),
        );
        let source_b_ref = source_b_builder
            .ensure_block_ref(vec![Operation::Add], vec![(0, source_b_asm_op)], vec![])
            .unwrap();
        record_test_root(&mut source_b_builder, source_b_ref);
        let (source_b_forest, source_b_remapping) = source_b_builder.build().unwrap().into_parts();
        let source_b_root = source_b_remapping[&source_b_ref];

        assert_eq!(source_a_root, source_b_root);
        assert_eq!(source_a_forest.commitment(), source_b_forest.commitment());
        assert_eq!(
            source_a_forest[source_a_root].digest(),
            source_b_forest[source_b_root].digest()
        );

        let mut builder = MastForestBuilder::new([&source_a_forest, &source_b_forest]).unwrap();
        let linked_ref = builder
            .ensure_external_link_with_source_ref(
                source_a_forest[source_a_root].digest(),
                Some(source_a_forest.commitment()),
                Some(source_a_root),
                None,
            )
            .unwrap();

        assert!(
            builder.nodes[linked_ref].kind.is_external(),
            "ambiguous same-commitment provenance must not import the wrong source metadata"
        );
    }

    /// Provenance-aware static linking imports package-owned source metadata for the selected root.
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
            .ensure_block_ref(vec![Operation::Add], vec![(0, alias_a_asm_op)], vec![])
            .unwrap();
        let alias_b_ref = source_builder
            .ensure_block_ref(vec![Operation::Add], vec![(0, alias_b_asm_op)], vec![])
            .unwrap();
        record_test_root(&mut source_builder, alias_a_ref);
        record_test_root(&mut source_builder, alias_b_ref);

        let (static_forest, source_remapping, static_source_graph, _) =
            source_builder.build().unwrap().into_parts_with_source_graph();
        let final_alias_a = source_remapping[&alias_a_ref];
        let final_alias_b = source_remapping[&alias_b_ref];
        assert_eq!(static_forest[final_alias_a].digest(), static_forest[final_alias_b].digest());
        let alias_b_source_root = static_source_graph.roots()[1];
        let package_debug_info = package_debug_info_from_source_graph(&static_source_graph);

        let mut provenance_builder =
            MastForestBuilder::new_with_static_libraries([StaticLibrary::new(
                &static_forest,
                Some(package_debug_info),
            )])
            .unwrap();
        let linked_alias_b_ref = provenance_builder
            .ensure_external_link_with_source_ref(
                static_forest[final_alias_b].digest(),
                Some(static_forest.commitment()),
                Some(final_alias_b),
                Some(DebugSourceMastNodeId::from(u32::from(alias_b_source_root))),
            )
            .unwrap();
        record_test_root(&mut provenance_builder, linked_alias_b_ref);
        let (_linked_forest, linked_remapping, linked_source_graph, _) =
            provenance_builder.build().unwrap().into_parts_with_source_graph();
        let final_linked_alias_b = linked_remapping[&linked_alias_b_ref];
        let linked_source_root = linked_source_graph.roots()[0];
        let linked_source_node = &linked_source_graph.nodes()[linked_source_root];

        assert_eq!(linked_source_node.exec_node(), final_linked_alias_b);
        assert_eq!(
            linked_source_node.asm_ops().first().unwrap().1.context_name(),
            "alias_b",
            "exact static provenance should select the hinted package source occurrence",
        );
    }
}
