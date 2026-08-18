use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};

use miden_assembly_syntax::{
    ast::DebugInlineCallInfo,
    debuginfo::{FileLineCol, SourceManager},
};
use miden_core::{
    Felt, Word,
    advice::AdviceMap,
    chiplets::hasher,
    mast::{
        BasicBlockNode, BasicBlockNodeBuilder, CallNode, DynNode, JoinNode, LoopNode, MastForest,
        MastForestRootMap, MastNode, MastNodeExt, OpBatch, SplitNode, error_code_from_msg,
    },
    operations::{AssemblyOp, Operation},
    serde::Serializable,
    utils::{IndexVec, bytes_to_packed_u32_elements},
};
use miden_mast_package::{
    ManifestValidationError,
    debug_info::{
        DebugFunctionIdx, DebugInfoBuilder, DebugInfoTableRemapping, DebugLocIdx, DebugSourceAsmOp,
        DebugSourceInlineCall, DebugSourceVar, FunctionInfo, PackageDebugInfo,
    },
};

use super::{GlobalItemIndex, LinkerError, Procedure};
use crate::{
    diagnostics::{IntoDiagnostic, Report, WrapErr},
    linker::LinkLibrary,
    report,
};

mod finalizer;
use finalizer::{BuiltMastForest, MastForestFinalizer};
mod node_identity_policy;
use node_identity_policy::FinalForestLayout;
mod pending_record;
use pending_record::{MastNodeKey, PendingMastNode, PendingMastNodeDraft, PendingMastNodeKind};
pub(crate) use pending_record::{MastNodeRef, SourceNodeRef};
mod static_import;

/// One use of an interned execution node together with its exact source/debug occurrence.
///
/// Execution nodes are deduplicated, but source occurrences are not. Keeping these references
/// paired prevents a later use of the same execution node from changing which source occurrence
/// is selected for an earlier parent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MastNodeUse {
    node_ref: MastNodeRef,
    source_ref: SourceNodeRef,
}

impl MastNodeUse {
    pub(crate) fn new(node_ref: MastNodeRef, source_ref: SourceNodeRef) -> Self {
        Self { node_ref, source_ref }
    }

    pub(crate) fn node_ref(self) -> MastNodeRef {
        self.node_ref
    }

    pub(crate) fn source_ref(self) -> SourceNodeRef {
        self.source_ref
    }
}

// CONSTANTS
// ================================================================================================

/// Constant that decides how many operation batches disqualify a procedure from inlining.
const PROCEDURE_INLINING_THRESHOLD: usize = 32;

/// Domain used when basic-block interning keys must include execution-visible error codes.
const BASIC_BLOCK_ERROR_CODE_KEY_DOMAIN: Felt = Felt::new_unchecked(0x2473_0001);
/// Domain used when control-node interning keys must include child keys.
const CHILD_KEY_DOMAIN: Felt = Felt::new_unchecked(0x2473_0002);
/// Domain used when basic-block interning keys must preserve source-index layout.
const BASIC_BLOCK_SOURCE_LAYOUT_KEY_DOMAIN: Felt = Felt::new_unchecked(0x2473_0003);

type InlineFunctionKey = (Arc<str>, Option<Arc<str>>, FileLineCol);
type InlineCallChainKey = Vec<(DebugFunctionIdx, DebugLocIdx)>;

// MAST FOREST BUILDER
// ================================================================================================

/// Builder for a [`MastForest`].
///
/// The purpose of the builder is to ensure that the underlying MAST forest contains as little
/// information as possible needed to adequately describe the logical MAST forest. Specifically:
/// - The builder deduplicates nodes that have the same MAST root when their execution-visible data
///   and source-index layouts are compatible.
/// - The builder tries to merge adjacent basic blocks and eliminate the source block whenever this
///   does not have an impact on other nodes in the forest.
#[derive(Clone, Debug, Default)]
pub struct MastForestBuilder {
    /// Advice map entries registered while building this forest.
    advice_map: AdviceMap,
    /// Package debug info produced while building the forest
    debug_info: DebugInfoBuilder<MastNodeRef, SourceNodeRef>,
    /// Interned source-level functions referenced by inline-call rows.
    inline_function_indices: BTreeMap<InlineFunctionKey, DebugFunctionIdx>,
    /// Decorated source trees reused by identical exec occurrences.
    decorated_source_refs: BTreeMap<(SourceNodeRef, InlineCallChainKey), SourceNodeRef>,
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
    /// Number of source/debug occurrences already selected as procedure roots per execution ref.
    #[cfg(test)]
    procedure_source_root_count_by_node_ref: BTreeMap<MastNodeRef, usize>,
    /// A map of MAST node interning keys to their corresponding builder-local node refs.
    node_ref_by_key: BTreeMap<MastNodeKey, MastNodeRef>,
    /// Builder-owned dense storage for node refs.
    nodes: IndexVec<MastNodeRef, PendingMastNode>,
    /// Most recent source occurrence for each execution node ref.
    latest_source_ref_by_node_ref: BTreeMap<MastNodeRef, SourceNodeRef>,
    /// Selectable source occurrences recorded for each execution node ref, in creation order.
    ///
    /// Supplemental range records created while merging blocks are excluded because they do not
    /// represent a complete occurrence of the execution node.
    source_refs_by_node_ref: BTreeMap<MastNodeRef, Vec<SourceNodeRef>>,
    /// Source occurrences which represent unresolved external execution boundaries.
    ///
    /// This is tracked independently of the execution node kind because an external placeholder
    /// can be deduplicated with, or later replaced by, a concrete node with the same digest.
    external_boundary_source_refs: BTreeSet<SourceNodeRef>,
    /// A MastForest that contains the MAST of all statically-linked libraries, it's used to find
    /// precompiled procedures and copy their subtrees instead of inserting external nodes.
    statically_linked_mast: Arc<MastForest>,
    /// Original statically-linked library forests, parallel to the inputs used to build
    /// `statically_linked_mast`.
    statically_linked_source_forests: Vec<Arc<MastForest>>,
    /// Package-owned debug info decoded from each statically-linked package, when available.
    statically_linked_package_debug_info: Vec<Option<PackageDebugInfo>>,
    /// Shared-table mappings imported lazily from each statically-linked package.
    statically_linked_debug_table_remappings: Vec<Option<Arc<DebugInfoTableRemapping>>>,
    /// Maps each statically linked source forest commitment to its positions in the merged forest
    /// root map.
    statically_linked_forest_indices_by_commitment: BTreeMap<Word, Vec<usize>>,
    /// Maps procedure roots from each source static library to their new root ID in the merged
    /// static forest.
    statically_linked_root_map: MastForestRootMap,
}

/// Statically-linked library data used by [`MastForestBuilder`].
pub(crate) struct StaticLibrary<'a> {
    mast: &'a MastForest,
    /// This field is expected to hold _validated_ package debug info - invalid debug info may
    /// cause panics during assembly.
    debug_info: Option<PackageDebugInfo>,
    source_library_commitment: Word,
    alternate_source_library_commitment: Option<Word>,
}

impl<'a> StaticLibrary<'a> {
    fn from_mast_forest(mast: &'a MastForest, debug_info: Option<PackageDebugInfo>) -> Self {
        Self {
            mast,
            debug_info,
            // Direct forest-backed static libraries do not have a package digest, so their source
            // identity is the full forest commitment. This keeps provenance hints scoped to the
            // same roots, external dependencies, and advice as package-backed static libraries.
            source_library_commitment: mast.commitment(),
            alternate_source_library_commitment: None,
        }
    }

    pub(crate) fn from_link_library(
        library: &'a LinkLibrary,
        debug_info: Option<PackageDebugInfo>,
    ) -> Result<Self, ManifestValidationError> {
        Ok(Self::from_mast_forest(library.mast().as_ref(), debug_info)
            .with_source_library_commitment(library.commitment())
            .with_alternate_source_library_commitment(library.interface_digest()?))
    }

    fn with_source_library_commitment(mut self, source_library_commitment: Word) -> Self {
        self.source_library_commitment = source_library_commitment;
        self
    }

    fn with_alternate_source_library_commitment(mut self, source_library_commitment: Word) -> Self {
        self.alternate_source_library_commitment = Some(source_library_commitment);
        self
    }
}

impl MastForestBuilder {
    /// Creates a new builder which will transitively include the MAST of any procedures referenced
    /// in the provided set of statically-linked libraries.
    ///
    /// In all other cases, references to procedures not present in the main MastForest are assumed
    /// to be dynamically-linked, and are inserted as an external node. Dynamically-linked libraries
    /// must be provided separately to the processor at runtime.
    #[cfg(test)]
    fn new<'a>(static_libraries: impl IntoIterator<Item = &'a MastForest>) -> Result<Self, Report> {
        Self::new_with_static_libraries(
            static_libraries
                .into_iter()
                .map(|mast| StaticLibrary::from_mast_forest(mast, None)),
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
        let mut debug_info_builder = DebugInfoBuilder::default();
        let statically_linked_package_debug_info = static_libraries
            .iter()
            .map(|library| {
                // Error messages from every static library must remain available even when none of
                // its source graph is linked. A later lazy table import revisits these rows, but
                // insertion is idempotent and preserves this first-wins ordering.
                if let Some(debug_info) = library.debug_info.as_ref() {
                    for row in debug_info.error_messages() {
                        debug_info_builder.add_error_message(
                            row.err_code,
                            debug_info.get_string(row.message).unwrap(),
                        );
                    }
                }
                library.debug_info.clone()
            })
            .collect::<Vec<_>>();
        let statically_linked_debug_table_remappings =
            static_libraries.iter().map(|_| None).collect();
        let mut statically_linked_forest_indices_by_commitment = BTreeMap::new();
        for (idx, library) in static_libraries.iter().enumerate() {
            statically_linked_forest_indices_by_commitment
                .entry(library.source_library_commitment)
                .or_insert_with(Vec::new)
                .push(idx);
            if let Some(source_library_commitment) = library.alternate_source_library_commitment
                && source_library_commitment != library.source_library_commitment
            {
                statically_linked_forest_indices_by_commitment
                    .entry(source_library_commitment)
                    .or_insert_with(Vec::new)
                    .push(idx);
            }
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
            debug_info: debug_info_builder,
            statically_linked_mast: Arc::new(statically_linked_mast),
            statically_linked_source_forests,
            statically_linked_package_debug_info,
            statically_linked_debug_table_remappings,
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

    fn intern_pending_node_use(
        &mut self,
        draft: PendingMastNodeDraft,
        source_child_refs: Vec<SourceNodeRef>,
    ) -> Result<MastNodeUse, Report> {
        let dedup_key = self.dedup_key_for_pending_data(&draft);
        let node_ref = if let Some(node_ref) = self.find_node_ref_by_key(&dedup_key) {
            if self.should_replace_pending_node(node_ref, &draft) {
                self.replace_pending_node_record_ref(
                    node_ref,
                    dedup_key,
                    draft.clone(),
                    &source_child_refs,
                );
            }
            node_ref
        } else {
            self.insert_pending_node_record_ref(dedup_key, draft.clone())?
        };

        let source_ref = self.record_source_occurrence(node_ref, source_child_refs, &draft)?;
        Ok(MastNodeUse::new(node_ref, source_ref))
    }

    fn intern_pending_node(&mut self, draft: PendingMastNodeDraft) -> Result<MastNodeRef, Report> {
        let source_child_refs = self.source_child_refs_for_node_refs(&draft.child_refs);
        Ok(self.intern_pending_node_use(draft, source_child_refs)?.node_ref())
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
        source_child_refs: &[SourceNodeRef],
    ) {
        // An external node is a zero-child placeholder, so every source occurrence recorded for
        // it initially has no children. Preserve those occurrence IDs when the concrete node
        // becomes available, but update their shape to match the replacement. This also preserves
        // references to those occurrences from source roots, parent occurrences, and functions.
        if let Some(source_refs) = self.source_refs_by_node_ref.get(&node_ref) {
            for &source_ref in source_refs {
                self.debug_info[source_ref].children = source_child_refs.to_vec();
            }
        }

        self.nodes[node_ref] = PendingMastNode {
            key,
            digest: draft.digest,
            kind: draft.kind,
            child_refs: draft.child_refs,
        };
        self.node_ref_by_key.insert(key, node_ref);
    }

    fn insert_or_replace_pending_node_record_ref(
        &mut self,
        key: MastNodeKey,
        draft: PendingMastNodeDraft,
        source_child_refs: &[SourceNodeRef],
    ) -> Result<MastNodeRef, Report> {
        if let Some(node_ref) = self.find_node_ref_by_key(&key) {
            if self.should_replace_pending_node(node_ref, &draft) {
                self.replace_pending_node_record_ref(node_ref, key, draft, source_child_refs);
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
        let error_code_key = if error_code_data.is_empty() {
            block_digest
        } else {
            hash_basic_block_key_data(
                BASIC_BLOCK_ERROR_CODE_KEY_DOMAIN,
                block_digest,
                &error_code_data,
            )
        };

        // An explicit Noop has a zero opcode, so it can be indistinguishable from group padding in
        // the MAST digest. Source indices, however, are recorded against raw operations and later
        // adjusted with the retained block's padding layout. Preserve that complete layout in the
        // pending identity whenever an explicit raw Noop makes digest-only reuse ambiguous.
        let Some(source_layout_data) = serialize_basic_block_source_layout(op_batches) else {
            return error_code_key;
        };

        hash_basic_block_key_data(
            BASIC_BLOCK_SOURCE_LAYOUT_KEY_DOMAIN,
            error_code_key,
            &source_layout_data,
        )
    }

    #[inline]
    pub(crate) fn debug_info_mut(&mut self) -> &mut DebugInfoBuilder<MastNodeRef, SourceNodeRef> {
        &mut self.debug_info
    }

    pub(crate) fn register_inline_function(
        &mut self,
        inline_call: &DebugInlineCallInfo,
    ) -> DebugFunctionIdx {
        let key = (
            Arc::from(inline_call.name()),
            inline_call.linkage_name().map(Arc::from),
            inline_call.declaration().clone(),
        );
        if let Some(function_idx) = self.inline_function_indices.get(&key) {
            return *function_idx;
        }

        let (name, linkage_name, declaration) = &key;
        let file_idx = self.debug_info.add_file(declaration.uri.clone(), None);
        let name_idx = self.debug_info.add_string(name.clone());
        let mut function = FunctionInfo::new(
            None,
            name_idx,
            file_idx,
            declaration.line,
            declaration.column,
            Word::default(),
        );
        if let Some(linkage_name) = linkage_name {
            function = function.with_linkage_name(self.debug_info.add_string(linkage_name.clone()));
        }
        let function_idx = self.debug_info.add_function(function);
        self.inline_function_indices.insert(key, function_idx);
        function_idx
    }

    fn intern_pending_node_with_asm_op_use(
        &mut self,
        mut draft: PendingMastNodeDraft,
        asm_op: AssemblyOp,
        source_child_refs: Vec<SourceNodeRef>,
    ) -> Result<MastNodeUse, Report> {
        let dedup_key = self.dedup_key_for_pending_data(&draft);

        let location_idx = asm_op.location().map(|loc| self.debug_info.add_location(loc.clone()));
        let context_name_idx = self.debug_info.add_string(asm_op.context_name().clone());
        let op_name_idx = self.debug_info.add_string(asm_op.op().clone());
        draft.asm_ops = vec![DebugSourceAsmOp::new(
            0,
            location_idx,
            context_name_idx,
            op_name_idx,
            asm_op.num_cycles(),
        )];
        let node_ref =
            if let Some(node_ref) = self.find_reusable_node_ref_by_key(&dedup_key, &draft) {
                node_ref
            } else {
                self.insert_or_replace_pending_node_record_ref(
                    dedup_key,
                    draft.clone(),
                    &source_child_refs,
                )?
            };

        let source_ref = self.record_source_occurrence(node_ref, source_child_refs, &draft)?;

        Ok(MastNodeUse::new(node_ref, source_ref))
    }

    fn source_refs_for_node_ref_occurrences(
        &self,
        node_refs: &[MastNodeRef],
    ) -> Vec<SourceNodeRef> {
        let mut child_counts = BTreeMap::<MastNodeRef, usize>::new();
        for node_ref in node_refs {
            *child_counts.entry(*node_ref).or_default() += 1;
        }

        let mut child_seen = BTreeMap::<MastNodeRef, usize>::new();
        node_refs
            .iter()
            .map(|node_ref| {
                let history = self
                    .source_refs_by_node_ref
                    .get(node_ref)
                    .expect("execution ref must have a source occurrence");
                let needed = child_counts[node_ref];
                let seen = child_seen.entry(*node_ref).or_default();
                let start = history.len().saturating_sub(needed);
                let source_ref = history
                    .get((start + *seen).min(history.len() - 1))
                    .copied()
                    .expect("execution ref must have at least one source occurrence");
                *seen += 1;
                source_ref
            })
            .collect()
    }

    fn source_child_refs_for_node_refs(&self, child_refs: &[MastNodeRef]) -> Vec<SourceNodeRef> {
        self.source_refs_for_node_ref_occurrences(child_refs)
    }

    /// Records a source occurrence of an `exec` target under the supplied inline call chain.
    ///
    /// `exec` reuses the callee's execution node instead of creating a control node. An undecorated
    /// use can reuse the exact source occurrence carried by [`MastNodeUse`]. When an inline chain
    /// is active, clone its source-occurrence tree so the chain is visible for every executed
    /// operation while leaving the shared MAST nodes and other source occurrences unchanged.
    pub(crate) fn record_exec_inline_calls(
        &mut self,
        target: MastNodeUse,
        inline_calls: &[DebugSourceInlineCall],
    ) -> Result<MastNodeUse, Report> {
        if inline_calls.is_empty() {
            return Ok(target);
        }

        let chain_key = inline_calls
            .iter()
            .map(|inline_call| (inline_call.callee_idx, inline_call.loc_idx))
            .collect::<Vec<_>>();
        let cache_key = (target.source_ref(), chain_key);
        if let Some(source_ref) = self.decorated_source_refs.get(&cache_key) {
            return Ok(MastNodeUse::new(target.node_ref(), *source_ref));
        }

        let mut cloned = BTreeMap::new();
        let decorated_source_ref = self.clone_source_occurrence_with_inline_calls(
            target.source_ref(),
            inline_calls,
            &mut cloned,
        )?;
        self.decorated_source_refs.insert(cache_key, decorated_source_ref);
        Ok(MastNodeUse::new(target.node_ref(), decorated_source_ref))
    }

    fn clone_source_occurrence_with_inline_calls(
        &mut self,
        source_ref: SourceNodeRef,
        active_inline_calls: &[DebugSourceInlineCall],
        cloned: &mut BTreeMap<SourceNodeRef, SourceNodeRef>,
    ) -> Result<SourceNodeRef, Report> {
        if let Some(cloned_ref) = cloned.get(&source_ref) {
            return Ok(*cloned_ref);
        }

        let is_external_boundary = self.external_boundary_source_refs.contains(&source_ref);
        let source_node =
            self.source_occurrence_with_inline_calls(source_ref, active_inline_calls, cloned)?;
        let cloned_ref = self.push_source_occurrence(
            source_node.exec_node,
            source_node.children,
            source_node.op_start as usize,
            source_node.op_end as usize,
            source_node.asm_ops,
            source_node.debug_vars,
            source_node.inline_calls,
            &[],
            is_external_boundary,
            false,
        )?;
        cloned.insert(source_ref, cloned_ref);
        Ok(cloned_ref)
    }

    fn source_occurrence_with_inline_calls(
        &mut self,
        source_ref: SourceNodeRef,
        active_inline_calls: &[DebugSourceInlineCall],
        cloned: &mut BTreeMap<SourceNodeRef, SourceNodeRef>,
    ) -> Result<miden_mast_package::debug_info::SourceNode<MastNodeRef, SourceNodeRef>, Report>
    {
        let mut pending = self.debug_info[source_ref]
            .children
            .iter()
            .rev()
            .copied()
            .map(|child_ref| (child_ref, false))
            .collect::<Vec<_>>();

        while let Some((pending_ref, children_cloned)) = pending.pop() {
            if cloned.contains_key(&pending_ref) {
                continue;
            }

            if !children_cloned {
                pending.push((pending_ref, true));
                pending.extend(
                    self.debug_info[pending_ref]
                        .children
                        .iter()
                        .rev()
                        .copied()
                        .filter(|child_ref| !cloned.contains_key(child_ref))
                        .map(|child_ref| (child_ref, false)),
                );
                continue;
            }

            let is_external_boundary = self.external_boundary_source_refs.contains(&pending_ref);
            let source_node = self.source_occurrence_with_cloned_children_and_inline_calls(
                pending_ref,
                active_inline_calls,
                cloned,
            );
            let cloned_ref = self.push_source_occurrence(
                source_node.exec_node,
                source_node.children,
                source_node.op_start as usize,
                source_node.op_end as usize,
                source_node.asm_ops,
                source_node.debug_vars,
                source_node.inline_calls,
                &[],
                is_external_boundary,
                false,
            )?;
            cloned.insert(pending_ref, cloned_ref);
        }

        Ok(self.source_occurrence_with_cloned_children_and_inline_calls(
            source_ref,
            active_inline_calls,
            cloned,
        ))
    }

    fn source_occurrence_with_cloned_children_and_inline_calls(
        &self,
        source_ref: SourceNodeRef,
        active_inline_calls: &[DebugSourceInlineCall],
        cloned: &BTreeMap<SourceNodeRef, SourceNodeRef>,
    ) -> miden_mast_package::debug_info::SourceNode<MastNodeRef, SourceNodeRef> {
        let mut source_node = self.debug_info[source_ref].clone();
        let is_external_boundary = self.external_boundary_source_refs.contains(&source_ref);
        let child_refs = source_node
            .children
            .iter()
            .map(|child_ref| {
                *cloned.get(child_ref).expect("source child must be cloned before its parent")
            })
            .collect();

        let mut inline_calls = Vec::with_capacity(
            source_node.inline_calls.len()
                + active_inline_calls.len()
                    * core::cmp::max(
                        source_node.op_end.saturating_sub(source_node.op_start),
                        u32::from(is_external_boundary),
                    ) as usize,
        );
        if source_node.op_start == source_node.op_end && is_external_boundary {
            let boundary_op_idx = source_node.op_start;
            inline_calls.extend(source_node.inline_calls.iter().copied());
            inline_calls.extend(active_inline_calls.iter().map(|inline_call| {
                DebugSourceInlineCall {
                    op_idx: boundary_op_idx,
                    callee_idx: inline_call.callee_idx,
                    loc_idx: inline_call.loc_idx,
                }
            }));
        }
        for op_idx in source_node.op_start..source_node.op_end {
            inline_calls.extend(
                source_node
                    .inline_calls
                    .iter()
                    .filter(|inline_call| inline_call.op_idx == op_idx)
                    .copied(),
            );
            inline_calls.extend(active_inline_calls.iter().map(|inline_call| {
                DebugSourceInlineCall {
                    op_idx,
                    callee_idx: inline_call.callee_idx,
                    loc_idx: inline_call.loc_idx,
                }
            }));
        }

        source_node.children = child_refs;
        source_node.inline_calls = inline_calls;
        source_node
    }

    fn record_source_occurrence(
        &mut self,
        exec_ref: MastNodeRef,
        child_refs: Vec<SourceNodeRef>,
        draft: &PendingMastNodeDraft,
    ) -> Result<SourceNodeRef, Report> {
        let (op_start, op_end) = self.source_op_range_for_draft(draft);
        self.record_source_occurrence_with_range(exec_ref, child_refs, draft, op_start, op_end)
    }

    fn record_source_occurrence_with_range(
        &mut self,
        exec_ref: MastNodeRef,
        child_refs: Vec<SourceNodeRef>,
        draft: &PendingMastNodeDraft,
        op_start: usize,
        op_end: usize,
    ) -> Result<SourceNodeRef, Report> {
        let is_external_boundary = draft.kind.is_external();
        if is_external_boundary && !self.nodes[exec_ref].kind.is_external() {
            let source_ref = self
                .latest_source_ref_by_node_ref
                .get(&exec_ref)
                .copied()
                .expect("a concrete execution node must have a source occurrence");
            for function in &draft.functions {
                self.debug_info.set_function_source_node(*function, source_ref);
            }
            return Ok(source_ref);
        }

        let source_ref = self.push_source_occurrence(
            exec_ref,
            child_refs,
            op_start,
            op_end,
            draft.asm_ops.clone(),
            draft.debug_vars.clone(),
            draft.inline_calls.clone(),
            &draft.functions,
            is_external_boundary,
            true,
        )?;

        if !is_external_boundary {
            self.remap_external_boundary_occurrences(exec_ref, source_ref)?;
        }

        Ok(source_ref)
    }

    fn remap_external_boundary_occurrences(
        &mut self,
        exec_ref: MastNodeRef,
        concrete_source_ref: SourceNodeRef,
    ) -> Result<(), Report> {
        let external_boundaries = self
            .external_boundary_source_refs
            .iter()
            .copied()
            .filter(|source_ref| self.debug_info[*source_ref].exec_node == exec_ref)
            .collect::<Vec<_>>();

        for boundary_source_ref in external_boundaries {
            let active_inline_calls = self.debug_info[boundary_source_ref].inline_calls.clone();
            let replacement = if active_inline_calls.is_empty() {
                self.debug_info[concrete_source_ref].clone()
            } else {
                self.source_occurrence_with_inline_calls(
                    concrete_source_ref,
                    &active_inline_calls,
                    &mut BTreeMap::new(),
                )?
            };
            self.debug_info[boundary_source_ref] = replacement;
            self.external_boundary_source_refs.remove(&boundary_source_ref);
        }

        Ok(())
    }

    fn source_op_range_for_draft(&self, draft: &PendingMastNodeDraft) -> (usize, usize) {
        let op_count = if let Some(op_batches) = draft.kind.basic_block_op_batches() {
            op_batches.iter().flat_map(OpBatch::raw_ops).count()
        } else {
            draft
                .asm_ops
                .iter()
                .map(|asm_op| asm_op.op_idx as usize + 1)
                .chain(draft.debug_vars.iter().map(|debug_var| debug_var.op_idx as usize + 1))
                .max()
                .unwrap_or(0)
        };

        (0, op_count)
    }

    fn push_source_occurrence(
        &mut self,
        exec_ref: MastNodeRef,
        child_refs: Vec<SourceNodeRef>,
        op_start: usize,
        op_end: usize,
        asm_ops: Vec<DebugSourceAsmOp>,
        debug_vars: Vec<DebugSourceVar>,
        inline_calls: Vec<DebugSourceInlineCall>,
        functions: &[DebugFunctionIdx],
        is_external_boundary: bool,
        update_latest: bool,
    ) -> Result<SourceNodeRef, Report> {
        let source_ref = self
            .debug_info
            .add_node(miden_mast_package::debug_info::SourceNode {
                exec_node: exec_ref,
                children: child_refs,
                op_start: op_start.try_into().expect("invalid op start"),
                op_end: op_end.try_into().expect("invalid op end"),
                asm_ops,
                debug_vars,
                inline_calls,
            })
            .into_diagnostic()
            .wrap_err("assembler created too many source MAST node refs")?;
        if is_external_boundary {
            self.external_boundary_source_refs.insert(source_ref);
        }
        for function in functions {
            self.debug_info.set_function_source_node(*function, source_ref);
        }
        if update_latest {
            self.latest_source_ref_by_node_ref.insert(exec_ref, source_ref);
            self.source_refs_by_node_ref.entry(exec_ref).or_default().push(source_ref);
        }
        Ok(source_ref)
    }

    fn function_indices_for_source_ref(&self, source_ref: SourceNodeRef) -> Vec<DebugFunctionIdx> {
        self.debug_info
            .debug_info()
            .functions()
            .iter()
            .enumerate()
            .filter(|(_, function)| {
                function
                    .source_node
                    .into_option()
                    .is_some_and(|function_source_ref| function_source_ref == source_ref)
            })
            .map(|(index, _)| {
                DebugFunctionIdx::from(u32::try_from(index).expect("too many functions"))
            })
            .collect()
    }

    /// Removes the unused nodes that were created as part of the assembly process, and returns the
    /// resulting MAST forest.
    ///
    /// Finalization preserves every recorded procedure root and every pending node reachable from
    /// those roots. Pending records which are unreachable from all roots are pruned.
    ///
    /// Final nodes are emitted in dense `MastForest` order: external nodes, then basic blocks,
    /// then internal nodes with children before parents.
    ///
    /// Finalization must happen in the order used below: plan the live layout first, materialize
    /// live nodes so builder-local refs have final node IDs, then register metadata against those
    /// final IDs before assembling the immutable forest.
    ///
    /// It also returns the map from assembly-time node refs to final node IDs. Any [`MastNodeRef`]
    /// used in reference to this builder should be resolved using this map.
    pub(crate) fn build(mut self) -> Result<BuiltMastForest, Report> {
        let procedure_root_refs = core::mem::take(&mut self.procedure_root_refs);

        let layout = FinalForestLayout::plan(procedure_root_refs, &self.nodes);

        let mut finalizer = MastForestFinalizer::new();
        finalizer.materialize_live_nodes(&layout.live_node_refs, &self.nodes)?;

        finalizer.into_built_forest(&layout.procedure_root_refs, self.advice_map, self.debug_info)
    }
}

/// Computes the number of operations for a node and adjusts AssemblyOp indices if needed.
///
/// For basic block nodes, adjusts indices to account for padding NOOPs in OpBatches.
/// For control flow nodes, computes the operation count from the maximum index.
fn compute_operations_and_adjust_mappings(
    node: &MastNode,
    mappings: Vec<usize>,
) -> (usize, Vec<usize>) {
    match node {
        MastNode::Block(block) => (
            block.num_operations() as usize,
            BasicBlockNode::adjust_asm_op_indices(mappings, block.op_batches()),
        ),
        _ => {
            let num_ops = mappings.iter().map(|idx| idx + 1).max().unwrap_or(0);
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

fn hash_basic_block_key_data(domain: Felt, base_key: Word, data: &[u8]) -> Word {
    let data_len = data.len() as u64;
    let mut elements = Vec::with_capacity(7 + data.len().div_ceil(4));
    elements.push(domain);
    elements.extend_from_slice(base_key.as_elements());
    elements.push(Felt::from_u32(data_len as u32));
    elements.push(Felt::from_u32((data_len >> 32) as u32));
    elements.extend(bytes_to_packed_u32_elements(data));
    hasher::hash_elements(&elements)
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

/// Serializes the information needed to reconstruct a block's raw-to-padded operation map.
///
/// The raw operation count and every raw boundary followed by an assembler-inserted padding Noop
/// fully determine the map. Blocks without explicit raw Noops return `None`: absent a hash
/// collision, their nonzero opcodes already distinguish the executable layout in the MAST digest.
fn serialize_basic_block_source_layout(op_batches: &[OpBatch]) -> Option<Vec<u8>> {
    let (raw_op_count, has_explicit_noop) = op_batches.iter().flat_map(OpBatch::raw_ops).fold(
        (0_u64, false),
        |(count, has_explicit_noop), op| {
            (count + 1, has_explicit_noop || matches!(op, Operation::Noop))
        },
    );
    if !has_explicit_noop {
        return None;
    }

    let mut data = Vec::new();
    data.extend_from_slice(&raw_op_count.to_le_bytes());

    let mut raw_op_prefix = 0_u64;
    for batch in op_batches {
        for group_idx in 0..batch.num_groups() {
            let group_op_count = batch.indptr()[group_idx + 1] - batch.indptr()[group_idx];
            let has_padding = batch.padding()[group_idx];
            debug_assert!(group_op_count >= usize::from(has_padding));
            raw_op_prefix += (group_op_count - usize::from(has_padding)) as u64;
            if has_padding {
                data.extend_from_slice(&raw_op_prefix.to_le_bytes());
            }
        }
    }
    debug_assert_eq!(raw_op_prefix, raw_op_count);

    Some(data)
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
    ) -> Option<SourceNodeRef> {
        self.latest_source_ref_by_node_ref.get(&node_ref).copied()
    }

    pub(crate) fn latest_node_use(&self, node_ref: MastNodeRef) -> Option<MastNodeUse> {
        self.latest_source_ref_for_node_ref(node_ref)
            .map(|source_ref| MastNodeUse::new(node_ref, source_ref))
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
        source_manager: &dyn SourceManager,
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

        self.record_procedure_root_use(procedure.body_node_use());
        self.record_procedure_debug_info(&procedure, source_manager)?;
        self.proc_gid_by_mast_root.insert(procedure.mast_root(), gid);

        self.procedures.insert(gid, procedure);

        Ok(())
    }

    fn record_procedure_debug_info(
        &mut self,
        procedure: &Procedure,
        source_manager: &dyn SourceManager,
    ) -> Result<(), Report> {
        use miden_assembly_syntax::ast::types::Type;

        if let Ok(file_line_col) = source_manager.file_line_col(*procedure.span()) {
            let source_ref = Some(procedure.body_source_ref());
            let file_idx = self.debug_info.add_file(file_line_col.uri.clone(), None);
            let name_idx = self.debug_info.add_string(procedure.path().as_str());
            let type_idx = if let Some(signature) = procedure.signature() {
                Some(self.debug_info.register_debug_type(
                    Some(name_idx),
                    None,
                    &Type::Function(signature),
                )?)
            } else {
                None
            };
            let func_info = FunctionInfo::new(
                source_ref,
                name_idx,
                file_idx,
                file_line_col.line,
                file_line_col.column,
                procedure.mast_root(),
            );
            let func_info = if let Some(type_idx) = type_idx {
                func_info.with_type(type_idx)
            } else {
                func_info
            };
            self.debug_info.add_function(func_info);
        }

        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn record_procedure_root_ref(&mut self, root_ref: MastNodeRef) {
        if !self.procedure_root_refs.contains(&root_ref) {
            self.procedure_root_refs.push(root_ref);
        }
        if let Some(history) = self.source_refs_by_node_ref.get(&root_ref)
            && let Some(source_ref) = history
                .get(*self.procedure_source_root_count_by_node_ref.entry(root_ref).or_default())
                .copied()
                .or_else(|| history.last().copied())
            && !self.debug_info.roots().contains(&source_ref)
        {
            self.debug_info.add_root(source_ref);
            *self.procedure_source_root_count_by_node_ref.entry(root_ref).or_default() += 1;
        }
    }

    pub(crate) fn record_procedure_root_use(&mut self, root: MastNodeUse) {
        if !self.procedure_root_refs.contains(&root.node_ref()) {
            self.procedure_root_refs.push(root.node_ref());
        }
        if !self.debug_info.roots().contains(&root.source_ref()) {
            self.debug_info.add_root(root.source_ref());
        }
    }

    fn is_procedure_root_ref(&self, node_ref: MastNodeRef) -> bool {
        self.procedure_root_refs.contains(&node_ref)
    }
}

// ------------------------------------------------------------------------------------------------
/// Joining nodes
impl MastForestBuilder {
    #[cfg(test)]
    pub(crate) fn join_node_refs(
        &mut self,
        node_refs: Vec<MastNodeRef>,
        asm_op: Option<AssemblyOp>,
    ) -> Result<MastNodeRef, Report> {
        let source_refs = self.source_refs_for_node_ref_occurrences(&node_refs);
        let node_uses = node_refs
            .into_iter()
            .zip(source_refs)
            .map(|(node_ref, source_ref)| MastNodeUse::new(node_ref, source_ref))
            .collect();
        Ok(self.join_node_uses(node_uses, asm_op)?.node_ref())
    }

    pub(crate) fn join_node_uses(
        &mut self,
        node_uses: Vec<MastNodeUse>,
        asm_op: Option<AssemblyOp>,
    ) -> Result<MastNodeUse, Report> {
        debug_assert!(!node_uses.is_empty(), "cannot combine empty MAST node use list");

        let mut node_uses = self.merge_contiguous_basic_block_uses(node_uses)?;

        // build a binary tree of blocks joining them using JOIN blocks
        while node_uses.len() > 1 {
            let last_mast_node_use = if node_uses.len().is_multiple_of(2) {
                None
            } else {
                node_uses.pop()
            };

            let mut source_node_uses = Vec::new();
            core::mem::swap(&mut node_uses, &mut source_node_uses);

            let mut source_mast_node_iter = source_node_uses.drain(0..);
            while let (Some(left), Some(right)) =
                (source_mast_node_iter.next(), source_mast_node_iter.next())
            {
                let left_digest = self.pending_node_mast_root(left.node_ref());
                let right_digest = self.pending_node_mast_root(right.node_ref());
                let join_digest =
                    hasher::merge_in_domain(&[left_digest, right_digest], JoinNode::DOMAIN);
                let child_refs = vec![left.node_ref(), right.node_ref()];
                let source_child_refs = vec![left.source_ref(), right.source_ref()];
                let draft =
                    PendingMastNodeDraft::new(PendingMastNodeKind::Join, join_digest, child_refs);
                let join_mast_node_use = if let Some(ref asm_op) = asm_op {
                    self.intern_pending_node_with_asm_op_use(
                        draft,
                        asm_op.clone(),
                        source_child_refs,
                    )?
                } else {
                    self.intern_pending_node_use(draft, source_child_refs)?
                };

                node_uses.push(join_mast_node_use);
            }
            if let Some(mast_node_use) = last_mast_node_use {
                node_uses.push(mast_node_use);
            }
        }

        Ok(node_uses.remove(0))
    }

    #[cfg(test)]
    pub(crate) fn ensure_split_node_ref(
        &mut self,
        branches: [MastNodeRef; 2],
        asm_op: AssemblyOp,
        inline_calls: Vec<DebugSourceInlineCall>,
    ) -> Result<MastNodeRef, Report> {
        let source_refs = self.source_refs_for_node_ref_occurrences(&branches);
        let uses = branches
            .into_iter()
            .zip(source_refs)
            .map(|(node_ref, source_ref)| MastNodeUse::new(node_ref, source_ref))
            .collect::<Vec<_>>()
            .try_into()
            .expect("split must have exactly two branches");
        Ok(self.ensure_split_node_use(uses, asm_op, inline_calls)?.node_ref())
    }

    pub(crate) fn ensure_split_node_use(
        &mut self,
        branches: [MastNodeUse; 2],
        asm_op: AssemblyOp,
        inline_calls: Vec<DebugSourceInlineCall>,
    ) -> Result<MastNodeUse, Report> {
        let source_child_refs = branches.map(MastNodeUse::source_ref).into();
        let branches = branches.map(MastNodeUse::node_ref);
        let branch_digests = branches.map(|node_ref| self.pending_node_mast_root(node_ref));
        let split_digest = hasher::merge_in_domain(&branch_digests, SplitNode::DOMAIN);
        let child_refs = Vec::from(branches);
        let mut draft =
            PendingMastNodeDraft::new(PendingMastNodeKind::Split, split_digest, child_refs);
        draft.inline_calls = inline_calls;

        self.intern_pending_node_with_asm_op_use(draft, asm_op, source_child_refs)
    }

    #[cfg(test)]
    pub(crate) fn ensure_loop_node_ref(
        &mut self,
        body: MastNodeRef,
        asm_op: AssemblyOp,
        inline_calls: Vec<DebugSourceInlineCall>,
    ) -> Result<MastNodeRef, Report> {
        let body = MastNodeUse::new(
            body,
            self.latest_source_ref_for_node_ref(body)
                .expect("execution ref must have a source occurrence"),
        );
        Ok(self.ensure_loop_node_use(body, asm_op, inline_calls)?.node_ref())
    }

    pub(crate) fn ensure_loop_node_use(
        &mut self,
        body: MastNodeUse,
        asm_op: AssemblyOp,
        inline_calls: Vec<DebugSourceInlineCall>,
    ) -> Result<MastNodeUse, Report> {
        let source_child_refs = vec![body.source_ref()];
        let body = body.node_ref();
        let body_digest = self.pending_node_mast_root(body);
        let loop_digest =
            hasher::merge_in_domain(&[body_digest, Word::default()], LoopNode::DOMAIN);
        let child_refs = vec![body];
        let mut draft =
            PendingMastNodeDraft::new(PendingMastNodeKind::Loop, loop_digest, child_refs);
        draft.inline_calls = inline_calls;

        self.intern_pending_node_with_asm_op_use(draft, asm_op, source_child_refs)
    }

    #[cfg(test)]
    pub(crate) fn ensure_call_node_ref(
        &mut self,
        callee: MastNodeRef,
        is_syscall: bool,
        asm_op: AssemblyOp,
        inline_calls: Vec<DebugSourceInlineCall>,
    ) -> Result<MastNodeRef, Report> {
        let callee = MastNodeUse::new(
            callee,
            self.latest_source_ref_for_node_ref(callee)
                .expect("execution ref must have a source occurrence"),
        );
        Ok(self.ensure_call_node_use(callee, is_syscall, asm_op, inline_calls)?.node_ref())
    }

    pub(crate) fn ensure_call_node_use(
        &mut self,
        callee: MastNodeUse,
        is_syscall: bool,
        asm_op: AssemblyOp,
        inline_calls: Vec<DebugSourceInlineCall>,
    ) -> Result<MastNodeUse, Report> {
        let source_child_refs = vec![callee.source_ref()];
        let callee = callee.node_ref();
        let callee_digest = self.pending_node_mast_root(callee);
        let call_domain = if is_syscall {
            CallNode::SYSCALL_DOMAIN
        } else {
            CallNode::CALL_DOMAIN
        };
        let call_digest = hasher::merge_in_domain(&[callee_digest, Word::default()], call_domain);
        let child_refs = vec![callee];
        let mut draft = PendingMastNodeDraft::new(
            PendingMastNodeKind::Call { is_syscall },
            call_digest,
            child_refs,
        );
        draft.inline_calls = inline_calls;
        self.intern_pending_node_with_asm_op_use(draft, asm_op, source_child_refs)
    }

    pub(crate) fn ensure_dyn_node_use(
        &mut self,
        is_dyncall: bool,
        asm_op: AssemblyOp,
        inline_calls: Vec<DebugSourceInlineCall>,
    ) -> Result<MastNodeUse, Report> {
        let dyn_digest = if is_dyncall {
            DynNode::DYNCALL_DEFAULT_DIGEST
        } else {
            DynNode::DYN_DEFAULT_DIGEST
        };
        let child_refs = Vec::new();
        let mut draft = PendingMastNodeDraft::new(
            PendingMastNodeKind::Dyn { is_dyncall },
            dyn_digest,
            child_refs,
        );
        draft.inline_calls = inline_calls;
        self.intern_pending_node_with_asm_op_use(draft, asm_op, Vec::new())
    }

    fn merge_contiguous_basic_block_uses(
        &mut self,
        node_uses: Vec<MastNodeUse>,
    ) -> Result<Vec<MastNodeUse>, Report> {
        let mut merged_node_uses = Vec::with_capacity(node_uses.len());
        let mut contiguous_basic_block_uses = Vec::new();

        for node_use in node_uses {
            if self.pending_node_is_basic_block(node_use.node_ref()) {
                contiguous_basic_block_uses.push(node_use);
            } else {
                merged_node_uses.extend(self.merge_basic_block_uses(&contiguous_basic_block_uses)?);
                contiguous_basic_block_uses.clear();
                merged_node_uses.push(node_use);
            }
        }

        merged_node_uses.extend(self.merge_basic_block_uses(&contiguous_basic_block_uses)?);
        Ok(merged_node_uses)
    }

    fn record_merged_source_occurrences(
        &mut self,
        merged_ref: MastNodeRef,
        merged_source_occurrences: &[(SourceNodeRef, usize)],
    ) -> Result<(), Report> {
        for &(source_ref, new_start) in merged_source_occurrences {
            let new_start = u32::try_from(new_start).expect("operation start index too large");
            let source_node = self.debug_info[source_ref].clone();
            let old_start = source_node.op_start;
            let op_len = source_node.op_end.saturating_sub(old_start);
            let remap_op_idx = |op_idx: u32| {
                debug_assert!(op_idx >= old_start);
                op_idx - old_start + new_start
            };

            self.push_source_occurrence(
                merged_ref,
                source_node.children,
                new_start as usize,
                (new_start + op_len) as usize,
                source_node
                    .asm_ops
                    .into_iter()
                    .map(|mut asm_op| {
                        asm_op.op_idx = remap_op_idx(asm_op.op_idx);
                        asm_op
                    })
                    .collect(),
                source_node
                    .debug_vars
                    .into_iter()
                    .map(|mut debug_var| {
                        debug_var.op_idx = remap_op_idx(debug_var.op_idx);
                        debug_var
                    })
                    .collect(),
                source_node
                    .inline_calls
                    .into_iter()
                    .map(|mut inline_call| {
                        inline_call.op_idx = remap_op_idx(inline_call.op_idx);
                        inline_call
                    })
                    .collect(),
                // The functions now belong to the aggregate merged occurrence created above.
                &[],
                false,
                false,
            )?;
        }

        Ok(())
    }

    #[cfg(test)]
    fn merge_basic_block_refs(
        &mut self,
        contiguous_basic_block_refs: &[MastNodeRef],
    ) -> Result<Vec<MastNodeRef>, Report> {
        let source_refs = self.source_refs_for_node_ref_occurrences(contiguous_basic_block_refs);
        let node_uses = contiguous_basic_block_refs
            .iter()
            .copied()
            .zip(source_refs)
            .map(|(node_ref, source_ref)| MastNodeUse::new(node_ref, source_ref))
            .collect::<Vec<_>>();
        Ok(self
            .merge_basic_block_uses(&node_uses)?
            .into_iter()
            .map(MastNodeUse::node_ref)
            .collect())
    }

    fn merge_basic_block_uses(
        &mut self,
        contiguous_basic_block_uses: &[MastNodeUse],
    ) -> Result<Vec<MastNodeUse>, Report> {
        if contiguous_basic_block_uses.len() <= 1 {
            return Ok(contiguous_basic_block_uses.to_vec());
        }

        let mut operations: Vec<Operation> = Vec::new();
        // Track asm_ops and debug_vars being accumulated for merged blocks, with adjusted indices
        let mut merged_asm_ops: Vec<DebugSourceAsmOp> = Vec::new();
        let mut merged_debug_vars: Vec<DebugSourceVar> = Vec::new();
        let mut merged_inline_calls: Vec<DebugSourceInlineCall> = Vec::new();
        let mut merged_functions: Vec<DebugFunctionIdx> = Vec::new();
        let mut merged_source_occurrences: Vec<(SourceNodeRef, usize)> = Vec::new();

        let mut merged_basic_block_uses = Vec::new();

        for &basic_block_use in contiguous_basic_block_uses {
            let basic_block_ref = basic_block_use.node_ref();
            let source_ref = basic_block_use.source_ref();
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

                merged_source_occurrences.push((source_ref, ops_offset));

                let source_node = &self.debug_info[source_ref];
                merged_asm_ops.extend(source_node.asm_ops.iter().map(|asm_op| {
                    let mut asm_op = *asm_op;
                    asm_op.op_idx += u32::try_from(ops_offset).unwrap();
                    asm_op
                }));
                merged_debug_vars.extend(source_node.debug_vars.iter().map(|debug_var| {
                    let mut debug_var = debug_var.clone();
                    debug_var.op_idx += u32::try_from(ops_offset).unwrap();
                    debug_var
                }));
                merged_inline_calls.extend(source_node.inline_calls.iter().map(|inline_call| {
                    let mut inline_call = *inline_call;
                    inline_call.op_idx += u32::try_from(ops_offset).unwrap();
                    inline_call
                }));
                merged_functions.extend(self.function_indices_for_source_ref(source_ref));

                operations.extend(block_ops);
            } else {
                // If we don't want to merge this block, flush the buffer of operations into a
                // new block, and add the un-merged block after it.
                if !operations.is_empty() {
                    let block_ops = core::mem::take(&mut operations);
                    let block_asm_ops = core::mem::take(&mut merged_asm_ops);
                    let block_debug_vars = core::mem::take(&mut merged_debug_vars);
                    let block_inline_calls = core::mem::take(&mut merged_inline_calls);
                    let block_functions = core::mem::take(&mut merged_functions);
                    let block_source_occurrences = core::mem::take(&mut merged_source_occurrences);
                    let merged_basic_block_use = self.ensure_block_use(
                        block_ops,
                        block_asm_ops,
                        block_debug_vars,
                        block_inline_calls,
                        block_functions,
                    )?;
                    self.record_merged_source_occurrences(
                        merged_basic_block_use.node_ref(),
                        &block_source_occurrences,
                    )?;

                    merged_basic_block_uses.push(merged_basic_block_use);
                }
                merged_basic_block_uses.push(basic_block_use);
            }
        }

        if !operations.is_empty() {
            let merged_basic_block = self.ensure_block_use(
                operations,
                merged_asm_ops,
                merged_debug_vars,
                merged_inline_calls,
                merged_functions,
            )?;
            self.record_merged_source_occurrences(
                merged_basic_block.node_ref(),
                &merged_source_occurrences,
            )?;
            merged_basic_block_uses.push(merged_basic_block);
        }

        Ok(merged_basic_block_uses)
    }

    /// Adds a basic block node to the forest, and returns its builder-local [`MastNodeRef`].
    #[cfg(test)]
    pub(crate) fn ensure_block_ref(
        &mut self,
        operations: Vec<Operation>,
        asm_ops: Vec<DebugSourceAsmOp>,
        debug_vars: Vec<DebugSourceVar>,
        inline_calls: Vec<DebugSourceInlineCall>,
        functions: Vec<DebugFunctionIdx>,
    ) -> Result<MastNodeRef, Report> {
        Ok(self
            .ensure_block_use(operations, asm_ops, debug_vars, inline_calls, functions)?
            .node_ref())
    }

    pub(crate) fn ensure_block_use(
        &mut self,
        operations: Vec<Operation>,
        asm_ops: Vec<DebugSourceAsmOp>,
        debug_vars: Vec<DebugSourceVar>,
        inline_calls: Vec<DebugSourceInlineCall>,
        functions: Vec<DebugFunctionIdx>,
    ) -> Result<MastNodeUse, Report> {
        let (op_batches, digest) = batch_basic_block_operations(operations)?;
        let kind = PendingMastNodeKind::BasicBlock { op_batches };
        self.intern_pending_node_use(
            PendingMastNodeDraft {
                kind,
                digest,
                child_refs: Vec::new(),
                asm_ops,
                debug_vars,
                inline_calls,
                functions,
            },
            Vec::new(),
        )
    }
}

// ------------------------------------------------------------------------------------------------

impl MastForestBuilder {
    /// Registers an error message in the MAST Forest and returns the
    /// corresponding error code as a Felt.
    pub fn register_error(&mut self, msg: Arc<str>) -> Felt {
        let err_code = error_code_from_msg(&msg);
        self.debug_info.add_error_message(err_code.as_canonical_u64(), msg);
        err_code
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
        sync::Arc,
    };

    use miden_assembly_syntax::{
        ast::{DebugVarInfo, DebugVarLocation},
        debuginfo::{ByteIndex, ColumnNumber, LineNumber, Location, Uri},
    };
    use miden_core::{
        mast::{MastNodeBuilder, MastNodeId},
        operations::Operation,
        serde::Serializable,
        utils::Idx,
    };
    use miden_mast_package::{
        Package, PackageExport, PackageId, PathBuf, ProcedureExport, Section, SectionId,
        TargetType, Version,
        debug_info::{
            DebugFieldInfo, DebugPrimitiveType, DebugSourceAsmOp, DebugSourceInlineCall,
            DebugSourceNode, DebugSourceVar, DebugTypeIdx, DebugTypeInfo, FunctionInfo,
            PackageDebugInfo, PackageDebugInfoBuilder,
        },
    };
    use proptest::prelude::*;

    use super::*;

    fn record_test_root(builder: &mut MastForestBuilder, node_ref: MastNodeRef) -> MastNodeRef {
        builder.record_procedure_root_ref(node_ref);
        node_ref
    }

    fn add_test_asm_op(builder: &mut MastForestBuilder, asm_op: AssemblyOp) -> DebugSourceAsmOp {
        let location_idx = asm_op
            .location()
            .map(|location| builder.debug_info_mut().add_location(location.clone()));
        let context_name_idx = builder.debug_info_mut().add_string(asm_op.context_name().clone());
        let op_name_idx = builder.debug_info_mut().add_string(asm_op.op().clone());
        DebugSourceAsmOp::new(0, location_idx, context_name_idx, op_name_idx, asm_op.num_cycles())
    }

    fn add_test_debug_var(
        builder: &mut MastForestBuilder,
        debug_var: DebugVarInfo,
    ) -> DebugSourceVar {
        let name_idx = builder.debug_info_mut().add_string(debug_var.name().clone());
        let location_idx = debug_var
            .location()
            .map(|location| builder.debug_info_mut().add_location(location.clone()));
        DebugSourceVar {
            op_idx: 0,
            name_idx,
            type_id: None,
            arg_idx: debug_var.arg_index(),
            location_idx,
            value_location: debug_var.value_location().clone(),
        }
    }

    fn with_asm_op_idx(mut asm_op: DebugSourceAsmOp, op_idx: u32) -> DebugSourceAsmOp {
        asm_op.op_idx = op_idx;
        asm_op
    }

    fn with_debug_var_idx(mut debug_var: DebugSourceVar, op_idx: u32) -> DebugSourceVar {
        debug_var.op_idx = op_idx;
        debug_var
    }

    fn test_asm_op(context: impl Into<String>, op: impl Into<String>) -> AssemblyOp {
        let context = context.into();
        let op = op.into();
        AssemblyOp::new(None, context, 1, op)
    }

    fn test_word(value: u64) -> Word {
        Word::from([Felt::new_unchecked(value), Felt::ZERO, Felt::ZERO, Felt::ZERO])
    }

    fn source_nodes_for_exec(
        debug_info: &PackageDebugInfo,
        exec_node: MastNodeId,
    ) -> Vec<&DebugSourceNode> {
        debug_info
            .nodes()
            .iter()
            .filter(|source_node| source_node.exec_node == exec_node)
            .collect()
    }

    fn source_debug_var_names(debug_info: &PackageDebugInfo, exec_node: MastNodeId) -> Vec<String> {
        source_nodes_for_exec(debug_info, exec_node)
            .into_iter()
            .flat_map(|source_node| {
                source_node
                    .debug_vars
                    .iter()
                    .map(|debug_var| debug_info[debug_var.name_idx].to_string())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    fn source_asm_contexts(debug_info: &PackageDebugInfo, exec_node: MastNodeId) -> Vec<String> {
        source_nodes_for_exec(debug_info, exec_node)
            .into_iter()
            .flat_map(|source_node| {
                source_node
                    .asm_ops
                    .iter()
                    .map(|asm_op| debug_info[asm_op.context_name_idx].to_string())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    #[test]
    fn plain_exec_reuses_the_exact_source_occurrence() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();
        let target = builder
            .ensure_block_use(vec![Operation::Add], vec![], vec![], vec![], vec![])
            .unwrap();
        let source_node_count = builder.debug_info.debug_info().nodes().len();

        for _ in 0..1_024 {
            assert_eq!(builder.record_exec_inline_calls(target, &[]).unwrap(), target);
        }

        assert_eq!(builder.debug_info.debug_info().nodes().len(), source_node_count);
    }

    #[test]
    fn repeated_decorated_exec_reuses_the_same_source_tree() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();
        let target = builder
            .ensure_block_use(vec![Operation::Add], vec![], vec![], vec![], vec![])
            .unwrap();
        let (callee_idx, loc_idx) = {
            let inline_call = DebugInlineCallInfo::new(
                "source::callee",
                FileLineCol::new(
                    "file:///decorated-exec.masm",
                    LineNumber::new(1).unwrap(),
                    ColumnNumber::new(1).unwrap(),
                ),
                FileLineCol::new(
                    "file:///decorated-exec.masm",
                    LineNumber::new(2).unwrap(),
                    ColumnNumber::new(1).unwrap(),
                ),
            );
            let callee_idx = builder.register_inline_function(&inline_call);
            let duplicate_idx = builder.register_inline_function(&inline_call);
            assert_eq!(callee_idx, duplicate_idx);
            let call_site_span = builder.debug_info_mut().add_location(Location::new(
                Uri::from("file:///decorated-exec.masm"),
                ByteIndex::from(1u32),
                ByteIndex::from(2u32),
            ));
            (callee_idx, call_site_span)
        };
        let inline_call = DebugSourceInlineCall { op_idx: 0, callee_idx, loc_idx };
        let decorated = builder.record_exec_inline_calls(target, &[inline_call]).unwrap();
        let source_node_count = builder.debug_info.debug_info().nodes().len();

        for _ in 0..1_024 {
            assert_eq!(
                builder.record_exec_inline_calls(target, &[inline_call]).unwrap(),
                decorated
            );
        }

        assert_eq!(builder.debug_info.debug_info().nodes().len(), source_node_count);
        assert_eq!(builder.debug_info.debug_info().functions().len(), 1);
        assert_eq!(builder.latest_node_use(target.node_ref()), Some(target));
    }

    #[test]
    fn external_exec_preserves_the_source_boundary_index() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();
        let mast_root = test_word(7);
        let (callee_idx, loc_idx) = {
            let debug_info = builder.debug_info_mut();
            let uri = Uri::from("file:///external-boundary.masm");
            let loc_idx = debug_info.add_location(Location::new(
                uri,
                ByteIndex::from(0u32),
                ByteIndex::from(1u32),
            ));
            let file_idx = debug_info.debug_info().locations()[loc_idx].file_idx;
            let name_idx = debug_info.add_string("external::callee");
            let callee_idx = debug_info.add_function(FunctionInfo::new(
                None,
                name_idx,
                file_idx,
                LineNumber::new(1).unwrap(),
                ColumnNumber::new(1).unwrap(),
                mast_root,
            ));
            (callee_idx, loc_idx)
        };
        let inline_call = DebugSourceInlineCall { op_idx: 0, callee_idx, loc_idx };
        let external_ref = builder
            .ensure_external_link_with_source_ref(mast_root, None, None, None)
            .unwrap();
        let boundary_source_ref = builder
            .push_source_occurrence(
                external_ref,
                vec![],
                7,
                7,
                vec![],
                vec![],
                vec![DebugSourceInlineCall { op_idx: 7, ..inline_call }],
                &[],
                true,
                false,
            )
            .unwrap();
        let target = MastNodeUse::new(external_ref, boundary_source_ref);

        let decorated = builder.record_exec_inline_calls(target, &[inline_call]).unwrap();
        let source_node = &builder.debug_info[decorated.source_ref()];

        assert_eq!((source_node.op_start, source_node.op_end), (7, 7));
        assert_eq!(source_node.inline_calls.len(), 2);
        assert!(source_node.inline_calls.iter().all(|row| row.op_idx == 7));
    }

    #[test]
    fn external_source_reuses_an_existing_concrete_occurrence() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();
        let target = builder
            .ensure_block_use(vec![Operation::Add], vec![], vec![], vec![], vec![])
            .unwrap();
        let source_node_count = builder.debug_info.debug_info().nodes().len();
        let mast_root = builder.nodes[target.node_ref()].digest;

        let external_ref = builder
            .ensure_external_link_with_source_ref(mast_root, None, None, None)
            .unwrap();

        assert_eq!(external_ref, target.node_ref());
        assert_eq!(builder.latest_source_ref_for_node_ref(external_ref), Some(target.source_ref()));
        assert_eq!(builder.debug_info.debug_info().nodes().len(), source_node_count);
        assert!(builder.external_boundary_source_refs.is_empty());
    }

    #[test]
    fn decorated_external_source_is_remapped_when_the_concrete_node_arrives() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();
        let block_digest =
            BasicBlockNodeBuilder::new(vec![Operation::Add]).build().unwrap().digest();
        let (callee_idx, loc_idx) = {
            let debug_info = builder.debug_info_mut();
            let uri = Uri::from("file:///external-replacement.masm");
            let loc_idx = debug_info.add_location(Location::new(
                uri,
                ByteIndex::from(0u32),
                ByteIndex::from(1u32),
            ));
            let file_idx = debug_info.debug_info().locations()[loc_idx].file_idx;
            let name_idx = debug_info.add_string("external::callee");
            let callee_idx = debug_info.add_function(FunctionInfo::new(
                None,
                name_idx,
                file_idx,
                LineNumber::new(1).unwrap(),
                ColumnNumber::new(1).unwrap(),
                block_digest,
            ));
            (callee_idx, loc_idx)
        };
        let inline_call = DebugSourceInlineCall { op_idx: 0, callee_idx, loc_idx };
        let external_ref = builder
            .ensure_external_link_with_source_ref(block_digest, None, None, None)
            .unwrap();
        let external_use = builder.latest_node_use(external_ref).unwrap();
        let decorated = builder.record_exec_inline_calls(external_use, &[inline_call]).unwrap();
        builder.record_procedure_root_use(decorated);

        let concrete = builder
            .ensure_block_use(vec![Operation::Add], vec![], vec![], vec![], vec![])
            .unwrap();

        assert_eq!(concrete.node_ref(), external_ref);
        assert!(!builder.external_boundary_source_refs.contains(&decorated.source_ref()));
        let remapped_source = &builder.debug_info[decorated.source_ref()];
        assert_eq!((remapped_source.op_start, remapped_source.op_end), (0, 1));
        assert_eq!(remapped_source.inline_calls, vec![inline_call]);

        let (_, _, debug_info, source_remapping) =
            builder.build().unwrap().into_parts_with_debug_info();
        let remapped_source = &debug_info[source_remapping[&decorated.source_ref()]];
        assert_eq!((remapped_source.op_start, remapped_source.op_end), (0, 1));
        assert_eq!(remapped_source.inline_calls.len(), 1);
        assert_eq!(remapped_source.inline_calls[0].op_idx, 0);
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
            let shared_debug_var = add_test_debug_var(
                &mut builder,
                DebugVarInfo::new("shared", DebugVarLocation::Stack(0)),
            );

            let seed_ref = builder
                .ensure_block_ref(
                    vec![Operation::Add, Operation::Mul],
                    vec![shared_asm_op, with_asm_op_idx(shared_asm_op, 1)],
                    vec![shared_debug_var],
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
                                vec![asm_op],
                                vec![],
                                vec![],
                                vec![],
                            )
                            .unwrap()
                    },
                    1 => builder
                        .ensure_split_node_ref(
                            [first_ref, second_ref],
                            test_asm_op(context.clone(), "if.true"),
                            vec![],
                        )
                        .unwrap(),
                    2 => builder
                        .ensure_loop_node_ref(
                            first_ref,
                            test_asm_op(context.clone(), "begin"),
                            vec![],
                        )
                        .unwrap(),
                    3 => builder
                        .ensure_call_node_ref(
                            first_ref,
                            step.flags & 1 == 1,
                            test_asm_op(context.clone(), "call"),
                            vec![],
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

        let dead_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![], vec![], vec![], vec![])
            .unwrap();

        let (forest, remapping) = builder.build().unwrap().into_parts();

        assert!(!remapping.contains_key(&dead_ref));
        assert_eq!(forest.num_nodes(), 0);
        assert_eq!(forest.procedure_roots().len(), 0);
    }

    #[test]
    fn test_build_prunes_unreachable_nodes() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let root_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![], vec![], vec![], vec![])
            .unwrap();
        let dead_ref = builder
            .ensure_block_ref(vec![Operation::Mul], vec![], vec![], vec![], vec![])
            .unwrap();
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
        let large_block_ref =
            builder.ensure_block_ref(large_ops, vec![], vec![], vec![], vec![]).unwrap();
        builder.record_procedure_root_ref(large_block_ref);

        let small_block_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![], vec![], vec![], vec![])
            .unwrap();

        let merged_blocks =
            builder.merge_basic_block_refs(&[large_block_ref, small_block_ref]).unwrap();

        assert_eq!(merged_blocks.len(), 2);
        assert_eq!(merged_blocks[0], large_block_ref);
        assert_eq!(merged_blocks[1], small_block_ref);
    }

    #[test]
    fn test_build_keeps_existing_forest_root_after_merge() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let root_block_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![], vec![], vec![], vec![])
            .unwrap();
        builder.record_procedure_root_ref(root_block_ref);
        let root_digest = builder.nodes[root_block_ref].digest;

        let tail_block_ref = builder
            .ensure_block_ref(vec![Operation::Mul], vec![], vec![], vec![], vec![])
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
    fn test_source_graph_preserves_pre_merge_block_ranges() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let first_asm_op = add_test_asm_op(&mut builder, test_asm_op("merge::first", "add"));
        let second_asm_op = add_test_asm_op(&mut builder, test_asm_op("merge::second", "mul"));
        let first_block_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![first_asm_op], vec![], vec![], vec![])
            .unwrap();
        let second_block_ref = builder
            .ensure_block_ref(vec![Operation::Mul], vec![second_asm_op], vec![], vec![], vec![])
            .unwrap();

        let merged_blocks =
            builder.merge_basic_block_refs(&[first_block_ref, second_block_ref]).unwrap();
        assert_eq!(merged_blocks.len(), 1);
        let merged_ref = record_test_root(&mut builder, merged_blocks[0]);

        let (_, remapping, source_graph, _) = builder.build().unwrap().into_parts_with_debug_info();
        let final_merged_id = remapping[&merged_ref];
        let source_nodes = source_nodes_for_exec(&source_graph, final_merged_id);

        assert_eq!(
            source_graph.roots().len(),
            1,
            "pre-merge source blocks should not become procedure roots",
        );
        assert!(
            source_nodes.iter().any(|source_node| {
                source_node.op_start == 0
                    && source_node.op_end == 1
                    && source_node.asm_ops.iter().any(|asm_op| {
                        source_graph[asm_op.context_name_idx].as_ref() == "merge::first"
                    })
            }),
            "first pre-merge source block should survive as range 0..1",
        );
        assert!(
            source_nodes.iter().any(|source_node| {
                source_node.op_start == 1
                    && source_node.op_end == 2
                    && source_node.asm_ops.iter().any(|asm_op| {
                        source_graph[asm_op.context_name_idx].as_ref() == "merge::second"
                    })
            }),
            "second pre-merge source block should survive as range 1..2",
        );
    }

    #[test]
    fn test_source_graph_uses_full_merged_occurrence_as_control_flow_child() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let first_asm_op = add_test_asm_op(&mut builder, test_asm_op("merge::first", "add"));
        let second_asm_op = add_test_asm_op(&mut builder, test_asm_op("merge::second", "mul"));
        let first_block_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![first_asm_op], vec![], vec![], vec![])
            .unwrap();
        let second_block_ref = builder
            .ensure_block_ref(vec![Operation::Mul], vec![second_asm_op], vec![], vec![], vec![])
            .unwrap();
        let merged_ref =
            builder.merge_basic_block_refs(&[first_block_ref, second_block_ref]).unwrap()[0];
        let external_ref = builder
            .ensure_external_link_with_source_ref(test_word(1), None, None, None)
            .unwrap();
        let root_ref = builder.join_node_refs(vec![merged_ref, external_ref], None).unwrap();
        record_test_root(&mut builder, root_ref);

        let (_, _, source_graph, _) = builder.build().unwrap().into_parts_with_debug_info();
        let root = source_graph.roots()[0];
        let merged_child = &source_graph[source_graph[root].children[0]];

        assert_eq!((merged_child.op_start, merged_child.op_end), (0, 2));
        assert_eq!(
            merged_child
                .asm_ops
                .iter()
                .map(|asm_op| source_graph[asm_op.context_name_idx].as_ref())
                .collect::<Vec<_>>(),
            vec!["merge::first", "merge::second"],
        );
    }

    #[test]
    fn test_source_graph_preserves_repeated_deduped_block_ranges_in_merge_window() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let first_asm_op = add_test_asm_op(&mut builder, test_asm_op("merge::first", "add"));
        let second_asm_op = add_test_asm_op(&mut builder, test_asm_op("merge::second", "add"));
        let first_block_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![first_asm_op], vec![], vec![], vec![])
            .unwrap();
        let second_block_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![second_asm_op], vec![], vec![], vec![])
            .unwrap();

        assert_eq!(
            first_block_ref, second_block_ref,
            "identical execution blocks should dedup to one execution ref",
        );

        let merged_blocks =
            builder.merge_basic_block_refs(&[first_block_ref, second_block_ref]).unwrap();
        assert_eq!(merged_blocks.len(), 1);
        let merged_ref = record_test_root(&mut builder, merged_blocks[0]);

        let (_, remapping, source_graph, _) = builder.build().unwrap().into_parts_with_debug_info();
        let final_merged_id = remapping[&merged_ref];
        let source_nodes = source_nodes_for_exec(&source_graph, final_merged_id);

        assert!(
            source_nodes.iter().any(|source_node| {
                source_node.op_start == 0
                    && source_node.op_end == 1
                    && source_node.asm_ops.iter().any(|asm_op| {
                        source_graph[asm_op.context_name_idx].as_ref() == "merge::first"
                    })
            }),
            "first deduped source block should survive as range 0..1",
        );
        assert!(
            source_nodes.iter().any(|source_node| {
                source_node.op_start == 1
                    && source_node.op_end == 2
                    && source_node.asm_ops.iter().any(|asm_op| {
                        source_graph[asm_op.context_name_idx].as_ref() == "merge::second"
                    })
            }),
            "second deduped source block should survive as range 1..2",
        );
    }

    #[test]
    fn test_block_merge_uses_selected_occurrence_inline_calls_and_functions() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();
        let mast_root = BasicBlockNodeBuilder::new(vec![Operation::Add]).build().unwrap().digest();

        let (function_a, function_b, location_a, location_b) = {
            let debug_info = builder.debug_info_mut();
            let uri = Uri::from("file:///same-digest-aliases.masm");
            let location_a = debug_info.add_location(Location::new(
                uri.clone(),
                ByteIndex::from(0u32),
                ByteIndex::from(1u32),
            ));
            let location_b = debug_info.add_location(Location::new(
                uri,
                ByteIndex::from(2u32),
                ByteIndex::from(3u32),
            ));
            let file_idx = debug_info.debug_info().locations()[location_a].file_idx;
            let function_a_name = debug_info.add_string("alias_a");
            let function_b_name = debug_info.add_string("alias_b");
            let function_a = debug_info.add_function(FunctionInfo::new(
                None,
                function_a_name,
                file_idx,
                LineNumber::new(1).unwrap(),
                ColumnNumber::new(1).unwrap(),
                mast_root,
            ));
            let function_b = debug_info.add_function(FunctionInfo::new(
                None,
                function_b_name,
                file_idx,
                LineNumber::new(2).unwrap(),
                ColumnNumber::new(1).unwrap(),
                mast_root,
            ));
            (function_a, function_b, location_a, location_b)
        };
        let asm_op_a = add_test_asm_op(&mut builder, test_asm_op("alias_a", "add"));
        let asm_op_b = add_test_asm_op(&mut builder, test_asm_op("alias_b", "add"));
        let debug_var_a =
            add_test_debug_var(&mut builder, DebugVarInfo::new("a", DebugVarLocation::Stack(0)));
        let debug_var_b =
            add_test_debug_var(&mut builder, DebugVarInfo::new("b", DebugVarLocation::Stack(0)));

        let alias_a_ref = builder
            .ensure_block_ref(
                vec![Operation::Add],
                vec![asm_op_a],
                vec![debug_var_a],
                vec![DebugSourceInlineCall {
                    op_idx: 0,
                    callee_idx: function_a,
                    loc_idx: location_a,
                }],
                vec![function_a],
            )
            .unwrap();
        let alias_a_source_ref = builder.latest_source_ref_for_node_ref(alias_a_ref).unwrap();
        let alias_b_ref = builder
            .ensure_block_ref(
                vec![Operation::Add],
                vec![asm_op_b],
                vec![debug_var_b],
                vec![DebugSourceInlineCall {
                    op_idx: 0,
                    callee_idx: function_b,
                    loc_idx: location_b,
                }],
                vec![function_b],
            )
            .unwrap();
        let alias_b_source_ref = builder.latest_source_ref_for_node_ref(alias_b_ref).unwrap();

        assert_eq!(alias_a_ref, alias_b_ref, "same-digest aliases must share execution identity");
        assert_ne!(alias_a_source_ref, alias_b_source_ref);

        let tail_ref = builder
            .ensure_block_ref(vec![Operation::Mul], vec![], vec![], vec![], vec![])
            .unwrap();
        let merged_refs = builder.merge_basic_block_refs(&[alias_b_ref, tail_ref]).unwrap();
        assert_eq!(merged_refs.len(), 1);
        let merged_source_ref = builder
            .latest_source_ref_for_node_ref(merged_refs[0])
            .expect("merged source occurrence");
        let merged_source = &builder.debug_info[merged_source_ref];

        assert_eq!(
            merged_source.inline_calls,
            vec![DebugSourceInlineCall {
                op_idx: 0,
                callee_idx: function_b,
                loc_idx: location_b,
            }],
            "the merged occurrence must use the selected alias's inline-call metadata",
        );
        assert_eq!(
            builder.debug_info[merged_source.asm_ops[0].context_name_idx].as_ref(),
            "alias_b",
            "the merged occurrence must use the selected alias's assembly metadata",
        );
        assert_eq!(
            builder.debug_info[merged_source.debug_vars[0].name_idx].as_ref(),
            "b",
            "the merged occurrence must use the selected alias's variable metadata",
        );
        assert_eq!(
            builder.debug_info[function_a].source_node.into_option(),
            Some(alias_a_source_ref),
            "merging alias B must not retarget alias A's function",
        );
        assert_eq!(
            builder.debug_info[function_b].source_node.into_option(),
            Some(merged_source_ref),
            "the selected alias's function must follow the merged occurrence",
        );

        let second_tail_ref = builder
            .ensure_block_ref(vec![Operation::Neg], vec![], vec![], vec![], vec![])
            .unwrap();
        let remerged_refs =
            builder.merge_basic_block_refs(&[merged_refs[0], second_tail_ref]).unwrap();
        assert_eq!(remerged_refs.len(), 1);
        let remerged_source_ref = builder
            .latest_source_ref_for_node_ref(remerged_refs[0])
            .expect("remerged source occurrence");
        let remerged_source = &builder.debug_info[remerged_source_ref];

        assert_eq!(
            remerged_source.inline_calls,
            vec![DebugSourceInlineCall {
                op_idx: 0,
                callee_idx: function_b,
                loc_idx: location_b,
            }],
            "re-merging must continue from the aggregate occurrence rather than a supplemental range",
        );
        assert_eq!(
            builder.debug_info[function_a].source_node.into_option(),
            Some(alias_a_source_ref),
            "re-merging alias B must not retarget alias A's function",
        );
        assert_eq!(
            builder.debug_info[function_b].source_node.into_option(),
            Some(remerged_source_ref),
            "the selected alias's function must follow repeated merges",
        );
    }

    #[test]
    fn test_build_orders_external_nodes_before_non_external_nodes() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let block_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![], vec![], vec![], vec![])
            .unwrap();
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

        let concrete_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![], vec![], vec![], vec![])
            .unwrap();
        assert_eq!(external_ref, concrete_ref);
        assert!(!builder.nodes[external_ref].kind.is_external());

        let (forest, remapping) = builder.build().unwrap().into_parts();
        let final_root = remapping[&external_ref];

        assert!(forest.is_procedure_root(final_root));
        assert!(matches!(forest[final_root], MastNode::Block(_)));
    }

    #[test]
    fn test_non_leaf_replacement_rebinds_external_source_occurrences() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();
        let left_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![], vec![], vec![], vec![])
            .unwrap();
        let right_ref = builder
            .ensure_block_ref(vec![Operation::Mul], vec![], vec![], vec![], vec![])
            .unwrap();
        let left_source_ref = builder.latest_source_ref_for_node_ref(left_ref).unwrap();
        let right_source_ref = builder.latest_source_ref_for_node_ref(right_ref).unwrap();
        let join_digest = hasher::merge_in_domain(
            &[builder.nodes[left_ref].digest, builder.nodes[right_ref].digest],
            JoinNode::DOMAIN,
        );

        let external_ref = builder
            .ensure_external_link_with_source_ref(join_digest, None, None, None)
            .unwrap();
        let external_source_ref = builder.latest_source_ref_for_node_ref(external_ref).unwrap();

        let parent_digest =
            hasher::merge_in_domain(&[join_digest, Word::default()], LoopNode::DOMAIN);
        let parent_ref = builder
            .intern_pending_node(PendingMastNodeDraft::new(
                PendingMastNodeKind::Loop,
                parent_digest,
                vec![external_ref],
            ))
            .unwrap();
        let parent_source_ref = builder.latest_source_ref_for_node_ref(parent_ref).unwrap();
        builder.record_procedure_root_ref(parent_ref);

        let concrete_ref = builder
            .intern_pending_node(PendingMastNodeDraft::new(
                PendingMastNodeKind::Join,
                join_digest,
                vec![left_ref, right_ref],
            ))
            .unwrap();
        assert_eq!(concrete_ref, external_ref);

        let (forest, remapping, debug_info, source_remapping) =
            builder.build().unwrap().into_parts_with_debug_info();
        let final_join = remapping[&concrete_ref];
        let final_parent = remapping[&parent_ref];
        let external_source = source_remapping[&external_source_ref];
        let parent_source = source_remapping[&parent_source_ref];
        let external_source = &debug_info[external_source];

        assert!(matches!(forest[final_join], MastNode::Join(_)));
        assert!(matches!(forest[final_parent], MastNode::Loop(_)));
        assert_eq!(
            debug_info[parent_source].children,
            vec![source_remapping[&external_source_ref]]
        );
        assert_eq!(
            external_source.children,
            vec![source_remapping[&left_source_ref], source_remapping[&right_source_ref]],
            "the source occurrence created for the external placeholder must match the concrete node",
        );
    }

    #[test]
    fn test_merge_basic_blocks_keeps_recorded_root_block_standalone() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let num_ops = PROCEDURE_INLINING_THRESHOLD * 1024;
        let large_ops = vec![Operation::Add; num_ops];
        let large_block_ref =
            builder.ensure_block_ref(large_ops, vec![], vec![], vec![], vec![]).unwrap();
        builder.record_procedure_root_ref(large_block_ref);

        let small_block_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![], vec![], vec![], vec![])
            .unwrap();

        let merged_blocks =
            builder.merge_basic_block_refs(&[large_block_ref, small_block_ref]).unwrap();

        assert_eq!(merged_blocks.len(), 2);
        assert_eq!(merged_blocks[0], large_block_ref);
        assert_eq!(merged_blocks[1], small_block_ref);
    }

    /// Same-ops blocks with different debug vars use the same execution node identity.
    #[test]
    fn test_ensure_node_preserving_debug_vars_prevents_aliasing() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let var_x_ref =
            add_test_debug_var(&mut builder, DebugVarInfo::new("x", DebugVarLocation::Stack(0)));
        let var_y_ref =
            add_test_debug_var(&mut builder, DebugVarInfo::new("y", DebugVarLocation::Stack(1)));

        // Same ops, different debug vars dedup to the same execution node.
        let block_a_ref = builder
            .ensure_block_ref(vec![Operation::Add], Vec::new(), vec![var_x_ref], vec![], vec![])
            .unwrap();
        let block_b_ref = builder
            .ensure_block_ref(vec![Operation::Add], Vec::new(), vec![var_y_ref], vec![], vec![])
            .unwrap();

        assert_eq!(block_a_ref, block_b_ref);

        record_test_root(&mut builder, block_a_ref);
        let (_forest, remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_debug_info();
        let final_block_a = remapping[&block_a_ref];
        let final_block_b = remapping[&block_b_ref];
        let var_names = source_debug_var_names(&source_graph, final_block_a);

        assert_eq!(var_names, vec!["x", "y"]);
        assert_eq!(final_block_a, final_block_b);
    }

    #[test]
    fn test_source_graph_distinguishes_same_exec_debug_var_occurrences() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let var_x_ref =
            add_test_debug_var(&mut builder, DebugVarInfo::new("x", DebugVarLocation::Stack(0)));
        let var_y_ref =
            add_test_debug_var(&mut builder, DebugVarInfo::new("y", DebugVarLocation::Stack(1)));

        let block_a_ref = builder
            .ensure_block_ref(vec![Operation::Add], Vec::new(), vec![var_x_ref], vec![], vec![])
            .unwrap();
        let block_b_ref = builder
            .ensure_block_ref(vec![Operation::Add], Vec::new(), vec![var_y_ref], vec![], vec![])
            .unwrap();

        assert_eq!(block_a_ref, block_b_ref);

        record_test_root(&mut builder, block_a_ref);
        let (forest, remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_debug_info();
        let final_block = remapping[&block_a_ref];
        let debug_var_names = source_nodes_for_exec(&source_graph, final_block)
            .into_iter()
            .flat_map(|source_node| {
                source_node
                    .debug_vars
                    .iter()
                    .map(|debug_var| source_graph[debug_var.name_idx].to_string())
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
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let var_a =
            add_test_debug_var(&mut builder, DebugVarInfo::new("x", DebugVarLocation::Stack(0)));
        let var_b =
            add_test_debug_var(&mut builder, DebugVarInfo::new("x", DebugVarLocation::Stack(0)));

        let block_a = builder
            .ensure_block_ref(vec![Operation::Add], Vec::new(), vec![var_a], vec![], vec![])
            .unwrap();
        let block_b = builder
            .ensure_block_ref(vec![Operation::Add], Vec::new(), vec![var_b], vec![], vec![])
            .unwrap();

        assert_eq!(
            block_a, block_b,
            "same op stream plus same DebugVarInfo payload should dedup to one node"
        );
    }

    #[test]
    fn test_trailing_noop_blocks_keep_compatible_source_occurrences() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();
        let event = Felt::from_u32(7);
        let emitted_event = vec![Operation::Push(event), Operation::Emit, Operation::Drop];

        let block_ref = builder
            .ensure_block_ref(emitted_event.clone(), Vec::new(), Vec::new(), vec![], vec![])
            .unwrap();
        let debug_var = add_test_debug_var(
            &mut builder,
            DebugVarInfo::new("result", DebugVarLocation::Stack(0)),
        );
        let trailing_noop_ops =
            emitted_event.into_iter().chain([Operation::Noop]).collect::<Vec<_>>();
        let trailing_noop_ref = builder
            .ensure_block_ref(
                trailing_noop_ops.clone(),
                Vec::new(),
                vec![with_debug_var_idx(debug_var, 3)],
                vec![],
                vec![],
            )
            .unwrap();

        assert_ne!(
            block_ref, trailing_noop_ref,
            "same-digest blocks with incompatible raw operation layouts must not deduplicate",
        );
        assert_eq!(
            builder.pending_node_mast_root(block_ref),
            builder.pending_node_mast_root(trailing_noop_ref),
            "an explicit trailing Noop must remain invisible to the MAST digest",
        );

        let call_ref = builder
            .ensure_call_node_ref(block_ref, false, test_asm_op("test", "call"), vec![])
            .unwrap();
        let trailing_noop_call_ref = builder
            .ensure_call_node_ref(trailing_noop_ref, false, test_asm_op("test", "call"), vec![])
            .unwrap();
        assert_ne!(
            call_ref, trailing_noop_call_ref,
            "incompatible child source layouts must propagate through control-node identity",
        );
        assert_eq!(
            builder.pending_node_mast_root(call_ref),
            builder.pending_node_mast_root(trailing_noop_call_ref),
        );

        let duplicate_trailing_noop_ref = builder
            .ensure_block_ref(trailing_noop_ops, Vec::new(), Vec::new(), vec![], vec![])
            .unwrap();
        assert_eq!(
            trailing_noop_ref, duplicate_trailing_noop_ref,
            "identical raw-to-padded layouts should still deduplicate",
        );

        record_test_root(&mut builder, call_ref);
        record_test_root(&mut builder, trailing_noop_call_ref);
        let (forest, remapping, debug_info, _) =
            builder.build().unwrap().into_parts_with_debug_info();
        let final_block = remapping[&block_ref];
        let final_trailing_noop = remapping[&trailing_noop_ref];

        let MastNode::Block(block) = &forest[final_block] else {
            panic!("expected a basic block")
        };
        let MastNode::Block(trailing_noop_block) = &forest[final_trailing_noop] else {
            panic!("expected a basic block")
        };
        assert_eq!(block.raw_operations().count(), 3);
        assert_eq!(trailing_noop_block.raw_operations().count(), 4);

        let source_node = source_nodes_for_exec(&debug_info, final_block)
            .into_iter()
            .next()
            .expect("base block source occurrence should survive finalization");
        assert_eq!(source_node.op_start..source_node.op_end, 0..3);

        let trailing_noop_source = source_nodes_for_exec(&debug_info, final_trailing_noop)
            .into_iter()
            .find(|source_node| !source_node.debug_vars.is_empty())
            .expect("trailing-Noop source occurrence should survive finalization");
        assert_eq!(trailing_noop_source.op_start..trailing_noop_source.op_end, 0..4);
        assert_eq!(trailing_noop_source.debug_vars.len(), 1);
        assert_eq!(trailing_noop_source.debug_vars[0].op_idx, 3);

        let export_path = PathBuf::new("source_layout_test::entry").unwrap();
        let export_path = export_path.as_path().to_absolute().unwrap().into_owned();
        let export_path = Arc::from(export_path.into_boxed_path());
        let final_call = remapping[&call_ref];
        let export = PackageExport::Procedure(ProcedureExport::new(
            export_path,
            Some(final_call),
            forest[final_call].digest(),
            None,
        ));
        let mut package = Package::create(
            PackageId::from("source-layout-test"),
            Version::new(0, 0, 0),
            TargetType::Library,
            Arc::new(forest),
            [export],
            [],
        )
        .unwrap();
        package
            .sections
            .push(Section::new(SectionId::DEBUG_INFO, debug_info.to_bytes()));
        assert!(
            package.debug_info().unwrap().is_some(),
            "final source ranges and rows must pass package validation",
        );
    }

    #[test]
    fn test_noop_layout_key_includes_padding_boundaries() {
        let event = Felt::from_u32(7);
        let mut first_ops = vec![Operation::Push(event); 8];
        first_ops.extend([Operation::Noop, Operation::Noop]);
        let mut second_ops = vec![Operation::Push(event); 7];
        second_ops.extend([Operation::Noop, Operation::Push(event), Operation::Noop]);

        let (first_batches, first_digest) =
            batch_basic_block_operations(first_ops.clone()).unwrap();
        let (second_batches, second_digest) =
            batch_basic_block_operations(second_ops.clone()).unwrap();
        assert_eq!(first_digest, second_digest);
        assert_eq!(
            first_batches.iter().flat_map(OpBatch::raw_ops).count(),
            second_batches.iter().flat_map(OpBatch::raw_ops).count(),
        );

        let raw_indices = (0..=first_ops.len()).collect::<Vec<_>>();
        let first_mapping =
            BasicBlockNode::adjust_asm_op_indices(raw_indices.clone(), &first_batches);
        let second_mapping = BasicBlockNode::adjust_asm_op_indices(raw_indices, &second_batches);
        assert_ne!(
            first_mapping, second_mapping,
            "the counterexample must have incompatible raw-to-padded source indices",
        );

        let mut builder = MastForestBuilder::new(&[]).unwrap();
        let first_var = add_test_debug_var(
            &mut builder,
            DebugVarInfo::new("first", DebugVarLocation::Stack(0)),
        );
        let second_var = add_test_debug_var(
            &mut builder,
            DebugVarInfo::new("second", DebugVarLocation::Stack(0)),
        );
        let first_ref = builder
            .ensure_block_ref(
                first_ops,
                Vec::new(),
                vec![with_debug_var_idx(first_var, 7)],
                vec![],
                vec![],
            )
            .unwrap();
        let second_ref = builder
            .ensure_block_ref(
                second_ops,
                Vec::new(),
                vec![with_debug_var_idx(second_var, 7)],
                vec![],
                vec![],
            )
            .unwrap();
        assert_ne!(
            first_ref, second_ref,
            "equal raw counts are insufficient when padding boundaries differ",
        );

        record_test_root(&mut builder, first_ref);
        record_test_root(&mut builder, second_ref);
        let (_forest, remapping, debug_info, _) =
            builder.build().unwrap().into_parts_with_debug_info();
        let first_source = source_nodes_for_exec(&debug_info, remapping[&first_ref])[0];
        let second_source = source_nodes_for_exec(&debug_info, remapping[&second_ref])[0];
        assert_eq!(first_source.op_start..first_source.op_end, 0..11);
        assert_eq!(second_source.op_start..second_source.op_end, 0..10);
        assert_eq!(first_source.debug_vars[0].op_idx, 8);
        assert_eq!(second_source.debug_vars[0].op_idx, 7);
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
                .ensure_block_ref(vec![make_op(first_code)], Vec::new(), Vec::new(), vec![], vec![])
                .unwrap();
            let duplicate_first_ref = builder
                .ensure_block_ref(vec![make_op(first_code)], Vec::new(), Vec::new(), vec![], vec![])
                .unwrap();
            let second_ref = builder
                .ensure_block_ref(
                    vec![make_op(second_code)],
                    Vec::new(),
                    Vec::new(),
                    vec![],
                    vec![],
                )
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
            .ensure_block_ref(
                vec![Operation::Assert(Felt::from_u32(1))],
                Vec::new(),
                Vec::new(),
                vec![],
                vec![],
            )
            .unwrap();
        let second_block = builder
            .ensure_block_ref(
                vec![Operation::Assert(Felt::from_u32(2))],
                Vec::new(),
                Vec::new(),
                vec![],
                vec![],
            )
            .unwrap();

        assert_eq!(
            builder.pending_node_mast_root(first_block),
            builder.pending_node_mast_root(second_block)
        );

        let first_call = builder
            .ensure_call_node_ref(first_block, false, test_asm_op("test", "call"), vec![])
            .unwrap();
        let second_call = builder
            .ensure_call_node_ref(second_block, false, test_asm_op("test", "call"), vec![])
            .unwrap();

        assert_ne!(
            first_call, second_call,
            "same-digest control nodes must not dedup when their children differ by runtime error code",
        );
    }

    #[test]
    fn test_build_assigns_final_debug_var_ids_to_used_refs() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let _unused_var = add_test_debug_var(
            &mut builder,
            DebugVarInfo::new("unused", DebugVarLocation::Stack(0)),
        );
        let used_var =
            add_test_debug_var(&mut builder, DebugVarInfo::new("used", DebugVarLocation::Stack(1)));
        let block_ref = builder
            .ensure_block_ref(vec![Operation::Add], Vec::new(), vec![used_var], vec![], vec![])
            .unwrap();

        record_test_root(&mut builder, block_ref);
        let (_forest, remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_debug_info();
        let final_block_id = remapping[&block_ref];
        let var_names = source_debug_var_names(&source_graph, final_block_id);

        assert_eq!(var_names, vec!["used"]);
    }

    #[test]
    fn test_build_preserves_function_debug_info_and_references() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();
        let block_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![], vec![], vec![], vec![])
            .unwrap();
        record_test_root(&mut builder, block_ref);
        let source_ref = builder.latest_source_ref_for_node_ref(block_ref).unwrap();
        let mast_root = builder.mast_root_for_ref(block_ref).unwrap();
        let dead_block_ref = builder
            .ensure_block_ref(vec![Operation::Mul], vec![], vec![], vec![], vec![])
            .unwrap();
        let dead_source_ref = builder.latest_source_ref_for_node_ref(dead_block_ref).unwrap();
        let dead_mast_root = builder.mast_root_for_ref(dead_block_ref).unwrap();

        let location = Location::new(
            Uri::from("file:///src/debug-test.masm"),
            ByteIndex::from(4u32),
            ByteIndex::from(9u32),
        );
        let debug_info = builder.debug_info_mut();
        let location_idx = debug_info.add_location(location.clone());
        let file_idx = debug_info.debug_info().locations()[location_idx].file_idx;
        let function_name_idx = debug_info.add_string("debug_test::entry");
        let linkage_name_idx = debug_info.add_string("entry");
        let dead_function_name_idx = debug_info.add_string("debug_test::dead");
        let struct_name_idx = debug_info.add_string("Wrapper");
        let field_name_idx = debug_info.add_string("inner");
        let expected_primitive_type_idx = DebugTypeIdx::from(1);
        let pointer_type_idx = debug_info.add_type(DebugTypeInfo::Pointer {
            pointee_type_idx: expected_primitive_type_idx,
        });
        let primitive_type_idx =
            debug_info.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U32));
        assert_eq!(primitive_type_idx, expected_primitive_type_idx);
        let struct_type_idx = debug_info.add_type(DebugTypeInfo::Struct {
            name_idx: struct_name_idx,
            size: 4,
            fields: vec![DebugFieldInfo {
                name_idx: field_name_idx,
                type_idx: pointer_type_idx,
                offset: 0,
            }],
        });
        let function_type_idx = debug_info.add_type(DebugTypeInfo::Function {
            return_type_idx: Some(struct_type_idx),
            param_type_indices: vec![struct_type_idx],
        });
        let function_idx = debug_info.add_function(
            FunctionInfo::new(
                Some(source_ref),
                function_name_idx,
                file_idx,
                LineNumber::new(1).unwrap(),
                ColumnNumber::new(1).unwrap(),
                mast_root,
            )
            .with_linkage_name(linkage_name_idx)
            .with_type(function_type_idx),
        );
        debug_info.add_function(
            FunctionInfo::new(
                Some(dead_source_ref),
                dead_function_name_idx,
                file_idx,
                LineNumber::new(2).unwrap(),
                ColumnNumber::new(1).unwrap(),
                dead_mast_root,
            )
            .with_type(function_type_idx),
        );
        debug_info[source_ref].inline_calls.push(DebugSourceInlineCall {
            op_idx: 0,
            callee_idx: function_idx,
            loc_idx: location_idx,
        });
        assert!(debug_info.add_error_message(7, "debug failure".into()));

        let (_forest, node_ids, debug_info, source_ids) =
            builder.build().unwrap().into_parts_with_debug_info();
        let source_id = source_ids[&source_ref];
        let function = debug_info.functions().iter().find(|f| f.mast_root == mast_root).unwrap();

        assert_eq!(debug_info.functions().len(), 2);
        assert_eq!(function.source_node.into_option(), Some(source_id));
        assert_eq!(function.mast_root, mast_root);
        assert_eq!(debug_info[source_id].exec_node, node_ids[&block_ref]);
        assert_eq!(debug_info[function.name_idx].as_ref(), "debug_test::entry");
        assert_eq!(debug_info[function.linkage_name_idx.into_option().unwrap()].as_ref(), "entry");
        let function_file = debug_info.get_file(function.file_idx).unwrap();
        assert_eq!(
            function.file_idx,
            debug_info.locations()[location_idx].file_idx,
            "function file reference should match its remapped source location",
        );
        assert!(!debug_info[function_file.path_idx].is_empty());
        assert_eq!(debug_info.get_location(location_idx), Some(location.clone()));
        assert_eq!(debug_info.error_message(7).as_deref(), Some("debug failure"));

        let dead_function =
            debug_info.functions().iter().find(|f| f.mast_root == dead_mast_root).unwrap();
        assert_eq!(dead_function.source_node.into_option(), None);
        assert_eq!(dead_function.mast_root, dead_mast_root);

        let DebugTypeInfo::Function {
            return_type_idx: Some(return_type_idx),
            param_type_indices,
        } = &debug_info[function.type_idx.into_option().unwrap()]
        else {
            panic!("expected remapped function type");
        };
        assert_eq!(param_type_indices, &[*return_type_idx]);
        let DebugTypeInfo::Struct { name_idx, fields, .. } = &debug_info[*return_type_idx] else {
            panic!("expected remapped struct type");
        };
        assert_eq!(debug_info[*name_idx].as_ref(), "Wrapper");
        assert_eq!(debug_info[fields[0].name_idx].as_ref(), "inner");
        let DebugTypeInfo::Pointer { pointee_type_idx } = debug_info[fields[0].type_idx] else {
            panic!("expected remapped pointer type");
        };
        assert_eq!(debug_info[pointee_type_idx], DebugTypeInfo::Primitive(DebugPrimitiveType::U32),);

        let inline_call = &debug_info[source_id].inline_calls[0];
        assert_eq!(inline_call.op_idx, 0);
        assert_eq!(debug_info.get_function(inline_call.callee_idx), Some(function));
        assert_eq!(debug_info.get_location(inline_call.loc_idx), Some(location));
    }

    /// Same-ops blocks with different AssemblyOps use the same execution node identity.
    #[test]
    fn test_ensure_block_keeps_different_asm_ops_distinct() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let asm_op_a = add_test_asm_op(&mut builder, AssemblyOp::new(None, "ctx_a", 1, "add"));
        let asm_op_b = add_test_asm_op(&mut builder, AssemblyOp::new(None, "ctx_b", 1, "add"));

        let block_a_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![asm_op_a], Vec::new(), vec![], vec![])
            .unwrap();
        let block_b_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![asm_op_b], Vec::new(), vec![], vec![])
            .unwrap();

        assert_eq!(
            block_a_ref, block_b_ref,
            "AssemblyOp payload must not affect execution node identity"
        );

        record_test_root(&mut builder, block_a_ref);
        let (_forest, remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_debug_info();
        let final_block_a = remapping[&block_a_ref];
        assert!(source_asm_contexts(&source_graph, final_block_a).contains(&"ctx_a".to_string()));
        assert_eq!(final_block_a, remapping[&block_b_ref]);
    }

    #[test]
    fn test_source_graph_distinguishes_same_exec_asm_op_occurrences() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let asm_op_a = add_test_asm_op(&mut builder, AssemblyOp::new(None, "ctx_a", 1, "add"));
        let asm_op_b = add_test_asm_op(&mut builder, AssemblyOp::new(None, "ctx_b", 1, "add"));

        let block_a_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![asm_op_a], Vec::new(), vec![], vec![])
            .unwrap();
        let block_b_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![asm_op_b], Vec::new(), vec![], vec![])
            .unwrap();

        assert_eq!(block_a_ref, block_b_ref);

        record_test_root(&mut builder, block_a_ref);
        let (forest, remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_debug_info();
        let final_block = remapping[&block_a_ref];
        let asm_contexts = source_nodes_for_exec(&source_graph, final_block)
            .into_iter()
            .flat_map(|source_node| {
                source_node
                    .asm_ops
                    .iter()
                    .map(|asm_op| source_graph[asm_op.context_name_idx].to_string())
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

        let asm_op_a = add_test_asm_op(&mut builder, AssemblyOp::new(None, "ctx_a", 1, "add"));
        let asm_op_b = add_test_asm_op(&mut builder, AssemblyOp::new(None, "ctx_b", 1, "add"));
        let block_a_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![asm_op_a], Vec::new(), vec![], vec![])
            .unwrap();
        let block_b_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![asm_op_b], Vec::new(), vec![], vec![])
            .unwrap();
        assert_eq!(block_a_ref, block_b_ref);

        let split_ref = builder
            .ensure_split_node_ref(
                [block_a_ref, block_b_ref],
                AssemblyOp::new(None, "split", 1, "if.true"),
                vec![],
            )
            .unwrap();
        record_test_root(&mut builder, split_ref);

        let (_forest, _remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_debug_info();
        let root = source_graph.roots()[0];
        let child_contexts = source_graph.nodes()[root]
            .children
            .iter()
            .map(|child| {
                let child_node = &source_graph.nodes()[*child];
                source_graph[child_node.asm_ops[0].context_name_idx].to_string()
            })
            .collect::<Vec<_>>();

        assert_eq!(child_contexts, vec!["ctx_a".to_string(), "ctx_b".to_string()]);
    }

    #[test]
    fn test_source_graph_reuses_source_occurrence_for_duplicate_child_refs() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let block_ref = builder
            .ensure_block_ref(vec![Operation::Add], Vec::new(), Vec::new(), vec![], vec![])
            .unwrap();
        let split_ref = builder
            .ensure_split_node_ref(
                [block_ref, block_ref],
                AssemblyOp::new(None, "split", 1, "if.true"),
                vec![],
            )
            .unwrap();
        record_test_root(&mut builder, split_ref);

        let (_forest, _remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_debug_info();
        let root = source_graph.roots()[0];
        let children = &source_graph.nodes()[root].children;

        assert_eq!(children.len(), 2);
        assert_eq!(children[0], children[1]);
    }

    /// Non-block nodes with different AssemblyOps use the same execution node identity.
    #[test]
    fn test_non_block_nodes_keep_different_asm_ops_distinct() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let callee_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![], vec![], vec![], vec![])
            .unwrap();
        let call_a_ref = builder
            .ensure_call_node_ref(
                callee_ref,
                false,
                AssemblyOp::new(None, "ctx_a", 1, "call.foo"),
                vec![],
            )
            .unwrap();
        let call_b_ref = builder
            .ensure_call_node_ref(
                callee_ref,
                false,
                AssemblyOp::new(None, "ctx_b", 1, "call.foo"),
                vec![],
            )
            .unwrap();

        assert_eq!(
            call_a_ref, call_b_ref,
            "AssemblyOp payload must not affect execution node identity"
        );

        record_test_root(&mut builder, call_a_ref);
        let (_forest, remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_debug_info();
        let final_call_a = remapping[&call_a_ref];
        assert!(source_asm_contexts(&source_graph, final_call_a).contains(&"ctx_a".to_string()));
        assert_eq!(final_call_a, remapping[&call_b_ref]);
    }

    /// Statically linked nodes dedup with local nodes that have the same execution shape.
    #[test]
    fn test_statically_linked_nodes_preserve_metadata_in_dedup() {
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

        let local_var_ref =
            add_test_debug_var(&mut builder, DebugVarInfo::new("y", DebugVarLocation::Stack(1)));
        let local_asm_op_ref =
            add_test_asm_op(&mut builder, AssemblyOp::new(None, "local_ctx", 1, "add"));
        let local_block_ref = builder
            .ensure_block_ref(
                vec![Operation::Add],
                vec![local_asm_op_ref],
                vec![local_var_ref],
                vec![],
                vec![],
            )
            .unwrap();

        assert_eq!(
            copied_block_ref, local_block_ref,
            "source metadata must not affect execution node identity"
        );

        record_test_root(&mut builder, copied_block_ref);
        let (_forest, remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_debug_info();
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
        let asm_op = AssemblyOp::new(None, "padded_ctx", 1, "push.3");
        let debug_var = DebugVarInfo::new("padded_var", DebugVarLocation::Stack(0));

        let static_asm_op_ref = add_test_asm_op(&mut source_builder, asm_op.clone());
        let static_debug_var_ref = add_test_debug_var(&mut source_builder, debug_var);
        let static_block_ref = source_builder
            .ensure_block_ref(
                ops.clone(),
                vec![with_asm_op_idx(static_asm_op_ref, 8)],
                vec![with_debug_var_idx(static_debug_var_ref, 8)],
                vec![],
                vec![],
            )
            .unwrap();
        record_test_root(&mut source_builder, static_block_ref);

        let (static_forest, source_remapping, static_source_graph, _) =
            source_builder.build().unwrap().into_parts_with_debug_info();
        let final_static_block = source_remapping[&static_block_ref];
        let static_source_root = static_source_graph.roots()[0];
        let expected_padded_idx = static_source_graph.nodes()[static_source_root].asm_ops[0].op_idx;
        assert_eq!(
            static_source_graph.nodes()[static_source_root].debug_vars[0].op_idx,
            expected_padded_idx
        );
        let package_debug_info = *static_source_graph;

        let mut builder =
            MastForestBuilder::new_with_static_libraries([StaticLibrary::from_mast_forest(
                &static_forest,
                Some(package_debug_info),
            )])
            .unwrap();
        let copied_block_ref = builder
            .ensure_external_link_with_source_ref(
                static_forest[final_static_block].digest(),
                Some(static_forest.commitment()),
                Some(final_static_block),
                Some(static_source_root),
            )
            .unwrap();
        let local_asm_op_ref = add_test_asm_op(&mut builder, asm_op);
        let local_block_ref = builder
            .ensure_block_ref(
                ops,
                vec![with_asm_op_idx(local_asm_op_ref, 8)],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();

        assert_eq!(
            copied_block_ref, local_block_ref,
            "copied padded blocks should dedup with equivalent local blocks",
        );

        record_test_root(&mut builder, copied_block_ref);
        let (_forest, remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_debug_info();
        let final_block_id = remapping[&copied_block_ref];
        let source_nodes = source_nodes_for_exec(&source_graph, final_block_id);
        assert!(source_nodes.iter().any(|source_node| {
            source_node.asm_ops.iter().any(|asm_op| {
                asm_op.op_idx == expected_padded_idx
                    && source_graph[asm_op.context_name_idx].as_ref() == "padded_ctx"
            })
        }));
        assert!(source_nodes.iter().any(|source_node| {
            source_node.debug_vars.iter().any(|debug_var| {
                debug_var.op_idx == expected_padded_idx
                    && source_graph[debug_var.name_idx].as_ref() == "padded_var"
            })
        }));
    }

    #[test]
    fn test_statically_linked_debug_variable_type_is_remapped() {
        let mut source_builder = MastForestBuilder::new(&[]).unwrap();
        let static_type = source_builder
            .debug_info_mut()
            .add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U32));
        let mut static_var = add_test_debug_var(
            &mut source_builder,
            DebugVarInfo::new("static_var", DebugVarLocation::Stack(0)),
        );
        static_var.type_id = Some(static_type);
        let static_block_ref = source_builder
            .ensure_block_ref(vec![Operation::Add], vec![], vec![static_var], vec![], vec![])
            .unwrap();
        record_test_root(&mut source_builder, static_block_ref);
        let (static_forest, source_remapping, static_debug_info, _) =
            source_builder.build().unwrap().into_parts_with_debug_info();
        let static_block = source_remapping[&static_block_ref];
        let static_source_root = static_debug_info.roots()[0];

        let mut builder =
            MastForestBuilder::new_with_static_libraries([StaticLibrary::from_mast_forest(
                &static_forest,
                Some(*static_debug_info),
            )])
            .unwrap();
        let local_type = builder
            .debug_info_mut()
            .add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U8));
        assert_eq!(local_type, DebugTypeIdx::from(0));
        let linked_ref = builder
            .ensure_external_link_with_source_ref(
                static_forest[static_block].digest(),
                Some(static_forest.commitment()),
                Some(static_block),
                Some(static_source_root),
            )
            .unwrap();
        record_test_root(&mut builder, linked_ref);

        let (_forest, _remapping, debug_info, _) =
            builder.build().unwrap().into_parts_with_debug_info();
        let linked_source = debug_info.roots()[0];
        let linked_var = &debug_info[linked_source].debug_vars[0];
        let linked_type = linked_var.type_id.unwrap();

        assert_eq!(linked_type, DebugTypeIdx::from(1));
        assert_eq!(debug_info[linked_type], DebugTypeInfo::Primitive(DebugPrimitiveType::U32),);
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
        let asm_op = AssemblyOp::new(None, "partial_ctx", 1, "push.2");
        let static_asm_op_ref = add_test_asm_op(&mut source_builder, asm_op);
        let static_block_ref = source_builder
            .ensure_block_ref(
                ops,
                vec![with_asm_op_idx(static_asm_op_ref, 4)],
                vec![],
                vec![],
                vec![],
            )
            .unwrap();
        record_test_root(&mut source_builder, static_block_ref);

        let (static_forest, source_remapping, static_source_graph, _) =
            source_builder.build().unwrap().into_parts_with_debug_info();
        let final_static_block = source_remapping[&static_block_ref];
        let static_source_root = static_source_graph.roots()[0];
        let expected_partial_start =
            static_source_graph.nodes()[static_source_root].asm_ops[0].op_idx;
        let package_source_root = static_source_root;
        let mut package_debug_info = PackageDebugInfoBuilder::from(static_source_graph);
        package_debug_info[package_source_root].op_start = expected_partial_start;
        package_debug_info[package_source_root].op_end = expected_partial_start + 1;
        let package_debug_info = *package_debug_info.build();

        let mut builder =
            MastForestBuilder::new_with_static_libraries([StaticLibrary::from_mast_forest(
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
            builder.build().unwrap().into_parts_with_debug_info();
        let final_block_id = remapping[&copied_block_ref];
        let linked_source_node = source_nodes_for_exec(&source_graph, final_block_id)
            .into_iter()
            .find(|source_node| {
                source_node
                    .asm_ops
                    .iter()
                    .any(|asm_op| source_graph[asm_op.context_name_idx].as_ref() == "partial_ctx")
            })
            .expect("linked source node should preserve package metadata");

        assert_eq!(linked_source_node.op_start, expected_partial_start);
        assert_eq!(linked_source_node.op_end, expected_partial_start + 1);
    }

    #[test]
    fn test_static_link_rejects_package_debug_child_exec_mismatch() {
        let mut source_builder = MastForestBuilder::new(&[]).unwrap();
        let left_ref = source_builder
            .ensure_block_ref(vec![Operation::Add], vec![], vec![], vec![], vec![])
            .unwrap();
        let right_ref = source_builder
            .ensure_block_ref(vec![Operation::Mul], vec![], vec![], vec![], vec![])
            .unwrap();
        let split_ref = source_builder
            .ensure_split_node_ref(
                [left_ref, right_ref],
                AssemblyOp::new(None, "split_ctx", 1, "if.true"),
                vec![],
            )
            .unwrap();
        record_test_root(&mut source_builder, split_ref);

        let (static_forest, source_remapping, static_source_graph, _) =
            source_builder.build().unwrap().into_parts_with_debug_info();
        let final_split = source_remapping[&split_ref];
        let package_source_root = static_source_graph.roots()[0];
        let mut package_debug_info = PackageDebugInfoBuilder::from(static_source_graph);
        package_debug_info[package_source_root].children.swap(0, 1);
        let package_debug_info = *package_debug_info.build();

        let mut builder =
            MastForestBuilder::new_with_static_libraries([StaticLibrary::from_mast_forest(
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
        use miden_core::operations::AssemblyOp;

        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let var_ref =
            add_test_debug_var(&mut builder, DebugVarInfo::new("x", DebugVarLocation::Stack(0)));
        let asm_op_ref = add_test_asm_op(&mut builder, AssemblyOp::new(None, "test", 1, "add"));

        // Small block that will be a procedure root -- should_merge returns true for
        // small roots, so it will be folded into the merged block.
        let root_block_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![asm_op_ref], vec![var_ref], vec![], vec![])
            .unwrap();
        builder.record_procedure_root_ref(root_block_ref);

        // Second block to merge with.
        let other_block_ref = builder
            .ensure_block_ref(vec![Operation::Mul], vec![], vec![], vec![], vec![])
            .unwrap();

        let merged = builder.merge_basic_block_refs(&[root_block_ref, other_block_ref]).unwrap();
        // Root was small enough to merge, so we get one merged block.
        assert_eq!(merged.len(), 1);
        let merged_ref = merged[0];
        assert_ne!(merged_ref, root_block_ref);

        let (forest, remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_debug_info();

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

        let alias_a_asm_op =
            add_test_asm_op(&mut source_builder, AssemblyOp::new(None, "alias_a", 1, "add"));
        let alias_b_asm_op =
            add_test_asm_op(&mut source_builder, AssemblyOp::new(None, "alias_b", 1, "add"));
        let alias_a_ref = source_builder
            .ensure_block_ref(vec![Operation::Add], vec![alias_a_asm_op], vec![], vec![], vec![])
            .unwrap();
        let alias_b_ref = source_builder
            .ensure_block_ref(vec![Operation::Add], vec![alias_b_asm_op], vec![], vec![], vec![])
            .unwrap();
        record_test_root(&mut source_builder, alias_a_ref);
        record_test_root(&mut source_builder, alias_b_ref);

        let (static_forest, source_remapping) = source_builder.build().unwrap().into_parts();
        let final_alias_a = source_remapping[&alias_a_ref];
        let final_alias_b = source_remapping[&alias_b_ref];
        assert_eq!(static_forest[final_alias_a].digest(), static_forest[final_alias_b].digest());

        // This path links only the execution forest, without package debug info, so no source
        // metadata is imported.
        let mut exact_builder = MastForestBuilder::new([&static_forest]).unwrap();
        let exact_alias_b_ref = {
            let source_forest = Arc::clone(&exact_builder.statically_linked_mast);
            let node = source_forest[final_alias_b].clone();
            let node_refs_by_source_id = BTreeMap::new();
            let child_refs = exact_builder
                .pending_refs_for_statically_linked_source(&node, &node_refs_by_source_id);
            exact_builder
                .ensure_node_from_statically_linked_source_ref(node, child_refs, None)
                .unwrap()
        };
        record_test_root(&mut exact_builder, exact_alias_b_ref);
        let (_exact_forest, exact_remapping, exact_source_graph, _) =
            exact_builder.build().unwrap().into_parts_with_debug_info();
        let final_exact_alias_b = exact_remapping[&exact_alias_b_ref];
        assert!(source_asm_contexts(&exact_source_graph, final_exact_alias_b).is_empty());
    }

    #[test]
    fn test_source_graph_distinguishes_same_digest_alias_roots() {
        let mut builder = MastForestBuilder::new(&[]).unwrap();

        let alias_a_asm_op =
            add_test_asm_op(&mut builder, AssemblyOp::new(None, "alias_a", 1, "add"));
        let alias_b_asm_op =
            add_test_asm_op(&mut builder, AssemblyOp::new(None, "alias_b", 1, "add"));
        let alias_a_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![alias_a_asm_op], vec![], vec![], vec![])
            .unwrap();
        let alias_b_ref = builder
            .ensure_block_ref(vec![Operation::Add], vec![alias_b_asm_op], vec![], vec![], vec![])
            .unwrap();
        record_test_root(&mut builder, alias_a_ref);
        record_test_root(&mut builder, alias_b_ref);

        let (forest, remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_debug_info();
        let final_alias_a = remapping[&alias_a_ref];
        let final_alias_b = remapping[&alias_b_ref];
        let root_contexts = source_graph
            .roots()
            .iter()
            .flat_map(|source_root| source_graph.nodes()[*source_root].asm_ops.iter())
            .map(|asm_op| source_graph[asm_op.context_name_idx].to_string())
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

        let alias_a_asm_op =
            add_test_asm_op(&mut source_builder, AssemblyOp::new(None, "alias_a", 1, "add"));
        let alias_b_asm_op =
            add_test_asm_op(&mut source_builder, AssemblyOp::new(None, "alias_b", 1, "add"));
        let alias_a_ref = source_builder
            .ensure_block_ref(vec![Operation::Add], vec![alias_a_asm_op], vec![], vec![], vec![])
            .unwrap();
        let alias_b_ref = source_builder
            .ensure_block_ref(vec![Operation::Add], vec![alias_b_asm_op], vec![], vec![], vec![])
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
    fn test_static_link_ambiguous_same_commitment_source_root_drops_source_metadata() {
        let mut source_a_builder = MastForestBuilder::new(&[]).unwrap();
        let source_a_asm_op =
            add_test_asm_op(&mut source_a_builder, AssemblyOp::new(None, "source_a", 1, "add"));
        let source_a_ref = source_a_builder
            .ensure_block_ref(vec![Operation::Add], vec![source_a_asm_op], vec![], vec![], vec![])
            .unwrap();
        record_test_root(&mut source_a_builder, source_a_ref);
        let (source_a_forest, source_a_remapping) = source_a_builder.build().unwrap().into_parts();
        let source_a_root = source_a_remapping[&source_a_ref];

        let mut source_b_builder = MastForestBuilder::new(&[]).unwrap();
        let source_b_asm_op =
            add_test_asm_op(&mut source_b_builder, AssemblyOp::new(None, "source_b", 1, "add"));
        let source_b_ref = source_b_builder
            .ensure_block_ref(vec![Operation::Add], vec![source_b_asm_op], vec![], vec![], vec![])
            .unwrap();
        record_test_root(&mut source_b_builder, source_b_ref);
        let (source_b_forest, source_b_remapping) = source_b_builder.build().unwrap().into_parts();
        let source_b_root = source_b_remapping[&source_b_ref];

        assert_eq!(source_a_root, source_b_root);
        assert_eq!(source_a_forest.interface_commitment(), source_b_forest.interface_commitment());
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
            !builder.nodes[linked_ref].kind.is_external(),
            "ambiguous same-commitment provenance should not force an external node"
        );
        record_test_root(&mut builder, linked_ref);
        let (_forest, remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_debug_info();
        let final_linked = remapping[&linked_ref];

        assert!(
            source_asm_contexts(&source_graph, final_linked).is_empty(),
            "ambiguous same-commitment provenance should import execution without source metadata"
        );
    }

    #[test]
    fn test_static_link_direct_forest_identity_uses_full_commitment() {
        let mut source_a_builder = MastForestBuilder::new(&[]).unwrap();
        let source_a_asm_op =
            add_test_asm_op(&mut source_a_builder, AssemblyOp::new(None, "source_a", 1, "add"));
        let source_a_ref = source_a_builder
            .ensure_block_ref(vec![Operation::Add], vec![source_a_asm_op], vec![], vec![], vec![])
            .unwrap();
        record_test_root(&mut source_a_builder, source_a_ref);
        let (source_a_forest, source_a_remapping, source_a_graph, _) =
            source_a_builder.build().unwrap().into_parts_with_debug_info();
        let source_a_root = source_a_remapping[&source_a_ref];

        let mut source_b_builder = MastForestBuilder::new(&[]).unwrap();
        let source_b_asm_op =
            add_test_asm_op(&mut source_b_builder, AssemblyOp::new(None, "source_b", 1, "add"));
        let source_b_ref = source_b_builder
            .ensure_block_ref(vec![Operation::Add], vec![source_b_asm_op], vec![], vec![], vec![])
            .unwrap();
        record_test_root(&mut source_b_builder, source_b_ref);
        let (source_b_forest, source_b_remapping, source_b_graph, _) =
            source_b_builder.build().unwrap().into_parts_with_debug_info();
        let source_b_root = source_b_remapping[&source_b_ref];
        let source_b_forest = source_b_forest.with_advice_map(AdviceMap::from_iter([(
            Word::from([Felt::new_unchecked(9), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
            vec![Felt::new_unchecked(1)],
        )]));

        assert_eq!(source_a_forest.interface_commitment(), source_b_forest.interface_commitment());
        assert_ne!(source_a_forest.commitment(), source_b_forest.commitment());
        assert_eq!(
            source_a_forest[source_a_root].digest(),
            source_b_forest[source_b_root].digest()
        );

        let source_b_debug_root = source_b_graph.roots()[0];
        let mut builder = MastForestBuilder::new_with_static_libraries([
            StaticLibrary::from_mast_forest(&source_a_forest, Some(*source_a_graph)),
            StaticLibrary::from_mast_forest(&source_b_forest, Some(*source_b_graph)),
        ])
        .unwrap();
        let linked_ref = builder
            .ensure_external_link_with_source_ref(
                source_b_forest[source_b_root].digest(),
                Some(source_b_forest.commitment()),
                Some(source_b_root),
                Some(source_b_debug_root),
            )
            .unwrap();
        record_test_root(&mut builder, linked_ref);
        let (_forest, remapping, source_graph, _) =
            builder.build().unwrap().into_parts_with_debug_info();
        let final_linked = remapping[&linked_ref];

        assert_eq!(source_asm_contexts(&source_graph, final_linked), vec!["source_b"]);
    }

    /// Provenance-aware static linking imports package-owned source metadata for the selected root.
    #[test]
    fn test_static_link_with_source_root_preserves_selected_alias_metadata() {
        let mut source_builder = MastForestBuilder::new(&[]).unwrap();

        let alias_a_asm_op =
            add_test_asm_op(&mut source_builder, AssemblyOp::new(None, "alias_a", 1, "add"));
        let alias_b_asm_op =
            add_test_asm_op(&mut source_builder, AssemblyOp::new(None, "alias_b", 1, "add"));
        let alias_a_ref = source_builder
            .ensure_block_ref(vec![Operation::Add], vec![alias_a_asm_op], vec![], vec![], vec![])
            .unwrap();
        let alias_b_ref = source_builder
            .ensure_block_ref(vec![Operation::Add], vec![alias_b_asm_op], vec![], vec![], vec![])
            .unwrap();
        record_test_root(&mut source_builder, alias_a_ref);
        record_test_root(&mut source_builder, alias_b_ref);

        let (static_forest, source_remapping, static_source_graph, _) =
            source_builder.build().unwrap().into_parts_with_debug_info();
        let final_alias_a = source_remapping[&alias_a_ref];
        let final_alias_b = source_remapping[&alias_b_ref];
        assert_eq!(static_forest[final_alias_a].digest(), static_forest[final_alias_b].digest());
        let alias_b_source_root = static_source_graph.roots()[1];
        let package_debug_info = *static_source_graph;

        let mut provenance_builder =
            MastForestBuilder::new_with_static_libraries([StaticLibrary::from_mast_forest(
                &static_forest,
                Some(package_debug_info),
            )])
            .unwrap();
        let linked_alias_b_ref = provenance_builder
            .ensure_external_link_with_source_ref(
                static_forest[final_alias_b].digest(),
                Some(static_forest.commitment()),
                Some(final_alias_b),
                Some(alias_b_source_root),
            )
            .unwrap();
        record_test_root(&mut provenance_builder, linked_alias_b_ref);
        let (_linked_forest, linked_remapping, linked_source_graph, _) =
            provenance_builder.build().unwrap().into_parts_with_debug_info();
        let final_linked_alias_b = linked_remapping[&linked_alias_b_ref];
        let linked_source_root = linked_source_graph.roots()[0];
        let linked_source_node = &linked_source_graph.nodes()[linked_source_root];

        assert_eq!(linked_source_node.exec_node, final_linked_alias_b);
        let linked_asm_op = linked_source_node.asm_ops.first().unwrap();
        assert_eq!(
            linked_source_graph[linked_asm_op.context_name_idx].as_ref(),
            "alias_b",
            "exact static provenance should select the hinted package source occurrence",
        );
    }

    #[test]
    fn test_static_link_preserves_repeated_exact_child_occurrences() {
        let mut source_builder = MastForestBuilder::new(&[]).unwrap();
        let static_asm_op =
            add_test_asm_op(&mut source_builder, AssemblyOp::new(None, "static", 1, "add"));
        let static_child = source_builder
            .ensure_block_use(vec![Operation::Add], vec![static_asm_op], vec![], vec![], vec![])
            .unwrap();
        let static_root = source_builder
            .ensure_split_node_use(
                [static_child, static_child],
                AssemblyOp::new(None, "static", 1, "if.true"),
                vec![],
            )
            .unwrap();
        source_builder.record_procedure_root_use(static_root);

        let (static_forest, static_remapping, static_debug_info, static_source_remapping) =
            source_builder.build().unwrap().into_parts_with_debug_info();
        let static_root_id = static_remapping[&static_root.node_ref()];
        let static_source_root_id = static_source_remapping[&static_root.source_ref()];

        let mut builder =
            MastForestBuilder::new_with_static_libraries([StaticLibrary::from_mast_forest(
                &static_forest,
                Some(*static_debug_info),
            )])
            .unwrap();
        let local_asm_op = add_test_asm_op(&mut builder, AssemblyOp::new(None, "local", 1, "add"));
        builder
            .ensure_block_use(vec![Operation::Add], vec![local_asm_op], vec![], vec![], vec![])
            .unwrap();

        let linked_root_ref = builder
            .ensure_external_link_with_source_ref(
                static_forest[static_root_id].digest(),
                Some(static_forest.commitment()),
                Some(static_root_id),
                Some(static_source_root_id),
            )
            .unwrap();
        record_test_root(&mut builder, linked_root_ref);

        let (_, _, linked_debug_info, _) = builder.build().unwrap().into_parts_with_debug_info();
        let linked_root = &linked_debug_info[linked_debug_info.roots()[0]];
        assert_eq!(linked_root.children.len(), 2);
        for child in linked_root.children.iter().copied() {
            let asm_op = linked_debug_info[child]
                .asm_ops
                .first()
                .expect("the exact static child should retain its assembly metadata");
            assert_eq!(linked_debug_info[asm_op.context_name_idx].as_ref(), "static");
        }
    }
}
