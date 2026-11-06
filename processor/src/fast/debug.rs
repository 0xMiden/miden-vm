use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec,
    vec::Vec,
};

use miden_core::{
    Word,
    mast::{MastForest, MastNodeExt, MastNodeId},
};
use miden_mast_package::debug_info::{
    DebugFunctionIdx, DebugFunctionInfo, DebugSourceNode, DebugSourceNodeId, DebugStringIdx,
    PackageDebugInfo,
};

use crate::{Continuation, ResumeContext, continuation_stack::DebugActivationId};

/// Evidence used to recover a source-level frame. Inferred frames are best-effort and may omit
/// optimized callers; consumers must distinguish them from frames identified by source identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DebugFrameOrigin {
    /// A unique function references the selected source occurrence and its executable root.
    Source,
    /// A retained operation range matches a function's assembly-operation metadata.
    InferredRange,
    /// The selected source occurrence's assembly context uniquely names a function.
    InferredContext,
    /// An external boundary's inline rows identify a caller with a retained canonical definition.
    InferredInline,
}

/// A recovered invocation of a debug function, without additional serialized frame metadata.
#[derive(Clone, Debug)]
pub struct DebugCallFrame {
    debug_info: Arc<PackageDebugInfo>,
    function_idx: DebugFunctionIdx,
    source_node_id: DebugSourceNodeId,
    range_start: u32,
    activation: DebugActivationId,
    inherited_inline_calls: usize,
    origin: DebugFrameOrigin,
}

impl DebugCallFrame {
    pub fn function_idx(&self) -> DebugFunctionIdx {
        self.function_idx
    }
    pub fn function(&self) -> &DebugFunctionInfo {
        &self.debug_info[self.function_idx]
    }
    pub fn debug_info(&self) -> &PackageDebugInfo {
        &self.debug_info
    }
    pub fn inherited_inline_calls(&self) -> usize {
        self.inherited_inline_calls
    }
    pub fn origin(&self) -> DebugFrameOrigin {
        self.origin
    }
    pub fn is_inferred(&self) -> bool {
        self.origin != DebugFrameOrigin::Source
    }

    /// Compares invocation identities, rather than names, so recursive activations stay separate.
    pub fn is_same_frame(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.debug_info, &other.debug_info)
            && self.function_idx == other.function_idx
            && self.source_node_id == other.source_node_id
            && self.range_start == other.range_start
            && self.activation == other.activation
    }
}

#[derive(Clone)]
struct FunctionRange {
    function: DebugFunctionIdx,
    start: u32,
    end: u32,
    signature: Signature,
    /// Explicit inline boundaries retain ownership even when merging re-batches their padding.
    explicit_boundary: bool,
}

impl FunctionRange {
    fn matches_source(&self, node: &DebugSourceNode) -> bool {
        let start = node.asm_ops.partition_point(|row| row.op_idx < self.start);
        let end = node.asm_ops.partition_point(|row| row.op_idx < self.end);
        let rows = &node.asm_ops[start..end];
        rows.len() == self.signature.len()
            && rows.iter().zip(&self.signature).all(
                |(row, (offset, context, operation, cycles))| {
                    (self.explicit_boundary || row.op_idx - self.start == *offset)
                        && (row.context_name_idx, row.op_name_idx, row.num_cycles)
                            == (*context, *operation, *cycles)
                },
            )
    }
}

type Signature = Vec<(u32, DebugStringIdx, DebugStringIdx, u8)>;

fn signature(node: &DebugSourceNode) -> Signature {
    node.asm_ops
        .iter()
        .map(|row| {
            (
                row.op_idx.saturating_sub(node.op_start),
                row.context_name_idx,
                row.op_name_idx,
                row.num_cycles,
            )
        })
        .collect()
}

/// Active inline depth at every boundary. Build once per source node so many adjacent execs
/// do not require scanning the entire inline table for each recovered range.
fn inline_depths(node: &DebugSourceNode) -> BTreeMap<u32, (usize, usize)> {
    let mut events = BTreeMap::<u32, (usize, usize, usize)>::new();
    for row in &node.inline_calls {
        if row.op_idx == row.op_end {
            events.entry(row.op_idx).or_default().2 += 1;
        } else {
            events.entry(row.op_idx).or_default().0 += 1;
            events.entry(row.op_end).or_default().1 += 1;
        }
    }
    let mut active = 0;
    events
        .into_iter()
        .map(|(position, (starts, ends, points))| {
            active += starts;
            active -= ends;
            (position, (active, points))
        })
        .collect()
}

struct FunctionIndex {
    info: Arc<PackageDebugInfo>,
    forest: Arc<MastForest>,
    sources: BTreeMap<DebugSourceNodeId, Vec<DebugFunctionIdx>>,
    names: BTreeMap<Arc<str>, Vec<DebugFunctionIdx>>,
    ranges: BTreeMap<MastNodeId, Vec<FunctionRange>>,
    entry_inline_counts: BTreeMap<DebugFunctionIdx, usize>,
    entry_names: BTreeMap<DebugSourceNodeId, Option<DebugStringIdx>>,
    inline_depths: BTreeMap<DebugSourceNodeId, BTreeMap<u32, (usize, usize)>>,
}

impl FunctionIndex {
    fn new(info: Arc<PackageDebugInfo>, forest: Arc<MastForest>) -> Self {
        let mut index = Self {
            info,
            forest,
            sources: BTreeMap::new(),
            names: BTreeMap::new(),
            ranges: BTreeMap::new(),
            entry_inline_counts: BTreeMap::new(),
            entry_names: BTreeMap::new(),
            inline_depths: BTreeMap::new(),
        };
        let mut root_nodes = BTreeMap::<Word, MastNodeId>::new();
        for root in index.forest.procedure_roots() {
            root_nodes.entry(index.forest[*root].digest()).or_insert(*root);
        }
        let mut default_sources = BTreeMap::<MastNodeId, &DebugSourceNode>::new();
        let mut named_sources = BTreeMap::<(MastNodeId, DebugStringIdx), &DebugSourceNode>::new();
        let rank = |node: &DebugSourceNode| {
            (node.asm_ops.len(), core::cmp::Reverse(node.inline_calls.len()))
        };
        for node in index.info.nodes() {
            default_sources
                .entry(node.exec_node)
                .and_modify(|current| {
                    if rank(node) >= rank(current) {
                        *current = node;
                    }
                })
                .or_insert(node);
            for row in &node.asm_ops {
                named_sources
                    .entry((node.exec_node, row.context_name_idx))
                    .and_modify(|current| {
                        if rank(node) >= rank(current) {
                            *current = node;
                        }
                    })
                    .or_insert(node);
            }
        }
        for position in 0..index.info.nodes().len() {
            let mut source = DebugSourceNodeId::from(position as u32);
            let mut path = Vec::new();
            let name = loop {
                if let Some(name) = index.entry_names.get(&source) {
                    break *name;
                }
                if path.len() >= index.info.nodes().len() {
                    break None;
                }
                path.push(source);
                let node = &index.info[source];
                if let Some(row) = node.asm_ops.first() {
                    break Some(row.context_name_idx);
                }
                let Some(child) = node.children.first() else {
                    break None;
                };
                source = *child;
            };
            for source in path {
                index.entry_names.insert(source, name);
            }
        }
        let mut signatures = BTreeMap::<Signature, Vec<DebugFunctionIdx>>::new();
        let mut function_signatures = BTreeMap::<DebugFunctionIdx, Signature>::new();
        for (position, function) in index.info.functions().iter().enumerate() {
            let function_idx = DebugFunctionIdx::from(position as u32);
            if let Some(source) = function.source_node.into_option() {
                index.sources.entry(source).or_default().push(function_idx);
            }
            for name_idx in [Some(function.name_idx), function.linkage_name_idx.into_option()]
                .into_iter()
                .flatten()
            {
                if let Some(name) = index.info.get_string(name_idx) {
                    let names = index.names.entry(name).or_default();
                    if names.last() != Some(&function_idx) {
                        names.push(function_idx);
                    }
                }
            }
            let Some(root) = root_nodes.get(&function.mast_root) else {
                continue;
            };
            let canonical = [Some(function.name_idx), function.linkage_name_idx.into_option()]
                .into_iter()
                .flatten()
                .filter_map(|name| named_sources.get(&(*root, name)).copied())
                .max_by_key(|node| rank(node));
            if let Some(node) = canonical.or_else(|| default_sources.get(root).copied()) {
                index.entry_inline_counts.insert(
                    function_idx,
                    node.inline_calls.iter().filter(|row| row.op_idx == node.op_start).count(),
                );
                if canonical.is_some() && !node.asm_ops.is_empty() {
                    let signature = signature(node);
                    function_signatures.insert(function_idx, signature.clone());
                    signatures.entry(signature).or_default().push(function_idx);
                }
            }
        }
        let mut seen_ranges = BTreeSet::new();
        for node in index.info.nodes().iter().filter(|node| !node.asm_ops.is_empty()) {
            let Some(functions) = signatures.get(&signature(node)) else {
                continue;
            };
            let [function] = functions.as_slice() else {
                continue;
            };
            let range = FunctionRange {
                function: *function,
                start: node.op_start,
                end: node.op_end,
                signature: signature(node),
                explicit_boundary: false,
            };
            let ranges = index.ranges.entry(node.exec_node).or_default();
            if seen_ranges.insert((node.exec_node, range.function, range.start, range.end)) {
                ranges.push(range);
            }
        }
        // An optimized exec may retain only its inline boundary, without a separate source
        // slice. Validate that explicit function identity against its complete executable
        // signature before recovering it: source-language inline rows alone are not invocations.
        // Re-batching may move padding inside that explicit boundary. Generic source slices still
        // require exact offsets so a caller's generated prefix cannot become part of the callee.
        for (position, node) in index.info.nodes().iter().enumerate() {
            if !node.inline_calls.is_empty() {
                index
                    .inline_depths
                    .insert(DebugSourceNodeId::from(position as u32), inline_depths(node));
            }
            for row in &node.inline_calls {
                let Some(signature) = function_signatures.get(&row.callee_idx) else {
                    continue;
                };
                let range = FunctionRange {
                    function: row.callee_idx,
                    start: row.op_idx,
                    end: row.op_end,
                    signature: signature.clone(),
                    explicit_boundary: true,
                };
                if range.matches_source(node)
                    && seen_ranges.insert((node.exec_node, range.function, range.start, range.end))
                {
                    index.ranges.entry(node.exec_node).or_default().push(range);
                }
            }
        }
        for ranges in index.ranges.values_mut() {
            ranges.sort_by_key(|range| (range.start, core::cmp::Reverse(range.end)));
        }
        index
    }

    fn inline_depth_at(&self, source: DebugSourceNodeId, operation: u32) -> usize {
        self.inline_depths
            .get(&source)
            .and_then(|depths| depths.range(..=operation).next_back())
            .map_or(0, |(position, (active, points))| {
                active + if *position == operation { *points } else { 0 }
            })
    }

    fn source_function(&self, source: DebugSourceNodeId) -> Option<DebugFunctionIdx> {
        let node = self.info.source_node(source)?;
        let digest = self.forest[node.exec_node].digest();
        let mut candidates = self
            .sources
            .get(&source)?
            .iter()
            .copied()
            .filter(|function| self.info[*function].mast_root == digest);
        let first = candidates.next()?;
        candidates.next().is_none().then_some(first)
    }

    fn external_caller_functions<'a>(
        &'a self,
        node: &'a DebugSourceNode,
    ) -> impl Iterator<Item = (DebugFunctionIdx, u32, usize)> + 'a {
        let external_digest = self.forest[node.exec_node]
            .is_external()
            .then(|| self.forest[node.exec_node].digest());
        node.inline_calls.iter().rev().filter_map(move |row| {
            if !row.contains_operation(node.op_start) {
                return None;
            }
            let function = self.info.get_function(row.callee_idx)?;
            let canonical = self.info.source_node(function.source_node.into_option()?)?;
            if canonical.exec_node != node.exec_node || Some(function.mast_root) != external_digest
            {
                return None;
            }
            let own_inline = canonical
                .inline_calls
                .iter()
                .filter(|row| row.contains_operation(canonical.op_start))
                .count();
            Some((row.callee_idx, row.op_idx, own_inline))
        })
    }

    fn context_function(&self, node: &DebugSourceNode, operation: u32) -> Option<DebugFunctionIdx> {
        let row = node.asm_op_for_operation(operation)?;
        if operation >= row.op_idx.saturating_add(u32::from(row.num_cycles)) {
            return None;
        }
        let name = self.info.get_string(row.context_name_idx)?;
        let [function] = self.names.get(&name)?.as_slice() else {
            return None;
        };
        Some(*function)
    }

    fn entry_function(&self, source: DebugSourceNodeId) -> Option<DebugFunctionIdx> {
        let name = self.info.get_string((*self.entry_names.get(&source)?)?)?;
        let [function] = self.names.get(&name)?.as_slice() else {
            return None;
        };
        let node = self.info.source_node(source)?;
        (self.info[*function].mast_root == self.forest[node.exec_node].digest())
            .then_some(*function)
    }
}

/// Caches indices derived from existing function records and source nodes. Retain this across
/// debugger steps and discard it when the debug session ends. It does not alter VM execution.
#[derive(Default)]
pub struct DebugCallFrameResolver {
    indices: Vec<FunctionIndex>,
}

impl DebugCallFrameResolver {
    pub fn new() -> Self {
        Self::default()
    }

    fn index(&mut self, info: &Arc<PackageDebugInfo>, forest: &Arc<MastForest>) -> &FunctionIndex {
        let position = self
            .indices
            .iter()
            .position(|index| Arc::ptr_eq(&index.info, info) && Arc::ptr_eq(&index.forest, forest));
        let position = position.unwrap_or_else(|| {
            self.indices.push(FunctionIndex::new(info.clone(), forest.clone()));
            self.indices.len() - 1
        });
        &self.indices[position]
    }

    /// Recover the active call chain for the next clock. Optimized `exec` boundaries may only be
    /// inferable from ranges or assembly context; inspect each frame's origin before presenting it.
    pub fn resolve(&mut self, context: &ResumeContext) -> Vec<DebugCallFrame> {
        let continuations =
            context.continuation_stack.iter_with_source_node_ids().collect::<Vec<_>>();
        let next_count = context.continuation_stack.iter_continuations_for_next_clock().count();
        let next_start = continuations.len().saturating_sub(next_count);
        let mut owners = vec![None; continuations.len()];
        let mut info = context.package_debug_info.clone();
        let mut forest = context.current_forest.clone();
        let mut inline_depth = context.inline_call_contexts.len();
        for (position, (continuation, _)) in continuations.iter().enumerate().rev() {
            if let Continuation::EnterForest {
                forest: caller_forest,
                package_debug_info,
                inline_context_depth,
                ..
            } = continuation
            {
                info = package_debug_info.clone();
                forest = caller_forest.clone();
                inline_depth = *inline_context_depth;
            }
            if matches!(continuation, Continuation::FinishDyn(_)) {
                inline_depth = inline_depth.saturating_sub(1);
            }
            let inherited = context.inline_call_contexts
                [..inline_depth.min(context.inline_call_contexts.len())]
                .iter()
                .filter_map(Option::as_ref)
                .map(|entry| entry.inline_calls().count())
                .sum::<usize>();
            owners[position] = info.as_ref().map(|info| (info.clone(), forest.clone(), inherited));
        }
        let mut frames = Vec::<DebugCallFrame>::new();
        for (position, (continuation, source)) in continuations.iter().enumerate() {
            let ancestor = matches!(
                continuation,
                Continuation::FinishJoin(_)
                    | Continuation::FinishSplit(_)
                    | Continuation::FinishLoop(_)
                    | Continuation::FinishCall(_)
                    | Continuation::FinishDyn(_)
                    | Continuation::EnterForest { .. }
            );
            if position > next_start || (!ancestor && position != next_start) {
                continue;
            }
            let (Some((info, forest, inherited)), Some(source)) = (&owners[position], source)
            else {
                continue;
            };
            let Some(node) = info.source_node(*source) else {
                continue;
            };
            let Some(activation) = context.continuation_stack.debug_activation_at(position) else {
                continue;
            };
            let operation = match continuation {
                Continuation::ResumeBasicBlock { node_id, batch_index, op_idx_in_batch } => {
                    let block = forest[*node_id].unwrap_basic_block();
                    (block
                        .op_batches()
                        .iter()
                        .take(*batch_index)
                        .map(|batch| batch.ops().len())
                        .sum::<usize>()
                        + op_idx_in_batch) as u32
                },
                Continuation::Respan { node_id, batch_index } => forest[*node_id]
                    .unwrap_basic_block()
                    .op_batches()
                    .iter()
                    .take(*batch_index)
                    .map(|batch| batch.ops().len() as u32)
                    .sum(),
                Continuation::FinishBasicBlock(node_id) => {
                    forest[*node_id].unwrap_basic_block().num_operations().saturating_sub(1)
                },
                _ => node.op_start,
            };
            let index = self.index(info, forest);
            let exact = index.source_function(*source);
            if let Some(function) = exact.or_else(|| index.entry_function(*source)) {
                let own_inline = index.entry_inline_counts.get(&function).copied().unwrap_or(0);
                let inherited = inherited
                    + node
                        .inline_calls
                        .iter()
                        .filter(|row| row.op_idx == node.op_start)
                        .count()
                        .saturating_sub(own_inline);
                frames.push(frame(
                    info,
                    function,
                    *source,
                    node.op_start,
                    activation.clone(),
                    inherited,
                    if exact.is_some() {
                        DebugFrameOrigin::Source
                    } else {
                        DebugFrameOrigin::InferredContext
                    },
                ));
            }
            // External exec copies have no assembly operations or canonical source identity.
            // Their explicit inline rows still identify caller-owned definitions, ordered
            // from outermost to innermost. Imported declarations without a local definition
            // belong to the loaded package's frames instead.
            for (function, start, own_inline) in index.external_caller_functions(node) {
                if frames.last().is_some_and(|frame| {
                    frame.function_idx == function && Arc::ptr_eq(&frame.debug_info, info)
                }) {
                    continue;
                }
                let inherited = inherited
                    + node
                        .inline_calls
                        .iter()
                        .filter(|row| row.contains_operation(node.op_start))
                        .count()
                        .saturating_sub(own_inline);
                frames.push(frame(
                    info,
                    function,
                    *source,
                    start,
                    activation.clone(),
                    inherited,
                    DebugFrameOrigin::InferredInline,
                ));
            }
            if position != next_start {
                continue;
            }
            if let Some(ranges) = index.ranges.get(&node.exec_node) {
                let mut enclosing_end = node.op_end;
                for range in
                    ranges.iter().filter(|range| range.start <= operation && operation < range.end)
                {
                    if range.start < node.op_start
                        || range.end > enclosing_end
                        || !range.matches_source(node)
                        || frames.last().is_some_and(|frame| {
                            frame.function_idx == range.function
                                && Arc::ptr_eq(&frame.debug_info, info)
                        })
                    {
                        continue;
                    }
                    enclosing_end = range.end;
                    frames.push(frame(
                        info,
                        range.function,
                        *source,
                        range.start,
                        activation.clone(),
                        inherited
                            + index.inline_depth_at(*source, range.start).saturating_sub(
                                index
                                    .entry_inline_counts
                                    .get(&range.function)
                                    .copied()
                                    .unwrap_or(0),
                            ),
                        DebugFrameOrigin::InferredRange,
                    ));
                }
            }
            if let Some(function) = index.context_function(node, operation)
                && !frames.last().is_some_and(|frame| {
                    frame.function_idx == function && Arc::ptr_eq(&frame.debug_info, info)
                })
            {
                let inline_calls =
                    node.inline_calls.iter().filter(|row| row.contains_operation(operation));
                // Rows are innermost-first. The exec boundary separates the callee's changing
                // source-inline context from its inherited callers, including the boundary itself.
                let own_inline =
                    inline_calls.clone().position(|row| row.callee_idx == function).unwrap_or_else(
                        || index.entry_inline_counts.get(&function).copied().unwrap_or(0),
                    );
                let inherited = inherited + inline_calls.count().saturating_sub(own_inline);
                frames.push(frame(
                    info,
                    function,
                    *source,
                    node.op_start,
                    activation,
                    inherited,
                    DebugFrameOrigin::InferredContext,
                ));
            }
        }
        frames
    }
}

impl ResumeContext {
    /// Recover frames without retaining an index. Repeated queries should use a
    /// [`DebugCallFrameResolver`] to avoid rebuilding the derived lookup tables.
    pub fn debug_call_frames(&self) -> Vec<DebugCallFrame> {
        DebugCallFrameResolver::new().resolve(self)
    }
}

fn frame(
    info: &Arc<PackageDebugInfo>,
    function_idx: DebugFunctionIdx,
    source_node_id: DebugSourceNodeId,
    range_start: u32,
    activation: DebugActivationId,
    inherited_inline_calls: usize,
    origin: DebugFrameOrigin,
) -> DebugCallFrame {
    DebugCallFrame {
        debug_info: info.clone(),
        function_idx,
        source_node_id,
        range_start,
        activation,
        inherited_inline_calls,
        origin,
    }
}

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, format};

    use miden_assembly::{Assembler, DefaultSourceManager};
    use miden_core::serde::Serializable;
    use miden_mast_package::debug_info::PackageDebugInfoBuilder;

    use super::*;

    #[test]
    fn inline_depth_index_respects_adjacent_nested_and_point_ranges() {
        use miden_mast_package::debug_info::{DebugLocIdx, DebugSourceInlineCall};
        let package = Assembler::new(Arc::new(DefaultSourceManager::default()))
            .assemble_program("program", "begin push.7 drop end")
            .unwrap();
        let info = package.debug_info().unwrap().unwrap();
        let mut node = info.nodes().iter().next().unwrap().clone();
        node.inline_calls = [(0, 10), (0, 5), (5, 10), (5, 5)]
            .into_iter()
            .map(|(op_idx, op_end)| DebugSourceInlineCall {
                op_idx,
                op_end,
                callee_idx: DebugFunctionIdx::from(0_u32),
                loc_idx: DebugLocIdx::from(0_u32),
            })
            .collect();
        let depths = inline_depths(&node);
        assert_eq!(depths[&0], (2, 0));
        assert_eq!(depths[&5], (2, 1));
        assert_eq!(depths[&10], (0, 0));
    }

    #[test]
    fn frame_index_handles_many_sources_and_functions_sharing_an_execution_node() {
        let package = Assembler::new(Arc::new(DefaultSourceManager::default()))
            .assemble_program("program", "begin push.7 drop end")
            .unwrap();
        let info = package.debug_info().unwrap().unwrap();
        let template = info.functions()[0];
        let node = info[template.source_node.into_option().unwrap()].clone();
        let mut builder = PackageDebugInfoBuilder::from(Box::new(info));
        for position in 0..50_000 {
            let name = builder.add_string(format!("function_{position}"));
            let mut source = node.clone();
            for row in &mut source.asm_ops {
                row.context_name_idx = name;
            }
            let source = builder.add_node(source).unwrap();
            let mut function = template;
            function.source_node = Some(source).into();
            function.name_idx = name;
            function.linkage_name_idx = Some(name).into();
            builder.add_function(function);
        }
        let info = Arc::<PackageDebugInfo>::from(builder.build());
        assert!(info.to_bytes().len() < 16 * 1024 * 1024);
        let index = FunctionIndex::new(info.clone(), package.mast_forest().clone());
        assert_eq!(index.entry_inline_counts.len(), 50_001);
        assert_eq!(index.ranges[&node.exec_node].len(), 50_001);
        for position in [1, 25_000, 50_000] {
            let function = DebugFunctionIdx::from(position);
            let source = info[function].source_node.into_option().unwrap();
            assert_eq!(index.source_function(source), Some(function));
            assert_eq!(index.entry_function(source), Some(function));
        }
    }
}
