use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};

use miden_core::{
    Word,
    mast::{MastForest, MastNodeExt, MastNodeId},
};
use miden_mast_package::debug_info::{
    DebugFunctionIdx, DebugFunctionInfo, DebugSourceNode, DebugSourceNodeId, DebugStringIdx,
    PackageDebugInfo,
};

use crate::{Continuation, ResumeContext};

/// Evidence used to recover a source-level frame. Inferred frames are best-effort and may omit
/// optimized callers; consumers must distinguish them from frames identified by source identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DebugFrameOrigin {
    /// A unique function references the selected source occurrence and its executable root.
    Source,
    /// A retained operation range matches a function's assembly-operation metadata.
    InferredRange,
    /// The current assembly context uniquely names a function.
    InferredContext,
    /// Only the executable root identifies the function; source identity is unavailable.
    InferredRoot,
}

/// A recovered invocation of a debug function, without additional serialized frame metadata.
#[derive(Clone, Debug)]
pub struct DebugCallFrame {
    debug_info: Arc<PackageDebugInfo>,
    function_idx: DebugFunctionIdx,
    source_node_id: DebugSourceNodeId,
    range_start: u32,
    continuation_depth: usize,
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
            && self.continuation_depth == other.continuation_depth
    }
}

#[derive(Clone)]
struct FunctionRange {
    function: DebugFunctionIdx,
    start: u32,
    end: u32,
    inherited_inline_calls: usize,
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

struct FunctionIndex {
    info: Arc<PackageDebugInfo>,
    forest: Arc<MastForest>,
    sources: BTreeMap<DebugSourceNodeId, Vec<DebugFunctionIdx>>,
    names: BTreeMap<Arc<str>, Vec<DebugFunctionIdx>>,
    roots: BTreeMap<Word, Vec<DebugFunctionIdx>>,
    ranges: BTreeMap<MastNodeId, Vec<FunctionRange>>,
    entry_inline_counts: BTreeMap<DebugFunctionIdx, usize>,
}

impl FunctionIndex {
    fn new(info: Arc<PackageDebugInfo>, forest: Arc<MastForest>) -> Self {
        let mut index = Self {
            info,
            forest,
            sources: BTreeMap::new(),
            names: BTreeMap::new(),
            roots: BTreeMap::new(),
            ranges: BTreeMap::new(),
            entry_inline_counts: BTreeMap::new(),
        };
        let mut signatures = BTreeMap::<Signature, Vec<DebugFunctionIdx>>::new();
        for (position, function) in index.info.functions().iter().enumerate() {
            let function_idx = DebugFunctionIdx::from(position as u32);
            if let Some(source) = function.source_node.into_option() {
                index.sources.entry(source).or_default().push(function_idx);
            }
            index.roots.entry(function.mast_root).or_default().push(function_idx);
            for name_idx in [Some(function.name_idx), function.linkage_name_idx.into_option()]
                .into_iter()
                .flatten()
            {
                if let Some(name) = index.info.get_string(name_idx) {
                    let names = index.names.entry(name).or_default();
                    if !names.contains(&function_idx) {
                        names.push(function_idx);
                    }
                }
            }
            let Some(root) = index.forest.find_procedure_root(function.mast_root) else {
                continue;
            };
            let canonical =
                index.info.nodes().iter().filter(|node| node.exec_node == root).max_by_key(
                    |node| {
                        (
                            node.asm_ops.iter().any(|row| {
                                row.context_name_idx == function.name_idx
                                    || Some(row.context_name_idx)
                                        == function.linkage_name_idx.into_option()
                            }),
                            node.asm_ops.len(),
                            core::cmp::Reverse(node.inline_calls.len()),
                        )
                    },
                );
            if let Some(node) = canonical {
                index.entry_inline_counts.insert(
                    function_idx,
                    node.inline_calls.iter().filter(|row| row.op_idx == node.op_start).count(),
                );
                if !node.asm_ops.is_empty() {
                    signatures.entry(signature(node)).or_default().push(function_idx);
                }
            }
        }
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
                inherited_inline_calls: node
                    .inline_calls
                    .iter()
                    .filter(|row| row.op_idx == node.op_start)
                    .count()
                    .saturating_sub(index.entry_inline_counts.get(function).copied().unwrap_or(0)),
            };
            let ranges = index.ranges.entry(node.exec_node).or_default();
            if !ranges.iter().any(|other| {
                other.function == range.function
                    && other.start == range.start
                    && other.end == range.end
            }) {
                ranges.push(range);
            }
        }
        for ranges in index.ranges.values_mut() {
            ranges.sort_by_key(|range| (range.start, core::cmp::Reverse(range.end)));
        }
        index
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
            let root = index.roots.get(&forest[node.exec_node].digest()).and_then(|functions| {
                match functions.as_slice() {
                    [function] => Some(*function),
                    _ => None,
                }
            });
            if let Some(function) = exact.or(root) {
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
                    position,
                    inherited,
                    if exact.is_some() {
                        DebugFrameOrigin::Source
                    } else {
                        DebugFrameOrigin::InferredRoot
                    },
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
                        position,
                        inherited + range.inherited_inline_calls,
                        DebugFrameOrigin::InferredRange,
                    ));
                }
            }
            if let Some(function) = index.context_function(node, operation)
                && !frames.last().is_some_and(|frame| {
                    frame.function_idx == function && Arc::ptr_eq(&frame.debug_info, info)
                })
            {
                let own_inline = index.entry_inline_counts.get(&function).copied().unwrap_or(0);
                let inherited = inherited
                    + node
                        .inline_calls
                        .iter()
                        .filter(|row| row.op_idx == operation)
                        .count()
                        .saturating_sub(own_inline);
                frames.push(frame(
                    info,
                    function,
                    *source,
                    node.op_start,
                    position,
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
    continuation_depth: usize,
    inherited_inline_calls: usize,
    origin: DebugFrameOrigin,
) -> DebugCallFrame {
    DebugCallFrame {
        debug_info: info.clone(),
        function_idx,
        source_node_id,
        range_start,
        continuation_depth,
        inherited_inline_calls,
        origin,
    }
}
