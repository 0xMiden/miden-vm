use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

use miden_core::{
    mast::{MastForestId, MastNodeId},
    program::Program,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};
use miden_mast_package::debug_info::{DebugSourceInlineCall, DebugSourceNodeId, PackageDebugInfo};

/// A hint for the initial size of the continuation stack.
const CONTINUATION_STACK_SIZE_HINT: usize = 64;

#[derive(Clone, Debug)]
pub(crate) struct DebugActivationId {
    execution: Arc<AtomicU64>,
    generation: u64,
}

impl PartialEq for DebugActivationId {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.execution, &other.execution) && self.generation == other.generation
    }
}

impl Eq for DebugActivationId {}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DebugActivations {
    active: DebugActivationId,
    pending: Vec<u64>,
}

impl DebugActivations {
    fn new(count: usize) -> Self {
        let mut activations = Self {
            active: DebugActivationId {
                execution: Arc::new(AtomicU64::new(1)),
                generation: 0,
            },
            pending: Vec::with_capacity(count),
        };
        for _ in 0..count {
            let generation = activations.next_generation();
            activations.pending.push(generation);
        }
        activations
    }

    fn next_generation(&self) -> u64 {
        self.active
            .execution
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |generation| {
                generation.checked_add(1)
            })
            .expect("debug activation generation exhausted")
    }

    fn activation_at(&self, position: usize) -> Option<DebugActivationId> {
        Some(DebugActivationId {
            execution: self.active.execution.clone(),
            generation: *self.pending.get(position)?,
        })
    }
}

/// Package-owned source context whose inline-call rows remain active across a dynamic target.
#[derive(Debug, Clone)]
pub struct SourceInlineCallContext {
    package_debug_info: Arc<PackageDebugInfo>,
    source_node_id: DebugSourceNodeId,
    op_idx: u32,
}

impl SourceInlineCallContext {
    pub(crate) fn new(
        package_debug_info: Arc<PackageDebugInfo>,
        source_node_id: DebugSourceNodeId,
        op_idx: u32,
    ) -> Self {
        Self {
            package_debug_info,
            source_node_id,
            op_idx,
        }
    }

    pub(crate) fn for_source_boundary(
        package_debug_info: Arc<PackageDebugInfo>,
        source_node_id: Option<DebugSourceNodeId>,
    ) -> Option<Self> {
        let source_node_id = source_node_id?;
        let op_idx = package_debug_info.source_node(source_node_id)?.op_start;
        package_debug_info.inline_calls_for_operation(source_node_id, op_idx).next()?;
        Some(Self::new(package_debug_info, source_node_id, op_idx))
    }

    /// Returns the package debug information which owns this source occurrence.
    pub fn debug_info(&self) -> &Arc<PackageDebugInfo> {
        &self.package_debug_info
    }

    /// Returns the source occurrence whose boundary inline rows form this context.
    pub fn source_node_id(&self) -> DebugSourceNodeId {
        self.source_node_id
    }

    /// Returns the inline calls inherited at this source boundary.
    pub fn inline_calls(&self) -> impl Iterator<Item = &DebugSourceInlineCall> {
        self.package_debug_info
            .inline_calls_for_operation(self.source_node_id, self.op_idx)
    }
}

// CONTINUATION
// ================================================================================================

/// Represents a unit of work in the continuation stack.
///
/// This enum defines the different types of continuations that can be performed on MAST nodes
/// during program execution.
///
/// The type parameter `F` is the representation of a MAST forest carried by the
/// [`Continuation::EnterForest`] variant. For live execution this is `Arc<MastForest>`; for the
/// snapshotted continuation stack inside a trace fragment it is a `usize` index into the
/// `mast_forest_store` of the trace generation context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Continuation<F> {
    /// Start processing a node in the MAST forest.
    StartNode(MastNodeId),
    /// Process the finish phase of a Join node.
    FinishJoin(MastNodeId),
    /// Process the finish phase of a Split node.
    FinishSplit(MastNodeId),
    /// Process the finish phase of a Loop node.
    ///
    /// Reached after the loop body has finished executing. Inspects the condition the body left on
    /// top of the stack and either fires REPEAT (re-enter the body) or END (exit the loop). Loop
    /// bodies are entered unconditionally — a `while.true` source construct is desugared into a
    /// SPLIT that wraps the LOOP, so the LOOP itself sees a do-while body.
    FinishLoop(MastNodeId),
    /// Process the finish phase of a Call node.
    FinishCall(MastNodeId),
    /// Process the finish phase of a Dyn node.
    FinishDyn(MastNodeId),
    /// Resume execution at the specified operation of the specified batch in the given basic block
    /// node.
    ResumeBasicBlock {
        node_id: MastNodeId,
        batch_index: usize,
        op_idx_in_batch: usize,
    },
    /// Resume execution at the RESPAN operation before the specific batch within a basic block
    /// node.
    Respan { node_id: MastNodeId, batch_index: usize },
    /// Process the finish phase of a basic block node.
    ///
    /// This corresponds to incrementing the clock to account for the inserted END operation.
    FinishBasicBlock(MastNodeId),
    /// Enter a new MAST forest, where all subsequent `MastNodeId`s will be relative to this forest.
    ///
    /// When we encounter an `ExternalNode`, we enter the corresponding MAST forest directly, and
    /// push an `EnterForest` continuation to restore the previous forest when done.
    EnterForest {
        forest: F,
        package_debug_info: Option<Arc<PackageDebugInfo>>,
        /// Inline-context stack depth to restore when returning to this forest.
        inline_context_depth: usize,
    },
}

impl<F> Continuation<F> {
    /// Returns true if executing this continuation increments the processor clock, and false
    /// otherwise.
    pub fn increments_clk(&self) -> bool {
        use Continuation::*;

        // Note: we prefer naming all the variants over using a wildcard arm to ensure that if new
        // variants are added in the future, we consciously decide whether they should increment the
        // clock or not.
        match self {
            StartNode(_)
            | FinishJoin(_)
            | FinishSplit(_)
            | FinishLoop(_)
            | FinishCall(_)
            | FinishDyn(_)
            | ResumeBasicBlock {
                node_id: _,
                batch_index: _,
                op_idx_in_batch: _,
            }
            | Respan { node_id: _, batch_index: _ }
            | FinishBasicBlock(_) => true,

            EnterForest { .. } => false,
        }
    }

    pub fn exec_node(&self) -> Option<MastNodeId> {
        match self {
            Self::StartNode(node_id)
            | Self::FinishJoin(node_id)
            | Self::FinishSplit(node_id)
            | Self::FinishLoop(node_id)
            | Self::FinishCall(node_id)
            | Self::FinishDyn(node_id)
            | Self::ResumeBasicBlock { node_id, .. }
            | Self::Respan { node_id, .. }
            | Self::FinishBasicBlock(node_id) => Some(*node_id),
            Self::EnterForest { .. } => None,
        }
    }
}

// CONTINUATION STACK
// ================================================================================================

/// [ContinuationStack] reifies the call stack used by the processor when executing a program made
/// up of possibly multiple MAST forests.
///
/// This allows the processor to execute a program iteratively in a loop rather than recursively
/// traversing the nodes. It also allows the processor to pass the state of execution to another
/// processor for further processing, which is useful for parallel execution of MAST forests.
///
/// Note: the binary wire format for this type is deliberately lossy (`package_debug_info` and
/// `source_node_ids` are not serialized), so the exact-equality round-trip test generated by
/// `serde_test` does not apply; `continuation_stack_mast_forest_id_round_trip_omits_debug_metadata`
/// covers the lossy round trip instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuationStack<F> {
    stack: Vec<Continuation<F>>,
    source_node_ids: Option<Vec<Option<DebugSourceNodeId>>>,
    debug_activations: Option<DebugActivations>,
}

impl<F> Default for ContinuationStack<F> {
    fn default() -> Self {
        Self {
            stack: Vec::new(),
            source_node_ids: None,
            debug_activations: None,
        }
    }
}

impl<F> ContinuationStack<F> {
    pub(crate) fn debug_activation_at(&self, position: usize) -> Option<DebugActivationId> {
        self.debug_activations.as_ref()?.activation_at(position)
    }

    pub(crate) fn iter_with_source_node_ids(
        &self,
    ) -> impl DoubleEndedIterator<Item = (&Continuation<F>, Option<DebugSourceNodeId>)> {
        self.stack.iter().enumerate().map(|(index, continuation)| {
            let source_node_id = self
                .source_node_ids
                .as_deref()
                .and_then(|ids| ids.get(index).copied())
                .flatten();
            (continuation, source_node_id)
        })
    }

    /// Creates a new continuation stack for a program.
    ///
    /// # Arguments
    /// * `program` - The program whose execution will be managed by this continuation stack
    pub fn new(program: &Program) -> Self {
        let mut stack = Vec::with_capacity(CONTINUATION_STACK_SIZE_HINT);
        stack.push(Continuation::StartNode(program.entrypoint()));

        Self {
            stack,
            source_node_ids: None,
            debug_activations: None,
        }
    }

    pub(crate) fn new_with_source_node_id(
        program: &Program,
        source_node_id: DebugSourceNodeId,
    ) -> Self {
        Self::new_with_optional_source_node_id(program, Some(source_node_id))
    }

    pub(crate) fn new_with_optional_source_node_id(
        program: &Program,
        source_node_id: Option<DebugSourceNodeId>,
    ) -> Self {
        let mut stack = Vec::with_capacity(CONTINUATION_STACK_SIZE_HINT);
        stack.push(Continuation::StartNode(program.entrypoint()));

        let mut source_node_ids = Vec::with_capacity(CONTINUATION_STACK_SIZE_HINT);
        source_node_ids.push(source_node_id);

        Self {
            stack,
            source_node_ids: Some(source_node_ids),
            debug_activations: Some(DebugActivations::new(1)),
        }
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Pushes a continuation onto the continuation stack.
    pub fn push_continuation(&mut self, continuation: Continuation<F>) {
        self.stack.push(continuation);
        self.push_source_node_id(None);
    }

    pub(crate) fn push_with_source_node_id(
        &mut self,
        continuation: Continuation<F>,
        source_node_id: Option<DebugSourceNodeId>,
    ) {
        self.stack.push(continuation);
        self.push_source_node_id(source_node_id);
    }

    pub(crate) fn push_resumed_with_source_node_id(
        &mut self,
        continuation: Continuation<F>,
        source_node_id: Option<DebugSourceNodeId>,
    ) {
        self.stack.push(continuation);
        self.push_source_node_id_with_resumption(source_node_id, true);
    }

    /// Pushes a continuation to enter the given MAST forest on the continuation stack.
    ///
    /// # Arguments
    /// * `forest` - The MAST forest to enter
    pub fn push_enter_forest(&mut self, forest: F) {
        self.push_enter_forest_with_package_debug_info(forest, None, 0, None);
    }

    pub(crate) fn push_enter_forest_with_package_debug_info(
        &mut self,
        forest: F,
        package_debug_info: Option<Arc<PackageDebugInfo>>,
        inline_context_depth: usize,
        source_node_id: Option<DebugSourceNodeId>,
    ) {
        self.stack.push(Continuation::EnterForest {
            forest,
            package_debug_info,
            inline_context_depth,
        });
        self.push_source_node_id(source_node_id);
    }

    /// Pushes a join finish continuation onto the stack.
    pub fn push_finish_join(&mut self, node_id: MastNodeId) {
        self.stack.push(Continuation::FinishJoin(node_id));
        self.push_source_node_id(None);
    }

    /// Pushes a split finish continuation onto the stack.
    pub fn push_finish_split(&mut self, node_id: MastNodeId) {
        self.stack.push(Continuation::FinishSplit(node_id));
        self.push_source_node_id(None);
    }

    /// Pushes a loop finish continuation onto the stack.
    pub fn push_finish_loop(&mut self, node_id: MastNodeId) {
        self.stack.push(Continuation::FinishLoop(node_id));
        self.push_source_node_id(None);
    }

    /// Pushes a call finish continuation onto the stack.
    pub fn push_finish_call(&mut self, node_id: MastNodeId) {
        self.stack.push(Continuation::FinishCall(node_id));
        self.push_source_node_id(None);
    }

    /// Pushes a dyn finish continuation onto the stack.
    pub fn push_finish_dyn(&mut self, node_id: MastNodeId) {
        self.stack.push(Continuation::FinishDyn(node_id));
        self.push_source_node_id(None);
    }

    /// Pushes a continuation to start processing the given node.
    ///
    /// # Arguments
    /// * `node_id` - The ID of the node to process
    pub fn push_start_node(&mut self, node_id: MastNodeId) {
        self.stack.push(Continuation::StartNode(node_id));
        self.push_source_node_id(None);
    }

    /// Pops the next continuation from the continuation stack, and returns it along with its
    /// associated MAST forest.
    pub fn pop_continuation(&mut self) -> Option<Continuation<F>> {
        let continuation = self.stack.pop()?;
        self.pop_source_node_id();
        Some(continuation)
    }

    pub(crate) fn pop_continuation_with_source_node_id(
        &mut self,
    ) -> Option<(Continuation<F>, Option<DebugSourceNodeId>)> {
        let continuation = self.stack.pop()?;
        let source_node_id = self.pop_source_node_id();
        Some((continuation, source_node_id))
    }

    /// Consumes this stack and returns its continuations in bottom-to-top order (i.e. the order in
    /// which they were originally pushed).
    pub fn into_inner(self) -> Vec<Continuation<F>> {
        self.stack
    }

    fn push_source_node_id(&mut self, source_node_id: Option<DebugSourceNodeId>) {
        self.push_source_node_id_with_resumption(source_node_id, false);
    }

    fn push_source_node_id_with_resumption(
        &mut self,
        source_node_id: Option<DebugSourceNodeId>,
        resumed: bool,
    ) {
        if let Some(source_node_ids) = &mut self.source_node_ids {
            source_node_ids.push(source_node_id);
            if let Some(activations) = &mut self.debug_activations {
                let generation =
                    if !resumed && matches!(self.stack.last(), Some(Continuation::StartNode(_))) {
                        activations.next_generation()
                    } else {
                        activations.active.generation
                    };
                activations.pending.push(generation);
            }
        }
    }

    fn pop_source_node_id(&mut self) -> Option<DebugSourceNodeId> {
        let source_node_ids = self.source_node_ids.as_mut()?;
        if let Some(activations) = &mut self.debug_activations {
            activations.active.generation = activations.pending.pop().unwrap();
        }
        source_node_ids.pop().flatten()
    }

    pub(crate) fn start_tracking_source_nodes(
        &mut self,
        next_source_node_id: Option<DebugSourceNodeId>,
    ) {
        let mut source_node_ids = Vec::with_capacity(self.stack.len());
        source_node_ids.resize(self.stack.len(), None);
        if let Some(source_node_id) = source_node_ids.last_mut() {
            *source_node_id = next_source_node_id;
        }
        self.source_node_ids = Some(source_node_ids);
        self.debug_activations = Some(DebugActivations::new(self.stack.len()));
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of continuations on the stack.
    pub fn len(&self) -> usize {
        self.stack.len()
    }

    /// Peeks at the next continuation to execute without removing it.
    ///
    /// Note that more than one continuation may execute in the same clock cycle. To get all
    /// continuations that will execute in the next clock cycle, use
    /// [`Self::iter_continuations_for_next_clock`].
    pub fn peek_continuation(&self) -> Option<&Continuation<F>> {
        self.stack.last()
    }

    pub(crate) fn peek_continuation_with_source_node_id(
        &self,
    ) -> Option<(&Continuation<F>, Option<DebugSourceNodeId>)> {
        let continuation = self.stack.last()?;
        let source_node_id = self
            .source_node_ids
            .as_ref()
            .and_then(|source_node_ids| source_node_ids.last().copied().flatten());
        Some((continuation, source_node_id))
    }

    pub(crate) fn tracks_source_nodes(&self) -> bool {
        self.source_node_ids.is_some()
    }

    /// Returns an iterator over the continuations on the stack that will execute in the next clock
    /// cycle.
    ///
    /// This includes all coming continuations up to and including the first continuation that
    /// increments the clock.
    ///
    /// Note: for this iterator to function correctly, it must be the case that executing a
    /// continuation that doesn't increment the clock *does not* push new continuations on the
    /// stack. This is currently the case, and is a reasonable invariant to maintain, as
    /// continuations that don't increment the clock can be expected to be simple (e.g. enter a new
    /// mast forest).
    pub fn iter_continuations_for_next_clock(&self) -> impl Iterator<Item = &Continuation<F>> {
        let mut found_incrementing_cont = false;

        self.stack.iter().rev().take_while(move |continuation| {
            if found_incrementing_cont {
                // We have already found the first incrementing continuation, stop here.
                false
            } else if continuation.increments_clk() {
                // This is the first incrementing continuation we have found.
                found_incrementing_cont = true;
                true
            } else {
                // This continuation does not increment the clock, continue.
                true
            }
        })
    }

    /// Same as [`Self::iter_continuations_for_next_clock`], but provides the set of source node
    /// ids for each continuation.
    pub fn iter_continuations_for_next_clock_with_source_node_ids(
        &self,
    ) -> impl Iterator<Item = (&Continuation<F>, Option<DebugSourceNodeId>)> {
        let mut stack_index = self.stack.len().saturating_sub(1);

        self.iter_continuations_for_next_clock().map(move |cont| {
            let source_node_id = self
                .source_node_ids
                .as_deref()
                .and_then(|ids| ids.get(stack_index).copied())
                .flatten();
            stack_index = stack_index.saturating_sub(1);
            (cont, source_node_id)
        })
    }
}

impl ContinuationStack<MastForestId> {
    pub(crate) fn iter_enter_forest_ids(&self) -> impl Iterator<Item = MastForestId> + '_ {
        self.stack.iter().filter_map(|continuation| match continuation {
            Continuation::EnterForest { forest, .. } => Some(*forest),
            _ => None,
        })
    }
}

// SERIALIZATION
// ================================================================================================

const TAG_START_NODE: u8 = 0;
const TAG_FINISH_JOIN: u8 = 1;
const TAG_FINISH_SPLIT: u8 = 2;
const TAG_FINISH_LOOP: u8 = 3;
const TAG_FINISH_CALL: u8 = 4;
const TAG_FINISH_DYN: u8 = 5;
const TAG_RESUME_BASIC_BLOCK: u8 = 6;
const TAG_RESPAN: u8 = 7;
const TAG_FINISH_BASIC_BLOCK: u8 = 8;
const TAG_ENTER_FOREST: u8 = 9;

// NOTE: `package_debug_info` is deliberately *not* serialized: it is reconstructable from the
// package a witness was produced from and would bloat the wire with data irrelevant to proving.
// Round-tripping a `Continuation` (or any struct containing one, such as `ContinuationStack`)
// therefore does not restore debug info exactly: deserialized continuations always carry
// `package_debug_info: None`.
impl Serializable for Continuation<MastForestId> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Self::StartNode(node_id) => {
                TAG_START_NODE.write_into(target);
                node_id.write_into(target);
            },
            Self::FinishJoin(node_id) => {
                TAG_FINISH_JOIN.write_into(target);
                node_id.write_into(target);
            },
            Self::FinishSplit(node_id) => {
                TAG_FINISH_SPLIT.write_into(target);
                node_id.write_into(target);
            },
            Self::FinishLoop(node_id) => {
                TAG_FINISH_LOOP.write_into(target);
                node_id.write_into(target);
            },
            Self::FinishCall(node_id) => {
                TAG_FINISH_CALL.write_into(target);
                node_id.write_into(target);
            },
            Self::FinishDyn(node_id) => {
                TAG_FINISH_DYN.write_into(target);
                node_id.write_into(target);
            },
            Self::ResumeBasicBlock { node_id, batch_index, op_idx_in_batch } => {
                TAG_RESUME_BASIC_BLOCK.write_into(target);
                node_id.write_into(target);
                batch_index.write_into(target);
                op_idx_in_batch.write_into(target);
            },
            Self::Respan { node_id, batch_index } => {
                TAG_RESPAN.write_into(target);
                node_id.write_into(target);
                batch_index.write_into(target);
            },
            Self::FinishBasicBlock(node_id) => {
                TAG_FINISH_BASIC_BLOCK.write_into(target);
                node_id.write_into(target);
            },
            Self::EnterForest {
                forest,
                package_debug_info: _,
                inline_context_depth,
            } => {
                TAG_ENTER_FOREST.write_into(target);
                forest.write_into(target);
                inline_context_depth.write_into(target);
            },
        }
    }
}

impl Deserializable for Continuation<MastForestId> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match u8::read_from(source)? {
            TAG_START_NODE => Ok(Self::StartNode(MastNodeId::read_from(source)?)),
            TAG_FINISH_JOIN => Ok(Self::FinishJoin(MastNodeId::read_from(source)?)),
            TAG_FINISH_SPLIT => Ok(Self::FinishSplit(MastNodeId::read_from(source)?)),
            TAG_FINISH_LOOP => Ok(Self::FinishLoop(MastNodeId::read_from(source)?)),
            TAG_FINISH_CALL => Ok(Self::FinishCall(MastNodeId::read_from(source)?)),
            TAG_FINISH_DYN => Ok(Self::FinishDyn(MastNodeId::read_from(source)?)),
            TAG_RESUME_BASIC_BLOCK => Ok(Self::ResumeBasicBlock {
                node_id: MastNodeId::read_from(source)?,
                batch_index: usize::read_from(source)?,
                op_idx_in_batch: usize::read_from(source)?,
            }),
            TAG_RESPAN => Ok(Self::Respan {
                node_id: MastNodeId::read_from(source)?,
                batch_index: usize::read_from(source)?,
            }),
            TAG_FINISH_BASIC_BLOCK => Ok(Self::FinishBasicBlock(MastNodeId::read_from(source)?)),
            TAG_ENTER_FOREST => Ok(Self::EnterForest {
                forest: MastForestId::read_from(source)?,
                package_debug_info: None,
                inline_context_depth: usize::read_from(source)?,
            }),
            tag => {
                Err(DeserializationError::InvalidValue(format!("invalid continuation tag {tag}")))
            },
        }
    }

    fn min_serialized_size() -> usize {
        u8::min_serialized_size() + MastNodeId::min_serialized_size()
    }
}

// `source_node_ids` is deliberately *not* serialized: those indices point into a package's
// `PackageDebugInfo`, which is itself absent from the wire (see the note above), so they would be
// dangling references on the deserialized side. A restored stack simply does not track source
// nodes, matching a non-debug-aware execution, which is all proving requires.
impl Serializable for ContinuationStack<MastForestId> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.stack.write_into(target);
    }
}

impl Deserializable for ContinuationStack<MastForestId> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let stack = Vec::<Continuation<MastForestId>>::read_from(source)?;
        Ok(Self {
            stack,
            source_node_ids: None,
            debug_activations: None,
        })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use miden_core::mast::MastForest;
    use miden_mast_package::debug_info::{
        DebugFunctionIdx, DebugLocIdx, DebugSourceInlineCall, DebugSourceNode,
        PackageDebugInfoBuilder,
    };

    use super::*;

    #[test]
    fn debug_activation_identity_survives_resumption_but_not_reentry() {
        let node_id = MastNodeId::from(1);
        let source_id = Some(DebugSourceNodeId::from(2));
        let mut stack: ContinuationStack<Arc<MastForest>> = ContinuationStack::default();
        stack.push_start_node(node_id);
        stack.start_tracking_source_nodes(source_id);
        let initial = stack.debug_activation_at(0).unwrap();

        let (continuation, source_id) = stack.pop_continuation_with_source_node_id().unwrap();
        stack.push_resumed_with_source_node_id(continuation, source_id);
        assert_eq!(stack.debug_activation_at(0).unwrap(), initial);

        stack.pop_continuation_with_source_node_id().unwrap();
        stack.push_with_source_node_id(Continuation::FinishJoin(node_id), source_id);
        assert_eq!(stack.debug_activation_at(0).unwrap(), initial);

        stack.pop_continuation_with_source_node_id().unwrap();
        stack.push_with_source_node_id(Continuation::StartNode(node_id), source_id);
        assert_ne!(stack.debug_activation_at(0).unwrap(), initial);
    }

    #[test]
    fn debug_activation_generations_are_unique_across_cloned_stacks() {
        let node_id = MastNodeId::from(1);
        let mut first: ContinuationStack<Arc<MastForest>> = ContinuationStack::default();
        first.push_start_node(node_id);
        first.start_tracking_source_nodes(Some(DebugSourceNodeId::from(2)));
        let mut second = first.clone();
        assert_eq!(first.debug_activation_at(0), second.debug_activation_at(0));

        first.pop_continuation().unwrap();
        second.pop_continuation().unwrap();
        first.push_start_node(node_id);
        second.push_start_node(node_id);
        assert_ne!(first.debug_activation_at(0), second.debug_activation_at(0));
    }

    #[test]
    fn source_unaware_continuations_do_not_track_activations() {
        let mut stack: ContinuationStack<Arc<MastForest>> = ContinuationStack::default();
        stack.push_start_node(MastNodeId::from(1));
        assert!(stack.debug_activations.is_none());
        assert!(stack.debug_activation_at(0).is_none());
        stack.pop_continuation().unwrap();
        assert!(stack.debug_activations.is_none());
    }

    #[test]
    fn get_next_clock_cycle_increment_empty_stack() {
        let stack: ContinuationStack<Arc<MastForest>> = ContinuationStack::default();
        assert!(stack.iter_continuations_for_next_clock().next().is_none());
    }

    #[test]
    fn get_next_clock_cycle_increment_ends_with_incrementing() {
        let mut stack: ContinuationStack<Arc<MastForest>> = ContinuationStack::default();
        // Push a continuation that increments the clock
        stack.push_continuation(Continuation::StartNode(MastNodeId::new_unchecked(0)));

        let result: Vec<_> = stack.iter_continuations_for_next_clock().collect();
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], Continuation::StartNode(_)));
    }

    #[test]
    fn get_next_clock_cycle_increment_enter_forest_after_incrementing() {
        let mut stack: ContinuationStack<Arc<MastForest>> = ContinuationStack::default();
        // Push an incrementing continuation first (bottom of stack)
        stack.push_continuation(Continuation::StartNode(MastNodeId::new_unchecked(0)));
        // Push a non-incrementing continuation on top
        stack.push_continuation(Continuation::EnterForest {
            forest: Arc::new(MastForest::new()),
            package_debug_info: None,
            inline_context_depth: 0,
        });

        let result: Vec<_> = stack.iter_continuations_for_next_clock().collect();
        // Should return: EnterForest (non-incrementing), then StartNode (first incrementing)
        assert_eq!(result.len(), 2);
        assert!(matches!(result[0], Continuation::EnterForest { .. }));
        assert!(matches!(result[1], Continuation::StartNode(_)));
    }

    #[test]
    fn get_next_clock_cycle_increment_multiple_enter_forest_after_incrementing() {
        let mut stack: ContinuationStack<Arc<MastForest>> = ContinuationStack::default();
        // Push an incrementing continuation first (bottom of stack)
        stack.push_continuation(Continuation::StartNode(MastNodeId::new_unchecked(0)));
        // Push two non-incrementing continuations on top
        stack.push_continuation(Continuation::EnterForest {
            forest: Arc::new(MastForest::new()),
            package_debug_info: None,
            inline_context_depth: 0,
        });
        stack.push_continuation(Continuation::EnterForest {
            forest: Arc::new(MastForest::new()),
            package_debug_info: None,
            inline_context_depth: 0,
        });

        let result: Vec<_> = stack.iter_continuations_for_next_clock().collect();
        // Should return: EnterForest, EnterForest, StartNode
        assert_eq!(result.len(), 3);
        assert!(matches!(result[0], Continuation::EnterForest { .. }));
        assert!(matches!(result[1], Continuation::EnterForest { .. }));
        assert!(matches!(result[2], Continuation::StartNode(_)));
    }

    #[test]
    fn inline_call_context_uses_the_source_boundary_index() {
        let mut builder = PackageDebugInfoBuilder::default();
        let source_node_id = builder
            .add_node(DebugSourceNode {
                exec_node: MastNodeId::new_unchecked(0),
                children: Vec::new(),
                op_start: 7,
                op_end: 7,
                asm_ops: Vec::new(),
                debug_vars: Vec::new(),
                inline_calls: vec![DebugSourceInlineCall {
                    op_idx: 7,
                    callee_idx: DebugFunctionIdx::from(0),
                    loc_idx: DebugLocIdx::from(0),
                }],
            })
            .unwrap();
        let debug_info = Arc::from(builder.build());

        let context =
            SourceInlineCallContext::for_source_boundary(debug_info, Some(source_node_id))
                .expect("boundary row should create inherited inline context");

        assert_eq!(context.inline_calls().map(|row| row.op_idx).collect::<Vec<_>>(), [7]);
    }

    #[test]
    fn continuation_stack_mast_forest_id_round_trip_omits_debug_metadata() {
        let mut stack: ContinuationStack<MastForestId> = ContinuationStack::default();
        stack.push_continuation(Continuation::StartNode(MastNodeId::from(1)));
        stack.push_continuation(Continuation::EnterForest {
            forest: MastForestId::from(2),
            package_debug_info: None,
            inline_context_depth: 0,
        });
        stack.push_continuation(Continuation::ResumeBasicBlock {
            node_id: MastNodeId::from(3),
            batch_index: 4,
            op_idx_in_batch: 5,
        });
        stack.start_tracking_source_nodes(None);
        stack.source_node_ids =
            Some(vec![Some(DebugSourceNodeId::from(10)), None, Some(DebugSourceNodeId::from(11))]);
        assert!(stack.debug_activations.is_some());

        let bytes = stack.to_bytes();
        let restored = ContinuationStack::<MastForestId>::read_from_bytes(&bytes).unwrap();

        assert_eq!(restored.stack.len(), 3);
        assert!(matches!(
            restored.stack[0],
            Continuation::StartNode(node_id) if node_id == MastNodeId::from(1)
        ));
        assert!(matches!(
            restored.stack[1],
            Continuation::EnterForest {
                forest,
                package_debug_info: None,
                inline_context_depth: 0,
            } if forest == MastForestId::from(2)
        ));
        assert!(matches!(
            restored.stack[2],
            Continuation::ResumeBasicBlock {
                node_id,
                batch_index: 4,
                op_idx_in_batch: 5,
            } if node_id == MastNodeId::from(3)
        ));
        // source_node_ids is not serialized: indices without their owning package debug info
        // would be dangling on the restored side.
        assert_eq!(restored.source_node_ids, None);
        assert!(restored.debug_activations.is_none());
    }
}
