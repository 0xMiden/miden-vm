use alloc::{sync::Arc, vec::Vec};

use miden_core::{
    mast::{MastForestId, MastNodeId},
    program::Program,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};
use miden_mast_package::debug_info::{DebugSourceNodeId, PackageDebugInfo};

/// A hint for the initial size of the continuation stack.
const CONTINUATION_STACK_SIZE_HINT: usize = 64;

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
#[derive(Debug, Clone)]
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

    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn exec_node(&self) -> Option<MastNodeId> {
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
#[derive(Debug, Clone)]
pub struct ContinuationStack<F> {
    stack: Vec<Continuation<F>>,
    source_node_ids: Option<Vec<Option<DebugSourceNodeId>>>,
}

impl<F> Default for ContinuationStack<F> {
    fn default() -> Self {
        Self { stack: Vec::new(), source_node_ids: None }
    }
}

impl<F> ContinuationStack<F> {
    /// Creates a new continuation stack for a program.
    ///
    /// # Arguments
    /// * `program` - The program whose execution will be managed by this continuation stack
    pub fn new(program: &Program) -> Self {
        let mut stack = Vec::with_capacity(CONTINUATION_STACK_SIZE_HINT);
        stack.push(Continuation::StartNode(program.entrypoint()));

        Self { stack, source_node_ids: None }
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

    /// Pushes a continuation to enter the given MAST forest on the continuation stack.
    ///
    /// # Arguments
    /// * `forest` - The MAST forest to enter
    pub fn push_enter_forest(&mut self, forest: F) {
        self.push_enter_forest_with_package_debug_info(forest, None);
    }

    pub(crate) fn push_enter_forest_with_package_debug_info(
        &mut self,
        forest: F,
        package_debug_info: Option<Arc<PackageDebugInfo>>,
    ) {
        self.stack.push(Continuation::EnterForest { forest, package_debug_info });
        self.push_source_node_id(None);
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
        if let Some(source_node_ids) = &mut self.source_node_ids {
            source_node_ids.pop();
        }
        Some(continuation)
    }

    pub(crate) fn pop_continuation_with_source_node_id(
        &mut self,
    ) -> Option<(Continuation<F>, Option<DebugSourceNodeId>)> {
        let continuation = self.stack.pop()?;
        let source_node_id = self.source_node_ids.as_mut().and_then(Vec::pop).flatten();
        Some((continuation, source_node_id))
    }

    /// Consumes this stack and returns its continuations in bottom-to-top order (i.e. the order in
    /// which they were originally pushed).
    pub fn into_inner(self) -> Vec<Continuation<F>> {
        self.stack
    }

    fn push_source_node_id(&mut self, source_node_id: Option<DebugSourceNodeId>) {
        if let Some(source_node_ids) = &mut self.source_node_ids {
            source_node_ids.push(source_node_id);
        }
    }

    #[cfg(any(test, feature = "testing"))]
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

impl Serializable for Continuation<MastForestId> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Self::StartNode(node_id) => {
                0u8.write_into(target);
                node_id.write_into(target);
            },
            Self::FinishJoin(node_id) => {
                1u8.write_into(target);
                node_id.write_into(target);
            },
            Self::FinishSplit(node_id) => {
                2u8.write_into(target);
                node_id.write_into(target);
            },
            Self::FinishLoop(node_id) => {
                3u8.write_into(target);
                node_id.write_into(target);
            },
            Self::FinishCall(node_id) => {
                4u8.write_into(target);
                node_id.write_into(target);
            },
            Self::FinishDyn(node_id) => {
                5u8.write_into(target);
                node_id.write_into(target);
            },
            Self::ResumeBasicBlock { node_id, batch_index, op_idx_in_batch } => {
                6u8.write_into(target);
                node_id.write_into(target);
                batch_index.write_into(target);
                op_idx_in_batch.write_into(target);
            },
            Self::Respan { node_id, batch_index } => {
                7u8.write_into(target);
                node_id.write_into(target);
                batch_index.write_into(target);
            },
            Self::FinishBasicBlock(node_id) => {
                8u8.write_into(target);
                node_id.write_into(target);
            },
            Self::EnterForest { forest, package_debug_info: _ } => {
                9u8.write_into(target);
                forest.write_into(target);
            },
        }
    }
}

impl Deserializable for Continuation<MastForestId> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match u8::read_from(source)? {
            0 => Ok(Self::StartNode(MastNodeId::read_from(source)?)),
            1 => Ok(Self::FinishJoin(MastNodeId::read_from(source)?)),
            2 => Ok(Self::FinishSplit(MastNodeId::read_from(source)?)),
            3 => Ok(Self::FinishLoop(MastNodeId::read_from(source)?)),
            4 => Ok(Self::FinishCall(MastNodeId::read_from(source)?)),
            5 => Ok(Self::FinishDyn(MastNodeId::read_from(source)?)),
            6 => Ok(Self::ResumeBasicBlock {
                node_id: MastNodeId::read_from(source)?,
                batch_index: usize::read_from(source)?,
                op_idx_in_batch: usize::read_from(source)?,
            }),
            7 => Ok(Self::Respan {
                node_id: MastNodeId::read_from(source)?,
                batch_index: usize::read_from(source)?,
            }),
            8 => Ok(Self::FinishBasicBlock(MastNodeId::read_from(source)?)),
            9 => Ok(Self::EnterForest {
                forest: MastForestId::read_from(source)?,
                package_debug_info: None,
            }),
            tag => {
                Err(DeserializationError::InvalidValue(format!("invalid continuation tag {tag}")))
            },
        }
    }
}

impl Serializable for ContinuationStack<MastForestId> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.stack.write_into(target);
        self.source_node_ids.write_into(target);
    }
}

impl Deserializable for ContinuationStack<MastForestId> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let stack = Vec::<Continuation<MastForestId>>::read_from(source)?;
        let source_node_ids = Option::<Vec<Option<DebugSourceNodeId>>>::read_from(source)?;
        if let Some(source_node_ids) = &source_node_ids
            && source_node_ids.len() != stack.len()
        {
            return Err(DeserializationError::InvalidValue(format!(
                "continuation source_node_ids length {} does not match stack length {}",
                source_node_ids.len(),
                stack.len()
            )));
        }
        Ok(Self { stack, source_node_ids })
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use miden_core::mast::MastForest;

    use super::*;

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
        });
        stack.push_continuation(Continuation::EnterForest {
            forest: Arc::new(MastForest::new()),
            package_debug_info: None,
        });

        let result: Vec<_> = stack.iter_continuations_for_next_clock().collect();
        // Should return: EnterForest, EnterForest, StartNode
        assert_eq!(result.len(), 3);
        assert!(matches!(result[0], Continuation::EnterForest { .. }));
        assert!(matches!(result[1], Continuation::EnterForest { .. }));
        assert!(matches!(result[2], Continuation::StartNode(_)));
    }

    #[test]
    fn continuation_stack_mast_forest_id_round_trip_omits_package_debug_info() {
        let mut stack: ContinuationStack<MastForestId> = ContinuationStack::default();
        stack.push_continuation(Continuation::StartNode(MastNodeId::from(1)));
        stack.push_continuation(Continuation::EnterForest {
            forest: MastForestId::from(2),
            package_debug_info: None,
        });
        stack.push_continuation(Continuation::ResumeBasicBlock {
            node_id: MastNodeId::from(3),
            batch_index: 4,
            op_idx_in_batch: 5,
        });
        stack.source_node_ids =
            Some(vec![Some(DebugSourceNodeId::from(10)), None, Some(DebugSourceNodeId::from(11))]);

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
        assert_eq!(
            restored.source_node_ids,
            Some(vec![Some(DebugSourceNodeId::from(10)), None, Some(DebugSourceNodeId::from(11)),])
        );
    }
}
