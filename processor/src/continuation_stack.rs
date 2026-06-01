use alloc::vec::Vec;

use miden_core::{mast::MastNodeId, program::Program};
use miden_mast_package::debug_info::DebugSourceMastNodeId;

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
    EnterForest(F),
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

            EnterForest(_) => false,
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
    source_nodes: Option<Vec<Option<DebugSourceMastNodeId>>>,
}

impl<F> Default for ContinuationStack<F> {
    fn default() -> Self {
        Self { stack: Vec::new(), source_nodes: None }
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

        Self { stack, source_nodes: None }
    }

    pub(crate) fn new_with_source_node(
        program: &Program,
        source_node: DebugSourceMastNodeId,
    ) -> Self {
        let mut stack = Vec::with_capacity(CONTINUATION_STACK_SIZE_HINT);
        stack.push(Continuation::StartNode(program.entrypoint()));

        let mut source_nodes = Vec::with_capacity(CONTINUATION_STACK_SIZE_HINT);
        source_nodes.push(Some(source_node));

        Self { stack, source_nodes: Some(source_nodes) }
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Pushes a continuation onto the continuation stack.
    pub fn push_continuation(&mut self, continuation: Continuation<F>) {
        self.stack.push(continuation);
        self.push_source_node(None);
    }

    /// Pushes a continuation to enter the given MAST forest on the continuation stack.
    ///
    /// # Arguments
    /// * `forest` - The MAST forest to enter
    pub fn push_enter_forest(&mut self, forest: F) {
        self.stack.push(Continuation::EnterForest(forest));
        self.push_source_node(None);
    }

    /// Pushes a join finish continuation onto the stack.
    pub fn push_finish_join(&mut self, node_id: MastNodeId) {
        self.stack.push(Continuation::FinishJoin(node_id));
        self.push_source_node(None);
    }

    pub(crate) fn push_finish_join_with_source(
        &mut self,
        node_id: MastNodeId,
        source_node: Option<DebugSourceMastNodeId>,
    ) {
        self.stack.push(Continuation::FinishJoin(node_id));
        self.push_source_node(source_node);
    }

    /// Pushes a split finish continuation onto the stack.
    pub fn push_finish_split(&mut self, node_id: MastNodeId) {
        self.stack.push(Continuation::FinishSplit(node_id));
        self.push_source_node(None);
    }

    pub(crate) fn push_finish_split_with_source(
        &mut self,
        node_id: MastNodeId,
        source_node: Option<DebugSourceMastNodeId>,
    ) {
        self.stack.push(Continuation::FinishSplit(node_id));
        self.push_source_node(source_node);
    }

    /// Pushes a loop finish continuation onto the stack.
    pub fn push_finish_loop(&mut self, node_id: MastNodeId) {
        self.stack.push(Continuation::FinishLoop(node_id));
        self.push_source_node(None);
    }

    pub(crate) fn push_finish_loop_with_source(
        &mut self,
        node_id: MastNodeId,
        source_node: Option<DebugSourceMastNodeId>,
    ) {
        self.stack.push(Continuation::FinishLoop(node_id));
        self.push_source_node(source_node);
    }

    /// Pushes a call finish continuation onto the stack.
    pub fn push_finish_call(&mut self, node_id: MastNodeId) {
        self.stack.push(Continuation::FinishCall(node_id));
        self.push_source_node(None);
    }

    pub(crate) fn push_finish_call_with_source(
        &mut self,
        node_id: MastNodeId,
        source_node: Option<DebugSourceMastNodeId>,
    ) {
        self.stack.push(Continuation::FinishCall(node_id));
        self.push_source_node(source_node);
    }

    /// Pushes a dyn finish continuation onto the stack.
    pub fn push_finish_dyn(&mut self, node_id: MastNodeId) {
        self.stack.push(Continuation::FinishDyn(node_id));
        self.push_source_node(None);
    }

    pub(crate) fn push_finish_dyn_with_source(
        &mut self,
        node_id: MastNodeId,
        source_node: Option<DebugSourceMastNodeId>,
    ) {
        self.stack.push(Continuation::FinishDyn(node_id));
        self.push_source_node(source_node);
    }

    /// Pushes a continuation to start processing the given node.
    ///
    /// # Arguments
    /// * `node_id` - The ID of the node to process
    pub fn push_start_node(&mut self, node_id: MastNodeId) {
        self.stack.push(Continuation::StartNode(node_id));
        self.push_source_node(None);
    }

    pub(crate) fn push_start_node_with_source(
        &mut self,
        node_id: MastNodeId,
        source_node: Option<DebugSourceMastNodeId>,
    ) {
        self.stack.push(Continuation::StartNode(node_id));
        self.push_source_node(source_node);
    }

    /// Pops the next continuation from the continuation stack, and returns it along with its
    /// associated MAST forest.
    pub fn pop_continuation(&mut self) -> Option<Continuation<F>> {
        let continuation = self.stack.pop()?;
        if let Some(source_nodes) = &mut self.source_nodes {
            source_nodes.pop();
        }
        Some(continuation)
    }

    pub(crate) fn pop_continuation_with_source(
        &mut self,
    ) -> Option<(Continuation<F>, Option<DebugSourceMastNodeId>)> {
        let continuation = self.stack.pop()?;
        let source_node = self.source_nodes.as_mut().and_then(Vec::pop).flatten();
        Some((continuation, source_node))
    }

    /// Consumes this stack and returns its continuations in bottom-to-top order (i.e. the order in
    /// which they were originally pushed).
    pub fn into_inner(self) -> Vec<Continuation<F>> {
        self.stack
    }

    fn push_source_node(&mut self, source_node: Option<DebugSourceMastNodeId>) {
        if let Some(source_nodes) = &mut self.source_nodes {
            source_nodes.push(source_node);
        }
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
        stack.push_continuation(Continuation::EnterForest(Arc::new(MastForest::new())));

        let result: Vec<_> = stack.iter_continuations_for_next_clock().collect();
        // Should return: EnterForest (non-incrementing), then StartNode (first incrementing)
        assert_eq!(result.len(), 2);
        assert!(matches!(result[0], Continuation::EnterForest(_)));
        assert!(matches!(result[1], Continuation::StartNode(_)));
    }

    #[test]
    fn get_next_clock_cycle_increment_multiple_enter_forest_after_incrementing() {
        let mut stack: ContinuationStack<Arc<MastForest>> = ContinuationStack::default();
        // Push an incrementing continuation first (bottom of stack)
        stack.push_continuation(Continuation::StartNode(MastNodeId::new_unchecked(0)));
        // Push two non-incrementing continuations on top
        stack.push_continuation(Continuation::EnterForest(Arc::new(MastForest::new())));
        stack.push_continuation(Continuation::EnterForest(Arc::new(MastForest::new())));

        let result: Vec<_> = stack.iter_continuations_for_next_clock().collect();
        // Should return: EnterForest, EnterForest, StartNode
        assert_eq!(result.len(), 3);
        assert!(matches!(result[0], Continuation::EnterForest(_)));
        assert!(matches!(result[1], Continuation::EnterForest(_)));
        assert!(matches!(result[2], Continuation::StartNode(_)));
    }
}
