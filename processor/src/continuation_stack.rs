use alloc::{sync::Arc, vec::Vec};

use miden_core::{
    Program,
    mast::{MastForest, MastNodeId},
};

/// A hint for the initial size of the continuation stack.
const CONTINUATION_STACK_SIZE_HINT: usize = 64;

/// Represents a unit of work in the continuation stack.
///
/// This enum defines the different types of continuations that can be performed on MAST nodes
/// during program execution.
#[derive(Debug, Clone)]
pub enum Continuation {
    /// Start processing a node in the MAST forest.
    StartNode(MastNodeId),
    /// Process the finish phase of a Join node.
    FinishJoin(MastNodeId),
    /// Process the finish phase of a Split node.
    FinishSplit(MastNodeId),
    /// Process the finish phase of a Loop node.
    ///
    /// The `was_entered` field indicates whether the loop body was entered at least once. When
    /// `was_entered == false`, the loop condition was `ZERO` and the loop body was never executed.
    FinishLoop { node_id: MastNodeId, was_entered: bool },
    /// Process the finish phase of a Call node.
    FinishCall(MastNodeId),
    /// Process the finish phase of a Dyn node.
    FinishDyn(MastNodeId),
    /// Process the finish phase of an External node (execute after_exit decorators).
    FinishExternal(MastNodeId),
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
    /// This corresponds to incrementing the clock to account for the inserted END operation, and
    /// then executing `AfterExitDecoratorsBasicBlock`.
    FinishBasicBlock(MastNodeId),
    /// Enter a new MAST forest, where all subsequent `MastNodeId`s will be relative to this forest.
    ///
    /// When we encounter an `ExternalNode`, we enter the corresponding MAST forest directly, and
    /// push an `EnterForest` continuation to restore the previous forest when done.
    EnterForest(Arc<MastForest>),
    /// Process the `after_exit` decorators of the given node.
    AfterExitDecorators(MastNodeId),
    /// Process the `after_exit` decorators of the basic block node.
    ///
    /// Similar to `AfterExitDecorators`, but also executes all operation-level decorators that
    /// refer to after the last operation in the basic block. See [`BasicBlockNode`] for more
    /// details.
    AfterExitDecoratorsBasicBlock(MastNodeId),
}

impl Continuation {
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
            | FinishLoop { node_id: _, was_entered: _ }
            | FinishCall(_)
            | FinishDyn(_)
            | ResumeBasicBlock {
                node_id: _,
                batch_index: _,
                op_idx_in_batch: _,
            }
            | Respan { node_id: _, batch_index: _ }
            | FinishBasicBlock(_) => true,

            FinishExternal(_)
            | EnterForest(_)
            | AfterExitDecorators(_)
            | AfterExitDecoratorsBasicBlock(_) => false,
        }
    }
}

/// [ContinuationStack] reifies the call stack used by the processor when executing a program made
/// up of possibly multiple MAST forests.
///
/// This allows the processor to execute a program iteratively in a loop rather than recursively
/// traversing the nodes. It also allows the processor to pass the state of execution to another
/// processor for further processing, which is useful for parallel execution of MAST forests.
#[derive(Debug, Default, Clone)]
pub struct ContinuationStack {
    stack: Vec<Continuation>,
}

impl ContinuationStack {
    /// Creates a new continuation stack for a program.
    ///
    /// # Arguments
    /// * `program` - The program whose execution will be managed by this continuation stack
    pub fn new(program: &Program) -> Self {
        let mut stack = Vec::with_capacity(CONTINUATION_STACK_SIZE_HINT);
        stack.push(Continuation::StartNode(program.entrypoint()));

        Self { stack }
    }

    /// Pushes a continuation onto the continuation stack.
    pub fn push_continuation(&mut self, continuation: Continuation) {
        self.stack.push(continuation);
    }

    /// Pushes a continuation to enter the given MAST forest on the continuation stack.
    ///
    /// # Arguments
    /// * `forest` - The MAST forest to enter
    pub fn push_enter_forest(&mut self, forest: Arc<MastForest>) {
        self.stack.push(Continuation::EnterForest(forest));
    }

    /// Pushes a join finish continuation onto the stack.
    pub fn push_finish_join(&mut self, node_id: MastNodeId) {
        self.stack.push(Continuation::FinishJoin(node_id));
    }

    /// Pushes a split finish continuation onto the stack.
    pub fn push_finish_split(&mut self, node_id: MastNodeId) {
        self.stack.push(Continuation::FinishSplit(node_id));
    }

    /// Pushes a loop finish continuation onto the stack, for which the loop was entered.
    pub fn push_finish_loop_entered(&mut self, node_id: MastNodeId) {
        self.stack.push(Continuation::FinishLoop { node_id, was_entered: true });
    }

    /// Pushes a call finish continuation onto the stack.
    pub fn push_finish_call(&mut self, node_id: MastNodeId) {
        self.stack.push(Continuation::FinishCall(node_id));
    }

    /// Pushes a dyn finish continuation onto the stack.
    pub fn push_finish_dyn(&mut self, node_id: MastNodeId) {
        self.stack.push(Continuation::FinishDyn(node_id));
    }

    /// Pushes an external finish continuation onto the stack.
    pub fn push_finish_external(&mut self, node_id: MastNodeId) {
        self.stack.push(Continuation::FinishExternal(node_id));
    }

    /// Pushes a continuation to start processing the given node.
    ///
    /// # Arguments
    /// * `node_id` - The ID of the node to process
    pub fn push_start_node(&mut self, node_id: MastNodeId) {
        self.stack.push(Continuation::StartNode(node_id));
    }

    /// Pops the next continuation from the continuation stack, and returns it along with its
    /// associated MAST forest.
    pub fn pop_continuation(&mut self) -> Option<Continuation> {
        self.stack.pop()
    }

    // ACCESSORS
    // ------------------------------------------------------------

    /// Peeks at the next continuation to execute without removing it.
    ///
    /// Note that more than one continuation may execute in the same clock cycle. To get all
    /// continuations that will execute in the next clock cycle, use
    /// [`Self::iter_continuations_for_next_clock`].
    pub fn peek_continuation(&self) -> Option<&Continuation> {
        self.stack.last()
    }

    /// Returns an iterator over the continuations on the stack that will execute in the next clock
    /// cycle.
    ///
    /// This includes all coming continuations up to and including the first continuation that
    /// increments the clock.
    ///
    /// Note: for this iterator to function correctly, it must be the case that that executing a
    /// continuation that doesn't increment the clock *does not* push new continuations on the
    /// stack. This is currently the case, and is a reasonable invariant to maintain, as
    /// continuations that don't increment the clock can be expected to be simple (e.g. run some
    /// decorators, or enter a new mast forest).
    pub fn iter_continuations_for_next_clock(&self) -> impl Iterator<Item = &Continuation> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_next_clock_cycle_increment_empty_stack() {
        let stack = ContinuationStack::default();
        let result: Vec<_> = stack.iter_continuations_for_next_clock().collect();
        assert!(result.is_empty());
    }

    #[test]
    fn get_next_clock_cycle_increment_ends_with_incrementing() {
        let mut stack = ContinuationStack::default();
        // Push a continuation that increments the clock
        stack.push_continuation(Continuation::StartNode(MastNodeId::new_unchecked(0)));

        let result: Vec<_> = stack.iter_continuations_for_next_clock().collect();
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], Continuation::StartNode(_)));
    }

    #[test]
    fn get_next_clock_cycle_increment_non_incrementing_after_incrementing() {
        let mut stack = ContinuationStack::default();
        // Push an incrementing continuation first (bottom of stack)
        stack.push_continuation(Continuation::StartNode(MastNodeId::new_unchecked(0)));
        // Push a non-incrementing continuation on top
        stack.push_continuation(Continuation::AfterExitDecorators(MastNodeId::new_unchecked(0)));

        let result: Vec<_> = stack.iter_continuations_for_next_clock().collect();
        // Should return: AfterExitDecorators (non-incrementing), then StartNode (first
        // incrementing)
        assert_eq!(result.len(), 2);
        assert!(matches!(result[0], Continuation::AfterExitDecorators(_)));
        assert!(matches!(result[1], Continuation::StartNode(_)));
    }

    #[test]
    fn get_next_clock_cycle_increment_two_non_incrementing_after_incrementing() {
        let mut stack = ContinuationStack::default();
        // Push an incrementing continuation first (bottom of stack)
        stack.push_continuation(Continuation::StartNode(MastNodeId::new_unchecked(0)));
        // Push two non-incrementing continuations on top
        stack.push_continuation(Continuation::AfterExitDecorators(MastNodeId::new_unchecked(0)));
        stack.push_continuation(Continuation::EnterForest(Arc::new(MastForest::new())));

        let result: Vec<_> = stack.iter_continuations_for_next_clock().collect();
        // Should return: EnterForest, AfterExitDecorators, StartNode
        assert_eq!(result.len(), 3);
        assert!(matches!(result[0], Continuation::EnterForest(_)));
        assert!(matches!(result[1], Continuation::AfterExitDecorators(_)));
        assert!(matches!(result[2], Continuation::StartNode(_)));
    }
}
