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
#[derive(Debug)]
pub enum Continuation {
    /// Start processing a node in the MAST forest.
    StartNode(MastNodeId),
    /// Process the finish phase of a Join node.
    FinishJoin(MastNodeId),
    /// Process the finish phase of a Split node.
    FinishSplit(MastNodeId),
    /// Process the finish phase of a Loop node.
    FinishLoop(MastNodeId),
    /// Process the finish phase of a Call node.
    FinishCall(MastNodeId),
    /// Process the finish phase of a Dyn node.
    FinishDyn(MastNodeId),
    /// Enter a new MAST forest, where all subsequent `MastNodeId`s will be relative to this forest.
    ///
    /// When we encounter an `ExternalNode`, we enter the corresponding MAST forest directly, and
    /// push an `EnterForest` continuation to restore the previous forest when done.
    EnterForest(Arc<MastForest>),
}

/// [ContinuationStack] reifies the call stack used by the processor when executing a program made
/// up of possibly multiple MAST forests.
///
/// This allows the processor to execute a program iteratively in a loop rather than recursively
/// traversing the nodes. It also allows the processor to pass the state of execution to another
/// processor for further processing, which is useful for parallel execution of MAST forests.
#[derive(Debug)]
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

    /// Pushes a loop finish continuation onto the stack.
    pub fn push_finish_loop(&mut self, node_id: MastNodeId) {
        self.stack.push(Continuation::FinishLoop(node_id));
    }

    /// Pushes a call finish continuation onto the stack.
    pub fn push_finish_call(&mut self, node_id: MastNodeId) {
        self.stack.push(Continuation::FinishCall(node_id));
    }

    /// Pushes a dyn finish continuation onto the stack.
    pub fn push_finish_dyn(&mut self, node_id: MastNodeId) {
        self.stack.push(Continuation::FinishDyn(node_id));
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
}
