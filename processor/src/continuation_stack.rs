use alloc::{sync::Arc, vec::Vec};

use miden_core::{
    Program,
    mast::{MastForest, MastNodeId},
};

/// Specifies the phase of a processing step.
///
/// Specifically, it allows to distinguish between the start and finish phases of processing a node,
/// which gives the processor sufficient information to execute the node correctly. Note that
/// exactly how "start" and "end" are used depends on the node type being processed.
#[derive(Debug, Default)]
pub enum ProcessingStepPhase {
    #[default]
    Start,
    Finish,
}

/// Represents a unit of work in the continuation stack.
///
/// This enum defines the different types of processing steps that can be performed on MAST nodes
/// during program execution. Each variant represents a specific phase of node processing.
#[derive(Debug)]
pub enum ProcessingStep {
    /// Process a MAST node in a given phase.
    ///
    /// The tuple contains the node ID and the processing phase (Start or Finish).
    Node((MastNodeId, ProcessingStepPhase)),
    /// Process the decorators that should be executed before the main node logic.
    PreDecorators(MastNodeId),
    /// Process the decorators that should be executed after the main node logic.
    PostDecorators(MastNodeId),
}

/// A continuation stack for processing nodes within a single MAST forest.
///
/// This struct manages the execution order of processing steps for nodes within a specific
/// MAST forest. It maintains a work stack that determines the order in which nodes and their
/// decorators are processed.
pub struct ForestContinuationStack {
    forest: Arc<MastForest>,
    work_stack: Vec<ProcessingStep>,
}

impl ForestContinuationStack {
    /// Creates a new continuation stack for a MAST forest.
    ///
    /// The stack is initialized with processing steps for the first node, including its
    /// pre-decorators, the node itself (in Start phase), and post-decorators.
    ///
    /// # Arguments
    /// * `forest` - The MAST forest containing the nodes to be processed
    /// * `first_node` - The ID of the first node to process
    pub fn new(forest: Arc<MastForest>, first_node: MastNodeId) -> Self {
        Self {
            forest,
            // Note: the steps are added in reverse order since they will be popped from the stack.
            work_stack: vec![
                ProcessingStep::PostDecorators(first_node),
                ProcessingStep::Node((first_node, ProcessingStepPhase::Start)),
                ProcessingStep::PreDecorators(first_node),
            ],
        }
    }

    /// Pushes a node processing step in a specific phase onto the work stack.
    ///
    /// This method adds a single processing step for a node without its decorators.
    /// The node will be processed in the specified phase when the step is popped.
    ///
    /// # Arguments
    /// * `node_id` - The ID of the node to process
    /// * `phase` - The processing phase (Start or Finish)
    pub fn push_node_in_phase(&mut self, node_id: MastNodeId, phase: ProcessingStepPhase) {
        self.work_stack.push(ProcessingStep::Node((node_id, phase)));
    }

    /// Pushes a complete node processing sequence onto the work stack.
    ///
    /// This method adds processing steps for a node along with its decorators.
    ///
    /// # Arguments
    /// * `node_id` - The ID of the node to process along with its decorators
    pub fn push_node_with_decorators(&mut self, node_id: MastNodeId) {
        // Note: the steps are added in reverse order: post-decorators, the node itself (in Start
        // phase), and pre-decorators, ensuring they are executed in the correct order when popped.
        self.work_stack.extend([
            ProcessingStep::PostDecorators(node_id),
            ProcessingStep::Node((node_id, ProcessingStepPhase::Start)),
            ProcessingStep::PreDecorators(node_id),
        ]);
    }

    /// Pops the next processing step from the work stack.
    ///
    /// Returns the next processing step to be executed, or `None` if the stack is empty.
    /// Processing steps are returned in LIFO order.
    ///
    /// # Returns
    /// The next `ProcessingStep` to execute, or `None` if no steps remain.
    pub fn pop_next_processing_step(&mut self) -> Option<ProcessingStep> {
        self.work_stack.pop()
    }
}

/// [ContinuationStack] reifies the call stack used by the processor when executing a program made
/// up of possibly multiple MAST forests.
///
/// This allows the processor to execute a program iteratively in a loop rather than recursively
/// traversing the nodes.
pub struct ContinuationStack {
    forest_continuation_stack: Vec<ForestContinuationStack>,
}

impl ContinuationStack {
    /// Creates a new continuation stack for a program.
    ///
    /// Initializes the stack with a single forest continuation stack for the program's
    /// main MAST forest, starting from the program's entrypoint.
    ///
    /// # Arguments
    /// * `program` - The program whose execution will be managed by this continuation stack
    pub fn new(program: &Program) -> Self {
        let first_forest_stack =
            ForestContinuationStack::new(program.mast_forest().clone(), program.entrypoint());

        Self {
            forest_continuation_stack: vec![first_forest_stack],
        }
    }

    /// Pushes a new MAST forest onto the continuation stack.
    ///
    /// Creates a new forest continuation stack for the specified forest and adds it to
    /// the top of the stack. This is typically used when entering a new execution context,
    /// such as when calling into a different MAST forest.
    ///
    /// # Arguments
    /// * `forest` - The MAST forest to add to the continuation stack
    /// * `first_node` - The ID of the first node to process in the new forest
    pub fn push_new_forest(&mut self, forest: Arc<MastForest>, first_node: MastNodeId) {
        let new_forest_stack = ForestContinuationStack::new(forest, first_node);
        self.forest_continuation_stack.push(new_forest_stack);
    }

    /// Pushes a node processing step in a specific phase onto the current forest's work stack.
    ///
    /// # Arguments
    /// * `node_id` - The ID of the node to process
    /// * `phase` - The processing phase (Start or Finish)
    ///
    /// # Panics
    /// Panics if the continuation stack is empty (no forests present).
    pub fn push_node_in_phase(&mut self, node_id: MastNodeId, phase: ProcessingStepPhase) {
        let last_forest_stack = self.forest_continuation_stack.last_mut().unwrap();
        last_forest_stack.push_node_in_phase(node_id, phase);
    }

    /// Pushes a complete node processing sequence onto the current forest's work stack.
    ///
    /// # Arguments
    /// * `node_id` - The ID of the node to process along with its decorators
    ///
    /// # Panics
    /// Panics if the continuation stack is empty (no forests present).
    pub fn push_node_with_decorators(&mut self, node_id: MastNodeId) {
        let last_forest_stack = self.forest_continuation_stack.last_mut().unwrap();
        last_forest_stack.push_node_with_decorators(node_id);
    }

    /// Pops the next processing step from the continuation stack.
    ///
    /// Returns the next processing step along with its associated MAST forest. If the
    /// current forest's work stack is empty, the forest is removed from the continuation
    /// stack and the method recursively tries the next forest. This continues until either
    /// a processing step is found or all forests are exhausted.
    ///
    /// # Returns
    /// A tuple containing the MAST forest and the next processing step, or `None` if
    /// no more processing steps remain in any forest.
    pub fn pop_next_processing_step(&mut self) -> Option<(Arc<MastForest>, ProcessingStep)> {
        let last_forest_stack = self.forest_continuation_stack.last_mut()?;

        match last_forest_stack.pop_next_processing_step() {
            Some(unit_of_work) => Some((last_forest_stack.forest.clone(), unit_of_work)),
            None => {
                self.forest_continuation_stack.pop();
                self.pop_next_processing_step()
            },
        }
    }
}
