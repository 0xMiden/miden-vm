use alloc::{sync::Arc, vec::Vec};

use miden_core::mast::{MastForest, MastNode, MastNodeId};

/// A helper structure that maintains a MastForest and its associated call stack, for use in
/// [ExecutionTraversal].
struct ForestCallStack {
    mast_forest: Arc<MastForest>,
    call_stack: Vec<MastNodeId>,
}

impl ForestCallStack {
    fn new_from_call_stack(mast_forest: Arc<MastForest>, call_stack: Vec<MastNodeId>) -> Self {
        Self { mast_forest, call_stack }
    }

    fn new_from_entrypoint(forest: Arc<MastForest>, entrypoint: MastNodeId) -> Self {
        Self::new_from_call_stack(forest, vec![entrypoint])
    }

    fn new_empty(forest: Arc<MastForest>) -> Self {
        Self::new_from_call_stack(forest, Vec::new())
    }

    fn peek_current_node(&self) -> Option<MastNodeId> {
        self.call_stack.last().copied()
    }

    fn is_empty(&self) -> bool {
        self.call_stack.is_empty()
    }

    fn forest(&self) -> &Arc<MastForest> {
        &self.mast_forest
    }

    /// Advances to the next node in the execution order, where the node on top of the call stack is
    /// considered to be fully executed. Returns the next node ID if available, or None if the
    /// traversal is complete.
    pub fn advance(&mut self) -> Option<MastNodeId> {
        // Get the current node (without popping it yet)
        let current_node_id = self.call_stack.last().copied()?;

        self.call_stack.pop();
        self.advance_from_parent(current_node_id)
    }

    /// Helper method to advance after completing execution of a child node
    fn advance_from_parent(&mut self, executed_node_id: MastNodeId) -> Option<MastNodeId> {
        // If no parent, traversal is complete
        let parent_node_id = self.call_stack.last().copied()?;

        let parent_node = self
            .mast_forest
            .get_node_by_id(parent_node_id)
            .expect("Parent node should exist in the forest");

        match parent_node {
            MastNode::Block(_) => unreachable!(
                "Basic blocks are always leaf nodes, and therefore cannot have children."
            ),
            MastNode::Join(join_node) => {
                if executed_node_id == join_node.first() {
                    // If we just executed the first node of the join, execute the second node
                    self.call_stack.push(join_node.second());
                    Some(join_node.second())
                } else {
                    // If we executed the second node, we are done with this join - pop it and
                    // continue
                    self.call_stack.pop();
                    self.advance_from_parent(parent_node_id)
                }
            },
            MastNode::Split(_)
            | MastNode::Loop(_)
            | MastNode::Call(_)
            | MastNode::Dyn(_)
            | MastNode::External(_) => {
                // These nodes complete immediately after their children - pop and continue
                self.call_stack.pop();
                self.advance_from_parent(parent_node_id)
            },
        }
    }
}

/// ExecutionTraversal is a structure that allows traversing a set of MastForests in the order of
/// execution, starting from the root node of the initial program's MastForest.
///
/// Each forest maintains its own call stack to ensure MastNodeIds are properly matched
/// with their corresponding MastForest.
pub struct ExecutionTraversal {
    /// Stack of forests, each with its own isolated call stack.
    forest_stack: Vec<ForestCallStack>,
}

impl ExecutionTraversal {
    /// Creates a new ExecutionTraversal starting from the given entrypoint node.
    pub fn new_from_entrypoint(mast_forest: Arc<MastForest>, entrypoint: MastNodeId) -> Self {
        Self {
            forest_stack: vec![ForestCallStack::new_from_entrypoint(mast_forest, entrypoint)],
        }
    }

    /// Creates a new ExecutionTraversal from an existing call stack.
    ///
    /// # Panics if the call stack is empty.
    pub fn new_from_call_stack(mast_forest: Arc<MastForest>, call_stack: Vec<MastNodeId>) -> Self {
        assert!(!call_stack.is_empty(), "Call stack cannot be empty");
        Self {
            forest_stack: vec![ForestCallStack::new_from_call_stack(mast_forest, call_stack)],
        }
    }

    /// Returns the next node in the execution order without advancing the traversal.
    pub fn peek_current_node(&self) -> Option<MastNodeId> {
        self.forest_stack.last()?.peek_current_node()
    }

    /// Advances to the next node in the execution order, where the node on top of the call stack is
    /// considered to be fully executed. Returns the next node ID if available, or None if the
    /// traversal is complete.
    pub fn advance(&mut self) -> Option<MastNodeId> {
        match self.forest_stack.last_mut()?.advance() {
            Some(node_id) => Some(node_id),
            None => {
                // If the current forest is complete, pop it and continue
                self.forest_stack.pop()?;
                self.advance()
            },
        }
    }

    /// Returns a reference to the current MastForest (top of the stack).
    pub fn current_forest(&self) -> &Arc<MastForest> {
        self.forest_stack.last().expect("No forest on stack").forest()
    }

    /// Push a new MastForest onto the stack (e.g., when entering an external forest).
    /// This creates a new execution context with an empty call stack.
    pub fn push_forest(&mut self, forest: Arc<MastForest>) {
        self.forest_stack.push(ForestCallStack::new_empty(forest));
    }

    /// Push a new MastForest onto the stack and immediately add a node to execute.
    /// This is a convenience method for external node resolution.
    pub fn push_forest_with_node(&mut self, forest: Arc<MastForest>, node_id: MastNodeId) {
        self.forest_stack.push(ForestCallStack::new_from_entrypoint(forest, node_id));
    }

    /// Pop the current MastForest from the stack (e.g., when returning from an external forest).
    /// The call stack for the popped forest must be empty (all nodes executed).
    pub fn pop_forest(&mut self) {
        // TODO(plafer): remove
        if self.forest_stack.len() <= 1 {
            // Don't pop the last forest for safety
            return;
        }

        let popped_forest_stack = self.forest_stack.pop().expect("No forest on stack to pop");
        debug_assert!(
            popped_forest_stack.is_empty(),
            "Cannot pop forest with active nodes on call stack"
        );
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use miden_core::{
        Felt, Operation, Word,
        mast::{MastForest, MastNode},
    };

    use super::*;

    /// Helper function to create a basic block node with simple operations
    fn create_basic_block(operations: Vec<Operation>) -> MastNode {
        MastNode::new_basic_block(operations, None).unwrap()
    }

    #[test]
    fn test_basic_block_traversal() {
        let mut forest = MastForest::new();

        // Create a simple basic block
        let block = create_basic_block(vec![Operation::Add, Operation::Mul]);
        let block_id = forest.add_node(block).unwrap();
        forest.make_root(block_id);

        let forest = Arc::new(forest);
        let mut forest_stack =
            ExecutionTraversal::new_from_entrypoint(Arc::clone(&forest), block_id);

        // Test peek - should return the block itself
        assert_eq!(forest_stack.peek_current_node(), Some(block_id));

        // Test advance - should return None since basic blocks are leaf nodes
        assert_eq!(forest_stack.advance(), None);

        // After advance, peek should return None
        assert_eq!(forest_stack.peek_current_node(), None);
    }

    #[test]
    fn test_join_node_traversal() {
        let mut forest = MastForest::new();

        // Create two basic blocks
        let block1 = create_basic_block(vec![Operation::Add]);
        let block2 = create_basic_block(vec![Operation::Mul]);

        let block1_id = forest.add_node(block1).unwrap();
        let block2_id = forest.add_node(block2).unwrap();

        // Create a join node
        let join_node = MastNode::new_join(block1_id, block2_id, &forest).unwrap();
        let join_id = forest.add_node(join_node).unwrap();
        forest.make_root(join_id);

        let forest = Arc::new(forest);
        let mut forest_stack = ForestCallStack::new_from_entrypoint(Arc::clone(&forest), join_id);

        // Initial peek should return the join node
        assert_eq!(forest_stack.peek_current_node(), Some(join_id));

        // When advance() is called on a join node, it means the join (including both children)
        // has been fully executed, so the traversal should be complete
        assert_eq!(forest_stack.advance(), None);
        assert_eq!(forest_stack.peek_current_node(), None);
    }

    #[test]
    fn test_nested_join_nodes() {
        let mut forest = MastForest::new();

        // Create basic blocks
        let block1 = create_basic_block(vec![Operation::Add]);
        let block2 = create_basic_block(vec![Operation::Mul]);
        let block3 = create_basic_block(vec![Operation::Drop]);

        let block1_id = forest.add_node(block1).unwrap();
        let block2_id = forest.add_node(block2).unwrap();
        let block3_id = forest.add_node(block3).unwrap();

        // Create nested join: join1(block1, block2), join2(join1, block3)
        let join1 = MastNode::new_join(block1_id, block2_id, &forest).unwrap();
        let join1_id = forest.add_node(join1).unwrap();

        let join2 = MastNode::new_join(join1_id, block3_id, &forest).unwrap();
        let join2_id = forest.add_node(join2).unwrap();
        forest.make_root(join2_id);

        let forest = Arc::new(forest);
        let mut forest_stack = ForestCallStack::new_from_entrypoint(Arc::clone(&forest), join2_id);

        // With corrected semantics, advance() means "fully executed"
        // So the traversal only surfaces the root join node
        assert_eq!(forest_stack.peek_current_node(), Some(join2_id));

        // When advance() is called, join2 (and all its children) are considered fully executed
        assert_eq!(forest_stack.advance(), None);
        assert_eq!(forest_stack.peek_current_node(), None);
    }

    #[test]
    fn test_split_node_traversal() {
        let mut forest = MastForest::new();

        // Create two basic blocks
        let true_block = create_basic_block(vec![Operation::Add]);
        let false_block = create_basic_block(vec![Operation::Mul]);

        let true_block_id = forest.add_node(true_block).unwrap();
        let false_block_id = forest.add_node(false_block).unwrap();

        // Create a split node
        let split_node = MastNode::new_split(true_block_id, false_block_id, &forest).unwrap();
        let split_id = forest.add_node(split_node).unwrap();
        forest.make_root(split_id);

        let forest = Arc::new(forest);
        let mut forest_stack = ForestCallStack::new_from_entrypoint(Arc::clone(&forest), split_id);

        // Initial peek should return the split node
        assert_eq!(forest_stack.peek_current_node(), Some(split_id));

        // Since split nodes don't have predetermined execution order,
        // advance should complete immediately
        assert_eq!(forest_stack.advance(), None);
        assert_eq!(forest_stack.peek_current_node(), None);
    }

    #[test]
    fn test_loop_node_traversal() {
        let mut forest = MastForest::new();

        // Create a basic block for the loop body
        let body_block = create_basic_block(vec![Operation::Add, Operation::Drop]);
        let body_id = forest.add_node(body_block).unwrap();

        // Create a loop node
        let loop_node = MastNode::new_loop(body_id, &forest).unwrap();
        let loop_id = forest.add_node(loop_node).unwrap();
        forest.make_root(loop_id);

        let forest = Arc::new(forest);
        let mut forest_stack = ForestCallStack::new_from_entrypoint(Arc::clone(&forest), loop_id);

        // Initial peek should return the loop node
        assert_eq!(forest_stack.peek_current_node(), Some(loop_id));

        // Since loop execution is runtime-dependent, advance should complete immediately
        assert_eq!(forest_stack.advance(), None);
        assert_eq!(forest_stack.peek_current_node(), None);
    }

    #[test]
    fn test_call_node_traversal() {
        let mut forest = MastForest::new();

        // Create a basic block to call
        let callee_block = create_basic_block(vec![Operation::Swap, Operation::Drop]);
        let callee_id = forest.add_node(callee_block).unwrap();

        // Create a call node
        let call_node = MastNode::new_call(callee_id, &forest).unwrap();
        let call_id = forest.add_node(call_node).unwrap();
        forest.make_root(call_id);

        let forest = Arc::new(forest);
        let mut forest_stack = ForestCallStack::new_from_entrypoint(Arc::clone(&forest), call_id);

        // Initial peek should return the call node
        assert_eq!(forest_stack.peek_current_node(), Some(call_id));

        // Since call execution involves context switching, advance should complete immediately
        assert_eq!(forest_stack.advance(), None);
        assert_eq!(forest_stack.peek_current_node(), None);
    }

    #[test]
    fn test_dyn_node_traversal() {
        let mut forest = MastForest::new();

        // Create a dyn node
        let dyn_node = MastNode::new_dyn();
        let dyn_id = forest.add_node(dyn_node).unwrap();
        forest.make_root(dyn_id);

        let forest = Arc::new(forest);
        let mut forest_stack = ForestCallStack::new_from_entrypoint(Arc::clone(&forest), dyn_id);

        // Initial peek should return the dyn node
        assert_eq!(forest_stack.peek_current_node(), Some(dyn_id));

        // Since dyn execution is runtime-dependent, advance should complete immediately
        assert_eq!(forest_stack.advance(), None);
        assert_eq!(forest_stack.peek_current_node(), None);
    }

    #[test]
    fn test_external_node_traversal() {
        let mut forest = MastForest::new();

        // Create an external node with a dummy digest
        let dummy_digest = Word::default();
        let external_node = MastNode::new_external(dummy_digest);
        let external_id = forest.add_node(external_node).unwrap();
        forest.make_root(external_id);

        let forest = Arc::new(forest);
        let mut forest_stack =
            ForestCallStack::new_from_entrypoint(Arc::clone(&forest), external_id);

        // Initial peek should return the external node
        assert_eq!(forest_stack.peek_current_node(), Some(external_id));

        // Since external nodes reference external procedures, advance should complete immediately
        assert_eq!(forest_stack.advance(), None);
        assert_eq!(forest_stack.peek_current_node(), None);
    }

    #[test]
    fn test_complex_nested_structure() {
        let mut forest = MastForest::new();

        // Create several basic blocks
        let block_a = create_basic_block(vec![Operation::Add]);
        let block_b = create_basic_block(vec![Operation::Mul]);
        let block_c = create_basic_block(vec![Operation::Drop]);
        let block_d = create_basic_block(vec![Operation::Swap]);

        let block_a_id = forest.add_node(block_a).unwrap();
        let block_b_id = forest.add_node(block_b).unwrap();
        let block_c_id = forest.add_node(block_c).unwrap();
        let block_d_id = forest.add_node(block_d).unwrap();

        // Create a complex structure: join(join(a, b), split(c, d))
        let join_ab = MastNode::new_join(block_a_id, block_b_id, &forest).unwrap();
        let join_ab_id = forest.add_node(join_ab).unwrap();

        let split_cd = MastNode::new_split(block_c_id, block_d_id, &forest).unwrap();
        let split_cd_id = forest.add_node(split_cd).unwrap();

        let root_join = MastNode::new_join(join_ab_id, split_cd_id, &forest).unwrap();
        let root_id = forest.add_node(root_join).unwrap();
        forest.make_root(root_id);

        let forest = Arc::new(forest);
        // Start execution with root_id, join_ab_id, and block_b_id on the call stack
        let mut forest_stack = ForestCallStack::new_from_call_stack(
            Arc::clone(&forest),
            vec![root_id, join_ab_id, block_b_id],
        );

        // Initial peek should return block b (top of call stack)
        assert_eq!(forest_stack.peek_current_node(), Some(block_b_id));

        // When advance() is called on block b, it should:
        // 1. Pop block_b (completing join_ab since block_b is the second child)
        // 2. Pop join_ab (since it's now complete)
        // 3. Since join_ab was the first child of root_join, push split_cd (the second child)
        assert_eq!(forest_stack.advance(), Some(split_cd_id));
        assert_eq!(forest_stack.peek_current_node(), Some(split_cd_id));

        // When advance() is called on split_cd, the traversal should complete
        assert_eq!(forest_stack.advance(), None);
        assert_eq!(forest_stack.peek_current_node(), None);
    }

    #[test]
    fn test_empty_traversal() {
        let mut forest = MastForest::new();

        // Create a basic block but don't add it to initialize traversal
        let block = create_basic_block(vec![Operation::Noop]);
        let block_id = forest.add_node(block).unwrap();
        forest.make_root(block_id);

        let forest = Arc::new(forest);
        let mut forest_stack = ForestCallStack::new_from_entrypoint(Arc::clone(&forest), block_id);

        // Consume the traversal
        assert_eq!(forest_stack.peek_current_node(), Some(block_id));
        assert_eq!(forest_stack.advance(), None);

        // Test that subsequent operations work correctly on empty traversal
        assert_eq!(forest_stack.peek_current_node(), None);
        assert_eq!(forest_stack.advance(), None);
        assert_eq!(forest_stack.peek_current_node(), None);
    }

    #[test]
    fn test_single_node_forest() {
        let mut forest = MastForest::new();

        // Create a forest with just one node
        let single_block = create_basic_block(vec![Operation::Push(Felt::new(42))]);
        let block_id = forest.add_node(single_block).unwrap();
        forest.make_root(block_id);

        let forest = Arc::new(forest);
        let mut forest_stack = ForestCallStack::new_from_entrypoint(Arc::clone(&forest), block_id);

        // Test the complete lifecycle
        assert_eq!(forest_stack.peek_current_node(), Some(block_id));
        assert_eq!(forest_stack.advance(), None);
        assert_eq!(forest_stack.peek_current_node(), None);
    }

    #[test]
    fn test_multi_forest_traversal() {
        // Create the third forest: JOIN of 2 basic blocks
        let mut forest3 = MastForest::new();
        let block3a = create_basic_block(vec![Operation::Add]);
        let block3b = create_basic_block(vec![Operation::Mul]);
        let block3a_id = forest3.add_node(block3a).unwrap();
        let block3b_id = forest3.add_node(block3b).unwrap();
        let join3 = MastNode::new_join(block3a_id, block3b_id, &forest3).unwrap();
        let join3_id = forest3.add_node(join3).unwrap();
        forest3.make_root(join3_id);

        // Create the second forest: only an ExternalNode (referring to third forest)
        let mut forest2 = MastForest::new();
        let external2 = MastNode::new_external(Word::default()); // references forest3
        let external2_id = forest2.add_node(external2).unwrap();
        forest2.make_root(external2_id);

        // Create the first forest: JOIN of ExternalNode (referring to second forest) and basic
        // block
        let mut forest1 = MastForest::new();
        let external1 = MastNode::new_external(Word::default()); // references forest2
        let external1_id = forest1.add_node(external1).unwrap();
        let block1 = create_basic_block(vec![Operation::Drop]);
        let block1_id = forest1.add_node(block1).unwrap();
        let join1 = MastNode::new_join(external1_id, block1_id, &forest1).unwrap();
        let join1_id = forest1.add_node(join1).unwrap();
        forest1.make_root(join1_id);

        let forest1 = Arc::new(forest1);
        let forest2 = Arc::new(forest2);
        let forest3 = Arc::new(forest3);

        // Initialize ExecutionTraversal starting with forest3, first child of the JOIN
        // This simulates having traversed through forest1 -> forest2 -> forest3 and being at the
        // first child
        let mut traversal =
            ExecutionTraversal::new_from_entrypoint(Arc::clone(&forest3), block3a_id);

        // Set up the forest stack to represent the complete traversal state:
        // - forest1 has join1 and external1 on the call stack (external1 being processed)
        // - forest2 has external2 on the call stack (external2 being processed)
        // - forest3 has join3 and block3a on the call stack (block3a being executed)

        // First, clear the current stack and rebuild it properly
        traversal.forest_stack.clear();

        // Add forest1 with join1 and external1 on call stack
        traversal.forest_stack.push(ForestCallStack::new_from_call_stack(
            Arc::clone(&forest1),
            vec![join1_id, external1_id],
        ));

        // Add forest2 with external2 on call stack
        traversal
            .forest_stack
            .push(ForestCallStack::new_from_call_stack(Arc::clone(&forest2), vec![external2_id]));

        // Add forest3 with join3 and block3a on call stack (currently executing block3a)
        traversal.forest_stack.push(ForestCallStack::new_from_call_stack(
            Arc::clone(&forest3),
            vec![join3_id, block3a_id],
        ));

        // Verify we're currently at block3a in forest3
        assert_eq!(traversal.peek_current_node(), Some(block3a_id));
        assert_eq!(traversal.current_forest(), &forest3);

        // First advance(): complete block3a, move to block3b (second child of join3) - stays in
        // forest3
        let next_node = traversal.advance();
        assert_eq!(next_node, Some(block3b_id));
        assert_eq!(traversal.peek_current_node(), Some(block3b_id));
        assert_eq!(traversal.current_forest(), &forest3);

        // Second advance(): complete block3b, which completes join3 and forest3,
        // return to forest1 at block1_id (second child of join1)
        let next_node = traversal.advance();
        assert_eq!(next_node, Some(block1_id));
        assert_eq!(traversal.peek_current_node(), Some(block1_id));
        assert_eq!(traversal.current_forest(), &forest1);

        // Third advance(): complete block1_id, which completes join1 and the entire traversal
        let next_node = traversal.advance();
        assert_eq!(next_node, None);
        assert_eq!(traversal.peek_current_node(), None);
    }

    #[test]
    fn test_pop_forest_safety() {
        let mut forest = MastForest::new();
        let block = create_basic_block(vec![Operation::Noop]);
        let block_id = forest.add_node(block).unwrap();
        forest.make_root(block_id);

        let forest = Arc::new(forest);
        let mut traversal = ExecutionTraversal::new_from_entrypoint(Arc::clone(&forest), block_id);

        // Should have one forest on the stack
        assert_eq!(traversal.forest_stack.len(), 1);

        // Try to pop the last forest - should not remove it (safety check)
        traversal.pop_forest();
        assert_eq!(traversal.forest_stack.len(), 1);

        // Add another forest and then pop it
        let mut forest2 = MastForest::new();
        let block2 = create_basic_block(vec![Operation::Add]);
        forest2.add_node(block2).unwrap();
        let forest2 = Arc::new(forest2);

        traversal.push_forest(forest2);
        assert_eq!(traversal.forest_stack.len(), 2);

        traversal.pop_forest();
        assert_eq!(traversal.forest_stack.len(), 1);
    }
}
