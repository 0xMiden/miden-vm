use alloc::{boxed::Box, vec::Vec};

use super::{IN_MEMORY_DEPTH, LargeSmtResult, StorageResult, is_empty_parent};
use crate::{
    Word,
    hash::poseidon2::Poseidon2,
    merkle::{
        InnerNodeInfo,
        smt::{LargeSmt, SmtStorageReader, large::subtree::Subtree},
    },
};

// ITERATORS
// ================================================================================================

enum InnerNodeIteratorState<'a> {
    InMemory {
        current_index: usize,
        large_smt_in_memory_nodes: &'a [Word],
    },
    Subtree {
        subtree_iter: Box<dyn Iterator<Item = StorageResult<Subtree>> + 'a>,
        current_subtree_node_iter: Option<Box<dyn Iterator<Item = InnerNodeInfo> + 'a>>,
    },
    Done,
}

pub struct LargeSmtInnerNodeIterator<'a, S: SmtStorageReader> {
    large_smt: &'a LargeSmt<S>,
    state: InnerNodeIteratorState<'a>,
}

impl<'a, S: SmtStorageReader> LargeSmtInnerNodeIterator<'a, S> {
    pub(super) fn new(large_smt: &'a LargeSmt<S>) -> Self {
        // in-memory nodes should never be empty
        Self {
            large_smt,
            state: InnerNodeIteratorState::InMemory {
                current_index: 0,
                large_smt_in_memory_nodes: &large_smt.in_memory_nodes,
            },
        }
    }
}

impl<S: SmtStorageReader> Iterator for LargeSmtInnerNodeIterator<'_, S> {
    type Item = LargeSmtResult<InnerNodeInfo>;

    /// Returns the next inner node info in the tree.
    ///
    /// The iterator operates in three phases:
    /// 1. InMemory: Iterates through the in-memory nodes (depths 0-IN_MEMORY_DEPTH-1)
    /// 2. Subtree: Iterates through nodes in storage subtrees (depths IN_MEMORY_DEPTH-SMT_DEPTH)
    /// 3. Done: No more nodes to iterate
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match &mut self.state {
                // Phase 1: Process in-memory nodes (depths 0-23)
                InnerNodeIteratorState::InMemory { current_index, large_smt_in_memory_nodes } => {
                    // Iterate through nodes at depths 0 to IN_MEMORY_DEPTH-1
                    // Start at index 1 (root), max node index is (1 << IN_MEMORY_DEPTH) - 1
                    if *current_index == 0 {
                        *current_index = 1;
                    }

                    let max_node_idx = (1 << IN_MEMORY_DEPTH) - 1;

                    while *current_index <= max_node_idx {
                        let node_idx = *current_index;
                        *current_index += 1;

                        // Get children from flat layout: left at 2*i, right at 2*i+1
                        let left = large_smt_in_memory_nodes[node_idx * 2];
                        let right = large_smt_in_memory_nodes[node_idx * 2 + 1];

                        // Skip empty nodes
                        let depth = node_idx.ilog2() as u8;
                        let child_depth = depth + 1;

                        if !is_empty_parent(left, right, child_depth) {
                            return Some(Ok(InnerNodeInfo {
                                value: Poseidon2::merge(&[left, right]),
                                left,
                                right,
                            }));
                        }
                    }

                    // All in-memory nodes processed. Transition to Phase 2: Subtree iteration
                    match self.large_smt.storage.iter_subtrees() {
                        Ok(subtree_iter) => {
                            self.state = InnerNodeIteratorState::Subtree {
                                subtree_iter,
                                current_subtree_node_iter: None,
                            };
                        },
                        Err(e) => {
                            // Storage error occurred - we should propagate this error.
                            // We also transition to Done state to avoid infinite loops.
                            self.state = InnerNodeIteratorState::Done;
                            return Some(LargeSmtResult::Err(e.into()));
                        },
                    }
                },
                // Phase 2: Process storage subtrees (depths 25-64)
                InnerNodeIteratorState::Subtree { subtree_iter, current_subtree_node_iter } => {
                    loop {
                        // First, try to get the next node from current subtree
                        if let Some(node_iter) = current_subtree_node_iter
                            && let Some(info) = node_iter.as_mut().next()
                        {
                            return Some(Ok(info));
                        }

                        // Current subtree exhausted, move to next subtree
                        match subtree_iter.next() {
                            Some(Ok(next_subtree)) => {
                                // Collect is necessary here because iter_inner_node_info returns
                                // an iterator borrowing from next_subtree, which would outlive
                                // the subtree itself. We need to eagerly evaluate to owned data.
                                #[expect(clippy::needless_collect)]
                                let infos: Vec<InnerNodeInfo> =
                                    next_subtree.iter_inner_node_info().collect();
                                *current_subtree_node_iter = Some(Box::new(infos.into_iter()));
                            },
                            Some(Err(err)) => return Some(Err(err.into())),
                            None => {
                                self.state = InnerNodeIteratorState::Done;
                                return None; // All subtrees processed
                            },
                        }
                    }
                },
                InnerNodeIteratorState::Done => {
                    return None; // Iteration finished.
                },
            }
        }
    }
}
