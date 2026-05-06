use alloc::vec::Vec;

use miden_air::Felt;
use miden_core::{Word, ZERO};

use crate::ContextId;

// BLOCK STACK
// ================================================================================================

/// Tracks per-block data needed for trace generation that the [`ContinuationStack`] does not
/// carry. Specifically, it stores the hasher chiplet addresses (`addr`, `parent_addr`) assigned
/// during execution, and for CALL/SYSCALL/DYNCALL blocks, the caller's execution context so it
/// can be restored on END.
///
/// [`ContinuationStack`]: crate::continuation_stack::ContinuationStack
#[derive(Debug, Default, Clone)]
pub struct BlockStack {
    blocks: Vec<BlockInfo>,
}

impl BlockStack {
    // STATE ACCESSORS AND MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Pushes a new code block onto the block stack and returns the address of the block's parent.
    ///
    /// The block is identified by its address. For CALL, SYSCALL and DYNCALL blocks, execution
    /// context info must be provided so that the caller's context can be restored on END.
    ///
    /// When the block is later popped (on END), the flags for the trace row are fully reconstructed
    /// from the continuation stack, and hence do not need to be stored in this data structure.
    pub fn push(&mut self, addr: Felt, ctx_info: Option<ExecutionContextInfo>) -> Felt {
        let parent_addr = match self.blocks.last() {
            Some(parent) => parent.addr,
            None => ZERO,
        };

        self.blocks.push(BlockInfo { addr, parent_addr, ctx_info });
        parent_addr
    }

    pub fn pop(&mut self) -> BlockInfo {
        self.blocks.pop().expect("block stack is empty")
    }

    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    pub fn peek(&self) -> &BlockInfo {
        self.blocks.last().expect("block stack is empty")
    }

    pub fn peek_mut(&mut self) -> &mut BlockInfo {
        self.blocks.last_mut().expect("block stack is empty")
    }
}

// BLOCK INFO
// ================================================================================================

#[derive(Debug, Clone)]
pub struct BlockInfo {
    pub addr: Felt,
    pub parent_addr: Felt,
    pub ctx_info: Option<ExecutionContextInfo>,
}

// EXECUTION CONTEXT INFO
// ================================================================================================

/// Contains information about an execution context. Execution contexts are relevant only for CALL
/// and SYSCALL blocks.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExecutionContextInfo {
    /// Context ID of the block's parent.
    pub parent_ctx: ContextId,
    /// Hash of the function which initiated execution of the block's parent. If the parent is a
    /// root context, this will be set to [ZERO; 4].
    pub parent_fn_hash: Word,
    /// Depth of the operand stack right before a CALL operation is executed.
    pub parent_stack_depth: u32,
    /// Address of the top row in the overflow table right before a CALL operations is executed.
    pub parent_next_overflow_addr: Felt,
}

impl ExecutionContextInfo {
    pub fn new(
        parent_ctx: ContextId,
        parent_fn_hash: Word,
        parent_stack_depth: u32,
        parent_next_overflow_addr: Felt,
    ) -> Self {
        Self {
            parent_fn_hash,
            parent_ctx,
            parent_stack_depth,
            parent_next_overflow_addr,
        }
    }
}
