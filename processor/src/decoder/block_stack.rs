use alloc::vec::Vec;

use super::{Felt, ONE, Word, ZERO};
use crate::system::ContextId;

// BLOCK STACK
// ================================================================================================

/// Keeps track of code blocks which are currently being executed by the VM.
#[derive(Debug, Default, Clone)]
pub struct BlockStack {
    blocks: Vec<BlockInfo>,
}

impl BlockStack {
    // STATE ACCESSORS AND MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Pushes a new code block onto the block stack and returns the address of the block's parent.
    ///
    /// The block is identified by its address, and we also need to know what type of a block this
    /// is. Additionally, for CALL, SYSCALL and DYNCALL blocks, execution context info must be
    /// provided. Other information (i.e., the block's parent, whether the block is a body of a loop
    /// or a first child of a JOIN block) is determined from the information already on the stack.
    pub fn push(
        &mut self,
        addr: Felt,
        block_type: BlockType,
        ctx_info: Option<ExecutionContextInfo>,
    ) -> Felt {
        // make sure execution context was provided for CALL, SYSCALL and DYNCALL blocks
        if block_type == BlockType::Call
            || block_type == BlockType::SysCall
            || block_type == BlockType::Dyncall
        {
            debug_assert!(ctx_info.is_some(), "no execution context provided for a CALL block");
        } else {
            debug_assert!(ctx_info.is_none(), "execution context provided for a non-CALL block");
        }

        // determine additional info about the new block based on its parent
        let (parent_addr, is_loop_body, is_first_child) = match self.blocks.last() {
            Some(parent) => match parent.block_type {
                // if the parent block is a LOOP block, the new block must be a loop body
                BlockType::Loop(loop_entered) => {
                    debug_assert!(loop_entered, "parent is un-entered loop");
                    (parent.addr, true, false)
                },
                // if the parent block is a JOIN block, figure out if the new block is the first
                // or the second child
                BlockType::Join(first_child_executed) => {
                    (parent.addr, false, !first_child_executed)
                },
                _ => (parent.addr, false, false),
            },
            // if the block stack is empty, a new block is neither a body of a loop nor the first
            // child of a JOIN block; also, we set the parent address to ZERO.
            None => (ZERO, false, false),
        };

        self.blocks.push(BlockInfo {
            addr,
            block_type,
            parent_addr,
            ctx_info,
            is_loop_body,
            is_first_child,
        });
        parent_addr
    }

    /// Removes a block from the top of the stack and returns it.
    pub fn pop(&mut self) -> BlockInfo {
        let block = self.blocks.pop().expect("block stack is empty");
        // if the parent block is a JOIN block (i.e., we just finished executing a child of a JOIN
        // block) and if the first_child_executed hasn't been set to true yet, set it to true
        if let Some(parent) = self.blocks.last_mut()
            && let BlockType::Join(first_child_executed) = parent.block_type
            && !first_child_executed
        {
            parent.block_type = BlockType::Join(true);
        }
        block
    }

    /// Returns true if the block stack is empty.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Returns a reference to a block at the top of the stack.
    pub fn peek(&self) -> &BlockInfo {
        self.blocks.last().expect("block stack is empty")
    }

    /// Returns a mutable reference to a block at the top of the stack.
    pub fn peek_mut(&mut self) -> &mut BlockInfo {
        self.blocks.last_mut().expect("block stack is empty")
    }
}

// BLOCK INFO
// ================================================================================================

/// Contains basic information about a code block.
#[derive(Debug, Clone)]
pub struct BlockInfo {
    pub addr: Felt,
    block_type: BlockType,
    pub parent_addr: Felt,
    pub ctx_info: Option<ExecutionContextInfo>,
    pub is_loop_body: bool,
    #[allow(dead_code)] // TODO: remove this filed
    pub is_first_child: bool,
}

impl BlockInfo {
    /// Returns ONE if the this block is a LOOP block and the body of the loop was executed at
    /// least once; otherwise, returns ZERO.
    pub fn is_entered_loop(&self) -> Felt {
        if self.block_type == BlockType::Loop(true) {
            ONE
        } else {
            ZERO
        }
    }

    /// Returns ONE if this block is a body of a LOOP block; otherwise returns ZERO.
    pub const fn is_loop_body(&self) -> Felt {
        if self.is_loop_body { ONE } else { ZERO }
    }

    /// Returns ONE if this block is a CALL or DYNCALL block; otherwise returns ZERO.
    pub const fn is_call(&self) -> Felt {
        match self.block_type {
            BlockType::Call | BlockType::Dyncall => ONE,
            _ => ZERO,
        }
    }

    /// Returns ONE if this block is a SYSCALL block; otherwise returns ZERO.
    pub const fn is_syscall(&self) -> Felt {
        match self.block_type {
            BlockType::SysCall => ONE,
            _ => ZERO,
        }
    }
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
    /// Returns an new [ExecutionContextInfo] instantiated with the specified parameters.
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

// BLOCK TYPE
// ================================================================================================

/// Specifies type of a code block with additional info for some block types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockType {
    Join(bool), // internal value set to true when the first child is fully executed
    Split,
    Loop(bool), // internal value set to false if the loop is never entered
    Call,
    Dyn,
    Dyncall,
    SysCall,
    BasicBlock,
}
