use alloc::sync::Arc;
use core::ops::ControlFlow;

use miden_air::trace::{RowIndex, chiplets::hasher::HasherState};

use crate::{
    BreakReason, ContextId, ExecutionError, Felt, Host, MemoryError, Word,
    advice::AdviceError,
    crypto::merkle::MerklePath,
    errors::OperationError,
    mast::{BasicBlockNode, MastForest, MastNodeId},
    precompile::PrecompileTranscriptState,
};

// PROCESSOR
// ================================================================================================

/// Abstract definition of a processor's components: system, stack, advice provider, memory, hasher,
/// and operation helper register computation.
pub(crate) trait Processor: Sized {
    type System: SystemInterface;
    type Stack: StackInterface;
    type AdviceProvider: AdviceProviderInterface;
    type Memory: MemoryInterface;
    type Hasher: HasherInterface;

    /// Returns a reference to the internal stack.
    fn stack(&self) -> &Self::Stack;

    /// Returns a mutable reference to the internal stack.
    fn stack_mut(&mut self) -> &mut Self::Stack;

    /// Returns a reference to the internal system.
    fn system(&self) -> &Self::System;

    /// Returns a mutable reference to the internal system.
    fn system_mut(&mut self) -> &mut Self::System;

    /// Returns a reference to the internal advice provider.
    fn advice_provider(&self) -> &Self::AdviceProvider;

    /// Returns a mutable reference to the internal advice provider.
    fn advice_provider_mut(&mut self) -> &mut Self::AdviceProvider;

    /// Returns a mutable reference to the internal memory subsystem.
    fn memory_mut(&mut self) -> &mut Self::Memory;

    /// Returns a mutable reference to the internal hasher subsystem.
    fn hasher(&mut self) -> &mut Self::Hasher;

    /// Saves the current execution context and truncates the stack to 16 elements in preparation to
    /// start a new execution context.
    fn save_context_and_truncate_stack(&mut self);

    /// Restores the execution context to the state it was in before the last `call`, `syscall` or
    /// `dyncall. This includes restoring the overflow stack and the system parameters.
    fn restore_context(&mut self) -> Result<(), OperationError>;

    /// Returns the current precompile transcript state (sponge capacity).
    ///
    /// Used by `log_precompile` to thread the transcript across invocations.
    fn precompile_transcript_state(&self) -> PrecompileTranscriptState;

    /// Sets the precompile transcript state (sponge capacity) to a new value.
    ///
    /// Called by `log_precompile` after recording a new commitment.
    fn set_precompile_transcript_state(&mut self, state: PrecompileTranscriptState);

    /// Executes the decorators that should be executed before entering a node.
    fn execute_before_enter_decorators(
        &self,
        node_id: MastNodeId,
        current_forest: &MastForest,
        host: &mut impl Host,
    ) -> ControlFlow<BreakReason>;

    /// Executes the decorators that should be executed after exiting a node.
    fn execute_after_exit_decorators(
        &self,
        node_id: MastNodeId,
        current_forest: &MastForest,
        host: &mut impl Host,
    ) -> ControlFlow<BreakReason>;

    /// Executes any decorator in a basic block that is to be executed before the operation at the
    /// given index in the block.
    fn execute_decorators_for_op(
        &self,
        node_id: MastNodeId,
        op_idx_in_block: usize,
        current_forest: &MastForest,
        host: &mut impl Host,
    ) -> ControlFlow<BreakReason>;

    /// Executes any decorator in a basic block that is to be executed after all operations in the
    /// block. This only differs from `execute_after_exit_decorators` in that these decorators are
    /// stored in the basic block node itself.
    fn execute_end_of_block_decorators(
        &self,
        basic_block_node: &BasicBlockNode,
        node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        host: &mut impl Host,
    ) -> ControlFlow<BreakReason>;
}

// SYSTEM INTERFACE
// ================================================================================================

/// Trait representing the system state of the processor.
pub(crate) trait SystemInterface {
    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the value of the CALLER_HASH register, which is the hash of the procedure that
    /// called the currently executing procedure.
    fn caller_hash(&self) -> Word;

    /// Returns the current clock cycle.
    fn clock(&self) -> RowIndex;

    /// Returns the current context ID.
    fn ctx(&self) -> ContextId;

    // MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Sets the CALLER_HASH register to the provided value.
    fn set_caller_hash(&mut self, caller_hash: Word);

    /// Sets the current context ID to the provided value.
    fn set_ctx(&mut self, ctx: ContextId);

    // Increments the clock by 1.
    fn increment_clock(&mut self);
}

// STACK INTERFACE
// ================================================================================================

/// We model the stack as a slice of `Felt` values, where the top of the stack is at the last index
/// of the slice. The stack is mutable, and the processor can manipulate it directly. A "stack top
/// pointer" tracks the current top of the stack, which we define to be the top 16 elements. Indices
/// are always taken relative to the top element of the stack, meaning that `stack_get(0)` returns
/// the top element, `stack_get(1)` returns the second element from the top, and so on. The stack is
/// always at least 16 elements deep.
pub(crate) trait StackInterface {
    /// Returns the top 16 elements of the stack, such that the top of the stack is at the last
    /// index of the returned slice.
    fn top(&self) -> &[Felt];

    /// Returns the element on the stack at index `idx`.
    fn get(&self, idx: usize) -> Felt;

    /// Mutable variant of `stack_get()`.
    fn get_mut(&mut self, idx: usize) -> &mut Felt;

    /// Returns the word on the stack starting at index `start_idx` in "stack order".
    ///
    /// That is, for `start_idx=0` the top element of the stack will be at the last position in the
    /// word.
    ///
    /// For example, if the stack looks like this:
    ///
    /// top                                                       bottom
    /// v                                                           v
    /// a | b | c | d | e | f | g | h | i | j | k | l | m | n | o | p
    ///
    /// Then
    /// - `stack_get_word(0)` returns `[a, b, c, d]`,
    /// - `stack_get_word(1)` returns `[b, c, d, e]`,
    /// - etc.
    ///
    /// Word\[0\] corresponds to the top of stack.
    fn get_word(&self, start_idx: usize) -> Word;

    /// Returns two words (8 elements) from the stack starting at index `start_idx`.
    ///
    /// This is equivalent to reading 8 consecutive elements from the stack, or to reading the words
    /// as `Self::get_word(0)` and `Self::get_word(4)`.
    ///
    /// For example, if the stack looks like this:
    ///
    /// top                                                       bottom
    /// v                                                           v
    /// a | b | c | d | e | f | g | h | i | j | k | l | m | n | o | p
    ///
    /// Then `get_double_word(0)` returns `[a, b, c, d, e, f, g, h]`.
    fn get_double_word(&self, start_idx: usize) -> [Felt; 8] {
        core::array::from_fn(|i| self.get(start_idx + i))
    }

    /// Returns the number of elements on the stack in the current context.
    fn depth(&self) -> u32;

    /// Writes an element to the stack at the given index.
    fn set(&mut self, idx: usize, element: Felt);

    /// Writes a word to the stack starting at the given index.
    ///
    /// Word\[0\] goes to stack position start_idx (top), word\[1\] to start_idx+1, etc.
    fn set_word(&mut self, start_idx: usize, word: &Word);

    /// Swaps the elements at the given indices on the stack.
    fn swap(&mut self, idx1: usize, idx2: usize);

    /// Swaps the nth word from the top of the stack with the top word of the stack.
    ///
    /// Valid values of `n` are 1, 2, and 3.
    fn swapw_nth(&mut self, n: usize);

    /// Rotates the top `n` elements of the stack to the left by 1.
    ///
    /// For example, if the stack is [a, b, c, d], with `d` at the top, then `rotate_left(3)` will
    /// result in the top 3 elements being rotated left: [a, c, d, b].
    ///
    /// This operation is useful for implementing the `movup` instructions.
    ///
    /// The stack size doesn't change.
    ///
    /// Note: This method doesn't use the `get()` and `write()` methods because it is
    /// more efficient to directly manipulate the stack array (~10% performance difference).
    fn rotate_left(&mut self, n: usize);

    /// Rotates the top `n` elements of the stack to the right by 1.
    ///
    /// Analogous to `rotate_left`, but in the opposite direction.
    ///
    /// Note: This method doesn't use the `get()` and `write()` methods because it is
    /// more efficient to directly manipulate the stack array (~10% performance difference).
    fn rotate_right(&mut self, n: usize);

    /// Increments the stack top pointer by one, announcing the intent to add a new element to the
    /// stack. That is, the stack size is incremented, but the element is not written yet.
    ///
    /// This can be understood as pushing a `None` on top of the stack, such that a subsequent call
    /// to `write(0)` or `write_word(0)` will write an element to that new position.
    ///
    /// It is guaranteed that any operation that calls `increment_size()` will subsequently
    /// call `write(0)` or `write_word(0)` to write an element to that position on the
    /// stack.
    fn increment_size(&mut self) -> Result<(), ExecutionError>;

    /// Decrements the stack size by one, removing the top element from the stack.
    ///
    /// Concretely, this decrements the stack top pointer by one (removing the top element), and
    /// pushes a `ZERO` at the bottom of the stack if the stack size is already at 16 elements
    /// (since the stack size can never be less than 16).
    fn decrement_size(&mut self) -> Result<(), OperationError>;
}

// ADVICE PROVIDER INTERFACE
// ================================================================================================

/// Trait representing an advice provider for the processor.
pub(crate) trait AdviceProviderInterface {
    /// Pops an element from the advice stack and returns it.
    fn pop_stack(&mut self) -> Result<Felt, AdviceError>;

    /// Pops a word (4 elements) from the advice stack and returns it.
    ///
    /// Note: a word is popped off the stack element-by-element. For example, a `[d, c, b, a, ...]`
    /// stack (i.e., `d` is at the top of the stack) will yield `[d, c, b, a]`.
    ///
    /// # Errors
    /// Returns an error if the advice stack does not contain a full word.
    fn pop_stack_word(&mut self) -> Result<Word, AdviceError>;

    /// Pops a double word (8 elements) from the advice stack and returns them.
    ///
    /// Note: words are popped off the stack element-by-element. For example, a
    /// `[h, g, f, e, d, c, b, a, ...]` stack (i.e., `h` is at the top of the stack) will yield
    /// two words: `[h, g, f,e ], [d, c, b, a]`.
    fn pop_stack_dword(&mut self) -> Result<[Word; 2], AdviceError>;

    /// Returns a path to a node at the specified depth and index in a Merkle tree with the
    /// specified root.
    ///
    /// The returned Merkle path is behind an `Option` to support environments where there is no
    /// advice provider. The Merkle path is guaranteed to be provided to [HasherInterface] methods
    /// and otherwise ignored, and therefore `None` can be returned when combined with a
    /// [HasherInterface] implementation that ignores the Merkle path.
    fn get_merkle_path(
        &self,
        root: Word,
        depth: Felt,
        index: Felt,
    ) -> Result<Option<MerklePath>, AdviceError>;

    /// Updates a node at the specified depth and index in a Merkle tree with the specified root;
    /// returns the Merkle path from the updated node to the new root.
    ///
    /// The returned Merkle path is behind an `Option` to support environments where there is no
    /// advice provider. The Merkle path is guaranteed to be provided to [HasherInterface] methods
    /// and otherwise ignored, and therefore `None` can be returned when combined with a
    /// [HasherInterface] implementation that ignores the Merkle path.
    fn update_merkle_node(
        &mut self,
        root: Word,
        depth: Felt,
        index: Felt,
        value: Word,
    ) -> Result<Option<MerklePath>, AdviceError>;
}

// MEMORY INTERFACE
// ================================================================================================

/// Trait representing the memory subsystem of the processor.
pub(crate) trait MemoryInterface {
    /// Reads an element from memory at the provided address in the provided context.
    fn read_element(&mut self, ctx: ContextId, addr: Felt) -> Result<Felt, MemoryError>;

    /// Reads a word from memory starting at the provided address in the provided context.
    fn read_word(&mut self, ctx: ContextId, addr: Felt, clk: RowIndex)
    -> Result<Word, MemoryError>;

    /// Writes an element to memory at the provided address in the provided context.
    fn write_element(
        &mut self,
        ctx: ContextId,
        addr: Felt,
        element: Felt,
    ) -> Result<(), MemoryError>;

    /// Writes a word to memory starting at the provided address in the provided context.
    fn write_word(
        &mut self,
        ctx: ContextId,
        addr: Felt,
        clk: RowIndex,
        word: Word,
    ) -> Result<(), MemoryError>;
}

// HASHER INTERFACE
// ================================================================================================

/// Trait representing the hasher subsystem of the processor.
pub(crate) trait HasherInterface {
    /// Applies a single permutation of the hash function to the provided state and records the
    /// execution trace of this computation.
    ///
    /// The returned tuple contains the hasher state after the permutation and the row address of
    /// the execution trace at which the permutation started.
    ///
    /// The address is only needed for operation helpers in trace generation, and thus an
    /// implementation might choose to return a default/invalid address if it is not needed.
    fn permute(&mut self, state: HasherState) -> Result<(Felt, HasherState), OperationError>;

    /// Verifies that the `claimed_root` is indeed the root of a Merkle tree containing `value` at
    /// the specified `index`.
    ///
    /// Returns the address of the computation, defined as the row index of the Hasher chiplet trace
    /// at which the computation started.
    ///
    /// The Merkle path is guaranteed to be provided by [AdviceProviderInterface::get_merkle_path],
    /// and thus an implementation might choose to return `None` from `get_merkle_path`, and ignore
    /// it in this method.
    ///
    /// Additionally, the address is only needed for operation helpers in trace generation, and thus
    /// an implementation might choose to return a default/invalid address if it is not needed.
    fn verify_merkle_root(
        &mut self,
        claimed_root: Word,
        value: Word,
        path: Option<&MerklePath>,
        index: Felt,
        on_err: impl FnOnce() -> OperationError,
    ) -> Result<Felt, OperationError>;

    /// Verifies that the `claimed_old_root` is indeed the root of a Merkle tree containing
    /// `old_value` at the specified `index`, and computes a new Merkle root after updating the node
    /// at `index` to `new_value`.
    ///
    /// Returns the new root and the address of the computation, defined as the row index of the
    /// Hasher chiplet trace at which the computation started.
    ///
    /// The Merkle path is guaranteed to be provided by [AdviceProviderInterface::get_merkle_path],
    /// and thus an implementation might choose to return `None` from `get_merkle_path`, and ignore
    /// it in this method.
    ///
    /// Additionally, the address is only needed for operation helpers in trace generation, and thus
    /// an implementation might choose to return a default/invalid address if it is not needed.
    fn update_merkle_root(
        &mut self,
        claimed_old_root: Word,
        old_value: Word,
        new_value: Word,
        path: Option<&MerklePath>,
        index: Felt,
        on_err: impl FnOnce() -> OperationError,
    ) -> Result<(Felt, Word), OperationError>;
}
