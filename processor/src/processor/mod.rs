use miden_air::{
    RowIndex,
    trace::{chiplets::hasher::HasherState, decoder::NUM_USER_OP_HELPERS},
};
use miden_core::{Felt, Operation, QuadFelt, Word, crypto::merkle::MerklePath, mast::MastForest};

use crate::{
    AdviceError, BaseHost, ContextId, ErrorContext, ExecutionError, MemoryError, ProcessState,
    fast::Tracer, processor::operations::execute_sync_op,
};

mod operations;

/// Processor abstraction for executing Miden VM programs.
pub trait Processor: Sized {
    type System: SystemInterface;
    type Stack: StackInterface;
    type AdviceProvider: AdviceProviderInterface;
    type Memory: MemoryInterface;
    type Hasher: HasherInterface;
    type HelperRegisters: OperationHelperRegisters;

    // -------------------------------------------------------------------------------------------
    // REQUIRED METHODS
    // -------------------------------------------------------------------------------------------

    /// Returns a mutable reference to the internal stack.
    fn stack(&mut self) -> &mut Self::Stack;

    /// Returns a mutable reference to the internal system.
    fn system(&mut self) -> &mut Self::System;

    /// Returns a [ProcessState] referring to the current process state.
    fn state(&mut self) -> ProcessState<'_>;

    /// Returns a mutable reference to the internal advice provider.
    fn advice_provider(&mut self) -> &mut Self::AdviceProvider;

    /// Returns a mutable reference to the internal memory subsystem.
    fn memory(&mut self) -> &mut Self::Memory;

    /// Returns a mutable reference to the internal hasher subsystem.
    fn hasher(&mut self) -> &mut Self::Hasher;

    /// Checks that the evaluation of an arithmetic circuit is equal to zero.
    fn op_eval_circuit(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError>;

    // -------------------------------------------------------------------------------------------
    // PROVIDED METHODS
    // -------------------------------------------------------------------------------------------

    /// Executes the provided synchronous operation.
    ///
    /// This excludes `Emit`, which must be executed asynchronously, as well as control flow
    /// operations, which are never executed directly.
    ///
    /// # Panics
    /// - If a control flow operation is provided.
    /// - If an `Emit` operation is provided.
    fn execute_sync_op(
        &mut self,
        op: &Operation,
        op_idx_in_block: usize,
        current_forest: &MastForest,
        host: &mut impl BaseHost,
        err_ctx: &impl ErrorContext,
        tracer: &mut impl Tracer,
    ) -> Result<Option<[Felt; NUM_USER_OP_HELPERS]>, ExecutionError> {
        execute_sync_op(self, op, op_idx_in_block, current_forest, host, err_ctx, tracer)
    }
}

/// Trait representing the system state of the processor.
pub trait SystemInterface {
    /// Returns the value of the CALLER_HASH register, which is the hash of the procedure that
    /// called the currently executing procedure.
    fn caller_hash(&self) -> Word;

    /// Returns true if the processor is currently executing a syscall, false otherwise.
    fn in_syscall(&self) -> bool;

    /// Returns the current clock cycle.
    fn clk(&self) -> RowIndex;

    /// Returns the current context ID.
    fn ctx(&self) -> ContextId;

    /// Returns the current value of the FMP register.
    fn fmp(&self) -> Felt;

    /// Sets the FMP register to a new value.
    fn set_fmp(&mut self, new_fmp: Felt);
}

/// We model the stack as a slice of `Felt` values, where the top of the stack is at the last index
/// of the slice. The stack is mutable, and the processor can manipulate it directly. A "stack top
/// pointer" tracks the current top of the stack, which we define to be the top 16 elements. Indices
/// are always taken relative to the top element of the stack, meaning that `stack_get(0)` returns
/// the top element, `stack_get(1)` returns the second element from the top, and so on. The stack is
/// always at least 16 elements deep.
pub trait StackInterface {
    /// Returns the top 16 elements of the stack, such that the top of the stack is at the last
    /// index of the returned slice.
    fn top(&self) -> &[Felt];

    /// Returns a mutable reference to the top 16 elements of the stack, such that the top of the
    /// stack is at the last index of the returned slice.
    fn top_mut(&mut self) -> &mut [Felt];

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
    /// - `stack_get_word(0)` returns `[d, c, b, a]`,
    /// - `stack_get_word(1)` returns `[e, d, c ,b]`,
    /// - etc.
    fn get_word(&self, start_idx: usize) -> Word;

    /// Returns the number of elements on the stack in the current context.
    fn depth(&self) -> u32;

    /// Writes an element to the stack at the given index.
    fn set(&mut self, idx: usize, element: Felt);

    /// Writes a word to the stack starting at the given index.
    ///
    /// The index is the index of the first element of the word, and the word is written in reverse
    /// order.
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
    fn increment_size(&mut self, tracer: &mut impl Tracer) -> Result<(), ExecutionError>;

    /// Decrements the stack size by one, removing the top element from the stack.
    ///
    /// Concretely, this decrements the stack top pointer by one (removing the top element), and
    /// pushes a `ZERO` at the bottom of the stack if the stack size is already at 16 elements
    /// (since the stack size can never be less than 16).
    fn decrement_size(&mut self, tracer: &mut impl Tracer);
}

/// Trait representing an advice provider for the processor.
pub trait AdviceProviderInterface {
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
        depth: &Felt,
        index: &Felt,
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
        depth: &Felt,
        index: &Felt,
        value: Word,
    ) -> Result<Option<MerklePath>, AdviceError>;
}

/// Trait representing the memory subsystem of the processor.
pub trait MemoryInterface {
    /// Reads an element from memory at the provided address in the provided context.
    fn read_element(
        &mut self,
        ctx: ContextId,
        addr: Felt,
        err_ctx: &impl ErrorContext,
    ) -> Result<Felt, MemoryError>;

    /// Reads a word from memory starting at the provided address in the provided context.
    fn read_word(
        &mut self,
        ctx: ContextId,
        addr: Felt,
        clk: RowIndex,
        err_ctx: &impl ErrorContext,
    ) -> Result<Word, MemoryError>;

    /// Writes an element to memory at the provided address in the provided context.
    fn write_element(
        &mut self,
        ctx: ContextId,
        addr: Felt,
        element: Felt,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), MemoryError>;

    /// Writes a word to memory starting at the provided address in the provided context.
    fn write_word(
        &mut self,
        ctx: ContextId,
        addr: Felt,
        clk: RowIndex,
        word: Word,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), MemoryError>;
}

/// Trait representing the hasher subsystem of the processor.
pub trait HasherInterface {
    /// Applies a single permutation of the hash function to the provided state and records the
    /// execution trace of this computation.
    ///
    /// The returned tuple contains the hasher state after the permutation and the row address of
    /// the execution trace at which the permutation started.
    ///
    /// The address is only needed for operation helpers in trace generation, and thus an
    /// implementation might choose to return a default/invalid address if it is not needed.
    fn permute(&mut self, state: HasherState) -> (Felt, HasherState);

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
        on_err: impl FnOnce() -> ExecutionError,
    ) -> Result<Felt, ExecutionError>;

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
        on_err: impl FnOnce() -> ExecutionError,
    ) -> Result<(Felt, Word), ExecutionError>;
}

/// Trait for computing helper registers for operations.
///
/// Concretely, the fast processor does not compute any helper registers, and thus returns a default
/// value (all zeros). On the other hand, the trace generation helpers compute the actual helper
/// registers to be included in the trace.
pub trait OperationHelperRegisters {
    /// The helper registers for the Eq operation.
    fn op_eq_registers(a: Felt, b: Felt) -> [Felt; NUM_USER_OP_HELPERS];

    /// The helper registers for the U32split operation.
    fn op_u32split_registers(hi: Felt, lo: Felt) -> [Felt; NUM_USER_OP_HELPERS];

    /// The helper registers for the Eqz operation.
    fn op_eqz_registers(top: Felt) -> [Felt; NUM_USER_OP_HELPERS];

    /// The helper registers for the Expacc operation.
    fn op_expacc_registers(acc_update_val: Felt) -> [Felt; NUM_USER_OP_HELPERS];

    /// The helper registers for the FriExt2Fold4 operation.
    fn op_fri_ext2fold4_registers(
        ev: QuadFelt,
        es: QuadFelt,
        x: Felt,
        x_inv: Felt,
    ) -> [Felt; NUM_USER_OP_HELPERS];

    /// The helper registers for the U32add operation.
    fn op_u32add_registers(hi: Felt, lo: Felt) -> [Felt; NUM_USER_OP_HELPERS];

    /// The helper registers for the U32add3 operation.
    fn op_u32add3_registers(hi: Felt, lo: Felt) -> [Felt; NUM_USER_OP_HELPERS];

    /// The helper registers for the U32sub operation.
    fn op_u32sub_registers(second_new: Felt) -> [Felt; NUM_USER_OP_HELPERS];

    /// The helper registers for the U32mul operation.
    fn op_u32mul_registers(hi: Felt, lo: Felt) -> [Felt; NUM_USER_OP_HELPERS];

    /// The helper registers for the U32madd operation.
    fn op_u32madd_registers(hi: Felt, lo: Felt) -> [Felt; NUM_USER_OP_HELPERS];

    /// The helper registers for the U32div operation.
    fn op_u32div_registers(
        numerator: u64,
        quotient: u64,
        denominator: u64,
        remainder: u64,
    ) -> [Felt; NUM_USER_OP_HELPERS];

    /// The helper registers for the U32assert2 operation.
    fn op_u32assert2_registers(first: Felt, second: Felt) -> [Felt; NUM_USER_OP_HELPERS];

    /// The helper registers for the HPerm operation.
    fn op_hperm_registers(addr: Felt) -> [Felt; NUM_USER_OP_HELPERS];

    /// The helper registers for the MPVerify and MrUpdate operation.
    fn op_merkle_path_registers(addr: Felt) -> [Felt; NUM_USER_OP_HELPERS];

    /// The helper registers for the HornerEvalBase and HornerEvalExt operations.
    fn op_horner_eval_registers(
        alpha: QuadFelt,
        k0: Felt,
        k1: Felt,
        acc_tmp: QuadFelt,
    ) -> [Felt; NUM_USER_OP_HELPERS];
}
