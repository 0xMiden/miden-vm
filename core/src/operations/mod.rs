use core::fmt;

use miden_crypto::field::PrimeField64;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

mod decorators;
pub use decorators::{AssemblyOp, DebugOptions, Decorator, DecoratorList};
use opcode_constants::*;

use crate::{
    Felt,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// OPERATIONS OP CODES
// ================================================================================================

/// Opcode patterns have the following meanings:
/// - 00xxxxx operations do not shift the stack; constraint degree can be up to 2.
/// - 010xxxx operations shift the stack the left; constraint degree can be up to 2.
/// - 011xxxx operations shift the stack to the right; constraint degree can be up to 2.
/// - 100xxx-: operations consume 4 range checks; constraint degree can be up to 3. These are used
///   to encode most u32 operations.
/// - 101xxx-: operations where constraint degree can be up to 3. These include control flow
///   operations and some other operations requiring high degree constraints.
/// - 11xxx--: operations where constraint degree can be up to 5. These include control flow
///   operations and some other operations requiring very high degree constraints.
#[rustfmt::skip]
pub(super) mod opcode_constants {
    pub const OPCODE_NOOP: u8           = 0b0000_0000;
    pub const OPCODE_EQZ: u8            = 0b0000_0001;
    pub const OPCODE_NEG: u8            = 0b0000_0010;
    pub const OPCODE_INV: u8            = 0b0000_0011;
    pub const OPCODE_INCR: u8           = 0b0000_0100;
    pub const OPCODE_NOT: u8            = 0b0000_0101;
    /* unused                             0b0000_0110 */
    pub const OPCODE_MLOAD: u8          = 0b0000_0111;
    pub const OPCODE_SWAP: u8           = 0b0000_1000;
    pub const OPCODE_CALLER: u8         = 0b0000_1001;
    pub const OPCODE_MOVUP2: u8         = 0b0000_1010;
    pub const OPCODE_MOVDN2: u8         = 0b0000_1011;
    pub const OPCODE_MOVUP3: u8         = 0b0000_1100;
    pub const OPCODE_MOVDN3: u8         = 0b0000_1101;
    pub const OPCODE_ADVPOPW: u8        = 0b0000_1110;
    pub const OPCODE_EXPACC: u8         = 0b0000_1111;

    pub const OPCODE_MOVUP4: u8         = 0b0001_0000;
    pub const OPCODE_MOVDN4: u8         = 0b0001_0001;
    pub const OPCODE_MOVUP5: u8         = 0b0001_0010;
    pub const OPCODE_MOVDN5: u8         = 0b0001_0011;
    pub const OPCODE_MOVUP6: u8         = 0b0001_0100;
    pub const OPCODE_MOVDN6: u8         = 0b0001_0101;
    pub const OPCODE_MOVUP7: u8         = 0b0001_0110;
    pub const OPCODE_MOVDN7: u8         = 0b0001_0111;
    pub const OPCODE_SWAPW: u8          = 0b0001_1000;
    pub const OPCODE_EXT2MUL: u8        = 0b0001_1001;
    pub const OPCODE_MOVUP8: u8         = 0b0001_1010;
    pub const OPCODE_MOVDN8: u8         = 0b0001_1011;
    pub const OPCODE_SWAPW2: u8         = 0b0001_1100;
    pub const OPCODE_SWAPW3: u8         = 0b0001_1101;
    pub const OPCODE_SWAPDW: u8         = 0b0001_1110;
    pub const OPCODE_EMIT: u8           = 0b0001_1111;

    pub const OPCODE_ASSERT: u8         = 0b0010_0000;
    pub const OPCODE_EQ: u8             = 0b0010_0001;
    pub const OPCODE_ADD: u8            = 0b0010_0010;
    pub const OPCODE_MUL: u8            = 0b0010_0011;
    pub const OPCODE_AND: u8            = 0b0010_0100;
    pub const OPCODE_OR: u8             = 0b0010_0101;
    pub const OPCODE_U32AND: u8         = 0b0010_0110;
    pub const OPCODE_U32XOR: u8         = 0b0010_0111;
    pub const OPCODE_FRIE2F4: u8        = 0b0010_1000;
    pub const OPCODE_DROP: u8           = 0b0010_1001;
    pub const OPCODE_CSWAP: u8          = 0b0010_1010;
    pub const OPCODE_CSWAPW: u8         = 0b0010_1011;
    pub const OPCODE_MLOADW: u8         = 0b0010_1100;
    pub const OPCODE_MSTORE: u8         = 0b0010_1101;
    pub const OPCODE_MSTOREW: u8        = 0b0010_1110;
    /* unused                             0b0010_1111 */

    pub const OPCODE_PAD: u8            = 0b0011_0000;
    pub const OPCODE_DUP0: u8           = 0b0011_0001;
    pub const OPCODE_DUP1: u8           = 0b0011_0010;
    pub const OPCODE_DUP2: u8           = 0b0011_0011;
    pub const OPCODE_DUP3: u8           = 0b0011_0100;
    pub const OPCODE_DUP4: u8           = 0b0011_0101;
    pub const OPCODE_DUP5: u8           = 0b0011_0110;
    pub const OPCODE_DUP6: u8           = 0b0011_0111;
    pub const OPCODE_DUP7: u8           = 0b0011_1000;
    pub const OPCODE_DUP9: u8           = 0b0011_1001;
    pub const OPCODE_DUP11: u8          = 0b0011_1010;
    pub const OPCODE_DUP13: u8          = 0b0011_1011;
    pub const OPCODE_DUP15: u8          = 0b0011_1100;
    pub const OPCODE_ADVPOP: u8         = 0b0011_1101;
    pub const OPCODE_SDEPTH: u8         = 0b0011_1110;
    pub const OPCODE_CLK: u8            = 0b0011_1111;

    pub const OPCODE_U32ADD: u8         = 0b0100_0000;
    pub const OPCODE_U32SUB: u8         = 0b0100_0010;
    pub const OPCODE_U32MUL: u8         = 0b0100_0100;
    pub const OPCODE_U32DIV: u8         = 0b0100_0110;
    pub const OPCODE_U32SPLIT: u8       = 0b0100_1000;
    pub const OPCODE_U32ASSERT2: u8     = 0b0100_1010;
    pub const OPCODE_U32ADD3: u8        = 0b0100_1100;
    pub const OPCODE_U32MADD: u8        = 0b0100_1110;

    pub const OPCODE_HPERM: u8          = 0b0101_0000;
    pub const OPCODE_MPVERIFY: u8       = 0b0101_0001;
    pub const OPCODE_PIPE: u8           = 0b0101_0010;
    pub const OPCODE_MSTREAM: u8        = 0b0101_0011;
    pub const OPCODE_SPLIT: u8          = 0b0101_0100;
    pub const OPCODE_LOOP: u8           = 0b0101_0101;
    pub const OPCODE_SPAN: u8           = 0b0101_0110;
    pub const OPCODE_JOIN: u8           = 0b0101_0111;
    pub const OPCODE_DYN: u8            = 0b0101_1000;
    pub const OPCODE_HORNERBASE: u8     = 0b0101_1001;
    pub const OPCODE_HORNEREXT: u8      = 0b0101_1010;
    pub const OPCODE_PUSH: u8           = 0b0101_1011;
    pub const OPCODE_DYNCALL: u8        = 0b0101_1100;
    pub const OPCODE_EVALCIRCUIT: u8    = 0b0101_1101;
    pub const OPCODE_LOGPRECOMPILE: u8  = 0b0101_1110;

    pub const OPCODE_MRUPDATE: u8       = 0b0110_0000;
    pub const OPCODE_CRYPTOSTREAM: u8   = 0b0110_0100;
    pub const OPCODE_SYSCALL: u8        = 0b0110_1000;
    pub const OPCODE_CALL: u8           = 0b0110_1100;
    pub const OPCODE_END: u8            = 0b0111_0000;
    pub const OPCODE_REPEAT: u8         = 0b0111_0100;
    pub const OPCODE_RESPAN: u8         = 0b0111_1000;
    pub const OPCODE_HALT: u8           = 0b0111_1100;
}

// OPERATIONS
// ================================================================================================

/// A set of native VM operations which take exactly one cycle to execute.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum Operation {
    // ----- system operations -------------------------------------------------------------------
    /// Advances cycle counter, but does not change the state of user stack.
    Noop = OPCODE_NOOP,

    /// Pops the stack; if the popped value is not 1, execution fails.
    ///
    /// The internal value specifies an error code associated with the error in case when the
    /// execution fails.
    Assert(Felt) = OPCODE_ASSERT,

    /// Pushes the current depth of the stack onto the stack.
    SDepth = OPCODE_SDEPTH,

    /// Overwrites the top four stack items with the hash of a function which initiated the current
    /// SYSCALL. Thus, this operation can be executed only inside a SYSCALL code block.
    Caller = OPCODE_CALLER,

    /// Pushes the current value of the clock cycle onto the stack. This operation can be used to
    /// measure the number of cycles it has taken to execute the program up to the current
    /// instruction.
    Clk = OPCODE_CLK,

    /// Emits an event to the host.
    ///
    /// Semantics:
    /// - Reads the event id from the top of the stack (as a `Felt`) without consuming it; the
    ///   caller is responsible for pushing and later dropping the id.
    /// - User-defined events are conventionally derived from strings via
    ///   `hash_string_to_word(name)[0]` (Blake3-based) and may be emitted via immediate forms in
    ///   assembly (`emit.event("...")` or `emit.CONST` where `CONST=event("...")`).
    /// - System events are still identified by specific 32-bit codes; the VM attempts to interpret
    ///   the stack `Felt` as `u32` to dispatch known system events, and otherwise forwards the
    ///   event to the host.
    ///
    /// This operation does not change the state of the user stack aside from reading the value.
    Emit = OPCODE_EMIT,

    // ----- flow control operations -------------------------------------------------------------
    /// Marks the beginning of a join block.
    Join = OPCODE_JOIN,

    /// Marks the beginning of a split block.
    Split = OPCODE_SPLIT,

    /// Marks the beginning of a loop block.
    Loop = OPCODE_LOOP,

    /// Marks the beginning of a function call.
    Call = OPCODE_CALL,

    /// Marks the beginning of a dynamic code block, where the target is specified by the stack.
    Dyn = OPCODE_DYN,

    /// Marks the beginning of a dynamic function call, where the target is specified by the stack.
    Dyncall = OPCODE_DYNCALL,

    /// Marks the beginning of a kernel call.
    SysCall = OPCODE_SYSCALL,

    /// Marks the beginning of a span code block.
    Span = OPCODE_SPAN,

    /// Marks the end of a program block.
    End = OPCODE_END,

    /// Indicates that body of an executing loop should be executed again.
    Repeat = OPCODE_REPEAT,

    /// Starts processing a new operation batch.
    Respan = OPCODE_RESPAN,

    /// Indicates the end of the program. This is used primarily to pad the execution trace to
    /// the required length. Once HALT operation is executed, no other operations can be executed
    /// by the VM (HALT operation itself excepted).
    Halt = OPCODE_HALT,

    // ----- field operations --------------------------------------------------------------------
    /// Pops two elements off the stack, adds them, and pushes the result back onto the stack.
    Add = OPCODE_ADD,

    /// Pops an element off the stack, negates it, and pushes the result back onto the stack.
    Neg = OPCODE_NEG,

    /// Pops two elements off the stack, multiplies them, and pushes the result back onto the
    /// stack.
    Mul = OPCODE_MUL,

    /// Pops an element off the stack, computes its multiplicative inverse, and pushes the result
    /// back onto the stack.
    Inv = OPCODE_INV,

    /// Pops an element off the stack, adds 1 to it, and pushes the result back onto the stack.
    Incr = OPCODE_INCR,

    /// Pops two elements off the stack, multiplies them, and pushes the result back onto the
    /// stack.
    ///
    /// If either of the elements is greater than 1, execution fails. This operation is equivalent
    /// to boolean AND.
    And = OPCODE_AND,

    /// Pops two elements off the stack and subtracts their product from their sum.
    ///
    /// If either of the elements is greater than 1, execution fails. This operation is equivalent
    /// to boolean OR.
    Or = OPCODE_OR,

    /// Pops an element off the stack and subtracts it from 1.
    ///
    /// If the element is greater than one, the execution fails. This operation is equivalent to
    /// boolean NOT.
    Not = OPCODE_NOT,

    /// Pops two elements off the stack and compares them. If the elements are equal, pushes 1
    /// onto the stack, otherwise pushes 0 onto the stack.
    Eq = OPCODE_EQ,

    /// Pops an element off the stack and compares it to 0. If the element is 0, pushes 1 onto
    /// the stack, otherwise pushes 0 onto the stack.
    Eqz = OPCODE_EQZ,

    /// Computes a single turn of exponent accumulation for the given inputs. This operation can be
    /// be used to compute a single turn of power of a field element.
    ///
    /// The top 4 elements of the stack are expected to be arranged as follows (form the top):
    /// - least significant bit of the exponent in the previous trace if there's an expacc call,
    ///   otherwise ZERO
    /// - exponent of base number `a` for this turn
    /// - accumulated power of base number `a` so far
    /// - number which needs to be shifted to the right
    ///
    /// At the end of the operation, exponent is replaced with its square, current value of power
    /// of base number `a` on exponent is incorporated into the accumulator and the number is
    /// shifted to the right by one bit.
    Expacc = OPCODE_EXPACC,

    // ----- ext2 operations ---------------------------------------------------------------------
    /// Computes the product of two elements in the extension field of degree 2 and pushes the
    /// result back onto the stack as the third and fourth elements. Pushes 0 onto the stack as
    /// the first and second elements.
    ///
    /// The extension field is defined as 𝔽ₚ\[x\]/(x² - x + 2), i.e. using the
    /// irreducible quadratic polynomial x² - x + 2 over the base field.
    Ext2Mul = OPCODE_EXT2MUL,

    // ----- u32 operations ----------------------------------------------------------------------
    /// Pops an element off the stack, splits it into upper and lower 32-bit values, and pushes
    /// these values back onto the stack.
    U32split = OPCODE_U32SPLIT,

    /// Pops two elements off the stack, adds them, and splits the result into upper and lower
    /// 32-bit values. Then pushes these values back onto the stack.
    ///
    /// If either of these elements is greater than or equal to 2^32, the result of this
    /// operation is undefined.
    U32add = OPCODE_U32ADD,

    /// Pops two elements off the stack and checks if each of them represents a 32-bit value.
    /// If both of them are, they are pushed back onto the stack, otherwise an error is returned.
    ///
    /// The internal value specifies an error code associated with the error in case when the
    /// assertion fails.
    U32assert2(Felt) = OPCODE_U32ASSERT2,

    /// Pops three elements off the stack, adds them together, and splits the result into upper
    /// and lower 32-bit values. Then pushes the result back onto the stack.
    U32add3 = OPCODE_U32ADD3,

    /// Pops two elements off the stack and subtracts the first element from the second. Then,
    /// the result, together with a flag indicating whether subtraction underflowed is pushed
    /// onto the stack.
    ///
    /// If their of the values is greater than or equal to 2^32, the result of this operation is
    /// undefined.
    U32sub = OPCODE_U32SUB,

    /// Pops two elements off the stack, multiplies them, and splits the result into upper and
    /// lower 32-bit values. Then pushes these values back onto the stack.
    ///
    /// If their of the values is greater than or equal to 2^32, the result of this operation is
    /// undefined.
    U32mul = OPCODE_U32MUL,

    /// Pops two elements off the stack and multiplies them. Then pops the third element off the
    /// stack, and adds it to the result. Finally, splits the result into upper and lower 32-bit
    /// values, and pushes them onto the stack.
    ///
    /// If any of the three values is greater than or equal to 2^32, the result of this operation
    /// is undefined.
    U32madd = OPCODE_U32MADD,

    /// Pops two elements off the stack and divides the second element by the first. Then pushes
    /// the integer result of the division, together with the remainder, onto the stack.
    ///
    /// If their of the values is greater than or equal to 2^32, the result of this operation is
    /// undefined.
    U32div = OPCODE_U32DIV,

    /// Pops two elements off the stack, computes their binary AND, and pushes the result back
    /// onto the stack.
    ///
    /// If either of the elements is greater than or equal to 2^32, execution fails.
    U32and = OPCODE_U32AND,

    /// Pops two elements off the stack, computes their binary XOR, and pushes the result back
    /// onto the stack.
    ///
    /// If either of the elements is greater than or equal to 2^32, execution fails.
    U32xor = OPCODE_U32XOR,

    // ----- stack manipulation ------------------------------------------------------------------
    /// Pushes 0 onto the stack.
    Pad = OPCODE_PAD,

    /// Removes to element from the stack.
    Drop = OPCODE_DROP,

    /// Pushes a copy of stack element 0 onto the stack.
    Dup0 = OPCODE_DUP0,

    /// Pushes a copy of stack element 1 onto the stack.
    Dup1 = OPCODE_DUP1,

    /// Pushes a copy of stack element 2 onto the stack.
    Dup2 = OPCODE_DUP2,

    /// Pushes a copy of stack element 3 onto the stack.
    Dup3 = OPCODE_DUP3,

    /// Pushes a copy of stack element 4 onto the stack.
    Dup4 = OPCODE_DUP4,

    /// Pushes a copy of stack element 5 onto the stack.
    Dup5 = OPCODE_DUP5,

    /// Pushes a copy of stack element 6 onto the stack.
    Dup6 = OPCODE_DUP6,

    /// Pushes a copy of stack element 7 onto the stack.
    Dup7 = OPCODE_DUP7,

    /// Pushes a copy of stack element 9 onto the stack.
    Dup9 = OPCODE_DUP9,

    /// Pushes a copy of stack element 11 onto the stack.
    Dup11 = OPCODE_DUP11,

    /// Pushes a copy of stack element 13 onto the stack.
    Dup13 = OPCODE_DUP13,

    /// Pushes a copy of stack element 15 onto the stack.
    Dup15 = OPCODE_DUP15,

    /// Swaps stack elements 0 and 1.
    Swap = OPCODE_SWAP,

    /// Swaps stack elements 0, 1, 2, and 3 with elements 4, 5, 6, and 7.
    SwapW = OPCODE_SWAPW,

    /// Swaps stack elements 0, 1, 2, and 3 with elements 8, 9, 10, and 11.
    SwapW2 = OPCODE_SWAPW2,

    /// Swaps stack elements 0, 1, 2, and 3, with elements 12, 13, 14, and 15.
    SwapW3 = OPCODE_SWAPW3,

    /// Swaps the top two words pair wise.
    ///
    /// Input: [D, C, B, A, ...]
    /// Output: [B, A, D, C, ...]
    SwapDW = OPCODE_SWAPDW,

    /// Moves stack element 2 to the top of the stack.
    MovUp2 = OPCODE_MOVUP2,

    /// Moves stack element 3 to the top of the stack.
    MovUp3 = OPCODE_MOVUP3,

    /// Moves stack element 4 to the top of the stack.
    MovUp4 = OPCODE_MOVUP4,

    /// Moves stack element 5 to the top of the stack.
    MovUp5 = OPCODE_MOVUP5,

    /// Moves stack element 6 to the top of the stack.
    MovUp6 = OPCODE_MOVUP6,

    /// Moves stack element 7 to the top of the stack.
    MovUp7 = OPCODE_MOVUP7,

    /// Moves stack element 8 to the top of the stack.
    MovUp8 = OPCODE_MOVUP8,

    /// Moves the top stack element to position 2 on the stack.
    MovDn2 = OPCODE_MOVDN2,

    /// Moves the top stack element to position 3 on the stack.
    MovDn3 = OPCODE_MOVDN3,

    /// Moves the top stack element to position 4 on the stack.
    MovDn4 = OPCODE_MOVDN4,

    /// Moves the top stack element to position 5 on the stack.
    MovDn5 = OPCODE_MOVDN5,

    /// Moves the top stack element to position 6 on the stack.
    MovDn6 = OPCODE_MOVDN6,

    /// Moves the top stack element to position 7 on the stack.
    MovDn7 = OPCODE_MOVDN7,

    /// Moves the top stack element to position 8 on the stack.
    MovDn8 = OPCODE_MOVDN8,

    /// Pops an element off the stack, and if the element is 1, swaps the top two remaining
    /// elements on the stack. If the popped element is 0, the stack remains unchanged.
    ///
    /// If the popped element is neither 0 nor 1, execution fails.
    CSwap = OPCODE_CSWAP,

    /// Pops an element off the stack, and if the element is 1, swaps the remaining elements
    /// 0, 1, 2, and 3 with elements 4, 5, 6, and 7. If the popped element is 0, the stack
    /// remains unchanged.
    ///
    /// If the popped element is neither 0 nor 1, execution fails.
    CSwapW = OPCODE_CSWAPW,

    // ----- input / output ----------------------------------------------------------------------
    /// Pushes the immediate value onto the stack.
    Push(Felt) = OPCODE_PUSH,

    /// Removes the next element from the advice stack and pushes it onto the operand stack.
    AdvPop = OPCODE_ADVPOP,

    /// Removes a word (4 elements) from the advice stack and overwrites the top four operand
    /// stack elements with it.
    AdvPopW = OPCODE_ADVPOPW,

    /// Pops an element off the stack, interprets it as a memory address, and replaces the
    /// remaining 4 elements at the top of the stack with values located at the specified address.
    MLoadW = OPCODE_MLOADW,

    /// Pops an element off the stack, interprets it as a memory address, and writes the remaining
    /// 4 elements at the top of the stack into memory at the specified address.
    MStoreW = OPCODE_MSTOREW,

    /// Pops an element off the stack, interprets it as a memory address, and pushes the first
    /// element of the word located at the specified address to the stack.
    MLoad = OPCODE_MLOAD,

    /// Pops an element off the stack, interprets it as a memory address, and writes the remaining
    /// element at the top of the stack into the first element of the word located at the specified
    /// memory address. The remaining 3 elements of the word are not affected.
    MStore = OPCODE_MSTORE,

    /// Loads two words from memory, and replaces the top 8 elements of the stack with them,
    /// element-wise, in stack order.
    ///
    /// The operation works as follows:
    /// - The memory address of the first word is retrieved from 13th stack element (position 12).
    /// - Two consecutive words, starting at this address, are loaded from memory.
    /// - The top 8 elements of the stack are overwritten with these words (element-wise, in stack
    ///   order).
    /// - Memory address (in position 12) is incremented by 2.
    /// - All other stack elements remain the same.
    MStream = OPCODE_MSTREAM,

    /// Pops two words from the advice stack, writes them to memory, and replaces the top 8
    /// elements of the stack with them, element-wise, in stack order.
    ///
    /// The operation works as follows:
    /// - Two words are popped from the advice stack.
    /// - The destination memory address for the first word is retrieved from the 13th stack element
    ///   (position 12).
    /// - The two words are written to memory consecutively, starting at this address.
    /// - The top 8 elements of the stack are overwritten with these words (element-wise, in stack
    ///   order).
    /// - Memory address (in position 12) is incremented by 2.
    /// - All other stack elements remain the same.
    Pipe = OPCODE_PIPE,

    /// Encrypts data from source memory to destination memory using the Poseidon2 sponge keystream.
    ///
    /// Two consecutive words (8 elements) are loaded from source memory, each element is added
    /// to the corresponding element in the rate (top 8 stack elements), and the resulting
    /// ciphertext is written to destination memory and replaces the rate. Source and destination
    /// addresses are incremented by 8.
    ///
    /// Stack transition:
    /// ```text
    /// [rate(8), cap(4), src, dst, ...]
    ///     ↓
    /// [ct(8), cap(4), src+8, dst+8, ...]
    /// ```
    /// where `ct = mem[src..src+8] + rate`, where addition is element-wise.
    ///
    /// After this operation, `hperm` should be applied to refresh the keystream for the next block.
    CryptoStream = OPCODE_CRYPTOSTREAM,

    // ----- cryptographic operations ------------------------------------------------------------
    /// Performs a Poseidon2 permutation on the top 3 words of the operand stack,
    /// where the top 2 words are the rate (words C and B), the deepest word is the capacity (word
    /// A), and the digest output is the middle word E.
    ///
    /// Stack transition:
    /// [C, B, A, ...] -> [F, E, D, ...]
    HPerm = OPCODE_HPERM,

    /// Verifies that a Merkle path from the specified node resolves to the specified root. This
    /// operation can be used to prove that the prover knows a path in the specified Merkle tree
    /// which starts with the specified node.
    ///
    /// The stack is expected to be arranged as follows (from the top):
    /// - value of the node, 4 elements.
    /// - depth of the path, 1 element.
    /// - index of the node, 1 element.
    /// - root of the tree, 4 elements.
    ///
    /// The Merkle path itself is expected to be provided by the prover non-deterministically (via
    /// merkle sets). If the prover is not able to provide the required path, the operation fails.
    /// The state of the stack does not change.
    ///
    /// The internal value specifies an error code associated with the error in case when the
    /// assertion fails.
    MpVerify(Felt) = OPCODE_MPVERIFY,

    /// Computes a new root of a Merkle tree where a node at the specified position is updated to
    /// the specified value.
    ///
    /// The stack is expected to be arranged as follows (from the top):
    /// - old value of the node, 4 element
    /// - depth of the node, 1 element
    /// - index of the node, 1 element
    /// - current root of the tree, 4 elements
    /// - new value of the node, 4 element
    ///
    /// The Merkle path for the node is expected to be provided by the prover non-deterministically
    /// via the advice provider. At the end of the operation, the old node value is replaced with
    /// the new root value, that is computed based on the provided path. Everything else on the
    /// stack remains the same.
    ///
    /// The tree will always be copied into a new instance, meaning the advice provider will keep
    /// track of both the old and new Merkle trees.
    MrUpdate = OPCODE_MRUPDATE,

    /// Performs FRI (Fast Reed-Solomon Interactive Oracle Proofs) layer folding by a factor of 4
    /// for FRI protocol executed in a degree 2 extension of the base field.
    ///
    /// This operation:
    /// - Folds 4 query values (v0, v1), (v2, v3), (v4, v5), (v6, v7) into a single value (ne0, ne1)
    /// - Computes new value of the domain generator power: poe' = poe^4
    /// - Increments layer pointer (cptr) by 2
    /// - Checks that the previous folding was done correctly
    /// - Shifts the stack to move an item from the overflow table to stack position 15
    ///
    /// Stack transition:
    /// Input: [v7, v6, v5, v4, v3, v2, v1, v0, f_pos, d_seg, poe, pe1, pe0, a1, a0, cptr, ...]
    /// Output: [t1, t0, s1, s0, df3, df2, df1, df0, poe^2, f_tau, cptr+2, poe^4, f_pos, ne1, ne0,
    /// eptr, ...] where eptr is moved from the stack overflow table and is the address of the
    /// final FRI layer.
    FriE2F4 = OPCODE_FRIE2F4,

    /// Performs 8 steps of the Horner evaluation method on a polynomial with coefficients over
    /// the base field, i.e., it computes
    ///
    /// acc' = (((acc_tmp * alpha + c3) * alpha + c2) * alpha + c1) * alpha + c0
    ///
    /// where
    ///
    /// acc_tmp := (((acc * alpha + c7) * alpha + c6) * alpha + c5) * alpha + c4
    ///
    ///
    /// In other words, the intsruction computes the evaluation at alpha of the polynomial
    ///
    /// P(X) := c7 * X^7 + c6 * X^6 + ... + c1 * X + c0
    HornerBase = OPCODE_HORNERBASE,

    /// Performs 4 steps of the Horner evaluation method on a polynomial with coefficients over
    /// the extension field, i.e., it computes
    ///
    /// acc' = (((acc * alpha + c3) * alpha + c2) * alpha + c1) * alpha + c0
    ///
    /// In other words, the intsruction computes the evaluation at alpha of the polynomial
    ///
    /// P(X) := c3 * X^3 + c2 * X^2 + c1 * X + c0
    HornerExt = OPCODE_HORNEREXT,

    /// Evaluates an arithmetic circuit given a pointer to its description in memory, the number
    /// of arithmetic gates, and the sum of the input and constant gates.
    EvalCircuit = OPCODE_EVALCIRCUIT,

    /// Logs a precompile event. This instruction is used to signal that a precompile computation
    /// was requested.
    LogPrecompile = OPCODE_LOGPRECOMPILE,
}

impl Operation {
    pub const OP_BITS: usize = 7;

    /// Returns the opcode of this operation.
    #[rustfmt::skip]
    pub fn op_code(&self) -> u8 {
        // SAFETY: This is safe because we have given this enum a primitive representation with
        // #[repr(u8)], with the first field of the underlying union-of-structs the discriminant.
        //
        // See the section on "accessing the numeric value of the discriminant"
        // here: https://doc.rust-lang.org/std/mem/fn.discriminant.html
        unsafe { *<*const _>::from(self).cast::<u8>() }
    }

    /// Returns an immediate value carried by this operation.
    // Proptest generators for operations in crate::mast::node::basic_block_node::tests discriminate
    // on this flag, please update them when you modify the semantics of this method.
    pub fn imm_value(&self) -> Option<Felt> {
        match *self {
            Self::Push(imm) => Some(imm),
            _ => None,
        }
    }

    /// Returns true if this operation writes any data to the decoder hasher registers.
    ///
    /// In other words, if so, then the user op helper registers are not available.
    pub fn populates_decoder_hasher_registers(&self) -> bool {
        matches!(
            self,
            Self::End
                | Self::Join
                | Self::Split
                | Self::Loop
                | Self::Repeat
                | Self::Respan
                | Self::Span
                | Self::Halt
                | Self::Call
                | Self::SysCall
        )
    }
}

impl crate::prettier::PrettyPrint for Operation {
    fn render(&self) -> crate::prettier::Document {
        crate::prettier::display(self)
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // ----- system operations ------------------------------------------------------------
            Self::Noop => write!(f, "noop"),
            Self::Assert(err_code) => write!(f, "assert({err_code})"),

            Self::SDepth => write!(f, "sdepth"),
            Self::Caller => write!(f, "caller"),

            Self::Clk => write!(f, "clk"),

            // ----- flow control operations ------------------------------------------------------
            Self::Join => write!(f, "join"),
            Self::Split => write!(f, "split"),
            Self::Loop => write!(f, "loop"),
            Self::Call => writeln!(f, "call"),
            Self::Dyncall => writeln!(f, "dyncall"),
            Self::SysCall => writeln!(f, "syscall"),
            Self::Dyn => writeln!(f, "dyn"),
            Self::Span => write!(f, "span"),
            Self::End => write!(f, "end"),
            Self::Repeat => write!(f, "repeat"),
            Self::Respan => write!(f, "respan"),
            Self::Halt => write!(f, "halt"),

            // ----- field operations -------------------------------------------------------------
            Self::Add => write!(f, "add"),
            Self::Neg => write!(f, "neg"),
            Self::Mul => write!(f, "mul"),
            Self::Inv => write!(f, "inv"),
            Self::Incr => write!(f, "incr"),

            Self::And => write!(f, "and"),
            Self::Or => write!(f, "or"),
            Self::Not => write!(f, "not"),

            Self::Eq => write!(f, "eq"),
            Self::Eqz => write!(f, "eqz"),

            Self::Expacc => write!(f, "expacc"),

            // ----- ext2 operations --------------------------------------------------------------
            Self::Ext2Mul => write!(f, "ext2mul"),

            // ----- u32 operations ---------------------------------------------------------------
            Self::U32assert2(err_code) => write!(f, "u32assert2({err_code})"),
            Self::U32split => write!(f, "u32split"),
            Self::U32add => write!(f, "u32add"),
            Self::U32add3 => write!(f, "u32add3"),
            Self::U32sub => write!(f, "u32sub"),
            Self::U32mul => write!(f, "u32mul"),
            Self::U32madd => write!(f, "u32madd"),
            Self::U32div => write!(f, "u32div"),

            Self::U32and => write!(f, "u32and"),
            Self::U32xor => write!(f, "u32xor"),

            // ----- stack manipulation -----------------------------------------------------------
            Self::Drop => write!(f, "drop"),
            Self::Pad => write!(f, "pad"),

            Self::Dup0 => write!(f, "dup0"),
            Self::Dup1 => write!(f, "dup1"),
            Self::Dup2 => write!(f, "dup2"),
            Self::Dup3 => write!(f, "dup3"),
            Self::Dup4 => write!(f, "dup4"),
            Self::Dup5 => write!(f, "dup5"),
            Self::Dup6 => write!(f, "dup6"),
            Self::Dup7 => write!(f, "dup7"),
            Self::Dup9 => write!(f, "dup9"),
            Self::Dup11 => write!(f, "dup11"),
            Self::Dup13 => write!(f, "dup13"),
            Self::Dup15 => write!(f, "dup15"),

            Self::Swap => write!(f, "swap"),
            Self::SwapW => write!(f, "swapw"),
            Self::SwapW2 => write!(f, "swapw2"),
            Self::SwapW3 => write!(f, "swapw3"),
            Self::SwapDW => write!(f, "swapdw"),

            Self::MovUp2 => write!(f, "movup2"),
            Self::MovUp3 => write!(f, "movup3"),
            Self::MovUp4 => write!(f, "movup4"),
            Self::MovUp5 => write!(f, "movup5"),
            Self::MovUp6 => write!(f, "movup6"),
            Self::MovUp7 => write!(f, "movup7"),
            Self::MovUp8 => write!(f, "movup8"),

            Self::MovDn2 => write!(f, "movdn2"),
            Self::MovDn3 => write!(f, "movdn3"),
            Self::MovDn4 => write!(f, "movdn4"),
            Self::MovDn5 => write!(f, "movdn5"),
            Self::MovDn6 => write!(f, "movdn6"),
            Self::MovDn7 => write!(f, "movdn7"),
            Self::MovDn8 => write!(f, "movdn8"),

            Self::CSwap => write!(f, "cswap"),
            Self::CSwapW => write!(f, "cswapw"),

            // ----- input / output ---------------------------------------------------------------
            Self::Push(value) => write!(f, "push({value})"),

            Self::AdvPop => write!(f, "advpop"),
            Self::AdvPopW => write!(f, "advpopw"),

            Self::MLoadW => write!(f, "mloadw"),
            Self::MStoreW => write!(f, "mstorew"),

            Self::MLoad => write!(f, "mload"),
            Self::MStore => write!(f, "mstore"),

            Self::MStream => write!(f, "mstream"),
            Self::Pipe => write!(f, "pipe"),
            Self::CryptoStream => write!(f, "crypto_stream"),

            Self::Emit => write!(f, "emit"),

            // ----- cryptographic operations -----------------------------------------------------
            Self::HPerm => write!(f, "hperm"),
            Self::MpVerify(err_code) => write!(f, "mpverify({err_code})"),
            Self::MrUpdate => write!(f, "mrupdate"),

            // ----- STARK proof verification -----------------------------------------------------
            Self::FriE2F4 => write!(f, "frie2f4"),
            Self::HornerBase => write!(f, "horner_eval_base"),
            Self::HornerExt => write!(f, "horner_eval_ext"),
            Self::EvalCircuit => write!(f, "eval_circuit"),
            Self::LogPrecompile => write!(f, "log_precompile"),
        }
    }
}

impl Serializable for Operation {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.op_code());

        // For operations that have extra data, encode it in `data`.
        match self {
            Operation::Assert(err_code)
            | Operation::MpVerify(err_code)
            | Operation::U32assert2(err_code) => {
                err_code.write_into(target);
            },
            Operation::Push(value) => value.as_canonical_u64().write_into(target),

            // Note: we explicitly write out all the operations so that whenever we make a
            // modification to the `Operation` enum, we get a compile error here. This
            // should help us remember to properly encode/decode each operation variant.
            Operation::Noop
            | Operation::SDepth
            | Operation::Caller
            | Operation::Clk
            | Operation::Join
            | Operation::Split
            | Operation::Loop
            | Operation::Call
            | Operation::Dyn
            | Operation::Dyncall
            | Operation::SysCall
            | Operation::Span
            | Operation::End
            | Operation::Repeat
            | Operation::Respan
            | Operation::Halt
            | Operation::Add
            | Operation::Neg
            | Operation::Mul
            | Operation::Inv
            | Operation::Incr
            | Operation::And
            | Operation::Or
            | Operation::Not
            | Operation::Eq
            | Operation::Eqz
            | Operation::Expacc
            | Operation::Ext2Mul
            | Operation::U32split
            | Operation::U32add
            | Operation::U32add3
            | Operation::U32sub
            | Operation::U32mul
            | Operation::U32madd
            | Operation::U32div
            | Operation::U32and
            | Operation::U32xor
            | Operation::Pad
            | Operation::Drop
            | Operation::Dup0
            | Operation::Dup1
            | Operation::Dup2
            | Operation::Dup3
            | Operation::Dup4
            | Operation::Dup5
            | Operation::Dup6
            | Operation::Dup7
            | Operation::Dup9
            | Operation::Dup11
            | Operation::Dup13
            | Operation::Dup15
            | Operation::Swap
            | Operation::SwapW
            | Operation::SwapW2
            | Operation::SwapW3
            | Operation::SwapDW
            | Operation::Emit
            | Operation::MovUp2
            | Operation::MovUp3
            | Operation::MovUp4
            | Operation::MovUp5
            | Operation::MovUp6
            | Operation::MovUp7
            | Operation::MovUp8
            | Operation::MovDn2
            | Operation::MovDn3
            | Operation::MovDn4
            | Operation::MovDn5
            | Operation::MovDn6
            | Operation::MovDn7
            | Operation::MovDn8
            | Operation::CSwap
            | Operation::CSwapW
            | Operation::AdvPop
            | Operation::AdvPopW
            | Operation::MLoadW
            | Operation::MStoreW
            | Operation::MLoad
            | Operation::MStore
            | Operation::MStream
            | Operation::Pipe
            | Operation::CryptoStream
            | Operation::HPerm
            | Operation::MrUpdate
            | Operation::FriE2F4
            | Operation::HornerBase
            | Operation::HornerExt
            | Operation::EvalCircuit
            | Operation::LogPrecompile => (),
        }
    }
}

impl Deserializable for Operation {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let op_code = source.read_u8()?;

        let operation = match op_code {
            OPCODE_NOOP => Self::Noop,
            OPCODE_EQZ => Self::Eqz,
            OPCODE_NEG => Self::Neg,
            OPCODE_INV => Self::Inv,
            OPCODE_INCR => Self::Incr,
            OPCODE_NOT => Self::Not,
            OPCODE_MLOAD => Self::MLoad,
            OPCODE_SWAP => Self::Swap,
            OPCODE_CALLER => Self::Caller,
            OPCODE_MOVUP2 => Self::MovUp2,
            OPCODE_MOVDN2 => Self::MovDn2,
            OPCODE_MOVUP3 => Self::MovUp3,
            OPCODE_MOVDN3 => Self::MovDn3,
            OPCODE_ADVPOPW => Self::AdvPopW,
            OPCODE_EXPACC => Self::Expacc,

            OPCODE_MOVUP4 => Self::MovUp4,
            OPCODE_MOVDN4 => Self::MovDn4,
            OPCODE_MOVUP5 => Self::MovUp5,
            OPCODE_MOVDN5 => Self::MovDn5,
            OPCODE_MOVUP6 => Self::MovUp6,
            OPCODE_MOVDN6 => Self::MovDn6,
            OPCODE_MOVUP7 => Self::MovUp7,
            OPCODE_MOVDN7 => Self::MovDn7,
            OPCODE_SWAPW => Self::SwapW,
            OPCODE_EXT2MUL => Self::Ext2Mul,
            OPCODE_MOVUP8 => Self::MovUp8,
            OPCODE_MOVDN8 => Self::MovDn8,
            OPCODE_SWAPW2 => Self::SwapW2,
            OPCODE_SWAPW3 => Self::SwapW3,
            OPCODE_SWAPDW => Self::SwapDW,
            OPCODE_EMIT => Self::Emit,

            OPCODE_ASSERT => Self::Assert(Felt::read_from(source)?),
            OPCODE_EQ => Self::Eq,
            OPCODE_ADD => Self::Add,
            OPCODE_MUL => Self::Mul,
            OPCODE_AND => Self::And,
            OPCODE_OR => Self::Or,
            OPCODE_U32AND => Self::U32and,
            OPCODE_U32XOR => Self::U32xor,
            OPCODE_FRIE2F4 => Self::FriE2F4,
            OPCODE_DROP => Self::Drop,
            OPCODE_CSWAP => Self::CSwap,
            OPCODE_CSWAPW => Self::CSwapW,
            OPCODE_MLOADW => Self::MLoadW,
            OPCODE_MSTORE => Self::MStore,
            OPCODE_MSTOREW => Self::MStoreW,

            OPCODE_PAD => Self::Pad,
            OPCODE_DUP0 => Self::Dup0,
            OPCODE_DUP1 => Self::Dup1,
            OPCODE_DUP2 => Self::Dup2,
            OPCODE_DUP3 => Self::Dup3,
            OPCODE_DUP4 => Self::Dup4,
            OPCODE_DUP5 => Self::Dup5,
            OPCODE_DUP6 => Self::Dup6,
            OPCODE_DUP7 => Self::Dup7,
            OPCODE_DUP9 => Self::Dup9,
            OPCODE_DUP11 => Self::Dup11,
            OPCODE_DUP13 => Self::Dup13,
            OPCODE_DUP15 => Self::Dup15,
            OPCODE_ADVPOP => Self::AdvPop,
            OPCODE_SDEPTH => Self::SDepth,
            OPCODE_CLK => Self::Clk,

            OPCODE_U32ADD => Self::U32add,
            OPCODE_U32SUB => Self::U32sub,
            OPCODE_U32MUL => Self::U32mul,
            OPCODE_U32DIV => Self::U32div,
            OPCODE_U32SPLIT => Self::U32split,
            OPCODE_U32ASSERT2 => Self::U32assert2(Felt::read_from(source)?),
            OPCODE_U32ADD3 => Self::U32add3,
            OPCODE_U32MADD => Self::U32madd,

            OPCODE_HPERM => Self::HPerm,
            OPCODE_MPVERIFY => Self::MpVerify(Felt::read_from(source)?),
            OPCODE_PIPE => Self::Pipe,
            OPCODE_MSTREAM => Self::MStream,
            OPCODE_CRYPTOSTREAM => Self::CryptoStream,
            OPCODE_SPLIT => Self::Split,
            OPCODE_LOOP => Self::Loop,
            OPCODE_SPAN => Self::Span,
            OPCODE_JOIN => Self::Join,
            OPCODE_DYN => Self::Dyn,
            OPCODE_DYNCALL => Self::Dyncall,
            OPCODE_HORNERBASE => Self::HornerBase,
            OPCODE_HORNEREXT => Self::HornerExt,
            OPCODE_LOGPRECOMPILE => Self::LogPrecompile,
            OPCODE_EVALCIRCUIT => Self::EvalCircuit,

            OPCODE_MRUPDATE => Self::MrUpdate,
            OPCODE_PUSH => Self::Push(Felt::read_from(source)?),
            OPCODE_SYSCALL => Self::SysCall,
            OPCODE_CALL => Self::Call,
            OPCODE_END => Self::End,
            OPCODE_REPEAT => Self::Repeat,
            OPCODE_RESPAN => Self::Respan,
            OPCODE_HALT => Self::Halt,
            _ => {
                return Err(DeserializationError::InvalidValue(format!(
                    "Invalid opcode '{op_code}'"
                )));
            },
        };

        Ok(operation)
    }
}
