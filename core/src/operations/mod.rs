use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

mod decorators;
pub use decorators::{
    AssemblyOp, DebugOptions, DebugVarInfo, DebugVarLocation, Decorator, DecoratorList,
};

use crate::{
    Felt,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// OPERATIONS AND CONTROL FLOW OPCODES
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
pub mod opcodes {
    pub const NOOP: u8           = 0b0000_0000;
    pub const EQZ: u8            = 0b0000_0001;
    pub const NEG: u8            = 0b0000_0010;
    pub const INV: u8            = 0b0000_0011;
    pub const INCR: u8           = 0b0000_0100;
    pub const NOT: u8            = 0b0000_0101;
    /* unused                      0b0000_0110 */
    pub const MLOAD: u8          = 0b0000_0111;
    pub const SWAP: u8           = 0b0000_1000;
    pub const CALLER: u8         = 0b0000_1001;
    pub const MOVUP2: u8         = 0b0000_1010;
    pub const MOVDN2: u8         = 0b0000_1011;
    pub const MOVUP3: u8         = 0b0000_1100;
    pub const MOVDN3: u8         = 0b0000_1101;
    pub const ADVPOPW: u8        = 0b0000_1110;
    pub const EXPACC: u8         = 0b0000_1111;

    pub const MOVUP4: u8         = 0b0001_0000;
    pub const MOVDN4: u8         = 0b0001_0001;
    pub const MOVUP5: u8         = 0b0001_0010;
    pub const MOVDN5: u8         = 0b0001_0011;
    pub const MOVUP6: u8         = 0b0001_0100;
    pub const MOVDN6: u8         = 0b0001_0101;
    pub const MOVUP7: u8         = 0b0001_0110;
    pub const MOVDN7: u8         = 0b0001_0111;
    pub const SWAPW: u8          = 0b0001_1000;
    pub const EXT2MUL: u8        = 0b0001_1001;
    pub const MOVUP8: u8         = 0b0001_1010;
    pub const MOVDN8: u8         = 0b0001_1011;
    pub const SWAPW2: u8         = 0b0001_1100;
    pub const SWAPW3: u8         = 0b0001_1101;
    pub const SWAPDW: u8         = 0b0001_1110;
    pub const EMIT: u8           = 0b0001_1111;

    pub const ASSERT: u8         = 0b0010_0000;
    pub const EQ: u8             = 0b0010_0001;
    pub const ADD: u8            = 0b0010_0010;
    pub const MUL: u8            = 0b0010_0011;
    pub const AND: u8            = 0b0010_0100;
    pub const OR: u8             = 0b0010_0101;
    pub const U32AND: u8         = 0b0010_0110;
    pub const U32XOR: u8         = 0b0010_0111;
    pub const FRIE2F4: u8        = 0b0010_1000;
    pub const DROP: u8           = 0b0010_1001;
    pub const CSWAP: u8          = 0b0010_1010;
    pub const CSWAPW: u8         = 0b0010_1011;
    pub const MLOADW: u8         = 0b0010_1100;
    pub const MSTORE: u8         = 0b0010_1101;
    pub const MSTOREW: u8        = 0b0010_1110;
    /* unused                      0b0010_1111 */

    pub const PAD: u8            = 0b0011_0000;
    pub const DUP0: u8           = 0b0011_0001;
    pub const DUP1: u8           = 0b0011_0010;
    pub const DUP2: u8           = 0b0011_0011;
    pub const DUP3: u8           = 0b0011_0100;
    pub const DUP4: u8           = 0b0011_0101;
    pub const DUP5: u8           = 0b0011_0110;
    pub const DUP6: u8           = 0b0011_0111;
    pub const DUP7: u8           = 0b0011_1000;
    pub const DUP9: u8           = 0b0011_1001;
    pub const DUP11: u8          = 0b0011_1010;
    pub const DUP13: u8          = 0b0011_1011;
    pub const DUP15: u8          = 0b0011_1100;
    pub const ADVPOP: u8         = 0b0011_1101;
    pub const SDEPTH: u8         = 0b0011_1110;
    pub const CLK: u8            = 0b0011_1111;

    pub const U32ADD: u8         = 0b0100_0000;
    pub const U32SUB: u8         = 0b0100_0010;
    pub const U32MUL: u8         = 0b0100_0100;
    pub const U32DIV: u8         = 0b0100_0110;
    pub const U32SPLIT: u8       = 0b0100_1000;
    pub const U32ASSERT2: u8     = 0b0100_1010;
    pub const U32ADD3: u8        = 0b0100_1100;
    pub const U32MADD: u8        = 0b0100_1110;

    pub const HPERM: u8          = 0b0101_0000;
    pub const MPVERIFY: u8       = 0b0101_0001;
    pub const PIPE: u8           = 0b0101_0010;
    pub const MSTREAM: u8        = 0b0101_0011;
    pub const SPLIT: u8          = 0b0101_0100;
    pub const LOOP: u8           = 0b0101_0101;
    pub const SPAN: u8           = 0b0101_0110;
    pub const JOIN: u8           = 0b0101_0111;
    pub const DYN: u8            = 0b0101_1000;
    pub const HORNERBASE: u8     = 0b0101_1001;
    pub const HORNEREXT: u8      = 0b0101_1010;
    pub const PUSH: u8           = 0b0101_1011;
    pub const DYNCALL: u8        = 0b0101_1100;
    pub const EVALCIRCUIT: u8    = 0b0101_1101;
    pub const LOGPRECOMPILE: u8  = 0b0101_1110;

    pub const MRUPDATE: u8       = 0b0110_0000;
    pub const CRYPTOSTREAM: u8   = 0b0110_0100;
    pub const SYSCALL: u8        = 0b0110_1000;
    pub const CALL: u8           = 0b0110_1100;
    pub const END: u8            = 0b0111_0000;
    pub const REPEAT: u8         = 0b0111_0100;
    pub const RESPAN: u8         = 0b0111_1000;
    pub const HALT: u8           = 0b0111_1100;
}

// OPERATIONS
// ================================================================================================

/// The set of native VM basic block operations executable which take exactly one cycle to execute.
///
/// Specifically, the operations encoded here are only those which can be executed within basic
/// blocks, i.e., they exclude all control flow operations (e.g., `Loop`, `Span`, `Join`, etc.).
/// Note though that those operations have their own unique opcode which lives in the same 7-bit
/// opcode space as the basic block operations.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum Operation {
    // ----- system operations -------------------------------------------------------------------
    /// Advances cycle counter, but does not change the state of user stack.
    Noop = opcodes::NOOP,

    /// Pops the stack; if the popped value is not 1, execution fails.
    ///
    /// The internal value specifies an error code associated with the error in case when the
    /// execution fails.
    Assert(Felt) = opcodes::ASSERT,

    /// Pushes the current depth of the stack onto the stack.
    SDepth = opcodes::SDEPTH,

    /// Overwrites the top four stack items with the hash of a function which initiated the current
    /// SYSCALL. Thus, this operation can be executed only inside a SYSCALL code block.
    Caller = opcodes::CALLER,

    /// Pushes the current value of the clock cycle onto the stack. This operation can be used to
    /// measure the number of cycles it has taken to execute the program up to the current
    /// instruction.
    Clk = opcodes::CLK,

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
    Emit = opcodes::EMIT,

    // ----- field operations --------------------------------------------------------------------
    /// Pops two elements off the stack, adds them, and pushes the result back onto the stack.
    Add = opcodes::ADD,

    /// Pops an element off the stack, negates it, and pushes the result back onto the stack.
    Neg = opcodes::NEG,

    /// Pops two elements off the stack, multiplies them, and pushes the result back onto the
    /// stack.
    Mul = opcodes::MUL,

    /// Pops an element off the stack, computes its multiplicative inverse, and pushes the result
    /// back onto the stack.
    Inv = opcodes::INV,

    /// Pops an element off the stack, adds 1 to it, and pushes the result back onto the stack.
    Incr = opcodes::INCR,

    /// Pops two elements off the stack, multiplies them, and pushes the result back onto the
    /// stack.
    ///
    /// If either of the elements is greater than 1, execution fails. This operation is equivalent
    /// to boolean AND.
    And = opcodes::AND,

    /// Pops two elements off the stack and subtracts their product from their sum.
    ///
    /// If either of the elements is greater than 1, execution fails. This operation is equivalent
    /// to boolean OR.
    Or = opcodes::OR,

    /// Pops an element off the stack and subtracts it from 1.
    ///
    /// If the element is greater than one, the execution fails. This operation is equivalent to
    /// boolean NOT.
    Not = opcodes::NOT,

    /// Pops two elements off the stack and compares them. If the elements are equal, pushes 1
    /// onto the stack, otherwise pushes 0 onto the stack.
    Eq = opcodes::EQ,

    /// Pops an element off the stack and compares it to 0. If the element is 0, pushes 1 onto
    /// the stack, otherwise pushes 0 onto the stack.
    Eqz = opcodes::EQZ,

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
    Expacc = opcodes::EXPACC,

    // ----- ext2 operations ---------------------------------------------------------------------
    /// Computes the product of two elements in the extension field of degree 2 and pushes the
    /// result back onto the stack as the third and fourth elements. Pushes 0 onto the stack as
    /// the first and second elements.
    ///
    /// The extension field is defined as 𝔽ₚ\[x\]/(x² - 7), i.e. using the
    /// irreducible quadratic polynomial x² - 7 over the base field.
    Ext2Mul = opcodes::EXT2MUL,

    // ----- u32 operations ----------------------------------------------------------------------
    /// Pops an element off the stack, splits it into upper and lower 32-bit values, and pushes
    /// these values back onto the stack.
    U32split = opcodes::U32SPLIT,

    /// Pops two elements off the stack, adds them, and splits the result into upper and lower
    /// 32-bit values. Then pushes these values back onto the stack.
    ///
    /// If either of these elements is greater than or equal to 2^32, the result of this
    /// operation is undefined.
    U32add = opcodes::U32ADD,

    /// Pops two elements off the stack and checks if each of them represents a 32-bit value.
    /// If both of them are, they are pushed back onto the stack, otherwise an error is returned.
    ///
    /// The internal value specifies an error code associated with the error in case when the
    /// assertion fails.
    U32assert2(Felt) = opcodes::U32ASSERT2,

    /// Pops three elements off the stack, adds them together, and splits the result into upper
    /// and lower 32-bit values. Then pushes the result back onto the stack.
    U32add3 = opcodes::U32ADD3,

    /// Pops two elements off the stack and subtracts the first element from the second. Then,
    /// the result, together with a flag indicating whether subtraction underflowed is pushed
    /// onto the stack.
    ///
    /// If their of the values is greater than or equal to 2^32, the result of this operation is
    /// undefined.
    U32sub = opcodes::U32SUB,

    /// Pops two elements off the stack, multiplies them, and splits the result into upper and
    /// lower 32-bit values. Then pushes these values back onto the stack.
    ///
    /// If their of the values is greater than or equal to 2^32, the result of this operation is
    /// undefined.
    U32mul = opcodes::U32MUL,

    /// Pops two elements off the stack and multiplies them. Then pops the third element off the
    /// stack, and adds it to the result. Finally, splits the result into upper and lower 32-bit
    /// values, and pushes them onto the stack.
    ///
    /// If any of the three values is greater than or equal to 2^32, the result of this operation
    /// is undefined.
    U32madd = opcodes::U32MADD,

    /// Pops two elements off the stack and divides the second element by the first. Then pushes
    /// the integer result of the division, together with the remainder, onto the stack.
    ///
    /// If their of the values is greater than or equal to 2^32, the result of this operation is
    /// undefined.
    U32div = opcodes::U32DIV,

    /// Pops two elements off the stack, computes their binary AND, and pushes the result back
    /// onto the stack.
    ///
    /// If either of the elements is greater than or equal to 2^32, execution fails.
    U32and = opcodes::U32AND,

    /// Pops two elements off the stack, computes their binary XOR, and pushes the result back
    /// onto the stack.
    ///
    /// If either of the elements is greater than or equal to 2^32, execution fails.
    U32xor = opcodes::U32XOR,

    // ----- stack manipulation ------------------------------------------------------------------
    /// Pushes 0 onto the stack.
    Pad = opcodes::PAD,

    /// Removes to element from the stack.
    Drop = opcodes::DROP,

    /// Pushes a copy of stack element 0 onto the stack.
    Dup0 = opcodes::DUP0,

    /// Pushes a copy of stack element 1 onto the stack.
    Dup1 = opcodes::DUP1,

    /// Pushes a copy of stack element 2 onto the stack.
    Dup2 = opcodes::DUP2,

    /// Pushes a copy of stack element 3 onto the stack.
    Dup3 = opcodes::DUP3,

    /// Pushes a copy of stack element 4 onto the stack.
    Dup4 = opcodes::DUP4,

    /// Pushes a copy of stack element 5 onto the stack.
    Dup5 = opcodes::DUP5,

    /// Pushes a copy of stack element 6 onto the stack.
    Dup6 = opcodes::DUP6,

    /// Pushes a copy of stack element 7 onto the stack.
    Dup7 = opcodes::DUP7,

    /// Pushes a copy of stack element 9 onto the stack.
    Dup9 = opcodes::DUP9,

    /// Pushes a copy of stack element 11 onto the stack.
    Dup11 = opcodes::DUP11,

    /// Pushes a copy of stack element 13 onto the stack.
    Dup13 = opcodes::DUP13,

    /// Pushes a copy of stack element 15 onto the stack.
    Dup15 = opcodes::DUP15,

    /// Swaps stack elements 0 and 1.
    Swap = opcodes::SWAP,

    /// Swaps stack elements 0, 1, 2, and 3 with elements 4, 5, 6, and 7.
    SwapW = opcodes::SWAPW,

    /// Swaps stack elements 0, 1, 2, and 3 with elements 8, 9, 10, and 11.
    SwapW2 = opcodes::SWAPW2,

    /// Swaps stack elements 0, 1, 2, and 3, with elements 12, 13, 14, and 15.
    SwapW3 = opcodes::SWAPW3,

    /// Swaps the top two words pair wise.
    ///
    /// Input: [D, C, B, A, ...]
    /// Output: [B, A, D, C, ...]
    SwapDW = opcodes::SWAPDW,

    /// Moves stack element 2 to the top of the stack.
    MovUp2 = opcodes::MOVUP2,

    /// Moves stack element 3 to the top of the stack.
    MovUp3 = opcodes::MOVUP3,

    /// Moves stack element 4 to the top of the stack.
    MovUp4 = opcodes::MOVUP4,

    /// Moves stack element 5 to the top of the stack.
    MovUp5 = opcodes::MOVUP5,

    /// Moves stack element 6 to the top of the stack.
    MovUp6 = opcodes::MOVUP6,

    /// Moves stack element 7 to the top of the stack.
    MovUp7 = opcodes::MOVUP7,

    /// Moves stack element 8 to the top of the stack.
    MovUp8 = opcodes::MOVUP8,

    /// Moves the top stack element to position 2 on the stack.
    MovDn2 = opcodes::MOVDN2,

    /// Moves the top stack element to position 3 on the stack.
    MovDn3 = opcodes::MOVDN3,

    /// Moves the top stack element to position 4 on the stack.
    MovDn4 = opcodes::MOVDN4,

    /// Moves the top stack element to position 5 on the stack.
    MovDn5 = opcodes::MOVDN5,

    /// Moves the top stack element to position 6 on the stack.
    MovDn6 = opcodes::MOVDN6,

    /// Moves the top stack element to position 7 on the stack.
    MovDn7 = opcodes::MOVDN7,

    /// Moves the top stack element to position 8 on the stack.
    MovDn8 = opcodes::MOVDN8,

    /// Pops an element off the stack, and if the element is 1, swaps the top two remaining
    /// elements on the stack. If the popped element is 0, the stack remains unchanged.
    ///
    /// If the popped element is neither 0 nor 1, execution fails.
    CSwap = opcodes::CSWAP,

    /// Pops an element off the stack, and if the element is 1, swaps the remaining elements
    /// 0, 1, 2, and 3 with elements 4, 5, 6, and 7. If the popped element is 0, the stack
    /// remains unchanged.
    ///
    /// If the popped element is neither 0 nor 1, execution fails.
    CSwapW = opcodes::CSWAPW,

    // ----- input / output ----------------------------------------------------------------------
    /// Pushes the immediate value onto the stack.
    Push(Felt) = opcodes::PUSH,

    /// Removes the next element from the advice stack and pushes it onto the operand stack.
    AdvPop = opcodes::ADVPOP,

    /// Removes a word (4 elements) from the advice stack and overwrites the top four operand
    /// stack elements with it.
    AdvPopW = opcodes::ADVPOPW,

    /// Pops an element off the stack, interprets it as a memory address, and replaces the
    /// remaining 4 elements at the top of the stack with values located at the specified address.
    MLoadW = opcodes::MLOADW,

    /// Pops an element off the stack, interprets it as a memory address, and writes the remaining
    /// 4 elements at the top of the stack into memory at the specified address.
    MStoreW = opcodes::MSTOREW,

    /// Pops an element off the stack, interprets it as a memory address, and pushes the first
    /// element of the word located at the specified address to the stack.
    MLoad = opcodes::MLOAD,

    /// Pops an element off the stack, interprets it as a memory address, and writes the remaining
    /// element at the top of the stack into the first element of the word located at the specified
    /// memory address. The remaining 3 elements of the word are not affected.
    MStore = opcodes::MSTORE,

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
    MStream = opcodes::MSTREAM,

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
    Pipe = opcodes::PIPE,

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
    CryptoStream = opcodes::CRYPTOSTREAM,

    // ----- cryptographic operations ------------------------------------------------------------
    /// Performs a Poseidon2 permutation on the top 3 words of the operand stack,
    /// where the top 2 words are the rate (words C and B), the deepest word is the capacity (word
    /// A), and the digest output is the middle word E.
    ///
    /// Stack transition:
    /// [C, B, A, ...] -> [F, E, D, ...]
    HPerm = opcodes::HPERM,

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
    MpVerify(Felt) = opcodes::MPVERIFY,

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
    MrUpdate = opcodes::MRUPDATE,

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
    FriE2F4 = opcodes::FRIE2F4,

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
    HornerBase = opcodes::HORNERBASE,

    /// Performs 4 steps of the Horner evaluation method on a polynomial with coefficients over
    /// the extension field, i.e., it computes
    ///
    /// acc' = (((acc * alpha + c3) * alpha + c2) * alpha + c1) * alpha + c0
    ///
    /// In other words, the intsruction computes the evaluation at alpha of the polynomial
    ///
    /// P(X) := c3 * X^3 + c2 * X^2 + c1 * X + c0
    HornerExt = opcodes::HORNEREXT,

    /// Evaluates an arithmetic circuit given a pointer to its description in memory, the number
    /// of arithmetic gates, and the sum of the input and constant gates.
    EvalCircuit = opcodes::EVALCIRCUIT,

    /// Logs a precompile event. This instruction is used to signal that a precompile computation
    /// was requested.
    LogPrecompile = opcodes::LOGPRECOMPILE,
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

    /// Returns true if this basic block operation increases the stack depth by one.
    ///
    /// Note: this only applies to operations within basic blocks (i.e. those executed via
    /// `ResumeBasicBlock` continuations). Control flow operations that affect stack size
    /// (e.g. Split, Loop, Dyn) are handled separately.
    pub fn increments_stack_size(&self) -> bool {
        matches!(
            self,
            Self::Push(_)
                | Self::Pad
                | Self::Dup0
                | Self::Dup1
                | Self::Dup2
                | Self::Dup3
                | Self::Dup4
                | Self::Dup5
                | Self::Dup6
                | Self::Dup7
                | Self::Dup9
                | Self::Dup11
                | Self::Dup13
                | Self::Dup15
                | Self::U32split
                | Self::SDepth
                | Self::Clk
                | Self::AdvPop
        )
    }

    /// Returns true if this basic block operation decreases the stack depth by one.
    ///
    /// Note: this only applies to operations within basic blocks (i.e. those executed via
    /// `ResumeBasicBlock` continuations). Control flow operations that affect stack size
    /// (e.g. Split, Loop, Dyn) are handled separately.
    pub fn decrements_stack_size(&self) -> bool {
        matches!(
            self,
            Self::Drop
                | Self::Assert(_)
                | Self::Add
                | Self::Mul
                | Self::And
                | Self::Or
                | Self::Eq
                | Self::U32add3
                | Self::U32madd
                | Self::U32and
                | Self::U32xor
                | Self::CSwap
                | Self::CSwapW
                | Self::MLoadW
                | Self::MStoreW
                | Self::MStore
                | Self::FriE2F4
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
            opcodes::NOOP => Self::Noop,
            opcodes::EQZ => Self::Eqz,
            opcodes::NEG => Self::Neg,
            opcodes::INV => Self::Inv,
            opcodes::INCR => Self::Incr,
            opcodes::NOT => Self::Not,
            opcodes::MLOAD => Self::MLoad,
            opcodes::SWAP => Self::Swap,
            opcodes::CALLER => Self::Caller,
            opcodes::MOVUP2 => Self::MovUp2,
            opcodes::MOVDN2 => Self::MovDn2,
            opcodes::MOVUP3 => Self::MovUp3,
            opcodes::MOVDN3 => Self::MovDn3,
            opcodes::ADVPOPW => Self::AdvPopW,
            opcodes::EXPACC => Self::Expacc,

            opcodes::MOVUP4 => Self::MovUp4,
            opcodes::MOVDN4 => Self::MovDn4,
            opcodes::MOVUP5 => Self::MovUp5,
            opcodes::MOVDN5 => Self::MovDn5,
            opcodes::MOVUP6 => Self::MovUp6,
            opcodes::MOVDN6 => Self::MovDn6,
            opcodes::MOVUP7 => Self::MovUp7,
            opcodes::MOVDN7 => Self::MovDn7,
            opcodes::SWAPW => Self::SwapW,
            opcodes::EXT2MUL => Self::Ext2Mul,
            opcodes::MOVUP8 => Self::MovUp8,
            opcodes::MOVDN8 => Self::MovDn8,
            opcodes::SWAPW2 => Self::SwapW2,
            opcodes::SWAPW3 => Self::SwapW3,
            opcodes::SWAPDW => Self::SwapDW,
            opcodes::EMIT => Self::Emit,

            opcodes::ASSERT => Self::Assert(Felt::read_from(source)?),
            opcodes::EQ => Self::Eq,
            opcodes::ADD => Self::Add,
            opcodes::MUL => Self::Mul,
            opcodes::AND => Self::And,
            opcodes::OR => Self::Or,
            opcodes::U32AND => Self::U32and,
            opcodes::U32XOR => Self::U32xor,
            opcodes::FRIE2F4 => Self::FriE2F4,
            opcodes::DROP => Self::Drop,
            opcodes::CSWAP => Self::CSwap,
            opcodes::CSWAPW => Self::CSwapW,
            opcodes::MLOADW => Self::MLoadW,
            opcodes::MSTORE => Self::MStore,
            opcodes::MSTOREW => Self::MStoreW,

            opcodes::PAD => Self::Pad,
            opcodes::DUP0 => Self::Dup0,
            opcodes::DUP1 => Self::Dup1,
            opcodes::DUP2 => Self::Dup2,
            opcodes::DUP3 => Self::Dup3,
            opcodes::DUP4 => Self::Dup4,
            opcodes::DUP5 => Self::Dup5,
            opcodes::DUP6 => Self::Dup6,
            opcodes::DUP7 => Self::Dup7,
            opcodes::DUP9 => Self::Dup9,
            opcodes::DUP11 => Self::Dup11,
            opcodes::DUP13 => Self::Dup13,
            opcodes::DUP15 => Self::Dup15,
            opcodes::ADVPOP => Self::AdvPop,
            opcodes::SDEPTH => Self::SDepth,
            opcodes::CLK => Self::Clk,

            opcodes::U32ADD => Self::U32add,
            opcodes::U32SUB => Self::U32sub,
            opcodes::U32MUL => Self::U32mul,
            opcodes::U32DIV => Self::U32div,
            opcodes::U32SPLIT => Self::U32split,
            opcodes::U32ASSERT2 => Self::U32assert2(Felt::read_from(source)?),
            opcodes::U32ADD3 => Self::U32add3,
            opcodes::U32MADD => Self::U32madd,

            opcodes::HPERM => Self::HPerm,
            opcodes::MPVERIFY => Self::MpVerify(Felt::read_from(source)?),
            opcodes::PIPE => Self::Pipe,
            opcodes::MSTREAM => Self::MStream,
            opcodes::CRYPTOSTREAM => Self::CryptoStream,
            opcodes::HORNERBASE => Self::HornerBase,
            opcodes::HORNEREXT => Self::HornerExt,
            opcodes::LOGPRECOMPILE => Self::LogPrecompile,
            opcodes::EVALCIRCUIT => Self::EvalCircuit,

            opcodes::MRUPDATE => Self::MrUpdate,
            opcodes::PUSH => Self::Push(Felt::read_from(source)?),
            _ => {
                return Err(DeserializationError::InvalidValue(format!(
                    "Invalid opcode '{op_code}'"
                )));
            },
        };

        Ok(operation)
    }

    /// Returns the minimum serialized size: 1 byte opcode.
    ///
    /// Some operations have additional payload (e.g., Push has 8 bytes for Felt),
    /// but the minimum is just the opcode byte.
    fn min_serialized_size() -> usize {
        1
    }
}

#[cfg(test)]
mod tests;
