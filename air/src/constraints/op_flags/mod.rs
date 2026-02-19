//! Operation flags for stack constraints.
//!
//! This module computes operation flags from decoder op bits. These flags are used
//! throughout stack constraints to gate constraint enforcement based on which operation
//! is currently being executed.
//!
//! ## Operation Degree Categories
//!
//! Operations are grouped by their flag computation degree:
//! - **Degree 7**: 64 operations (opcodes 0-63) - use all 7 op bits
//! - **Degree 6**: 8 operations (opcodes 64-79) - u32 operations
//! - **Degree 5**: 16 operations (opcodes 80-95) - use op_bit_extra[0]
//! - **Degree 4**: 8 operations (opcodes 96-127) - use op_bit_extra[1]
//!
//! ## Composite Flags
//!
//! The module also computes composite flags that combine multiple operations:
//! - `no_shift_at(i)`: stack position i unchanged
//! - `left_shift_at(i)`: stack shifts left at position i
//! - `right_shift_at(i)`: stack shifts right at position i

use core::marker::PhantomData;

use miden_core::{field::PrimeCharacteristicRing, operations::Operation};

#[cfg(test)]
use crate::trace::decoder::NUM_OP_BITS;
use crate::trace::{
    decoder::{IS_LOOP_FLAG_COL_IDX, OP_BITS_EXTRA_COLS_RANGE, OP_BITS_RANGE},
    stack::{B0_COL_IDX, H0_COL_IDX},
};

// CONSTANTS
// ================================================================================================

/// Total number of degree 7 operations in the VM.
pub const NUM_DEGREE_7_OPS: usize = 64;

/// Total number of degree 6 operations in the VM.
pub const NUM_DEGREE_6_OPS: usize = 8;

/// Total number of degree 5 operations in the VM.
pub const NUM_DEGREE_5_OPS: usize = 16;

/// Total number of degree 4 operations in the VM.
pub const NUM_DEGREE_4_OPS: usize = 8;

/// Total number of composite flags per stack impact type in the VM.
pub const NUM_STACK_IMPACT_FLAGS: usize = 16;

/// Opcode at which degree 7 operations start.
const DEGREE_7_OPCODE_STARTS: usize = 0;

/// Opcode at which degree 7 operations end.
const DEGREE_7_OPCODE_ENDS: usize = DEGREE_7_OPCODE_STARTS + 63;

/// Opcode at which degree 6 operations start.
const DEGREE_6_OPCODE_STARTS: usize = DEGREE_7_OPCODE_ENDS + 1;

/// Opcode at which degree 6 operations end.
const DEGREE_6_OPCODE_ENDS: usize = DEGREE_6_OPCODE_STARTS + 15;

/// Opcode at which degree 5 operations start.
const DEGREE_5_OPCODE_STARTS: usize = DEGREE_6_OPCODE_ENDS + 1;

/// Opcode at which degree 5 operations end.
const DEGREE_5_OPCODE_ENDS: usize = DEGREE_5_OPCODE_STARTS + 15;

/// Opcode at which degree 4 operations start.
const DEGREE_4_OPCODE_STARTS: usize = DEGREE_5_OPCODE_ENDS + 1;

/// Opcode at which degree 4 operations end.
#[allow(dead_code)]
const DEGREE_4_OPCODE_ENDS: usize = DEGREE_4_OPCODE_STARTS + 31;

// INTERNAL HELPERS
// ================================================================================================

/// Operation flags for all stack operations.
///
/// Computes all operation flag expressions from decoder op bits. Only one flag will be
/// non-zero for any given row. The flags are computed using intermediate values to
/// minimize the number of multiplications.
///
/// This struct is parameterized by the expression type `E` which allows it to work
/// with both concrete field elements (for testing) and symbolic expressions (for
/// constraint generation).
#[allow(dead_code)]
pub struct OpFlags<E> {
    degree7_op_flags: [E; NUM_DEGREE_7_OPS],
    degree6_op_flags: [E; NUM_DEGREE_6_OPS],
    degree5_op_flags: [E; NUM_DEGREE_5_OPS],
    degree4_op_flags: [E; NUM_DEGREE_4_OPS],
    no_shift_flags: [E; NUM_STACK_IMPACT_FLAGS],
    left_shift_flags: [E; NUM_STACK_IMPACT_FLAGS],
    right_shift_flags: [E; NUM_STACK_IMPACT_FLAGS],

    left_shift: E,
    right_shift: E,
    control_flow: E,
    overflow: E,
    u32_rc_op: E,
}

/// Helper trait for accessing decoder columns from a trace row.
pub trait DecoderAccess<E> {
    /// Returns the value of op_bit[index] from the decoder.
    fn op_bit(&self, index: usize) -> E;

    /// Returns the value of op_bit_extra[index] from the decoder.
    fn op_bit_extra(&self, index: usize) -> E;

    /// Returns the h0 helper register (overflow indicator).
    fn overflow_register(&self) -> E;

    /// Returns the stack depth (b0 column).
    fn stack_depth(&self) -> E;

    /// Returns the is_loop flag from the decoder.
    fn is_loop_end(&self) -> E;
}

/// Implement DecoderAccess for MainTraceRow references.
impl<T> DecoderAccess<T> for &crate::MainTraceRow<T>
where
    T: Clone,
{
    #[inline]
    fn op_bit(&self, index: usize) -> T {
        self.decoder[OP_BITS_RANGE.start + index].clone()
    }

    #[inline]
    fn op_bit_extra(&self, index: usize) -> T {
        self.decoder[OP_BITS_EXTRA_COLS_RANGE.start + index].clone()
    }

    #[inline]
    fn overflow_register(&self) -> T {
        self.stack[H0_COL_IDX].clone()
    }

    #[inline]
    fn stack_depth(&self) -> T {
        self.stack[B0_COL_IDX].clone()
    }

    #[inline]
    fn is_loop_end(&self) -> T {
        self.decoder[IS_LOOP_FLAG_COL_IDX].clone()
    }
}

/// Wrapper that converts trace row variables to expressions during decoder access.
///
/// This is used when building constraints to convert `AB::Var` to `AB::Expr` so that
/// `OpFlags<AB::Expr>` can be created for use in constraint expressions.
pub struct ExprDecoderAccess<'a, V, E> {
    row: &'a crate::MainTraceRow<V>,
    _phantom: PhantomData<E>,
}

impl<'a, V, E> ExprDecoderAccess<'a, V, E> {
    /// Creates a new expression decoder access wrapper.
    pub fn new(row: &'a crate::MainTraceRow<V>) -> Self {
        Self { row, _phantom: PhantomData }
    }
}

impl<'a, V, E> DecoderAccess<E> for ExprDecoderAccess<'a, V, E>
where
    V: Clone + Into<E>,
{
    #[inline]
    fn op_bit(&self, index: usize) -> E {
        self.row.decoder[OP_BITS_RANGE.start + index].clone().into()
    }

    #[inline]
    fn op_bit_extra(&self, index: usize) -> E {
        self.row.decoder[OP_BITS_EXTRA_COLS_RANGE.start + index].clone().into()
    }

    #[inline]
    fn overflow_register(&self) -> E {
        self.row.stack[H0_COL_IDX].clone().into()
    }

    #[inline]
    fn stack_depth(&self) -> E {
        self.row.stack[B0_COL_IDX].clone().into()
    }

    #[inline]
    fn is_loop_end(&self) -> E {
        self.row.decoder[IS_LOOP_FLAG_COL_IDX].clone().into()
    }
}

/// Helper function to compute binary NOT: 1 - x
#[inline]
fn binary_not<E>(x: E) -> E
where
    E: Clone + core::ops::Sub<Output = E> + PrimeCharacteristicRing,
{
    E::ONE - x
}

#[derive(Clone)]
struct Op<E> {
    bit: E,
    not: E,
}

impl<E: Clone> Op<E> {
    #[inline]
    fn is(&self) -> E {
        self.bit.clone()
    }

    #[inline]
    fn not(&self) -> E {
        self.not.clone()
    }
}

macro_rules! op_flag_getters {
    ($array:ident, $( $(#[$meta:meta])* $name:ident => $op:expr ),* $(,)?) => {
        $(
            $(#[$meta])*
            #[inline(always)]
            pub fn $name(&self) -> E {
                self.$array[get_op_index($op.op_code())].clone()
            }
        )*
    };
}

#[allow(dead_code)]
impl<E> OpFlags<E>
where
    E: Clone
        + Default
        + core::ops::Add<Output = E>
        + core::ops::Sub<Output = E>
        + core::ops::Mul<Output = E>
        + PrimeCharacteristicRing,
{
    /// Creates a new OpFlags instance by computing all flags from the decoder columns.
    ///
    /// The computation uses intermediate values to minimize multiplications:
    /// - Degree 7 flags: computed hierarchically from op bits
    /// - Degree 6 flags: u32 operations, share common prefix `100`
    /// - Degree 5 flags: use op_bit_extra[0] for degree reduction
    /// - Degree 4 flags: use op_bit_extra[1] for degree reduction
    pub fn new<D: DecoderAccess<E>>(frame: D) -> Self {
        // Initialize arrays with default values
        let mut degree7_op_flags: [E; NUM_DEGREE_7_OPS] = core::array::from_fn(|_| E::default());
        let mut degree6_op_flags: [E; NUM_DEGREE_6_OPS] = core::array::from_fn(|_| E::default());
        let mut degree5_op_flags: [E; NUM_DEGREE_5_OPS] = core::array::from_fn(|_| E::default());
        let mut degree4_op_flags: [E; NUM_DEGREE_4_OPS] = core::array::from_fn(|_| E::default());
        let mut no_shift_flags: [E; NUM_STACK_IMPACT_FLAGS] =
            core::array::from_fn(|_| E::default());
        let mut left_shift_flags: [E; NUM_STACK_IMPACT_FLAGS] =
            core::array::from_fn(|_| E::default());
        let mut right_shift_flags: [E; NUM_STACK_IMPACT_FLAGS] =
            core::array::from_fn(|_| E::default());

        // Get op bits and their binary negations.
        let op: [Op<E>; 7] = core::array::from_fn(|i| {
            let bit = frame.op_bit(i);
            let not = binary_not(bit.clone());
            Op { bit, not }
        });

        // --- Low-degree prefix selectors for composite flags ---
        // These produce degree-5 left_shift and right_shift composite flags.
        // per spec: https://0xmiden.github.io/miden-vm/design/stack/op_constraints.html#shift-left-flag

        // Prefix `010` selector: (1-b6)*b5*(1-b4) - degree 3
        // Covers all degree-7 operations with this prefix (left shift ops)
        let prefix_010 = op[6].not() * op[5].is() * op[4].not();

        // Prefix `011` selector: (1-b6)*b5*b4 - degree 3
        // Covers all degree-7 operations with this prefix (right shift ops)
        let prefix_011 = op[6].not() * op[5].is() * op[4].is();

        // Prefix `10011` selector: b6*(1-b5)*(1-b4)*b3*b2 - degree 5
        // Covers U32ADD3 and U32MADD (both cause left shift by 2)
        let add3_madd_prefix = op[6].is() * op[5].not() * op[4].not() * op[3].is() * op[2].is();

        // --- Computation of degree 7 operation flags ---

        // Intermediate values computed from most significant bits
        degree7_op_flags[0] = op[5].not() * op[4].not();
        degree7_op_flags[16] = op[5].not() * op[4].is();
        degree7_op_flags[32] = op[5].is() * op[4].not();
        // Prefix `11` in bits [5..4] (binary 110000 = 48).
        degree7_op_flags[0b110000] = op[5].is() * op[4].is();

        // Flag of prefix `100` - all degree 6 u32 operations
        let f100 = degree7_op_flags[0].clone() * op[6].is();
        // Flag of prefix `1000` - u32 arithmetic operations
        let f1000 = f100.clone() * op[3].not();

        let not_6_not_3 = op[6].not() * op[3].not();
        let not_6_yes_3 = op[6].not() * op[3].is();

        // Add fourth most significant bit along with most significant bit
        for i in (0..64).step_by(16) {
            let base = degree7_op_flags[i].clone();
            degree7_op_flags[i + 8] = base.clone() * not_6_yes_3.clone();
            degree7_op_flags[i] = base * not_6_not_3.clone();
        }

        // Flag of prefix `011` - degree 7 right shift operations
        let f011 = degree7_op_flags[48].clone() + degree7_op_flags[56].clone();
        // Flag of prefix `010` - degree 7 left shift operations (reserved for future use)
        let _f010 = degree7_op_flags[32].clone() + degree7_op_flags[40].clone();
        // Flag of prefix `0000` - no shift from position 1 onwards
        let f0000 = degree7_op_flags[0].clone();
        // Flag of prefix `0100` - left shift from position 2 onwards
        let f0100 = degree7_op_flags[32].clone();

        // Add fifth most significant bit
        for i in (0..64).step_by(8) {
            let base = degree7_op_flags[i].clone();
            degree7_op_flags[i + 4] = base.clone() * op[2].is();
            degree7_op_flags[i] = base * op[2].not();
        }

        // Add sixth most significant bit
        for i in (0..64).step_by(4) {
            let base = degree7_op_flags[i].clone();
            degree7_op_flags[i + 2] = base.clone() * op[1].is();
            degree7_op_flags[i] = base * op[1].not();
        }

        // Cache flags for mov{up/dn}{2-8}, swapw{2-3} operations
        let mov2_flag = degree7_op_flags[10].clone();
        let mov3_flag = degree7_op_flags[12].clone();
        let mov4_flag = degree7_op_flags[16].clone();
        let mov5_flag = degree7_op_flags[18].clone();
        let mov6_flag = degree7_op_flags[20].clone();
        let mov7_flag = degree7_op_flags[22].clone();
        let mov8_flag = degree7_op_flags[26].clone();
        let swapwx_flag = degree7_op_flags[28].clone();
        let adv_popw_expacc = degree7_op_flags[14].clone();

        // Add least significant bit
        for i in (0..64).step_by(2) {
            let base = degree7_op_flags[i].clone();
            degree7_op_flags[i + 1] = base.clone() * op[0].is();
            degree7_op_flags[i] = base * op[0].not();
        }

        let ext2mul_flag = degree7_op_flags[25].clone();

        // Flag when items from first position onwards are copied over (excludes NOOP)
        let no_change_1_flag = f0000.clone() - degree7_op_flags[0].clone();
        // Flag when items from second position onwards shift left (excludes ASSERT)
        let left_change_1_flag = f0100 - degree7_op_flags[32].clone();

        // --- Computation of degree 6 operation flags ---

        // Degree 6 flag prefix is `100`
        let degree_6_flag = op[6].is() * op[5].not() * op[4].not();

        // Degree 6 flags do not use the first bit (op_bits[0])
        let not_2_not_3 = op[2].not() * op[3].not();
        let yes_2_not_3 = op[2].is() * op[3].not();
        let not_2_yes_3 = op[2].not() * op[3].is();
        let yes_2_yes_3 = op[2].is() * op[3].is();

        degree6_op_flags[0] = op[1].not() * not_2_not_3.clone(); // U32ADD
        degree6_op_flags[1] = op[1].is() * not_2_not_3.clone(); // U32SUB
        degree6_op_flags[2] = op[1].not() * yes_2_not_3.clone(); // U32MUL
        degree6_op_flags[3] = op[1].is() * yes_2_not_3.clone(); // U32DIV
        degree6_op_flags[4] = op[1].not() * not_2_yes_3.clone(); // U32SPLIT
        degree6_op_flags[5] = op[1].is() * not_2_yes_3.clone(); // U32ASSERT2
        degree6_op_flags[6] = op[1].not() * yes_2_yes_3.clone(); // U32ADD3
        degree6_op_flags[7] = op[1].is() * yes_2_yes_3.clone(); // U32MADD

        // Multiply by degree 6 flag
        for flag in degree6_op_flags.iter_mut() {
            *flag = flag.clone() * degree_6_flag.clone();
        }

        // --- Computation of degree 5 operation flags ---

        // Degree 5 flag uses the first degree reduction column
        let degree_5_flag = frame.op_bit_extra(0);

        let not_0_not_1 = op[0].not() * op[1].not();
        let yes_0_not_1 = op[0].is() * op[1].not();
        let not_0_yes_1 = op[0].not() * op[1].is();
        let yes_0_yes_1 = op[0].is() * op[1].is();

        degree5_op_flags[0] = not_0_not_1.clone() * op[2].not(); // HPERM
        degree5_op_flags[1] = yes_0_not_1.clone() * op[2].not(); // MPVERIFY
        degree5_op_flags[2] = not_0_yes_1.clone() * op[2].not(); // PIPE
        degree5_op_flags[3] = yes_0_yes_1.clone() * op[2].not(); // MSTREAM
        degree5_op_flags[4] = not_0_not_1.clone() * op[2].is(); // SPLIT
        degree5_op_flags[5] = yes_0_not_1.clone() * op[2].is(); // LOOP
        degree5_op_flags[6] = not_0_yes_1.clone() * op[2].is(); // SPAN
        degree5_op_flags[7] = yes_0_yes_1.clone() * op[2].is(); // JOIN

        // Second half shares same lower 3 bits
        for i in 0..8 {
            degree5_op_flags[i + 8] = degree5_op_flags[i].clone();
        }

        // Update with op_bit[3] and degree 5 flag
        let deg_5_not_3 = op[3].not() * degree_5_flag.clone();
        for flag in degree5_op_flags.iter_mut().take(8) {
            *flag = flag.clone() * deg_5_not_3.clone();
        }
        let deg_5_yes_3 = op[3].is() * degree_5_flag.clone();
        for flag in degree5_op_flags.iter_mut().skip(8) {
            *flag = flag.clone() * deg_5_yes_3.clone();
        }

        // --- Computation of degree 4 operation flags ---

        // Degree 4 flag uses the second degree reduction column
        let degree_4_flag = frame.op_bit_extra(1);

        // Degree 4 flags do not use the first two bits
        degree4_op_flags[0] = not_2_not_3.clone(); // MRUPDATE
        degree4_op_flags[1] = yes_2_not_3; // (unused)
        degree4_op_flags[2] = not_2_yes_3; // SYSCALL
        degree4_op_flags[3] = yes_2_yes_3; // CALL

        // Second half shares same lower 4 bits
        for i in 0..4 {
            degree4_op_flags[i + 4] = degree4_op_flags[i].clone();
        }

        // Update with op_bit[4] and degree 4 flag
        let deg_4_not_4 = op[4].not() * degree_4_flag.clone();
        for flag in degree4_op_flags.iter_mut().take(4) {
            *flag = flag.clone() * deg_4_not_4.clone();
        }
        let deg_4_yes_4 = op[4].is() * degree_4_flag.clone();
        for flag in degree4_op_flags.iter_mut().skip(4) {
            *flag = flag.clone() * deg_4_yes_4.clone();
        }

        // --- No shift composite flags computation ---

        // Flag for END operation causing stack to shift left (depends on whether in loop)
        let shift_left_on_end = degree4_op_flags[4].clone() * frame.is_loop_end();

        no_shift_flags[0] = degree7_op_flags[0].clone() // NOOP
            + degree6_op_flags[5].clone() // U32ASSERT2
            + degree5_op_flags[1].clone() // MPVERIFY
            + degree5_op_flags[6].clone() // SPAN
            + degree5_op_flags[7].clone() // JOIN
            + degree7_op_flags[31].clone() // EMIT
            + degree4_op_flags[6].clone() // RESPAN
            + degree4_op_flags[7].clone() // HALT
            + degree4_op_flags[3].clone() // CALL
            + degree4_op_flags[4].clone() * binary_not(frame.is_loop_end()); // END (non-loop)

        no_shift_flags[1] = no_shift_flags[0].clone() + no_change_1_flag;
        no_shift_flags[2] = no_shift_flags[1].clone()
            + degree7_op_flags[8].clone() // SWAP
            + f1000.clone(); // u32 arithmetic
        no_shift_flags[3] = no_shift_flags[2].clone() + mov2_flag.clone();
        no_shift_flags[4] = no_shift_flags[3].clone()
            + mov3_flag.clone()
            + adv_popw_expacc.clone()
            + swapwx_flag.clone()
            + ext2mul_flag.clone()
            + degree4_op_flags[0].clone(); // MRUPDATE

        no_shift_flags[5] = no_shift_flags[4].clone() + mov4_flag.clone();
        no_shift_flags[6] = no_shift_flags[5].clone() + mov5_flag.clone();
        no_shift_flags[7] = no_shift_flags[6].clone() + mov6_flag.clone();
        no_shift_flags[8] =
            no_shift_flags[7].clone() + mov7_flag.clone() + degree7_op_flags[24].clone()
                - degree7_op_flags[28].clone();

        no_shift_flags[9] = no_shift_flags[8].clone() + mov8_flag.clone();
        no_shift_flags[10] = no_shift_flags[9].clone();
        no_shift_flags[11] = no_shift_flags[9].clone();
        // SWAPW3; SWAPW2; HPERM
        no_shift_flags[12] = no_shift_flags[9].clone() - degree7_op_flags[29].clone()
            + degree7_op_flags[28].clone()
            + degree5_op_flags[0].clone();
        no_shift_flags[13] = no_shift_flags[12].clone();
        no_shift_flags[14] = no_shift_flags[12].clone();
        no_shift_flags[15] = no_shift_flags[12].clone();

        // --- Left shift composite flags computation ---

        let movdnn_flag = degree7_op_flags[11].clone()
            + degree7_op_flags[13].clone()
            + degree7_op_flags[17].clone()
            + degree7_op_flags[19].clone()
            + degree7_op_flags[21].clone()
            + degree7_op_flags[23].clone()
            + degree7_op_flags[27].clone();

        let split_loop_flag = degree5_op_flags[4].clone() + degree5_op_flags[5].clone();
        let add3_madd_flag = degree6_op_flags[6].clone() + degree6_op_flags[7].clone();

        left_shift_flags[1] = degree7_op_flags[32].clone()
            + movdnn_flag.clone()
            + degree7_op_flags[41].clone()
            + degree7_op_flags[45].clone()
            + degree7_op_flags[47].clone()
            + degree7_op_flags[46].clone()
            + split_loop_flag.clone()
            + shift_left_on_end.clone()
            + degree5_op_flags[8].clone() // DYN
            + degree5_op_flags[12].clone(); // DYNCALL

        left_shift_flags[2] = left_shift_flags[1].clone() + left_change_1_flag;
        left_shift_flags[3] =
            left_shift_flags[2].clone() + add3_madd_flag.clone() + degree7_op_flags[42].clone()
                - degree7_op_flags[11].clone();
        left_shift_flags[4] = left_shift_flags[3].clone() - degree7_op_flags[13].clone();
        left_shift_flags[5] = left_shift_flags[4].clone() + degree7_op_flags[44].clone()
            - degree7_op_flags[17].clone();
        left_shift_flags[6] = left_shift_flags[5].clone() - degree7_op_flags[19].clone();
        left_shift_flags[7] = left_shift_flags[6].clone() - degree7_op_flags[21].clone();
        left_shift_flags[8] = left_shift_flags[7].clone() - degree7_op_flags[23].clone();
        left_shift_flags[9] = left_shift_flags[8].clone() + degree7_op_flags[43].clone()
            - degree7_op_flags[27].clone();
        left_shift_flags[10] = left_shift_flags[9].clone();
        left_shift_flags[11] = left_shift_flags[9].clone();
        left_shift_flags[12] = left_shift_flags[9].clone();
        left_shift_flags[13] = left_shift_flags[9].clone();
        left_shift_flags[14] = left_shift_flags[9].clone();
        left_shift_flags[15] = left_shift_flags[9].clone();

        // --- Right shift composite flags computation ---

        let movupn_flag = degree7_op_flags[10].clone()
            + degree7_op_flags[12].clone()
            + degree7_op_flags[16].clone()
            + degree7_op_flags[18].clone()
            + degree7_op_flags[20].clone()
            + degree7_op_flags[22].clone()
            + degree7_op_flags[26].clone();

        right_shift_flags[0] = f011.clone()
            + degree5_op_flags[11].clone() // PUSH
            + movupn_flag.clone();

        right_shift_flags[1] = right_shift_flags[0].clone() + degree6_op_flags[4].clone(); // U32SPLIT

        right_shift_flags[2] = right_shift_flags[1].clone() - degree7_op_flags[10].clone();
        right_shift_flags[3] = right_shift_flags[2].clone() - degree7_op_flags[12].clone();
        right_shift_flags[4] = right_shift_flags[3].clone() - degree7_op_flags[16].clone();
        right_shift_flags[5] = right_shift_flags[4].clone() - degree7_op_flags[18].clone();
        right_shift_flags[6] = right_shift_flags[5].clone() - degree7_op_flags[20].clone();
        right_shift_flags[7] = right_shift_flags[6].clone() - degree7_op_flags[22].clone();
        right_shift_flags[8] = right_shift_flags[7].clone() - degree7_op_flags[26].clone();
        right_shift_flags[9] = right_shift_flags[8].clone();
        right_shift_flags[10] = right_shift_flags[8].clone();
        right_shift_flags[11] = right_shift_flags[8].clone();
        right_shift_flags[12] = right_shift_flags[8].clone();
        right_shift_flags[13] = right_shift_flags[8].clone();
        right_shift_flags[14] = right_shift_flags[8].clone();
        right_shift_flags[15] = right_shift_flags[8].clone();

        // --- Other composite flags ---

        // Flag if stack shifted right (degree 6, dominated by U32SPLIT)
        // Uses prefix_011 (degree 3) instead of f011 (degree 4) for lower base degree
        let right_shift = prefix_011.clone()
            + degree5_op_flags[11].clone() // PUSH
            + degree6_op_flags[4].clone(); // U32SPLIT

        // Flag if stack shifted left (degree 5).
        // Uses low-degree prefixes to keep left_shift at degree 5 (avoids degree growth).
        // Note: DYNCALL is intentionally excluded; see stack overflow depth constraints.
        let left_shift = prefix_010.clone()
            + add3_madd_prefix.clone()
            + split_loop_flag
            + degree4_op_flags[5].clone() // REPEAT
            + shift_left_on_end
            + degree5_op_flags[8].clone(); // DYN

        // Flag if current operation is a control flow operation.
        //
        // Control flow operations are the only operations that can execute when outside a basic
        // block (i.e., when in_span = 0). This is enforced by the decoder constraint:
        //   (1 - in_span) * (1 - control_flow) = 0
        //
        // Control flow operations (must include ALL of these):
        // - Block starters: SPAN, JOIN, SPLIT, LOOP
        // - Block transitions: END, REPEAT, RESPAN, HALT
        // - Dynamic execution: DYN, DYNCALL
        // - Procedure calls: CALL, SYSCALL
        //
        // IMPORTANT: If a new control flow operation is added, it MUST be included here,
        // otherwise the decoder constraint will fail when executing that operation.
        let control_flow = degree_5_flag * op[3].not() * op[2].is() // SPAN, JOIN, SPLIT, LOOP
            + degree_4_flag * op[4].is() // END, REPEAT, RESPAN, HALT
            + degree5_op_flags[8].clone() // DYN
            + degree5_op_flags[12].clone() // DYNCALL
            + degree4_op_flags[2].clone() // SYSCALL
            + degree4_op_flags[3].clone(); // CALL

        // Flag if current operation is a degree 6 u32 operation
        let u32_rc_op = f100;

        // Flag if overflow table contains values
        let overflow = (frame.stack_depth() - E::from_u64(16)) * frame.overflow_register();

        Self {
            degree7_op_flags,
            degree6_op_flags,
            degree5_op_flags,
            degree4_op_flags,
            no_shift_flags,
            left_shift_flags,
            right_shift_flags,
            left_shift,
            right_shift,
            control_flow,
            overflow,
            u32_rc_op,
        }
    }

    // STATE ACCESSORS
    // ============================================================================================

    // ------ Operation flags ---------------------------------------------------------------------

    op_flag_getters!(degree7_op_flags,
        /// Operation Flag of NOOP operation.
        #[allow(dead_code)]
        noop => Operation::Noop,
        /// Operation Flag of EQZ operation.
        eqz => Operation::Eqz,
        /// Operation Flag of NEG operation.
        neg => Operation::Neg,
        /// Operation Flag of INV operation.
        inv => Operation::Inv,
        /// Operation Flag of INCR operation.
        incr => Operation::Incr,
        /// Operation Flag of NOT operation.
        not => Operation::Not,
        /// Operation Flag of MLOAD operation.
        mload => Operation::MLoad,
        /// Operation Flag of SWAP operation.
        swap => Operation::Swap,
        /// Operation Flag of CALLER operation.
        ///
        /// CALLER overwrites the top 4 stack elements with the hash of the function
        /// that initiated the current SYSCALL.
        caller => Operation::Caller,
        /// Operation Flag of MOVUP2 operation.
        movup2 => Operation::MovUp2,
        /// Operation Flag of MOVDN2 operation.
        movdn2 => Operation::MovDn2,
        /// Operation Flag of MOVUP3 operation.
        movup3 => Operation::MovUp3,
        /// Operation Flag of MOVDN3 operation.
        movdn3 => Operation::MovDn3,
        /// Operation Flag of ADVPOPW operation.
        #[allow(dead_code)]
        advpopw => Operation::AdvPopW,
        /// Operation Flag of EXPACC operation.
        expacc => Operation::Expacc,
        /// Operation Flag of MOVUP4 operation.
        movup4 => Operation::MovUp4,
        /// Operation Flag of MOVDN4 operation.
        movdn4 => Operation::MovDn4,
        /// Operation Flag of MOVUP5 operation.
        movup5 => Operation::MovUp5,
        /// Operation Flag of MOVDN5 operation.
        movdn5 => Operation::MovDn5,
        /// Operation Flag of MOVUP6 operation.
        movup6 => Operation::MovUp6,
        /// Operation Flag of MOVDN6 operation.
        movdn6 => Operation::MovDn6,
        /// Operation Flag of MOVUP7 operation.
        movup7 => Operation::MovUp7,
        /// Operation Flag of MOVDN7 operation.
        movdn7 => Operation::MovDn7,
        /// Operation Flag of SWAPW operation.
        swapw => Operation::SwapW,
        /// Operation Flag of MOVUP8 operation.
        movup8 => Operation::MovUp8,
        /// Operation Flag of MOVDN8 operation.
        movdn8 => Operation::MovDn8,
        /// Operation Flag of SWAPW2 operation.
        swapw2 => Operation::SwapW2,
        /// Operation Flag of SWAPW3 operation.
        swapw3 => Operation::SwapW3,
        /// Operation Flag of SWAPDW operation.
        swapdw => Operation::SwapDW,
        /// Operation Flag of EXT2MUL operation.
        ext2mul => Operation::Ext2Mul,
        /// Operation Flag of ASSERT operation.
        assert_op => Operation::Assert(miden_core::ZERO),
        /// Operation Flag of EQ operation.
        eq => Operation::Eq,
        /// Operation Flag of ADD operation.
        add => Operation::Add,
        /// Operation Flag of MUL operation.
        mul => Operation::Mul,
        /// Operation Flag of AND operation.
        and => Operation::And,
        /// Operation Flag of OR operation.
        or => Operation::Or,
        /// Operation Flag of U32AND operation.
        u32and => Operation::U32and,
        /// Operation Flag of U32XOR operation.
        u32xor => Operation::U32xor,
        /// Operation Flag of DROP operation.
        #[allow(dead_code)]
        drop => Operation::Drop,
        /// Operation Flag of CSWAP operation.
        cswap => Operation::CSwap,
        /// Operation Flag of CSWAPW operation.
        cswapw => Operation::CSwapW,
        /// Operation Flag of MLOADW operation.
        mloadw => Operation::MLoadW,
        /// Operation Flag of MSTORE operation.
        mstore => Operation::MStore,
        /// Operation Flag of MSTOREW operation.
        mstorew => Operation::MStoreW,
        /// Operation Flag of PAD operation.
        pad => Operation::Pad,
        /// Operation Flag of DUP operation.
        dup => Operation::Dup0,
        /// Operation Flag of DUP1 operation.
        dup1 => Operation::Dup1,
        /// Operation Flag of DUP2 operation.
        dup2 => Operation::Dup2,
        /// Operation Flag of DUP3 operation.
        dup3 => Operation::Dup3,
        /// Operation Flag of DUP4 operation.
        dup4 => Operation::Dup4,
        /// Operation Flag of DUP5 operation.
        dup5 => Operation::Dup5,
        /// Operation Flag of DUP6 operation.
        dup6 => Operation::Dup6,
        /// Operation Flag of DUP7 operation.
        dup7 => Operation::Dup7,
        /// Operation Flag of DUP9 operation.
        dup9 => Operation::Dup9,
        /// Operation Flag of DUP11 operation.
        dup11 => Operation::Dup11,
        /// Operation Flag of DUP13 operation.
        dup13 => Operation::Dup13,
        /// Operation Flag of DUP15 operation.
        dup15 => Operation::Dup15,
        /// Operation Flag of ADVPOP operation.
        #[allow(dead_code)]
        advpop => Operation::AdvPop,
        /// Operation Flag of SDEPTH operation.
        sdepth => Operation::SDepth,
        /// Operation Flag of CLK operation.
        clk => Operation::Clk,
    );

    // ------ Degree 6 u32 operations  ------------------------------------------------------------

    op_flag_getters!(degree6_op_flags,
        /// Operation Flag of U32ADD operation.
        u32add => Operation::U32add,
        /// Operation Flag of U32SUB operation.
        u32sub => Operation::U32sub,
        /// Operation Flag of U32MUL operation.
        u32mul => Operation::U32mul,
        /// Operation Flag of U32DIV operation.
        u32div => Operation::U32div,
        /// Operation Flag of U32SPLIT operation.
        u32split => Operation::U32split,
        /// Operation Flag of U32ASSERT2 operation.
        u32assert2 => Operation::U32assert2(miden_core::ZERO),
        /// Operation Flag of U32ADD3 operation.
        u32add3 => Operation::U32add3,
        /// Operation Flag of U32MADD operation.
        u32madd => Operation::U32madd,
    );

    // ------ Degree 5 operations  ----------------------------------------------------------------

    op_flag_getters!(degree5_op_flags,
        /// Operation Flag of HPERM operation.
        hperm => Operation::HPerm,
        /// Operation Flag of MPVERIFY operation.
        mpverify => Operation::MpVerify(miden_core::ZERO),
        /// Operation Flag of SPLIT operation.
        split => Operation::Split,
        /// Operation Flag of LOOP operation.
        loop_op => Operation::Loop,
        /// Operation Flag of SPAN operation.
        span => Operation::Span,
        /// Operation Flag of JOIN operation.
        join => Operation::Join,
        /// Operation Flag of PUSH operation.
        push => Operation::Push(miden_core::ONE),
        /// Operation Flag of DYN operation.
        dyn_op => Operation::Dyn,
        /// Operation Flag of DYNCALL operation.
        dyncall => Operation::Dyncall,
        /// Operation Flag of EVALCIRCUIT operation.
        evalcircuit => Operation::EvalCircuit,
        /// Operation Flag of LOG_PRECOMPILE operation.
        log_precompile => Operation::LogPrecompile,
        /// Operation Flag of HORNERBASE operation.
        hornerbase => Operation::HornerBase,
        /// Operation Flag of HORNEREXT operation.
        hornerext => Operation::HornerExt,
        /// Operation Flag of MSTREAM operation.
        mstream => Operation::MStream,
        /// Operation Flag of PIPE operation.
        pipe => Operation::Pipe,
    );

    // ------ Degree 4 operations  ----------------------------------------------------------------

    op_flag_getters!(degree4_op_flags,
        /// Operation Flag of MRUPDATE operation.
        mrupdate => Operation::MrUpdate,
        /// Operation Flag of CALL operation.
        call => Operation::Call,
        /// Operation Flag of SYSCALL operation.
        syscall => Operation::SysCall,
        /// Operation Flag of END operation.
        end => Operation::End,
        /// Operation Flag of REPEAT operation.
        repeat => Operation::Repeat,
        /// Operation Flag of RESPAN operation.
        respan => Operation::Respan,
        /// Operation Flag of HALT operation.
        halt => Operation::Halt,
        /// Operation Flag of CRYPTOSTREAM operation.
        cryptostream => Operation::CryptoStream,
    );

    // ------ Composite Flags ---------------------------------------------------------------------

    /// Returns the flag for when the stack item at the specified depth remains unchanged.
    #[inline(always)]
    pub fn no_shift_at(&self, index: usize) -> E {
        self.no_shift_flags[index].clone()
    }

    /// Returns the flag for when the stack item at the specified depth shifts left.
    /// Left shift is not defined on position 0, so returns default for index 0.
    #[inline(always)]
    pub fn left_shift_at(&self, index: usize) -> E {
        self.left_shift_flags[index].clone()
    }

    /// Returns the flag for when the stack item at the specified depth shifts right.
    #[inline(always)]
    pub fn right_shift_at(&self, index: usize) -> E {
        self.right_shift_flags[index].clone()
    }

    /// Returns the flag when the stack operation shifts the stack to the right.
    /// Degree: 6
    #[inline(always)]
    pub fn right_shift(&self) -> E {
        self.right_shift.clone()
    }

    /// Returns the flag when the stack operation shifts the stack to the left.
    ///
    /// Note: `DYNCALL` still shifts the stack, but it is handled via the per-position
    /// `left_shift_at` flags. The aggregate `left_shift` flag only gates the generic
    /// helper/overflow constraints, which do not apply to `DYNCALL` because those
    /// helper columns are reused for the context switch and the overflow pointer is
    /// stored in decoder hasher state (h5), not in the usual helper/stack columns.
    /// Degree: 5
    #[inline(always)]
    pub fn left_shift(&self) -> E {
        self.left_shift.clone()
    }

    /// Returns the flag when the current operation is a control flow operation.
    ///
    /// Control flow operations are the only operations allowed to execute when outside a basic
    /// block (i.e., when in_span = 0). This includes:
    /// - Block starters: SPAN, JOIN, SPLIT, LOOP
    /// - Block transitions: END, REPEAT, RESPAN, HALT
    /// - Dynamic execution: DYN, DYNCALL
    /// - Procedure calls: CALL, SYSCALL
    ///
    /// Used by the decoder constraint: `(1 - in_span) * (1 - control_flow) = 0`
    ///
    /// Degree: 3
    #[inline(always)]
    pub fn control_flow(&self) -> E {
        self.control_flow.clone()
    }

    /// Returns the flag when the current operation is a u32 operation requiring range checks.
    #[inline(always)]
    #[allow(dead_code)]
    pub fn u32_rc_op(&self) -> E {
        self.u32_rc_op.clone()
    }

    /// Returns the flag indicating whether the overflow stack contains values.
    /// Degree: 2
    #[inline(always)]
    pub fn overflow(&self) -> E {
        self.overflow.clone()
    }

    // TEST ACCESSORS
    // ============================================================================================

    /// Returns reference to degree 7 operation flags array (for testing).
    #[cfg(test)]
    pub fn degree7_op_flags(&self) -> &[E; NUM_DEGREE_7_OPS] {
        &self.degree7_op_flags
    }

    /// Returns reference to degree 6 operation flags array (for testing).
    #[cfg(test)]
    pub fn degree6_op_flags(&self) -> &[E; NUM_DEGREE_6_OPS] {
        &self.degree6_op_flags
    }

    /// Returns reference to degree 5 operation flags array (for testing).
    #[cfg(test)]
    pub fn degree5_op_flags(&self) -> &[E; NUM_DEGREE_5_OPS] {
        &self.degree5_op_flags
    }

    /// Returns reference to degree 4 operation flags array (for testing).
    #[cfg(test)]
    pub fn degree4_op_flags(&self) -> &[E; NUM_DEGREE_4_OPS] {
        &self.degree4_op_flags
    }
}

// INTERNAL HELPERS
// ================================================================================================

/// Maps opcode of an operation to the index in its respective degree flag array.
pub const fn get_op_index(opcode: u8) -> usize {
    let opcode = opcode as usize;

    if opcode <= DEGREE_7_OPCODE_ENDS {
        // Index of a degree 7 operation (0-63)
        opcode
    } else if opcode <= DEGREE_6_OPCODE_ENDS {
        // Index of a degree 6 operation (64-79, even opcodes only)
        (opcode - DEGREE_6_OPCODE_STARTS) / 2
    } else if opcode <= DEGREE_5_OPCODE_ENDS {
        // Index of a degree 5 operation (80-95)
        opcode - DEGREE_5_OPCODE_STARTS
    } else {
        // Index of a degree 4 operation (96-127, every 4th opcode)
        (opcode - DEGREE_4_OPCODE_STARTS) / 4
    }
}

// TEST HELPERS
// ================================================================================================

/// Generates a test trace row with the op bits set for a given opcode.
///
/// This creates a minimal trace row where:
/// - Op bits are set according to the opcode's binary representation
/// - Op bits extra columns are computed for degree reduction
/// - All other columns are zero
#[cfg(test)]
pub fn generate_test_row(opcode: usize) -> crate::MainTraceRow<miden_core::Felt> {
    use miden_core::{ONE, ZERO};

    use crate::trace::{
        CHIPLETS_WIDTH, DECODER_TRACE_WIDTH, RANGE_CHECK_TRACE_WIDTH, STACK_TRACE_WIDTH,
        decoder::OP_BITS_EXTRA_COLS_RANGE,
    };

    // Get op bits for this opcode
    let op_bits = get_op_bits(opcode);

    // Initialize decoder array with zeros
    let mut decoder = [ZERO; DECODER_TRACE_WIDTH];

    // Set op bits (indices 1-7 in decoder, after addr column at index 0)
    for (i, &bit) in op_bits.iter().enumerate() {
        decoder[OP_BITS_RANGE.start + i] = bit;
    }

    // Compute and set op bits extra columns for degree reduction
    let bit_6 = op_bits[6];
    let bit_5 = op_bits[5];
    let bit_4 = op_bits[4];

    // op_bit_extra[0] = bit_6 * (1 - bit_5) * bit_4 (degree 5 flag)
    decoder[OP_BITS_EXTRA_COLS_RANGE.start] = bit_6 * (ONE - bit_5) * bit_4;

    // op_bit_extra[1] = bit_6 * bit_5 (degree 4 flag)
    decoder[OP_BITS_EXTRA_COLS_RANGE.start + 1] = bit_6 * bit_5;

    crate::MainTraceRow {
        clk: ZERO,
        ctx: ZERO,
        fn_hash: [ZERO; 4],
        decoder,
        stack: [ZERO; STACK_TRACE_WIDTH],
        range: [ZERO; RANGE_CHECK_TRACE_WIDTH],
        chiplets: [ZERO; CHIPLETS_WIDTH],
    }
}

/// Returns a 7-bit array representation of an opcode.
#[cfg(test)]
pub fn get_op_bits(opcode: usize) -> [miden_core::Felt; NUM_OP_BITS] {
    use miden_core::{Felt, ZERO};

    let mut opcode_copy = opcode;
    let mut bit_array = [ZERO; NUM_OP_BITS];

    for bit in bit_array.iter_mut() {
        *bit = Felt::new((opcode_copy & 1) as u64);
        opcode_copy >>= 1;
    }

    assert_eq!(opcode_copy, 0, "Opcode must be 7 bits");
    bit_array
}

#[cfg(test)]
mod tests;
