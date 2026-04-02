//! Operation flags for stack constraints.
//!
//! This module computes operation flags from decoder op bits. These flags are used
//! throughout stack constraints to gate constraint enforcement based on which operation
//! is currently being executed.
//!
//! ## Opcode Bit Layout
//!
//! Each opcode is 7 bits `[b0, b1, b2, b3, b4, b5, b6]` (b0 = LSB):
//!
//! ```text
//!   b6 b5 b4 | Degree | Opcodes  | Description
//!   ---------+--------+----------+---------------------------
//!    0  *  *  |   7    |  0 - 63  | All 7 bits discriminate
//!    1  0  0  |   6    | 64 - 79  | u32 ops (b0 unused)
//!    1  0  1  |   5    | 80 - 95  | Uses extra[0] column
//!    1  1  *  |   4    | 96 - 127 | Uses extra[1] column
//! ```
//!
//! ## Composite Flags
//!
//! The module also computes composite flags that combine multiple operations:
//! - `no_shift_at(i)`: stack position i unchanged
//! - `left_shift_at(i)`: stack shifts left at position i
//! - `right_shift_at(i)`: stack shifts right at position i

use core::array;

use miden_core::{
    field::{Algebra, PrimeCharacteristicRing},
    operations::opcodes,
};

#[cfg(test)]
use crate::trace::decoder::{NUM_OP_BITS, OP_BITS_RANGE};
use crate::trace::{DecoderCols, StackCols};

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
#[cfg(test)]
const DEGREE_4_OPCODE_ENDS: usize = DEGREE_4_OPCODE_STARTS + 31;

/// Op bit selectors: `bits[k][0]` = 1 - b_k (negation), `bits[k][1]` = b_k (value).
type OpBits<E> = [[E; 2]; 7];

/// Builds a prefix sum from sparse `(index, delta)` pairs.
///
/// Each entry adds `delta` at the given index. Gaps carry the previous value forward.
fn prefix_sum_sparse<const N: usize, E>(changes: &[(usize, E)]) -> [E; N]
where
    E: Clone + Default + core::ops::Add<Output = E>,
{
    let mut result: [E; N] = core::array::from_fn(|_| E::default());
    let mut ci = 0;
    for i in 0..N {
        if i > 0 {
            result[i] = result[i - 1].clone();
        }
        if ci < changes.len() && changes[ci].0 == i {
            result[i] = result[i].clone() + changes[ci].1.clone();
            ci += 1;
        }
    }
    result
}

// OP FLAGS
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

    // Next-row control flow flags (degree 4)
    end_next: E,
    repeat_next: E,
    respan_next: E,
    halt_next: E,
}

impl<E> OpFlags<E>
where
    E: PrimeCharacteristicRing,
{
    /// Creates a new OpFlags instance by computing all flags from the decoder columns.
    ///
    /// Builds flags for the current row from `decoder`/`stack`, and also computes
    /// degree-4 next-row control flow flags (END, REPEAT, RESPAN, HALT) from
    /// `decoder_next`, so that callers never need to construct a second `OpFlags`.
    ///
    /// The computation uses intermediate values to minimize multiplications:
    /// - Degree 7 flags: computed hierarchically from op bits
    /// - Degree 6 flags: u32 operations, share common prefix `100`
    /// - Degree 5 flags: use op_bit_extra[0] for degree reduction
    /// - Degree 4 flags: use op_bit_extra[1] for degree reduction
    pub fn new<V>(
        decoder: &DecoderCols<V>,
        stack: &StackCols<V>,
        decoder_next: &DecoderCols<V>,
    ) -> Self
    where
        V: Copy,
        E: Algebra<V>,
    {
        // Op bit selectors: bits[k][v] returns bit k with value v (0=negated, 1=value).
        let bits: OpBits<E> = array::from_fn(|k| {
            let val = decoder.op_bits[k];
            [E::ONE - val, val.into()]
        });
        // --- Precomputed multi-bit selector products ---
        // Each array is built iteratively: prev[i>>1] * bits[next_bit][i&1].
        // MSB expanded first so index = MSB*2^(n-1) + ... + LSB.

        // b32: index = b3*2 + b2. Shared by degree-6, degree-5, and degree-7.
        let b32: [E; 4] = array::from_fn(|i| bits[3][i >> 1].clone() * bits[2][i & 1].clone());
        // b321: index = b3*4 + b2*2 + b1. Used by degree-6 and degree-7 (with nb6 prefix).
        let b321: [E; 8] = array::from_fn(|i| b32[i >> 1].clone() * bits[1][i & 1].clone());
        // b3210: index = b3*8 + b2*4 + b1*2 + b0. Used by degree-5.
        let b3210: [E; 16] = array::from_fn(|i| b321[i >> 1].clone() * bits[0][i & 1].clone());
        // b432: index = b4*4 + b3*2 + b2. Used by degree-4. Reuses b32.
        let b432: [E; 8] = array::from_fn(|i| bits[4][i >> 2].clone() * b32[i & 3].clone());
        // b654: index = b5*2 + b4 (b6 always negated). Used by degree-7.
        let b654: [E; 4] = array::from_fn(|i| {
            bits[5][i >> 1].clone() * bits[4][i & 1].clone() * bits[6][0].clone()
        });
        // b654321: all bits except b0. index = b5*16 + b4*8 + b3*4 + b2*2 + b1. Reuses b321.
        let b654321: [E; 32] = array::from_fn(|i| b654[i >> 3].clone() * b321[i & 7].clone());

        // --- Degree-7 flags (opcodes 0-63) ---
        // 64 flags, one per opcode. Each is a degree-7 product of all 7 bit selectors.
        // b654321 holds the pre-b0 intermediates (degree 6) that pair adjacent opcodes
        // differing only in the LSB (e.g., MOVUP2 and MOVDN2).
        let pre_b0 = PreB0Flags {
            movup_or_movdn: [
                b654321[opcodes::MOVUP2 as usize >> 1].clone(), // MOVUP2 | MOVDN2
                b654321[opcodes::MOVUP3 as usize >> 1].clone(), // MOVUP3 | MOVDN3
                b654321[opcodes::MOVUP4 as usize >> 1].clone(), // MOVUP4 | MOVDN4
                b654321[opcodes::MOVUP5 as usize >> 1].clone(), // MOVUP5 | MOVDN5
                b654321[opcodes::MOVUP6 as usize >> 1].clone(), // MOVUP6 | MOVDN6
                b654321[opcodes::MOVUP7 as usize >> 1].clone(), // MOVUP7 | MOVDN7
                b654321[opcodes::MOVUP8 as usize >> 1].clone(), // MOVUP8 | MOVDN8
            ],
            swapw2_or_swapw3: b654321[opcodes::SWAPW2 as usize >> 1].clone(),
            advpopw_or_expacc: b654321[opcodes::ADVPOPW as usize >> 1].clone(),
        };
        let degree7_op_flags: [E; NUM_DEGREE_7_OPS] =
            array::from_fn(|i| b654321[i >> 1].clone() * bits[0][i & 1].clone());

        // --- Degree-6 flags (opcodes 64-79, u32 operations) ---
        // Prefix `100` (b6=1, b5=0, b4=0), discriminated by [b1, b2, b3].
        // Index = b3*4 + b2*2 + b1:
        // - 0: U32ADD       - 1: U32SUB
        // - 2: U32MUL       - 3: U32DIV
        // - 4: U32SPLIT     - 5: U32ASSERT2
        // - 6: U32ADD3      - 7: U32MADD
        let degree6_prefix = bits[6][1].clone() * bits[5][0].clone() * bits[4][0].clone();
        let degree6_op_flags: [E; NUM_DEGREE_6_OPS] =
            array::from_fn(|i| degree6_prefix.clone() * b321[i].clone());

        // --- Degree-5 flags (opcodes 80-95) ---
        // Uses extra[0] = b6*(1-b5)*b4 (degree 3), discriminated by [b0, b1, b2, b3].
        // Index = b3*8 + b2*4 + b1*2 + b0:
        // - 0: HPERM          -  1: MPVERIFY
        // - 2: PIPE           -  3: MSTREAM
        // - 4: SPLIT          -  5: LOOP
        // - 6: SPAN           -  7: JOIN
        // - 8: DYN            -  9: HORNERBASE
        // - 10: HORNEREXT      - 11: PUSH
        // - 12: DYNCALL        - 13: EVALCIRCUIT
        // - 14: LOGPRECOMPILE  - 15: (unused)
        let degree5_extra: E = decoder.extra[0].into();
        let degree5_op_flags: [E; NUM_DEGREE_5_OPS] =
            array::from_fn(|i| degree5_extra.clone() * b3210[i].clone());

        // --- Degree-4 flags (opcodes 96-127) ---
        // Uses extra[1] = b6*b5 (degree 2), discriminated by [b2, b3, b4].
        // Index = b4*4 + b3*2 + b2:
        // - 0: MRUPDATE      - 1: CRYPTOSTREAM
        // - 2: SYSCALL        - 3: CALL
        // - 4: END            - 5: REPEAT
        // - 6: RESPAN         - 7: HALT
        let degree4_extra = decoder.extra[1];
        let degree4_op_flags: [E; NUM_DEGREE_4_OPS] =
            array::from_fn(|i| b432[i].clone() * degree4_extra);

        // --- Composite flags ---
        let composite = Self::compute_composite_flags::<V>(
            &bits,
            &degree7_op_flags,
            &pre_b0,
            &degree6_op_flags,
            &degree5_op_flags,
            &degree4_op_flags,
            decoder,
            stack,
        );

        // --- Next-row control flow flags (degree 4) ---
        // Detect END, REPEAT, RESPAN, HALT on the *next* row.
        // Prefix = extra[1]' * b4' = b6'*b5'*b4'.
        // - END    = 0b0111_0000 → prefix * (1-b3') * (1-b2')
        // - REPEAT = 0b0111_0100 → prefix * (1-b3') * b2'
        // - RESPAN = 0b0111_1000 → prefix * b3' * (1-b2')
        // - HALT   = 0b0111_1100 → prefix * b3' * b2'
        let (end_next, repeat_next, respan_next, halt_next) = {
            let prefix: E = decoder_next.extra[1].into();
            let prefix = prefix * decoder_next.op_bits[4];
            // b32_next[i] = b3'[i>>1] * b2'[i&1], same pattern as b32 above.
            let b32_next: [E; 4] = {
                let b3 = decoder_next.op_bits[3];
                let b2 = decoder_next.op_bits[2];
                let bits_next: [[E; 2]; 2] = [[E::ONE - b2, b2.into()], [E::ONE - b3, b3.into()]];
                array::from_fn(|i| bits_next[1][i >> 1].clone() * bits_next[0][i & 1].clone())
            };
            (
                prefix.clone() * b32_next[0].clone(), // END:    (1-b3') * (1-b2')
                prefix.clone() * b32_next[1].clone(), // REPEAT: (1-b3') * b2'
                prefix.clone() * b32_next[2].clone(), // RESPAN: b3' * (1-b2')
                prefix * b32_next[3].clone(),         // HALT:   b3' * b2'
            )
        };

        Self {
            degree7_op_flags,
            degree6_op_flags,
            degree5_op_flags,
            degree4_op_flags,
            no_shift_flags: composite.no_shift,
            left_shift_flags: composite.left_shift,
            right_shift_flags: composite.right_shift,
            left_shift: composite.left_shift_scalar,
            right_shift: composite.right_shift_scalar,
            control_flow: composite.control_flow,
            overflow: composite.overflow,
            u32_rc_op: composite.u32_rc_op,
            end_next,
            repeat_next,
            respan_next,
            halt_next,
        }
    }

    // COMPOSITE FLAGS
    // ============================================================================================

    /// Computes composite stack-shift flags, control flow flag, and overflow flag.
    ///
    /// Each `no_shift[d]` / `left_shift[d]` / `right_shift[d]` is the sum of all
    /// operation flags whose stack impact matches that shift at depth `d`. These are
    /// built incrementally: each depth adds or removes operations relative to the
    /// previous depth.
    #[allow(clippy::too_many_arguments)]
    fn compute_composite_flags<V>(
        bits: &OpBits<E>,
        deg7: &[E; NUM_DEGREE_7_OPS],
        pre_b0: &PreB0Flags<E>,
        deg6: &[E; NUM_DEGREE_6_OPS],
        deg5: &[E; NUM_DEGREE_5_OPS],
        deg4: &[E; NUM_DEGREE_4_OPS],
        decoder: &DecoderCols<V>,
        stack: &StackCols<V>,
    ) -> CompositeFlags<E>
    where
        V: Copy,
        E: Algebra<V>,
    {
        // --- Low-degree prefix selectors for scalar shift flags ---
        // per spec: https://0xmiden.github.io/miden-vm/design/stack/op_constraints.html#shift-left-flag

        // Prefix `010`: (1-b6)*b5*(1-b4) — degree 3, covers left-shift degree-7 ops
        let prefix_010 = bits[6][0].clone() * bits[5][1].clone() * bits[4][0].clone();

        // Prefix `011`: (1-b6)*b5*b4 — degree 3, covers right-shift degree-7 ops
        let prefix_011 = bits[6][0].clone() * bits[5][1].clone() * bits[4][1].clone();

        // Prefix `10011`: b6*(1-b5)*(1-b4)*b3*b2 — degree 5, covers U32ADD3 and U32MADD
        let add3_madd_prefix = bits[6][1].clone()
            * bits[5][0].clone()
            * bits[4][0].clone()
            * bits[3][1].clone()
            * bits[2][1].clone();

        // --- Named flag references ---
        // Degree-7 individual flags used in composite computation.
        let f_noop = deg7[opcodes::NOOP as usize].clone();
        let f_swap = deg7[opcodes::SWAP as usize].clone();
        let f_movup2 = deg7[opcodes::MOVUP2 as usize].clone();
        let f_movdn2 = deg7[opcodes::MOVDN2 as usize].clone();
        let f_movup3 = deg7[opcodes::MOVUP3 as usize].clone();
        let f_movdn3 = deg7[opcodes::MOVDN3 as usize].clone();
        let f_movup4 = deg7[opcodes::MOVUP4 as usize].clone();
        let f_movdn4 = deg7[opcodes::MOVDN4 as usize].clone();
        let f_movup5 = deg7[opcodes::MOVUP5 as usize].clone();
        let f_movdn5 = deg7[opcodes::MOVDN5 as usize].clone();
        let f_movup6 = deg7[opcodes::MOVUP6 as usize].clone();
        let f_movdn6 = deg7[opcodes::MOVDN6 as usize].clone();
        let f_movup7 = deg7[opcodes::MOVUP7 as usize].clone();
        let f_movdn7 = deg7[opcodes::MOVDN7 as usize].clone();
        let f_swapw = deg7[opcodes::SWAPW as usize].clone();
        let f_ext2mul = deg7[opcodes::EXT2MUL as usize].clone();
        let f_movup8 = deg7[opcodes::MOVUP8 as usize].clone();
        let f_movdn8 = deg7[opcodes::MOVDN8 as usize].clone();
        let f_swapw3 = deg7[opcodes::SWAPW3 as usize].clone();
        let f_emit = deg7[opcodes::EMIT as usize].clone();
        let f_assert = deg7[opcodes::ASSERT as usize].clone();
        let f_drop = deg7[opcodes::DROP as usize].clone();
        let f_cswap = deg7[opcodes::CSWAP as usize].clone();
        let f_cswapw = deg7[opcodes::CSWAPW as usize].clone();
        let f_mloadw = deg7[opcodes::MLOADW as usize].clone();
        let f_mstore = deg7[opcodes::MSTORE as usize].clone();
        let f_mstorew = deg7[opcodes::MSTOREW as usize].clone();

        // Degree-6 (u32) flags.
        let f_u32assert2 = deg6[get_op_index(opcodes::U32ASSERT2)].clone();
        let f_u32split = deg6[get_op_index(opcodes::U32SPLIT)].clone();
        let f_u32add3 = deg6[get_op_index(opcodes::U32ADD3)].clone();
        let f_u32madd = deg6[get_op_index(opcodes::U32MADD)].clone();

        // Degree-5 flags.
        let f_hperm = deg5[get_op_index(opcodes::HPERM)].clone();
        let f_mpverify = deg5[get_op_index(opcodes::MPVERIFY)].clone();
        let f_split = deg5[get_op_index(opcodes::SPLIT)].clone();
        let f_loop = deg5[get_op_index(opcodes::LOOP)].clone();
        let f_span = deg5[get_op_index(opcodes::SPAN)].clone();
        let f_join = deg5[get_op_index(opcodes::JOIN)].clone();
        let f_push = deg5[get_op_index(opcodes::PUSH)].clone();
        let f_dyn = deg5[get_op_index(opcodes::DYN)].clone();
        let f_dyncall = deg5[get_op_index(opcodes::DYNCALL)].clone();

        // Degree-4 flags.
        let f_mrupdate = deg4[get_op_index(opcodes::MRUPDATE)].clone();
        let f_syscall = deg4[get_op_index(opcodes::SYSCALL)].clone();
        let f_call = deg4[get_op_index(opcodes::CALL)].clone();
        let f_end = deg4[get_op_index(opcodes::END)].clone();
        let f_repeat = deg4[get_op_index(opcodes::REPEAT)].clone();
        let f_respan = deg4[get_op_index(opcodes::RESPAN)].clone();
        let f_halt = deg4[get_op_index(opcodes::HALT)].clone();

        // --- Prefix-derived group flags (from degree-7 hierarchical splitting) ---

        // Flag of prefix `100` — all degree-6 u32 operations
        let f100 = {
            // Reconstruct from the degree-7 seed: (1-b5)*(1-b4) was at f[0], times b6.
            // This is equivalent to the degree-6 prefix b6*(1-b5)*(1-b4).
            // We recompute to avoid depending on intermediate degree-7 state.
            bits[6][1].clone() * bits[5][0].clone() * bits[4][0].clone()
        };

        // Flag of prefix `1000` — u32 arithmetic operations (U32ADD..U32DIV)
        let f1000 = f100.clone() * bits[3][0].clone();

        // Flag of prefix `011` — degree-7 right-shift operations (PAD..CLK range subset)
        // Computed as sum of the two pre-b0-split halves that correspond to b5=1,b4=1
        let f011 = deg7[48].clone()
            + deg7[49].clone()
            + deg7[50].clone()
            + deg7[51].clone()
            + deg7[52].clone()
            + deg7[53].clone()
            + deg7[54].clone()
            + deg7[55].clone()
            + deg7[56].clone()
            + deg7[57].clone()
            + deg7[58].clone()
            + deg7[59].clone()
            + deg7[60].clone()
            + deg7[61].clone()
            + deg7[62].clone()
            + deg7[63].clone();

        // Flag of prefix `0000` — no-shift from position 1 onwards
        // Sum of all degree-7 flags with b5=0, b4=0, b6=0, b3=0 (opcodes 0..7)
        let f0000 = deg7[0].clone()
            + deg7[1].clone()
            + deg7[2].clone()
            + deg7[3].clone()
            + deg7[4].clone()
            + deg7[5].clone()
            + deg7[6].clone()
            + deg7[7].clone();

        // Flag of prefix `0100` — left shift from position 2 onwards
        // Sum of all degree-7 flags with b6=0, b5=1, b4=0, b3=0 (opcodes 32..39)
        let f0100 = deg7[32].clone()
            + deg7[33].clone()
            + deg7[34].clone()
            + deg7[35].clone()
            + deg7[36].clone()
            + deg7[37].clone()
            + deg7[38].clone()
            + deg7[39].clone();

        // Flag when items from first position onwards are copied over (excludes NOOP)
        let no_change_1_flag = f0000 - f_noop.clone();
        // Flag when items from second position onwards shift left (excludes ASSERT)
        let left_change_1_flag = f0100 - f_assert.clone();

        // --- END operation with loop flag ---
        let is_loop_end = decoder.end_block_flags().is_loop;
        let shift_left_on_end = f_end.clone() * is_loop_end;

        // --- No-shift composite flags ---
        //
        // Depth | New ops that become no-shift at this depth
        // ------+-----------------------------------------------------------
        //   0   | NOOP, U32ASSERT2, MPVERIFY, SPAN, JOIN, EMIT, RESPAN,
        //       | HALT, CALL, END*(1-is_loop)
        //   1   | += prefix 0000 ops except NOOP
        //   2   | += SWAP, u32 arithmetic (prefix 1000)
        //   3   | += MOVUP2|MOVDN2
        //   4   | += MOVUP3|MOVDN3, ADVPOPW|EXPACC, SWAPW2|SWAPW3,
        //       |    EXT2MUL, MRUPDATE
        //   5   | += MOVUP4|MOVDN4
        //   6   | += MOVUP5|MOVDN5
        //   7   | += MOVUP6|MOVDN6
        //   8   | += MOVUP7|MOVDN7, SWAPW; -= SWAPW2|SWAPW3
        //   9   | += MOVUP8|MOVDN8
        // 10-11 | (same as 9)
        // 12-15 | += HPERM, SWAPW2|SWAPW3; -= SWAPW3
        //
        // Each entry: (depth, delta). Gaps carry the previous value forward.
        let d0 = E::sum_array::<9>(&[
            f_noop.clone(),
            f_u32assert2.clone(),
            f_mpverify.clone(),
            f_span.clone(),
            f_join.clone(),
            f_emit.clone(),
            f_respan.clone(),
            f_halt.clone(),
            f_call.clone(),
        ]) + f_end.clone() * (E::ONE - is_loop_end);
        let d4 = E::sum_array::<5>(&[
            pre_b0.movup_or_movdn[1].clone(),
            pre_b0.advpopw_or_expacc.clone(),
            pre_b0.swapw2_or_swapw3.clone(),
            f_ext2mul.clone(),
            f_mrupdate.clone(),
        ]);
        let d8 =
            pre_b0.movup_or_movdn[5].clone() + f_swapw.clone() - pre_b0.swapw2_or_swapw3.clone();
        let d12 = pre_b0.swapw2_or_swapw3.clone() + f_hperm.clone() - f_swapw3.clone();

        let no_shift = prefix_sum_sparse::<NUM_STACK_IMPACT_FLAGS, _>(&[
            (0, d0),
            (1, no_change_1_flag),
            (2, f_swap.clone() + f1000.clone()),
            (3, pre_b0.movup_or_movdn[0].clone()),
            (4, d4),
            (5, pre_b0.movup_or_movdn[2].clone()),
            (6, pre_b0.movup_or_movdn[3].clone()),
            (7, pre_b0.movup_or_movdn[4].clone()),
            (8, d8),
            (9, pre_b0.movup_or_movdn[6].clone()),
            (12, d12),
        ]);

        // --- Left-shift composite flags ---
        //
        // Depth | Ops causing left shift at this depth
        // ------+-----------------------------------------------------------
        //   1   | ASSERT, all MOVDN{2..8}, DROP, MSTORE, MSTOREW,
        //       | opcode 47 (unused slot), SPLIT, LOOP, END*is_loop,
        //       | DYN, DYNCALL
        //   2   | += prefix 010 ops except ASSERT
        //   3   | += CSWAP, U32ADD3, U32MADD; -= MOVDN2
        //   4   | -= MOVDN3
        //   5   | += MLOADW; -= MOVDN4
        //   6   | -= MOVDN5
        //   7   | -= MOVDN6
        //   8   | -= MOVDN7
        //   9   | += CSWAPW; -= MOVDN8
        // 10-15 | (same as 9)

        // Sum of all MOVUP|MOVDN pre-b0 pairs, then split by b0.
        let f_all_mov_pair = E::sum_array::<7>(&pre_b0.movup_or_movdn);
        let f_all_movdn = f_all_mov_pair.clone() * bits[0][1].clone();

        let d1 = E::sum_array::<11>(&[
            f_assert.clone(),
            f_all_movdn,
            f_drop.clone(),
            f_mstore.clone(),
            f_mstorew.clone(),
            deg7[47].clone(),
            f_split.clone(),
            f_loop.clone(),
            shift_left_on_end.clone(),
            f_dyn.clone(),
            f_dyncall.clone(),
        ]);

        let left_shift = prefix_sum_sparse::<NUM_STACK_IMPACT_FLAGS, _>(&[
            (1, d1),
            (2, left_change_1_flag),
            (3, f_u32add3.clone() + f_u32madd.clone() + f_cswap.clone() - f_movdn2.clone()),
            (4, -f_movdn3.clone()),
            (5, f_mloadw.clone() - f_movdn4.clone()),
            (6, -f_movdn5.clone()),
            (7, -f_movdn6.clone()),
            (8, -f_movdn7.clone()),
            (9, f_cswapw.clone() - f_movdn8.clone()),
        ]);

        // --- Right-shift composite flags ---
        //
        // Depth | Ops causing right shift at this depth
        // ------+-----------------------------------------------------------
        //   0   | prefix 011 (PAD..CLK), PUSH, all MOVUP{2..8}
        //   1   | += U32SPLIT
        //   2   | -= MOVUP2
        //   3   | -= MOVUP3
        //   4   | -= MOVUP4
        //   5   | -= MOVUP5
        //   6   | -= MOVUP6
        //   7   | -= MOVUP7
        //   8   | -= MOVUP8
        //  9-15 | (same as 8)

        let f_all_movup = f_all_mov_pair * bits[0][0].clone();

        let right_shift = prefix_sum_sparse::<NUM_STACK_IMPACT_FLAGS, _>(&[
            (0, f011 + f_push.clone() + f_all_movup),
            (1, f_u32split.clone()),
            (2, -f_movup2),
            (3, -f_movup3),
            (4, -f_movup4),
            (5, -f_movup5),
            (6, -f_movup6),
            (7, -f_movup7),
            (8, -f_movup8),
        ]);

        // --- Scalar shift flags ---

        // Flag if stack shifted right (degree 6, dominated by U32SPLIT).
        // Uses prefix_011 (degree 3) instead of f011 (degree 4) for lower base degree.
        let right_shift_scalar = prefix_011 + f_push + f_u32split;

        // Flag if stack shifted left (degree 5).
        // Uses low-degree prefixes to keep left_shift at degree 5 (avoids degree growth).
        // Note: DYNCALL is intentionally excluded; see stack overflow depth constraints.
        let left_shift_scalar = E::sum_array::<7>(&[
            prefix_010,
            add3_madd_prefix,
            f_split,
            f_loop,
            f_repeat,
            shift_left_on_end,
            f_dyn,
        ]);

        // --- Control flow flag ---
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
        let degree_5_flag = decoder.extra[0];
        let degree_4_flag = decoder.extra[1];
        let control_flow = E::sum_array::<6>(&[
            bits[3][0].clone() * bits[2][1].clone() * degree_5_flag, // SPAN, JOIN, SPLIT, LOOP
            bits[4][1].clone() * degree_4_flag,                      // END, REPEAT, RESPAN, HALT
            f_dyncall,                                               // DYNCALL
            deg5[get_op_index(opcodes::DYN)].clone(),                // DYN
            f_syscall,                                               // SYSCALL
            f_call,                                                  // CALL
        ]);

        // Flag if current operation is a degree-6 u32 operation
        let u32_rc_op = f100;

        // Flag if overflow table contains values
        let overflow: E = stack.b0.into();
        let overflow = (overflow - E::from_u64(16)) * stack.h0;

        CompositeFlags {
            no_shift,
            left_shift,
            right_shift,
            left_shift_scalar,
            right_shift_scalar,
            control_flow,
            u32_rc_op,
            overflow,
        }
    }

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

    /// Returns the flag indicating whether the overflow stack contains values.
    /// Degree: 2
    #[inline(always)]
    pub fn overflow(&self) -> E {
        self.overflow.clone()
    }

    // ------ Next-row flags -------------------------------------------------------------------

    /// Returns the flag for END on the next row. Degree: 4
    #[inline(always)]
    pub fn end_next(&self) -> E {
        self.end_next.clone()
    }

    /// Returns the flag for REPEAT on the next row. Degree: 4
    #[inline(always)]
    pub fn repeat_next(&self) -> E {
        self.repeat_next.clone()
    }

    /// Returns the flag for RESPAN on the next row. Degree: 4
    #[inline(always)]
    pub fn respan_next(&self) -> E {
        self.respan_next.clone()
    }

    /// Returns the flag for HALT on the next row. Degree: 4
    #[inline(always)]
    pub fn halt_next(&self) -> E {
        self.halt_next.clone()
    }

    /// Returns the flag when the current operation is a u32 operation requiring range checks.
    #[expect(dead_code)]
    #[inline(always)]
    pub fn u32_rc_op(&self) -> E {
        self.u32_rc_op.clone()
    }
}

macro_rules! op_flag_getters {
    ($array:ident, $( $(#[$meta:meta])* $name:ident => $op:expr ),* $(,)?) => {
        $(
            $(#[$meta])*
            #[inline(always)]
            pub fn $name(&self) -> E {
                self.$array[get_op_index($op)].clone()
            }
        )*
    };
}

impl<E: PrimeCharacteristicRing> OpFlags<E> {
    // STATE ACCESSORS
    // ============================================================================================

    // ------ Operation flags ---------------------------------------------------------------------

    op_flag_getters!(degree7_op_flags,
        /// Operation Flag of NOOP operation.
        #[allow(dead_code)]
        noop => opcodes::NOOP,
        /// Operation Flag of EQZ operation.
        eqz => opcodes::EQZ,
        /// Operation Flag of NEG operation.
        neg => opcodes::NEG,
        /// Operation Flag of INV operation.
        inv => opcodes::INV,
        /// Operation Flag of INCR operation.
        incr => opcodes::INCR,
        /// Operation Flag of NOT operation.
        not => opcodes::NOT,
        /// Operation Flag of MLOAD operation.
        mload => opcodes::MLOAD,
        /// Operation Flag of SWAP operation.
        swap => opcodes::SWAP,
        /// Operation Flag of CALLER operation.
        ///
        /// CALLER overwrites the top 4 stack elements with the hash of the function
        /// that initiated the current SYSCALL.
        caller => opcodes::CALLER,
        /// Operation Flag of MOVUP2 operation.
        movup2 => opcodes::MOVUP2,
        /// Operation Flag of MOVDN2 operation.
        movdn2 => opcodes::MOVDN2,
        /// Operation Flag of MOVUP3 operation.
        movup3 => opcodes::MOVUP3,
        /// Operation Flag of MOVDN3 operation.
        movdn3 => opcodes::MOVDN3,
        /// Operation Flag of ADVPOPW operation.
        #[allow(dead_code)]
        advpopw => opcodes::ADVPOPW,
        /// Operation Flag of EXPACC operation.
        expacc => opcodes::EXPACC,
        /// Operation Flag of MOVUP4 operation.
        movup4 => opcodes::MOVUP4,
        /// Operation Flag of MOVDN4 operation.
        movdn4 => opcodes::MOVDN4,
        /// Operation Flag of MOVUP5 operation.
        movup5 => opcodes::MOVUP5,
        /// Operation Flag of MOVDN5 operation.
        movdn5 => opcodes::MOVDN5,
        /// Operation Flag of MOVUP6 operation.
        movup6 => opcodes::MOVUP6,
        /// Operation Flag of MOVDN6 operation.
        movdn6 => opcodes::MOVDN6,
        /// Operation Flag of MOVUP7 operation.
        movup7 => opcodes::MOVUP7,
        /// Operation Flag of MOVDN7 operation.
        movdn7 => opcodes::MOVDN7,
        /// Operation Flag of SWAPW operation.
        swapw => opcodes::SWAPW,
        /// Operation Flag of MOVUP8 operation.
        movup8 => opcodes::MOVUP8,
        /// Operation Flag of MOVDN8 operation.
        movdn8 => opcodes::MOVDN8,
        /// Operation Flag of SWAPW2 operation.
        swapw2 => opcodes::SWAPW2,
        /// Operation Flag of SWAPW3 operation.
        swapw3 => opcodes::SWAPW3,
        /// Operation Flag of SWAPDW operation.
        swapdw => opcodes::SWAPDW,
        /// Operation Flag of EXT2MUL operation.
        ext2mul => opcodes::EXT2MUL,
        /// Operation Flag of ASSERT operation.
        assert_op => opcodes::ASSERT,
        /// Operation Flag of EQ operation.
        eq => opcodes::EQ,
        /// Operation Flag of ADD operation.
        add => opcodes::ADD,
        /// Operation Flag of MUL operation.
        mul => opcodes::MUL,
        /// Operation Flag of AND operation.
        and => opcodes::AND,
        /// Operation Flag of OR operation.
        or => opcodes::OR,
        /// Operation Flag of U32AND operation.
        u32and => opcodes::U32AND,
        /// Operation Flag of U32XOR operation.
        u32xor => opcodes::U32XOR,
        /// Operation Flag of DROP operation.
        #[allow(dead_code)]
        drop => opcodes::DROP,
        /// Operation Flag of CSWAP operation.
        cswap => opcodes::CSWAP,
        /// Operation Flag of CSWAPW operation.
        cswapw => opcodes::CSWAPW,
        /// Operation Flag of MLOADW operation.
        mloadw => opcodes::MLOADW,
        /// Operation Flag of MSTORE operation.
        mstore => opcodes::MSTORE,
        /// Operation Flag of MSTOREW operation.
        mstorew => opcodes::MSTOREW,
        /// Operation Flag of PAD operation.
        pad => opcodes::PAD,
        /// Operation Flag of DUP operation.
        dup => opcodes::DUP0,
        /// Operation Flag of DUP1 operation.
        dup1 => opcodes::DUP1,
        /// Operation Flag of DUP2 operation.
        dup2 => opcodes::DUP2,
        /// Operation Flag of DUP3 operation.
        dup3 => opcodes::DUP3,
        /// Operation Flag of DUP4 operation.
        dup4 => opcodes::DUP4,
        /// Operation Flag of DUP5 operation.
        dup5 => opcodes::DUP5,
        /// Operation Flag of DUP6 operation.
        dup6 => opcodes::DUP6,
        /// Operation Flag of DUP7 operation.
        dup7 => opcodes::DUP7,
        /// Operation Flag of DUP9 operation.
        dup9 => opcodes::DUP9,
        /// Operation Flag of DUP11 operation.
        dup11 => opcodes::DUP11,
        /// Operation Flag of DUP13 operation.
        dup13 => opcodes::DUP13,
        /// Operation Flag of DUP15 operation.
        dup15 => opcodes::DUP15,
        /// Operation Flag of ADVPOP operation.
        #[allow(dead_code)]
        advpop => opcodes::ADVPOP,
        /// Operation Flag of SDEPTH operation.
        sdepth => opcodes::SDEPTH,
        /// Operation Flag of CLK operation.
        clk => opcodes::CLK,
    );

    // ------ Degree 6 u32 operations  ------------------------------------------------------------

    op_flag_getters!(degree6_op_flags,
        /// Operation Flag of U32ADD operation.
        u32add => opcodes::U32ADD,
        /// Operation Flag of U32SUB operation.
        u32sub => opcodes::U32SUB,
        /// Operation Flag of U32MUL operation.
        u32mul => opcodes::U32MUL,
        /// Operation Flag of U32DIV operation.
        u32div => opcodes::U32DIV,
        /// Operation Flag of U32SPLIT operation.
        u32split => opcodes::U32SPLIT,
        /// Operation Flag of U32ASSERT2 operation.
        u32assert2 => opcodes::U32ASSERT2,
        /// Operation Flag of U32ADD3 operation.
        u32add3 => opcodes::U32ADD3,
        /// Operation Flag of U32MADD operation.
        u32madd => opcodes::U32MADD,
    );

    // ------ Degree 5 operations  ----------------------------------------------------------------

    op_flag_getters!(degree5_op_flags,
        /// Operation Flag of HPERM operation.
        hperm => opcodes::HPERM,
        /// Operation Flag of MPVERIFY operation.
        mpverify => opcodes::MPVERIFY,
        /// Operation Flag of SPLIT operation.
        split => opcodes::SPLIT,
        /// Operation Flag of LOOP operation.
        loop_op => opcodes::LOOP,
        /// Operation Flag of SPAN operation.
        span => opcodes::SPAN,
        /// Operation Flag of JOIN operation.
        join => opcodes::JOIN,
        /// Operation Flag of PUSH operation.
        push => opcodes::PUSH,
        /// Operation Flag of DYN operation.
        dyn_op => opcodes::DYN,
        /// Operation Flag of DYNCALL operation.
        dyncall => opcodes::DYNCALL,
        /// Operation Flag of EVALCIRCUIT operation.
        evalcircuit => opcodes::EVALCIRCUIT,
        /// Operation Flag of LOG_PRECOMPILE operation.
        log_precompile => opcodes::LOGPRECOMPILE,
        /// Operation Flag of HORNERBASE operation.
        hornerbase => opcodes::HORNERBASE,
        /// Operation Flag of HORNEREXT operation.
        hornerext => opcodes::HORNEREXT,
        /// Operation Flag of MSTREAM operation.
        mstream => opcodes::MSTREAM,
        /// Operation Flag of PIPE operation.
        pipe => opcodes::PIPE,
    );

    // ------ Degree 4 operations  ----------------------------------------------------------------

    op_flag_getters!(degree4_op_flags,
        /// Operation Flag of MRUPDATE operation.
        mrupdate => opcodes::MRUPDATE,
        /// Operation Flag of CALL operation.
        call => opcodes::CALL,
        /// Operation Flag of SYSCALL operation.
        syscall => opcodes::SYSCALL,
        /// Operation Flag of END operation.
        end => opcodes::END,
        /// Operation Flag of REPEAT operation.
        repeat => opcodes::REPEAT,
        /// Operation Flag of RESPAN operation.
        respan => opcodes::RESPAN,
        /// Operation Flag of HALT operation.
        halt => opcodes::HALT,
        /// Operation Flag of CRYPTOSTREAM operation.
        cryptostream => opcodes::CRYPTOSTREAM,
    );
}

// INTERNAL HELPERS
// ================================================================================================

/// Pre-b0 intermediate flags captured before the final bit split.
///
/// These are degree-6 products (all bits except b0) that pair adjacent opcodes
/// sharing all bits except the LSB. Used by composite shift flag computation.
struct PreB0Flags<E> {
    /// MOVUP{2..8} | MOVDN{2..8} paired flags, indexed 0..7 for widths 2..8.
    movup_or_movdn: [E; 7],
    /// SWAPW2 | SWAPW3 paired flag.
    swapw2_or_swapw3: E,
    /// ADVPOPW | EXPACC paired flag.
    advpopw_or_expacc: E,
}

/// Composite flag results: shift arrays, scalar flags, and control flow.
struct CompositeFlags<E> {
    no_shift: [E; NUM_STACK_IMPACT_FLAGS],
    left_shift: [E; NUM_STACK_IMPACT_FLAGS],
    right_shift: [E; NUM_STACK_IMPACT_FLAGS],
    left_shift_scalar: E,
    right_shift_scalar: E,
    control_flow: E,
    u32_rc_op: E,
    overflow: E,
}

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
    use miden_core::{Felt, ZERO};

    use crate::trace::{TRACE_WIDTH, decoder::OP_BITS_EXTRA_COLS_RANGE};

    let op_bits = get_op_bits(opcode);

    // Build a flat zeroed row, then set the decoder op bits via the col map.
    let mut row = [ZERO; TRACE_WIDTH];
    for (i, &bit) in op_bits.iter().enumerate() {
        row[OP_BITS_RANGE.start + crate::trace::DECODER_TRACE_OFFSET + i] = bit;
    }

    // Compute and set op bits extra columns for degree reduction.
    let bit_6 = op_bits[6];
    let bit_5 = op_bits[5];
    let bit_4 = op_bits[4];
    row[OP_BITS_EXTRA_COLS_RANGE.start + crate::trace::DECODER_TRACE_OFFSET] =
        bit_6 * (Felt::ONE - bit_5) * bit_4;
    row[OP_BITS_EXTRA_COLS_RANGE.start + 1 + crate::trace::DECODER_TRACE_OFFSET] = bit_6 * bit_5;

    // Safety: MainCols is #[repr(C)] with the same layout as [Felt; TRACE_WIDTH].
    unsafe { core::mem::transmute::<[Felt; TRACE_WIDTH], crate::MainTraceRow<Felt>>(row) }
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
