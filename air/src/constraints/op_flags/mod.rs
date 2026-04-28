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
//! b6 b5 b4 | Degree | Opcodes  | Description
//! ---------+--------+----------+---------------------------
//!  0  *  * |   7    |  0 - 63  | All 7 bits discriminate
//!  1  0  0 |   6    | 64 - 79  | u32 ops (b0 unused)
//!  1  0  1 |   5    | 80 - 95  | Uses extra[0] column
//!  1  1  * |   4    | 96 - 127 | Uses extra[1] column
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

use crate::constraints::{decoder::columns::DecoderCols, stack::columns::StackCols};
#[cfg(test)]
use crate::trace::decoder::{NUM_OP_BITS, OP_BITS_RANGE};

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
            pre_b0,
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
        pre_b0: PreB0Flags<E>,
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
        let PreB0Flags {
            movup_or_movdn,
            swapw2_or_swapw3,
            advpopw_or_expacc,
        } = pre_b0;

        // --- Op flag accessors ---
        let op7 = |op: u8| deg7[op as usize].clone();
        let op6 = |op: u8| deg6[get_op_index(op)].clone();
        let op5 = |op: u8| deg5[get_op_index(op)].clone();
        let op4 = |op: u8| deg4[get_op_index(op)].clone();

        // --- Shared bit-prefix selectors ---

        // prefix_01: (1-b6)*b5 — degree 2, shared by prefix_010 and prefix_011
        let prefix_01 = bits[6][0].clone() * bits[5][1].clone();

        // prefix_100: b6*(1-b5)*(1-b4) — degree 3, all u32 operations (opcodes 64-79)
        let prefix_100 = bits[6][1].clone() * bits[5][0].clone() * bits[4][0].clone();

        // --- END operation with loop flag ---
        let is_loop_end = decoder.end_block_flags().is_loop;
        let end_loop_flag = op4(opcodes::END) * is_loop_end;

        // ── No-shift flags ──────────────────────────────────────────
        // no_shift[d] = sum of op flags whose stack position d is unchanged.
        // Built incrementally via accumulate_depth_deltas.

        let no_shift_depth0 = E::sum_array::<10>(&[
            // +NOOP         — no-op
            op7(opcodes::NOOP),
            // +U32ASSERT2   — checks s0,s1 are u32, no change
            op6(opcodes::U32ASSERT2),
            // +MPVERIFY     — verifies Merkle path in place
            op5(opcodes::MPVERIFY),
            // +SPAN         — control flow: begins basic block
            op5(opcodes::SPAN),
            // +JOIN         — control flow: begins join block
            op5(opcodes::JOIN),
            // +EMIT         — emits event, no stack change
            op7(opcodes::EMIT),
            // +RESPAN       — control flow: next batch in basic block
            op4(opcodes::RESPAN),
            // +HALT         — control flow: ends program
            op4(opcodes::HALT),
            // +CALL         — control flow: enters procedure
            op4(opcodes::CALL),
            // +END*(1-loop) — no-shift only when NOT ending a loop body
            op4(opcodes::END) * (E::ONE - is_loop_end),
        ]);

        // +opcodes[0..8] –NOOP — unary ops that modify only s0 (EQZ, NEG, INV, INCR, NOT, MLOAD)
        let no_shift_depth1 = deg7[0..8].iter().cloned().sum::<E>() - op7(opcodes::NOOP);

        // +U32ADD +U32SUB +U32MUL +U32DIV — consume s0,s1, produce 2 results
        let u32_arith_group = prefix_100.clone() * bits[3][0].clone();

        let no_shift_depth4 = E::sum_array::<5>(&[
            // +MOVUP3|MOVDN3  — permute s0..s3
            movup_or_movdn[1].clone(),
            // +ADVPOPW|EXPACC — overwrite s0..s3 in place
            advpopw_or_expacc,
            // +SWAPW2|SWAPW3  — swap s0..s3 with s8+ (leaves at depth 8)
            swapw2_or_swapw3.clone(),
            // +EXT2MUL        — ext field multiply on s0..s3
            op7(opcodes::EXT2MUL),
            // +MRUPDATE       — Merkle root update on s0..s3
            op4(opcodes::MRUPDATE),
        ]);

        // SWAPW2/SWAPW3 depth lifecycle:
        //   Op      Swaps               No-shift depths
        //   SWAPW2  s[0..4] ↔ s[8..12]  0-7, 12-15
        //   SWAPW3  s[0..4] ↔ s[12..16] 0-7, 8-11
        //   Combined pair: enters at 4, leaves at 8, re-enters at 12 (minus SWAPW3)

        let no_shift_depth8
            // +MOVUP7|MOVDN7  — permute s0..s7
            = movup_or_movdn[5].clone()
            // +SWAPW          — swap s0..s3 with s4..s7, only affects depths 0-7
            + op7(opcodes::SWAPW)
            // –SWAPW2|SWAPW3  — target range s8+ now affected at this depth
            - swapw2_or_swapw3.clone();

        let no_shift_depth12
            // +SWAPW2|SWAPW3 — pair re-enters (both leave depths 12+ untouched)
            = swapw2_or_swapw3
            // +HPERM         — Poseidon2 permutation on s0..s11
            + op5(opcodes::HPERM)
            // –SWAPW3        — SWAPW3 swaps s0..s3 with s12..s15, so s12+ still changes
            - op7(opcodes::SWAPW3);

        let no_shift = accumulate_depth_deltas([
            // d=0
            no_shift_depth0,
            // d=1
            no_shift_depth1,
            // +SWAP            — swap s0,s1
            // +u32_arith_group — U32ADD..U32DIV: consume s0,s1, produce 2 results
            op7(opcodes::SWAP) + u32_arith_group,
            // +MOVUP2|MOVDN2   — permute s0..s2
            movup_or_movdn[0].clone(),
            // d=4
            no_shift_depth4,
            // +MOVUP4|MOVDN4   — permute s0..s4
            movup_or_movdn[2].clone(),
            // +MOVUP5|MOVDN5   — permute s0..s5
            movup_or_movdn[3].clone(),
            // +MOVUP6|MOVDN6   — permute s0..s6
            movup_or_movdn[4].clone(),
            // d=8
            no_shift_depth8,
            // +MOVUP8|MOVDN8   — permute s0..s8
            movup_or_movdn[6].clone(),
            // d=10 (unchanged)
            E::ZERO,
            // d=11 (unchanged)
            E::ZERO,
            // d=12
            no_shift_depth12,
            // d=13 (unchanged)
            E::ZERO,
            // d=14 (unchanged)
            E::ZERO,
            // d=15 (unchanged)
            E::ZERO,
        ]);

        // ── Left-shift flags ────────────────────────────────────────
        // left_shift[d] = sum of op flags causing a left shift at depth d.
        // Built incrementally via accumulate_depth_deltas.

        // All MOVUP/MOVDN pairs share bits [1..6] and differ only in b0:
        //   b0 = 0 → MOVUP{w},  b0 = 1 → MOVDN{w}    (for all widths 2..8)
        let all_mov_pairs = E::sum_array::<7>(&movup_or_movdn);
        let all_movdn = all_mov_pairs.clone() * bits[0][1].clone();

        let left_shift_depth1 = E::sum_array::<11>(&[
            // +ASSERT      — consumes s0 (must be 1)
            op7(opcodes::ASSERT),
            // +MOVDN{2..8} — move s0 down, shifts left above
            all_movdn,
            // +DROP         — discards s0
            op7(opcodes::DROP),
            // +MSTORE       — pops address s0, stores s1 to memory
            op7(opcodes::MSTORE),
            // +MSTOREW      — pops address s0, stores word to memory
            op7(opcodes::MSTOREW),
            // +(opcode 47)  — unused opcode slot
            deg7[47].clone(),
            // +SPLIT        — control flow: pops condition from s0
            op5(opcodes::SPLIT),
            // +LOOP         — control flow: pops condition from s0
            op5(opcodes::LOOP),
            // +END*loop     — END when ending a loop: pops the loop flag
            end_loop_flag.clone(),
            // +DYN          — control flow: consumes s0..s3 (target hash)
            op5(opcodes::DYN),
            // +DYNCALL      — control flow: consumes s0..s3 (target hash)
            op5(opcodes::DYNCALL),
        ]);

        // +opcodes[32..40] –ASSERT — binary ops (EQ, ADD, MUL, AND, OR, U32AND, U32XOR)
        //   that consume s0,s1 and produce 1 result; ASSERT already counted at depth 1
        let left_shift_depth2 = deg7[32..40].iter().cloned().sum::<E>() - op7(opcodes::ASSERT);

        let left_shift_depth3
            // +CSWAP   — pops condition s0, conditionally swaps s1,s2; net -1 at depth 3
            = op7(opcodes::CSWAP)
            // +U32ADD3 — pops s0,s1,s2, pushes 2 results; net -1 at depth 3
            + op6(opcodes::U32ADD3)
            // +U32MADD — pops s0,s1,s2, pushes s0*s1+s2 as 2 results; net -1 at depth 3
            + op6(opcodes::U32MADD)
            // –MOVDN2  — only shifts left at depths 1..2
            - op7(opcodes::MOVDN2);

        let left_shift = accumulate_depth_deltas([
            // d=0  (left shift undefined at depth 0)
            E::ZERO,
            // d=1
            left_shift_depth1,
            // d=2
            left_shift_depth2,
            // d=3
            left_shift_depth3,
            // –MOVDN3  — only shifts left at depths 1..3
            -op7(opcodes::MOVDN3),
            // +MLOADW  — pops address, loads 4 values; net -1 at depth 5
            // –MOVDN4  — only shifts left at depths 1..4
            op7(opcodes::MLOADW) - op7(opcodes::MOVDN4),
            // –MOVDN5  — only shifts left at depths 1..5
            -op7(opcodes::MOVDN5),
            // –MOVDN6  — only shifts left at depths 1..6
            -op7(opcodes::MOVDN6),
            // –MOVDN7  — only shifts left at depths 1..7
            -op7(opcodes::MOVDN7),
            // +CSWAPW  — pops condition, swaps words s1..s4 with s5..s8; net -1 from depth 9
            // –MOVDN8  — only shifts left at depths 1..8
            op7(opcodes::CSWAPW) - op7(opcodes::MOVDN8),
            // d=10 (unchanged)
            E::ZERO,
            // d=11 (unchanged)
            E::ZERO,
            // d=12 (unchanged)
            E::ZERO,
            // d=13 (unchanged)
            E::ZERO,
            // d=14 (unchanged)
            E::ZERO,
            // d=15 (unchanged)
            E::ZERO,
        ]);

        // ── Right-shift flags ───────────────────────────────────────
        // right_shift[d] = sum of op flags causing a right shift at depth d.
        // Built incrementally via accumulate_depth_deltas.

        let all_movup = all_mov_pairs * bits[0][0].clone();
        let right_shift_depth0
            // +deg7[48..64] — PAD, DUP0..DUP15, ADVPOP, SDEPTH, CLK: push one element
            = deg7[48..64].iter().cloned().sum::<E>()
            // +PUSH         — push immediate value
            + op5(opcodes::PUSH)
            // +MOVUP{2..8}  — move element from below to top, shifting s0..s{w-1} right
            + all_movup;

        let right_shift = accumulate_depth_deltas([
            // d=0
            right_shift_depth0,
            // +U32SPLIT — pops one u32, pushes high and low halves; net +1 from depth 1
            op6(opcodes::U32SPLIT),
            // –MOVUP2   — only shifts right at depths 0..1
            -op7(opcodes::MOVUP2),
            // –MOVUP3   — only shifts right at depths 0..2
            -op7(opcodes::MOVUP3),
            // –MOVUP4   — only shifts right at depths 0..3
            -op7(opcodes::MOVUP4),
            // –MOVUP5   — only shifts right at depths 0..4
            -op7(opcodes::MOVUP5),
            // –MOVUP6   — only shifts right at depths 0..5
            -op7(opcodes::MOVUP6),
            // –MOVUP7   — only shifts right at depths 0..6
            -op7(opcodes::MOVUP7),
            // –MOVUP8   — only shifts right at depths 0..7
            -op7(opcodes::MOVUP8),
            // d=9 (unchanged)
            E::ZERO,
            // d=10 (unchanged)
            E::ZERO,
            // d=11 (unchanged)
            E::ZERO,
            // d=12 (unchanged)
            E::ZERO,
            // d=13 (unchanged)
            E::ZERO,
            // d=14 (unchanged)
            E::ZERO,
            // d=15 (unchanged)
            E::ZERO,
        ]);

        // ── Scalar shift flags ──────────────────────────────────────
        // These are NOT the same expressions as right_shift[15] / left_shift[15].
        // They use low-degree bit prefixes that are algebraically equivalent on
        // valid traces (exactly one opcode active), but produce lower-degree
        // expressions for use in constraints that multiply these with other terms.

        // right_shift_scalar (degree 6):
        // Uses prefix_011 (degree 3) instead of summing all 16 push-like degree-7 flags.
        let prefix_011 = prefix_01.clone() * bits[4][1].clone();
        let right_shift_scalar
            // +prefix_011 — PAD, DUP0..DUP15, ADVPOP, SDEPTH, CLK (opcodes 48-63)
            = prefix_011
            // +PUSH       — push immediate value
            + op5(opcodes::PUSH)
            // +U32SPLIT   — pops one u32, pushes high and low halves
            + op6(opcodes::U32SPLIT);

        // left_shift_scalar (degree 5):
        // Uses prefix_010 (degree 3) instead of summing all left-shifting degree-7 flags.
        // DYNCALL is intentionally excluded — it left-shifts the stack but uses
        // decoder hasher state (h5) for overflow constraints, not the generic path.
        let prefix_010 = prefix_01 * bits[4][0].clone();
        let u32_add3_madd_group = prefix_100.clone() * bits[3][1].clone() * bits[2][1].clone();
        let left_shift_scalar = E::sum_array::<7>(&[
            // +prefix_010          — ASSERT, EQ, ADD, MUL, AND, OR, U32AND, U32XOR, DROP,
            //                        CSWAP, CSWAPW, MLOADW, MSTORE, MSTOREW, (op46), (op47)
            prefix_010,
            // +u32_add3_madd_group — U32ADD3, U32MADD: consume 3, produce 2
            u32_add3_madd_group,
            // +SPLIT               — control flow: pops condition
            op5(opcodes::SPLIT),
            // +LOOP                — control flow: pops condition
            op5(opcodes::LOOP),
            // +REPEAT              — control flow: pops condition for next iteration
            op4(opcodes::REPEAT),
            // +END*loop            — END when ending a loop: pops loop flag
            end_loop_flag,
            // +DYN                 — control flow: consumes target hash
            op5(opcodes::DYN),
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
        let control_flow = E::sum_array::<6>(&[
            // +SPAN, JOIN, SPLIT, LOOP    — block starters
            bits[3][0].clone() * bits[2][1].clone() * decoder.extra[0],
            // +END, REPEAT, RESPAN, HALT  — block transitions
            bits[4][1].clone() * decoder.extra[1],
            // +DYNCALL                    — dynamic execution
            op5(opcodes::DYNCALL),
            // +DYN                        — dynamic execution
            op5(opcodes::DYN),
            // +SYSCALL                    — procedure call
            op4(opcodes::SYSCALL),
            // +CALL                       — procedure call
            op4(opcodes::CALL),
        ]);

        // Flag if current operation is a degree-6 u32 operation
        let u32_rc_op = prefix_100;

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

    /// Returns the scalar flag when the stack operation shifts the stack to the right.
    ///
    /// This is NOT the same expression as `right_shift_at(15)`. It uses low-degree
    /// bit prefixes (degree 6) that are algebraically equivalent on valid traces,
    /// producing a lower-degree expression for use in constraints that multiply
    /// this flag with other terms.
    #[inline(always)]
    pub fn right_shift(&self) -> E {
        self.right_shift.clone()
    }

    /// Returns the scalar flag when the stack operation shifts the stack to the left.
    ///
    /// This is NOT the same expression as `left_shift_at(15)`. It uses low-degree
    /// bit prefixes (degree 5) that are algebraically equivalent on valid traces.
    ///
    /// Excludes `DYNCALL` — it left-shifts the stack but is handled via the
    /// per-position `left_shift_at` flags. The aggregate `left_shift` flag only
    /// gates generic helper/overflow constraints, which don't apply to `DYNCALL`
    /// because those helper columns are reused for the context switch and the
    /// overflow pointer is stored in decoder hasher state (h5).
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
        #[expect(dead_code)]
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
        #[expect(dead_code)]
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
        /// Operation Flag of FRIE2F4 operation.
        frie2f4 => opcodes::FRIE2F4,
        /// Operation Flag of DROP operation.
        #[expect(dead_code)]
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
        #[expect(dead_code)]
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

/// Prefix-sums an array of per-depth deltas in place.
///
/// `result[d] = deltas[0] + deltas[1] + ... + deltas[d]`
fn accumulate_depth_deltas<const N: usize, E: PrimeCharacteristicRing>(
    mut deltas: [E; N],
) -> [E; N] {
    for i in 1..N {
        deltas[i] = deltas[i - 1].clone() + deltas[i].clone();
    }
    deltas
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
pub fn generate_test_row(opcode: usize) -> crate::MainCols<miden_core::Felt> {
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
    unsafe { core::mem::transmute::<[Felt; TRACE_WIDTH], crate::MainCols<Felt>>(row) }
}

/// Returns a 7-bit array representation of an opcode.
#[cfg(test)]
pub fn get_op_bits(opcode: usize) -> [miden_core::Felt; NUM_OP_BITS] {
    use miden_core::{Felt, ZERO};

    let mut opcode_copy = opcode;
    let mut bit_array = [ZERO; NUM_OP_BITS];

    for bit in bit_array.iter_mut() {
        *bit = Felt::new_unchecked((opcode_copy & 1) as u64);
        opcode_copy >>= 1;
    }

    assert_eq!(opcode_copy, 0, "Opcode must be 7 bits");
    bit_array
}

#[cfg(test)]
mod tests;
