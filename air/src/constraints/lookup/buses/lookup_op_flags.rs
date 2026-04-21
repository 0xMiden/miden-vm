//! Bus-scoped operation flags for the LogUp lookup argument.
//!
//! [`LookupOpFlags`] is a narrower cousin of [`crate::constraints::op_flags::OpFlags`] that
//! carries only the ~32 flags the bus emitters in [`super`] actually read — enough to gate
//! every interaction without materialising the ~150-field surface `OpFlags` exposes to the
//! stack / decoder / chiplet constraint code.
//!
//! The two construction paths live side by side:
//!
//! - [`from_main_cols`](LookupOpFlags::from_main_cols) — polynomial, shared by the
//!   constraint-path adapter and the debug builders. Mirrors the relevant parts of
//!   [`OpFlags::new`](crate::constraints::op_flags::OpFlags::new) but skips every prefix
//!   product that would feed only unused flags.
//! - [`from_boolean_row`](LookupOpFlags::from_boolean_row) (added in a follow-up commit) —
//!   prover-path override that decodes the 7-bit opcode as a `u8` and flips exactly one
//!   flag per row. Saves a further factor by sidestepping Felt arithmetic altogether on
//!   the discrete flags.
//!
//! The method-accessor shape intentionally mirrors `OpFlags` so the bus emitters read
//! `op_flags.join()` / `op_flags.overflow()` etc. without caring which constructor ran.

use core::array;

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, PrimeField64},
    operations::opcodes,
};

use crate::constraints::{
    decoder::columns::DecoderCols,
    op_flags::get_op_index,
    stack::columns::StackCols,
};

// LOOKUP OP FLAGS
// ================================================================================================

/// Subset of [`OpFlags`](crate::constraints::op_flags::OpFlags) consumed by the LogUp bus
/// emitters.
///
/// Parameterised by the expression type `E` so the same struct serves the symbolic constraint
/// path and the concrete-row prover path. Only one flag is non-zero on any valid row, same as
/// `OpFlags`.
pub struct LookupOpFlags<E> {
    // -- Degree-4 individual ops (current row) --------------------------------------------------
    end: E,
    repeat: E,
    respan: E,
    call: E,
    syscall: E,
    mrupdate: E,

    // -- Degree-5 individual ops ----------------------------------------------------------------
    join: E,
    split: E,
    span: E,
    loop_op: E,
    dyn_op: E,
    dyncall: E,
    push: E,
    hperm: E,
    mpverify: E,
    mstream: E,
    pipe: E,
    evalcircuit: E,
    log_precompile: E,

    // -- Degree-7 individual ops ----------------------------------------------------------------
    mload: E,
    mstore: E,
    mloadw: E,
    mstorew: E,
    u32and: E,
    u32xor: E,

    // -- Next-row control flow (degree 4) -------------------------------------------------------
    end_next: E,
    repeat_next: E,
    halt_next: E,

    // -- Composite flags ------------------------------------------------------------------------
    left_shift: E,
    right_shift: E,
    overflow: E,
    u32_rc_op: E,
}

// CONSTRUCTORS
// ================================================================================================

impl<E> LookupOpFlags<E>
where
    E: PrimeCharacteristicRing + Clone,
{
    /// Polynomial constructor used by the constraint-path adapter and the debug builders.
    ///
    /// Mirrors the structure of [`OpFlags::new`](crate::constraints::op_flags::OpFlags::new)
    /// but computes only the prefix products needed for the ~32 bus-consumed flags. The
    /// shared `b32 / b321 / b3210 / b432` prefix tables are still built once up-front so
    /// the per-flag cost is a single multiplication each.
    pub fn from_main_cols<V>(
        decoder: &DecoderCols<V>,
        stack: &StackCols<V>,
        decoder_next: &DecoderCols<V>,
    ) -> Self
    where
        V: Copy,
        E: Algebra<V>,
    {
        // -- Bit selectors: bits[k][0] = 1 - b_k, bits[k][1] = b_k --------------------------
        let bits: [[E; 2]; 7] = array::from_fn(|k| {
            let val = decoder.op_bits[k];
            [E::ONE - val, val.into()]
        });

        // -- Shared prefix product tables (same shape as OpFlags::new) ----------------------
        let b32: [E; 4] =
            array::from_fn(|i| bits[3][i >> 1].clone() * bits[2][i & 1].clone());
        let b321: [E; 8] =
            array::from_fn(|i| b32[i >> 1].clone() * bits[1][i & 1].clone());
        let b3210: [E; 16] =
            array::from_fn(|i| b321[i >> 1].clone() * bits[0][i & 1].clone());
        let b432: [E; 8] =
            array::from_fn(|i| bits[4][i >> 2].clone() * b32[i & 3].clone());

        // -- Degree-7 subset --------------------------------------------------------------
        // deg-7 flag(op) = b654[op >> 4] * b321[(op >> 1) & 7] * bits[0][op & 1].
        // All six bus-consumed deg-7 opcodes have b6=0, so we only need b654[0] (b5=0,b4=0)
        // for MLOAD and b654[2] (b5=1,b4=0) for the rest.
        let b654_0 = bits[6][0].clone() * bits[5][0].clone() * bits[4][0].clone();
        let b654_2 = bits[6][0].clone() * bits[5][1].clone() * bits[4][0].clone();
        let deg7 = |b654: &E, op: u8| -> E {
            let op = op as usize;
            b654.clone() * b321[(op >> 1) & 7].clone() * bits[0][op & 1].clone()
        };
        let mload = deg7(&b654_0, opcodes::MLOAD);
        let u32and = deg7(&b654_2, opcodes::U32AND);
        let u32xor = deg7(&b654_2, opcodes::U32XOR);
        let mloadw = deg7(&b654_2, opcodes::MLOADW);
        let mstore = deg7(&b654_2, opcodes::MSTORE);
        let mstorew = deg7(&b654_2, opcodes::MSTOREW);

        // -- Degree-5 subset --------------------------------------------------------------
        let deg5_extra: E = decoder.extra[0].into();
        let deg5 = |op: u8| -> E {
            deg5_extra.clone() * b3210[get_op_index(op)].clone()
        };
        let hperm = deg5(opcodes::HPERM);
        let mpverify = deg5(opcodes::MPVERIFY);
        let pipe = deg5(opcodes::PIPE);
        let mstream = deg5(opcodes::MSTREAM);
        let split = deg5(opcodes::SPLIT);
        let loop_op = deg5(opcodes::LOOP);
        let span = deg5(opcodes::SPAN);
        let join = deg5(opcodes::JOIN);
        let dyn_op = deg5(opcodes::DYN);
        let push = deg5(opcodes::PUSH);
        let dyncall = deg5(opcodes::DYNCALL);
        let evalcircuit = deg5(opcodes::EVALCIRCUIT);
        let log_precompile = deg5(opcodes::LOGPRECOMPILE);

        // -- Degree-4 subset --------------------------------------------------------------
        let deg4_extra: E = decoder.extra[1].into();
        let deg4 = |op: u8| -> E {
            b432[get_op_index(op)].clone() * deg4_extra.clone()
        };
        let end = deg4(opcodes::END);
        let repeat = deg4(opcodes::REPEAT);
        let respan = deg4(opcodes::RESPAN);
        let call = deg4(opcodes::CALL);
        let syscall = deg4(opcodes::SYSCALL);
        let mrupdate = deg4(opcodes::MRUPDATE);

        // -- Next-row control flow (END / REPEAT / HALT only) ------------------------------
        // prefix = extra[1]' * b4' = b6'*b5'*b4'. Distinguishes among the four deg-4 ops
        // under the `0b0111_xxxx` family via (b3', b2').
        let (end_next, repeat_next, halt_next) = {
            let prefix: E = decoder_next.extra[1].into();
            let prefix = prefix * decoder_next.op_bits[4];
            let b3n: E = decoder_next.op_bits[3].into();
            let b2n: E = decoder_next.op_bits[2].into();
            let nb3n = E::ONE - b3n.clone();
            let nb2n = E::ONE - b2n.clone();
            (
                prefix.clone() * nb3n.clone() * nb2n,   // END:    nb3' * nb2'
                prefix.clone() * nb3n * b2n.clone(),    // REPEAT: nb3' * b2'
                prefix * b3n * b2n,                     // HALT:   b3'  * b2'
            )
        };

        // -- Composite flags --------------------------------------------------------------
        // u32_rc_op = prefix_100 = b6*(1-b5)*(1-b4), degree 3.
        let u32_rc_op = bits[6][1].clone() * bits[5][0].clone() * bits[4][0].clone();

        // right_shift_scalar (degree 6): prefix_011 + PUSH + U32SPLIT.
        // U32SPLIT is a degree-6 op: u32_rc_op * b321[get_op_index(U32SPLIT)].
        let u32split = u32_rc_op.clone() * b321[get_op_index(opcodes::U32SPLIT)].clone();
        let prefix_01 = bits[6][0].clone() * bits[5][1].clone();
        let prefix_011 = prefix_01.clone() * bits[4][1].clone();
        let right_shift = prefix_011 + push.clone() + u32split;

        // left_shift_scalar (degree 5):
        //   prefix_010 + u32_add3_madd_group + SPLIT + LOOP + REPEAT + END*is_loop + DYN.
        // DYNCALL intentionally excluded (see OpFlags::left_shift doc).
        let prefix_010 = prefix_01 * bits[4][0].clone();
        let u32_add3_madd_group = u32_rc_op.clone() * bits[3][1].clone() * bits[2][1].clone();
        let is_loop = decoder.end_block_flags().is_loop;
        let end_loop = end.clone() * is_loop;
        let left_shift = prefix_010
            + u32_add3_madd_group
            + split.clone()
            + loop_op.clone()
            + repeat.clone()
            + end_loop
            + dyn_op.clone();

        // overflow = (b0 - 16) * h0, degree 2 (uses stack columns, not decoder).
        let b0: E = stack.b0.into();
        let overflow = (b0 - E::from_u64(16)) * stack.h0;

        Self {
            end,
            repeat,
            respan,
            call,
            syscall,
            mrupdate,
            join,
            split,
            span,
            loop_op,
            dyn_op,
            dyncall,
            push,
            hperm,
            mpverify,
            mstream,
            pipe,
            evalcircuit,
            log_precompile,
            mload,
            mstore,
            mloadw,
            mstorew,
            u32and,
            u32xor,
            end_next,
            repeat_next,
            halt_next,
            left_shift,
            right_shift,
            overflow,
            u32_rc_op,
        }
    }
}

// BOOLEAN FAST PATH (PROVER)
// ================================================================================================

impl LookupOpFlags<Felt> {
    /// Concrete-row constructor used by the prover-path adapter.
    ///
    /// Decodes the 7-bit opcode from `decoder.op_bits` as a `u8` and flips exactly one
    /// (or no) flag instead of materialising the polynomial products that
    /// [`from_main_cols`](LookupOpFlags::from_main_cols) builds. Semantics match
    /// `from_main_cols` on any valid trace — op_bits are 0/1 by the decoder's boolean
    /// constraint, and the `is_loop` hasher slot that gates `left_shift`'s `end` term is
    /// also 0/1 on valid traces.
    ///
    /// When `debug_assertions` is on, the output is cross-checked field-by-field against
    /// `from_main_cols` so divergences surface immediately in tests.
    pub fn from_boolean_row(
        decoder: &DecoderCols<Felt>,
        stack: &StackCols<Felt>,
        decoder_next: &DecoderCols<Felt>,
    ) -> Self {
        let opcode = decode_opcode_u8(&decoder.op_bits);
        let opcode_next = decode_opcode_u8(&decoder_next.op_bits);

        let mut f = Self::all_zero();

        // One match statement per row — branch-free in the hot case (inactive deg-7 rows
        // fall through the default arm).
        match opcode {
            opcodes::JOIN => f.join = Felt::ONE,
            opcodes::SPLIT => f.split = Felt::ONE,
            opcodes::SPAN => f.span = Felt::ONE,
            opcodes::LOOP => f.loop_op = Felt::ONE,
            opcodes::DYN => f.dyn_op = Felt::ONE,
            opcodes::DYNCALL => f.dyncall = Felt::ONE,
            opcodes::PUSH => f.push = Felt::ONE,
            opcodes::HPERM => f.hperm = Felt::ONE,
            opcodes::MPVERIFY => f.mpverify = Felt::ONE,
            opcodes::MSTREAM => f.mstream = Felt::ONE,
            opcodes::PIPE => f.pipe = Felt::ONE,
            opcodes::EVALCIRCUIT => f.evalcircuit = Felt::ONE,
            opcodes::LOGPRECOMPILE => f.log_precompile = Felt::ONE,
            opcodes::END => f.end = Felt::ONE,
            opcodes::REPEAT => f.repeat = Felt::ONE,
            opcodes::RESPAN => f.respan = Felt::ONE,
            opcodes::CALL => f.call = Felt::ONE,
            opcodes::SYSCALL => f.syscall = Felt::ONE,
            opcodes::MRUPDATE => f.mrupdate = Felt::ONE,
            opcodes::MLOAD => f.mload = Felt::ONE,
            opcodes::MSTORE => f.mstore = Felt::ONE,
            opcodes::MLOADW => f.mloadw = Felt::ONE,
            opcodes::MSTOREW => f.mstorew = Felt::ONE,
            opcodes::U32AND => f.u32and = Felt::ONE,
            opcodes::U32XOR => f.u32xor = Felt::ONE,
            _ => {},
        }
        match opcode_next {
            opcodes::END => f.end_next = Felt::ONE,
            opcodes::REPEAT => f.repeat_next = Felt::ONE,
            opcodes::HALT => f.halt_next = Felt::ONE,
            _ => {},
        }

        // -- Composite flags via integer range tests ------------------------------------
        // u32_rc_op: 1 iff opcode is a degree-6 u32 op (opcodes 64..80).
        f.u32_rc_op = bool_to_felt((64..80).contains(&opcode));
        // right_shift_scalar: prefix_011 (opcodes 48..64) + PUSH + U32SPLIT.
        f.right_shift = bool_to_felt(
            (48..64).contains(&opcode)
                || opcode == opcodes::PUSH
                || opcode == opcodes::U32SPLIT,
        );
        // left_shift_scalar: prefix_010 (opcodes 32..48) + U32ADD3/U32MADD + SPLIT/LOOP/
        // REPEAT/DYN + END*is_loop. DYNCALL intentionally excluded — see OpFlags::left_shift.
        let is_end_loop =
            opcode == opcodes::END && decoder.end_block_flags().is_loop == Felt::ONE;
        f.left_shift = bool_to_felt(
            (32..48).contains(&opcode)
                || matches!(
                    opcode,
                    opcodes::U32ADD3
                        | opcodes::U32MADD
                        | opcodes::SPLIT
                        | opcodes::LOOP
                        | opcodes::REPEAT
                        | opcodes::DYN
                )
                || is_end_loop,
        );

        // overflow uses non-boolean stack columns, so keep the Felt expression.
        f.overflow = (stack.b0 - Felt::from_u64(16)) * stack.h0;

        // -- Debug parity check -----------------------------------------------------------
        // Cross-check against the polynomial path. `from_main_cols` always produces
        // identical output on valid traces — mismatches here indicate either (a) a bug in
        // this fast path or (b) a non-boolean op_bits row, which the decoder constraint
        // would also reject.
        #[cfg(debug_assertions)]
        f.assert_matches_polynomial(decoder, stack, decoder_next);

        f
    }

    fn all_zero() -> Self {
        Self {
            end: Felt::ZERO,
            repeat: Felt::ZERO,
            respan: Felt::ZERO,
            call: Felt::ZERO,
            syscall: Felt::ZERO,
            mrupdate: Felt::ZERO,
            join: Felt::ZERO,
            split: Felt::ZERO,
            span: Felt::ZERO,
            loop_op: Felt::ZERO,
            dyn_op: Felt::ZERO,
            dyncall: Felt::ZERO,
            push: Felt::ZERO,
            hperm: Felt::ZERO,
            mpverify: Felt::ZERO,
            mstream: Felt::ZERO,
            pipe: Felt::ZERO,
            evalcircuit: Felt::ZERO,
            log_precompile: Felt::ZERO,
            mload: Felt::ZERO,
            mstore: Felt::ZERO,
            mloadw: Felt::ZERO,
            mstorew: Felt::ZERO,
            u32and: Felt::ZERO,
            u32xor: Felt::ZERO,
            end_next: Felt::ZERO,
            repeat_next: Felt::ZERO,
            halt_next: Felt::ZERO,
            left_shift: Felt::ZERO,
            right_shift: Felt::ZERO,
            overflow: Felt::ZERO,
            u32_rc_op: Felt::ZERO,
        }
    }

    #[cfg(debug_assertions)]
    fn assert_matches_polynomial(
        &self,
        decoder: &DecoderCols<Felt>,
        stack: &StackCols<Felt>,
        decoder_next: &DecoderCols<Felt>,
    ) {
        let p = Self::from_main_cols::<Felt>(decoder, stack, decoder_next);
        // The deg-5/7 row flags can appear in out-of-range rows where op_bits aren't
        // strictly boolean (e.g. the padded tail of a trace); only cross-check on
        // genuinely boolean rows so this doesn't fire on harmless padding.
        if !decoder.op_bits.iter().all(|b| *b == Felt::ZERO || *b == Felt::ONE) {
            return;
        }
        macro_rules! check {
            ($($name:ident),* $(,)?) => {
                $(
                    debug_assert_eq!(
                        self.$name, p.$name,
                        concat!("LookupOpFlags parity: ", stringify!($name)),
                    );
                )*
            };
        }
        check!(
            end, repeat, respan, call, syscall, mrupdate,
            join, split, span, loop_op, dyn_op, dyncall, push,
            hperm, mpverify, mstream, pipe, evalcircuit, log_precompile,
            mload, mstore, mloadw, mstorew, u32and, u32xor,
            end_next, repeat_next, halt_next,
            left_shift, right_shift, overflow, u32_rc_op,
        );
    }
}

/// Decodes a 7-bit opcode out of boolean op-bit columns. On a valid trace every `op_bits[k]`
/// is in `{0, 1}`; anything else is undefined but also rejected by the decoder's boolean
/// constraints, so this isn't a safety-critical conversion.
#[inline]
fn decode_opcode_u8(op_bits: &[Felt; 7]) -> u8 {
    let mut out = 0u8;
    for k in 0..7 {
        out |= ((op_bits[k].as_canonical_u64() & 1) as u8) << k;
    }
    out
}

#[inline]
fn bool_to_felt(b: bool) -> Felt {
    if b { Felt::ONE } else { Felt::ZERO }
}

// STATE ACCESSORS
// ================================================================================================

macro_rules! accessors {
    ($( $(#[$meta:meta])* $name:ident ),* $(,)?) => {
        impl<E: Clone> LookupOpFlags<E> {
            $(
                $(#[$meta])*
                #[inline(always)]
                pub fn $name(&self) -> E {
                    self.$name.clone()
                }
            )*
        }
    };
}

accessors!(
    // Degree-4 individual ops
    end, repeat, respan, call, syscall, mrupdate,
    // Degree-5 individual ops
    join, split, span, loop_op, dyn_op, dyncall, push,
    hperm, mpverify, mstream, pipe, evalcircuit, log_precompile,
    // Degree-7 individual ops
    mload, mstore, mloadw, mstorew, u32and, u32xor,
    // Next-row control flow
    end_next, repeat_next, halt_next,
    // Composite flags
    left_shift, right_shift, overflow, u32_rc_op,
);
