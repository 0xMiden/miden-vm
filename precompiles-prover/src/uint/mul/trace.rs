//! UintMul trace generation + aux builder.
//!
//! [`generate_trace`] lays each MAC op out as a [`PERIOD`]-row block per
//! the liquid layout (operand limb rows + the `q` / `Γ` witnesses placed
//! by [`GAMMA_SLOTS`]); the quotient comes from the exact division in
//! [`math`], the carries from the synthetic division here.
//! `build_aux` drives
//! the LogUp running sums and the two Schwartz–Zippel registers (`id`,
//! `S`), whose per-row accumulation mirrors [`super::UintMulAir`]'s
//! expressions exactly — both sides read the same placement table.

use alloc::{collections::BTreeMap, vec::Vec};
use core::array;

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
};

use super::{
    AUX_WIDTH, COL_A_PTR, COL_ACT, COL_B_PTR, COL_BORROW, COL_BOUND_PTR, COL_KAPPA_A, COL_R_PTR,
    GAMMA_OFFSET, GAMMA_SLOTS, NUM_CELLS, NUM_GAMMA, NUM_MAIN_COLS, NUM_Q_LIMBS, PERIOD, ROW_A_HI,
    ROW_A_LO, ROW_B_HI, ROW_B_LO, ROW_C, ROW_P_HI, ROW_P_LO, ROW_Q_HI, ROW_Q_LO, ROW_R, ROW_TERM,
    S_KEEP, TERM_CELL_C_PTR, TERM_CELL_IS_SUB, TERM_CELL_KAPPA_C, TERM_CELL_KAPPA_C_SIGNED,
    TERM_CELL_MULT, UintMulAir,
};
use crate::{
    logup::build_logup_aux_trace,
    math::{self, U256, to_limbs16, to_limbs32},
    primitives::byte_pair_lut::BytePairLutRequires,
    relations::ProvideMult,
    uint::trace::{UintPtr, UintStoreRequires},
};

/// One scaled MAC op `κₐ·a·b + κ_c·c ≡ r (mod p)`: the operand / result
/// handles + the shared modulus handle — pure ptr space; the values (and
/// the derived quotient + carries) are resolved from the store at
/// trace-gen. `r` is **caller-assigned** (a nondeterministic witness —
/// supporting `div` as `y·z + 0 = x`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct MulOp {
    pub kappa_a: u16,
    pub kappa_c: u16,
    pub a: UintPtr,
    pub b: UintPtr,
    pub c: UintPtr,
    pub r: UintPtr,
    pub bound: UintPtr,
    /// `false` for `κₐ·a·b + κ_c·c ≡ r`, `true` for the subtractive
    /// `κₐ·a·b − κ_c·c ≡ r` (the EC tail's fused `λ²−t` / `λe−y₁`).
    pub is_sub: bool,
}

/// An op's values resolved from the store, in field order
/// `(a, b, c, r, bound)`.
pub(crate) struct MulVals {
    pub a: U256,
    pub b: U256,
    pub c: U256,
    pub r: U256,
    pub bound: U256,
}

impl MulOp {
    /// Resolve the op's five values from the store; panics on a dangling
    /// ptr, debug-asserts the MAC identity itself.
    pub(crate) fn resolve(&self, store: &UintStoreRequires) -> MulVals {
        let value = |ptr: UintPtr| -> U256 { store.uint(ptr).value };
        let vals = MulVals {
            a: value(self.a),
            b: value(self.b),
            c: value(self.c),
            r: value(self.r),
            bound: value(self.bound),
        };
        let expected = if self.is_sub {
            math::mac_sub_reduce(self.kappa_a, vals.a, vals.b, self.kappa_c, vals.c, vals.bound)
        } else {
            math::mac_reduce(self.kappa_a, vals.a, vals.b, self.kappa_c, vals.c, vals.bound)
        };
        debug_assert_eq!(vals.r, expected, "r must equal (κₐ·a·b ± κ_c·c) mod p");
        vals
    }
}

/// The canonical 17-limb quotient `q_committed` of an op (`q < κₐ·p ≤
/// 2²⁷²`) plus the subtractive `borrow ∈ {0, 1, 2}` — the moduli the
/// canonical reduction adds back on underflow (`0` for additive ops).
/// The identity is `κₐ·a·b ± κ_c·c = r + (q_committed − borrow)·p`.
pub(crate) fn canonical_q(op: &MulOp, vals: &MulVals) -> ([u32; NUM_Q_LIMBS], u8) {
    let (q, rem, borrow) = if op.is_sub {
        math::mac_sub_div_rem(op.kappa_a, vals.a, vals.b, op.kappa_c, vals.c, vals.bound)
    } else {
        let (q, rem) =
            math::mac_div_rem(op.kappa_a, vals.a, vals.b, op.kappa_c, vals.c, vals.bound);
        (q, rem, 0u8)
    };
    debug_assert_eq!(rem, vals.r, "the op's r must be the canonical MAC remainder");
    debug_assert!(q >> 272 == math::U320::ZERO, "quotient exceeds 17 limbs (κₐ out of contract?)",);
    (
        array::from_fn(|i| ((q.as_limbs()[i / 4] >> (16 * (i % 4))) as u32) & 0xffff),
        borrow,
    )
}

/// The 31 carry coefficients of the SZ identity, committed sign-offset:
/// `γ'ₖ = γₖ + 2³¹` as `(lo, hi)` 16-bit halves, where `γ` is the exact
/// synthetic division of `E_pre` by `(X − t)`:
///
/// ```text
/// E_pre(X) = κₐ·a(X)b(X) ± κ_c·C(X²) − q(X)·(bound(X) + 1) − R(X²)
///                                     + borrow·(bound(X) + 1)
/// γₖ = (dₖ + γₖ₋₁) / t,    t = 2¹⁶
/// ```
///
/// The sign on `κ_c·C` is `−` for `is_sub`, and the subtractive `borrow`
/// adds one `(bound + 1)` back (`q` here is `q_committed`, so
/// `q_committed − borrow` is the true quotient). `q` / `borrow` are
/// parameters (not recomputed) so a forged limb *encoding* of the same
/// quotient value — the attack the `Range16` checks exist to stop — can be
/// witnessed in tests.
pub(crate) fn gamma_halves(
    op: &MulOp,
    vals: &MulVals,
    q: &[u32; NUM_Q_LIMBS],
    borrow: u8,
) -> [(u16, u16); NUM_GAMMA] {
    let (a, b, bound) = (to_limbs16(vals.a), to_limbs16(vals.b), to_limbs16(vals.bound));
    let c32 = to_limbs32(vals.c);
    let r32 = to_limbs32(vals.r);
    // 0 for additive ops, so the borrow term vanishes without gating; the
    // c term flips sign for the subtractive shape.
    let borrow = borrow as i128;
    let c_sign: i128 = if op.is_sub { -1 } else { 1 };
    let d = |k: usize| -> i128 {
        let ab: i128 = (k.saturating_sub(15)..=k.min(15))
            .map(|i| a[i] as i128 * b[k - i] as i128)
            .sum();
        let q_bound: i128 = (k.saturating_sub(15)..=k.min(16))
            .map(|i| q[i] as i128 * bound[k - i] as i128)
            .sum();
        let mut d = op.kappa_a as i128 * ab - q_bound;
        if k < NUM_Q_LIMBS {
            d -= q[k] as i128;
        }
        // +borrow·(bound + 1): the modulus added back on subtractive
        // underflow (borrow = 0 ⟹ no effect).
        if k < 16 {
            d += borrow * bound[k] as i128;
        }
        if k == 0 {
            d += borrow;
        }
        if k.is_multiple_of(2) && k / 2 < 8 {
            d += c_sign * op.kappa_c as i128 * c32[k / 2] as i128 - r32[k / 2] as i128;
        }
        d
    };

    let mut out = [(0u16, 0u16); NUM_GAMMA];
    let mut prev: i128 = 0;
    for (k, half) in out.iter_mut().enumerate() {
        let num = d(k) + prev;
        debug_assert_eq!(num % (1 << 16), 0, "synthetic division must be exact");
        let g = num / (1 << 16);
        debug_assert!(
            g.unsigned_abs() < GAMMA_OFFSET as u128,
            "carry γ_{k} outside its 2³¹ window",
        );
        let g_offset = (g + GAMMA_OFFSET as i128) as u64;
        *half = (g_offset as u16, (g_offset >> 16) as u16);
        prev = g;
    }
    debug_assert_eq!(d(NUM_GAMMA) + prev, 0, "E_pre must vanish at t (top coefficient)",);
    out
}

// REQUIRES + TRACE
// ================================================================================================

/// `*Requires` accumulator for the UintMul chiplet: the recorded MAC
/// ops (pure ptr space — trace-gen resolves the values and derives the
/// witnesses from the store) with their accumulated `UintMul` provide
/// multiplicities. Recording **interns by relation identity** — a
/// duplicate of an already-recorded arrangement collapses onto its
/// block, the mults adding (e.g. two points sharing a membership MAC).
/// Each block's store demand is routed by [`generate_trace`]'s laying
/// pass — once per block, since the operand lookups are
/// mult-independent.
#[derive(Debug, Default)]
pub struct UintMulRequires {
    /// `(op, provide mult)` in first-recorded order; mult 0 = dormant.
    pub(crate) ops: Vec<(MulOp, ProvideMult)>,
    /// Relation identity → index into `ops`.
    dedup: BTreeMap<MulOp, usize>,
}

impl UintMulRequires {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `κₐ·a·b + κ_c·c ≡ r (mod p)` over stored uints sharing the
    /// modulus at `bound`, providing the op's `UintMul` tuple at
    /// multiplicity `mult` (the consumer count; 0 = dormant). `r` is the
    /// caller-assigned result — debug-asserted (at trace-gen, against the
    /// stored values) to be the canonical remainder.
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &mut self,
        kappa_a: u16,
        a: UintPtr,
        b: UintPtr,
        kappa_c: u16,
        c: UintPtr,
        r: UintPtr,
        bound: UintPtr,
        mult: ProvideMult,
    ) {
        self.insert(kappa_a, a, b, kappa_c, c, r, bound, false, mult);
    }

    /// Record the subtractive `κₐ·a·b − κ_c·c ≡ r (mod p)` (the EC tail's
    /// fused `λ²−t` / `λe−y₁`). `r` is the caller-assigned canonical
    /// remainder; the underflow borrow is derived at trace-gen.
    #[allow(clippy::too_many_arguments)]
    pub fn record_sub(
        &mut self,
        kappa_a: u16,
        a: UintPtr,
        b: UintPtr,
        kappa_c: u16,
        c: UintPtr,
        r: UintPtr,
        bound: UintPtr,
        mult: ProvideMult,
    ) {
        self.insert(kappa_a, a, b, kappa_c, c, r, bound, true, mult);
    }

    #[allow(clippy::too_many_arguments)]
    fn insert(
        &mut self,
        kappa_a: u16,
        a: UintPtr,
        b: UintPtr,
        kappa_c: u16,
        c: UintPtr,
        r: UintPtr,
        bound: UintPtr,
        is_sub: bool,
        mult: ProvideMult,
    ) {
        let op = MulOp {
            kappa_a,
            kappa_c,
            a,
            b,
            c,
            r,
            bound,
            is_sub,
        };
        match self.dedup.get(&op) {
            Some(&i) => self.ops[i].1 += mult,
            None => {
                self.dedup.insert(op, self.ops.len());
                self.ops.push((op, mult));
            },
        }
    }
}

/// One op's [`PERIOD`]×[`NUM_MAIN_COLS`] block at provide multiplicity
/// `mult`, with the quotient limbs and γ halves supplied by the caller
/// ([`generate_trace`] passes the canonical encodings; tests may pass
/// forged ones).
pub(crate) fn op_block(
    op: &MulOp,
    v: &MulVals,
    q: &[u32; NUM_Q_LIMBS],
    borrow: u8,
    gammas: &[(u16, u16); NUM_GAMMA],
    mult: ProvideMult,
) -> Vec<Felt> {
    let mut block = [[Felt::ZERO; NUM_MAIN_COLS]; PERIOD];
    // κ_c_signed = κ_c · (1 − 2·is_sub) — the pinned witness
    // `TERM_CELL_KAPPA_C_SIGNED`'s eval constraint mirror; written directly
    // (ahead of `set`, which is u32-only and can't hold a field negation).
    block[ROW_TERM][TERM_CELL_KAPPA_C_SIGNED] = if op.is_sub {
        Felt::ZERO - Felt::from(op.kappa_c as u32)
    } else {
        Felt::from(op.kappa_c as u32)
    };
    let mut set = |row: usize, col: usize, v: u32| {
        block[row][col] = Felt::from(v);
    };

    let (a, b, bound) = (to_limbs16(v.a), to_limbs16(v.b), to_limbs16(v.bound));
    for i in 0..8 {
        set(ROW_A_LO, i, a[i] as u32);
        set(ROW_A_HI, i, a[8 + i] as u32);
        set(ROW_B_LO, i, b[i] as u32);
        set(ROW_B_HI, i, b[8 + i] as u32);
        set(ROW_P_LO, i, bound[i] as u32);
        set(ROW_P_HI, i, bound[8 + i] as u32);
    }
    for (i, &qi) in q.iter().enumerate() {
        if i < NUM_CELLS {
            set(ROW_Q_LO, i, qi);
        } else {
            set(ROW_Q_HI, i - NUM_CELLS, qi);
        }
    }
    for (s, &(row, cell)) in GAMMA_SLOTS.iter().enumerate() {
        let (lo, hi) = gammas[s / 2];
        set(row, cell, if s % 2 == 0 { lo } else { hi } as u32);
    }
    let r32 = to_limbs32(v.r);
    let c32 = to_limbs32(v.c);
    for (m, (&r, &c)) in r32.iter().zip(&c32).enumerate() {
        set(ROW_R, m, r);
        set(ROW_C, m, c);
    }
    // Term metadata (the provide mult = the op's consumer count) +
    // cycle-constant columns.
    set(ROW_TERM, TERM_CELL_MULT, mult);
    set(ROW_TERM, TERM_CELL_C_PTR, op.c.addr());
    set(ROW_TERM, TERM_CELL_KAPPA_C, op.kappa_c as u32);
    set(ROW_TERM, TERM_CELL_IS_SUB, op.is_sub as u32);
    for row in 0..PERIOD {
        set(row, COL_A_PTR, op.a.addr());
        set(row, COL_B_PTR, op.b.addr());
        set(row, COL_R_PTR, op.r.addr());
        set(row, COL_BOUND_PTR, op.bound.addr());
        set(row, COL_KAPPA_A, op.kappa_a as u32);
        set(row, COL_ACT, 1);
        set(row, COL_BORROW, borrow as u32);
    }
    block.into_iter().flatten().collect()
}

/// Build the UintMul main trace from the recorded ops — one op = one
/// [`PERIOD`]-row block, the values + witnesses resolved from the store —
/// padded to a power-of-two height with all-zero (`act = 0`) rows that
/// touch no bus.
///
/// The same pass routes each block's store demand (the convolution
/// operands `a` / `b` / modulus consume the raw `UintLimbs` view, the
/// linear `c` / `r` the 4×32 `UintVal` view — run it before the store's
/// own trace reads its ledger) and drives the `Range16` demand the
/// chiplet consumes into `bpl`: the 17 `q` limbs, the 62 γ halves and
/// the two κ cells per op. Padding blocks are act-gated and consume
/// nothing.
pub fn generate_trace(
    requires: UintMulRequires,
    store: &mut UintStoreRequires,
    bpl: &mut BytePairLutRequires,
) -> RowMajorMatrix<Felt> {
    let height = (requires.ops.len().max(1) * PERIOD).next_power_of_two();
    let mut vals = Vec::with_capacity(height * NUM_MAIN_COLS);
    for (op, mult) in &requires.ops {
        store.require_uintlimbs(op.a);
        store.require_uintlimbs(op.b);
        store.require_uintlimbs(op.bound);
        store.require_uintval(op.c);
        store.require_uintval(op.r);

        let v = op.resolve(store);
        let (q, borrow) = canonical_q(op, &v);
        let gammas = gamma_halves(op, &v, &q, borrow);
        for &qi in &q {
            bpl.require_range16(qi as u16);
        }
        for &(lo, hi) in &gammas {
            bpl.require_range16(lo);
            bpl.require_range16(hi);
        }
        bpl.require_range16(op.kappa_a);
        bpl.require_range16(op.kappa_c);

        vals.extend(op_block(op, &v, &q, borrow, &gammas, *mult));
    }
    // Padding blocks: all-zero (act = 0) rows that touch no bus.
    vals.resize(height * NUM_MAIN_COLS, Felt::ZERO);
    RowMajorMatrix::new(vals, NUM_MAIN_COLS)
}

// PROVER
// ================================================================================================

/// Witness-bearing companion to [`UintMulAir`].
pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    // Cols 0–2: LogUp running sum + the two fraction columns.
    let (logup, sigma) = build_logup_aux_trace(&UintMulAir, main, challenges);
    let logup_width = logup.width();
    let n = main.height();
    let beta = challenges[1];

    // β⁰..β³¹ + the γ slot weights (mirroring the AIR's).
    let mut bp = [QuadFelt::ZERO; 2 * PERIOD];
    bp[0] = QuadFelt::ONE;
    for i in 1..2 * PERIOD {
        bp[i] = bp[i - 1] * beta;
    }
    let t16 = QuadFelt::from(Felt::from(1u32 << 16));
    let x_minus_t = beta - t16;
    let offset = Felt::from(GAMMA_OFFSET);
    let slot_weight = |s: usize| -> QuadFelt {
        let w = x_minus_t * bp[s / 2];
        if s % 2 == 1 { w * t16 } else { w }
    };
    // Per row-role: the hosted γ slots (slot index, cell).
    let slots_by_row: [Vec<(usize, usize)>; PERIOD] = {
        let mut by_row: [Vec<(usize, usize)>; PERIOD] = array::from_fn(|_| Vec::new());
        for (s, &(row, cell)) in GAMMA_SLOTS.iter().enumerate() {
            by_row[row].push((s, cell));
        }
        by_row
    };

    // Cols 3–4: the `id` and `S` registers. Both start at 0; the
    // updates mirror UintMulAir's role-gated expressions exactly.
    let mut data = Vec::with_capacity(AUX_WIDTH * n);
    let mut id = QuadFelt::ZERO;
    let mut s_reg = QuadFelt::ZERO;
    for r in 0..n {
        data.extend((0..logup_width).map(|c| logup.values[r * logup_width + c]));
        data.push(id);
        data.push(s_reg);

        let cell = |c: usize| -> Felt { main.values[r * NUM_MAIN_COLS + c] };
        let row_kind = r % PERIOD;
        let kappa_a = QuadFelt::from(cell(COL_KAPPA_A));
        let act = cell(COL_ACT);

        let lo_sum = (0..8).fold(QuadFelt::ZERO, |acc, i| acc + bp[i] * QuadFelt::from(cell(i)));
        let hi_sum =
            (0..8).fold(QuadFelt::ZERO, |acc, i| acc + bp[8 + i] * QuadFelt::from(cell(i)));
        let val_sum =
            (0..8).fold(QuadFelt::ZERO, |acc, m| acc + bp[2 * m] * QuadFelt::from(cell(m)));

        let role_contrib: QuadFelt = match row_kind {
            _ if row_kind == ROW_B_LO => s_reg * lo_sum,
            _ if row_kind == ROW_B_HI => s_reg * hi_sum,
            // +borrow·(bound(β)+1), split across the p-rows where bound(β)
            // lives (the +1 of p = bound + 1 rides p_lo's β⁰).
            _ if row_kind == ROW_P_LO => {
                let borrow = main.values[r * NUM_MAIN_COLS + COL_BORROW];
                QuadFelt::from(borrow) * (lo_sum + QuadFelt::ONE)
            },
            _ if row_kind == ROW_P_HI => {
                let borrow = main.values[r * NUM_MAIN_COLS + COL_BORROW];
                QuadFelt::from(borrow) * hi_sum
            },
            _ if row_kind == ROW_Q_LO => {
                -((s_reg + QuadFelt::ONE)
                    * (0..NUM_CELLS)
                        .fold(QuadFelt::ZERO, |acc, i| acc + bp[i] * QuadFelt::from(cell(i))))
            },
            _ if row_kind == ROW_Q_HI => {
                -((s_reg + QuadFelt::ONE)
                    * (0..NUM_Q_LIMBS - NUM_CELLS).fold(QuadFelt::ZERO, |acc, i| {
                        acc + bp[NUM_CELLS + i] * QuadFelt::from(cell(i))
                    }))
            },
            _ if row_kind == ROW_R => -val_sum,
            _ if row_kind == ROW_C => {
                let kappa_c_signed =
                    main.values[(r + 1) * NUM_MAIN_COLS + TERM_CELL_KAPPA_C_SIGNED];
                QuadFelt::from(kappa_c_signed) * val_sum
            },
            _ => QuadFelt::ZERO,
        };
        let gamma_contrib: QuadFelt =
            slots_by_row[row_kind].iter().fold(QuadFelt::ZERO, |acc, &(s, c)| {
                let v = if s % 2 == 0 { cell(c) - act * offset } else { cell(c) };
                acc + slot_weight(s) * QuadFelt::from(v)
            });
        id += role_contrib + gamma_contrib;

        let build: QuadFelt = match row_kind {
            _ if row_kind == ROW_A_LO => kappa_a * lo_sum,
            _ if row_kind == ROW_A_HI => kappa_a * hi_sum,
            _ if row_kind == ROW_P_LO => lo_sum,
            _ if row_kind == ROW_P_HI => hi_sum,
            _ => QuadFelt::ZERO,
        };
        let keep = QuadFelt::from(Felt::from(S_KEEP[row_kind] as u32));
        s_reg = s_reg * keep + build;
    }

    (RowMajorMatrix::new(data, AUX_WIDTH), sigma)
}
