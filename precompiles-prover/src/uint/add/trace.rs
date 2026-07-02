//! UintAdd trace generation + aux builder.
//!
//! [`generate_trace`] lays each add op out as a [`PERIOD`]-row block: the
//! full 8×32 operand rows (pulled from the store over `UintVal`, one value
//! per row) with the binary carry chains γ⁺ (of `a+b`) and γ⁻ (of `c+k·p`)
//! spread across their spare cells per [`GAMMA_POS_SLOTS`] /
//! [`GAMMA_NEG_SLOTS`]. `build_aux` drives the LogUp running sum and the
//! Schwartz–Zippel `id` register, whose per-row accumulation mirrors
//! [`super::UintAddAir`]'s `contrib` exactly.

use alloc::{collections::BTreeMap, vec::Vec};

use miden_core::{
    Felt,
    field::{Field, PrimeCharacteristicRing, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
};

use super::{
    AUX_WIDTH, CELL_D_W, CELL_D_WS, CELL_IS_B_ZERO, CELL_IS_C_ZERO, CELL_K, COL_A_PTR, COL_NZ,
    GAMMA_NEG_SLOTS, GAMMA_POS_SLOTS, NUM_MAIN_COLS, PERIOD, ROW_A, ROW_B, ROW_C, ROW_P,
    TERM_CELL_MULT, UintAddAir,
};
use crate::{
    logup::build_logup_aux_trace,
    math::{U256, add_reduce, from_limbs32, to_limbs32},
    relations::ProvideMult,
    uint::trace::{UintPtr, UintStoreRequires},
};

/// One modular-addition op `a + b ≡ c (mod p)`: the three operand
/// handles + the shared modulus handle — pure ptr space; the values
/// (and the derived `k` / carry witnesses) are resolved from the store
/// at trace-gen. `c` is **caller-assigned** (a nondeterministic witness
/// — supporting `sub` as `y + z = x`); `None` marks the `is_c_zero`
/// mode: `c` is the (unstored) zero, neither looked up nor subtracted
/// (the `a + b ≡ 0` negation primitive, laid as the `c_ptr = 0`
/// sentinel). `b = None` is the mirror `is_b_zero` mode: `a + 0 ≡ c`,
/// the stored-value **equality certificate** `a = c`. `nz` additionally
/// certifies `b ≠ 0` (see [`super::UintAddAir`]'s "Nonzero certificate")
/// — part of the relation identity, like `is_sub` on `UintMul`: a plain
/// provide can never satisfy an `nz = 1` consume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct AddOp {
    a: UintPtr,
    b: Option<UintPtr>,
    c: Option<UintPtr>,
    bound: UintPtr,
    nz: bool,
}

/// Carries of an 8×32-bit addition `Σ (x + y)`: `out[j]` = carry **out of**
/// limb `j` (`j = 0..6`); the final carry out of limb 7 is returned
/// separately (the top bit, which has no trace slot).
fn add_carries(limbs: impl Fn(usize) -> u64) -> ([u16; 7], u16) {
    let mut out = [0u16; 7];
    let mut carry: u64 = 0;
    for (j, out_j) in out.iter_mut().enumerate() {
        let s = limbs(j) + carry;
        carry = s >> 32;
        *out_j = carry as u16;
    }
    let top = ((limbs(7) + carry) >> 32) as u16;
    (out, top)
}

/// `*Requires` accumulator for the UintAdd chiplet: the recorded add
/// ops with their accumulated `UintAdd` provide multiplicities.
/// Recording **interns by relation identity** — a duplicate of an
/// already-recorded arrangement collapses onto its block, the mults
/// adding — so identical relations demanded by different consumers
/// (e.g. an eval op node and an EC certificate, or two group ops over
/// shared points) cost one block. Each block's `UintVal` demand is
/// routed into the store by [`generate_trace`]'s laying pass — once per
/// block, since the operand lookups are mult-independent.
#[derive(Debug, Default)]
pub struct UintAddRequires {
    /// `(op, provide mult)` in first-recorded order; mult 0 = dormant.
    ops: Vec<(AddOp, ProvideMult)>,
    /// Relation identity → index into `ops`.
    dedup: BTreeMap<AddOp, usize>,
}

impl UintAddRequires {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `a + b ≡ c (mod p)` over stored uints sharing the modulus
    /// at `bound`, providing the op's `UintAdd` tuple at multiplicity
    /// `mult` (the consumer count; 0 = dormant). The identity itself is
    /// derived — and debug-asserted — from the stored values at
    /// trace-gen.
    pub fn record(
        &mut self,
        a: UintPtr,
        b: UintPtr,
        c: UintPtr,
        bound: UintPtr,
        mult: ProvideMult,
    ) {
        self.push(
            AddOp {
                a,
                b: Some(b),
                c: Some(c),
                bound,
                nz: false,
            },
            mult,
        );
    }

    /// Record `a + b ≡ c (mod p)` **and** certify `b ≠ 0` — the disequality
    /// cert the EC group law's generic-add case consumes on its
    /// `d = x₂ − x₁` subtraction (`(a, b, c) = (x₁, d, x₂)`) in place of a
    /// full inverse modmul. See [`super::UintAddAir`]'s "Nonzero
    /// certificate".
    pub fn record_nz(
        &mut self,
        a: UintPtr,
        b: UintPtr,
        c: UintPtr,
        bound: UintPtr,
        mult: ProvideMult,
    ) {
        self.push(
            AddOp {
                a,
                b: Some(b),
                c: Some(c),
                bound,
                nz: true,
            },
            mult,
        );
    }

    /// Record `a + b ≡ 0 (mod p)` — the **negation** primitive (`b = −a`).
    /// `c` is the unstored zero (no result ptr, no `c` lookup), so this
    /// needs no reference to a stored zero (which can't be pinned untyped
    /// for an arbitrary modulus).
    pub fn record_to_zero(&mut self, a: UintPtr, b: UintPtr, bound: UintPtr, mult: ProvideMult) {
        self.push(AddOp { a, b: Some(b), c: None, bound, nz: false }, mult);
    }

    /// Record `a + 0 ≡ c (mod p)` — the **equality certificate** `a = c`
    /// over two stored uints (`is_b_zero`: `b` is the unstored zero, no
    /// `b` lookup, no zero pin). With both values canonical under the
    /// shared modulus the identity is exactly value equality — the EC
    /// group law's `x₁ = x₂` / `y₁ = y₂` case ties.
    pub fn record_eq(&mut self, a: UintPtr, c: UintPtr, bound: UintPtr, mult: ProvideMult) {
        self.push(AddOp { a, b: None, c: Some(c), bound, nz: false }, mult);
    }

    fn push(&mut self, op: AddOp, mult: ProvideMult) {
        match self.dedup.get(&op) {
            Some(&i) => self.ops[i].1 += mult,
            None => {
                self.dedup.insert(op, self.ops.len());
                self.ops.push((op, mult));
            },
        }
    }
}

/// Per-op values resolved from the store (as the full 8×32 views trace-gen
/// lays out) plus the derived witness: the reduction bit `k` and the two
/// binary carry chains γ⁺ (of `a+b`) and γ⁻ (of `c+k·p`, with
/// `p = bound + 1`).
struct Witness {
    a: [u32; 8],
    b: [u32; 8],
    c: [u32; 8],
    bound: [u32; 8],
    k: u32,
    gamma_pos: [u16; 7],
    gamma_neg: [u16; 7],
    /// The nonzero certificate's witness: `S⁻¹` (native Goldilocks
    /// inverse of `b`'s raw limb sum), only meaningful when `op.nz`.
    d_w: Felt,
}

fn witness(op: &AddOp, store: &UintStoreRequires) -> Witness {
    let value = |ptr: UintPtr| -> U256 { store.uint(ptr).value };
    let bound_v = value(op.bound);
    let b_v = op.b.map_or(U256::ZERO, value);
    let c_v = op.c.map_or(U256::ZERO, value);
    debug_assert_eq!(add_reduce(value(op.a), b_v, bound_v), c_v, "a + b must reduce to c",);
    let (a, b, c, bound) =
        (to_limbs32(value(op.a)), to_limbs32(b_v), to_limbs32(c_v), to_limbs32(bound_v));

    // k = (a + b ≥ p) = (a + b > bound), and γ⁺ = the carries of a + b.
    let (gamma_pos, top) = add_carries(|j| a[j] as u64 + b[j] as u64);
    // bit-256 set ⇒ a + b ≥ 2²⁵⁶ > bound; otherwise the wrapping sum is
    // exact and compares directly.
    let k = u32::from(top != 0 || from_limbs32(&a) + from_limbs32(&b) > from_limbs32(&bound));

    // γ⁻ = carries of c + k·bound + k (the +k applies the p = bound+1
    // correction at limb 0). Binary: each ≤ (2³²−1)+(2³²−1)+1+carry < 2³³.
    let (gamma_neg, top_neg) = add_carries(|j| {
        let kb = (k as u64) * (bound[j] as u64);
        let ku = if j == 0 { k as u64 } else { 0 };
        c[j] as u64 + kb + ku
    });

    debug_assert_eq!(
        top, top_neg,
        "a + b and c + k·p must share the bit-256 carry (a + b = c + k·p)",
    );

    // The nonzero certificate: S = Σⱼ bⱼ (native sum, no wrap — 8 limbs
    // each < 2³² sum to < 2³⁵ ≪ p_Goldilocks), w = S⁻¹.
    let d_w = if op.nz {
        let s: u64 = b.iter().map(|&limb| u64::from(limb)).sum();
        debug_assert_ne!(s, 0, "nz certifies b ≠ 0, but b's limbs sum to 0");
        Felt::new(s).expect("S < 2^35 < Goldilocks p").inverse()
    } else {
        Felt::ZERO
    };

    Witness {
        a,
        b,
        c,
        bound,
        k,
        gamma_pos,
        gamma_neg,
        d_w,
    }
}

/// Build the UintAdd main trace from the recorded ops — one op = one
/// [`PERIOD`]-row block, the values + witnesses resolved from the store.
/// The four ptrs + `act` repeat on every row (cycle-constant); each
/// operand row hosts its own block scalar — `is_b_zero` on the `b` row,
/// `is_c_zero` on the `c` row, `k` on the `p` row, the provide multiplicity
/// on the `p` row's closing cell — plus its share of the γ⁺ / γ⁻ carries
/// per [`GAMMA_POS_SLOTS`] / [`GAMMA_NEG_SLOTS`]. Padded to a power-of-two
/// height.
///
/// The same pass routes each block's `UintVal` demand into the store
/// (the `a` operand + the shared modulus, plus `b` / `c` unless they are
/// the unstored zero), so the store's provide multiplicities cover the
/// adds — run it before the store's own trace reads its ledger.
pub fn generate_trace(
    requires: UintAddRequires,
    store: &mut UintStoreRequires,
) -> RowMajorMatrix<Felt> {
    let n_ops = requires.ops.len().max(1);
    let height = (n_ops * PERIOD).next_power_of_two();
    let mut vals = Vec::with_capacity(height * NUM_MAIN_COLS);

    for (op, mult) in &requires.ops {
        store.require_uintval(op.a);
        if let Some(b) = op.b {
            store.require_uintval(b);
        }
        if let Some(c) = op.c {
            store.require_uintval(c);
        }
        store.require_uintval(op.bound);
        let w = witness(op, store);

        // Rows 0–3: a / b / c / p, each a full 8×32 value on cells 0–7; the
        // γ⁺ / γ⁻ carries and the closing-row provide mult ride the spare
        // cells 8–12 per the placement tables.
        let mut block = [[Felt::ZERO; NUM_MAIN_COLS]; PERIOD];
        let put = |row: &mut [Felt; NUM_MAIN_COLS], v: &[u32; 8]| {
            for j in 0..8 {
                row[j] = Felt::from(v[j]);
            }
        };
        put(&mut block[ROW_A], &w.a);
        put(&mut block[ROW_B], &w.b);
        put(&mut block[ROW_C], &w.c);
        put(&mut block[ROW_P], &w.bound);
        block[ROW_B][CELL_IS_B_ZERO] = Felt::from(op.b.is_none() as u32);
        block[ROW_C][CELL_IS_C_ZERO] = Felt::from(op.c.is_none() as u32);
        block[ROW_P][CELL_K] = Felt::from(w.k);
        for (j, &(row, cell)) in GAMMA_POS_SLOTS.iter().enumerate() {
            block[row][cell] = Felt::from(w.gamma_pos[j]);
        }
        for (j, &(row, cell)) in GAMMA_NEG_SLOTS.iter().enumerate() {
            block[row][cell] = Felt::from(w.gamma_neg[j]);
        }
        block[ROW_P][TERM_CELL_MULT] = Felt::from(*mult);
        if op.nz {
            let s_sum: Felt = block[ROW_B][0..8].iter().copied().sum();
            block[ROW_B][CELL_D_W] = w.d_w;
            block[ROW_B][CELL_D_WS] = w.d_w * s_sum;
        }

        // Cycle-constant metadata (cols COL_A_PTR..=COL_NZ), identical on
        // every row of the block.
        let meta: [Felt; 6] = [
            Felt::from(op.a.addr()),
            Felt::from(op.b.map_or(0, UintPtr::addr)),
            Felt::from(op.c.map_or(0, UintPtr::addr)),
            Felt::from(op.bound.addr()),
            Felt::ONE, // act: a real op block
            Felt::from(op.nz as u32),
        ];
        for row in block.iter_mut() {
            row[COL_A_PTR..=COL_NZ].copy_from_slice(&meta);
            vals.extend_from_slice(row);
        }
    }
    // Padding blocks keep the zero fill — in particular act = 0, taking
    // their consumes off the bus.
    vals.resize(height * NUM_MAIN_COLS, Felt::ZERO);

    RowMajorMatrix::new(vals, NUM_MAIN_COLS)
}

/// Witness-bearing companion to [`UintAddAir`].
pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    // Col 0: LogUp running sum over the UintVal consumes + UintAdd provide.
    let (logup, sigma) = build_logup_aux_trace(&UintAddAir, main, challenges);
    let n = main.height();
    let beta = challenges[1];

    // β^0..β^7.
    let mut bp = [QuadFelt::ZERO; 8];
    bp[0] = QuadFelt::ONE;
    for i in 1..8 {
        bp[i] = bp[i - 1] * beta;
    }
    let t32 = QuadFelt::from(Felt::new(1u64 << 32).expect("2^32 < Goldilocks p"));

    // The SZ register. id[0] = 0; id[r+1] = id[r] + contrib(row r), contrib
    // matching UintAddAir's role-gated expression exactly (all local now).
    let logup_width = logup.width();
    let mut data = Vec::with_capacity(AUX_WIDTH * n);
    let mut id = QuadFelt::ZERO;
    for r in 0..n {
        data.extend((0..logup_width).map(|c| logup.values[r * logup_width + c]));
        data.push(id); // the register past the LogUp columns

        let cell = |c: usize| -> Felt { main.values[r * NUM_MAIN_COLS + c] };
        let full_sum = (0..8).fold(QuadFelt::ZERO, |s, j| s + bp[j] * QuadFelt::from(cell(j)));
        let row_kind = r % PERIOD;

        let mut contrib: QuadFelt = if row_kind == ROW_A {
            full_sum
        } else if row_kind == ROW_B {
            let b_active = QuadFelt::ONE - QuadFelt::from(cell(CELL_IS_B_ZERO));
            full_sum * b_active
        } else if row_kind == ROW_C {
            let c_active = QuadFelt::ONE - QuadFelt::from(cell(CELL_IS_C_ZERO));
            -(full_sum * c_active)
        } else {
            debug_assert_eq!(row_kind, ROW_P);
            let k = QuadFelt::from(cell(CELL_K));
            -(k * (full_sum + bp[0]))
        };

        for (j, &(row, gc)) in GAMMA_POS_SLOTS.iter().enumerate() {
            if row == row_kind {
                let w = bp[j + 1] - bp[j] * t32;
                contrib += w * QuadFelt::from(cell(gc));
            }
        }
        for (j, &(row, gc)) in GAMMA_NEG_SLOTS.iter().enumerate() {
            if row == row_kind {
                let w = bp[j + 1] - bp[j] * t32;
                contrib -= w * QuadFelt::from(cell(gc));
            }
        }
        id += contrib;
    }

    (RowMajorMatrix::new(data, AUX_WIDTH), sigma)
}
