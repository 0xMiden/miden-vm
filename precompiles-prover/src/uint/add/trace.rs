//! UintAdd trace generation + aux builder.
//!
//! [`generate_trace`] lays each add op out as a [`PERIOD`]-row block: the
//! open row holds `a ‖ b` (two full 8×32 values, pulled from the store
//! over `UintVal`), the closing row `c ‖ p`, with the signed ternary
//! carries `γⱼ` spread across the carry columns per [`GAMMA_SLOTS`].
//! `build_aux` drives the LogUp running sums; the Schwartz–Zippel
//! identity is a block-local main-trace constraint, so no aux register
//! accompanies them.

use alloc::{collections::BTreeMap, vec::Vec};

use miden_core::{
    Felt,
    field::{Field, QuadFelt},
    utils::RowMajorMatrix,
};

use super::{
    CELL_B_ON, CELL_C_ON, CELL_D_W, CELL_D_WS, CELL_HI, CELL_IS_B_ZERO, CELL_IS_C_ZERO, CELL_K,
    COL_A_PTR, COL_NZ, GAMMA_SLOTS, NUM_GAMMA, NUM_LIMBS, NUM_MAIN_COLS, PERIOD, ROW_AB, ROW_CP,
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
/// lays out) plus the derived witness: the reduction bit `k` and the
/// signed ternary carries `γⱼ` — each the difference between the binary
/// carry chain of `a+b` and that of `c+k·p` (with `p = bound + 1`), so
/// `γⱼ ∈ {−1, 0, 1}`, committed directly as field elements.
struct Witness {
    a: [u32; 8],
    b: [u32; 8],
    c: [u32; 8],
    bound: [u32; 8],
    k: u32,
    gamma: [Felt; NUM_GAMMA],
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

    // γⱼ = γ⁺ⱼ − γ⁻ⱼ: two binary chains difference to a ternary value.
    let mut gamma = [Felt::ZERO; NUM_GAMMA];
    for j in 0..NUM_GAMMA {
        gamma[j] = Felt::from(gamma_pos[j]) - Felt::from(gamma_neg[j]);
    }

    // The nonzero certificate: S = Σⱼ bⱼ (native sum, no wrap — 8 limbs
    // each < 2³² sum to < 2³⁵ ≪ p_Goldilocks), w = S⁻¹.
    let d_w = if op.nz {
        let s: u64 = b.iter().map(|&limb| u64::from(limb)).sum();
        debug_assert_ne!(s, 0, "nz certifies b ≠ 0, but b's limbs sum to 0");
        Felt::new(s).expect("S < 2^35 < Goldilocks p").inverse()
    } else {
        Felt::ZERO
    };

    Witness { a, b, c, bound, k, gamma, d_w }
}

/// Build the UintAdd main trace from the recorded ops — one op = one
/// [`PERIOD`]-row block, the values + witnesses resolved from the store.
/// The open row holds `a ‖ b`, the closing row `c ‖ p`; the four ptrs +
/// `act` + `nz` repeat on both rows (cycle-constant); the block scalars
/// (`is_b_zero`, `k`, `is_c_zero`, the activity gates, the nz-cert
/// witness, the provide multiplicity) and the signed carries ride the
/// cells per the layout table in [`super`]. Padded to a power-of-two
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

        // Open row: a ‖ b; closing row: c ‖ p. The carries, flags and the
        // closing-row provide mult ride the cells per the layout table.
        let mut block = [[Felt::ZERO; NUM_MAIN_COLS]; PERIOD];
        for j in 0..NUM_LIMBS {
            block[ROW_AB][j] = Felt::from(w.a[j]);
            block[ROW_AB][CELL_HI + j] = Felt::from(w.b[j]);
            block[ROW_CP][j] = Felt::from(w.c[j]);
            block[ROW_CP][CELL_HI + j] = Felt::from(w.bound[j]);
        }
        for (j, &(row, cell)) in GAMMA_SLOTS.iter().enumerate() {
            block[row][cell] = w.gamma[j];
        }
        block[ROW_AB][CELL_IS_B_ZERO] = Felt::from(op.b.is_none() as u32);
        block[ROW_CP][CELL_IS_C_ZERO] = Felt::from(op.c.is_none() as u32);
        // b_on / c_on = act·(1 − is_zero); act = 1 for every real op block
        // (padding blocks stay all-zero via the trailing zero-fill).
        block[ROW_AB][CELL_B_ON] = Felt::from(op.b.is_some() as u32);
        block[ROW_CP][CELL_C_ON] = Felt::from(op.c.is_some() as u32);
        block[ROW_CP][CELL_K] = Felt::from(w.k);
        block[ROW_CP][TERM_CELL_MULT] = Felt::from(*mult);
        if op.nz {
            let s_sum: Felt = block[ROW_AB][CELL_HI..CELL_HI + NUM_LIMBS].iter().copied().sum();
            block[ROW_AB][CELL_D_W] = w.d_w;
            block[ROW_AB][CELL_D_WS] = w.d_w * s_sum;
        }

        // Cycle-constant metadata (cols COL_A_PTR..=COL_NZ), identical on
        // both rows of the block.
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

/// Witness-bearing companion to [`UintAddAir`]: the three LogUp fraction
/// columns over the `UintVal` consumes + the `UintAdd` provide. The
/// Schwartz–Zippel identity is a block-local main-trace constraint, so
/// the aux trace carries no register alongside them.
pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    build_logup_aux_trace(&UintAddAir, main, challenges)
}
