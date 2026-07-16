//! 64-bit lane bitwise chiplet.
//!
//! Provides two relations:
//!
//! - [`Logic64Msg`]: tuple `(op, a_lo, a_hi, b_lo, b_hi, c_lo, c_hi)` where `op ∈ {AndNot, Xor}`,
//!   `a, b, c ∈ [0, 2^64)` carried as 32-bit halves (Goldilocks `p ≈ 2^64 − 2^32 + 1` cannot
//!   represent every `u64` canonically).
//! - [`Rol64Msg`]: tuple `(a_lo, a_hi, b_lo, b_hi, k)` where `b = rol_64(a, log2(k))` and `k = 2^s`
//!   is a power of two with `s < 31`. The AIR does not enforce `k` to be a power of two; callers
//!   supply `k` from a periodic column of valid values and [`Bitwise64Requires::require_rol`]
//!   asserts the bound at IR-construction time.
//!
//! The chiplet requires:
//! - [`BytePairLutMsg`] byte-wise on LOGIC rows (8 lookups per row, verifying `c = op(a, b)`
//!   byte-by-byte and implicitly range-checking each byte to `[0, 256)`).
//! - [`Range16Msg`] limb-wise on ROL rows (8 lookups per row, range-checking the 16-bit limbs of
//!   `(lo+2^32)·k` and `(hi+2^32)·k`).
//!
//! ## Trace layout
//!
//! Three row modes, gated by `(is_logic, is_rol)`:
//!
//! - **LOGIC** (`is_logic = 1, is_rol = 0`): provides `Logic64(op, a, b, c)` and issues 8 byte-wise
//!   `BytePairLut` requires. `op_or_k` carries the op tag (0 = AndNot, 1 = Xor); `b_limbs` carry
//!   the 8 bytes of `b`. The result `c` lives in the *next* row's `a_bytes`, locked there by the
//!   byte requires (chain trick).
//! - **ROL** (`is_logic = 0, is_rol = 1`): provides `Rol64(a, b, k)` and issues 8 limb-wise
//!   `Range16` requires. `op_or_k` carries `k` (a power of two `< 2^31`); `b_limbs` carry the 8
//!   16-bit limbs of `((lo+2^32)·k, (hi+2^32)·k)` — first 4 are `(lo+2^32)·k` LSB-first, next 4 are
//!   `(hi+2^32)·k`. The +2^32 offset ensures the products escape the aliasable range `[0, 2^32-2]`,
//!   eliminating the need for canonical-decomposition witnesses. The rolled output `b` is
//!   constructed by pairing each low-half limb with the high-half limb sharing its post-rotate bit
//!   window — `c0 = b_limbs[0] + b_limbs[6]`, `c1 = b_limbs[1] + b_limbs[7]`, `c2 = b_limbs[2] +
//!   b_limbs[4]`, `c3 = b_limbs[3] + b_limbs[5]` — then `b_lo = c0 + c1·2^16 - k`, `b_hi = c2 +
//!   c3·2^16 - k` (subtracting `k` cancels the offset contribution).
//! - **Carrier / padding** (`is_logic = 0, is_rol = 0`): no provide, no requires. Used to hold a
//!   chain value between LOGIC rows (so the previous LOGIC's byte requires resolve) or as zero
//!   padding.
//!
//! `b_limbs` is shared across LOGIC and ROL with different bit-width
//! semantics: 8-bit bytes on LOGIC (range-checked via byte requires);
//! 16-bit limbs on ROL (range-checked via Range16 requires). The
//! column never carries values requiring more than 16 bits.
//!
//! ## ROL soundness — predecessor must be LOGIC
//!
//! ROL rows do not range-check their own `a_bytes`. The byte-range
//! check comes from the *previous* row's BPL byte requires (which
//! constrain `next_row.a_bytes ∈ [0, 256)`). Constraint
//! `is_rol_next · (1 − is_logic) = 0` (cyclic ungated) forbids any
//! non-LOGIC predecessor. [`Bitwise64Requires::require_rol`] enforces
//! the same invariant at IR-construction time.
//!
//! See the design notes for the row-construction
//! algorithm, the +2^32 offset trick's full derivation, and
//! known soundness gaps.

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{array, ops::Range};

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_lifted_air::{BaseAir, LiftedAir, LiftedAirBuilder};

use crate::{
    logup::{
        Challenges, CyclicConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder,
        LookupColumn, LookupGroup, LookupMessage, NUM_PUBLIC_VALUES, NUM_RANDOMNESS,
        NUM_SIGMA_VALUES, build_logup_aux_trace,
    },
    primitives::byte_pair_lut::{BytePairLutMsg, BytePairLutRequires, BytePairOp, Range16Msg},
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    utils::{current_main, halves_le, next_main, pack_le, split_u64_u32},
};

// COLUMN LAYOUT
// ================================================================================================

pub const A_BYTES_RANGE: Range<usize> = 0..8;
/// 8 columns dual-purpose: 8-bit `b` operand bytes on LOGIC rows
/// (range-checked via byte requires); 16-bit limbs of `(lo·k, hi·k)`
/// on ROL rows (range-checked via Range16 requires). On ROL the
/// first 4 are limbs of `lo·k` LSB-first, the next 4 are limbs of
/// `hi·k`.
pub const B_LIMBS_RANGE: Range<usize> = 8..16;
/// LOGIC: op tag (0 = AndNot, 1 = Xor). ROL: `k`, the multiplier
/// (a power of two `< 2^31`). Disabled: 0.
pub const COL_OP_OR_K: usize = 16;
pub const COL_IS_LOGIC: usize = 17;
pub const COL_IS_ROL: usize = 18;
pub const NUM_MAIN_COLS: usize = 19;
/// Three aux columns: one combined provide column (Logic64 + Rol64)
/// and one requires column per row mode (BPL byte requires for LOGIC,
/// Range16 requires for ROL).
pub const NUM_AUX_COLS: usize = 3;
// The single exposed σ ([`NUM_SIGMA_VALUES`]) and the shared
// transcript-root public values ([`NUM_PUBLIC_VALUES`]) follow the
// VM-wide LogUp contract in [`crate::logup`]; the natural last-row
// σ-closing needs no `inv_n`, and this chiplet declares the root but
// does not read it. The three aux columns' running-sum closings share
// the natural last-row close.

/// Aux column accumulating the per-row self-provides — Logic64 on
/// LOGIC rows (gated by `is_logic`) and Rol64 on ROL rows (gated by
/// `is_rol`). 2 LogUp summands per row.
pub const AUX_PROVIDE: usize = 0;
/// Aux column accumulating 8 byte-wise [`BytePairLutMsg`] requires per
/// LOGIC row (gated by `is_logic`).
pub const AUX_LOGIC_REQUIRES: usize = 1;
/// Aux column accumulating 8 [`Range16Msg`] requires per ROL row
/// (gated by `is_rol`).
pub const AUX_ROL_REQUIRES: usize = 2;

// OPERATION
// ================================================================================================

/// 64-bit logic op the chiplet supports. Tag values match
/// [`BytePairOp::tag`] so byte-wise requires use the same op tag in their
/// encoded tuples.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Logic64Op {
    /// `(NOT a) AND b` — Keccak χ convention.
    AndNot,
    Xor,
}

impl Logic64Op {
    pub fn apply(self, a: u64, b: u64) -> u64 {
        match self {
            Logic64Op::AndNot => (!a) & b,
            Logic64Op::Xor => a ^ b,
        }
    }

    pub fn tag(self) -> u8 {
        match self {
            Logic64Op::AndNot => 0,
            Logic64Op::Xor => 1,
        }
    }

    /// The matching [`BytePairOp`] for byte-wise requires.
    pub fn byte_pair_op(self) -> BytePairOp {
        match self {
            Logic64Op::AndNot => BytePairOp::AndNot,
            Logic64Op::Xor => BytePairOp::Xor,
        }
    }
}

// MESSAGES
// ================================================================================================

/// LogUp message for the `Logic64` relation: a 7-tuple
/// `(op, a_lo, a_hi, b_lo, b_hi, c_lo, c_hi)` describing a 64-bit logic
/// op result.
///
/// - `op ∈ {0 = AndNot, 1 = Xor}`
/// - `a_lo, a_hi, …, c_hi ∈ [0, 2^32)` — 32-bit halves of `a`, `b`, `c`, LSB-first (`a = a_lo +
///   2^32 · a_hi`). Goldilocks `p ≈ 2^64 − 2^32 + 1` cannot represent every `u64` canonically, so
///   we encode halves rather than the full 64-bit value.
///
/// Provided by [`Bitwise64Air`] on bus [`BusId::Logic64`]. Encoded as
/// `bus_prefix[Logic64] + β⁰·op + β¹·a_lo + … + β⁶·c_hi`.
#[derive(Debug, Clone)]
pub struct Logic64Msg<E> {
    pub op: E,
    pub a_lo: E,
    pub a_hi: E,
    pub b_lo: E,
    pub b_hi: E,
    pub c_lo: E,
    pub c_hi: E,
}

impl<E, EF> LookupMessage<E, EF> for Logic64Msg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(
            BusId::Logic64 as usize,
            [
                self.op.clone(),
                self.a_lo.clone(),
                self.a_hi.clone(),
                self.b_lo.clone(),
                self.b_hi.clone(),
                self.c_lo.clone(),
                self.c_hi.clone(),
            ],
        )
    }
}

/// LogUp message for the `Rol64` relation: a 5-tuple
/// `(a_lo, a_hi, b_lo, b_hi, k)` describing a 64-bit rotate-left.
///
/// - `a_lo, a_hi, b_lo, b_hi ∈ [0, 2^32)` — 32-bit halves of input `a` and rolled output `b`.
/// - `k = 2^s` with `s ∈ [0, 31)` — the rotation amount as a multiplier. `b = rol_64(a, s)`. The
///   AIR does not enforce that `k` is a power of two or that `s < 31`; callers source `k` from a
///   periodic column of valid values, and [`Bitwise64Requires::require_rol`] asserts the bound at
///   IR-construction time.
///
/// Provided by [`Bitwise64Air`] on bus [`BusId::Rol64`]. Encoded as
/// `bus_prefix[Rol64] + β⁰·a_lo + β¹·a_hi + β²·b_lo + β³·b_hi + β⁴·k`.
#[derive(Debug, Clone)]
pub struct Rol64Msg<E> {
    pub a_lo: E,
    pub a_hi: E,
    pub b_lo: E,
    pub b_hi: E,
    pub k: E,
}

impl<E, EF> LookupMessage<E, EF> for Rol64Msg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(
            BusId::Rol64 as usize,
            [
                self.a_lo.clone(),
                self.a_hi.clone(),
                self.b_lo.clone(),
                self.b_hi.clone(),
                self.k.clone(),
            ],
        )
    }
}

// REQUESTS + CHAIN IR
// ================================================================================================

/// One emitted trace row, lowered from a [`Chain`] at trace-gen.
#[derive(Debug, Clone, Copy)]
enum PendingRow {
    /// LOGIC row (`is_logic = 1`): provides `Logic64(op, a, b, c)` and
    /// issues 8 byte-wise `BytePairLut` requires.
    Real { op: Logic64Op, a: u64, b: u64 },
    /// ROL row (`is_rol = 1`): provides `Rol64(a, b, k)` and issues 8
    /// `Range16` requires. `k` is assumed (by caller contract) to be a
    /// power of two `< 2^31`.
    Rol { a: u64, k: u64 },
    /// Disabled row (`is_logic = is_rol = 0`): holds an uncapped chain's
    /// tail `c` in its `a_bytes` — the one dead carrier every ROL-less
    /// chain leaves. No LogUp activity. (Trace padding shares this mode.)
    Carrier { a: u64 },
}

/// One LOGIC link in a chain: provides `Logic64(op, a, b, c)` with
/// `c = op(a, b)`. Lowered to one `is_logic = 1` row.
#[derive(Debug, Clone, Copy)]
struct LogicOp {
    op: Logic64Op,
    a: u64,
    b: u64,
}

impl LogicOp {
    /// This link's result `c = op(a, b)` — what the next link chains
    /// onto, or what the trailing Carrier / ROL cap holds.
    fn c(&self) -> u64 {
        self.op.apply(self.a, self.b)
    }
}

/// Terminal ROL cap on a chain: provides `Rol64(tail, ·, k)` where the
/// rotated input `tail` is — by construction — the chain's last
/// [`LogicOp`]'s `c`. Only `k` is stored, so the cap can never disagree
/// with the value it rotates. Lowered to one `is_rol = 1` row that
/// recycles the tail LOGIC's result-slot, so the ROL directly follows a
/// LOGIC and the AIR's `is_rol_next · (1 − is_logic) = 0` holds
/// structurally.
#[derive(Debug, Clone, Copy)]
struct RolCap {
    k: u64,
}

/// A maximal `a`-chain: a non-empty run of [`LogicOp`] links where each
/// link's `a` is the previous link's `c`, optionally capped by one
/// terminal ROL. The shape *is* the algorithm — `cap: Option<RolCap>`
/// makes "a ROL is only ever terminal" unrepresentable-if-violated, and
/// emission falls straight out: `logics.len()` `Real` rows, then either
/// the `Rol` cap or one trailing dead `Carrier`.
#[derive(Debug, Clone)]
struct Chain {
    logics: Vec<LogicOp>,
    cap: Option<RolCap>,
}

impl Chain {
    /// The chain's current tail value — its last link's `c`. Total
    /// because `logics` is non-empty by construction.
    fn tail(&self) -> u64 {
        self.logics.last().expect("a chain has >= 1 logic").c()
    }
}

/// One recorded request, in caller-issue order. [`build_chains`] lowers
/// the whole stream into [`Chain`]s at trace-gen; nothing is laid out
/// until then.
#[derive(Debug, Clone, Copy)]
enum Request {
    Logic { op: Logic64Op, a: u64, b: u64 },
    Rol { a: u64, k: u64 },
}

/// Records the `(op, a, b)` LOGIC triples and `(a, k)` rotations
/// [`Bitwise64Air`] must provide, in issue order. The layout — which
/// result chains into which consumer's `a` slot — is deferred to
/// `build_chains`, which packs the stream into `Chain`s.
///
/// Recording (rather than laying rows eagerly) is what lets a consumer's
/// `a` sit right after the LOGIC that produced it regardless of issue
/// order. Chaining is on operand `a` only and matches consumers to
/// producers by **producer index**, not value — so repeated values (e.g.
/// the many θ chains producing `0`) never alias — and the emitted
/// Logic64/Rol64 provides stay an unchanged multiset: the packing is
/// invisible to every other chiplet and to the verifier.
#[derive(Debug, Default, Clone)]
pub struct Bitwise64Requires {
    requests: Vec<Request>,
}

impl Bitwise64Requires {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one `(op, a, b)` LOGIC triple; returns `op(a, b)`.
    ///
    /// Records the request only — the row layout (which result chains into
    /// which consumer's `a`) is deferred to `build_chains`. Drives the 8
    /// byte-wise `BytePairLut` requires the LOGIC row's bus consume expects
    /// (order-invariant, so eager is correct).
    pub fn require(
        &mut self,
        bpl_req: &mut BytePairLutRequires,
        op: Logic64Op,
        a: u64,
        b: u64,
    ) -> u64 {
        let a_bytes = a.to_le_bytes();
        let b_bytes = b.to_le_bytes();
        for i in 0..8 {
            bpl_req.require(op.byte_pair_op(), a_bytes[i], b_bytes[i]);
        }
        self.requests.push(Request::Logic { op, a, b });
        op.apply(a, b)
    }

    /// Record one `(a, k)` ROL operation; returns `rol_64(a, log2(k))`.
    ///
    /// Records the request only. `build_chains` caps the chain whose tail
    /// is `a` with this ROL — claiming its producer *before* any LOGIC, so
    /// the AIR's "ROL must follow LOGIC" constraint
    /// (`is_rol_next · (1 − is_logic) = 0`) is met. Every ROL input must be
    /// a prior LOGIC result; if none exists, `build_chains` panics
    /// (callers can issue `require(Xor, a, 0)` to materialize one).
    ///
    /// `k` must be a power of two with `k < 2^31` (checked here). See
    /// the design notes for the soundness derivation behind the
    /// upper bound. Drives 8 `Range16` requires for the b-limb decomposition
    /// (order-invariant).
    pub fn require_rol(&mut self, bpl_req: &mut BytePairLutRequires, a: u64, k: u64) -> u64 {
        assert!(
            k.is_power_of_two() && k < (1u64 << 31),
            "ROL k must be a power of two < 2^31, got {k:#x}",
        );

        let [a_lo, a_hi] = split_u64_u32(a);
        let lo_offset_k: u64 = (a_lo + (1u64 << 32)).wrapping_mul(k);
        let hi_offset_k: u64 = (a_hi + (1u64 << 32)).wrapping_mul(k);
        for limb in u64_as_four_u16_limbs(lo_offset_k) {
            bpl_req.require_range16(limb);
        }
        for limb in u64_as_four_u16_limbs(hi_offset_k) {
            bpl_req.require_range16(limb);
        }

        self.requests.push(Request::Rol { a, k });
        a.rotate_left(k.trailing_zeros())
    }

    /// Whether any request has been recorded.
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    /// Laid-out rows before power-of-two padding: each chain emits
    /// `logics.len()` LOGIC rows plus one (its ROL cap, or the trailing
    /// dead Carrier holding the uncapped tail). Diagnostic for the
    /// per-perm floor test and trace-size measurement.
    pub fn active_rows(&self) -> usize {
        build_chains(&self.requests).iter().map(|ch| ch.logics.len() + 1).sum()
    }
}

// TRACE GENERATION
// ================================================================================================

/// Lower the recorded requests into [`Chain`]s — the single pass that
/// does the packing.
///
/// Chaining is on operand `a`: a consumer chains onto the LOGIC that
/// produced its `a`. Producers are matched by **index**, not value, so
/// repeated values (e.g. the many θ chains producing `0`) never alias.
/// ROLs claim first — each *must* cap a real producer (no fallback) —
/// then LOGICs, so a ROL never loses its producer to a LOGIC
/// chain-extension competing for the same result.
///
/// Each producer is claimed at most once, so the claim graph is a set of
/// disjoint **paths**. We walk each from its head (a LOGIC that claimed
/// no producer, reading its `a` fresh) along the single `next` pointer,
/// collecting `LogicOp`s until a ROL caps the path or it ends in a dead
/// Carrier tail.
fn build_chains(requests: &[Request]) -> Vec<Chain> {
    let n = requests.len();

    // value -> indices of LOGIC requests producing it, in issue order.
    let mut producers: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (i, r) in requests.iter().enumerate() {
        if let Request::Logic { op, a, b } = *r {
            producers.entry(op.apply(a, b)).or_default().push(i);
        }
    }

    // `next[p]` = the consumer claiming producer `p`'s result (its chain
    // successor); `claimed[p]` pins each producer to one claimer;
    // `is_continuation[i]` marks a LOGIC that chained onto a producer (so
    // it's mid-chain, not a head). ROLs are always caps, never heads.
    let mut next: Vec<Option<usize>> = vec![None; n];
    let mut claimed = vec![false; n];
    let mut is_continuation = vec![false; n];

    // Pass 1 — ROLs claim their producer (no fallback). Pass 2 — LOGICs.
    for (i, r) in requests.iter().enumerate() {
        if let Request::Rol { a, .. } = *r {
            let p = claim_producer(a, i, &producers, &mut claimed).unwrap_or_else(|| {
                panic!(
                    "ROL input {a:#x} has no prior LOGIC producer — issue \
                     require(Xor, {a:#x}, 0) first to materialize one",
                )
            });
            next[p] = Some(i);
            is_continuation[i] = true;
        }
    }
    for (i, r) in requests.iter().enumerate() {
        if let Request::Logic { a, .. } = *r
            && let Some(p) = claim_producer(a, i, &producers, &mut claimed)
        {
            next[p] = Some(i);
            is_continuation[i] = true;
        }
    }

    // Walk each path from its head into a `Chain`.
    let mut chains = Vec::new();
    for head in 0..n {
        if !matches!(requests[head], Request::Logic { .. }) || is_continuation[head] {
            continue;
        }
        let mut logics = Vec::new();
        let mut cap = None;
        let mut cur = Some(head);
        while let Some(idx) = cur {
            match requests[idx] {
                Request::Logic { op, a, b } => {
                    logics.push(LogicOp { op, a, b });
                    cur = next[idx];
                },
                Request::Rol { k, .. } => {
                    cap = Some(RolCap { k });
                    cur = None;
                },
            }
        }
        chains.push(Chain { logics, cap });
    }
    chains
}

/// The latest unclaimed LOGIC producing `v` at an index before `before`,
/// marked claimed. Latest-first keeps a chain's links close in issue
/// order and is a maximum matching for this "any earlier producer"
/// structure, so every ROL that *can* be satisfied is.
fn claim_producer(
    v: u64,
    before: usize,
    producers: &BTreeMap<u64, Vec<usize>>,
    claimed: &mut [bool],
) -> Option<usize> {
    let ps = producers.get(&v)?;
    for &p in ps.iter().rev() {
        if p < before && !claimed[p] {
            claimed[p] = true;
            return Some(p);
        }
    }
    None
}

/// Row-major trace.
///
/// Lowers the recorded requests into chains (`build_chains`) and walks
/// each: its LOGIC links as `Real` rows — every link's `a` is the prior
/// link's `c`, so the AIR's c-in-next-row holds by construction — then
/// either the ROL cap or one trailing dead `Carrier` holding the uncapped
/// tail. Pads to `next_power_of_two` with all-zero rows; minimum height 1.
pub fn generate_trace(requires: Bitwise64Requires) -> RowMajorMatrix<Felt> {
    let chains = build_chains(&requires.requests);
    let total: usize = chains.iter().map(|ch| ch.logics.len() + 1).sum();
    let height = total.max(1).next_power_of_two().max(2);
    let mut values = Vec::with_capacity(height * NUM_MAIN_COLS);

    for chain in &chains {
        for link in &chain.logics {
            push_row(&mut values, PendingRow::Real { op: link.op, a: link.a, b: link.b });
        }
        let tail = chain.tail();
        push_row(
            &mut values,
            match chain.cap {
                Some(RolCap { k }) => PendingRow::Rol { a: tail, k },
                None => PendingRow::Carrier { a: tail },
            },
        );
    }

    values.resize(height * NUM_MAIN_COLS, Felt::ZERO);
    RowMajorMatrix::new(values, NUM_MAIN_COLS)
}

/// Append one trace row's `NUM_MAIN_COLS` field elements to `values`.
fn push_row(values: &mut Vec<Felt>, row: PendingRow) {
    match row {
        PendingRow::Real { op, a, b } => {
            values.extend(a.to_le_bytes().map(Felt::from));
            values.extend(b.to_le_bytes().map(Felt::from));
            // op_or_k = op tag; is_logic = 1; is_rol = 0.
            values.extend([Felt::from(op.tag()), Felt::from(1u8), Felt::ZERO]);
        },
        PendingRow::Rol { a, k } => {
            values.extend(a.to_le_bytes().map(Felt::from));
            // b_limbs: 8 × 16-bit limbs of ((lo+2^32)·k, (hi+2^32)·k).
            // The +2^32 offset keeps the product ≥ 2^32, escaping the
            // aliasable range [0, 2^32−2] and eliminating the need for
            // canonical-decomposition witness columns.
            let [a_lo, a_hi] = split_u64_u32(a);
            let lo_offset_k: u64 = (a_lo + (1u64 << 32)).wrapping_mul(k);
            let hi_offset_k: u64 = (a_hi + (1u64 << 32)).wrapping_mul(k);
            values.extend(u64_as_four_u16_limbs(lo_offset_k).map(Felt::from));
            values.extend(u64_as_four_u16_limbs(hi_offset_k).map(Felt::from));
            // op_or_k = k; is_logic = 0; is_rol = 1.
            values.extend([
                Felt::new(k).expect("k fits in canonical Goldilocks"),
                Felt::ZERO,
                Felt::from(1u8),
            ]);
        },
        PendingRow::Carrier { a } => {
            values.extend(a.to_le_bytes().map(Felt::from));
            // Zero b_limbs (8) + zero op_or_k + zero is_logic + zero is_rol.
            values.extend([Felt::ZERO; 11]);
        },
    }
}

/// Decompose a `u64` into four 16-bit limbs LSB-first.
fn u64_as_four_u16_limbs(x: u64) -> [u16; 4] {
    [
        (x & 0xffff) as u16,
        ((x >> 16) & 0xffff) as u16,
        ((x >> 32) & 0xffff) as u16,
        ((x >> 48) & 0xffff) as u16,
    ]
}

// AIR
// ================================================================================================

#[derive(Debug, Default, Clone, Copy)]
pub struct Bitwise64Air;

impl BaseAir<Felt> for Bitwise64Air {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        // The shared transcript root (declared, unread by this chiplet);
        // the aux columns' running-sum closings share the natural
        // last-row σ-closing, which needs no `inv_n`.
        NUM_PUBLIC_VALUES
    }
}

impl LiftedAir<Felt, QuadFelt> for Bitwise64Air {
    fn num_randomness(&self) -> usize {
        NUM_RANDOMNESS
    }

    fn aux_width(&self) -> usize {
        NUM_AUX_COLS
    }

    fn num_aux_values(&self) -> usize {
        // Single committed σ — the running sum's residue at column 0.
        // Cols 1, 2 are per-row fraction columns whose values are
        // aggregated into col 0's running sum, so they contribute no
        // separate σ.
        NUM_SIGMA_VALUES
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        build_aux(main, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        // Phase 1: non-LogUp constraints. Read the row, emit all
        // boolean / mutex / ROL-after-LOGIC / limb-decomp /
        // rolled-output constraints against `&mut AB` directly.
        let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
        let next_is_rol: AB::Var = next_main::<_, _, 1>(builder.main(), COL_IS_ROL)[0];

        let op_or_k = AB::Expr::from(local[COL_OP_OR_K]);
        let is_logic = AB::Expr::from(local[COL_IS_LOGIC]);
        let is_rol = AB::Expr::from(local[COL_IS_ROL]);

        // Selector binarity.
        builder.assert_bool(local[COL_IS_LOGIC]);
        builder.assert_bool(local[COL_IS_ROL]);

        // Mutex: at most one mode active per row. Both 0 = disabled.
        builder.assert_zero(is_logic.clone() * is_rol.clone());

        // ROL must be preceded by LOGIC (cyclic ungated). Subsumes
        // ROL/ROL forbid AND Carrier/padding → ROL forbid AND wrap.
        builder.assert_zero(AB::Expr::from(next_is_rol) * (AB::Expr::ONE - is_logic));

        let a_bytes: [AB::Var; 8] = array::from_fn(|i| local[A_BYTES_RANGE.start + i]);
        let b_limbs: [AB::Var; 8] = array::from_fn(|i| local[B_LIMBS_RANGE.start + i]);

        // Reconstruct 32-bit halves of a (current row).
        let [a_lo, a_hi]: [AB::Expr; 2] = halves_le(&a_bytes, 256);

        // ROL: b_limbs are 16-bit limbs of ((lo+2^32)·k, (hi+2^32)·k).
        // The +2^32 offset ensures the product is always ≥ 2^32,
        // escaping the aliasable range [0, 2^32-2] and eliminating the
        // need for canonical-decomposition witness columns.
        let two_32 = AB::Expr::from(Felt::new(1u64 << 32).expect("2^32 fits"));

        let lo_offset_k_decomp: AB::Expr = pack_le(&b_limbs[0..4], 1u64 << 16);
        let hi_offset_k_decomp: AB::Expr = pack_le(&b_limbs[4..8], 1u64 << 16);

        // (lo + 2^32)·k = decomposition (gated by is_rol; deg 1 + 1 + 1 = 3).
        builder.assert_zero(
            is_rol.clone() * ((a_lo + two_32.clone()) * op_or_k.clone() - lo_offset_k_decomp),
        );
        builder.assert_zero(is_rol * ((a_hi + two_32) * op_or_k - hi_offset_k_decomp));

        // Phase 2: LogUp argument via the LogUp adapter.
        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

// LOOKUP AIR
// ================================================================================================

/// Per-column emission shape, mutex-aware:
/// - col 0: 2 mutex provides → max 1 active per row.
/// - col 1: 8-way batch of byte requires (always 8 pushes per row, with multiplicity = is_logic
///   baked in).
/// - col 2: 8-way batch of Range16 requires (always 8 pushes, multiplicity = is_rol).
const COLUMN_SHAPE: [usize; 3] = [1, 8, 8];

impl<LB> LookupAir<LB> for Bitwise64Air
where
    LB: LookupBuilder<F = Felt>,
{
    fn num_columns(&self) -> usize {
        NUM_AUX_COLS
    }

    fn column_shape(&self) -> &[usize] {
        &COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        NUM_BUS_IDS
    }

    fn eval(&self, builder: &mut LB) {
        let local: [LB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
        let next_a_bytes: [LB::Var; 8] = next_main(builder.main(), A_BYTES_RANGE.start);

        let op_or_k: LB::Expr = local[COL_OP_OR_K].into();
        let is_logic: LB::Expr = local[COL_IS_LOGIC].into();
        let is_rol: LB::Expr = local[COL_IS_ROL].into();

        let a_bytes: [LB::Var; 8] = array::from_fn(|i| local[A_BYTES_RANGE.start + i]);
        let b_limbs: [LB::Var; 8] = array::from_fn(|i| local[B_LIMBS_RANGE.start + i]);

        // === Shared between LOGIC and ROL self-provides ============
        // `a` is the row's input operand; both messages encode it as
        // its two 32-bit halves.
        let [a_lo, a_hi]: [LB::Expr; 2] = halves_le(&a_bytes, 256);

        // === LOGIC-only halves =====================================
        // `b` is composed of bytes (8-bit limbs); `c` lives in the
        // next row's `a_bytes` (chain trick).
        let [b_lo, b_hi]: [LB::Expr; 2] = halves_le(&b_limbs, 256);
        let [c_lo, c_hi]: [LB::Expr; 2] = halves_le(&next_a_bytes, 256);

        // === ROL-only halves =======================================
        // `b` is reconstructed from b_limbs (16-bit limbs of offset
        // products), with the +2^32·k offset cancelled per half.
        let two_16: LB::Expr = LB::Expr::from(Felt::from(1u32 << 16));
        let c0 = LB::Expr::from(b_limbs[0]) + LB::Expr::from(b_limbs[6]);
        let c1 = LB::Expr::from(b_limbs[1]) + LB::Expr::from(b_limbs[7]);
        let c2 = LB::Expr::from(b_limbs[2]) + LB::Expr::from(b_limbs[4]);
        let c3 = LB::Expr::from(b_limbs[3]) + LB::Expr::from(b_limbs[5]);
        let rol_b_lo = c0 + c1 * two_16.clone() - op_or_k.clone();
        let rol_b_hi = c2 + c3 * two_16 - op_or_k.clone();

        // Per-emission `Deg` annotations. The framework treats these as
        // documentation (production adapters ignore them); names make
        // the call sites legible.
        //
        // - Per interaction: payload deg 1 (committed columns), signed multiplicity deg 1 → `n=1,
        //   d=1`.
        // - Col 0 mutex group of 2 provides: `U_g = 1 + Σ (v_i−1)·flag_i` ⇒ deg 2; `V_g = ±Σ
        //   flag_i` ⇒ deg 1.
        // - Cols 1, 2 8-way batches: `(N, D) = (Σ is_X·∏v_{j≠i}, ∏v)` ⇒ each side deg 8.
        //   Group/column inherit the batch's shape (single batch per group, single group per
        //   column).
        let interaction_deg = Deg { v: 1, u: 1 };
        let provides_deg = Deg { v: 1, u: 2 };
        let requires_deg = Deg { v: 8, u: 8 };

        // ---- col 0: mutex group, 2 self-provides ------------------
        // `g.remove` carries multiplicity = -1 implicitly (provide).
        // Mutex flags is_logic / is_rol select which message is active
        // for the row; carrier/padding rows produce no contribution.
        builder.next_column(
            |col| {
                col.group(
                    "self-provides",
                    |g| {
                        g.remove(
                            "logic",
                            is_logic.clone(),
                            || Logic64Msg {
                                op: op_or_k.clone(),
                                a_lo: a_lo.clone(),
                                a_hi: a_hi.clone(),
                                b_lo,
                                b_hi,
                                c_lo,
                                c_hi,
                            },
                            interaction_deg,
                        );
                        g.remove(
                            "rol",
                            is_rol.clone(),
                            || Rol64Msg {
                                a_lo,
                                a_hi,
                                b_lo: rol_b_lo,
                                b_hi: rol_b_hi,
                                k: op_or_k.clone(),
                            },
                            interaction_deg,
                        );
                    },
                    provides_deg,
                );
            },
            provides_deg,
        );

        // ---- col 1: 8 simultaneous LOGIC byte requires ------------
        // Inner mult = is_logic gates the contribution per insert.
        // Outer flag = ONE keeps the column degree at 9 (legacy
        // parity); the prover does push 8 zero-multiplicity fractions
        // per row when is_logic = 0, which the accumulator collapses
        // to 0 in col 1's per-row value.
        builder.next_column(
            |col| {
                col.group(
                    "logic-byte-requires",
                    |g| {
                        g.batch(
                            "bytes",
                            LB::Expr::ONE,
                            |b| {
                                for i in 0..8 {
                                    b.insert(
                                        "byte_i",
                                        is_logic.clone(),
                                        BytePairLutMsg {
                                            op: op_or_k.clone(),
                                            a: a_bytes[i].into(),
                                            b: b_limbs[i].into(),
                                            c: next_a_bytes[i].into(),
                                        },
                                        interaction_deg,
                                    );
                                }
                            },
                            requires_deg,
                        );
                    },
                    requires_deg,
                );
            },
            requires_deg,
        );

        // ---- col 2: 8 simultaneous ROL Range16 requires -----------
        // Same inner-mult pattern, gated by is_rol.
        builder.next_column(
            |col| {
                col.group(
                    "rol-range16-requires",
                    |g| {
                        g.batch(
                            "limbs",
                            LB::Expr::ONE,
                            |b| {
                                for &limb in &b_limbs {
                                    b.insert(
                                        "limb_i",
                                        is_rol.clone(),
                                        Range16Msg { w: limb.into() },
                                        interaction_deg,
                                    );
                                }
                            },
                            requires_deg,
                        );
                    },
                    requires_deg,
                );
            },
            requires_deg,
        );
    }
}

// PROVER
// ================================================================================================

/// Builds the aux trace for [`Bitwise64Air`].
///
/// Carries no state: the free [`generate_trace`] builds the main trace
/// from a [`Bitwise64Requires`] accumulator, and the aux trace is driven
/// by the generic [`build_logup_aux_trace`] over that populated main
/// trace. The verifier-side [`Bitwise64Air`] is likewise a unit struct.
pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    build_logup_aux_trace(&Bitwise64Air, main, challenges)
}
