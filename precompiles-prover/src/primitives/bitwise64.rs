//! 64-bit lane bitwise chiplet.
//!
//! Provides three relations:
//!
//! - [`Logic64Msg`]: tuple `(op, a_lo, a_hi, b_lo, b_hi, c_lo, c_hi)` where `op ∈ {AndNot, Xor}`,
//!   `a, b, c ∈ [0, 2^64)` carried as 32-bit halves (Goldilocks `p ≈ 2^64 − 2^32 + 1` cannot
//!   represent every `u64` canonically).
//! - [`Rol64Msg`]: tuple `(a_lo, a_hi, b_lo, b_hi, k)` where `b = rol_64(a, log2(k))` and `k = 2^s`
//!   is a power of two with `s < 31`. The AIR does not enforce `k` to be a power of two; callers
//!   supply `k` from a periodic column of valid values and [`Bitwise64Requires::require_rol`]
//!   asserts the bound at IR-construction time.
//! - [`XorRol64Msg`]: tuple `(a_lo, a_hi, b_lo, b_hi, c_lo, c_hi, k)` describing the fused `c =
//!   rol_64(a ⊕ b, log2(k))` — a θ-apply+ρ pair provided as one tuple instead of a `Logic64 +
//!   Rol64` pair, so a consumer (the keccak round) never needs the XOR intermediate `r = a ⊕ b` to
//!   leave this chiplet. See [`Bitwise64Requires::require_xorrol`].
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
//! A ROL row may additionally set `is_xorrol_cap` (implies `is_rol`): the preceding LOGIC row then
//! provides `XorRol64` (reading this row's rolled output + `k`) instead of `Logic64`, and this row
//! suppresses its own `Rol64`. The requires are unchanged — the LOGIC row's byte requires and this
//! row's Range16 requires still pin `r = a ⊕ b` and `c = rol(r, k)`, so verification is identical
//! to the un-fused two-op form.
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
        NUM_SIGMA_VALUES, build_logup_aux_trace, frac_col,
    },
    primitives::byte_pair_lut::{BytePairLutMsg, BytePairLutRequires, BytePairOp, Range16Msg},
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    utils::{current_main, halves_le, next_main, pack_le, split_u64_u32},
};

// COLUMN LAYOUT
// ================================================================================================

// All column indices below are **lane-local** (within one
// [`LANE_WIDTH`]-wide band); the absolute index in the main trace is
// `lane * LANE_WIDTH + local`, via [`lane_base`].
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
/// Fused-pair cap flag (boolean): 1 on the ROL row that caps a θ-apply+ρ
/// fused request ([`Bitwise64Requires::require_xorrol`]), 0 elsewhere. Drives
/// the provide mux — the LOGIC row before it provides `XorRol64` (not
/// `Logic64`) and this ROL row suppresses its `Rol64`, so a consumer reads
/// one fused tuple. Implies `is_rol`.
pub const COL_IS_XORROL_CAP: usize = 19;

/// Width of one chain-lane's column band.
pub const LANE_WIDTH: usize = 20;
/// Number of parallel chain-lanes packed side-by-side per row. The trace
/// runs `NUM_LANES` independent chain-streams in disjoint column bands, so
/// the row count is ~`1/NUM_LANES` of a single stream. Each lane holds
/// **whole chains only** — a chain is never split across lanes — so every
/// cross-row dependency (the chain trick's `c`-in-next-row, the
/// `is_rol·(1−is_logic)` predecessor constraint, and the fused cap's
/// next-row `b_limbs` read) stays intra-lane. The LogUp bus contribution is
/// the union of all lanes (an unchanged multiset), summed into the single σ.
pub const NUM_LANES: usize = 2;
pub const NUM_MAIN_COLS: usize = LANE_WIDTH * NUM_LANES;

/// Absolute start column of `lane`'s band in the main trace.
#[inline]
pub fn lane_base(lane: usize) -> usize {
    lane * LANE_WIDTH
}

/// FLATTENED to lqd 1: per lane, 18 fractions (2 self-provides, 8 LOGIC byte
/// requires, 8 ROL Range16 requires — all degree-1 multiplicities) split
/// across ten columns, ≤ 2 each, the lane's provide column a single fraction.
/// Aux column 0 (lane 0's running sum) uses a single-insert batch (outer flag
/// ONE) so the gated σ-close lands at degree 3, not the degree 4 a group-level
/// `remove` flag would give; every later lane's provide is an ordinary
/// fraction column folded into that same running sum. Width disregarded.
pub const NUM_AUX_COLS: usize = 10 * NUM_LANES;
// The single exposed σ ([`NUM_SIGMA_VALUES`]) and the shared
// transcript-root public values ([`NUM_PUBLIC_VALUES`]) follow the
// VM-wide LogUp contract in [`crate::logup`]; the natural last-row
// σ-closing needs no `inv_n`, and this chiplet declares the root but
// does not read it. The aux columns' running-sum closing shares the
// natural last-row close, folding every lane's fraction columns into
// the single running sum at column 0.

/// Aux column 0 (running sum) — lane 0's `Rol64` self-provide (gated
/// `−(is_rol − is_xorrol_cap)`; a fused cap defers to the LOGIC row's
/// `XorRol64`). Every other fraction column — including each later lane's
/// own `Rol64` provide — is summed into this running sum by the col-0
/// recurrence.
pub const AUX_PROVIDE: usize = 0;

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

/// LogUp message for the fused `XorRol64` relation: a 7-tuple
/// `(a_lo, a_hi, b_lo, b_hi, c_lo, c_hi, k)` describing `c = rol_64(a ⊕ b, log2(k))`.
///
/// Provided once per θ-apply+ρ pair from the pair's LOGIC row (reading the capping ROL row's
/// rolled output and `k`), so a consumer reads one tuple instead of `Logic64 + Rol64`. The fusion
/// is provide-only: the LOGIC row's `BytePairLut` requires still pin `r = a ⊕ b` (in the ROL row's
/// `a_bytes` via the chain trick) and the ROL row's `Range16` requires still pin `c = rol(r, k)`,
/// so `r` never leaves the chiplet and the verification is unchanged.
///
/// Provided by [`Bitwise64Air`] on bus [`BusId::XorRol64`]. Encoded as
/// `bus_prefix[XorRol64] + β⁰·a_lo + … + β⁵·c_hi + β⁶·k`.
#[derive(Debug, Clone)]
pub struct XorRol64Msg<E> {
    pub a_lo: E,
    pub a_hi: E,
    pub b_lo: E,
    pub b_hi: E,
    pub c_lo: E,
    pub c_hi: E,
    pub k: E,
}

impl<E, EF> LookupMessage<E, EF> for XorRol64Msg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(
            BusId::XorRol64 as usize,
            [
                self.a_lo.clone(),
                self.a_hi.clone(),
                self.b_lo.clone(),
                self.b_hi.clone(),
                self.c_lo.clone(),
                self.c_hi.clone(),
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
    /// power of two `< 2^31`. `fused` caps a `require_xorrol` pair: the row
    /// sets `is_xorrol_cap` and suppresses its `Rol64` (the preceding LOGIC
    /// provides `XorRol64` instead).
    Rol { a: u64, k: u64, fused: bool },
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
    /// Set when this cap closes a `require_xorrol` pair — the row is flagged
    /// `is_xorrol_cap` and the chain's last LOGIC provides `XorRol64`.
    fused: bool,
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
    Rol { a: u64, k: u64, fused: bool },
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
        self.require_rol_inner(bpl_req, a, k, false)
    }

    /// Record a fused `c = rol_64(a ⊕ b, log2(k))` — one `require(Xor, a, b)`
    /// producing `r = a ⊕ b` then a *fused* ROL on `r`. The pair lays a LOGIC
    /// row (the XOR) capped by an `is_xorrol_cap` ROL row; the LOGIC row
    /// provides a single `XorRol64(a, b, c, k)` instead of `Logic64`, and the
    /// ROL row suppresses its `Rol64`. Drives both the 8 byte-wise XOR
    /// requires and the 8 ROL `Range16` requires (the verification is
    /// unchanged from the two-op form). Returns `c`.
    pub fn require_xorrol(
        &mut self,
        bpl_req: &mut BytePairLutRequires,
        a: u64,
        b: u64,
        k: u64,
    ) -> u64 {
        let r = self.require(bpl_req, Logic64Op::Xor, a, b);
        self.require_rol_inner(bpl_req, r, k, true)
    }

    fn require_rol_inner(
        &mut self,
        bpl_req: &mut BytePairLutRequires,
        a: u64,
        k: u64,
        fused: bool,
    ) -> u64 {
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

        self.requests.push(Request::Rol { a, k, fused });
        a.rotate_left(k.trailing_zeros())
    }

    /// Whether any request has been recorded.
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    /// Total logical rows across all chains, independent of lane packing:
    /// each chain emits `logics.len()` LOGIC rows plus one (its ROL cap, or
    /// the trailing dead Carrier holding the uncapped tail). Diagnostic for
    /// the per-perm floor test; the populated trace height is ~this divided
    /// by [`NUM_LANES`] (see [`Self::populated_rows`]).
    pub fn active_rows(&self) -> usize {
        build_chains(&self.requests).iter().map(|ch| ch.logics.len() + 1).sum()
    }

    /// Populated trace height before power-of-two padding: the busiest
    /// lane's row count after `build_lanes` balances whole chains across
    /// [`NUM_LANES`] bands.
    pub fn populated_rows(&self) -> usize {
        build_lanes(&self.requests)
            .iter()
            .map(|lane| lane.iter().map(|ch| ch.logics.len() + 1).sum::<usize>())
            .max()
            .unwrap_or(0)
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
                Request::Rol { k, fused, .. } => {
                    cap = Some(RolCap { k, fused });
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

/// Partition the chains ([`build_chains`]) into [`NUM_LANES`] bands by
/// least-loaded greedy on row count (`logics.len() + 1`). Whole chains
/// only — a chain is never split — so every intra-chain row dependency
/// (the chain trick, the ROL-after-LOGIC predecessor, the fused cap's
/// next-row read) stays inside one lane. Balance is purely a height
/// concern; soundness is independent of the assignment because the LogUp
/// bus sees the same multiset regardless of which lane provides it.
fn build_lanes(requests: &[Request]) -> [Vec<Chain>; NUM_LANES] {
    let mut lanes: [Vec<Chain>; NUM_LANES] = array::from_fn(|_| Vec::new());
    let mut loads = [0usize; NUM_LANES];
    for chain in build_chains(requests) {
        let rows = chain.logics.len() + 1;
        // Lowest-index least-loaded lane (deterministic on ties).
        let target = (0..NUM_LANES).min_by_key(|&l| loads[l]).unwrap_or(0);
        loads[target] += rows;
        lanes[target].push(chain);
    }
    lanes
}

/// Row-major trace, [`NUM_LANES`] chain-lanes packed side-by-side.
///
/// Lowers the recorded requests into chains (`build_chains`), balances
/// whole chains across [`NUM_LANES`] column bands (`build_lanes`), and
/// lays each lane independently: its LOGIC links as `Real` rows — every
/// link's `a` is the prior link's `c`, so the AIR's c-in-next-row holds by
/// construction — then either the ROL cap or one trailing dead `Carrier`
/// holding the uncapped tail. Each lane is zero-padded past its content;
/// the matrix pads to `next_power_of_two` of the busiest lane, minimum 2.
pub fn generate_trace(requires: Bitwise64Requires) -> RowMajorMatrix<Felt> {
    let lanes = build_lanes(&requires.requests);

    // Each lane lowers to its own flat band of LANE_WIDTH-wide rows.
    let lane_cells: [Vec<Felt>; NUM_LANES] = array::from_fn(|l| {
        let mut v = Vec::new();
        for chain in &lanes[l] {
            for link in &chain.logics {
                push_row(&mut v, PendingRow::Real { op: link.op, a: link.a, b: link.b });
            }
            let tail = chain.tail();
            push_row(
                &mut v,
                match chain.cap {
                    Some(RolCap { k, fused }) => PendingRow::Rol { a: tail, k, fused },
                    None => PendingRow::Carrier { a: tail },
                },
            );
        }
        v
    });

    let lane_rows = |l: usize| lane_cells[l].len() / LANE_WIDTH;
    let max_rows = (0..NUM_LANES).map(lane_rows).max().unwrap_or(0);
    let height = max_rows.max(1).next_power_of_two().max(2);

    // Interleave the lane bands into one NUM_MAIN_COLS-wide row-major
    // matrix, zero-padding each lane past its content up to `height`.
    let mut values = vec![Felt::ZERO; height * NUM_MAIN_COLS];
    for (l, cells) in lane_cells.iter().enumerate() {
        let base = lane_base(l);
        for r in 0..lane_rows(l) {
            let src = &cells[r * LANE_WIDTH..(r + 1) * LANE_WIDTH];
            let row_start = r * NUM_MAIN_COLS + base;
            values[row_start..row_start + LANE_WIDTH].copy_from_slice(src);
        }
    }
    RowMajorMatrix::new(values, NUM_MAIN_COLS)
}

/// Append one lane row's `LANE_WIDTH` field elements to `values`.
fn push_row(values: &mut Vec<Felt>, row: PendingRow) {
    match row {
        PendingRow::Real { op, a, b } => {
            values.extend(a.to_le_bytes().map(Felt::from));
            values.extend(b.to_le_bytes().map(Felt::from));
            // op_or_k = op tag; is_logic = 1; is_rol = 0; is_xorrol_cap = 0.
            values.extend([Felt::from(op.tag()), Felt::from(1u8), Felt::ZERO, Felt::ZERO]);
        },
        PendingRow::Rol { a, k, fused } => {
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
            // op_or_k = k; is_logic = 0; is_rol = 1; is_xorrol_cap = fused.
            values.extend([
                Felt::new(k).expect("k fits in canonical Goldilocks"),
                Felt::ZERO,
                Felt::from(1u8),
                Felt::from(fused as u8),
            ]);
        },
        PendingRow::Carrier { a } => {
            values.extend(a.to_le_bytes().map(Felt::from));
            // Zero b_limbs (8) + op_or_k + is_logic + is_rol + is_xorrol_cap.
            values.extend([Felt::ZERO; 12]);
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
        // Phase 1: non-LogUp constraints, replicated per lane over its
        // disjoint column band. Whole chains stay in one lane, so each band
        // is an independent single-stream trace — boolean / mutex /
        // ROL-after-LOGIC / limb-decomp constraints apply lane-locally.
        let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);

        // ROL: b_limbs are 16-bit limbs of ((lo+2^32)·k, (hi+2^32)·k). The
        // +2^32 offset ensures the product is always ≥ 2^32, escaping the
        // aliasable range [0, 2^32-2] and eliminating the need for
        // canonical-decomposition witness columns.
        let two_32 = AB::Expr::from(Felt::new(1u64 << 32).expect("2^32 fits"));

        for lane in 0..NUM_LANES {
            let base = lane_base(lane);

            let op_or_k = AB::Expr::from(local[base + COL_OP_OR_K]);
            let is_logic = AB::Expr::from(local[base + COL_IS_LOGIC]);
            let is_rol = AB::Expr::from(local[base + COL_IS_ROL]);
            let next_is_rol: AB::Var = next_main::<_, _, 1>(builder.main(), base + COL_IS_ROL)[0];

            // Selector binarity.
            builder.assert_bool(local[base + COL_IS_LOGIC]);
            builder.assert_bool(local[base + COL_IS_ROL]);
            builder.assert_bool(local[base + COL_IS_XORROL_CAP]);

            // Mutex: at most one mode active per row. Both 0 = disabled.
            builder.assert_zero(is_logic.clone() * is_rol.clone());

            // The fused-pair cap flag only ever rides a ROL row (it gates
            // that row's `Rol64` suppression and the preceding LOGIC's
            // `XorRol64` provide). `cap ⟹ is_rol`.
            let is_xorrol_cap = AB::Expr::from(local[base + COL_IS_XORROL_CAP]);
            builder.assert_zero(is_xorrol_cap * (AB::Expr::ONE - is_rol.clone()));

            // A LOGIC row whose next row caps a fused pair drives that pair's
            // `XorRol64` provide. `XorRol64` is definitionally
            // `c = rol_64(a ⊕ b, k)` — its tuple carries no op field — so the
            // op tag is pinned to Xor here. Without it an `op_or_k = AndNot`
            // LOGIC row would make the provide carry `rol_64((¬a)∧b, k)` under
            // the XorRol64 label, and a consumer (the keccak round, which holds
            // no op of its own) would read it as XOR.
            let next_is_xorrol_cap: AB::Var =
                next_main::<_, _, 1>(builder.main(), base + COL_IS_XORROL_CAP)[0];
            builder.assert_zero(
                is_logic.clone()
                    * AB::Expr::from(next_is_xorrol_cap)
                    * (AB::Expr::ONE - op_or_k.clone()),
            );

            // ROL must be preceded by LOGIC (cyclic ungated), within this
            // lane. Subsumes ROL/ROL forbid AND Carrier/padding → ROL forbid
            // AND wrap.
            builder.assert_zero(AB::Expr::from(next_is_rol) * (AB::Expr::ONE - is_logic.clone()));

            let a_bytes: [AB::Var; 8] = array::from_fn(|i| local[base + A_BYTES_RANGE.start + i]);
            let b_limbs: [AB::Var; 8] = array::from_fn(|i| local[base + B_LIMBS_RANGE.start + i]);

            // Reconstruct 32-bit halves of a (current row).
            let [a_lo, a_hi]: [AB::Expr; 2] = halves_le(&a_bytes, 256);

            let lo_offset_k_decomp: AB::Expr = pack_le(&b_limbs[0..4], 1u64 << 16);
            let hi_offset_k_decomp: AB::Expr = pack_le(&b_limbs[4..8], 1u64 << 16);

            // (lo + 2^32)·k = decomposition (gated by is_rol; deg 1+1+1 = 3).
            builder.assert_zero(
                is_rol.clone() * ((a_lo + two_32.clone()) * op_or_k.clone() - lo_offset_k_decomp),
            );
            builder.assert_zero(
                is_rol.clone() * ((a_hi + two_32.clone()) * op_or_k - hi_offset_k_decomp),
            );
        }

        // Phase 2: LogUp argument via the LogUp adapter.
        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

// LOOKUP AIR
// ================================================================================================

/// Per-column emission shape (FLATTENED to lqd 1), repeated per lane: within
/// each lane's 10-column band, col 0 = rol provide (a single fraction; for
/// lane 0 it is the running sum, for later lanes an ordinary fraction folded
/// into it), col 1 = the paired logic + fused-xorrol provides (deg-2 mux
/// mults), cols 2–5 = the 8 LOGIC byte requires (two per col), cols 6–9 = the
/// 8 ROL Range16 requires.
const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = build_column_shape();

const fn build_column_shape() -> [usize; NUM_AUX_COLS] {
    let mut shape = [2usize; NUM_AUX_COLS];
    let mut lane = 0;
    while lane < NUM_LANES {
        // Each lane's provide column (band-local index 0) is a single fraction.
        shape[lane * 10] = 1;
        lane += 1;
    }
    shape
}

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
        let next: [LB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);

        // Per-emission `Deg` annotations. The framework treats these as
        // documentation (production adapters ignore them); names make
        // the call sites legible.
        let interaction_deg = Deg { v: 1, u: 1 };
        let provides_deg = Deg { v: 1, u: 2 };
        let pair_deg = Deg { v: 3, u: 2 };
        let requires_deg = Deg { v: 8, u: 8 };

        // Each lane emits its own 10-column band of fractions over its
        // disjoint main columns. Lane 0's provide column is the running sum
        // (col 0); every later lane's provide is an ordinary fraction column
        // the col-0 recurrence folds in. The bus contribution is the union
        // over lanes — an unchanged multiset — so the single σ is identical
        // to a single-stream trace.
        for lane in 0..NUM_LANES {
            let base = lane_base(lane);

            let next_a_bytes: [LB::Var; 8] =
                array::from_fn(|i| next[base + A_BYTES_RANGE.start + i]);
            let next_b_limbs: [LB::Var; 8] =
                array::from_fn(|i| next[base + B_LIMBS_RANGE.start + i]);

            let op_or_k: LB::Expr = local[base + COL_OP_OR_K].into();
            let is_logic: LB::Expr = local[base + COL_IS_LOGIC].into();
            let is_rol: LB::Expr = local[base + COL_IS_ROL].into();
            // Fused-pair cap flag — local (this ROL suppresses its `Rol64`)
            // and next (the preceding LOGIC muxes `Logic64` → `XorRol64`).
            let is_xorrol_cap: LB::Expr = local[base + COL_IS_XORROL_CAP].into();
            let is_xorrol_cap_next: LB::Expr = next[base + COL_IS_XORROL_CAP].into();
            let next_op_or_k: LB::Expr = next[base + COL_OP_OR_K].into();

            let a_bytes: [LB::Var; 8] = array::from_fn(|i| local[base + A_BYTES_RANGE.start + i]);
            let b_limbs: [LB::Var; 8] = array::from_fn(|i| local[base + B_LIMBS_RANGE.start + i]);

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
            let rol_b_hi = c2 + c3 * two_16.clone() - op_or_k.clone();

            // The *next* (cap ROL) row's rolled output — the fused
            // `XorRol64`'s `c` halves, read by the preceding LOGIC row so it
            // can provide the fused tuple without exposing the XOR
            // intermediate `r`.
            let nc0 = LB::Expr::from(next_b_limbs[0]) + LB::Expr::from(next_b_limbs[6]);
            let nc1 = LB::Expr::from(next_b_limbs[1]) + LB::Expr::from(next_b_limbs[7]);
            let nc2 = LB::Expr::from(next_b_limbs[2]) + LB::Expr::from(next_b_limbs[4]);
            let nc3 = LB::Expr::from(next_b_limbs[3]) + LB::Expr::from(next_b_limbs[5]);
            let next_rol_b_lo = nc0 + nc1 * two_16.clone() - next_op_or_k.clone();
            let next_rol_b_hi = nc2 + nc3 * two_16 - next_op_or_k.clone();

            // band col 0: rol self-provide. A fused cap (`is_xorrol_cap`)
            // suppresses its own `Rol64` — the preceding LOGIC provides the
            // fused `XorRol64` instead; since `is_xorrol_cap ⟹ is_rol`, the
            // mult is the degree-1 `−(is_rol − is_xorrol_cap)`.
            frac_col!(
                builder,
                "self-provides",
                provides_deg,
                (
                    "rol",
                    is_xorrol_cap.clone() - is_rol.clone(),
                    Rol64Msg {
                        a_lo: a_lo.clone(),
                        a_hi: a_hi.clone(),
                        b_lo: rol_b_lo,
                        b_hi: rol_b_hi,
                        k: op_or_k.clone()
                    },
                    interaction_deg
                ),
            );
            // band col 1 (paired, lqd-1): the logic provide muxed with the
            // fused-xorrol provide. A LOGIC row whose next row is a fused cap
            // provides `XorRol64(a, b, c=next rolled output, k=next k)` and
            // suppresses its `Logic64`; otherwise it provides `Logic64`.
            frac_col!(
                builder,
                "self-provides",
                pair_deg,
                (
                    "logic",
                    (is_xorrol_cap_next.clone() - LB::Expr::ONE) * is_logic.clone(),
                    Logic64Msg {
                        op: op_or_k.clone(),
                        a_lo: a_lo.clone(),
                        a_hi: a_hi.clone(),
                        b_lo: b_lo.clone(),
                        b_hi: b_hi.clone(),
                        c_lo,
                        c_hi
                    },
                    interaction_deg
                ),
                (
                    "xorrol",
                    LB::Expr::ZERO - is_logic.clone() * is_xorrol_cap_next,
                    XorRol64Msg {
                        a_lo,
                        a_hi,
                        b_lo,
                        b_hi,
                        c_lo: next_rol_b_lo,
                        c_hi: next_rol_b_hi,
                        k: next_op_or_k
                    },
                    interaction_deg
                ),
            );
            // band cols 2–5: the 8 LOGIC byte requires (BytePairLut), two per column.
            frac_col!(
                builder,
                "logic-byte-requires",
                requires_deg,
                (
                    "byte0",
                    is_logic.clone(),
                    BytePairLutMsg {
                        op: op_or_k.clone(),
                        a: a_bytes[0].into(),
                        b: b_limbs[0].into(),
                        c: next_a_bytes[0].into()
                    },
                    interaction_deg
                ),
                (
                    "byte1",
                    is_logic.clone(),
                    BytePairLutMsg {
                        op: op_or_k.clone(),
                        a: a_bytes[1].into(),
                        b: b_limbs[1].into(),
                        c: next_a_bytes[1].into()
                    },
                    interaction_deg
                ),
            );
            frac_col!(
                builder,
                "logic-byte-requires",
                requires_deg,
                (
                    "byte2",
                    is_logic.clone(),
                    BytePairLutMsg {
                        op: op_or_k.clone(),
                        a: a_bytes[2].into(),
                        b: b_limbs[2].into(),
                        c: next_a_bytes[2].into()
                    },
                    interaction_deg
                ),
                (
                    "byte3",
                    is_logic.clone(),
                    BytePairLutMsg {
                        op: op_or_k.clone(),
                        a: a_bytes[3].into(),
                        b: b_limbs[3].into(),
                        c: next_a_bytes[3].into()
                    },
                    interaction_deg
                ),
            );
            frac_col!(
                builder,
                "logic-byte-requires",
                requires_deg,
                (
                    "byte4",
                    is_logic.clone(),
                    BytePairLutMsg {
                        op: op_or_k.clone(),
                        a: a_bytes[4].into(),
                        b: b_limbs[4].into(),
                        c: next_a_bytes[4].into()
                    },
                    interaction_deg
                ),
                (
                    "byte5",
                    is_logic.clone(),
                    BytePairLutMsg {
                        op: op_or_k.clone(),
                        a: a_bytes[5].into(),
                        b: b_limbs[5].into(),
                        c: next_a_bytes[5].into()
                    },
                    interaction_deg
                ),
            );
            frac_col!(
                builder,
                "logic-byte-requires",
                requires_deg,
                (
                    "byte6",
                    is_logic.clone(),
                    BytePairLutMsg {
                        op: op_or_k.clone(),
                        a: a_bytes[6].into(),
                        b: b_limbs[6].into(),
                        c: next_a_bytes[6].into()
                    },
                    interaction_deg
                ),
                (
                    "byte7",
                    is_logic.clone(),
                    BytePairLutMsg {
                        op: op_or_k.clone(),
                        a: a_bytes[7].into(),
                        b: b_limbs[7].into(),
                        c: next_a_bytes[7].into()
                    },
                    interaction_deg
                ),
            );
            // band cols 6–9: the 8 ROL Range16 requires, two per column.
            frac_col!(
                builder,
                "rol-range16-requires",
                requires_deg,
                ("limb0", is_rol.clone(), Range16Msg { w: b_limbs[0].into() }, interaction_deg),
                ("limb1", is_rol.clone(), Range16Msg { w: b_limbs[1].into() }, interaction_deg),
            );
            frac_col!(
                builder,
                "rol-range16-requires",
                requires_deg,
                ("limb2", is_rol.clone(), Range16Msg { w: b_limbs[2].into() }, interaction_deg),
                ("limb3", is_rol.clone(), Range16Msg { w: b_limbs[3].into() }, interaction_deg),
            );
            frac_col!(
                builder,
                "rol-range16-requires",
                requires_deg,
                ("limb4", is_rol.clone(), Range16Msg { w: b_limbs[4].into() }, interaction_deg),
                ("limb5", is_rol.clone(), Range16Msg { w: b_limbs[5].into() }, interaction_deg),
            );
            frac_col!(
                builder,
                "rol-range16-requires",
                requires_deg,
                ("limb6", is_rol.clone(), Range16Msg { w: b_limbs[6].into() }, interaction_deg),
                ("limb7", is_rol, Range16Msg { w: b_limbs[7].into() }, interaction_deg),
            );
        }
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
