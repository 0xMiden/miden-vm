//! UintStore trace generation + aux builder.
//!
//! [`generate_trace`] lays each interned uint out as a [`PERIOD`]-row
//! block (resolving each uint's bound-value from the modulus it references
//! and counting consumers for `uintval_mult`), padding the block count to
//! a power of two (min 1) with self-referential zero blocks at fresh tail
//! ptrs — each its own modulus and its own single `UintVal` consumer, so
//! padding nets out on the bus without touching the demand ledger.
//! [`build_aux`] drives the LogUp running sum (the `UintVal` provide /
//! consume) and the Schwartz–Zippel `id` register, whose per-row
//! accumulation mirrors [`super::UintStoreAir`]'s `contrib` exactly.

use core::array;
use std::collections::{BTreeMap, HashMap};

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

use crate::logup::build_logup_aux_trace;
use crate::math::{U256, to_limbs16, to_limbs32};
use crate::primitives::byte_pair_lut::BytePairLutRequires;
use crate::relations::ProvideMult;

use super::{
    AUX_WIDTH, CARRY_CELLS_BEGIN, HUB_CELL_UINTLIMBS_MULT, HUB_CELL_UINTVAL_MULT, NUM_LIMBS,
    NUM_MAIN_COLS, PERIOD, TERM_CELL_GAP, UintStoreAir,
};

/// Handle to an interned uint — the store's currency. Only the store
/// mints them (its interning entries are the sole constructors), so
/// holding one *is* proof the uint exists: the require layers accept
/// handles, never raw store addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UintPtr(u32);

impl UintPtr {
    /// The raw store address (trace cells, cap fields, diagnostics).
    pub fn addr(self) -> u32 {
        self.0
    }

    /// Mint a handle for a *known* store address — a pinned uint at a
    /// protocol address the caller already chose (curve params, moduli).
    /// The inverse of [`addr`](Self::addr); store reads panic if nothing
    /// is pinned there.
    pub fn from_addr(addr: u32) -> Self {
        Self(addr)
    }

    /// Mint a handle from a raw address, bypassing the store — for
    /// bare-chiplet tests that lay rows with no backing store.
    #[cfg(test)]
    pub(crate) fn forged(addr: u32) -> Self {
        Self(addr)
    }
}

/// An interned uint: its 256-bit value, its handle, and the handle of
/// its modulus `p − 1`. The modulus references itself
/// (`bound_ptr == ptr`); every other uint references it.
#[derive(Debug, Clone, Copy)]
pub struct Uint {
    pub value: U256,
    pub ptr: UintPtr,
    pub bound_ptr: UintPtr,
}

/// Carries `c_0..c_6` of the 8×32-bit addition `v32 + comp32` (= bound32).
/// The top carry `c_7` is 0 (no overflow) and not stored.
fn carries(v32: &[u32; 8], comp32: &[u32; 8]) -> [u16; 7] {
    let mut c = [0u16; 7];
    let mut carry: u64 = 0;
    for j in 0..7 {
        let s = v32[j] as u64 + comp32[j] as u64 + carry;
        carry = s >> 32;
        c[j] = carry as u16;
    }
    c
}

/// Demand ledger for the [`UintVal`](crate::relations::BusId::UintVal) bus:
/// every consumer — the store's own bound-refs ([`require_bound_refs`]),
/// eval uint-leaves, future add / mul — records per-ptr demand, and the
/// store reads the totals for each uint's provide multiplicity. Mirrors
/// [`BytePairLutRequires`](crate::primitives::byte_pair_lut::BytePairLutRequires)
/// for the `Range16` bus.
#[derive(Debug, Default)]
pub struct UintValRequires {
    demand: BTreeMap<UintPtr, ProvideMult>,
}

impl UintValRequires {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one consumer of the `UintVal` at `ptr`.
    pub fn require(&mut self, ptr: UintPtr) {
        *self.demand.entry(ptr).or_insert(0) += 1;
    }

    /// Total recorded consumers of the `UintVal` at `ptr`.
    pub fn count(&self, ptr: UintPtr) -> ProvideMult {
        self.demand.get(&ptr).copied().unwrap_or(0)
    }
}

/// Pinned uints (well-known constants) occupy the ptr namespace
/// `[1, 2^16)`; ptr 0 is never a store address — it is the uint-leaf
/// cap's "transient" marker (`pin_ptr = 0`) — and transients allocate
/// from `2^16` upward (later).
pub const PIN_NAMESPACE_END: u32 = 1 << 16;

/// `*Requires` accumulator for the UintStore: the interned uints (a
/// ptr-keyed map, with a `(value, modulus)`-keyed reverse index) plus the
/// [`UintVal`](crate::relations::BusId::UintVal) demand ledger. Each
/// uint's bound-ref demand is recorded here on intern, so
/// [`generate_trace`] never relies on the caller to supply it.
///
/// Interning is **canonical**: `value → ptr` is kept injective per
/// modulus, so equal values share one ptr under every interleaving —
/// the `Is`-predicate completeness contract, and what lets an honest
/// prover treat ptrs and values interchangeably. [`intern`](Self::intern)
/// enforces it by dedup, the pin entries by asserting pins land before
/// any equal value. The interning entries are the only [`UintPtr`]
/// constructors.
#[derive(Debug)]
pub struct UintStoreRequires {
    /// ptr → uint; BTreeMap so trace-gen walks blocks in ptr order.
    uints: BTreeMap<UintPtr, Uint>,
    /// `(value, bound_ptr)` → ptr — the canonical-dedup reverse index.
    by_value: HashMap<(U256, UintPtr), UintPtr>,
    /// Next free ptr of the transient namespace `[2^16, …)`.
    next_transient: u32,
    demand: UintValRequires,
    limbs_demand: UintValRequires,
}

impl UintStoreRequires {
    pub fn new() -> Self {
        Self {
            uints: BTreeMap::new(),
            by_value: HashMap::new(),
            next_transient: PIN_NAMESPACE_END,
            demand: UintValRequires::new(),
            limbs_demand: UintValRequires::new(),
        }
    }

    /// Pin a *modulus* at the protocol address `addr ∈ [1, 2^16)` — the
    /// self-referential entry (`bound_ptr == ptr`) every other intern
    /// under that field references. Returns its handle.
    pub fn pin_modulus(&mut self, addr: u32, bound: U256) -> UintPtr {
        let ptr = UintPtr(addr);
        self.insert_pinned(ptr, bound, ptr);
        ptr
    }

    /// Intern a *pinned* uint (a well-known constant) at the protocol
    /// address `addr ∈ [1, 2^16)` under the modulus `bound`, recording
    /// its bound-ref `UintVal` demand. Returns its handle. Panics on an
    /// out-of-namespace or duplicate address, an out-of-range value, and
    /// on a value already interned under the same modulus — pins are
    /// protocol addresses, so they must land before any equal value can
    /// be interned canonically onto them.
    pub fn intern_pinned(&mut self, addr: u32, value: U256, bound: UintPtr) -> UintPtr {
        let ptr = UintPtr(addr);
        assert!(
            value <= self.uint(bound).value,
            "value exceeds its modulus bound"
        );
        self.insert_pinned(ptr, value, bound);
        ptr
    }

    fn insert_pinned(&mut self, ptr: UintPtr, value: U256, bound_ptr: UintPtr) {
        assert!(
            (1..PIN_NAMESPACE_END).contains(&ptr.0),
            "pinned uint ptr {} outside the pin namespace [1, 2^16)",
            ptr.0,
        );
        assert!(
            !self.uints.contains_key(&ptr),
            "duplicate uint ptr {}",
            ptr.0,
        );
        let prev = self.by_value.insert((value, bound_ptr), ptr);
        assert!(
            prev.is_none(),
            "value already interned at ptr {} — pin before computing",
            prev.unwrap().0,
        );
        self.uints.insert(
            ptr,
            Uint {
                value,
                ptr,
                bound_ptr,
            },
        );
        self.demand.require(bound_ptr);
    }

    /// Resolve a *protocol address* to its pin's handle — how a runner's
    /// well-known constant (a modulus address) re-enters handle space.
    /// Panics if nothing is pinned there.
    pub fn pinned(&self, addr: u32) -> UintPtr {
        assert!(
            (1..PIN_NAMESPACE_END).contains(&addr),
            "address {addr} outside the pin namespace [1, 2^16)",
        );
        let ptr = UintPtr(addr);
        assert!(
            self.uints.contains_key(&ptr),
            "no uint pinned at address {addr}",
        );
        ptr
    }

    /// Record one external `UintVal` consumer at `ptr` — e.g. an eval
    /// uint-leaf hashing the stored uint, or an add / mul operand.
    pub fn require_uintval(&mut self, ptr: UintPtr) {
        self.demand.require(ptr);
    }

    /// Record one external `UintLimbs` (raw 8×16 view) consumer at `ptr` —
    /// a mul-chiplet convolution operand. One require covers both halves
    /// (the consumer takes the lo and the hi message exactly once each).
    pub fn require_uintlimbs(&mut self, ptr: UintPtr) {
        self.limbs_demand.require(ptr);
    }

    /// Canonically intern `value` under the modulus `bound` and return
    /// its handle: an already-stored `(value, modulus)` — pinned or
    /// transient — returns its existing ptr (laying no new block);
    /// otherwise the value takes the next ptr of the transient namespace
    /// `[2^16, …)`, with its bound-ref `UintVal` demand recorded.
    pub fn intern(&mut self, value: U256, bound: UintPtr) -> UintPtr {
        if let Some(&ptr) = self.by_value.get(&(value, bound)) {
            return ptr;
        }
        assert!(
            value <= self.uint(bound).value,
            "value exceeds its modulus bound"
        );
        let ptr = UintPtr(self.next_transient);
        self.next_transient += 1;
        self.by_value.insert((value, bound), ptr);
        self.uints.insert(
            ptr,
            Uint {
                value,
                ptr,
                bound_ptr: bound,
            },
        );
        self.demand.require(bound);
        ptr
    }

    /// The interned uint behind a handle. Handles are minted at
    /// interning, so the lookup is infallible (a handle from a *different*
    /// store panics).
    pub fn uint(&self, ptr: UintPtr) -> &Uint {
        self.uints
            .get(&ptr)
            .unwrap_or_else(|| panic!("ptr {} is not an interned uint", ptr.0))
    }
}

impl Default for UintStoreRequires {
    fn default() -> Self {
        Self::new()
    }
}

/// The trace's block list: the interned uints (in ptr order) padded to a
/// power-of-two count (min 1, so the trace height is a valid power of
/// two) with self-referential zero blocks at fresh tail ptrs. A padding
/// block is its own modulus (`v = comp = bound = 0`) and its own single
/// `UintVal` consumer, so it nets out on the bus; its self bound-ref is
/// laid by [`generate_trace`] directly rather than through the demand
/// ledger.
fn padded_blocks(requires: &UintStoreRequires) -> Vec<Uint> {
    let n_real = requires.uints.len();
    let n_padded = n_real.next_power_of_two().max(1);
    let next_ptr = requires
        .uints
        .last_key_value()
        .map_or(1, |(&ptr, _)| ptr.0 + 1);
    let pad = (0..n_padded - n_real).map(|i| {
        let ptr = UintPtr(next_ptr + i as u32);
        Uint {
            value: U256::ZERO,
            ptr,
            bound_ptr: ptr,
        }
    });
    requires.uints.values().copied().chain(pad).collect()
}

/// The block's resolved modulus bound. Padding blocks (`is_pad`) are
/// their own zero modulus and live outside the store map.
fn bound_value(requires: &UintStoreRequires, u: &Uint, is_pad: bool) -> U256 {
    if is_pad {
        return U256::ZERO;
    }
    requires.uint(u.bound_ptr).value
}

/// Build the UintStore main trace from the [`UintStoreRequires`]
/// accumulator — the sorted uints (padded per [`padded_blocks`]) plus the
/// `UintVal` demand ledger (each uint's `uintval_mult` = its total
/// consumers). One uint = one [`PERIOD`]-row block; `ptr`/`bound_ptr` are
/// repeated on every row of the block (cycle-constant), while the
/// per-block scalars live in their host rows' cells: the provide mults
/// on the hub, the carries on the bound rows, the gap on the term row.
///
/// The same pass drives the `Range16` demand the chiplet consumes into
/// `bpl` — every `v` / `comp` 16-bit limb plus the per-block ptr gap,
/// padding blocks included — mirroring the consumes [`UintStoreAir`]
/// emits on the `v` / `comp` / term rows.
pub fn generate_trace(
    requires: UintStoreRequires,
    bpl: &mut BytePairLutRequires,
) -> RowMajorMatrix<Felt> {
    let requires = &requires;
    let n_real = requires.uints.len();
    let blocks = padded_blocks(requires);
    let demand = &requires.demand;

    let mut vals = Vec::with_capacity(blocks.len() * PERIOD * NUM_MAIN_COLS);
    for (i, u) in blocks.iter().enumerate() {
        let bound_value = bound_value(requires, u, i >= n_real);
        let comp = bound_value
            .checked_sub(u.value)
            .expect("stored value exceeds its bound");
        let v16 = to_limbs16(u.value);
        let comp16 = to_limbs16(comp);
        let bound32 = to_limbs32(bound_value);
        let c = carries(&to_limbs32(u.value), &to_limbs32(comp));
        // A padding block's single self bound-ref consumer lives outside
        // the demand ledger.
        let mult = demand.count(u.ptr) + u32::from(i >= n_real);
        let limbs_mult = requires.limbs_demand.count(u.ptr);
        // ptr gap to the next block (term-row cell); the last block's gap
        // is free (when_transition drops it), so 0.
        let gap = match blocks.get(i + 1) {
            Some(nxt) => nxt.ptr.0 - u.ptr.0 - 1,
            None => 0,
        };
        for l in v16.into_iter().chain(comp16) {
            bpl.require_range16(l);
        }
        bpl.require_range16(gap as u16);

        let mut hub = [Felt::ZERO; NUM_LIMBS];
        hub[HUB_CELL_UINTVAL_MULT] = Felt::from(mult);
        hub[HUB_CELL_UINTLIMBS_MULT] = Felt::from(limbs_mult);
        let mut term = [Felt::ZERO; NUM_LIMBS];
        term[TERM_CELL_GAP] = Felt::from(gap);

        let rows: [[Felt; NUM_LIMBS]; PERIOD] = [
            array::from_fn(|i| Felt::from(v16[i])), // v_lo
            hub,
            array::from_fn(|i| Felt::from(v16[8 + i])), // v_hi
            array::from_fn(|i| Felt::from(comp16[i])),  // comp_lo
            array::from_fn(|i| Felt::from(comp16[8 + i])), // comp_hi
            // bound lo/hi: the 4×32 half in cells 0–3, carries in 4–7/4–6.
            array::from_fn(|i| {
                if i < 4 {
                    Felt::from(bound32[i])
                } else {
                    Felt::from(c[i - 4])
                }
            }),
            array::from_fn(|i| {
                if i < 4 {
                    Felt::from(bound32[4 + i])
                } else if i < 7 {
                    Felt::from(c[i])
                } else {
                    Felt::ZERO
                }
            }),
            term,
        ];
        for row in rows {
            vals.extend(row);
            vals.push(Felt::from(u.ptr.0));
            vals.push(Felt::from(u.bound_ptr.0));
        }
    }

    RowMajorMatrix::new(vals, NUM_MAIN_COLS)
}

/// Witness-bearing companion to [`UintStoreAir`].
pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    // Col 0: LogUp running sum over the UintVal provide / consume.
    let (logup, sigma) = build_logup_aux_trace(&UintStoreAir, main, challenges);
    let n = main.height();
    let beta = challenges[1];

    // β^0..β^7.
    let mut bp = [QuadFelt::ZERO; 8];
    bp[0] = QuadFelt::ONE;
    for i in 1..8 {
        bp[i] = bp[i - 1] * beta;
    }
    let two16 = Felt::from(1u32 << 16);
    let t32 = QuadFelt::from(Felt::new(1u64 << 32).expect("2^32 < Goldilocks p"));

    // Col 1: the SZ register. id[0] = 0; id[r+1] = id[r] + contrib(row r),
    // contrib matching UintStoreAir's role-gated expression exactly.
    let logup_width = logup.width();
    let mut data = Vec::with_capacity(AUX_WIDTH * n);
    let mut id = QuadFelt::ZERO;
    for r in 0..n {
        data.extend((0..logup_width).map(|c| logup.values[r * logup_width + c]));
        data.push(id);

        let limb = |c: usize| -> Felt { main.values[r * NUM_MAIN_COLS + c] };
        let contrib: QuadFelt = match r % PERIOD {
            0 | 3 => (0..4).fold(QuadFelt::ZERO, |s, k| {
                let rk = limb(2 * k) + two16 * limb(2 * k + 1);
                s + bp[k] * QuadFelt::from(rk)
            }),
            2 | 4 => (0..4).fold(QuadFelt::ZERO, |s, k| {
                let rk = limb(2 * k) + two16 * limb(2 * k + 1);
                s + bp[4 + k] * QuadFelt::from(rk)
            }),
            // Bound rows: subtract the direct 4×32 half, add the
            // hosted carries' (β^{j+1} − t·β^j) terms.
            5 => (0..4).fold(QuadFelt::ZERO, |s, j| {
                let w = bp[j + 1] - bp[j] * t32;
                s + w * QuadFelt::from(limb(CARRY_CELLS_BEGIN + j))
                    - bp[j] * QuadFelt::from(limb(j))
            }),
            6 => (0..4).fold(QuadFelt::ZERO, |s, k| {
                let carry = if k < 3 {
                    let j = 4 + k;
                    (bp[j + 1] - bp[j] * t32) * QuadFelt::from(limb(CARRY_CELLS_BEGIN + k))
                } else {
                    QuadFelt::ZERO
                };
                s + carry - bp[4 + k] * QuadFelt::from(limb(k))
            }),
            _ => QuadFelt::ZERO,
        };
        id += contrib;
    }

    (RowMajorMatrix::new(data, AUX_WIDTH), sigma)
}
