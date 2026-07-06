//! Bus-id registry.
//!
//! Every LogUp relation in the Precompile VM is identified by a globally
//! unique numeric **bus id**. The id selects a precomputed prefix
//! `bus_prefix[id] = α + (id + 1) · β^W` (see [`logup`](crate::logup) and
//! [`Challenges`](miden_air::lookup::Challenges)) which serves as the encoded tuple's
//! additive base. Distinct bus ids therefore live on disjoint
//! `β^W`-spaced offsets, providing domain separation between relations
//! without consuming a payload slot.
//!
//! Bus-id values must never collide across relations; this module is the
//! single source of truth.
//!
//! ## Registry
//!
//! | BusId | Relation        | Provided by                     | Tuple shape                                                 |
//! |-------|-----------------|---------------------------------|-------------------------------------------------------------|
//! | 0     | `BytePairLut`   | `byte_pair_lut::BytePairLutAir` | `(op, a, b, c)`, `c = op(a, b)`                             |
//! | 1     | `Range16`       | `byte_pair_lut::BytePairLutAir` | `(w,)`, where `w ∈ [0, 2^16)`                               |
//! | 2     | `Logic64`       | `bitwise64::Bitwise64Air`       | `(op, a_lo, a_hi, b_lo, b_hi, c_lo, c_hi)`, 32-bit halves   |
//! | 3     | `Rol64`         | `bitwise64::Bitwise64Air`       | `(a_lo, a_hi, b_lo, b_hi, k)`, `b = rol_64(a, log2(k))`     |
//! | 4     | `Memory64`      | external (sponge / miniVM)      | `(addr, lo, hi)`, 64-bit cell — multiset, see `memory64`    |
//! | 5     | `KeccakSponge`  | external (transcript chiplet)   | `(sponge_seq_id, chunk_ptr, len_bytes)`, per-invocation request — see `keccak::sponge` |
//! | 6     | `Poseidon2In`   | `poseidon2::Poseidon2Air`       | `(perm_seq_id, tag, c0, c1, c2, c3)`, `tag ∈ {0, 1, 2}` for rate0/rate1/cap |
//! | 7     | `Poseidon2Out`  | `poseidon2::Poseidon2Air`       | `(perm_seq_id, d0, d1, d2, d3)` — digest = first 4 lanes of post-perm state |
//! | 8     | `Binding`       | transcript eval chips           | `(h0, h1, h2, h3, value_tag, ptr)` — node hash ↦ typed value (self-referential) |
//! | 9     | `ChunkChain`    | `chunk::ChunkAir`               | `(chunk_seq_id_head, perm_seq_id_head)` — per-invocation chain head, in chunk's native namespace |
//! | 10    | `UintVal`      | `uint::UintStoreAir`          | `(ptr, bound_ptr, offset, c0..c3)` — 256-bit uint half: 4×32-bit recombined view at offset ∈ {0, 1} |
//! | 11    | `UintAdd`      | `uint::add::UintAddAir`       | `(bound_ptr, a_ptr, b_ptr, c_ptr)` — asserts `a + b ≡ c (mod p)` for uints sharing `bound_ptr` |
//! | 12    | `UintMul`      | `uint::mul::UintMulAir`       | `(kappa_a, kappa_c, a_ptr, b_ptr, c_ptr, r_ptr, bound_ptr)` — asserts `κₐ·a·b + κ_c·c ≡ r (mod p)` for uints sharing `bound_ptr` |
//! | 13    | `UintLimbs`    | `uint::UintStoreAir`          | `(ptr, bound_ptr, offset, l0..l7)` — 256-bit uint half: raw 8×16-bit limb view at offset ∈ {0, 1} |
//! | 14    | `EcGroup`      | `ec::groups::EcGroupsAir`     | `(group_ptr, a_ptr, b_ptr, bound_ptr, scalar_bound_ptr)` — a short-Weierstrass group binding its curve context (params + base-field modulus + scalar-field modulus, the latter = `bound_ptr` while unconstrained) |
//! | 15    | `EcPoint`      | `ec::EcPointStoreAir`         | `(point_ptr, group_ptr, x_ptr, y_ptr, is_pai)` — a stored on-curve point (or the group's ∞ when `is_pai`) |
//! | 16    | `EcGroupAdd`   | `ec::add::EcGroupAddAir`      | `(group_ptr, p_ptr, q_ptr, r_ptr)` — asserts `R = P + Q` in the group |
//! | 17    | `EcOnCurveCert` | `ec::add::EcGroupAddAir`, `ec::msm::EcMsmAir` | `(group_ptr, r_ptr)` — an on-curve membership certificate for a fresh point `r`: provided by its minting op (a group-law add result, or an MSM `neg`'s value `−P`), consumed by `r`'s point-store row in place of the on-curve MAC trio |
//! | 18    | `MsmTerm`      | `ec::msm::EcMsmAir`           | `(expr_ptr, idx, base_ptr, scalar_ptr)` — one term `P × s` of MSM expression `expr_ptr` at position `idx` |
//! | 19    | `MsmExpr`      | `ec::msm::EcMsmAir`           | `(expr_ptr, group_ptr, val_ptr, k)` — MSM expression head: `k` terms summing to the point `val_ptr` (see `chiplets/ec-msm.md`) |
//! | 20    | `MsmClaimTerm` | `ec::msm::EcMsmAir`           | `(expr_ptr, base_ptr, scalar_ptr)` — a **resolve-seam** term of MSM expression `expr_ptr`, *positionless* (unlike `MsmTerm`): the eval `EcMsm` absorb consumes the claim's terms as a **set**, so the DAG absorb order is the caller's, decoupled from the chiplet's storage `idx` (and thus from the addition-chain strategy). Provided per claim-expr term at the **resolve** use count |
//!
//! ## Adding a new relation
//!
//! 1. Pick the next unused id (one greater than the current maximum).
//! 2. Add a row to the table above.
//! 3. Add a variant to [`BusId`] below.
//! 4. Bump [`NUM_BUS_IDS`] to match the new variant count.
//! 5. Reference the variant from the relation type's `BUS` associated const.

/// Domain-separated bus identifier.
///
/// `#[repr(usize)]` lets each variant be cast directly to the `usize`
/// argument [`Challenges::encode`](miden_air::lookup::Challenges::encode) expects.
#[repr(usize)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum BusId {
    BytePairLut = 0,
    Range16 = 1,
    Logic64 = 2,
    Rol64 = 3,
    Memory64 = 4,
    KeccakSponge = 5,
    Poseidon2In = 6,
    Poseidon2Out = 7,
    Binding = 8,
    ChunkChain = 9,
    UintVal = 10,
    UintAdd = 11,
    UintMul = 12,
    UintLimbs = 13,
    EcGroup = 14,
    EcPoint = 15,
    EcGroupAdd = 16,
    EcOnCurveCert = 17,
    MsmTerm = 18,
    MsmExpr = 19,
    MsmClaimTerm = 20,
}

/// Number of distinct buses currently registered. Sized so that
/// [`Challenges::new`](miden_air::lookup::Challenges::new) precomputes
/// exactly one prefix per [`BusId`] variant.
pub const NUM_BUS_IDS: usize = 21;

/// Maximum payload width (excluding the bus prefix) any message in this
/// VM emits. Sets the size of the precomputed `β^0..β^{W-1}` table held
/// by [`Challenges`](miden_air::lookup::Challenges).
///
/// The widest payload is `UintLimbs` at 11 elements (`ptr`, `bound_ptr`,
/// `offset`, plus a full 8×16-bit half) — the raw limb view the mul
/// chiplet convolves over. Width costs only precomputed powers of β;
/// encoding stays linear.
pub const MAX_MESSAGE_WIDTH: usize = 11;

/// Net multiplicity a LogUp bus tuple is provided / consumed with — the
/// count a chiplet stamps into its trace cells and the demand ledgers
/// tally per pointer. A plain `u32` (the dedup pass dropped the old
/// Range16 ceiling on multiplicities); the alias names the role, so a
/// demand ledger reads `Ptr → ProvideMult` rather than `u32 → u32`.
pub type ProvideMult = u32;
