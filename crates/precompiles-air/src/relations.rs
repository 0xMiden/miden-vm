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
//! | 4     | `Memory64`      | external (sponge / miniVM)      | `(addr, lo, hi)`, 64-bit cell — multiset, see `memory64`    |
//! | 5     | `KeccakSponge`  | external (transcript chiplet)   | `(sponge_seq_id, chunk_ptr, len_bytes)`, per-invocation request — see `keccak::sponge` |
//! | 6     | `EidosBlock` | native `EidosCompressionAir` | `(compression_id, block[8])` — one message block |
//! | 7     | `EidosOut`  | native `EidosCompressionAir` | `(chain_head_id, compression_id, d0, d1, d2, d3)` — terminal Eidos chaining word and physical span |
//! | 8     | `Binding`       | transcript eval chips           | `(h0, h1, h2, h3, value_tag, ptr, bound_ptr)` — node hash ↦ typed value (self-referential) |
//! | 9     | `ChunkChain`    | `hash::chunk_node_sponge::ChunkNodeSpongeAir` (chunk band) | `(chunk_seq_id_head, absorption_id_head)` — per-invocation chain head, in chunk's native namespace |
//! | 10    | `UintVal`      | `uint::store_mul::UintStoreMulAir` (store band) | `(ptr, bound_ptr, c0..c7)` — complete 256-bit value as 8×32-bit recombined limbs |
//! | 11    | `UintAdd`      | `uint::add::UintAddAir`       | `(bound_ptr, a_ptr, b_ptr, c_ptr)` — asserts `a + b ≡ c (mod p)` for uints sharing `bound_ptr` |
//! | 12    | `UintMul`      | `uint::mul::UintMulAir`       | `(kappa_a, kappa_c, a_ptr, b_ptr, c_ptr, r_ptr, bound_ptr)` — asserts `κₐ·a·b + κ_c·c ≡ r (mod p)` for uints sharing `bound_ptr` |
//! | 13    | `UintLimbs`    | `uint::store_mul::UintStoreMulAir` (store band) | `(ptr, bound_ptr, l0..l15)` — raw 16×16-bit limb view of the complete 256-bit uint |
//! | 14    | `EcGroup`      | `ec::point_store_groups::EcPointStoreGroupsAir` (group band) | `(group_ptr, a_ptr, b_ptr, bound_ptr, scalar_bound_ptr)` — a short-Weierstrass group binding its curve context (params + base-field modulus + scalar-field modulus, the latter = `bound_ptr` while unconstrained) |
//! | 15    | `EcPoint`      | `ec::point_store_groups::EcPointStoreGroupsAir` (point band) | `(point_ptr, group_ptr, x_ptr, y_ptr, is_pai)` — a stored on-curve point (or the group's ∞ when `is_pai`) |
//! | 16    | `EcGroupAdd`   | `ec::add::EcGroupAddAir`      | `(group_ptr, p_ptr, q_ptr, r_ptr)` — asserts `R = P + Q` in the group |
//! | 17    | `EcOnCurveCert` | `ec::add::EcGroupAddAir`, `ec::msm::EcMsmAir` | `(group_ptr, r_ptr)` — an on-curve membership certificate for a fresh point `r`: provided by its minting op (a group-law add result, or an MSM `neg`'s value `−P`), consumed by `r`'s point-store row in place of the on-curve MAC trio |
//! | 18    | `MsmTerm`      | `ec::msm::EcMsmAir`           | `(expr_ptr, idx, base_ptr, scalar_ptr)` — one term `P × s` of MSM expression `expr_ptr` at position `idx` |
//! | 19    | `MsmExpr`      | `ec::msm::EcMsmAir`           | `(expr_ptr, group_ptr, val_ptr, k)` — MSM expression head: `k` terms summing to the point `val_ptr` (see `chiplets/ec-msm.md`) |
//! | 20    | `MsmClaimTerm` | `ec::msm::EcMsmAir`           | `(expr_ptr, base_ptr, scalar_ptr)` — a **resolve-seam** term of MSM expression `expr_ptr`, *positionless* (unlike `MsmTerm`): the eval `EcMsm` absorb consumes the claim's terms as a **set**, so the DAG absorb order is the caller's, decoupled from the chiplet's storage `idx` (and thus from the addition-chain strategy). Provided per claim-expr term at the **resolve** use count |
//! | 21    | `EidosCv`      | native `EidosCompressionAir` | `(compression_cycle_id, cv0, ..., cv7)` — atomic internal bridge from the first fused row to footer 3 |
//! | 22    | `EidosInit` | native `EidosCompressionAir` | `(compression_id, cv0, cv1, cv2, cv3)` — initial chaining value at a chain head |
//!
//! ## Adding a new relation
//!
//! 1. Pick the next unused id (one greater than the current maximum).
//! 2. Add a row to the table above.
//! 3. Add a variant to [`BusId`] below.
//! 4. Set [`NUM_BUS_IDS`] to one greater than the maximum assigned ID.
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
    Memory64 = 4,
    KeccakSponge = 5,
    EidosBlock = 6,
    EidosOut = 7,
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
    EidosCv = 21,
    EidosInit = 22,
}

/// Number of bus-prefix slots, one greater than the maximum [`BusId`].
///
/// [`Challenges::new`](miden_air::lookup::Challenges::new) precomputes one prefix for each numeric
/// ID in this range. IDs 2 and 3 are intentionally unused.
pub const NUM_BUS_IDS: usize = 23;
const _: () = assert!(NUM_BUS_IDS == BusId::EidosInit as usize + 1);

/// Maximum payload width (excluding the bus prefix) any message in this
/// VM emits. Sets the size of the precomputed `β^0..β^{W-1}` table held
/// by [`Challenges`](miden_air::lookup::Challenges).
///
/// The widest payload is `UintLimbs`: `ptr`, `bound_ptr`, and one complete 16-limb value. The
/// multiplication chiplet consumes this raw limb view. Message width affects only the precomputed
/// powers of β; encoding remains linear.
pub const MAX_MESSAGE_WIDTH: usize = 18;

/// Net multiplicity with which a LogUp tuple is provided or consumed.
///
/// Chiplets store this `u32` count in trace cells, and demand ledgers aggregate it per pointer. The
/// alias names its semantic role so ledgers read `Ptr → ProvideMult`.
pub type ProvideMult = u32;
