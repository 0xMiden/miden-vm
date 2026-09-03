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
//! | 0     | `BytePairLut`   | `byte_pair_lut::BytePairLutAir` | `(a, b, x)`, where `x = a xor b`; AND and ANDNOT map to this canonical relation |
//! | 1     | `Range16`       | `byte_pair_lut::BytePairLutAir` | `(w,)`, where `w ∈ [0, 2^16)`                               |
//! | 2,3   | reserved        | —                                |                                                             |
//! | 4     | `Memory64`      | external (sponge / miniVM)      | `(addr, lo, hi)`, 64-bit cell — multiset, see `memory64`    |
//! | 5     | `KeccakSponge`  | external (transcript chiplet)   | `(sponge_seq_id, chunk_ptr, len_bytes)`, per-invocation request — see `keccak::sponge` |
//! | 6     | `EidosIn`       | native `EidosCompressionAir` | `(chain_step_id, is_head, domain, message[8], chain_context[4])` — atomic Eidos chaining input |
//! | 7     | `EidosOut`      | native `EidosCompressionAir` | `(chain_step_id, d0, d1, d2, d3)` — terminal Eidos chaining word |
//! | 8     | `Binding`       | transcript eval chips           | `(h0, h1, h2, h3, value_tag, ptr, bound_ptr)` — node hash ↦ typed value (self-referential) |
//! | 9     | `ChunkChain`    | `hash::chunk_node_sponge::ChunkNodeSpongeAir` (chunk band) | `(chunk_seq_id_head, absorption_id_head)` — per-invocation chain head, in chunk's native namespace |
//! | 10    | `UintVal`      | `uint::store_mul::UintStoreMulAir` (store band) | `(ptr, bound_ptr, c0..c7)` — complete 256-bit value as 8×32-bit recombined limbs |
//! | 11    | `UintAdd`      | `uint::add::UintAddAir`       | `(bound_ptr, a_ptr, b_ptr, c_ptr)` — asserts `a + b ≡ c (mod p)` for uints sharing `bound_ptr` |
//! | 12    | `UintMul`      | `uint::mul::UintMulAir`       | `(kappa_a, kappa_c, a_ptr, b_ptr, c_ptr, r_ptr, bound_ptr)` — asserts `κₐ·a·b + κ_c·c ≡ r (mod p)` for uints sharing `bound_ptr` |
//! | 13    | `UintLimbs`    | `uint::store_mul::UintStoreMulAir` (store band) | `(ptr, bound_ptr, l0..l15)` — raw 16×16-bit limb view of the complete 256-bit uint |
//! | 14    | `EcGroup`      | `ec::point_store_groups::EcPointStoreGroupsAir` (group band) | `(group_ptr, a_ptr, b_ptr, bound_ptr, scalar_bound_ptr)` — a short-Weierstrass group binding its curve context (params + base-field modulus + scalar-field modulus, the latter = `bound_ptr` while unconstrained) |
//! | 15    | `EcPoint`      | `ec::point_store_groups::EcPointStoreGroupsAir` (point band) | `(point_ptr, group_ptr, x_ptr, y_ptr, is_pai)` — a stored on-curve point (or the group's ∞ when `is_pai`) |
//! | 16    | `EcGroupAdd`   | `ec::add::EcGroupAddAir`      | `(group_ptr, p_ptr, q_ptr, r_ptr)` — asserts `R = P + Q` in the group |
//! | 17    | `EcOnCurveCert` | `ec::add::EcGroupAddAir`, `ec::msm::EcMsmAir` | `(group_ptr, r_ptr)` — an on-curve membership certificate for a fresh point `r`: provided by its minting op (a group-law add result, an MSM `neg` value `−P`, or an MSM `intro_endo` value `φ(P)`), consumed by `r`'s point-store row in place of the on-curve MAC trio |
//! | 18    | `MsmTerm`      | `ec::msm::EcMsmAir`           | `(expr_ptr, idx, base_ptr, scalar_ptr)` — one term `P × s` of MSM expression `expr_ptr` at position `idx` |
//! | 19    | `MsmExpr`      | `ec::msm::EcMsmAir`           | `(expr_ptr, group_ptr, val_ptr, k)` — MSM expression head: `k` terms summing to the point `val_ptr` (see `chiplets/ec-msm.md`) |
//! | 20    | `MsmClaimTerm` | `ec::msm::EcMsmAir`           | `(expr_ptr, base_ptr, scalar_ptr)` — a **resolve-seam** term of MSM expression `expr_ptr`, *positionless* (unlike `MsmTerm`): the eval `EcMsm` absorb consumes the claim's terms as a **set**, so the DAG absorb order is the caller's, decoupled from the chiplet's storage `idx` (and thus from the addition-chain strategy). Provided per claim-expr term at the **resolve** use count |
//! | 21    | `EidosCv`       | native `EidosCompressionAir` | `(compression_cycle_id, cv0, ..., cv7)` — atomic internal bridge from the first fused row to footer 3 |
//! | 23,25 | `EidosRot12Pos*` | `byte_pair_lut::BytePairLutAir` | `(a, b, z)` — normalized positions 1 and 3 of `rotr32(a xor b, 12)` |
//! | 26,28,29 | `EidosRot7Pos*` | `byte_pair_lut::BytePairLutAir` | `(a, b, z)` — normalized positions 0, 2, and 3 of `rotr32(a xor b, 7)` |
//! | 22,24,27 | reserved | — | These byte positions use the canonical relation at bus 0 |
//! | 30    | `EidosWord`    | native `EidosCompressionAir` | `(message_index, message_word, compression_cycle_id)` — scheduled message-word permutation |
//!
//! ## Adding a new relation
//!
//! 1. Pick the next unused id (one greater than the current maximum).
//! 2. Add a row to the table above.
//! 3. Add a variant to [`BusId`] below.
//! 4. Extend [`NUM_BUS_IDS`] through the new highest assigned ID.
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
    Reserved2 = 2,
    Reserved3 = 3,
    Memory64 = 4,
    KeccakSponge = 5,
    EidosIn = 6,
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
    /// Reserved because rot12 byte position 0 uses canonical XOR.
    ReservedEidosRot12Pos0 = 22,
    EidosRot12Pos1 = 23,
    /// Reserved because rot12 byte position 2 uses canonical XOR.
    ReservedEidosRot12Pos2 = 24,
    EidosRot12Pos3 = 25,
    EidosRot7Pos0 = 26,
    /// Reserved because rot7 byte position 1 uses canonical XOR.
    ReservedEidosRot7Pos1 = 27,
    EidosRot7Pos2 = 28,
    EidosRot7Pos3 = 29,
    EidosWord = 30,
}

/// Size of the indexed bus-prefix table. [`Challenges::new`](miden_air::lookup::Challenges::new)
/// precomputes every prefix in `0..=30`, including the reserved entries.
pub const NUM_BUS_IDS: usize = 31;
const _: () = assert!(NUM_BUS_IDS == BusId::EidosWord as usize + 1);

// The numeric IDs are transcript domain separators. Pin every assigned and reserved slot so a
// reorder cannot silently change relation encodings while leaving `NUM_BUS_IDS` unchanged.
const _: () = assert!(BusId::BytePairLut as usize == 0);
const _: () = assert!(BusId::Range16 as usize == 1);
const _: () = assert!(BusId::Reserved2 as usize == 2);
const _: () = assert!(BusId::Reserved3 as usize == 3);
const _: () = assert!(BusId::Memory64 as usize == 4);
const _: () = assert!(BusId::KeccakSponge as usize == 5);
const _: () = assert!(BusId::EidosIn as usize == 6);
const _: () = assert!(BusId::EidosOut as usize == 7);
const _: () = assert!(BusId::Binding as usize == 8);
const _: () = assert!(BusId::ChunkChain as usize == 9);
const _: () = assert!(BusId::UintVal as usize == 10);
const _: () = assert!(BusId::UintAdd as usize == 11);
const _: () = assert!(BusId::UintMul as usize == 12);
const _: () = assert!(BusId::UintLimbs as usize == 13);
const _: () = assert!(BusId::EcGroup as usize == 14);
const _: () = assert!(BusId::EcPoint as usize == 15);
const _: () = assert!(BusId::EcGroupAdd as usize == 16);
const _: () = assert!(BusId::EcOnCurveCert as usize == 17);
const _: () = assert!(BusId::MsmTerm as usize == 18);
const _: () = assert!(BusId::MsmExpr as usize == 19);
const _: () = assert!(BusId::MsmClaimTerm as usize == 20);
const _: () = assert!(BusId::EidosCv as usize == 21);
const _: () = assert!(BusId::ReservedEidosRot12Pos0 as usize == 22);
const _: () = assert!(BusId::EidosRot12Pos1 as usize == 23);
const _: () = assert!(BusId::ReservedEidosRot12Pos2 as usize == 24);
const _: () = assert!(BusId::EidosRot12Pos3 as usize == 25);
const _: () = assert!(BusId::EidosRot7Pos0 as usize == 26);
const _: () = assert!(BusId::ReservedEidosRot7Pos1 as usize == 27);
const _: () = assert!(BusId::EidosRot7Pos2 as usize == 28);
const _: () = assert!(BusId::EidosRot7Pos3 as usize == 29);
const _: () = assert!(BusId::EidosWord as usize == 30);

/// Maximum payload width (excluding the bus prefix) any message in this
/// VM emits. Sets the size of the precomputed `β^0..β^{W-1}` table held
/// by [`Challenges`](miden_air::lookup::Challenges).
///
/// The widest payload is `UintLimbs` at 18 elements: `ptr`, `bound_ptr`,
/// and a complete 16×16-bit value. Each operand occupies one row and sends
/// its whole value in one message. Width affects only the precomputed
/// powers of β; encoding stays linear.
pub const MAX_MESSAGE_WIDTH: usize = 18;

/// Net multiplicity a LogUp bus tuple is provided / consumed with — the
/// count a chiplet stamps into its trace cells and the demand ledgers
/// tally per pointer. The alias names the role, so a demand ledger reads
/// `Ptr → ProvideMult` rather than `u32 → u32`.
pub type ProvideMult = u32;
