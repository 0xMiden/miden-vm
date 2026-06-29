//! Transcript node-tag registry & protocol version.
//!
//! The transcript analog of [`relations`](crate::relations): a single
//! source of truth for the transcript DAG's `tag_id` values and the
//! protocol `version`. Every transcript node commits a 12-felt
//! preimage whose capacity slot carries
//! `(tag_id, param_a, param_b, version)`; producers of those nodes
//! (the chunk chiplet today; uint / group / Keccak-eval chiplets
//! soon) and the eval chip all read their tags and version from here.
//!
//! See `docs/transcript-nodes.md` for the full node-format spec and
//! `docs/transcript-eval.md` for how the tags are dispatched.
//!
//! ## Registry
//!
//! | tag_id | Variant            | Role                                       |
//! |--------|--------------------|--------------------------------------------|
//! | 0      | `Transcript`       | assertion-chain node (AND over children)   |
//! | 1      | `Chunk`            | generic chunk capacity domain separator    |
//! | 2      | `UintLeaf`         | uint leaf (u32-LE in the rate)             |
//! | 3      | unused             | intentionally unassigned                   |
//! | 4      | `UintOp`           | uint add / sub / mul / neg / is ([`UintOpId`]) |
//! | 5      | `EcCreate`      | curve-point construction                   |
//! | 6      | `EcBinOp`       | group add / sub / eq                       |
//! | 7      | `Keccak`           | `keccak(chunks) == digest` relation        |
//! | 8      | `EcMsm`            | multi-scalar-mul claim (absorb-run sponge) |

/// Transcript node type, stamped into the `tag_id` capacity slot of a
/// node's 12-felt hash preimage. `#[repr(u8)]` lets a variant cast
/// directly (`NodeTag::Chunk as u8`) to the felt the slot holds —
/// mirroring [`BusId`](crate::relations::BusId)'s `as usize`.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum NodeTag {
    Transcript = 0,
    Chunk = 1,
    UintLeaf = 2,
    UintOp = 4,
    EcCreate = 5,
    EcBinOp = 6,
    Keccak = 7,
    /// Multi-scalar-multiplication claim `R = Σ sᵢ·Pᵢ`, hashed as a
    /// chaining sponge over the term sequence `(Pᵢ.hash, sᵢ.hash)` — a
    /// **variable-length** run of absorb rows in the eval chip (every
    /// other node is one row). Capacity-threaded by row adjacency
    /// (`capᵢ = stateᵢ₋₁`); the first absorb's cap is the IV
    /// `(EcMsm, group_ptr, 0, version)`, which domain-separates MSM
    /// hashes from every one-shot cap. The node *is* its value point
    /// (binds `Group`); see `docs/chiplets/ec-msm.md §6.2`.
    EcMsm = 8,
}

/// Operation discriminant of a [`NodeTag::UintOp`] node, committed as the
/// cap's `param_a` (`param_b` is pinned 0, reserved for future per-op
/// parameters). The node's preimage rate is `lhs_hash ‖ rhs_hash`; the
/// result rides the node's `Binding` as a nondeterministic ptr — **never
/// the hash**: store addresses are bus-level witness data, observable in
/// a cap only as a uint leaf's `bound_ptr` / pin seam.
///
/// | op | children (lhs, rhs) | relation consumed |
/// |---|---|---|
/// | `Add` | a, b | `UintAdd(bp, a, b, r)` — `r = a + b mod p` |
/// | `Sub` | a, b | `UintAdd(bp, b, r, a)` — `r = a − b mod p` |
/// | `Mul` | a, b | `UintMul(1, 0, a, b, bp, r, bp)` — `r = a·b mod p` |
/// | `Neg` | a, `0⁴` | `UintAdd(bp, a, r, 0)` — `r = −a mod p` (`is_c_zero`) |
/// | `Is` | a, b | none — `a ≡ b` asserted as binding-ptr equality |
///
/// `Add`/`Sub`/`Mul`/`Neg` bind `(h, Uint, r_ptr, bound_ptr)`; `Is` binds
/// `(h, True)` — the predicate that folds uint values into the spine.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum UintOpId {
    Add = 1,
    Sub = 2,
    Mul = 3,
    Neg = 4,
    Is = 5,
}

/// Operation discriminant of a [`NodeTag::EcBinOp`] node, committed as
/// the cap's `param_a` (`param_b` pinned 0). The preimage rate is
/// `lhs_hash ‖ rhs_hash` over two `Group` children; the result point
/// rides the node's `Binding` as a nondeterministic ptr — **never the
/// hash**. The curve is *not* in this cap: it threads transitively from
/// the operands' [`NodeTag::EcCreate`] caps (where `a`/`b` enter the
/// DAG), exactly as the uint modulus threads through [`UintOpId`] ops.
///
/// | op | children (lhs, rhs) | relation consumed |
/// |---|---|---|
/// | `Add` | P, Q | `EcGroupAdd(g, p, q, r)` — `R = P + Q` |
/// | `Sub` | P, Q | `EcGroupAdd(g, r, q, p)` — `R = P − Q` |
/// | `Neg` | P, `0⁴` | `EcGroupAdd(g, p, r, pai)` — `R = −P` (reserved id 3) |
/// | `Is` | P, Q | none — `P ≡ Q` asserted as binding-ptr equality |
///
/// `Add`/`Sub`/`Neg` bind `(h, Group, r_ptr)`; `Is` binds `(h, True)` —
/// the predicate folding a curve point into the transcript spine.
/// `Sub` (2) consumes the *rearranged* relation `EcGroupAdd(g, r, q, p)`
/// — `R + Q = P` with the bound `R` the subtraction result — exactly as
/// [`UintOpId::Sub`] rearranges its `UintAdd`. The witness `R = P − Q` is
/// interned, then the add relation re-derives and certifies `R + Q = P`
/// (deduping the result onto `P`). `Neg` (3) is the cancel-case op
/// `P + (−P) = ∞`. The ids stay fixed so committed hashes are stable.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum EcOpId {
    Add = 1,
    Sub = 2,
    Neg = 3,
    Is = 4,
}

/// Transcript protocol version, bound into every node's hash via the
/// capacity `version` slot. Bumping it invalidates all prior
/// commitments — the upgrade lever. Placeholder `0` until a
/// version-1 cut is appropriate.
pub const CURRENT_VERSION: u8 = 0;
