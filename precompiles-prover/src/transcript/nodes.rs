//! Transcript node-tag registry.
//!
//! The transcript analog of [`relations`](crate::relations): a single
//! source of truth for the transcript DAG's `tag_id` values. Every
//! transcript node commits a 12-felt preimage whose capacity slot carries
//! `(tag_id, param_a, param_b, reserved)`; producers of those nodes
//! (the chunk chiplet today; uint / group / Keccak-eval chiplets
//! soon) and the eval chip all read their tags from here.
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
//! | 2      | `UintLeaf`         | reserved                                   |
//! | 3      | `UintPinClaim`     | bootstrap uint pin claim                   |
//! | 4      | `UintOp`           | reserved                                   |
//! | 5      | `EcCreate`         | reserved; curve VALUE now uses VM tag      |
//! | 6      | `EcBinOp`          | reserved; curve ops now use VM tags        |
//! | 7      | `Keccak`           | `keccak(chunks) == digest` relation        |
//! | 8      | `EcMsm`            | reserved; curve MSM now uses VM tag        |

/// Capacity tag for bootstrap uint pin claims.
///
/// Pin claims commit `store[pin_ptr] = value` as initial-root inputs.
pub const UINT_PIN_CLAIM_TAG: u8 = 3;

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
    /// Reserved local tag id for the multi-scalar-multiplication claim shape.
    /// Current curve MSM transcript caps use the VM curve MSM tag
    /// `[CurvePrecompile::id(), MSM_OP_ID, group_ptr, 0]`; the eval chip still
    /// lays MSM as a capacity-threaded variable-length run where
    /// `capᵢ = stateᵢ₋₁`. The node *is* its value point (binds `Group`); see
    /// `docs/chiplets/ec-msm.md §6.2`.
    EcMsm = 8,
}

/// Operation discriminant for VM uint op rows.
///
/// The cap is `[UintPrecompile::id(), op_id, 0, 0]`; operand/result pointers and
/// `bound_ptr` are carried by `Binding` and relation witnesses.
///
/// | op | children (lhs, rhs) | relation consumed |
/// |---|---|---|
/// | `Add` | a, b | `UintAdd(bp, a, b, r)` — `r = a + b mod p` |
/// | `Sub` | a, b | `UintAdd(bp, b, r, a)` — `r = a − b mod p` |
/// | `Mul` | a, b | `UintMul(1, 0, a, b, bp, r, bp)` — `r = a·b mod p` |
/// | `Is` | a, b | none — `a ≡ b` asserted as binding-ptr equality |
///
/// `Add`/`Sub`/`Mul` bind `(h, Uint, r_ptr, bound_ptr)`; `Is` binds
/// `(h, True)` — the predicate that folds uint values into the spine.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum UintOpId {
    Add = 1,
    Sub = 2,
    Mul = 3,
    Is = 4,
}

/// Operation discriminant of a curve binary-op node.
///
/// The VM cap is `[CurvePrecompile::id(), op_id, 0, 0]`. The preimage rate is
/// `lhs_hash ‖ rhs_hash` over two `Group` children; the result point rides
/// the node's `Binding` as a nondeterministic ptr. The curve threads from
/// the operands' curve VALUE caps.
///
/// | op | children (lhs, rhs) | relation consumed |
/// |---|---|---|
/// | `Add` | P, Q | `EcGroupAdd(g, p, q, r)` — `R = P + Q` |
/// | `Sub` | P, Q | `EcGroupAdd(g, r, q, p)` — `R = P − Q` |
/// | `Is` | P, Q | none — `P ≡ Q` asserted as binding-ptr equality |
///
/// `Add`/`Sub` bind `(h, Group, r_ptr)`; `Is` binds `(h, True)` —
/// the predicate folding a curve point into the transcript spine.
/// `Sub` (2) consumes the *rearranged* relation `EcGroupAdd(g, r, q, p)`
/// — `R + Q = P` with the bound `R` the subtraction result — exactly as
/// [`UintOpId::Sub`] rearranges its `UintAdd`. The witness `R = P − Q` is
/// interned, then the add relation re-derives and certifies `R + Q = P`
/// (deduping the result onto `P`).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum EcOpId {
    Add = 1,
    Sub = 2,
    Is = 3,
}
