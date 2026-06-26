//! Newtype wrappers for the two semantically distinct `[Felt; 4]`
//! shapes the Poseidon2 chiplet hands around.
//!
//! Without these, [`P2Digest`] (output of the permutation) and
//! [`P2Cap`] (capacity prefix carrying a domain separator such as a
//! VM deferred tag or a local `(NodeTag, …, CURRENT_VERSION)` tuple)
//! collapse to the same primitive type — the compiler can't catch a
//! digest accidentally fed in as a cap (or vice versa).

use miden_core::{
    Felt,
    deferred::{Digest, Tag},
};
use miden_precompiles::Keccak256Precompile;

use crate::transcript::nodes::{CURRENT_VERSION, EcOpId, NodeTag, UintOpId};

/// Output digest of a Poseidon2 absorption — `state[0..4]` after the
/// last block's permutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct P2Digest(pub [Felt; 4]);

impl P2Digest {
    pub fn as_array(&self) -> [Felt; 4] {
        self.0
    }
}

impl From<Digest> for P2Digest {
    fn from(digest: Digest) -> Self {
        Self(digest.into_elements())
    }
}

/// Capacity prefix for a Poseidon2 absorption. VM deferred caps are raw
/// VM tag words; prover-local field/uint/EC caps use `(tag, param_a,
/// param_b, version)`. Constructors for off-pattern caps stay open via
/// the tuple-struct constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct P2Cap(pub [Felt; 4]);

impl P2Cap {
    pub fn as_array(&self) -> [Felt; 4] {
        self.0
    }

    /// VM `Tag::CHUNKS` (`[2, 0, 0, 0]`) — generic chunk-content
    /// capacity used by chunk chains and one-chunk Keccak digest commitments.
    pub fn chunk() -> Self {
        Self(Tag::CHUNKS.as_word())
    }

    /// VM `Tag::AND` (`[1, 0, 0, 0]`) — capacity for the transcript eval
    /// chip's AND-node hash combining two proven-true child hashes.
    pub fn and() -> Self {
        Self(Tag::AND.as_word())
    }

    /// VM Keccak-256 assertion tag (`[Keccak256Precompile::id(), 0,
    /// len_bytes, 0]`) — capacity for the Keccak-node transcript hash.
    pub fn keccak256_assertion(len_bytes: Felt) -> Self {
        Self([
            Keccak256Precompile::id(),
            Felt::from_u32(Keccak256Precompile::ASSERT_TAG_ID),
            len_bytes,
            Felt::ZERO,
        ])
    }

    /// `(NodeTag::UintLeaf, bound_ptr, pin_ptr, CURRENT_VERSION)` —
    /// capacity for hashing a stored uint's value into a transcript-DAG
    /// leaf; `param_a` commits the modulus pointer and `param_b` the pin
    /// address. `pin_ptr = 0` marks a transient (nondeterministic store
    /// address, content-addressed hash); nonzero anchors the value to that
    /// exact store address — `store[pin_ptr] = value`, not merely "the
    /// value exists somewhere under the bound".
    pub fn uint_leaf(bound_ptr: u32, pin_ptr: u32) -> Self {
        Self([
            Felt::from(NodeTag::UintLeaf as u8),
            Felt::from(bound_ptr),
            Felt::from(pin_ptr),
            Felt::from(CURRENT_VERSION),
        ])
    }

    /// `(NodeTag::UintOp, op_id, 0, CURRENT_VERSION)` — capacity for a
    /// uint arithmetic / `Is` node over two child hashes. Only the op
    /// discriminant is committed: operand / result ptrs are
    /// nondeterministic bus glue, and the modulus is threaded through the
    /// lookups (anchored by the children's leaf caps), not the cap.
    pub fn uint_op(op: UintOpId) -> Self {
        Self([
            Felt::from(NodeTag::UintOp as u8),
            Felt::from(op as u8),
            Felt::ZERO,
            Felt::from(CURRENT_VERSION),
        ])
    }

    /// `(NodeTag::EcCreate, a_ptr, b_ptr, CURRENT_VERSION)` — capacity
    /// for a curve-point construction node over two uint-coordinate
    /// children `(x, y)`. `param_a` / `param_b` commit the pinned curve
    /// coefficients' store addresses — the **only** place `a` / `b` enter
    /// the DAG; the modulus `p` threads in via the coords' shared bound.
    pub fn ec_create(a_ptr: u32, b_ptr: u32) -> Self {
        Self([
            Felt::from(NodeTag::EcCreate as u8),
            Felt::from(a_ptr),
            Felt::from(b_ptr),
            Felt::from(CURRENT_VERSION),
        ])
    }

    /// `(NodeTag::EcBinOp, op_id, 0, CURRENT_VERSION)` — capacity for a
    /// group add / sub / eq node over two child point hashes. Like
    /// [`uint_op`](Self::uint_op), only the op discriminant is committed;
    /// the curve threads transitively from the operands' `EcCreate`
    /// caps, never restated here.
    pub fn ec_op(op: EcOpId) -> Self {
        Self([
            Felt::from(NodeTag::EcBinOp as u8),
            Felt::from(op as u8),
            Felt::ZERO,
            Felt::from(CURRENT_VERSION),
        ])
    }

    /// `(NodeTag::EcMsm, group_ptr, 0, CURRENT_VERSION)` — the **IV** of
    /// an MSM-claim chaining sponge: the capacity fed to the *first*
    /// absorb (`stateₒ`); subsequent absorbs thread `capᵢ = stateᵢ₋₁` (the
    /// prior digest). The distinct `EcMsm` tag domain-separates MSM
    /// hashes from every one-shot cap, and `param_a = group_ptr` binds the
    /// claim to its group. See `docs/chiplets/ec-msm.md §6.2`.
    pub fn ec_msm_iv(group_ptr: u32) -> Self {
        Self([
            Felt::from(NodeTag::EcMsm as u8),
            Felt::from(group_ptr),
            Felt::ZERO,
            Felt::from(CURRENT_VERSION),
        ])
    }
}
