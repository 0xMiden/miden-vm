//! Newtype wrappers for the two semantically distinct `[Felt; 4]`
//! shapes the Poseidon2 chiplet hands around.
//!
//! Without these, [`P2Digest`] (output of the permutation) and
//! [`P2Cap`] (capacity prefix carrying a domain separator such as a
//! VM deferred tag word or a prover-local bootstrap pin tuple) collapse
//! to the same primitive type — the compiler can't catch a
//! digest accidentally fed in as a cap (or vice versa).

use miden_core::{
    Felt,
    deferred::{Digest, Tag},
};
use miden_precompiles::{CurvePrecompile, Keccak256Precompile, UintDomain, UintPrecompile};

use crate::transcript::nodes::{EcOpId, UINT_PIN_CLAIM_TAG, UintOpId};

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
/// VM tag words; prover-local bootstrap-pin caps keep their local tuple.
/// Constructors for off-pattern caps stay open via the tuple-struct
/// constructor.
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
    pub fn keccak256_assertion(len_bytes: u32) -> Self {
        Self(Keccak256Precompile::assert_tag(len_bytes).as_word())
    }

    /// VM uint `VALUE` capacity: `[UintPrecompile::id(), VALUE_OP_ID, bound_ptr, 0]`.
    pub fn uint_value(bound_ptr: u32) -> Self {
        let domain = UintDomain::from_bound_ptr(bound_ptr).expect("known uint bound pointer");
        Self(UintPrecompile::value_tag(domain).as_word())
    }

    /// Bootstrap uint pin-claim capacity: `[UINT_PIN_CLAIM_TAG, bound_ptr, pin_ptr, 0]`.
    pub fn uint_pin_claim(bound_ptr: u32, pin_ptr: u32) -> Self {
        Self([
            Felt::from(UINT_PIN_CLAIM_TAG),
            Felt::from(bound_ptr),
            Felt::from(pin_ptr),
            Felt::ZERO,
        ])
    }

    /// VM uint operation capacity: `[UintPrecompile::id(), op_id, 0, 0]`.
    pub fn uint_op(op: UintOpId) -> Self {
        let op_id = match op {
            UintOpId::Add => UintPrecompile::ADD_OP_ID,
            UintOpId::Sub => UintPrecompile::SUB_OP_ID,
            UintOpId::Mul => UintPrecompile::MUL_OP_ID,
            UintOpId::Is => UintPrecompile::EQ_OP_ID,
        };
        Self(UintPrecompile::op_tag(op_id).as_word())
    }

    /// VM curve `VALUE` capacity: `[CurvePrecompile::id(), VALUE_OP_ID, a_ptr, b_ptr]`.
    /// The cap carries the curve coefficient pointers; the modulus `p`
    /// threads in via the coordinates' shared bound.
    pub fn ec_create(a_ptr: u32, b_ptr: u32) -> Self {
        Self([
            CurvePrecompile::id(),
            Felt::from_u32(CurvePrecompile::VALUE_OP_ID as u32),
            Felt::from(a_ptr),
            Felt::from(b_ptr),
        ])
    }

    /// VM curve operation capacity: `[CurvePrecompile::id(), op_id, 0, 0]`
    /// for group add / sub / eq nodes over two child point hashes. The curve
    /// threads from the operands' VALUE caps.
    pub fn ec_op(op: EcOpId) -> Self {
        let op_id = match op {
            EcOpId::Add => CurvePrecompile::ADD_OP_ID,
            EcOpId::Sub => CurvePrecompile::SUB_OP_ID,
            EcOpId::Is => CurvePrecompile::EQ_OP_ID,
        };
        Self([CurvePrecompile::id(), Felt::from_u32(op_id as u32), Felt::ZERO, Felt::ZERO])
    }

    /// VM curve MSM capacity: `[CurvePrecompile::id(), MSM_OP_ID, group_ptr, 0]` —
    /// the **IV** of an MSM-claim chaining sponge, fed to the *first* absorb
    /// (`stateₒ`). Subsequent absorbs thread `capᵢ = stateᵢ₋₁` (the prior
    /// digest). The group pointer binds the claim to its group. See
    /// `docs/chiplets/ec-msm.md §6.2`.
    pub fn ec_msm_iv(group_ptr: u32) -> Self {
        Self([
            CurvePrecompile::id(),
            Felt::from_u32(CurvePrecompile::MSM_OP_ID as u32),
            Felt::from(group_ptr),
            Felt::ZERO,
        ])
    }
}
