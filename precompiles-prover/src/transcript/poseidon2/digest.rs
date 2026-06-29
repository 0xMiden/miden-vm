//! Newtype wrappers for the two semantically distinct `[Felt; 4]`
//! shapes the Poseidon2 chiplet hands around.
//!
//! Without these, [`P2Digest`] (output of the permutation) and
//! [`P2Cap`] (capacity prefix carrying a domain separator such as a
//! VM deferred tag) collapse to the same primitive type - the compiler can't catch a
//! digest accidentally fed in as a cap (or vice versa).

use miden_core::{
    Felt,
    deferred::{Digest, Tag},
};
use miden_precompiles::{CurvePrecompile, Keccak256Precompile, UintDomain, UintPrecompile};

use crate::transcript::nodes::{EcOpId, UintOpId};

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
/// VM tag words. Constructors for off-pattern caps stay open via the
/// tuple-struct constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct P2Cap(pub [Felt; 4]);

impl P2Cap {
    pub fn as_array(&self) -> [Felt; 4] {
        self.0
    }

    /// VM Keccak-256 preimage data tag, carrying the input byte length.
    pub fn keccak256_preimage(len_bytes: Felt) -> Self {
        Self([
            Keccak256Precompile::id(),
            Felt::from_u32(Keccak256Precompile::PREIMAGE_TAG_ID),
            len_bytes,
            Felt::ZERO,
        ])
    }

    /// VM Keccak-256 digest data tag.
    pub fn keccak256_digest() -> Self {
        Self([
            Keccak256Precompile::id(),
            Felt::from_u32(Keccak256Precompile::DIGEST_TAG_ID),
            Felt::ZERO,
            Felt::ZERO,
        ])
    }

    /// VM `Tag::AND` (`[1, 0, 0, 0]`) — capacity for the transcript eval
    /// chip's AND-node hash combining two proven-true child hashes.
    pub fn and() -> Self {
        Self(Tag::AND.as_word())
    }

    /// Canonical uint value tag for a fixed arithmetic domain.
    pub fn uint_value(domain: UintDomain) -> Self {
        Self(UintPrecompile::value_tag(domain).as_word())
    }

    /// Canonical uint operation tag.
    pub fn uint_op(op: UintOpId) -> Self {
        Self(UintPrecompile::op_tag(op.canonical_id()).as_word())
    }

    /// Generic short-Weierstrass point creation tag for the prover EC DAG.
    ///
    /// The product curve precompile commits concrete `CurveId`s; this prover
    /// layer is still generic over pinned curve-parameter handles, so creation
    /// keeps those handles in the cap.
    pub fn ec_create(a_ptr: u32, b_ptr: u32) -> Self {
        Self([
            CurvePrecompile::id(),
            Felt::from_u32(CurvePrecompile::VALUE_OP_ID as u32),
            Felt::from_u32(a_ptr),
            Felt::from_u32(b_ptr),
        ])
    }

    /// Curve operation tag used by prover EC DAG joins.
    pub fn ec_op(op: EcOpId) -> Self {
        let id = match op {
            EcOpId::Add | EcOpId::Sub | EcOpId::Is => op.canonical_id(),
            EcOpId::Neg => 255,
        };
        Self(CurvePrecompile::op_tag(id).as_word())
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
}
