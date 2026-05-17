//! `LegacyPrecompile` — the schema [`App`] that replaces the legacy `PrecompileVerifier`
//! framework. Hosts the four production precompiles (keccak256, sha512, ecdsa_k256_keccak,
//! eddsa_ed25519) as schema discriminants whose `reduce` runs the real cryptographic kernels.
//!
//! Tag layout (per the composite [`super::PrecompileSchema`] convention):
//!
//! ```text
//! [LP_APP_ID, node_disc, imm, ZERO]
//! ```
//!
//! Node shapes per discriminant:
//!
//! - `keccak256_preimage` (chunk-bodied): `imm = n_bytes`; chunks carry the preimage
//!   u32-packed-LE. Reduces to a `keccak256_digest` leaf with the actual hash.
//! - `keccak256_digest` (value, 8 felts): self-evaluating digest leaf.
//! - `keccak256_eq` (binary predicate): two `keccak256_digest` children, succeeds iff equal.
//! - `sha512_preimage` (chunk-bodied): `imm = n_bytes`; chunks carry the preimage. Reduces to
//!   a `sha512_digest` chunk leaf (16 felts = 2 chunks).
//! - `sha512_digest` (`Chunks(2)` self-eval): 16-felt digest leaf.
//! - `sha512_eq` (binary predicate): compares two `sha512_digest` children.
//! - `ecdsa_k256_keccak_verify` (chunk-bodied predicate, 5 chunks = 40 felts): packed
//!   `pk[9] || digest[8] || sig[17] || pad[6]`. Succeeds iff `pk.verify_prehash(digest, sig)`.
//! - `eddsa_ed25519_verify` (chunk-bodied predicate, 5 chunks = 40 felts): packed
//!   `pk[8] || k_digest[16] || sig[16]`. Succeeds iff `pk.verify_with_unchecked_k(k_digest, sig)`.
//!
//! Kernel modules live alongside this file; this file holds the [`App`] glue.

use alloc::vec::Vec;

use miden_crypto::{
    dsa::{
        ecdsa_k256_keccak::{PublicKey as EcdsaPublicKey, Signature as EcdsaSignature},
        eddsa_25519_sha512::{PublicKey as EddsaPublicKey, Signature as EddsaSignature},
    },
    hash::{keccak::Keccak256, sha2::Sha512},
};

use crate::{
    Felt, ZERO,
    deferred::{
        Digest, Node, NodePayload, NodeType, Payload, ReduceCtx, SchemaError, TRUE_TAG, Tag,
        TagInfo, true_node,
    },
    serde::Deserializable,
};

use super::{App, AppTag, app_id_from};

// PUBLIC APP TYPE
// ================================================================================================

/// Zero-sized handle for the `LegacyPrecompile` app. Carries all production precompile
/// discriminants under a single `app_id`.
#[derive(Debug, Default, Clone, Copy)]
pub struct LegacyPrecompile;

impl LegacyPrecompile {
    /// App name — hashed into `app_id`. Don't change without bumping [`Self::VERSION`].
    pub const NAME: &'static str = "legacy_precompile";
    /// App version — bump on incompatible discriminant changes.
    pub const VERSION: u32 = 1;
    /// Discriminant names — hashed into `app_id`; renaming changes the id.
    pub const DISCS: &'static [&'static str] = &[
        "keccak256_preimage",
        "keccak256_digest",
        "keccak256_eq",
        "sha512_preimage",
        "sha512_digest",
        "sha512_eq",
        "ecdsa_k256_keccak_verify",
        "eddsa_ed25519_verify",
    ];

    /// Discriminant indices, matching positions in [`Self::DISCS`].
    pub const D_KECCAK_PREIMAGE: Felt = Felt::new_unchecked(0);
    pub const D_KECCAK_DIGEST: Felt = Felt::new_unchecked(1);
    pub const D_KECCAK_EQ: Felt = Felt::new_unchecked(2);
    pub const D_SHA512_PREIMAGE: Felt = Felt::new_unchecked(3);
    pub const D_SHA512_DIGEST: Felt = Felt::new_unchecked(4);
    pub const D_SHA512_EQ: Felt = Felt::new_unchecked(5);
    pub const D_ECDSA_VERIFY: Felt = Felt::new_unchecked(6);
    pub const D_EDDSA_VERIFY: Felt = Felt::new_unchecked(7);

    /// Bytes packed per 8-felt chunk: each felt carries a u32 (4 bytes) little-endian limb.
    pub const BYTES_PER_CHUNK: u32 = 32;

    /// Derive `app_id`. Pure function over `LegacyPrecompile`'s metadata.
    pub fn app_id() -> Felt {
        app_id_from(Self::NAME, Self::VERSION, &[], Self::DISCS)
    }

    /// Number of 8-felt chunks needed to encode `n_bytes` of u32-packed input.
    pub fn n_chunks(n_bytes: u32) -> u32 {
        n_bytes.div_ceil(Self::BYTES_PER_CHUNK)
    }

    // TAG CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Tag for a `keccak256_preimage` chunk node for an `n_bytes`-byte payload.
    pub fn keccak_preimage_tag(n_bytes: u32) -> Tag {
        [Self::app_id(), Self::D_KECCAK_PREIMAGE, Felt::from_u32(n_bytes), ZERO]
    }

    /// Tag for the canonical `keccak256_digest` leaf.
    pub fn keccak_digest_tag() -> Tag {
        [Self::app_id(), Self::D_KECCAK_DIGEST, ZERO, ZERO]
    }

    /// Tag for a `keccak256_eq` predicate node.
    pub fn keccak_eq_tag() -> Tag {
        [Self::app_id(), Self::D_KECCAK_EQ, ZERO, ZERO]
    }

    /// Tag for a `sha512_preimage` chunk node.
    pub fn sha512_preimage_tag(n_bytes: u32) -> Tag {
        [Self::app_id(), Self::D_SHA512_PREIMAGE, Felt::from_u32(n_bytes), ZERO]
    }

    /// Tag for the canonical `sha512_digest` chunk leaf.
    pub fn sha512_digest_tag() -> Tag {
        [Self::app_id(), Self::D_SHA512_DIGEST, ZERO, ZERO]
    }

    /// Tag for a `sha512_eq` predicate node.
    pub fn sha512_eq_tag() -> Tag {
        [Self::app_id(), Self::D_SHA512_EQ, ZERO, ZERO]
    }

    /// Tag for an `ecdsa_k256_keccak_verify` predicate chunk node.
    pub fn ecdsa_verify_tag() -> Tag {
        [Self::app_id(), Self::D_ECDSA_VERIFY, ZERO, ZERO]
    }

    /// Tag for an `eddsa_ed25519_verify` predicate chunk node.
    pub fn eddsa_verify_tag() -> Tag {
        [Self::app_id(), Self::D_EDDSA_VERIFY, ZERO, ZERO]
    }

    // NODE CONSTRUCTORS — KECCAK
    // --------------------------------------------------------------------------------------------

    /// Build a `keccak256_preimage` chunk node from caller-supplied 8-felt chunks.
    ///
    /// The caller is responsible for u32-packing the preimage bytes (4 bytes per felt, LE) and
    /// for matching `chunks.len() == ceil(n_bytes / BYTES_PER_CHUNK)`. The schema reduce strips
    /// the trailing zero-pad bytes back down to `n_bytes` before hashing.
    pub fn keccak_preimage_node(
        n_bytes: u32,
        chunks: impl Into<alloc::sync::Arc<[[Felt; 8]]>>,
    ) -> Node {
        Node::chunk(Self::keccak_preimage_tag(n_bytes), chunks)
    }

    /// Build a canonical `keccak256_digest` leaf from 8 u32-packed felts (the keccak hash
    /// output, little-endian).
    pub fn keccak_digest_node(felts: [Felt; 8]) -> Node {
        Node::expression(Self::keccak_digest_tag(), Payload::new(felts))
    }

    /// Build a `keccak256_eq` predicate over two child digests.
    pub fn keccak_eq_node(lhs: Digest, rhs: Digest) -> Node {
        Node::expression(Self::keccak_eq_tag(), Payload::binary_op(lhs, rhs))
    }

    // NODE CONSTRUCTORS — SHA512
    // --------------------------------------------------------------------------------------------

    /// Build a `sha512_preimage` chunk node from caller-supplied 8-felt chunks.
    pub fn sha512_preimage_node(
        n_bytes: u32,
        chunks: impl Into<alloc::sync::Arc<[[Felt; 8]]>>,
    ) -> Node {
        Node::chunk(Self::sha512_preimage_tag(n_bytes), chunks)
    }

    /// Build a canonical `sha512_digest` leaf from the 16-felt u32-packed digest.
    pub fn sha512_digest_node(felts: [Felt; 16]) -> Node {
        let chunks = [
            core::array::from_fn(|i| felts[i]),
            core::array::from_fn(|i| felts[8 + i]),
        ];
        Node::chunk(Self::sha512_digest_tag(), chunks.to_vec())
    }

    /// Build a `sha512_eq` predicate over two child digests.
    pub fn sha512_eq_node(lhs: Digest, rhs: Digest) -> Node {
        Node::expression(Self::sha512_eq_tag(), Payload::binary_op(lhs, rhs))
    }

    // NODE CONSTRUCTORS — ECDSA
    // --------------------------------------------------------------------------------------------

    /// Bytes-per-field-component for ecdsa: pk=33, digest=32, sig=65 ⇒ total 130 bytes.
    /// Packed as ceil(130/4)=33 u32 felts → 5 chunks of 8 felts with 7 felts of zero padding
    /// in the final chunk. (Schema unpack uses the offsets to slice each component out.)
    pub const ECDSA_PK_BYTES: usize = 33;
    pub const ECDSA_DIGEST_BYTES: usize = 32;
    pub const ECDSA_SIG_BYTES: usize = 65;

    /// Build an `ecdsa_k256_keccak_verify` chunk-bodied predicate from caller-supplied chunks.
    /// The caller must pack `pk || digest || sig` (u32-LE) contiguously and zero-pad to the
    /// 5-chunk (40-felt) boundary.
    pub fn ecdsa_verify_node(chunks: impl Into<alloc::sync::Arc<[[Felt; 8]]>>) -> Node {
        Node::chunk(Self::ecdsa_verify_tag(), chunks)
    }

    // NODE CONSTRUCTORS — EDDSA
    // --------------------------------------------------------------------------------------------

    /// Bytes-per-field-component for eddsa: pk=32, k_digest=64, sig=64 ⇒ 160 bytes total,
    /// 40 felts, 5 chunks exactly (no padding). `k_digest` is the externally pre-computed
    /// `SHA-512(R || A || message)` (see `verify_with_unchecked_k` docs in miden-crypto).
    pub const EDDSA_PK_BYTES: usize = 32;
    pub const EDDSA_K_DIGEST_BYTES: usize = 64;
    pub const EDDSA_SIG_BYTES: usize = 64;

    /// Build an `eddsa_ed25519_verify` chunk-bodied predicate from caller-supplied chunks.
    /// The caller must pack `pk || k_digest || sig` (u32-LE) into exactly 5 chunks.
    pub fn eddsa_verify_node(chunks: impl Into<alloc::sync::Arc<[[Felt; 8]]>>) -> Node {
        Node::chunk(Self::eddsa_verify_tag(), chunks)
    }
}

// CHUNK ↔ BYTES CODEC
// ================================================================================================

/// Unpack a slice of u32-packed-LE chunks back to a `n_bytes`-length byte vector, returning
/// `SchemaError::InvalidNode` if any felt holds a value larger than `u32::MAX`.
///
/// The caller-supplied `n_bytes` may be shorter than `chunks.len() * BYTES_PER_CHUNK as usize`;
/// the trailing bytes are zero-pad and are stripped from the output.
fn chunks_to_bytes(chunks: &[[Felt; 8]], n_bytes: usize) -> Result<Vec<u8>, SchemaError> {
    let chunk_bytes = LegacyPrecompile::BYTES_PER_CHUNK as usize;
    if n_bytes > chunks.len() * chunk_bytes {
        return Err(SchemaError::InvalidNode);
    }
    let mut bytes = Vec::with_capacity(chunks.len() * chunk_bytes);
    for chunk in chunks {
        for felt in chunk {
            let limb = u32::try_from(felt.as_canonical_u64())
                .map_err(|_| SchemaError::InvalidNode)?;
            bytes.extend_from_slice(&limb.to_le_bytes());
        }
    }
    bytes.truncate(n_bytes);
    Ok(bytes)
}

/// Pack 32 contiguous bytes into 8 u32-packed-LE felts. Panics if `bytes.len() != 32` — used
/// for keccak's fixed 256-bit digest.
fn bytes32_to_felts(bytes: &[u8]) -> [Felt; 8] {
    assert_eq!(bytes.len(), 32, "keccak digest must be 32 bytes");
    core::array::from_fn(|i| {
        let mut limb = [0u8; 4];
        limb.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        Felt::from_u32(u32::from_le_bytes(limb))
    })
}

/// Pack 64 contiguous bytes into 16 u32-packed-LE felts. Panics if `bytes.len() != 64` — used
/// for sha512's 512-bit digest.
fn bytes64_to_felts(bytes: &[u8]) -> [Felt; 16] {
    assert_eq!(bytes.len(), 64, "sha512 digest must be 64 bytes");
    core::array::from_fn(|i| {
        let mut limb = [0u8; 4];
        limb.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        Felt::from_u32(u32::from_le_bytes(limb))
    })
}

// APP IMPL
// ================================================================================================

impl App for LegacyPrecompile {
    fn id(&self) -> Felt {
        Self::app_id()
    }

    fn decode(&self, local: AppTag) -> Result<TagInfo, SchemaError> {
        let disc = Discriminant::classify(local.node_disc).ok_or(SchemaError::InvalidNode)?;
        match disc {
            Discriminant::KeccakPreimage => {
                // `imm` carries n_bytes; chunk count is derived.
                let n_bytes = u32::try_from(local.imm.as_canonical_u64())
                    .map_err(|_| SchemaError::InvalidNode)?;
                Ok(TagInfo {
                    node_type: NodeType::Chunks(Self::n_chunks(n_bytes)),
                    evaluates_to: Self::keccak_digest_tag(),
                })
            },
            Discriminant::KeccakDigest => {
                if local.imm != ZERO {
                    return Err(SchemaError::InvalidNode);
                }
                Ok(TagInfo {
                    node_type: NodeType::Value,
                    evaluates_to: Self::keccak_digest_tag(),
                })
            },
            Discriminant::KeccakEq => {
                if local.imm != ZERO {
                    return Err(SchemaError::InvalidNode);
                }
                Ok(TagInfo {
                    node_type: NodeType::Binary,
                    evaluates_to: TRUE_TAG,
                })
            },
            Discriminant::Sha512Preimage => {
                let n_bytes = u32::try_from(local.imm.as_canonical_u64())
                    .map_err(|_| SchemaError::InvalidNode)?;
                Ok(TagInfo {
                    node_type: NodeType::Chunks(Self::n_chunks(n_bytes)),
                    evaluates_to: Self::sha512_digest_tag(),
                })
            },
            Discriminant::Sha512Digest => {
                if local.imm != ZERO {
                    return Err(SchemaError::InvalidNode);
                }
                // 64-byte SHA-512 digest packed as 16 u32 felts → 2 chunks of 8 felts.
                Ok(TagInfo {
                    node_type: NodeType::Chunks(2),
                    evaluates_to: Self::sha512_digest_tag(),
                })
            },
            Discriminant::Sha512Eq => {
                if local.imm != ZERO {
                    return Err(SchemaError::InvalidNode);
                }
                Ok(TagInfo {
                    node_type: NodeType::Binary,
                    evaluates_to: TRUE_TAG,
                })
            },
            Discriminant::EcdsaVerify => {
                if local.imm != ZERO {
                    return Err(SchemaError::InvalidNode);
                }
                // pk[9] || digest[8] || sig[17] || pad[6] = 40 felts = 5 chunks.
                Ok(TagInfo {
                    node_type: NodeType::Chunks(5),
                    evaluates_to: TRUE_TAG,
                })
            },
            Discriminant::EddsaVerify => {
                if local.imm != ZERO {
                    return Err(SchemaError::InvalidNode);
                }
                // pk[8] || k_digest[16] || sig[16] = 40 felts = 5 chunks.
                Ok(TagInfo {
                    node_type: NodeType::Chunks(5),
                    evaluates_to: TRUE_TAG,
                })
            },
        }
    }

    fn reduce(
        &self,
        node: &Node,
        ctx: &mut dyn ReduceCtx,
    ) -> Result<Node, SchemaError> {
        if node.tag[0] != Self::app_id() || node.tag[3] != ZERO {
            return Err(SchemaError::InvalidNode);
        }
        let disc = Discriminant::classify(node.tag[1]).ok_or(SchemaError::InvalidNode)?;
        match disc {
            Discriminant::KeccakPreimage => reduce_keccak_preimage(node),
            Discriminant::KeccakDigest => reduce_keccak_digest(node),
            Discriminant::KeccakEq => reduce_keccak_eq(node, ctx),
            Discriminant::Sha512Preimage => reduce_sha512_preimage(node),
            Discriminant::Sha512Digest => reduce_sha512_digest(node),
            Discriminant::Sha512Eq => reduce_sha512_eq(node, ctx),
            Discriminant::EcdsaVerify => reduce_ecdsa_verify(node),
            Discriminant::EddsaVerify => reduce_eddsa_verify(node),
        }
    }
}

// KECCAK KERNELS
// ================================================================================================

/// Reduce a `keccak256_preimage` chunk node: unpack chunks to bytes (stripping zero-pad to
/// `n_bytes` carried in `tag[2]`), run `Keccak256::hash`, and emit the canonical
/// `keccak256_digest` leaf with the result u32-packed.
fn reduce_keccak_preimage(node: &Node) -> Result<Node, SchemaError> {
    let n_bytes = u32::try_from(node.tag[2].as_canonical_u64())
        .map_err(|_| SchemaError::InvalidNode)? as usize;
    let chunks = match &node.payload {
        NodePayload::Chunk(c) => c,
        NodePayload::Expression(_) => return Err(SchemaError::InvalidNode),
    };
    let bytes = chunks_to_bytes(chunks, n_bytes)?;
    let digest_bytes = Keccak256::hash(&bytes);
    Ok(LegacyPrecompile::keccak_digest_node(bytes32_to_felts(&digest_bytes)))
}

/// Reduce a `keccak256_digest` leaf — self-evaluating. The framework already validated
/// `tag[2] == ZERO` via `decode`; reduce just returns the node as canonical.
fn reduce_keccak_digest(node: &Node) -> Result<Node, SchemaError> {
    if node.tag[2] != ZERO {
        return Err(SchemaError::InvalidNode);
    }
    // Confirm expression body shape — register-time validation already enforces this, but the
    // schema is a defense-in-depth surface.
    match &node.payload {
        NodePayload::Expression(_) => Ok(node.clone()),
        NodePayload::Chunk(_) => Err(SchemaError::InvalidNode),
    }
}

/// Reduce a `keccak256_eq` binary predicate: resolve both children to their canonical forms,
/// require both to be `keccak256_digest` leaves, and assert their payloads match.
fn reduce_keccak_eq(node: &Node, ctx: &mut dyn ReduceCtx) -> Result<Node, SchemaError> {
    if node.tag[2] != ZERO {
        return Err(SchemaError::InvalidNode);
    }
    let payload = node.expression_payload().ok_or(SchemaError::InvalidNode)?;
    let (lhs_digest, rhs_digest) = payload.binary_op_children();
    let lhs = ctx.resolve(lhs_digest)?;
    let rhs = ctx.resolve(rhs_digest)?;
    if lhs.tag != LegacyPrecompile::keccak_digest_tag()
        || rhs.tag != LegacyPrecompile::keccak_digest_tag()
    {
        return Err(SchemaError::InvalidNode);
    }
    if lhs.expression_payload() != rhs.expression_payload() {
        return Err(SchemaError::AssertionFailed);
    }
    Ok(true_node())
}

// SHA512 KERNELS
// ================================================================================================

/// Reduce a `sha512_preimage` chunk node: unpack chunks to bytes, run `Sha512::hash`, and emit
/// the canonical `sha512_digest` chunk leaf (16 u32-packed felts = 2 chunks).
fn reduce_sha512_preimage(node: &Node) -> Result<Node, SchemaError> {
    let n_bytes = u32::try_from(node.tag[2].as_canonical_u64())
        .map_err(|_| SchemaError::InvalidNode)? as usize;
    let chunks = match &node.payload {
        NodePayload::Chunk(c) => c,
        NodePayload::Expression(_) => return Err(SchemaError::InvalidNode),
    };
    let bytes = chunks_to_bytes(chunks, n_bytes)?;
    let digest_bytes = Sha512::hash(&bytes);
    Ok(LegacyPrecompile::sha512_digest_node(bytes64_to_felts(&digest_bytes)))
}

/// Reduce a `sha512_digest` chunk leaf — self-evaluating. Validates `tag[2] == ZERO` and chunk
/// count = 2; returns the node as canonical.
fn reduce_sha512_digest(node: &Node) -> Result<Node, SchemaError> {
    if node.tag[2] != ZERO {
        return Err(SchemaError::InvalidNode);
    }
    match &node.payload {
        NodePayload::Chunk(c) if c.len() == 2 => Ok(node.clone()),
        _ => Err(SchemaError::InvalidNode),
    }
}

/// Reduce a `sha512_eq` binary predicate: resolve both children, require both to be
/// `sha512_digest` chunk leaves, and assert their chunk contents match.
fn reduce_sha512_eq(node: &Node, ctx: &mut dyn ReduceCtx) -> Result<Node, SchemaError> {
    if node.tag[2] != ZERO {
        return Err(SchemaError::InvalidNode);
    }
    let payload = node.expression_payload().ok_or(SchemaError::InvalidNode)?;
    let (lhs_digest, rhs_digest) = payload.binary_op_children();
    let lhs = ctx.resolve(lhs_digest)?;
    let rhs = ctx.resolve(rhs_digest)?;
    if lhs.tag != LegacyPrecompile::sha512_digest_tag()
        || rhs.tag != LegacyPrecompile::sha512_digest_tag()
    {
        return Err(SchemaError::InvalidNode);
    }
    let (lhs_chunks, rhs_chunks) = match (&lhs.payload, &rhs.payload) {
        (NodePayload::Chunk(l), NodePayload::Chunk(r)) => (l, r),
        _ => return Err(SchemaError::InvalidNode),
    };
    if lhs_chunks.as_ref() != rhs_chunks.as_ref() {
        return Err(SchemaError::AssertionFailed);
    }
    Ok(true_node())
}

// ECDSA KERNEL
// ================================================================================================

/// Reduce an `ecdsa_k256_keccak_verify` chunk predicate: unpack pk/digest/sig from the chunks,
/// deserialize via the `miden-crypto` types, and run `PublicKey::verify_prehash`. Returns
/// `true_node()` on success or `AssertionFailed` on signature mismatch / deserialization
/// failure.
///
/// Chunk layout: 5 chunks = 40 felts = 160 bytes.
///   bytes[0..33]   = pk     (compressed secp256k1, 33 bytes)
///   bytes[33..65]  = digest (keccak256 prehash, 32 bytes)
///   bytes[65..130] = sig    (r || s || v, 65 bytes)
///   bytes[130..]   = zero padding (validated as zero)
fn reduce_ecdsa_verify(node: &Node) -> Result<Node, SchemaError> {
    if node.tag[2] != ZERO {
        return Err(SchemaError::InvalidNode);
    }
    let chunks = match &node.payload {
        NodePayload::Chunk(c) if c.len() == 5 => c,
        _ => return Err(SchemaError::InvalidNode),
    };
    let total_bytes = 5 * LegacyPrecompile::BYTES_PER_CHUNK as usize; // 160
    let bytes = chunks_to_bytes(chunks, total_bytes)?;

    let pk_end = LegacyPrecompile::ECDSA_PK_BYTES;
    let digest_end = pk_end + LegacyPrecompile::ECDSA_DIGEST_BYTES;
    let sig_end = digest_end + LegacyPrecompile::ECDSA_SIG_BYTES;

    // Tail bytes after the meaningful payload must be zero — they're zero-padding for the
    // chunk boundary, and a non-zero tail would let the prover smuggle data through the
    // digest binding without affecting the kernel result.
    if bytes[sig_end..].iter().any(|&b| b != 0) {
        return Err(SchemaError::InvalidNode);
    }

    let pk = EcdsaPublicKey::read_from_bytes(&bytes[..pk_end])
        .map_err(|_| SchemaError::AssertionFailed)?;
    let digest: [u8; 32] = bytes[pk_end..digest_end]
        .try_into()
        .expect("ECDSA_DIGEST_BYTES sliced to 32 bytes");
    let sig = EcdsaSignature::read_from_bytes(&bytes[digest_end..sig_end])
        .map_err(|_| SchemaError::AssertionFailed)?;

    if pk.verify_prehash(digest, &sig) {
        Ok(true_node())
    } else {
        Err(SchemaError::AssertionFailed)
    }
}

// EDDSA KERNEL
// ================================================================================================

/// Reduce an `eddsa_ed25519_verify` chunk predicate: unpack pk/k_digest/sig from the chunks
/// and run `PublicKey::verify_with_unchecked_k`. Returns `true_node()` on success or
/// `AssertionFailed` on signature mismatch / deserialization failure.
///
/// Chunk layout: 5 chunks = 40 felts = 160 bytes — no padding.
///   bytes[0..32]    = pk       (32 bytes)
///   bytes[32..96]   = k_digest (SHA-512(R || A || message), 64 bytes)
///   bytes[96..160]  = sig      (R || s, 64 bytes)
fn reduce_eddsa_verify(node: &Node) -> Result<Node, SchemaError> {
    if node.tag[2] != ZERO {
        return Err(SchemaError::InvalidNode);
    }
    let chunks = match &node.payload {
        NodePayload::Chunk(c) if c.len() == 5 => c,
        _ => return Err(SchemaError::InvalidNode),
    };
    let total_bytes = 5 * LegacyPrecompile::BYTES_PER_CHUNK as usize; // 160
    let bytes = chunks_to_bytes(chunks, total_bytes)?;

    let pk_end = LegacyPrecompile::EDDSA_PK_BYTES;
    let k_digest_end = pk_end + LegacyPrecompile::EDDSA_K_DIGEST_BYTES;
    let sig_end = k_digest_end + LegacyPrecompile::EDDSA_SIG_BYTES;
    debug_assert_eq!(sig_end, total_bytes, "eddsa layout fills all 160 bytes exactly");

    let pk = EddsaPublicKey::read_from_bytes(&bytes[..pk_end])
        .map_err(|_| SchemaError::AssertionFailed)?;
    let k_digest: [u8; 64] = bytes[pk_end..k_digest_end]
        .try_into()
        .expect("EDDSA_K_DIGEST_BYTES sliced to 64 bytes");
    let sig = EddsaSignature::read_from_bytes(&bytes[k_digest_end..sig_end])
        .map_err(|_| SchemaError::AssertionFailed)?;

    if pk.verify_with_unchecked_k(k_digest, &sig).is_ok() {
        Ok(true_node())
    } else {
        Err(SchemaError::AssertionFailed)
    }
}

// TYPED DISCRIMINANT
// ================================================================================================

/// Closed enum over the 8 production discriminants, indexed by `DISCS` order. `classify` is
/// the inverse of the `D_*` constants — `decode` uses it to route by tag without bare `match`
/// on raw felt integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Discriminant {
    KeccakPreimage,
    KeccakDigest,
    KeccakEq,
    Sha512Preimage,
    Sha512Digest,
    Sha512Eq,
    EcdsaVerify,
    EddsaVerify,
}

impl Discriminant {
    fn classify(disc: Felt) -> Option<Self> {
        match disc.as_canonical_u64() {
            0 => Some(Self::KeccakPreimage),
            1 => Some(Self::KeccakDigest),
            2 => Some(Self::KeccakEq),
            3 => Some(Self::Sha512Preimage),
            4 => Some(Self::Sha512Digest),
            5 => Some(Self::Sha512Eq),
            6 => Some(Self::EcdsaVerify),
            7 => Some(Self::EddsaVerify),
            _ => None,
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_id_is_stable() {
        // Re-derivation must match. Bumping VERSION or any DISCS name changes this value.
        let a = LegacyPrecompile::app_id();
        let b = LegacyPrecompile::app_id();
        assert_eq!(a, b);
    }

    /// Pin the felt values that the per-precompile MASM files hardcode as `const LP_APP_ID = ...`
    /// etc. Any change to the underlying app_id derivation (NAME, VERSION, params, DISCS) or to
    /// discriminant ordering will fail this test, forcing a matching update to the four
    /// precompile MASM files (keccak256.masm, sha512.masm, ecdsa_k256_keccak.masm,
    /// eddsa_ed25519.masm) so MASM and Rust never diverge silently.
    ///
    /// Update procedure on intentional change: bump VERSION (or rename a discriminant), re-run
    /// this test, copy the printed values into the `expected_*` constants below AND into the
    /// `const LP_APP_ID` / `const LP_D_*` declarations in each precompile MASM file.
    #[test]
    fn masm_constants_pinned_to_rust_values() {
        // Derived once via `app_id_from("legacy_precompile", 1, b"", DISCS)`. Pinned here so
        // any drift surfaces at CI time. Discriminant indices are positional in DISCS.
        const EXPECTED_LP_APP_ID: u64 = 18_269_343_673_680_090_362;

        assert_eq!(
            LegacyPrecompile::app_id().as_canonical_u64(),
            EXPECTED_LP_APP_ID,
            "LP_APP_ID drift — update precompile MASM files to match",
        );
        // Discriminants are positional 0..8 mapping to DISCS order; pin them explicitly so a
        // reorder is caught.
        assert_eq!(LegacyPrecompile::D_KECCAK_PREIMAGE.as_canonical_u64(), 0);
        assert_eq!(LegacyPrecompile::D_KECCAK_DIGEST.as_canonical_u64(), 1);
        assert_eq!(LegacyPrecompile::D_KECCAK_EQ.as_canonical_u64(), 2);
        assert_eq!(LegacyPrecompile::D_SHA512_PREIMAGE.as_canonical_u64(), 3);
        assert_eq!(LegacyPrecompile::D_SHA512_DIGEST.as_canonical_u64(), 4);
        assert_eq!(LegacyPrecompile::D_SHA512_EQ.as_canonical_u64(), 5);
        assert_eq!(LegacyPrecompile::D_ECDSA_VERIFY.as_canonical_u64(), 6);
        assert_eq!(LegacyPrecompile::D_EDDSA_VERIFY.as_canonical_u64(), 7);
    }

    #[test]
    fn decode_keccak_preimage_carries_n_bytes_in_imm() {
        let info = LegacyPrecompile.decode(AppTag {
            node_disc: LegacyPrecompile::D_KECCAK_PREIMAGE,
            imm: Felt::from_u32(65),
        }).unwrap();
        // 65 bytes → ceil(65/32) = 3 chunks.
        assert!(matches!(info.node_type, NodeType::Chunks(3)));
        assert_eq!(info.evaluates_to, LegacyPrecompile::keccak_digest_tag());
    }

    #[test]
    fn decode_keccak_digest_is_self_evaluating_value() {
        let info = LegacyPrecompile
            .decode(AppTag { node_disc: LegacyPrecompile::D_KECCAK_DIGEST, imm: ZERO })
            .unwrap();
        assert!(matches!(info.node_type, NodeType::Value));
        assert_eq!(info.evaluates_to, LegacyPrecompile::keccak_digest_tag());
    }

    #[test]
    fn decode_keccak_eq_is_binary_predicate() {
        let info = LegacyPrecompile
            .decode(AppTag { node_disc: LegacyPrecompile::D_KECCAK_EQ, imm: ZERO })
            .unwrap();
        assert!(matches!(info.node_type, NodeType::Binary));
        assert_eq!(info.evaluates_to, TRUE_TAG);
    }

    #[test]
    fn decode_sha512_preimage_carries_n_bytes_in_imm() {
        let info = LegacyPrecompile.decode(AppTag {
            node_disc: LegacyPrecompile::D_SHA512_PREIMAGE,
            imm: Felt::from_u32(100),
        }).unwrap();
        // 100 bytes → ceil(100/32) = 4 chunks.
        assert!(matches!(info.node_type, NodeType::Chunks(4)));
        assert_eq!(info.evaluates_to, LegacyPrecompile::sha512_digest_tag());
    }

    #[test]
    fn decode_sha512_digest_is_2_chunk_self_eval() {
        let info = LegacyPrecompile
            .decode(AppTag { node_disc: LegacyPrecompile::D_SHA512_DIGEST, imm: ZERO })
            .unwrap();
        // 64-byte digest = 16 u32 felts = 2 chunks of 8.
        assert!(matches!(info.node_type, NodeType::Chunks(2)));
        assert_eq!(info.evaluates_to, LegacyPrecompile::sha512_digest_tag());
    }

    #[test]
    fn decode_sha512_eq_is_binary_predicate() {
        let info = LegacyPrecompile
            .decode(AppTag { node_disc: LegacyPrecompile::D_SHA512_EQ, imm: ZERO })
            .unwrap();
        assert!(matches!(info.node_type, NodeType::Binary));
        assert_eq!(info.evaluates_to, TRUE_TAG);
    }

    #[test]
    fn decode_ecdsa_verify_is_5_chunk_predicate() {
        let info = LegacyPrecompile
            .decode(AppTag { node_disc: LegacyPrecompile::D_ECDSA_VERIFY, imm: ZERO })
            .unwrap();
        // pk[9] || digest[8] || sig[17] || pad[6] = 40 felts = 5 chunks.
        assert!(matches!(info.node_type, NodeType::Chunks(5)));
        assert_eq!(info.evaluates_to, TRUE_TAG);
    }

    #[test]
    fn decode_eddsa_verify_is_5_chunk_predicate() {
        let info = LegacyPrecompile
            .decode(AppTag { node_disc: LegacyPrecompile::D_EDDSA_VERIFY, imm: ZERO })
            .unwrap();
        // pk[8] || k_digest[16] || sig[16] = 40 felts = 5 chunks.
        assert!(matches!(info.node_type, NodeType::Chunks(5)));
        assert_eq!(info.evaluates_to, TRUE_TAG);
    }

    #[test]
    fn decode_unknown_discriminant_rejected() {
        let err = LegacyPrecompile
            .decode(AppTag { node_disc: Felt::from_u32(99), imm: ZERO });
        assert!(matches!(err, Err(SchemaError::InvalidNode)));
    }

    #[test]
    fn decode_rejects_imm_on_non_preimage_discs() {
        for disc in [
            LegacyPrecompile::D_KECCAK_DIGEST,
            LegacyPrecompile::D_KECCAK_EQ,
            LegacyPrecompile::D_SHA512_DIGEST,
            LegacyPrecompile::D_SHA512_EQ,
            LegacyPrecompile::D_ECDSA_VERIFY,
            LegacyPrecompile::D_EDDSA_VERIFY,
        ] {
            let err = LegacyPrecompile.decode(AppTag { node_disc: disc, imm: Felt::from_u32(1) });
            assert!(
                matches!(err, Err(SchemaError::InvalidNode)),
                "disc {} must reject non-zero imm",
                disc.as_canonical_u64()
            );
        }
    }

    #[test]
    fn n_chunks_rounds_up() {
        assert_eq!(LegacyPrecompile::n_chunks(0), 0);
        assert_eq!(LegacyPrecompile::n_chunks(1), 1);
        assert_eq!(LegacyPrecompile::n_chunks(31), 1);
        assert_eq!(LegacyPrecompile::n_chunks(32), 1);
        assert_eq!(LegacyPrecompile::n_chunks(33), 2);
        assert_eq!(LegacyPrecompile::n_chunks(64), 2);
        assert_eq!(LegacyPrecompile::n_chunks(65), 3);
    }

    // KECCAK KERNEL TESTS
    // ============================================================================================

    use crate::{
        deferred::{DeferredState, PrecompileSchema},
        utils::bytes_to_packed_u32_elements,
    };

    /// Pack `bytes` into 8-felt chunks, zero-padded to a chunk boundary. Mirrors how MASM
    /// writes preimage bytes to memory before invoking `adv.register_deferred_chunk`.
    fn pack_chunks(bytes: &[u8]) -> Vec<[Felt; 8]> {
        let felts = bytes_to_packed_u32_elements(bytes);
        // Pad felts to a multiple of 8.
        let n_chunks = felts.len().div_ceil(8);
        let mut padded = felts;
        padded.resize(n_chunks * 8, ZERO);
        padded
            .chunks_exact(8)
            .map(|c| core::array::from_fn(|i| c[i]))
            .collect()
    }

    fn fresh_state() -> (PrecompileSchema, DeferredState) {
        (PrecompileSchema::single(LegacyPrecompile), DeferredState::new())
    }

    fn keccak_known(input: &[u8]) -> Node {
        let digest_bytes = miden_crypto::hash::keccak::Keccak256::hash(input);
        LegacyPrecompile::keccak_digest_node(bytes32_to_felts(&digest_bytes))
    }

    #[test]
    fn keccak_preimage_reduces_to_digest_leaf_empty() {
        // Empty preimage. n_bytes = 0 → 0 chunks. Kernel: Keccak256([]) yields a known digest.
        let (schema, mut state) = fresh_state();
        let expected = keccak_known(&[]);
        let node = LegacyPrecompile::keccak_preimage_node(0, Vec::new());
        let canonical = state.evaluate(&schema, node).unwrap();
        assert_eq!(canonical, expected);
    }

    #[test]
    fn keccak_preimage_reduces_to_digest_leaf_short() {
        // 11-byte preimage "hello world" → 1 chunk (zero-padded to 32 bytes), n_bytes=11.
        let (schema, mut state) = fresh_state();
        let bytes = b"hello world";
        let expected = keccak_known(bytes);
        let chunks = pack_chunks(bytes);
        let node = LegacyPrecompile::keccak_preimage_node(bytes.len() as u32, chunks);
        let canonical = state.evaluate(&schema, node).unwrap();
        assert_eq!(canonical, expected);
    }

    #[test]
    fn keccak_preimage_reduces_to_digest_leaf_multi_chunk() {
        // 70-byte preimage → 3 chunks (96 bytes with padding), n_bytes=70 strips trailing zeros.
        let (schema, mut state) = fresh_state();
        let bytes: Vec<u8> = (0u8..70).collect();
        let expected = keccak_known(&bytes);
        let chunks = pack_chunks(&bytes);
        assert_eq!(chunks.len(), 3, "70 bytes should pack into 3 chunks");
        let node = LegacyPrecompile::keccak_preimage_node(bytes.len() as u32, chunks);
        let canonical = state.evaluate(&schema, node).unwrap();
        assert_eq!(canonical, expected);
    }

    #[test]
    fn keccak_preimage_rejects_oversized_n_bytes_for_chunk_count() {
        // n_bytes claims 100 but only 1 chunk (32 bytes) is provided. chunks_to_bytes catches it.
        let (schema, mut state) = fresh_state();
        let chunks = vec![[Felt::from_u32(0); 8]];
        let node = LegacyPrecompile::keccak_preimage_node(100, chunks);
        // Decode fails first because n_bytes=100 demands 4 chunks but only 1 was provided —
        // payload_matches_type rejects it at register time, surfacing through evaluate.
        let err = state.evaluate(&schema, node);
        assert!(matches!(err, Err(SchemaError::InvalidNode)));
    }

    #[test]
    fn keccak_digest_leaf_is_self_evaluating() {
        let (schema, mut state) = fresh_state();
        let leaf = LegacyPrecompile::keccak_digest_node([Felt::from_u32(7); 8]);
        let leaf_digest = state.register(&schema, leaf.clone()).unwrap();
        let canonical = state
            .evaluate(&schema, state.get(&leaf_digest).unwrap().clone())
            .unwrap();
        assert_eq!(canonical, leaf);
    }

    #[test]
    fn keccak_eq_succeeds_on_matching_preimage_and_digest() {
        // The full intended flow: register preimage chunk + claimed digest leaf, build eq
        // predicate, evaluate. Schema reduces preimage to canonical digest, compares against
        // the registered claim. Both pass.
        let (schema, mut state) = fresh_state();
        let bytes = b"test vector for eq";
        let chunks = pack_chunks(bytes);
        let preimage_digest = state
            .register(&schema, LegacyPrecompile::keccak_preimage_node(bytes.len() as u32, chunks))
            .unwrap();
        let known_leaf = keccak_known(bytes);
        let leaf_digest = state.register(&schema, known_leaf).unwrap();
        let eq = LegacyPrecompile::keccak_eq_node(preimage_digest, leaf_digest);
        let result = state.evaluate(&schema, eq).unwrap();
        assert!(result.is_true_node());
    }

    #[test]
    fn keccak_eq_fails_on_mismatched_digest_claim() {
        let (schema, mut state) = fresh_state();
        let bytes = b"data";
        let chunks = pack_chunks(bytes);
        let preimage_digest = state
            .register(&schema, LegacyPrecompile::keccak_preimage_node(bytes.len() as u32, chunks))
            .unwrap();
        // Deliberately wrong digest claim.
        let wrong_leaf = LegacyPrecompile::keccak_digest_node([Felt::from_u32(0xdead); 8]);
        let wrong_digest = state.register(&schema, wrong_leaf).unwrap();
        let eq = LegacyPrecompile::keccak_eq_node(preimage_digest, wrong_digest);
        let err = state.evaluate(&schema, eq);
        assert!(matches!(err, Err(SchemaError::AssertionFailed)));
    }

    #[test]
    fn keccak_eq_missing_child_surfaces() {
        // Sanity that the eq path actually walks children. If one child digest isn't in the DAG,
        // the resolver fails with MissingNode.
        let (schema, mut state) = fresh_state();
        let bytes = b"x";
        let chunks = pack_chunks(bytes);
        let preimage_digest = state
            .register(&schema, LegacyPrecompile::keccak_preimage_node(bytes.len() as u32, chunks))
            .unwrap();
        let dangling = crate::Word::new([Felt::from_u32(0xdead); 4]);
        let eq = LegacyPrecompile::keccak_eq_node(preimage_digest, dangling);
        let err = state.evaluate(&schema, eq);
        assert!(matches!(err, Err(SchemaError::MissingNode)));
    }

    // SHA512 KERNEL TESTS
    // ============================================================================================

    fn sha512_known(input: &[u8]) -> Node {
        let digest_bytes = miden_crypto::hash::sha2::Sha512::hash(input);
        LegacyPrecompile::sha512_digest_node(bytes64_to_felts(&digest_bytes))
    }

    #[test]
    fn sha512_preimage_reduces_to_digest_leaf_empty() {
        let (schema, mut state) = fresh_state();
        let expected = sha512_known(&[]);
        let node = LegacyPrecompile::sha512_preimage_node(0, Vec::new());
        let canonical = state.evaluate(&schema, node).unwrap();
        assert_eq!(canonical, expected);
    }

    #[test]
    fn sha512_preimage_reduces_to_digest_leaf_short() {
        let (schema, mut state) = fresh_state();
        let bytes = b"hello world";
        let expected = sha512_known(bytes);
        let chunks = pack_chunks(bytes);
        let node = LegacyPrecompile::sha512_preimage_node(bytes.len() as u32, chunks);
        let canonical = state.evaluate(&schema, node).unwrap();
        assert_eq!(canonical, expected);
    }

    #[test]
    fn sha512_preimage_reduces_to_digest_leaf_multi_chunk() {
        let (schema, mut state) = fresh_state();
        let bytes: Vec<u8> = (0u8..100).collect();
        let expected = sha512_known(&bytes);
        let chunks = pack_chunks(&bytes);
        let node = LegacyPrecompile::sha512_preimage_node(bytes.len() as u32, chunks);
        let canonical = state.evaluate(&schema, node).unwrap();
        assert_eq!(canonical, expected);
    }

    #[test]
    fn sha512_digest_leaf_is_self_evaluating() {
        let (schema, mut state) = fresh_state();
        let felts: [Felt; 16] = core::array::from_fn(|i| Felt::from_u32(i as u32));
        let leaf = LegacyPrecompile::sha512_digest_node(felts);
        let leaf_digest = state.register(&schema, leaf.clone()).unwrap();
        let canonical = state
            .evaluate(&schema, state.get(&leaf_digest).unwrap().clone())
            .unwrap();
        assert_eq!(canonical, leaf);
    }

    #[test]
    fn sha512_eq_succeeds_on_matching_preimage_and_digest() {
        let (schema, mut state) = fresh_state();
        let bytes = b"some sha512 input";
        let chunks = pack_chunks(bytes);
        let preimage_digest = state
            .register(&schema, LegacyPrecompile::sha512_preimage_node(bytes.len() as u32, chunks))
            .unwrap();
        let leaf_digest = state.register(&schema, sha512_known(bytes)).unwrap();
        let eq = LegacyPrecompile::sha512_eq_node(preimage_digest, leaf_digest);
        let result = state.evaluate(&schema, eq).unwrap();
        assert!(result.is_true_node());
    }

    #[test]
    fn sha512_eq_fails_on_mismatched_digest_claim() {
        let (schema, mut state) = fresh_state();
        let bytes = b"a";
        let chunks = pack_chunks(bytes);
        let preimage_digest = state
            .register(&schema, LegacyPrecompile::sha512_preimage_node(bytes.len() as u32, chunks))
            .unwrap();
        let wrong_leaf = LegacyPrecompile::sha512_digest_node([Felt::from_u32(0xdead); 16]);
        let wrong_digest = state.register(&schema, wrong_leaf).unwrap();
        let eq = LegacyPrecompile::sha512_eq_node(preimage_digest, wrong_digest);
        let err = state.evaluate(&schema, eq);
        assert!(matches!(err, Err(SchemaError::AssertionFailed)));
    }

    // ECDSA KERNEL TESTS
    // ============================================================================================

    use crate::serde::Serializable;

    /// Pack the ecdsa concatenation `pk || digest || sig` into 5 chunks (40 felts), zero-padded
    /// in the tail. Mirrors what MASM writes to memory before invoking register_chunk.
    fn pack_ecdsa(pk: &[u8], digest: &[u8], sig: &[u8]) -> Vec<[Felt; 8]> {
        assert_eq!(pk.len(), 33);
        assert_eq!(digest.len(), 32);
        assert_eq!(sig.len(), 65);
        let mut buf = Vec::with_capacity(160);
        buf.extend_from_slice(pk);
        buf.extend_from_slice(digest);
        buf.extend_from_slice(sig);
        buf.resize(160, 0);
        pack_chunks(&buf)
    }

    fn ecdsa_keypair_and_sig(digest: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
        use miden_crypto::dsa::ecdsa_k256_keccak::SigningKey as SecretKey;
        let sk = SecretKey::new();
        let pk_bytes = sk.public_key().to_bytes().to_vec();
        let sig_bytes = sk.sign_prehash(digest).to_bytes().to_vec();
        (pk_bytes, sig_bytes)
    }

    #[test]
    fn ecdsa_verify_succeeds_on_valid_signature() {
        let (schema, mut state) = fresh_state();
        let digest = [7u8; 32];
        let (pk_bytes, sig_bytes) = ecdsa_keypair_and_sig(digest);
        let chunks = pack_ecdsa(&pk_bytes, &digest, &sig_bytes);
        let node = LegacyPrecompile::ecdsa_verify_node(chunks);
        let result = state.evaluate(&schema, node).unwrap();
        assert!(result.is_true_node());
    }

    #[test]
    fn ecdsa_verify_fails_on_tampered_signature() {
        let (schema, mut state) = fresh_state();
        let digest = [7u8; 32];
        let (pk_bytes, mut sig_bytes) = ecdsa_keypair_and_sig(digest);
        // Flip a byte in the signature.
        sig_bytes[0] ^= 0xff;
        let chunks = pack_ecdsa(&pk_bytes, &digest, &sig_bytes);
        let node = LegacyPrecompile::ecdsa_verify_node(chunks);
        let err = state.evaluate(&schema, node);
        assert!(matches!(err, Err(SchemaError::AssertionFailed)));
    }

    #[test]
    fn ecdsa_verify_fails_on_tampered_digest() {
        let (schema, mut state) = fresh_state();
        let digest = [7u8; 32];
        let (pk_bytes, sig_bytes) = ecdsa_keypair_and_sig(digest);
        let mut wrong_digest = digest;
        wrong_digest[0] ^= 0xff;
        let chunks = pack_ecdsa(&pk_bytes, &wrong_digest, &sig_bytes);
        let node = LegacyPrecompile::ecdsa_verify_node(chunks);
        let err = state.evaluate(&schema, node);
        assert!(matches!(err, Err(SchemaError::AssertionFailed)));
    }

    #[test]
    fn ecdsa_verify_rejects_nonzero_padding_tail() {
        let (schema, mut state) = fresh_state();
        let digest = [7u8; 32];
        let (pk_bytes, sig_bytes) = ecdsa_keypair_and_sig(digest);
        let mut buf = Vec::with_capacity(160);
        buf.extend_from_slice(&pk_bytes);
        buf.extend_from_slice(&digest);
        buf.extend_from_slice(&sig_bytes);
        // Tail bytes 130..160 should be zero; set one to non-zero.
        buf.resize(160, 0);
        buf[140] = 0xaa;
        let chunks = pack_chunks(&buf);
        let node = LegacyPrecompile::ecdsa_verify_node(chunks);
        let err = state.evaluate(&schema, node);
        assert!(matches!(err, Err(SchemaError::InvalidNode)));
    }

    // EDDSA KERNEL TESTS
    // ============================================================================================

    /// Pack the eddsa concatenation `pk || k_digest || sig` (32 + 64 + 64 = 160 bytes) into 5
    /// chunks. No padding since the layout exactly fills 5 chunks.
    fn pack_eddsa(pk: &[u8], k_digest: &[u8], sig: &[u8]) -> Vec<[Felt; 8]> {
        assert_eq!(pk.len(), 32);
        assert_eq!(k_digest.len(), 64);
        assert_eq!(sig.len(), 64);
        let mut buf = Vec::with_capacity(160);
        buf.extend_from_slice(pk);
        buf.extend_from_slice(k_digest);
        buf.extend_from_slice(sig);
        assert_eq!(buf.len(), 160);
        pack_chunks(&buf)
    }

    /// Generate a valid (pk, k_digest, sig) triple for a Word message. Uses the library's
    /// `compute_challenge_k` so the k_digest matches whatever the sign path produced internally.
    fn eddsa_valid_triple_for_word(
        message: crate::Word,
    ) -> (Vec<u8>, [u8; 64], Vec<u8>) {
        use miden_crypto::dsa::eddsa_25519_sha512::SigningKey as SecretKey;
        let sk = SecretKey::new();
        let pk = sk.public_key();
        let sig = sk.sign(message);
        let k_digest = pk.compute_challenge_k(message, &sig);
        let pk_bytes = pk.to_bytes().to_vec();
        let sig_bytes = sig.to_bytes();
        (pk_bytes, k_digest, sig_bytes)
    }

    fn eddsa_test_word(seed: u32) -> crate::Word {
        crate::Word::new(core::array::from_fn(|i| Felt::from_u32(seed + i as u32)))
    }

    #[test]
    fn eddsa_verify_succeeds_on_valid_triple() {
        let (schema, mut state) = fresh_state();
        let (pk, k_digest, sig) = eddsa_valid_triple_for_word(eddsa_test_word(1));
        let chunks = pack_eddsa(&pk, &k_digest, &sig);
        let node = LegacyPrecompile::eddsa_verify_node(chunks);
        let result = state.evaluate(&schema, node).unwrap();
        assert!(result.is_true_node());
    }

    #[test]
    fn eddsa_verify_fails_on_tampered_signature() {
        let (schema, mut state) = fresh_state();
        let (pk, k_digest, mut sig) = eddsa_valid_triple_for_word(eddsa_test_word(11));
        sig[0] ^= 0xff;
        let chunks = pack_eddsa(&pk, &k_digest, &sig);
        let node = LegacyPrecompile::eddsa_verify_node(chunks);
        let err = state.evaluate(&schema, node);
        assert!(matches!(err, Err(SchemaError::AssertionFailed)));
    }

    #[test]
    fn eddsa_verify_fails_on_tampered_k_digest() {
        let (schema, mut state) = fresh_state();
        let (pk, mut k_digest, sig) = eddsa_valid_triple_for_word(eddsa_test_word(22));
        k_digest[0] ^= 0xff;
        let chunks = pack_eddsa(&pk, &k_digest, &sig);
        let node = LegacyPrecompile::eddsa_verify_node(chunks);
        let err = state.evaluate(&schema, node);
        assert!(matches!(err, Err(SchemaError::AssertionFailed)));
    }
}
