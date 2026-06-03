//! Shared base for deferred hash precompiles (keccak256, sha512, ...).
//!
//! Every hash precompile shares the same tag layout `Tag { id, args: [disc, arg1, ZERO] }`, the
//! same three nodes — `preimage` (data-bodied, hashes to a digest), `digest` (self-evaluating
//! data), `eq` (binary predicate asserting two digests match) — and the same deferred-DAG protocol.
//! A concrete hash supplies only its [`HashFunction`]: the name, the digest width, and the
//! byte-level hash. [`HashPrecompile<H>`] turns that into a full [`Precompile`].

use alloc::{sync::Arc, vec::Vec};
use core::{marker::PhantomData, num::NonZeroU32};

use miden_core::{
    Felt, ZERO,
    deferred::{
        DeferredContext, Digest, Node, NodeType, Payload, Precompile, PrecompileError, Tag,
        precompile_id,
    },
    utils::bytes_to_packed_u32_elements,
};

use crate::codec::{chunks_to_bytes, n_chunks};

pub mod keccak256;
pub mod sha512;

// HASH FUNCTION
// ================================================================================================

/// The byte-level hash backing a [`HashPrecompile`].
pub trait HashFunction: Default + Send + Sync + 'static {
    /// Stable name hashed into the precompile id; renaming changes every tag it owns.
    const NAME: &'static str;
    /// u32-packed-LE felts in the digest (8 for a 256-bit hash, 16 for 512-bit).
    const DIGEST_FELTS: usize;
    /// Hashes `input`, returning the digest as `DIGEST_FELTS * 4` bytes.
    fn hash(input: &[u8]) -> Vec<u8>;
}

// TAG DISCRIMINANTS
// ================================================================================================

const PREIMAGE_DISC: u32 = 0;
const DIGEST_DISC: u32 = 1;
const EQ_DISC: u32 = 2;

// HASH PRECOMPILE
// ================================================================================================

/// A deferred hash precompile parameterized by its [`HashFunction`].
pub struct HashPrecompile<H>(PhantomData<H>);

impl<H> Default for HashPrecompile<H> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<H: HashFunction> HashPrecompile<H> {
    /// Local discriminant of the `preimage` tag.
    pub const PREIMAGE_TAG_ID: u32 = PREIMAGE_DISC;
    /// Local discriminant of the `digest` tag.
    pub const DIGEST_TAG_ID: u32 = DIGEST_DISC;
    /// Local discriminant of the `eq` tag.
    pub const EQ_TAG_ID: u32 = EQ_DISC;

    /// Derives this precompile's id from its [`HashFunction::NAME`].
    pub fn id() -> Felt {
        precompile_id(H::NAME)
    }

    /// Tag for a `preimage` data node carrying `n_bytes` of input.
    pub fn preimage_tag(n_bytes: u32) -> Tag {
        Self::tag([Felt::from_u32(PREIMAGE_DISC), Felt::from_u32(n_bytes), ZERO])
    }

    /// Tag for the canonical `digest` data node.
    pub fn digest_tag() -> Tag {
        Self::tag([Felt::from_u32(DIGEST_DISC), ZERO, ZERO])
    }

    /// Tag for an `eq` predicate node.
    pub fn eq_tag() -> Tag {
        Self::tag([Felt::from_u32(EQ_DISC), ZERO, ZERO])
    }

    fn tag(args: [Felt; 3]) -> Tag {
        Tag::precompile(Self::id(), args).expect("hash precompile id is not framework-reserved")
    }

    /// Builds a `preimage` data node from caller-supplied 8-felt chunks (the input u32-packed-LE,
    /// zero-padded to a chunk boundary).
    pub fn preimage_node(n_bytes: u32, chunks: impl Into<Arc<[[Felt; 8]]>>) -> Node {
        Node::try_data(Self::preimage_tag(n_bytes), chunks)
            .expect("preimage requires at least one data chunk")
    }

    /// Builds the canonical `digest` node: the `DIGEST_FELTS` u32-packed felts encoded as
    /// `ceil(DIGEST_FELTS / 8)` eight-felt chunks, zero-padded to the chunk boundary — a single,
    /// width-agnostic encoding.
    pub fn digest_node(felts: &[Felt]) -> Node {
        debug_assert_eq!(felts.len(), H::DIGEST_FELTS, "digest must be DIGEST_FELTS felts");
        let mut padded = felts.to_vec();
        padded.resize(Self::digest_chunks() * 8, ZERO);
        let chunks: Vec<[Felt; 8]> = padded
            .chunks_exact(8)
            .map(|c| c.try_into().expect("chunk is 8 felts"))
            .collect();
        Node::try_data(Self::digest_tag(), chunks).expect("digest uses at least one data chunk")
    }

    /// Builds an `eq` predicate over two child digests.
    pub fn eq_node(lhs: Digest, rhs: Digest) -> Node {
        Node::join(Self::eq_tag(), lhs, rhs).expect("eq tag is precompile-owned")
    }

    /// Number of eight-felt chunks in the canonical digest node.
    fn digest_chunks() -> usize {
        H::DIGEST_FELTS.div_ceil(8)
    }

    /// Body shape of the `digest` node — `ceil(DIGEST_FELTS / 8)` data chunks for every width.
    fn digest_node_type() -> NodeType {
        NodeType::Data(
            NonZeroU32::new(Self::digest_chunks() as u32).expect("digest spans >= 1 chunk"),
        )
    }
}

impl<H: HashFunction> Precompile for HashPrecompile<H> {
    fn name(&self) -> &'static str {
        H::NAME
    }

    fn id(&self) -> Felt {
        Self::id()
    }

    fn decode(&self, args: [Felt; 3]) -> Option<NodeType> {
        let disc = u32::try_from(args[0].as_canonical_u64()).ok()?;
        match disc {
            PREIMAGE_DISC if args[2] == ZERO => {
                let n_bytes = u32::try_from(args[1].as_canonical_u64()).ok()?;
                Some(NodeType::Data(n_chunks(n_bytes)))
            },
            DIGEST_DISC if args[1] == ZERO && args[2] == ZERO => Some(Self::digest_node_type()),
            EQ_DISC if args[1] == ZERO && args[2] == ZERO => Some(NodeType::Join),
            _ => None,
        }
    }

    fn evaluate(
        &self,
        args: [Felt; 3],
        payload: &Payload,
        context: &mut DeferredContext<'_>,
    ) -> Result<Node, PrecompileError> {
        let disc =
            u32::try_from(args[0].as_canonical_u64()).map_err(|_| PrecompileError::InvalidNode)?;
        match disc {
            PREIMAGE_DISC => evaluate_preimage::<H>(args, payload),
            DIGEST_DISC => Ok(Node::try_data(Self::tag(args), payload.as_data()?.to_vec())?),
            EQ_DISC => evaluate_eq::<H>(payload, context),
            _ => Err(PrecompileError::InvalidNode),
        }
    }
}

/// Evaluates a `preimage` data node: unpack chunks to bytes (stripping zero-pad down to the
/// `n_bytes` carried in `args[1]`), hash, and emit the canonical `digest` node.
fn evaluate_preimage<H: HashFunction>(
    args: [Felt; 3],
    payload: &Payload,
) -> Result<Node, PrecompileError> {
    let n_bytes = u32::try_from(args[1].as_canonical_u64())
        .map_err(|_| PrecompileError::InvalidNode)? as usize;
    let bytes = chunks_to_bytes(payload.as_data()?, n_bytes)?;
    let felts = bytes_to_packed_u32_elements(&H::hash(&bytes));
    debug_assert_eq!(felts.len(), H::DIGEST_FELTS, "hash packs to DIGEST_FELTS felts");
    Ok(HashPrecompile::<H>::digest_node(&felts))
}

/// Evaluates an `eq` predicate: resolve both children, require both are this hash's `digest`
/// leaves, and assert their payloads match.
fn evaluate_eq<H: HashFunction>(
    payload: &Payload,
    context: &mut DeferredContext<'_>,
) -> Result<Node, PrecompileError> {
    let (lhs_digest, rhs_digest) = payload.as_join()?;
    let (lhs_digest, rhs_digest) = context.evaluate_digest_pair(lhs_digest, rhs_digest)?;
    let lhs = context.get_node(&lhs_digest).ok_or(PrecompileError::InvalidNode)?;
    let rhs = context.get_node(&rhs_digest).ok_or(PrecompileError::InvalidNode)?;
    let digest_tag = HashPrecompile::<H>::digest_tag();
    if lhs.tag() != digest_tag || rhs.tag() != digest_tag {
        return Err(PrecompileError::InvalidNode);
    }
    if lhs.payload() != rhs.payload() {
        return Err(PrecompileError::AssertionFailed);
    }
    Ok(Node::TRUE)
}

// TEST SUPPORT
// ================================================================================================

/// Parses a `const NAME = VALUE` line out of a MASM source as a `u64`. Shared by the per-hash
/// `masm_pinned_ids_match_derived_ids` tests.
#[cfg(test)]
pub(crate) fn masm_const(source: &str, name: &str) -> u64 {
    source
        .lines()
        .filter_map(|line| line.trim().strip_prefix("const "))
        .find_map(|assignment| {
            let (const_name, value) = assignment.split_once(" = ")?;
            (const_name == name).then(|| value.parse().ok()).flatten()
        })
        .expect("MASM const must be present and parse as u64")
}

/// Exercises the shared hash-precompile behavior for `H`: tag decoding, preimage evaluation across
/// chunk boundaries, the `eq` predicate, and the malformed-input rejections. Each concrete hash
/// calls this from its own test module; end-to-end hash correctness is pinned by the package
/// integration tests.
#[cfg(test)]
pub(crate) fn assert_hash_precompile<H: HashFunction>() {
    use alloc::{sync::Arc, vec, vec::Vec};

    use miden_core::deferred::{DeferredState, PrecompileRegistry};

    fn pack_chunks(bytes: &[u8]) -> Vec<[Felt; 8]> {
        let mut felts = bytes_to_packed_u32_elements(bytes);
        let n = felts.len().div_ceil(8).max(1);
        felts.resize(n * 8, ZERO);
        felts.chunks_exact(8).map(|c| core::array::from_fn(|i| c[i])).collect()
    }

    let fresh = || {
        DeferredState::new(
            Arc::new(PrecompileRegistry::new().with_precompile(HashPrecompile::<H>::default())),
            usize::MAX,
        )
        .expect("hash precompile initialization should fit the test budget")
    };
    let evaluate = |state: &mut DeferredState, node: Node| -> Result<Node, PrecompileError> {
        let digest = state.register(node)?;
        let canonical = state.evaluate_digest(digest)?;
        state.get_node(&canonical).cloned().ok_or(PrecompileError::InvalidNode)
    };

    // -- decode routes each tag to its node shape and rejects malformed tags --
    let pc = HashPrecompile::<H>::default();
    assert!(matches!(
        pc.decode([Felt::from_u32(HashPrecompile::<H>::PREIMAGE_TAG_ID), Felt::from_u32(65), ZERO]),
        Some(NodeType::Data(n)) if n.get() == 3
    ));
    assert_eq!(
        pc.decode([Felt::from_u32(HashPrecompile::<H>::DIGEST_TAG_ID), ZERO, ZERO]),
        Some(HashPrecompile::<H>::digest_node_type()),
    );
    assert_eq!(
        pc.decode([Felt::from_u32(HashPrecompile::<H>::EQ_TAG_ID), ZERO, ZERO]),
        Some(NodeType::Join),
    );
    assert!(pc.decode([Felt::from_u32(99), ZERO, ZERO]).is_none());
    // unused tag args must be zero
    let one = Felt::from_u32(1);
    assert!(
        pc.decode([Felt::from_u32(HashPrecompile::<H>::PREIMAGE_TAG_ID), Felt::from_u32(1), one])
            .is_none()
    );
    assert!(
        pc.decode([Felt::from_u32(HashPrecompile::<H>::DIGEST_TAG_ID), one, ZERO])
            .is_none()
    );
    assert!(pc.decode([Felt::from_u32(HashPrecompile::<H>::EQ_TAG_ID), ZERO, one]).is_none());

    // -- preimage evaluates to the digest of the hashed bytes, across chunk boundaries --
    for &n in &[0usize, 11, 70] {
        let mut state = fresh();
        let input: Vec<u8> = (0..n).map(|i| i as u8).collect();
        let node = HashPrecompile::<H>::preimage_node(n as u32, pack_chunks(&input));
        let got = evaluate(&mut state, node).unwrap();
        let want =
            HashPrecompile::<H>::digest_node(&bytes_to_packed_u32_elements(&H::hash(&input)));
        assert_eq!(got, want, "preimage of {n} bytes");
    }

    // -- eq accepts a matching (preimage, digest) and rejects a forged digest --
    {
        let mut state = fresh();
        let input = b"hash precompile eq";
        let preimage = state
            .register(HashPrecompile::<H>::preimage_node(input.len() as u32, pack_chunks(input)))
            .unwrap();
        let leaf = state
            .register(HashPrecompile::<H>::digest_node(&bytes_to_packed_u32_elements(&H::hash(
                input,
            ))))
            .unwrap();
        assert!(
            evaluate(&mut state, HashPrecompile::<H>::eq_node(preimage, leaf))
                .unwrap()
                .is_true()
        );

        let forged = state
            .register(HashPrecompile::<H>::digest_node(&vec![
                Felt::from_u32(0xdead);
                H::DIGEST_FELTS
            ]))
            .unwrap();
        let err = evaluate(&mut state, HashPrecompile::<H>::eq_node(preimage, forged));
        assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
    }

    // -- preimage rejects an oversized n_bytes for the chunk count, and nonzero trailing pad --
    {
        let mut state = fresh();
        let node = HashPrecompile::<H>::preimage_node(100, vec![[ZERO; 8]]);
        assert!(matches!(
            evaluate(&mut state, node).unwrap_err().root(),
            PrecompileError::InvalidNode
        ));
    }
    {
        let mut state = fresh();
        let mut chunks = pack_chunks(&[1, 2, 3]);
        chunks[0][0] = Felt::from_u32(u32::from_le_bytes([1, 2, 3, 0xaa]));
        let node = HashPrecompile::<H>::preimage_node(3, chunks);
        assert!(matches!(
            evaluate(&mut state, node).unwrap_err().root(),
            PrecompileError::InvalidNode
        ));
    }
}
