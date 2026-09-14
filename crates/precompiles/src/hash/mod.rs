//! Shared base for hash precompiles.
//!
//! [`HashPrecompile<H>`] implements the generic hash assertion protocol. A hash assertion is one
//! precompile-owned join node framed as `(domain, [ASSERT_OP, n_bytes, 0])` over two
//! `DEFERRED_CHUNKS` children: the preimage bytes and the expected digest bytes.

use alloc::vec::Vec;
use core::marker::PhantomData;

use miden_core::{
    deferred::{DeferredContext, Digest, Node, NodeType, Payload, Precompile, PrecompileError},
    program::domain::DeferredChunksDomain,
};
use miden_crypto::hash::eidos::{DomainTag, EidosDomain, EidosFrame};

use crate::codec::{chunks_to_bytes_exact, n_chunks};

pub mod keccak256;

// HASH FUNCTION
// ================================================================================================

/// The byte-level hash backing a [`HashPrecompile`].
pub trait HashFunction: Default + Send + Sync + 'static {
    /// Human-readable name used for diagnostics.
    const NAME: &'static str;
    /// Registered Eidos domain tag for this hash precompile.
    const DOMAIN: DomainTag;
    /// u32-packed-LE felts in the digest (8 for a 256-bit hash, 16 for 512-bit).
    const DIGEST_FELTS: usize;
    /// Hashes `input`, returning the digest as `DIGEST_FELTS * 4` bytes.
    fn hash(input: &[u8]) -> Vec<u8>;
}

// HASH PRECOMPILE
// ================================================================================================

const ASSERT_DISC: u32 = 0;

/// A structural view of a hash assertion node owned by [`HashPrecompile`].
///
/// This exposes only the assertion frame parameters and join child digests; it does not evaluate
/// the preimage or expected digest children.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashAssertNode {
    /// Declared preimage length in bytes.
    pub n_bytes: u32,
    /// Structural digest of the preimage chunk-list child.
    pub preimage_digest: Digest,
    /// Structural digest of the expected-digest chunk-list child.
    pub expected_digest: Digest,
}

/// A hash assertion precompile parameterized by its [`HashFunction`].
pub struct HashPrecompile<H>(PhantomData<H>);

impl<H> Default for HashPrecompile<H> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<H: HashFunction> HashPrecompile<H> {
    /// Local operation discriminant of the assertion frame.
    pub const ASSERT_OP_ID: u32 = ASSERT_DISC;

    /// Returns this precompile's registered domain.
    pub const fn domain() -> DomainTag {
        H::DOMAIN
    }

    /// Frame for a hash assertion node carrying the preimage byte length.
    pub const fn assert_frame(n_bytes: u32) -> EidosFrame {
        EidosFrame::new(Self::domain(), [ASSERT_DISC, n_bytes, 0])
    }

    /// Builds a hash assertion predicate over generic chunk-list children.
    pub fn assert_node(n_bytes: u32, preimage_digest: Digest, expected_digest: Digest) -> Node {
        Node::join(Self::assert_frame(n_bytes), preimage_digest, expected_digest)
            .expect("assertion frame is precompile-owned")
    }

    /// Decodes a hash assertion frame owned by this precompile.
    ///
    /// Returns `Ok(None)` when `frame` belongs to another precompile. Frames in this domain with
    /// invalid parameters return [`PrecompileError::InvalidNode`].
    pub fn decode_assert_frame(frame: EidosFrame) -> Result<Option<u32>, PrecompileError> {
        if frame.domain() != Self::domain() {
            return Ok(None);
        }

        let [operation, n_bytes, reserved] = frame.params();
        if operation != ASSERT_DISC || reserved != 0 {
            return Err(PrecompileError::InvalidNode);
        }

        Ok(Some(n_bytes))
    }

    /// Decodes a hash assertion node without evaluating its children.
    ///
    /// Returns `Ok(None)` when `node` belongs to another precompile. Owned nodes return their
    /// structural join child digests directly from the payload.
    pub fn decode_assert_node(node: &Node) -> Result<Option<HashAssertNode>, PrecompileError> {
        let Some(frame) = node.frame() else {
            return Ok(None);
        };
        let Some(n_bytes) = Self::decode_assert_frame(frame)? else {
            return Ok(None);
        };
        let (preimage_digest, expected_digest) = node.payload().as_join()?;
        Ok(Some(HashAssertNode {
            n_bytes,
            preimage_digest,
            expected_digest,
        }))
    }

    fn digest_chunks() -> usize {
        H::DIGEST_FELTS.div_ceil(8)
    }
}

impl<H: HashFunction> Precompile for HashPrecompile<H> {
    fn name(&self) -> &'static str {
        H::NAME
    }

    fn domain(&self) -> DomainTag {
        Self::domain()
    }

    fn decode(&self, params: [u32; 3]) -> Option<NodeType> {
        matches!(params, [ASSERT_DISC, _, 0]).then_some(NodeType::Join)
    }

    fn evaluate(
        &self,
        params: [u32; 3],
        payload: &Payload,
        context: &mut DeferredContext<'_>,
    ) -> Result<Node, PrecompileError> {
        let [operation, n_bytes, reserved] = params;
        if operation != ASSERT_DISC || reserved != 0 {
            return Err(PrecompileError::InvalidNode);
        }

        let (preimage_digest, expected_digest) = payload.as_join()?;
        let preimage = chunks_child_to_bytes(
            context,
            preimage_digest,
            n_chunks(n_bytes).get() as usize,
            n_bytes as usize,
        )?;
        let expected = chunks_child_to_bytes(
            context,
            expected_digest,
            Self::digest_chunks(),
            H::DIGEST_FELTS * size_of::<u32>(),
        )?;

        if expected != H::hash(&preimage) {
            return Err(PrecompileError::AssertionFailed);
        }
        Ok(Node::TRUE)
    }
}

fn chunks_child_to_bytes(
    context: &mut DeferredContext<'_>,
    digest: Digest,
    expected_chunks: usize,
    n_bytes: usize,
) -> Result<Vec<u8>, PrecompileError> {
    let canonical_digest = context.evaluate_digest(digest)?;
    let canonical_node = context.get_node(&canonical_digest).ok_or(PrecompileError::InvalidNode)?;
    if canonical_node
        .frame()
        .is_none_or(|frame| frame.domain() != DeferredChunksDomain::TAG)
    {
        return Err(PrecompileError::InvalidNode);
    }
    let chunks = canonical_node.payload().as_data()?;
    chunks_to_bytes_exact(chunks, expected_chunks, n_bytes)
}

// TEST SUPPORT
// ================================================================================================

/// Exercises the shared hash assertion protocol for `H`.
#[cfg(test)]
pub(crate) fn assert_hash_precompile<H: HashFunction>() {
    use alloc::{sync::Arc, vec, vec::Vec};

    use miden_core::{
        Felt, ZERO,
        deferred::{DeferredState, PrecompileRegistry, TRUE_DIGEST, deferred_chunks_frame},
        utils::bytes_to_packed_u32_elements,
    };

    fn chunks_from_bytes(bytes: &[u8]) -> Vec<[Felt; 8]> {
        Node::chunks_from_bytes(bytes)
            .payload()
            .as_data()
            .expect("chunks_from_bytes creates data payload")
            .to_vec()
    }

    fn digest_chunks<H: HashFunction>(input: &[u8]) -> Vec<[Felt; 8]> {
        let mut felts = bytes_to_packed_u32_elements(&H::hash(input));
        felts.resize(HashPrecompile::<H>::digest_chunks() * 8, ZERO);
        felts
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| core::array::from_fn(|i| c[i]))
            .collect()
    }

    let fresh = || {
        DeferredState::new(Arc::new(
            PrecompileRegistry::new().with_precompile(HashPrecompile::<H>::default()),
        ))
        .expect("hash precompile initialization should fit the test budget")
    };
    let assert_registers = |state: &mut DeferredState,
                            n_bytes: u32,
                            preimage_chunks: Vec<[Felt; 8]>,
                            expected_chunks: Vec<[Felt; 8]>|
     -> Result<Digest, PrecompileError> {
        let preimage = state.register(Node::chunks(preimage_chunks).expect("preimage chunks"))?;
        let expected = state.register(Node::chunks(expected_chunks).expect("expected chunks"))?;
        state.register(HashPrecompile::<H>::assert_node(n_bytes, preimage, expected))
    };
    let assert_error = |err: PrecompileError, expected: PrecompileError| {
        assert!(
            matches!(
                (err.root(), &expected),
                (PrecompileError::InvalidNode, PrecompileError::InvalidNode)
                    | (PrecompileError::AssertionFailed, PrecompileError::AssertionFailed)
            ),
            "unexpected error root: {err:?}"
        );
    };

    let pc = HashPrecompile::<H>::default();
    assert_eq!(pc.decode([HashPrecompile::<H>::ASSERT_OP_ID, 65, 0]), Some(NodeType::Join),);
    assert!(pc.decode([1, 65, 0]).is_none());
    assert!(pc.decode([HashPrecompile::<H>::ASSERT_OP_ID, 65, 1]).is_none());

    let assert_frame = HashPrecompile::<H>::assert_frame(65);
    assert_eq!(HashPrecompile::<H>::decode_assert_frame(assert_frame).unwrap(), Some(65));
    assert_eq!(
        HashPrecompile::<H>::decode_assert_frame(deferred_chunks_frame(1)).unwrap(),
        None
    );
    let invalid_assert_frame = EidosFrame::new(HashPrecompile::<H>::domain(), [1, 65, 0]);
    assert!(matches!(
        HashPrecompile::<H>::decode_assert_frame(invalid_assert_frame),
        Err(PrecompileError::InvalidNode)
    ));

    let assert_node = HashPrecompile::<H>::assert_node(65, TRUE_DIGEST, TRUE_DIGEST);
    assert_eq!(HashPrecompile::<H>::decode_assert_node(&Node::TRUE).unwrap(), None);
    assert_eq!(
        HashPrecompile::<H>::decode_assert_node(&assert_node).unwrap(),
        Some(HashAssertNode {
            n_bytes: 65,
            preimage_digest: TRUE_DIGEST,
            expected_digest: TRUE_DIGEST,
        })
    );
    let invalid_node = Node::join(invalid_assert_frame, TRUE_DIGEST, TRUE_DIGEST).unwrap();
    assert!(matches!(
        HashPrecompile::<H>::decode_assert_node(&invalid_node),
        Err(PrecompileError::InvalidNode)
    ));
    let invalid_shape = Node::value(assert_frame, [ZERO; 8]).unwrap();
    assert!(HashPrecompile::<H>::decode_assert_node(&invalid_shape).is_err());

    let input = b"hash assertions consume generic chunks";
    let mut state = fresh();
    let assertion = assert_registers(
        &mut state,
        input.len() as u32,
        chunks_from_bytes(input),
        digest_chunks::<H>(input),
    )
    .expect("matching hash assertion should register");
    assert_eq!(state.evaluate_digest(assertion).unwrap(), TRUE_DIGEST);
    state.log_statement(assertion).expect("true assertion should log");

    let mut wrong = digest_chunks::<H>(input);
    wrong[0][0] = if wrong[0][0] == ZERO { Felt::from_u32(1) } else { ZERO };
    let mut state = fresh();
    let err = assert_registers(&mut state, input.len() as u32, chunks_from_bytes(input), wrong)
        .unwrap_err();
    assert_error(err, PrecompileError::AssertionFailed);

    let too_long: Vec<u8> = (0u8..33).collect();
    let mut state = fresh();
    let err = assert_registers(
        &mut state,
        too_long.len() as u32,
        vec![chunks_from_bytes(&too_long)[0]],
        digest_chunks::<H>(&too_long),
    )
    .unwrap_err();
    assert_error(err, PrecompileError::InvalidNode);

    let mut padded = chunks_from_bytes(&[1, 2, 3]);
    padded[0][0] = Felt::from_u32(u32::from_le_bytes([1, 2, 3, 0xaa]));
    let mut state = fresh();
    let err = assert_registers(&mut state, 3, padded, digest_chunks::<H>(&[1, 2, 3])).unwrap_err();
    assert_error(err, PrecompileError::InvalidNode);

    let non_u32 = Felt::new_unchecked(u64::from(u32::MAX) + 1);
    let mut preimage = chunks_from_bytes(input);
    preimage[0][0] = non_u32;
    let mut state = fresh();
    let err = assert_registers(&mut state, input.len() as u32, preimage, digest_chunks::<H>(input))
        .unwrap_err();
    assert_error(err, PrecompileError::InvalidNode);

    let mut expected = digest_chunks::<H>(input);
    expected[0][0] = non_u32;
    let mut state = fresh();
    let err = assert_registers(&mut state, input.len() as u32, chunks_from_bytes(input), expected)
        .unwrap_err();
    assert_error(err, PrecompileError::InvalidNode);

    let precompile_owned_data = Node::try_data(
        HashPrecompile::<H>::assert_frame(input.len() as u32),
        chunks_from_bytes(input),
    )
    .expect("data node is syntactically constructible");
    let mut state = fresh();
    let preimage = state.register(precompile_owned_data).unwrap_err();
    assert_error(preimage, PrecompileError::InvalidNode);

    let mut state = fresh();
    let zero = assert_registers(&mut state, 0, vec![[ZERO; 8]], digest_chunks::<H>(&[]))
        .expect("zero-byte hash assertion should register");
    assert_eq!(state.evaluate_digest(zero).unwrap(), TRUE_DIGEST);

    let mut state = fresh();
    let preimage_chunks = chunks_from_bytes(input);
    let expected_chunks = digest_chunks::<H>(input);
    let preimage = state.register(Node::chunks(preimage_chunks).unwrap()).unwrap();
    let expected = state.register(Node::chunks(expected_chunks).unwrap()).unwrap();
    let assertion_node = HashPrecompile::<H>::assert_node(input.len() as u32, preimage, expected);
    let assertion = state.register(assertion_node).unwrap();
    state.log_statement(assertion).unwrap();
    let wire = state.to_wire().expect("hash assertion state should encode");
    let mut rehydrated = DeferredState::from_wire(
        Arc::new(PrecompileRegistry::new().with_precompile(HashPrecompile::<H>::default())),
        &wire,
    )
    .expect("wire should rehydrate under the hash registry");
    assert_eq!(rehydrated.evaluate_digest(rehydrated.root()).unwrap(), TRUE_DIGEST);
}
