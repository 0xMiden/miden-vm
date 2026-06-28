//! Shared base for deferred hash precompiles.

use alloc::vec::Vec;
use core::marker::PhantomData;

use miden_core::{
    Felt, ZERO,
    deferred::{
        DeferredContext, Digest, Node, NodeType, Payload, Precompile, PrecompileError, Tag,
        precompile_id,
    },
};

use crate::codec::{chunks_to_bytes, n_chunks};

pub(crate) mod handlers;
pub mod keccak256;
pub mod sha512;

// HASH FUNCTION
// ================================================================================================

/// The byte-level hash backing a [`HashPrecompile`].
pub trait HashFunction: Default + Send + Sync + 'static {
    /// Stable name hashed into the precompile id; renaming changes every tag it owns.
    const NAME: &'static str;
    /// u32-packed-LE felts in the digest.
    const DIGEST_FELTS: usize;
    /// Hashes `input`, returning the digest as `DIGEST_FELTS * 4` bytes.
    fn hash(input: &[u8]) -> Vec<u8>;
}

// HASH PRECOMPILE
// ================================================================================================

const ASSERT_DISC: u32 = 0;
const PREIMAGE_DISC: u32 = 1;
const DIGEST_DISC: u32 = 2;

/// A deferred hash assertion precompile parameterized by its [`HashFunction`].
///
/// Hash wrappers register two hash-owned data nodes and one assertion node:
///
/// - `[hash_id, PREIMAGE_DISC, n_bytes, 0]` stores the u32-packed preimage chunks.
/// - `[hash_id, DIGEST_DISC, 0, 0]` stores the expected digest chunks.
/// - `[hash_id, ASSERT_DISC, n_bytes, 0]` joins those children and evaluates to TRUE only when the
///   expected digest equals `H(preimage)`.
pub struct HashPrecompile<H>(PhantomData<H>);

impl<H> Default for HashPrecompile<H> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<H: HashFunction> HashPrecompile<H> {
    /// Local discriminant of the assertion tag.
    pub const ASSERT_TAG_ID: u32 = ASSERT_DISC;
    /// Local discriminant of preimage data nodes.
    pub const PREIMAGE_TAG_ID: u32 = PREIMAGE_DISC;
    /// Local discriminant of digest data nodes.
    pub const DIGEST_TAG_ID: u32 = DIGEST_DISC;

    /// Derives this precompile's id from its [`HashFunction::NAME`].
    pub fn id() -> Felt {
        precompile_id(H::NAME)
    }

    /// Tag for a hash assertion node carrying the preimage byte length.
    pub fn assert_tag(n_bytes: u32) -> Tag {
        Self::tag([Felt::from_u32(ASSERT_DISC), Felt::from_u32(n_bytes), ZERO])
    }

    /// Tag for the preimage data node used by the assertion.
    pub fn preimage_tag(n_bytes: u32) -> Tag {
        Self::tag([Felt::from_u32(PREIMAGE_DISC), Felt::from_u32(n_bytes), ZERO])
    }

    /// Tag for the expected digest data node used by the assertion.
    pub fn digest_tag() -> Tag {
        Self::tag([Felt::from_u32(DIGEST_DISC), ZERO, ZERO])
    }

    /// Builds a hash assertion predicate over registered preimage and digest children.
    pub fn assert_node(n_bytes: u32, preimage_digest: Digest, expected_digest: Digest) -> Node {
        Node::join(Self::assert_tag(n_bytes), preimage_digest, expected_digest)
            .expect("assert tag is precompile-owned")
    }

    fn tag(args: [Felt; 3]) -> Tag {
        Tag::precompile(Self::id(), args).expect("hash precompile id is not framework-reserved")
    }

    fn digest_chunks() -> u32 {
        H::DIGEST_FELTS.div_ceil(8) as u32
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
        if args[2] != ZERO {
            return None;
        }

        match disc {
            ASSERT_DISC => {
                u32::try_from(args[1].as_canonical_u64()).ok()?;
                Some(NodeType::Join)
            },
            PREIMAGE_DISC => {
                let n_bytes = u32::try_from(args[1].as_canonical_u64()).ok()?;
                Some(NodeType::data_chunks(n_chunks(n_bytes).get())?)
            },
            DIGEST_DISC if args[1] == ZERO => Some(NodeType::data_chunks(Self::digest_chunks())?),
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
        if args[2] != ZERO {
            return Err(PrecompileError::InvalidNode);
        }

        match disc {
            ASSERT_DISC => {
                let n_bytes = u32::try_from(args[1].as_canonical_u64())
                    .map_err(|_| PrecompileError::InvalidNode)?;
                let (preimage_digest, expected_digest) = payload.as_join()?;
                let preimage = data_child_to_bytes(
                    context,
                    preimage_digest,
                    Self::preimage_tag(n_bytes),
                    n_bytes as usize,
                )?;
                let expected = data_child_to_bytes(
                    context,
                    expected_digest,
                    Self::digest_tag(),
                    H::DIGEST_FELTS * size_of::<u32>(),
                )?;

                if expected != H::hash(&preimage) {
                    return Err(PrecompileError::AssertionFailed);
                }
                Ok(Node::TRUE)
            },
            PREIMAGE_DISC | DIGEST_DISC => {
                let tag = Tag::precompile(Self::id(), args).map_err(PrecompileError::Other)?;
                Ok(Node::try_data(tag, payload.as_data()?.to_vec())?)
            },
            _ => Err(PrecompileError::InvalidNode),
        }
    }
}

fn data_child_to_bytes(
    context: &mut DeferredContext<'_>,
    digest: Digest,
    expected_tag: Tag,
    n_bytes: usize,
) -> Result<Vec<u8>, PrecompileError> {
    let canonical_digest = context.evaluate_digest(digest)?;
    let canonical_node = context.get_node(&canonical_digest).ok_or(PrecompileError::InvalidNode)?;
    if canonical_node.tag() != expected_tag {
        return Err(PrecompileError::InvalidNode);
    }
    chunks_to_bytes(canonical_node.payload().as_data()?, n_bytes)
}

// TEST SUPPORT
// ================================================================================================

/// Exercises the shared hash assertion protocol for `H`.
#[cfg(test)]
pub(crate) fn assert_hash_precompile<H: HashFunction>() {
    use alloc::{sync::Arc, vec, vec::Vec};

    use miden_core::{
        deferred::{DeferredState, PrecompileRegistry, TRUE_DIGEST, WireEntry},
        utils::bytes_to_packed_u32_elements,
    };

    fn pack_chunks(bytes: &[u8]) -> Vec<[Felt; 8]> {
        let mut felts = bytes_to_packed_u32_elements(bytes);
        let n = felts.len().div_ceil(8).max(1);
        felts.resize(n * 8, ZERO);
        felts.chunks_exact(8).map(|c| core::array::from_fn(|i| c[i])).collect()
    }

    fn digest_chunks<H: HashFunction>(input: &[u8]) -> Vec<[Felt; 8]> {
        let mut felts = bytes_to_packed_u32_elements(&H::hash(input));
        felts.resize(HashPrecompile::<H>::digest_chunks() as usize * 8, ZERO);
        felts.chunks_exact(8).map(|c| core::array::from_fn(|i| c[i])).collect()
    }

    let fresh = || {
        DeferredState::new(
            Arc::new(PrecompileRegistry::new().with_precompile(HashPrecompile::<H>::default())),
            usize::MAX,
        )
        .expect("hash precompile initialization should fit the test budget")
    };
    let assert_registers = |state: &mut DeferredState,
                            n_bytes: u32,
                            preimage_chunks: Vec<[Felt; 8]>,
                            expected_chunks: Vec<[Felt; 8]>|
     -> Result<Digest, PrecompileError> {
        let preimage = state.register(Node::try_data(
            HashPrecompile::<H>::preimage_tag(n_bytes),
            preimage_chunks,
        )?)?;
        let expected =
            state.register(Node::try_data(HashPrecompile::<H>::digest_tag(), expected_chunks)?)?;
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
    assert_eq!(
        pc.decode([Felt::from_u32(HashPrecompile::<H>::ASSERT_TAG_ID), Felt::from_u32(65), ZERO]),
        Some(NodeType::Join),
    );
    assert_eq!(
        pc.decode(
            [Felt::from_u32(HashPrecompile::<H>::PREIMAGE_TAG_ID), Felt::from_u32(65), ZERO,]
        ),
        Some(NodeType::data_chunks(3).unwrap()),
    );
    assert_eq!(
        pc.decode([Felt::from_u32(HashPrecompile::<H>::DIGEST_TAG_ID), ZERO, ZERO]),
        Some(NodeType::data_chunks(HashPrecompile::<H>::digest_chunks()).unwrap()),
    );
    assert!(pc.decode([Felt::from_u32(9), ZERO, ZERO]).is_none());
    assert!(
        pc.decode([
            Felt::from_u32(HashPrecompile::<H>::ASSERT_TAG_ID),
            Felt::from_u32(65),
            Felt::from_u32(1),
        ])
        .is_none()
    );
    let non_u32 = Felt::new_unchecked(u64::from(u32::MAX) + 1);
    assert!(pc.decode([non_u32, ZERO, ZERO]).is_none());
    assert!(
        pc.decode([Felt::from_u32(HashPrecompile::<H>::ASSERT_TAG_ID), non_u32, ZERO])
            .is_none()
    );

    let input = b"hash assertions consume owned chunks";
    let mut state = fresh();
    let assertion = assert_registers(
        &mut state,
        input.len() as u32,
        pack_chunks(input),
        digest_chunks::<H>(input),
    )
    .expect("matching hash assertion should register");
    assert_eq!(state.evaluate_digest(assertion).unwrap(), TRUE_DIGEST);
    state.log_statement(assertion).expect("true assertion should log");

    let mut wrong = digest_chunks::<H>(input);
    wrong[0][0] = if wrong[0][0] == ZERO { Felt::from_u32(1) } else { ZERO };
    let mut state = fresh();
    let err =
        assert_registers(&mut state, input.len() as u32, pack_chunks(input), wrong).unwrap_err();
    assert_error(err, PrecompileError::AssertionFailed);

    let too_long: Vec<u8> = (0u8..33).collect();
    let mut state = fresh();
    let err = assert_registers(
        &mut state,
        too_long.len() as u32,
        vec![pack_chunks(&too_long)[0]],
        digest_chunks::<H>(&too_long),
    )
    .unwrap_err();
    assert_error(err, PrecompileError::InvalidNode);

    let mut padded = pack_chunks(&[1, 2, 3]);
    padded[0][0] = Felt::from_u32(u32::from_le_bytes([1, 2, 3, 0xaa]));
    let mut state = fresh();
    let err = assert_registers(&mut state, 3, padded, digest_chunks::<H>(&[1, 2, 3])).unwrap_err();
    assert_error(err, PrecompileError::InvalidNode);

    let non_u32 = Felt::new_unchecked(u64::from(u32::MAX) + 1);
    let mut preimage = pack_chunks(input);
    preimage[0][0] = non_u32;
    let mut state = fresh();
    let err = assert_registers(&mut state, input.len() as u32, preimage, digest_chunks::<H>(input))
        .unwrap_err();
    assert_error(err, PrecompileError::InvalidNode);

    let mut expected = digest_chunks::<H>(input);
    expected[0][0] = non_u32;
    let mut state = fresh();
    let err =
        assert_registers(&mut state, input.len() as u32, pack_chunks(input), expected).unwrap_err();
    assert_error(err, PrecompileError::InvalidNode);

    let precompile_owned_data =
        Node::try_data(HashPrecompile::<H>::assert_tag(input.len() as u32), pack_chunks(input))
            .expect("data node is syntactically constructible");
    let mut state = fresh();
    let preimage = state.register(precompile_owned_data).unwrap_err();
    assert_error(preimage, PrecompileError::InvalidNode);

    let mut state = fresh();
    let zero = assert_registers(&mut state, 0, vec![[ZERO; 8]], digest_chunks::<H>(&[]))
        .expect("zero-byte hash assertion should register");
    assert_eq!(state.evaluate_digest(zero).unwrap(), TRUE_DIGEST);

    let mut state = fresh();
    let preimage_chunks = pack_chunks(input);
    let expected_chunks = digest_chunks::<H>(input);
    let preimage = state
        .register(
            Node::try_data(HashPrecompile::<H>::preimage_tag(input.len() as u32), preimage_chunks)
                .unwrap(),
        )
        .unwrap();
    let expected = state
        .register(Node::try_data(HashPrecompile::<H>::digest_tag(), expected_chunks).unwrap())
        .unwrap();
    let assertion_node = HashPrecompile::<H>::assert_node(input.len() as u32, preimage, expected);
    let assertion = state.register(assertion_node).unwrap();
    state.log_statement(assertion).unwrap();
    let wire = state.to_wire().expect("hash assertion state should encode");
    assert!(wire.entries.iter().any(|entry| matches!(
        entry,
        WireEntry::Join { tag, .. } if *tag == HashPrecompile::<H>::assert_tag(input.len() as u32)
    )));
    let mut rehydrated = DeferredState::from_wire(
        Arc::new(PrecompileRegistry::new().with_precompile(HashPrecompile::<H>::default())),
        &wire,
        usize::MAX,
    )
    .expect("wire should rehydrate under the hash registry");
    assert_eq!(rehydrated.evaluate_digest(rehydrated.root()).unwrap(), TRUE_DIGEST);
}
