//! Canary integration test for the chunk-node variant of the deferred-DAG public API.
//!
//! Defines a tiny reference precompile that:
//! - Decodes its immediate felts to pick between "preimage chunk", "digest leaf", and "assert
//!   equal" roles, reading `n` for chunks out of the second immediate felt.
//! - `reduce` for a chunk computes a tiny "rolling sum" hash (definitely not a real hash — the
//!   framework doesn't care, the precompile picks the function) and returns an expression
//!   digest-leaf.
//! - `reduce` for the assertion predicate compares the two operands canonically and returns
//!   `Node::TRUE` on match.
//!
//! This is the canonical demonstration that `Precompile::decode + Precompile::reduce + ChunkNode`
//! are sufficient to model "preimage hashes to digest" as a predicate in the deferred DAG.

use miden_core::{
    Felt, ZERO,
    deferred::{
        DeferredState, Node, NodeType, Payload, Precompile, PrecompileError, PrecompileRegistry,
        Tag, WitnessBuilder, precompile_id,
    },
};

// TEST PRECOMPILE — non-native "rolling sum" hash
// ================================================================================================

/// Role marker for chunk preimage. The second immediate felt holds `n` (the chunk count).
const PREIMAGE_ROLE: Felt = Felt::new_unchecked(0);
/// Role marker for digest leaf.
const DIGEST_ROLE: Felt = Felt::new_unchecked(1);
/// Role marker for an assertion equating two digests.
const ASSERT_ROLE: Felt = Felt::new_unchecked(2);

#[derive(Debug, Default, Clone, Copy)]
struct ChunkTestPrecompile;

impl ChunkTestPrecompile {
    const NAME: &'static str = "chunk_test";

    fn id() -> Felt {
        precompile_id(&ChunkTestPrecompile)
    }

    /// "Hash" `chunks` by summing every felt limb-wise into an 8-felt accumulator. Replace with
    /// a real non-native hash in production precompiles — the framework doesn't constrain this.
    fn fake_hash(chunks: &[[Felt; 8]]) -> [Felt; 8] {
        let mut acc = [ZERO; 8];
        for c in chunks {
            for (a, x) in acc.iter_mut().zip(c.iter()) {
                *a += *x;
            }
        }
        acc
    }
}

fn preimage_tag(n: u32) -> Tag {
    Tag {
        id: ChunkTestPrecompile::id(),
        args: [PREIMAGE_ROLE, Felt::from_u32(n), ZERO],
    }
}

fn digest_tag() -> Tag {
    Tag {
        id: ChunkTestPrecompile::id(),
        args: [DIGEST_ROLE, ZERO, ZERO],
    }
}

fn assert_tag() -> Tag {
    Tag {
        id: ChunkTestPrecompile::id(),
        args: [ASSERT_ROLE, ZERO, ZERO],
    }
}

impl Precompile for ChunkTestPrecompile {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn id(&self) -> Felt {
        Self::id()
    }

    fn decode(&self, args: [Felt; 3]) -> Option<NodeType> {
        let [role, n, _] = args;
        match role {
            // Preimage chunk reduces to a digest leaf; `n` is the chunk count.
            r if r == PREIMAGE_ROLE => Some(NodeType::Chunks(n.as_canonical_u64() as u32)),
            // Digest leaf is self-evaluating with 8 raw felts.
            r if r == DIGEST_ROLE && n == ZERO => Some(NodeType::Value),
            // Assertion is a binary predicate (two child digests, evaluates to TRUE).
            r if r == ASSERT_ROLE && n == ZERO => Some(NodeType::Join),
            _ => None,
        }
    }

    fn reduce(
        &self,
        args: [Felt; 3],
        payload: &Payload,
        witness: &mut WitnessBuilder<'_>,
    ) -> Result<Node, PrecompileError> {
        let [role, ..] = args;
        if role == ASSERT_ROLE {
            let (lhs, rhs) = payload.join_children()?;
            if witness.resolve(lhs)? != witness.resolve(rhs)? {
                return Err(PrecompileError::AssertionFailed);
            }
            return Ok(Node::TRUE);
        }
        match payload {
            // Preimage chunk reduces to its digest leaf.
            Payload::Chunk(chunks) => Ok(Node::leaf(digest_tag(), Self::fake_hash(chunks))),
            // Digest leaf is self-evaluating.
            Payload::Expression(f) => Ok(Node::leaf(Tag::new(Self::id(), args), *f)),
        }
    }
}

// HELPERS
// ================================================================================================

fn chunk_data(n: u32) -> Vec<[Felt; 8]> {
    (0..n)
        .map(|i| core::array::from_fn(|j| Felt::from_u32(1 + i * 8 + j as u32)))
        .collect()
}

// TESTS
// ================================================================================================

#[test]
fn chunk_digest_for_n1_matches_equivalent_expression() {
    // Sanity check: an `n=1` chunk and an expression with the same tag and same 8 felts should
    // have identical digests. The chunk-digest body reduces to "fill rate, one permutation" for
    // n=1, which is exactly the standard expression digest body.
    let tag = preimage_tag(1);
    let data = chunk_data(1);
    let chunk = Node::chunk(tag, data.clone());
    let expr = Node::leaf(tag, data[0]);
    assert_eq!(chunk.digest(), expr.digest());
}

#[test]
fn register_chunk_stores_node() {
    let schema = PrecompileRegistry::default().with_precompile(ChunkTestPrecompile);
    let mut state = DeferredState::new();
    let chunk = Node::chunk(preimage_tag(3), chunk_data(3));
    let digest = state.register(&schema, chunk.clone()).unwrap();
    assert_eq!(digest, chunk.digest());
    assert_eq!(state.get(&digest).unwrap(), &chunk);
}

#[test]
fn register_chunk_with_mismatched_length_fails() {
    let schema = PrecompileRegistry::default().with_precompile(ChunkTestPrecompile);
    let mut state = DeferredState::new();
    // Tag declares n=3 but we hand it 2 chunks of data.
    let bad = Node::chunk(preimage_tag(3), chunk_data(2));
    assert!(matches!(state.register(&schema, bad), Err(PrecompileError::InvalidNode)));
}

#[test]
fn predicate_preimage_equals_digest_succeeds() {
    let schema = PrecompileRegistry::default().with_precompile(ChunkTestPrecompile);
    let mut state = DeferredState::new();

    // Register a 3-chunk preimage.
    let chunks = chunk_data(3);
    let preimage = Node::chunk(preimage_tag(3), chunks.clone());
    let preimage_digest = state.register(&schema, preimage).unwrap();

    // Pre-compute and register the matching digest leaf.
    let digest_leaf = Node::leaf(digest_tag(), ChunkTestPrecompile::fake_hash(&chunks));
    let digest_leaf_digest = state.register(&schema, digest_leaf).unwrap();

    // Predicate: preimage's digest == precomputed digest leaf. Reduce drives the chunk's hash
    // and compares against the precomputed leaf, returning the TRUE node on match.
    let assertion = Node::join(assert_tag(), preimage_digest, digest_leaf_digest);
    state.register(&schema, assertion.clone()).unwrap();
    let result = state.evaluate(&schema, assertion).unwrap();
    assert!(result.is_true_node());
}

#[test]
fn predicate_preimage_mismatch_fails_on_evaluate() {
    let schema = PrecompileRegistry::default().with_precompile(ChunkTestPrecompile);
    let mut state = DeferredState::new();

    let chunks = chunk_data(2);
    let preimage = Node::chunk(preimage_tag(2), chunks);
    let preimage_digest = state.register(&schema, preimage).unwrap();

    // A digest leaf with the wrong content — predicate must fail when verified.
    let wrong_leaf = Node::leaf(digest_tag(), [Felt::from_u32(99); 8]);
    let wrong_leaf_digest = state.register(&schema, wrong_leaf).unwrap();

    let assertion = Node::join(assert_tag(), preimage_digest, wrong_leaf_digest);
    // Register is a pure hint — succeeds even when the predicate doesn't hold.
    state.register(&schema, assertion.clone()).unwrap();
    let err = state.evaluate(&schema, assertion);
    // The registry name-wraps the precompile's failure; assert the root cause.
    assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
}

#[test]
fn empty_chunk_digest_binds_tag() {
    // n=0 is allowed. The empty digest must still depend on the tag (one permutation runs even
    // for n=0). Two distinct tags should produce distinct empty-chunk digests.
    let a = Node::chunk(preimage_tag(0), vec![]);
    let b = Node::chunk(preimage_tag(1), vec![]);
    assert_ne!(a.digest(), b.digest());
}

#[test]
fn deferred_state_includes_chunk_nodes() {
    let schema = PrecompileRegistry::default().with_precompile(ChunkTestPrecompile);
    let mut state = DeferredState::new();

    let preimage = Node::chunk(preimage_tag(2), chunk_data(2));
    let preimage_digest = state.register(&schema, preimage.clone()).unwrap();

    assert_eq!(
        state.get(&preimage_digest).unwrap(),
        &preimage,
        "chunk node must be present in the deferred state"
    );
}
