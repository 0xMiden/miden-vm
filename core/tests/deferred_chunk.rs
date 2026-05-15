//! Canary integration test for the chunk-node variant of the deferred-DAG public API.
//!
//! Defines a tiny test schema that:
//! - Decodes a 2-byte tag prefix to pick between "preimage chunk" and "digest leaf" roles,
//!   reading `n` for chunks out of the tag's third felt.
//! - `reduce` for a chunk computes a tiny "rolling sum" hash (definitely not a real hash —
//!   the framework doesn't care, the schema picks the function) and returns an expression
//!   digest-leaf.
//! - `reduce` for an assertion compares the two operands canonically.
//!
//! This is the canonical demonstration that `Schema::decode + Schema::reduce + ChunkNode` are
//! sufficient to model "preimage hashes to digest" as an assertion in the deferred DAG.

use miden_core::{
    Felt, ZERO,
    crypto::hash::Poseidon2,
    deferred::{
        ChildResolver, DeferredState, Node, NodeType, Payload, Schema, SchemaError, Tag,
    },
};

// TEST SCHEMA — non-native "rolling sum" hash
// ================================================================================================

/// Tag prefix shared by every test-schema tag.
const TEST_PREFIX: [Felt; 2] = [Felt::new_unchecked(0x73), Felt::new_unchecked(0x68)];
/// Role marker for chunk preimage. The third tag felt holds `n` (the chunk count).
const PREIMAGE_ROLE: Felt = Felt::new_unchecked(0);
/// Role marker for digest leaf.
const DIGEST_ROLE: Felt = Felt::new_unchecked(1);
/// Role marker for an assertion equating two digests.
const ASSERT_ROLE: Felt = Felt::new_unchecked(2);

fn preimage_tag(n: u32) -> Tag {
    [TEST_PREFIX[0], TEST_PREFIX[1], PREIMAGE_ROLE, Felt::from_u32(n)]
}

fn digest_tag() -> Tag {
    [TEST_PREFIX[0], TEST_PREFIX[1], DIGEST_ROLE, ZERO]
}

fn assert_tag() -> Tag {
    [TEST_PREFIX[0], TEST_PREFIX[1], ASSERT_ROLE, ZERO]
}

#[derive(Debug, Default, Clone, Copy)]
struct TestSchema;

impl TestSchema {
    /// "Hash" `chunks` by summing every felt limb-wise into an 8-felt accumulator. Replace with
    /// a real non-native hash in production schemas — the framework doesn't constrain this.
    fn fake_hash(chunks: &[[Felt; 8]]) -> Payload {
        let mut acc = [ZERO; 8];
        for c in chunks {
            for (a, x) in acc.iter_mut().zip(c.iter()) {
                *a += *x;
            }
        }
        Payload::new(acc)
    }
}

impl Schema for TestSchema {
    fn decode(&self, tag: Tag) -> Result<NodeType, SchemaError> {
        if tag[0] != TEST_PREFIX[0] || tag[1] != TEST_PREFIX[1] {
            return Err(SchemaError::InvalidNode);
        }
        match tag[2] {
            r if r == PREIMAGE_ROLE => Ok(NodeType::Chunk(tag[3].as_canonical_u64() as u32)),
            r if r == DIGEST_ROLE => Ok(NodeType::Expression),
            r if r == ASSERT_ROLE => Ok(NodeType::Assertion),
            _ => Err(SchemaError::InvalidNode),
        }
    }

    fn reduce(&self, node: &Node, children: &mut dyn ChildResolver) -> Result<Node, SchemaError> {
        use miden_core::deferred::NodePayload;
        match &node.payload {
            // Preimage chunk reduces to its digest leaf.
            NodePayload::Chunk(chunks) => Ok(Node::expression(digest_tag(), Self::fake_hash(chunks))),
            // Digest leaf is already canonical.
            NodePayload::Expression(_) => Ok(node.clone()),
            // Assertion: resolve both digests, compare canonical forms.
            NodePayload::Assertion(p) => {
                let (lhs, rhs) = p.binary_op_children();
                let lhs_canonical = children.resolve(lhs)?;
                let rhs_canonical = children.resolve(rhs)?;
                if lhs_canonical != rhs_canonical {
                    return Err(SchemaError::AssertionFailed);
                }
                Ok(node.clone())
            },
        }
    }
}

// HELPERS
// ================================================================================================

fn chunk_data(n: u32) -> Vec<[Felt; 8]> {
    (0..n)
        .map(|i| {
            core::array::from_fn(|j| Felt::from_u32(1 + i * 8 + j as u32))
        })
        .collect()
}

// TESTS
// ================================================================================================

#[test]
fn chunk_digest_for_n1_matches_equivalent_expression() {
    // Sanity check: an `n=1` chunk and an expression with the same tag and same 8 felts should
    // have identical digests. The chunk-digest body reduces to "fill rate, one permutation" for
    // n=1, which is exactly the standard expression digest body.
    //
    // Note: these two nodes can't co-exist under the same schema because `decode(tag)` returns
    // only one role per tag — this test reaches under the framework just to verify the digest
    // math.
    let tag = preimage_tag(1);
    let data = chunk_data(1);
    let chunk = Node::chunk(tag, data.clone());
    let expr = Node::expression(tag, Payload::new(data[0]));
    assert_eq!(chunk.digest(), expr.digest());
}

#[test]
fn register_chunk_stores_node() {
    let schema = TestSchema;
    let mut state = DeferredState::new();
    let chunk = Node::chunk(preimage_tag(3), chunk_data(3));
    let digest = state.register(&schema, chunk.clone()).unwrap();
    assert_eq!(digest, chunk.digest());
    assert_eq!(state.get(&digest).unwrap(), &chunk);
}

#[test]
fn register_chunk_with_mismatched_length_fails() {
    let schema = TestSchema;
    let mut state = DeferredState::new();
    // Tag declares n=3 but we hand it 2 chunks of data.
    let bad = Node::chunk(preimage_tag(3), chunk_data(2));
    assert!(matches!(state.register(&schema, bad), Err(SchemaError::InvalidNode)));
}

#[test]
fn assertion_preimage_equals_digest_succeeds() {
    let schema = TestSchema;
    let mut state = DeferredState::new();

    // Register a 3-chunk preimage.
    let chunks = chunk_data(3);
    let preimage = Node::chunk(preimage_tag(3), chunks.clone());
    let preimage_digest = state.register(&schema, preimage).unwrap();

    // Pre-compute and register the matching digest leaf.
    let digest_leaf = Node::expression(digest_tag(), TestSchema::fake_hash(&chunks));
    let digest_leaf_digest = state.register(&schema, digest_leaf).unwrap();

    // Assert preimage's digest == precomputed digest leaf's digest. The schema's reduce will:
    // 1. Resolve preimage_digest → canonical form via `reduce(Chunk)` → Expression{digest_tag,
    //    fake_hash(chunks)}
    // 2. Resolve digest_leaf_digest → already canonical Expression.
    // 3. Compare — must be equal.
    state
        .register(
            &schema,
            Node::assertion(assert_tag(), Payload::binary_op(preimage_digest, digest_leaf_digest)),
        )
        .unwrap();

    assert_eq!(state.assertions().len(), 1);
}

#[test]
fn assertion_preimage_mismatch_fails() {
    let schema = TestSchema;
    let mut state = DeferredState::new();

    let chunks = chunk_data(2);
    let preimage = Node::chunk(preimage_tag(2), chunks);
    let preimage_digest = state.register(&schema, preimage).unwrap();

    // A digest leaf with the wrong content — assertion must fail.
    let wrong_leaf = Node::expression(digest_tag(), Payload::new([Felt::from_u32(99); 8]));
    let wrong_leaf_digest = state.register(&schema, wrong_leaf).unwrap();

    let err = state.register(
        &schema,
        Node::assertion(assert_tag(), Payload::binary_op(preimage_digest, wrong_leaf_digest)),
    );
    assert!(matches!(err, Err(SchemaError::AssertionFailed)));
}

#[test]
fn empty_chunk_digest_binds_tag() {
    // n=0 is allowed. The empty digest must still depend on the tag (one permutation runs even
    // for n=0). Two distinct tags should produce distinct empty-chunk digests.
    let a = Node::chunk(preimage_tag(0), vec![]);
    let b = Node::chunk([TEST_PREFIX[0], TEST_PREFIX[1], PREIMAGE_ROLE, Felt::from_u32(1)], vec![]);
    assert_ne!(a.digest(), b.digest());
}

#[test]
fn extract_witness_includes_chunk_nodes() {
    let schema = TestSchema;
    let mut state = DeferredState::new();

    let preimage = Node::chunk(preimage_tag(2), chunk_data(2));
    let preimage_digest = state.register(&schema, preimage.clone()).unwrap();

    let witness = state.extract_witness();
    assert!(
        witness.nodes.iter().any(|(d, n)| *d == preimage_digest && *n == preimage),
        "chunk node must appear in the extracted witness"
    );
}

#[test]
fn assertion_transcript_folds_chunk_assertions_in_order() {
    let schema = TestSchema;
    let mut state = DeferredState::new();
    assert_eq!(state.transcript(), miden_core::Word::new([ZERO; 4]));

    let chunks = chunk_data(2);
    let preimage = Node::chunk(preimage_tag(2), chunks.clone());
    let preimage_digest = state.register(&schema, preimage).unwrap();
    let leaf = Node::expression(digest_tag(), TestSchema::fake_hash(&chunks));
    let leaf_digest = state.register(&schema, leaf).unwrap();

    let assertion =
        Node::assertion(assert_tag(), Payload::binary_op(preimage_digest, leaf_digest));
    state.register(&schema, assertion.clone()).unwrap();
    let expected =
        Poseidon2::merge(&[miden_core::Word::new([ZERO; 4]), assertion.digest()]);
    assert_eq!(state.transcript(), expected);
}
