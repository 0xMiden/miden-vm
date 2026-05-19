//! Content-addressed DAG of *deferred algebraic operations*.
//!
//! The deferred subsystem represents expensive precompile work (e.g. 256-bit non-native field
//! arithmetic, future curve ops, non-native hashes over bulk data) as a DAG of typed [`Node`]s
//! addressed by their 4-felt Poseidon2 digest. The VM uses three generic system events
//! (`DeferredRegister`, `DeferredRegisterChunk`, `DeferredEvaluate`) to populate the DAG; the
//! verifier later consumes the resulting [`DeferredState`] (nodes + rolling root) and reduces
//! the root to TRUE.
//!
//! The full subsystem — data model, [`Schema`] trait, in-memory [`DeferredState`], and the
//! [`Precompile`] / [`PrecompileSchema`] composite substrate — lives here in `miden-core`. The
//! processor only contributes the system-event glue that bridges VM operand-stack reads to
//! schema calls. Reference precompiles that exercise this public surface live in `miden-core`'s
//! integration tests (`core/tests/common/precompile/`), not on the crate's public surface.

mod schema;
mod state;
mod wire;

pub use schema::{NodeType, NoopSchema, ReduceCtx, Schema, SchemaError, TagInfo};
pub use state::DeferredState;
pub use wire::{DeferredStateWire, IntegrityError, TRUE_INDEX, WireBody, WireEntry};

// Multi-app composite layer. The `App` trait + `PrecompileSchema` substrate are the public
// surface. Production precompile apps (keccak256, sha512, ecdsa_k256_keccak, eddsa_ed25519)
// live in `miden-core-lib::precompiles`, next to their MASM wrappers; reference precompiles
// live in `core/tests/common/precompile/`.
mod precompile;
mod precompile_schema;

// Minimal `#[cfg(test)]` schema fixture for the engine's own unit tests (state.rs et al.).
// Not exported, not on the `testing` surface — scaffolding only.
#[cfg(test)]
pub(crate) mod test_precompile;

use alloc::sync::Arc;

use miden_crypto::{ZERO, hash::poseidon2::Poseidon2};
use miden_utils_sync::OnceLockCompat;
pub use precompile::{Precompile, PrecompileTag, precompile_id};
pub use precompile_schema::PrecompileSchema;

use crate::{
    Felt, Word,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

/// Content-addressed digest of a [`Node`]. A 4-felt Poseidon2 output.
pub type Digest = Word;

/// A 4-felt opaque tag identifying a deferred node. Tags are not interpreted by `miden-core` or
/// by the processor — the installed schema decodes any structure (type prefix, op suffix, kind,
/// chunk length, …) it needs out of the tag's four felts.
pub type Tag = [Felt; 4];

/// An 8-felt block — the Poseidon2 rate, and the bulk-data unit of a chunk node. A `ChunkNode`
/// carries `n` chunks; its digest is the linear hash of those `8n` felts with the tag as the
/// IV (capacity).
pub type Chunk = [Felt; 8];

/// Reserved framework-level tag carried by the canonical TRUE node and by AND nodes
/// (transcript-step nodes). No schema may claim this tag — the framework owns it.
///
/// Structurally `[ZERO; 4]`. Paired with [`TRUE_DIGEST`].
pub const TRUE_TAG: Tag = [ZERO; 4];

/// Verifier-side sentinel for "trivial transcript" / "empty AND" — the zero word.
///
/// This is the initial value of `DeferredState::root`, and the terminal the verifier
/// short-circuits on when reducing the root. It is *not* the `.digest()` of any concrete
/// [`Node`]: [`Node::digest`] always runs Poseidon2 (which does not fix zero), so a [`true_node`]
/// hashes to a non-zero word. The framework distinguishes "TRUE the result" (structural — see
/// [`Node::is_true_node`]) from "TRUE the transcript-terminal" (digest comparison against this
/// sentinel) at different points in the verifier walk.
pub const TRUE_DIGEST: Digest = Word::new([ZERO; 4]);

/// Canonical TRUE node value: zero tag, zero expression payload. Predicate-tag schemas return
/// this from `reduce` on success; framework code checks the result structurally via
/// [`Node::is_true_node`], not by digest comparison.
pub fn true_node() -> Node {
    Node::expression(TRUE_TAG, Payload::new([ZERO; 8]))
}

// PAYLOAD
// ================================================================================================

/// 8-felt body of an expression or assertion node. For a leaf, this is the value data; for a
/// binary op, the first 4 felts are the lhs child digest and the last 4 are the rhs child digest.
/// Assertion payloads follow the same `lhs_digest || rhs_digest` convention as binary ops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Payload(pub [Felt; 8]);

impl Payload {
    pub const fn new(felts: [Felt; 8]) -> Self {
        Self(felts)
    }

    pub fn as_felts(&self) -> &[Felt; 8] {
        &self.0
    }

    /// Builds a binary-op payload from two child digests in `(lhs, rhs)` order. Same convention
    /// is reused by assertion nodes, which encode `lhs_digest || rhs_digest` in their 8-felt
    /// payload.
    pub fn binary_op(lhs: Digest, rhs: Digest) -> Self {
        let mut felts = [ZERO; 8];
        felts[0..4].copy_from_slice(lhs.as_elements());
        felts[4..8].copy_from_slice(rhs.as_elements());
        Self(felts)
    }

    /// Splits a binary-op or assertion payload into its two child digests in `(lhs, rhs)` order.
    /// Inverse of [`Self::binary_op`]; convenient for schema `reduce` implementations that walk
    /// children.
    pub fn binary_op_children(&self) -> (Digest, Digest) {
        let lhs = Word::new([self.0[0], self.0[1], self.0[2], self.0[3]]);
        let rhs = Word::new([self.0[4], self.0[5], self.0[6], self.0[7]]);
        (lhs, rhs)
    }
}

// NODE
// ================================================================================================

/// A DAG node identified by its [`Digest`].
///
/// The tag is opaque at this layer — the installed [`Schema`] decodes it. The payload comes in
/// two shapes ([`NodePayload`]):
/// - `Expression(Payload)` — leaves, op-nodes, predicates, and AND-nodes. All carry an 8-felt
///   payload.
/// - `Chunk(Arc<[Chunk]>)` — bulk-data leaves; `n` (number of 8-felt chunks) is `chunks.len()` and
///   is also encoded into the tag, so the digest binds it. Stored behind an `Arc` so cloning a
///   chunk node (when interning or resolving children) is an atomic ref-count bump rather than a
///   deep copy of the bulk data.
///
/// Predicate nodes (those whose tag decodes with `evaluates_to == TRUE_TAG`) are structurally
/// indistinguishable from regular expression-bodied nodes; their "predicate-ness" is a property
/// of the *tag*, not the *node*, and is communicated by `Schema::decode`'s [`TagInfo`].
///
/// Carries a lazily-populated digest cache (`OnceLockCompat<Digest>`) so repeated `.digest()`
/// calls on a node — and on its clones — amortise to one Poseidon2 invocation. The cache is
/// populated either on the first `.digest()` call, or eagerly by `DeferredState::intern*`
/// (which know the digest already). The cache is *not* part of structural identity: equality,
/// serialization, and the wire format ignore it.
#[derive(Clone, Debug)]
pub struct Node {
    pub tag: Tag,
    pub payload: NodePayload,
    /// Memoised Poseidon2 digest. Cloning a node may yield a fresh empty cache (depends on the
    /// `OnceLockCompat` impl); the first `.digest()` call on the clone re-populates it.
    digest_cache: OnceLockCompat<Digest>,
}

impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        // Digest cache is derived data — exclude from structural equality.
        self.tag == other.tag && self.payload == other.payload
    }
}
impl Eq for Node {}

/// Variant of a [`Node`]'s body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodePayload {
    /// Leaves, op-nodes, predicates, AND-nodes. 8-felt payload.
    Expression(Payload),
    /// Bulk-data leaves. `n = chunks.len()`, also encoded in the tag. `Arc`-shared so the bulk
    /// data is never deep-copied during interning or resolution.
    Chunk(Arc<[Chunk]>),
}

impl Node {
    /// Build an expression node (leaf, op-node, predicate, or AND-node).
    pub fn expression(tag: Tag, payload: Payload) -> Self {
        Self {
            tag,
            payload: NodePayload::Expression(payload),
            digest_cache: OnceLockCompat::new(),
        }
    }

    /// Build a chunk node from `n = chunks.len()` rate-sized blocks of bulk data. Accepts
    /// anything that converts into `Arc<[Chunk]>` — typically a `Vec<Chunk>` from the processor
    /// handler, or a slice literal in tests.
    pub fn chunk(tag: Tag, chunks: impl Into<Arc<[Chunk]>>) -> Self {
        Self {
            tag,
            payload: NodePayload::Chunk(chunks.into()),
            digest_cache: OnceLockCompat::new(),
        }
    }

    /// Returns the 8-felt payload of an expression node. Returns `None` for chunk nodes,
    /// which don't have a fixed-size payload.
    pub fn expression_payload(&self) -> Option<&Payload> {
        match &self.payload {
            NodePayload::Expression(p) => Some(p),
            NodePayload::Chunk(_) => None,
        }
    }

    /// Returns `true` iff this node has the structural shape of the canonical TRUE node: zero
    /// tag and zero expression payload. Used by the verifier to accept a predicate `reduce`
    /// result as "verified."
    ///
    /// Note this shape is also the shape of an AND-node both of whose children are
    /// [`TRUE_DIGEST`] — the two are structurally identical and logically equivalent (AND of two
    /// TRUEs *is* TRUE). The framework relies on contextual dispatch (predicate `reduce` results
    /// vs. AND-node DAG walks) rather than on byte-level distinction.
    pub fn is_true_node(&self) -> bool {
        self.tag == TRUE_TAG
            && matches!(&self.payload, NodePayload::Expression(p) if p.0 == [ZERO; 8])
    }

    /// Canonical 4-felt Poseidon2 digest of this node.
    ///
    /// Sponge state is laid out as `[rate || tag]` — the tag occupies the 4-felt capacity. For
    /// expression and assertion nodes, the 8-felt payload fills the rate and a single permutation
    /// produces the digest. For chunk nodes, each 8-felt chunk overwrites the rate and the
    /// permutation iterates `n` times (linear hash); the empty `n == 0` case still applies one
    /// permutation so the digest binds the tag.
    ///
    /// For `n == 1` the chunk digest is byte-identical to the equivalent Expression digest with
    /// the same tag and payload.
    ///
    /// **TRUE-node digest.** [`true_node`] hashes through Poseidon2 like any other node — its
    /// digest is *not* [`TRUE_DIGEST`]. That sentinel is purely a verifier-side handle for the
    /// "trivial transcript" / "empty AND" terminal; it is never the `.digest()` of any concrete
    /// `Node`. This keeps `Node::digest` honest to the in-circuit hasher, so AND-nodes interned
    /// after `log_precompile` (whose digest is computed by the in-circuit permute) match what
    /// callers compute here.
    ///
    /// Memoised on first call via the `digest_cache` field. Subsequent calls are O(1).
    /// `DeferredState::intern*` paths prime the cache eagerly via `prime_digest`.
    pub fn digest(&self) -> Digest {
        *self.digest_cache.get_or_init(|| self.compute_digest())
    }

    /// Populate the digest cache with a pre-computed value, skipping Poseidon2. Used by
    /// the `DeferredState` reduction driver, which knows each node's digest before insertion.
    /// Idempotent: if the cache is already populated, the hint is dropped silently. There is
    /// no debug-assert that `hint == self.compute_digest()` here — the resolver's contract
    /// guarantees the match, and a runtime check would defeat the purpose of priming.
    pub(crate) fn prime_digest(&self, hint: Digest) {
        let _ = self.digest_cache.get_or_init(|| hint);
    }

    /// Recompute the digest from scratch, bypassing the cache. Crate-visible so the
    /// `DeferredState` debug assertions in `intern_with_digest` can re-verify the resolver's
    /// hint without depending on cache state.
    pub(crate) fn compute_digest(&self) -> Digest {
        let mut state = [ZERO; 12];
        state[8..12].copy_from_slice(&self.tag);
        match &self.payload {
            NodePayload::Expression(p) => {
                state[0..8].copy_from_slice(p.as_felts());
                Poseidon2::apply_permutation(&mut state);
            },
            NodePayload::Chunk(chunks) if chunks.is_empty() => {
                // n=0: one permutation so the empty digest still binds to the tag.
                Poseidon2::apply_permutation(&mut state);
            },
            NodePayload::Chunk(chunks) => {
                for c in chunks.iter() {
                    state[0..8].copy_from_slice(c);
                    Poseidon2::apply_permutation(&mut state);
                }
            },
        }
        Word::new([state[0], state[1], state[2], state[3]])
    }
}

// SERIALIZATION
// ================================================================================================

// `Payload` is the only deferred node-body type with a hand-written `Serializable` /
// `Deserializable`: the wire format ([`wire`]) reuses it for `WireBody::Value`. `Node` and
// `NodePayload` are never serialized directly — wire entries are the transit unit — so they
// carry no custom serde, and no `serde` derives exist on the deferred types either.
impl Serializable for Payload {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        for felt in &self.0 {
            felt.write_into(target);
        }
    }
}

impl Deserializable for Payload {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut felts = [ZERO; 8];
        for felt in &mut felts {
            *felt = Felt::read_from(source)?;
        }
        Ok(Self(felts))
    }
}

// ERROR
// ================================================================================================

/// Errors raised by the deferred subsystem. Intentionally coarse for v1; refine as concrete
/// failure modes accumulate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeferredError {
    #[error("invalid or unknown deferred tag")]
    InvalidTag,
    #[error("referenced digest is not present in deferred state")]
    MissingNode,
    #[error("conflicting node definition for digest")]
    ConflictingNode,
    #[error("payload is not valid for the given tag")]
    InvalidPayload,
    #[error("equality assertion failed")]
    AssertionFailed,
    #[error("operation is not supported by this handler")]
    Unsupported,
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    const TAG_A: Tag = [
        Felt::new_unchecked(1),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
        Felt::new_unchecked(0),
    ];
    const TAG_B: Tag = [
        Felt::new_unchecked(1),
        Felt::new_unchecked(0),
        Felt::new_unchecked(1),
        Felt::new_unchecked(0),
    ];

    fn payload(seed: u64) -> Payload {
        Payload::new([
            Felt::new_unchecked(seed),
            Felt::new_unchecked(seed.wrapping_add(1)),
            Felt::new_unchecked(seed.wrapping_add(2)),
            Felt::new_unchecked(seed.wrapping_add(3)),
            Felt::new_unchecked(seed.wrapping_add(4)),
            Felt::new_unchecked(seed.wrapping_add(5)),
            Felt::new_unchecked(seed.wrapping_add(6)),
            Felt::new_unchecked(seed.wrapping_add(7)),
        ])
    }

    #[test]
    fn digest_is_deterministic() {
        let n = Node::expression(TAG_A, payload(42));
        assert_eq!(n.digest(), n.digest());
    }

    #[test]
    fn tag_changes_digest() {
        let p = payload(7);
        assert_ne!(Node::expression(TAG_A, p).digest(), Node::expression(TAG_B, p).digest());
    }

    #[test]
    fn payload_changes_digest() {
        assert_ne!(
            Node::expression(TAG_A, payload(0)).digest(),
            Node::expression(TAG_A, payload(1)).digest(),
        );
    }

    #[test]
    fn chunk_n1_matches_expression_with_same_tag_and_payload() {
        // Single-chunk digest is the same body as Expression: rate := payload, capacity := tag,
        // one permutation, take state[0..4].
        let p = payload(123);
        let expr = Node::expression(TAG_A, p);
        let chunk = Node::chunk(TAG_A, vec![p.0]);
        assert_eq!(expr.digest(), chunk.digest());
    }

    #[test]
    fn chunk_n0_binds_tag() {
        // Empty chunk still applies one permutation, so different tags produce different digests.
        let chunk_a = Node::chunk(TAG_A, vec![]);
        let chunk_b = Node::chunk(TAG_B, vec![]);
        assert_ne!(chunk_a.digest(), chunk_b.digest());
    }

    #[test]
    fn chunk_n3_matches_manual_linear_hash() {
        let chunks: Vec<Chunk> = (0..3).map(|i| payload(100 + i * 8).0).collect();
        let chunk = Node::chunk(TAG_A, chunks.clone());

        // Manual computation: capacity = tag, iterate over chunks overwriting rate.
        let mut state = [ZERO; 12];
        state[8..12].copy_from_slice(&TAG_A);
        for c in &chunks {
            state[0..8].copy_from_slice(c);
            Poseidon2::apply_permutation(&mut state);
        }
        let expected = Word::new([state[0], state[1], state[2], state[3]]);
        assert_eq!(chunk.digest(), expected);
    }

    #[test]
    fn true_tag_and_digest_are_zero_word() {
        assert_eq!(TRUE_TAG, [ZERO; 4]);
        assert_eq!(TRUE_DIGEST, Word::new([ZERO; 4]));
    }

    #[test]
    fn true_node_has_zero_tag_and_zero_expression_payload() {
        let n = true_node();
        assert_eq!(n.tag, TRUE_TAG);
        match &n.payload {
            NodePayload::Expression(p) => assert_eq!(p.0, [ZERO; 8]),
            _ => panic!("true_node must be expression-bodied"),
        }
        assert!(n.is_true_node());
    }

    #[test]
    fn poseidon2_does_not_fix_zero() {
        // Load-bearing for the unified-transcript refactor: because Poseidon2's round
        // constants are non-zero, applying the permutation to the all-zero state does NOT
        // return all zeros. Consequence: `true_node().digest() != TRUE_DIGEST`, and the
        // framework keeps these two concepts separate (see TRUE_DIGEST docs and
        // `true_node_digest_matches_in_circuit_merge` below).
        let mut state = [ZERO; 12];
        Poseidon2::apply_permutation(&mut state);
        let rate0 = Word::new([state[0], state[1], state[2], state[3]]);
        assert_ne!(rate0, Word::new([ZERO; 4]));
    }

    #[test]
    fn true_node_hashes_normally_via_poseidon2() {
        // TRUE-node is not digest-special-cased: it hashes through Poseidon2 like any other
        // node, producing a specific non-zero word. This keeps `Node::digest()` honest to the
        // in-circuit hasher — critical for AND-nodes interned by `log_precompile` (where the
        // in-circuit hasher computes the same `merge(0, 0)` value).
        assert_ne!(true_node().digest(), TRUE_DIGEST);
    }

    #[test]
    fn true_node_digest_equals_and_of_true_true() {
        // AND(TRUE, TRUE) and the TRUE sentinel share the structural shape
        // `Node { tag: TRUE_TAG, payload: Expression([0; 8]) }`, so their digests are equal
        // (both run the same Poseidon2 permutation). This is logically consistent (AND of two
        // TRUEs IS TRUE) and load-bearing for the recursive-proof use case where the program
        // logs a sub-proof's transcript whose root happens to be TRUE_DIGEST.
        let and_true_true =
            Node::expression(TRUE_TAG, Payload::binary_op(TRUE_DIGEST, TRUE_DIGEST));
        assert_eq!(and_true_true.digest(), true_node().digest());
    }

    #[test]
    fn cached_digest_matches_recomputed_digest() {
        // After `digest()` populates the cache, the cached value must equal `compute_digest()`.
        let n = Node::expression(TAG_A, payload(11));
        let cached = n.digest();
        assert_eq!(cached, n.compute_digest());
        assert_eq!(cached, n.digest(), "repeated digest() is stable");
    }

    #[test]
    fn primed_digest_skips_recomputation() {
        // `prime_digest` populates the cache with a user-supplied value. Subsequent `.digest()`
        // calls return the primed value without recomputation. Use a deliberately-wrong hint
        // to prove the cached path is taken (in production the resolver primes with a value it
        // computed correctly; this test is white-box).
        let n = Node::expression(TAG_A, payload(22));
        let bogus = Word::new([Felt::from_u32(0xdead); 4]);
        n.prime_digest(bogus);
        assert_eq!(n.digest(), bogus, "primed cache short-circuits digest()");
        // compute_digest still bypasses the cache.
        assert_ne!(n.compute_digest(), bogus);
    }

    #[test]
    fn clone_yields_consistent_digest() {
        // Cloning a node may yield a fresh empty cache (no_std) or a populated one (std).
        // Either way, the digest must equal the source's digest — the cache is derived data.
        let n = Node::expression(TAG_A, payload(33));
        let d1 = n.digest();
        let cloned = n.clone();
        let d2 = cloned.digest();
        assert_eq!(d1, d2);
    }

    #[test]
    fn equality_ignores_digest_cache_state() {
        // Two structurally-identical nodes must compare equal regardless of whether either
        // has populated its digest cache.
        let a = Node::expression(TAG_A, payload(44));
        let b = Node::expression(TAG_A, payload(44));
        // Populate `a`'s cache; leave `b`'s empty.
        let _ = a.digest();
        assert_eq!(a, b, "equality compares tag + payload, not cache state");
    }
}
