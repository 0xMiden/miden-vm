//! A precompile VM, content-addressed.
//!
//! Each [`Precompile`] is a small interpreter for a slice of tag space — a specific hash,
//! signature, or non-native arithmetic. The VM emits `DeferredRegister` /
//! `DeferredRegisterChunk` / `DeferredEvaluate` system events to build a DAG of [`Node`]s, each
//! addressed by its 4-felt Poseidon2 digest. The [`PrecompileRegistry`] dispatches every
//! [`Tag::id`] to the right precompile, which decodes the immediate felts and reduces the node
//! to its canonical form. [`DeferredState::log`] extends a rolling AND-chain whose head — the
//! transcript root — is the verifier's single fixed point: reduce the root to TRUE and every
//! logged statement holds.
//!
//! The framework data model + [`DeferredState`] + [`PrecompileRegistry`] live here in
//! `miden-core`; the processor only contributes the system-event glue. Reference precompiles
//! that exercise the public surface live in `crate::testing::precompile`.

mod node;
mod precompile;
mod precompile_schema;
mod state;
mod wire;

use alloc::sync::Arc;

use miden_crypto::{ZERO, hash::poseidon2::Poseidon2};
pub use node::{NodeType, PrecompileError};
pub use precompile::{Precompile, precompile_id};
pub use precompile_schema::PrecompileRegistry;
pub use state::{DeferredState, WitnessBuilder};
pub use wire::{DeferredStateWire, IntegrityError, TRUE_INDEX, WireBody, WireEntry};

use crate::{Felt, Word};

/// Content-addressed digest of a [`Node`]. A 4-felt Poseidon2 output.
pub type Digest = Word;

/// A tag identifying a deferred node: a precompile `id` plus three precompile-local immediate
/// felts.
///
/// `id == ZERO` is reserved for the framework — it tags the canonical TRUE node and the AND
/// (transcript-step) nodes. No [`Precompile`] may derive id `ZERO`;
/// [`PrecompileRegistry::with_precompile`] rejects one that does. The [`Tag::args`] felts are
/// opaque to `miden-core` and the processor: each
/// precompile decodes whatever structure (discriminant, chunk length, …) it needs out of them.
///
/// Laid out as `[id, arg0, arg1, arg2]` in the Poseidon2 capacity and on the wire — see
/// [`Tag::as_word`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tag {
    pub id: Felt,
    pub args: [Felt; 3],
}

impl Tag {
    /// Reserved framework-level tag carried by the canonical [`Node::TRUE`] and by AND nodes
    /// (transcript-step nodes). No precompile may claim id `ZERO` — the framework owns it.
    ///
    /// Paired with [`TRUE_DIGEST`].
    pub const TRUE: Tag = Tag { id: ZERO, args: [ZERO; 3] };

    /// Build a tag from a precompile id and its three immediate felts.
    pub const fn new(id: Felt, args: [Felt; 3]) -> Self {
        Self { id, args }
    }

    /// The 4-felt word `[id, arg0, arg1, arg2]` — the layout fed to the Poseidon2 capacity and
    /// written to the wire.
    pub const fn as_word(&self) -> [Felt; 4] {
        [self.id, self.args[0], self.args[1], self.args[2]]
    }

    /// Inverse of [`Self::as_word`]: split a 4-felt word into `id` and `args`. Used by the
    /// processor (operand-stack reads) and the wire decoder.
    pub const fn from_word(w: [Felt; 4]) -> Self {
        Self { id: w[0], args: [w[1], w[2], w[3]] }
    }
}

/// An 8-felt block — the Poseidon2 rate, and the bulk-data unit of a chunk node. A `ChunkNode`
/// carries `n` chunks; its digest is the linear hash of those `8n` felts with the tag as the
/// IV (capacity).
pub type Chunk = [Felt; 8];

/// Verifier-side sentinel for "trivial transcript" / "empty AND" — the zero word.
///
/// This is the initial value of `DeferredState::root`, and the terminal the verifier
/// short-circuits on when reducing the root. It is *not* the `.digest()` of any concrete
/// [`Node`]: [`Node::digest`] always runs Poseidon2 (which does not fix zero), so a [`Node::TRUE`]
/// hashes to a non-zero word. The framework distinguishes "TRUE the result" (structural — see
/// [`Node::is_true_node`]) from "TRUE the transcript-terminal" (digest comparison against this
/// sentinel) at different points in the verifier walk.
pub const TRUE_DIGEST: Digest = Word::new([ZERO; 4]);

// PAYLOAD
// ================================================================================================

/// The body of a [`Node`], in one of two shapes:
///
/// - [`Expression`](Payload::Expression) — exactly 8 felts (one Poseidon2 rate block): value
///   leaves, binary ops, predicates, AND-nodes. For a leaf the 8 felts are raw value data; for a
///   binary op / assertion they are `lhs_digest || rhs_digest` (see [`Payload::join`]).
/// - [`Chunk`](Payload::Chunk) — bulk-data leaves: `n` 8-felt blocks. `n = chunks.len()` is also
///   encoded in the tag, so the digest binds it. `Arc`-shared so cloning a chunk node (when
///   interning or resolving children) is a ref-count bump, not a deep copy.
///
/// Accessors that only make sense for one shape return [`DeferredError::InvalidPayload`] when
/// called on the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    Expression([Felt; 8]),
    Chunk(Arc<[Chunk]>),
}

impl Payload {
    /// An [`Expression`](Payload::Expression) payload from 8 raw felts.
    pub const fn new(felts: [Felt; 8]) -> Self {
        Self::Expression(felts)
    }

    /// An [`Expression`](Payload::Expression) payload packing two child digests as `lhs || rhs`.
    /// Reused by assertion nodes, which encode `lhs_digest || rhs_digest` the same way.
    pub fn join(lhs: Digest, rhs: Digest) -> Self {
        let mut felts = [ZERO; 8];
        felts[0..4].copy_from_slice(lhs.as_elements());
        felts[4..8].copy_from_slice(rhs.as_elements());
        Self::Expression(felts)
    }

    /// A [`Chunk`](Payload::Chunk) payload from `n` rate-sized blocks of bulk data.
    pub fn chunks(chunks: impl Into<Arc<[Chunk]>>) -> Self {
        Self::Chunk(chunks.into())
    }

    /// The 8 felts of an [`Expression`](Payload::Expression) payload. Errors with
    /// [`DeferredError::InvalidPayload`] on a [`Chunk`](Payload::Chunk) payload.
    pub fn as_felts(&self) -> Result<&[Felt; 8], DeferredError> {
        match self {
            Self::Expression(felts) => Ok(felts),
            Self::Chunk(_) => Err(DeferredError::InvalidPayload),
        }
    }

    /// The bulk blocks of a [`Chunk`](Payload::Chunk) payload. Errors with
    /// [`DeferredError::InvalidPayload`] on an [`Expression`](Payload::Expression) payload.
    pub fn as_chunks(&self) -> Result<&[Chunk], DeferredError> {
        match self {
            Self::Chunk(chunks) => Ok(chunks),
            Self::Expression(_) => Err(DeferredError::InvalidPayload),
        }
    }

    /// Splits an [`Expression`](Payload::Expression) payload into its two child digests in
    /// `(lhs, rhs)` order — inverse of [`Self::join`]. Errors with
    /// [`DeferredError::InvalidPayload`] on a [`Chunk`](Payload::Chunk) payload.
    pub fn join_children(&self) -> Result<(Digest, Digest), DeferredError> {
        let f = self.as_felts()?;
        let lhs = Word::new([f[0], f[1], f[2], f[3]]);
        let rhs = Word::new([f[4], f[5], f[6], f[7]]);
        Ok((lhs, rhs))
    }
}

// NODE
// ================================================================================================

/// A DAG node: a [`Tag`] and a [`Payload`], addressed by its Poseidon2 [`Digest`].
///
/// What a node *means* (value leaf? binary op? predicate? AND-step?) is up to the precompile
/// that owns its `tag.id` — the precompile decodes the immediate felts via
/// [`Precompile::decode`] and `reduce`s the payload via [`Precompile::reduce`]. The framework
/// only enforces the structural shape declared by [`NodeType`].
///
/// Predicate nodes have no distinguished shape: a precompile signals "predicate verified" by
/// returning [`Node::TRUE`] from `reduce`. The framework detects this via [`Node::is_true_node`]
/// on the canonical and skips the advice-stack push that non-predicate canonicals get.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    pub tag: Tag,
    pub payload: Payload,
}

impl Node {
    /// Canonical TRUE node: zero tag, zero expression payload. Predicate-tag precompiles return
    /// this from `reduce` on success; framework code checks the result structurally via
    /// [`Node::is_true_node`], not by digest comparison.
    pub const TRUE: Node = Node {
        tag: Tag::TRUE,
        payload: Payload::Expression([ZERO; 8]),
    };

    /// Build a node from an 8-felt [`Expression`](Payload::Expression) body (leaf, op-node,
    /// predicate, or AND-node). Takes the [`Payload`] directly — callers typically pass
    /// `Payload::new(..)` or `Payload::join(..)`.
    pub fn expression(tag: Tag, payload: Payload) -> Self {
        Self { tag, payload }
    }

    /// Build an expression-bodied leaf node from raw 8-felt payload data.
    pub fn leaf(tag: Tag, felts: [Felt; 8]) -> Self {
        Self::expression(tag, Payload::new(felts))
    }

    /// Build an expression-bodied binary node with joined child digests.
    pub fn join(tag: Tag, lhs: Digest, rhs: Digest) -> Self {
        Self::expression(tag, Payload::join(lhs, rhs))
    }

    /// Build an AND-chain step node `{ tag: TRUE, payload: lhs || rhs }`.
    pub fn and(lhs: Digest, rhs: Digest) -> Self {
        Self::join(Tag::TRUE, lhs, rhs)
    }

    /// Build a chunk node from `n = chunks.len()` rate-sized blocks of bulk data. Accepts
    /// anything that converts into `Arc<[Chunk]>` — typically a `Vec<Chunk>` from the processor
    /// handler, or a slice literal in tests.
    pub fn chunk(tag: Tag, chunks: impl Into<Arc<[Chunk]>>) -> Self {
        Self {
            tag,
            payload: Payload::Chunk(chunks.into()),
        }
    }

    /// Returns `true` iff this node has the structural shape of [`Node::TRUE`]: zero tag and zero
    /// expression payload. Used by the verifier to accept a predicate `reduce` result as
    /// "verified."
    ///
    /// Note this shape is also the shape of an AND-node both of whose children are
    /// [`TRUE_DIGEST`] — the two are structurally identical and logically equivalent (AND of two
    /// TRUEs *is* TRUE). The framework relies on contextual dispatch (predicate `reduce` results
    /// vs. AND-node DAG walks) rather than on byte-level distinction.
    pub fn is_true_node(&self) -> bool {
        self.tag == Tag::TRUE && matches!(&self.payload, Payload::Expression(f) if *f == [ZERO; 8])
    }

    /// Canonical 4-felt Poseidon2 digest of this node.
    ///
    /// Sponge state is laid out as `[rate || tag]` — the tag occupies the 4-felt capacity. For
    /// expression and assertion nodes, the 8-felt payload fills the rate and a single permutation
    /// produces the digest. For chunk nodes, each 8-felt chunk overwrites the rate and the
    /// permutation iterates `n` times (linear hash); the empty `n == 0` case still applies one
    /// permutation so the digest binds the tag. The in-circuit chunk verifier must mirror this —
    /// including the one-permutation rule for `n == 0`, which is unusual for a
    /// "linear hash of zero elements" but matches what `Node::digest` computes here.
    ///
    /// For `n == 1` the chunk digest is byte-identical to the equivalent Expression digest with
    /// the same tag and payload.
    ///
    /// **TRUE-node digest.** [`Node::TRUE`] hashes through Poseidon2 like any other node — its
    /// digest is *not* [`TRUE_DIGEST`]. That sentinel is purely a verifier-side handle for the
    /// "trivial transcript" / "empty AND" terminal; it is never the `.digest()` of any concrete
    /// `Node`. This keeps `Node::digest` honest to the in-circuit hasher, so AND-nodes interned
    /// by [`DeferredState::log`] (whose digest is computed by the in-circuit permute) match what
    /// callers compute here.
    pub fn digest(&self) -> Digest {
        let mut state = [ZERO; 12];
        state[8..12].copy_from_slice(&self.tag.as_word());
        match &self.payload {
            Payload::Expression(f) => {
                state[0..8].copy_from_slice(f);
                Poseidon2::apply_permutation(&mut state);
            },
            Payload::Chunk(chunks) if chunks.is_empty() => {
                // n=0: one permutation so the empty digest still binds to the tag.
                Poseidon2::apply_permutation(&mut state);
            },
            Payload::Chunk(chunks) => {
                for c in chunks.iter() {
                    state[0..8].copy_from_slice(c);
                    Poseidon2::apply_permutation(&mut state);
                }
            },
        }
        Word::new([state[0], state[1], state[2], state[3]])
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

    const TAG_A: Tag = Tag {
        id: Felt::new_unchecked(1),
        args: [Felt::new_unchecked(0); 3],
    };
    const TAG_B: Tag = Tag {
        id: Felt::new_unchecked(1),
        args: [Felt::new_unchecked(0), Felt::new_unchecked(1), Felt::new_unchecked(0)],
    };

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
        let n = Node::leaf(TAG_A, *payload(42).as_felts().unwrap());
        assert_eq!(n.digest(), n.digest());
    }

    #[test]
    fn tag_changes_digest() {
        let p = payload(7);
        assert_ne!(
            Node::leaf(TAG_A, *p.as_felts().unwrap()).digest(),
            Node::leaf(TAG_B, *p.as_felts().unwrap()).digest()
        );
    }

    #[test]
    fn payload_changes_digest() {
        assert_ne!(
            Node::leaf(TAG_A, *payload(0).as_felts().unwrap()).digest(),
            Node::leaf(TAG_A, *payload(1).as_felts().unwrap()).digest(),
        );
    }

    #[test]
    fn chunk_n1_matches_expression_with_same_tag_and_payload() {
        // Single-chunk digest is the same body as Expression: rate := payload, capacity := tag,
        // one permutation, take state[0..4].
        let p = payload(123);
        let felts = *p.as_felts().unwrap();
        let expr = Node::leaf(TAG_A, felts);
        let chunk = Node::chunk(TAG_A, vec![felts]);
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
        let chunks: Vec<Chunk> =
            (0..3).map(|i| *payload(100 + i * 8).as_felts().unwrap()).collect();
        let chunk = Node::chunk(TAG_A, chunks.clone());

        // Manual computation: capacity = tag, iterate over chunks overwriting rate.
        let mut state = [ZERO; 12];
        state[8..12].copy_from_slice(&TAG_A.as_word());
        for c in &chunks {
            state[0..8].copy_from_slice(c);
            Poseidon2::apply_permutation(&mut state);
        }
        let expected = Word::new([state[0], state[1], state[2], state[3]]);
        assert_eq!(chunk.digest(), expected);
    }

    #[test]
    fn true_tag_and_digest_are_zero_word() {
        assert_eq!(Tag::TRUE, Tag { id: ZERO, args: [ZERO; 3] });
        assert_eq!(TRUE_DIGEST, Word::new([ZERO; 4]));
    }

    #[test]
    fn true_node_has_zero_tag_and_zero_expression_payload() {
        let n = Node::TRUE;
        assert_eq!(n.tag, Tag::TRUE);
        match &n.payload {
            Payload::Expression(f) => assert_eq!(*f, [ZERO; 8]),
            Payload::Chunk(_) => panic!("Node::TRUE must be expression-bodied"),
        }
        assert!(n.is_true_node());
    }

    #[test]
    fn poseidon2_does_not_fix_zero() {
        // Load-bearing for the unified-transcript refactor: because Poseidon2's round
        // constants are non-zero, applying the permutation to the all-zero state does NOT
        // return all zeros. Consequence: `Node::TRUE.digest() != TRUE_DIGEST`, and the
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
        // in-circuit hasher — critical for AND-nodes interned by `DeferredState::log` (where the
        // in-circuit hasher computes the same `merge(0, 0)` value).
        assert_ne!(Node::TRUE.digest(), TRUE_DIGEST);
    }

    #[test]
    fn true_node_digest_equals_and_of_true_true() {
        // AND(TRUE, TRUE) and the TRUE sentinel share the structural shape
        // `Node { tag: Tag::TRUE, payload: Expression([0; 8]) }`, so their digests are equal
        // (both run the same Poseidon2 permutation). This is logically consistent (AND of two
        // TRUEs IS TRUE) and load-bearing for the recursive-proof use case where the program
        // logs a sub-proof's transcript whose root happens to be TRUE_DIGEST.
        let and_true_true = Node::and(TRUE_DIGEST, TRUE_DIGEST);
        assert_eq!(and_true_true.digest(), Node::TRUE.digest());
    }

    #[test]
    fn clone_yields_consistent_digest() {
        // A clone's digest matches the source's — `Clone` is a structural copy.
        let n = Node::leaf(TAG_A, *payload(33).as_felts().unwrap());
        let d1 = n.digest();
        let cloned = n;
        let d2 = cloned.digest();
        assert_eq!(d1, d2);
    }
}
