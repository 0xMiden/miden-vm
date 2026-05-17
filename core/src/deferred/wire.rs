//! Wire format for [`DeferredState`].
//!
//! The wire form is the passive bytes-shape that travels in proofs: a flat list of nodes plus
//! the transcript root. It deliberately does *not* carry the digest column (digests are
//! recomputed on the verifier side), and it does *not* carry any pre-checked invariant — the
//! `Deserializable` impl just reads bytes, never validates schema-validity or chain integrity.
//!
//! The single trusted path from wire bytes to a usable [`DeferredState`] is
//! [`DeferredState::rehydrate`]: it re-runs the schema-validation, content-addressing, and
//! AND-chain walk that the prover did, so a hydrated `DeferredState` value satisfies the
//! invariants laid out in `state.rs`'s module docs.

use alloc::vec::Vec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{Digest, Node};
use crate::serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

/// Wire-format representation of a [`super::DeferredState`].
///
/// Contains the flat node list and the root digest. Node order is not constrained — rehydration
/// uses a two-pass approach (intern then check closure) so it tolerates any ordering, including
/// the `BTreeMap` digest-order produced by [`super::DeferredState::to_wire`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DeferredStateWire {
    /// All nodes the prover wishes to ship to the verifier. Includes the AND-chain transcript
    /// nodes, every predicate stmt referenced in the chain, and the transitive closure of
    /// children each stmt's `reduce` walk visits.
    pub nodes: Vec<Node>,
    /// The transcript root pointer. Either [`super::TRUE_DIGEST`] (trivial transcript) or the
    /// digest of an AND-node in `nodes`.
    pub root: Digest,
}

impl DeferredStateWire {
    /// Construct an empty wire (`root == TRUE_DIGEST`, no nodes). Convenience for tests and for
    /// the no-precompile proof path.
    pub fn empty() -> Self {
        Self::default()
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for DeferredStateWire {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.nodes.len());
        for node in &self.nodes {
            node.write_into(target);
        }
        self.root.write_into(target);
    }
}

impl Deserializable for DeferredStateWire {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let count = source.read_usize()?;
        let mut nodes = Vec::with_capacity(count);
        for _ in 0..count {
            nodes.push(Node::read_from(source)?);
        }
        let root = Digest::read_from(source)?;
        Ok(Self { nodes, root })
    }
}

// INTEGRITY ERROR
// ================================================================================================

/// Failure modes for [`super::DeferredState::rehydrate`].
///
/// Every variant means the wire-format input does not correspond to a valid deferred-DAG witness
/// under the installed schema. The verifier rejects any proof carrying a wire that yields any of
/// these errors.
///
/// Not `Clone`/`Eq` because `PredicateFailed` wraps `SchemaError`, which is itself opaque
/// (wraps `DeferredError`). Tests should `matches!` on variants, not `assert_eq!` whole values.
#[derive(Debug, thiserror::Error)]
pub enum IntegrityError {
    /// A node's tag is not claimed by the installed schema.
    #[error("wire contains a node with a tag the installed schema does not recognise")]
    UnknownTag,
    /// A node's in-memory payload shape disagrees with `schema.decode(tag).node_type`.
    #[error("wire contains a node whose payload shape disagrees with its tag's declared NodeType")]
    ShapeMismatch,
    /// A `Binary`-typed node references a child digest that's not in the wire.
    #[error("wire contains a Binary node whose child digest is not present in the node set")]
    DanglingChild,
    /// `wire.root` is not [`super::TRUE_DIGEST`] and not the digest of any node in the wire.
    #[error("wire root points to a node that is not present in the node set")]
    MissingRoot,
    /// An AND-chain step does not have `tag == TRUE_TAG` (corrupt transcript).
    #[error("AND-chain walk encountered a node whose tag is not TRUE_TAG")]
    NonAndNode,
    /// An AND-chain step's payload doesn't decode as a binary `(prev_root, stmt_digest)`.
    #[error("AND-chain walk encountered a node whose payload is not in binary-op shape")]
    BadAndPayload,
    /// A statement referenced by an AND-node is not in the wire.
    #[error("AND-chain walk references a statement digest that is not in the node set")]
    MissingStatement,
    /// A statement does not reduce to `true_node` under the schema. Wraps the schema's error so
    /// the precise reduce-failure surfaces in test output.
    #[error("AND-chain statement failed re-evaluation: {0}")]
    PredicateFailed(#[from] super::SchemaError),
    /// A statement reduced successfully but its canonical is not the TRUE node.
    #[error("AND-chain statement reduced to a non-TRUE canonical form")]
    PredicateNotTrue,
}
