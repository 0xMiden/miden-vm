//! Wire format for [`DeferredState`].
//!
//! The wire form is the passive bytes-shape that travels in proofs: a topologically-ordered
//! list of entries plus the transcript root. Binary entries reference their children by *index*
//! into earlier entries, not by digest — Poseidon2 digests are recomputed on the verifier side
//! during rehydration. The wire deliberately carries no validated invariants; `Deserializable`
//! just reads bytes, and the trusted bytes→state path runs through
//! [`super::DeferredState::rehydrate`].
//!
//! Compared to a flat `Vec<Node>` layout, the index encoding shrinks every Binary entry from a
//! 64-byte payload (two child digests as felts) to 8 bytes (two `u32` indices) — meaningful
//! savings for op-heavy programs and AND-chain–heavy proofs.

use alloc::{sync::Arc, vec::Vec};

use super::{Chunk, Payload, Tag};
use crate::{
    Felt, ZERO,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// CONSTANTS
// ================================================================================================

/// Reserved index sentinel mapping to [`super::TRUE_DIGEST`]. Appears as a child slot in the
/// first AND-node of a chain (whose `prev_root` is the trivial-empty transcript terminal that has
/// no corresponding wire entry).
pub const TRUE_INDEX: u32 = u32::MAX;

// WIRE BODY
// ================================================================================================

/// Wire-format body of a [`WireEntry`]. The variant is discriminated by a single byte on the
/// wire (0/1/2). Validation of the body against the schema-declared
/// [`super::NodeType`] for the entry's tag happens during rehydration, not at the bytes layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireBody {
    /// 8 raw felts as the payload. Used for self-evaluating value leaves (Uint256 leaf,
    /// MockHash digest, ...) and, per the structural heuristic in
    /// [`super::DeferredState::to_wire`], any Expression-bodied node whose two would-be child
    /// digests don't both resolve.
    Value(Payload),
    /// Two indices into earlier wire entries. Each is either a valid index `< current_idx` or
    /// [`TRUE_INDEX`] for the transcript terminal. Rehydration reconstructs the digest-form
    /// payload as `Payload::binary_op(digests[lhs], digests[rhs])`.
    Binary { lhs: u32, rhs: u32 },
    /// `n` chunks of bulk data. Self-describing on the wire (length-prefixed) so deserialization
    /// doesn't depend on the schema for chunk counts.
    Chunks(Arc<[Chunk]>),
}

// WIRE ENTRY
// ================================================================================================

/// A single wire-format node: tag plus body. Multiple entries form a topologically-ordered
/// sequence (child indices reference earlier entries).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireEntry {
    pub tag: Tag,
    pub body: WireBody,
}

// DEFERRED STATE WIRE
// ================================================================================================

/// Wire-format representation of a [`super::DeferredState`].
///
/// `entries` are topologically ordered: each `Binary` entry's child indices are strictly less
/// than its own index (or equal to [`TRUE_INDEX`]). [`super::DeferredState::to_wire`] produces
/// such an ordering via DFS post-order from `root`. The deferred commitment is *derived* from
/// the wire — specifically, the digest of the last entry (which is structurally the topmost
/// AND-node of the transcript) — and is therefore not carried as a separate field. Callers that
/// need the commitment go through [`super::DeferredState::rehydrate`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeferredStateWire {
    pub entries: Vec<WireEntry>,
}

// SERIALIZATION
// ================================================================================================

impl Serializable for WireBody {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            WireBody::Value(payload) => {
                target.write_u8(0);
                payload.write_into(target);
            },
            WireBody::Binary { lhs, rhs } => {
                target.write_u8(1);
                target.write_u32(*lhs);
                target.write_u32(*rhs);
            },
            WireBody::Chunks(chunks) => {
                target.write_u8(2);
                target.write_usize(chunks.len());
                for chunk in chunks.iter() {
                    for felt in chunk {
                        felt.write_into(target);
                    }
                }
            },
        }
    }
}

impl Deserializable for WireBody {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            0 => Ok(WireBody::Value(Payload::read_from(source)?)),
            1 => {
                let lhs = source.read_u32()?;
                let rhs = source.read_u32()?;
                Ok(WireBody::Binary { lhs, rhs })
            },
            2 => {
                let n = source.read_usize()?;
                let mut chunks: Vec<Chunk> = Vec::with_capacity(n);
                for _ in 0..n {
                    let mut chunk = [ZERO; 8];
                    for felt in &mut chunk {
                        *felt = Felt::read_from(source)?;
                    }
                    chunks.push(chunk);
                }
                Ok(WireBody::Chunks(Arc::from(chunks)))
            },
            disc => Err(DeserializationError::InvalidValue(alloc::format!(
                "invalid WireBody discriminant: {disc}"
            ))),
        }
    }
}

impl Serializable for WireEntry {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        for felt in &self.tag {
            felt.write_into(target);
        }
        self.body.write_into(target);
    }
}

impl Deserializable for WireEntry {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let tag: Tag = [
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
        ];
        let body = WireBody::read_from(source)?;
        Ok(Self { tag, body })
    }
}

impl Serializable for DeferredStateWire {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.entries.len());
        for entry in &self.entries {
            entry.write_into(target);
        }
    }
}

impl Deserializable for DeferredStateWire {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let count = source.read_usize()?;
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(WireEntry::read_from(source)?);
        }
        Ok(Self { entries })
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
    /// A `Binary`-body entry's child index is out of range (≥ its own position and not
    /// [`TRUE_INDEX`]).
    #[error("wire Binary entry references an out-of-range child index")]
    BadIndex,
    /// A node's tag is not claimed by the installed schema.
    #[error("wire contains a node with a tag the installed schema does not recognise")]
    UnknownTag,
    /// A node's reconstructed payload shape disagrees with `schema.decode(tag).node_type`. In
    /// practice this fires when a `Chunks` entry's chunk count doesn't match the schema-declared
    /// arity, or when a tag declared `NodeType::Chunks(n)` is encoded as `Value`/`Binary`.
    #[error("wire contains a node whose payload shape disagrees with its tag's declared NodeType")]
    ShapeMismatch,
    /// An AND-chain step's `prev_root` references a digest not present in the wire entries —
    /// the chain doesn't bottom out cleanly at [`super::TRUE_DIGEST`].
    #[error("AND-chain walk encountered a prev_root digest not present in the wire entries")]
    BrokenChain,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Felt;

    fn felts(seed: u64) -> [Felt; 8] {
        core::array::from_fn(|i| Felt::new_unchecked(seed + i as u64))
    }

    /// `DeferredStateWire` is the proof-transit unit; its hand-written `Serializable` /
    /// `Deserializable` must round-trip byte-for-byte across all three `WireBody` variants
    /// (including the `TRUE_INDEX` child sentinel) and the empty wire.
    #[test]
    fn wire_serialize_round_trip_all_bodies() {
        let wire = DeferredStateWire {
            entries: alloc::vec![
                WireEntry {
                    tag: felts(1)[..4].try_into().unwrap(),
                    body: WireBody::Value(Payload::new(felts(10)))
                },
                WireEntry {
                    tag: felts(2)[..4].try_into().unwrap(),
                    body: WireBody::Chunks(Arc::from(alloc::vec![felts(20), felts(30)])),
                },
                WireEntry {
                    tag: felts(3)[..4].try_into().unwrap(),
                    body: WireBody::Binary { lhs: 0, rhs: TRUE_INDEX },
                },
            ],
        };
        let decoded = DeferredStateWire::read_from_bytes(&wire.to_bytes()).unwrap();
        assert_eq!(decoded, wire);

        let empty = DeferredStateWire::default();
        assert_eq!(DeferredStateWire::read_from_bytes(&empty.to_bytes()).unwrap(), empty);
    }
}
