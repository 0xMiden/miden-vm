//! Compact wire format for deferred-state witnesses.
//!
//! Proofs carry a topologically ordered node list. Join bodies reference earlier entries by index
//! instead of carrying child digests; rehydration recomputes those digests and validates the DAG
//! before any wire data becomes trusted state.

use alloc::{sync::Arc, vec::Vec};

use super::{Chunk, Tag};
use crate::{
    Felt, ZERO,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// CONSTANTS
// ================================================================================================

/// Index sentinel for the virtual [`super::TRUE_DIGEST`] transcript terminal.
pub const TRUE_INDEX: u32 = u32::MAX;

// WIRE BODY
// ================================================================================================

/// Serialized body of a deferred node before schema validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireBody {
    /// Raw expression payload for value-shaped entries.
    Value([Felt; 8]),
    /// Child references by earlier-entry index, with [`TRUE_INDEX`] for the virtual terminal.
    Join { lhs: u32, rhs: u32 },
    /// Bulk chunk payload; rehydration checks the length against the tag schema.
    Chunks(Arc<[Chunk]>),
}

// WIRE ENTRY
// ================================================================================================

/// One topologically ordered wire entry: tag plus body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireEntry {
    pub tag: Tag,
    pub body: WireBody,
}

// DEFERRED STATE WIRE
// ================================================================================================

/// Wire representation of a deferred state.
///
/// The transcript commitment is derived from the last entry's recomputed digest, so the wire does
/// not carry a separate root field. Empty entries represent the empty transcript.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeferredStateWire {
    pub entries: Vec<WireEntry>,
}

// SERIALIZATION
// ================================================================================================

impl Serializable for WireBody {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            WireBody::Value(felts) => {
                target.write_u8(0);
                for felt in felts {
                    felt.write_into(target);
                }
            },
            WireBody::Join { lhs, rhs } => {
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
            0 => {
                let mut felts = [ZERO; 8];
                for felt in &mut felts {
                    *felt = Felt::read_from(source)?;
                }
                Ok(WireBody::Value(felts))
            },
            1 => {
                let lhs = source.read_u32()?;
                let rhs = source.read_u32()?;
                Ok(WireBody::Join { lhs, rhs })
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
        // Wire layout is the 4-felt capacity `[id, arg0, arg1, arg2]`.
        for felt in &self.tag.as_word() {
            felt.write_into(target);
        }
        self.body.write_into(target);
    }
}

impl Deserializable for WireEntry {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let tag = Tag::from_word([
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
            Felt::read_from(source)?,
        ]);
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

/// Reasons untrusted wire data failed deferred-state rehydration.
///
/// Any variant rejects the proof witness under the installed precompile schema. The enum is not
/// `Clone`/`Eq` because predicate failures carry opaque precompile errors.
#[derive(Debug, thiserror::Error)]
pub enum IntegrityError {
    /// A join child index is not earlier than the current entry and is not [`TRUE_INDEX`].
    #[error("wire Join entry references an out-of-range child index")]
    BadIndex,
    /// A non-framework tag is not claimed by the installed schema.
    #[error("wire contains a node with a tag the installed schema does not recognise")]
    UnknownTag,
    /// The wire body shape or chunk count does not match the tag's declared node type.
    #[error("wire contains a node whose payload shape disagrees with its tag's declared NodeType")]
    ShapeMismatch,
    /// The transcript chain references a previous root missing from the wire closure.
    #[error("AND-chain walk encountered a prev_root digest not present in the wire entries")]
    BrokenChain,
    /// A transcript-chain step is not tagged with the framework TRUE tag.
    #[error("AND-chain walk encountered a node whose tag is not Tag::TRUE")]
    NonAndNode,
    /// A transcript-chain step does not carry `(prev_root, statement_digest)`.
    #[error("AND-chain walk encountered a node whose payload is not in join shape")]
    BadAndPayload,
    /// A logged statement digest is absent from the wire closure.
    #[error("AND-chain walk references a statement digest that is not in the node set")]
    MissingStatement,
    /// A logged statement failed while being re-evaluated by its precompile.
    #[error("AND-chain statement failed re-evaluation: {0}")]
    PredicateFailed(#[from] super::PrecompileError),
    /// A logged statement reduced, but not to the canonical TRUE node.
    #[error("AND-chain statement reduced to a non-TRUE canonical form")]
    PredicateNotTrue,
    /// The wire includes data outside the transcript root's reachable closure.
    #[error("wire contains an entry not reachable from the transcript root")]
    DanglingNode,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Felt;

    fn felts(seed: u64) -> [Felt; 8] {
        core::array::from_fn(|i| Felt::new_unchecked(seed + i as u64))
    }

    /// The proof-transit format must round-trip every body variant and the empty transcript.
    #[test]
    fn wire_serialize_round_trip_all_bodies() {
        let wire = DeferredStateWire {
            entries: alloc::vec![
                WireEntry {
                    tag: Tag::from_word(felts(1)[..4].try_into().unwrap()),
                    body: WireBody::Value(felts(10))
                },
                WireEntry {
                    tag: Tag::from_word(felts(2)[..4].try_into().unwrap()),
                    body: WireBody::Chunks(Arc::from(alloc::vec![felts(20), felts(30)])),
                },
                WireEntry {
                    tag: Tag::from_word(felts(3)[..4].try_into().unwrap()),
                    body: WireBody::Join { lhs: 0, rhs: TRUE_INDEX },
                },
            ],
        };
        let decoded = DeferredStateWire::read_from_bytes(&wire.to_bytes()).unwrap();
        assert_eq!(decoded, wire);

        let empty = DeferredStateWire::default();
        assert_eq!(DeferredStateWire::read_from_bytes(&empty.to_bytes()).unwrap(), empty);
    }
}
