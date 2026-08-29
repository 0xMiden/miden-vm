use super::DeferredRoot;
use crate::{
    Word,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

/// The exact deferred-state claim proved by a precompile VM proof.
///
/// The root is the PVM STARK public input. The commitment identifies the claim in proof-request
/// keys and downstream statements. For this claim type, the protocol defines that commitment to
/// be the root itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeferredClaim(DeferredRoot);

impl DeferredClaim {
    /// Creates a claim for `deferred_root`.
    pub const fn new(deferred_root: DeferredRoot) -> Self {
        Self(deferred_root)
    }

    /// Returns the deferred root used as the PVM STARK public input.
    pub const fn root(self) -> DeferredRoot {
        self.0
    }

    /// Returns the identifier used to bind and address proofs of this claim.
    ///
    /// For this claim type, the protocol defines the commitment as the root itself, so this
    /// returns the same word as [`Self::root`].
    pub const fn commitment(self) -> Word {
        self.0
    }
}

impl Serializable for DeferredClaim {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
    }
}

impl Deserializable for DeferredClaim {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self::new(DeferredRoot::read_from(source)?))
    }

    fn min_serialized_size() -> usize {
        DeferredRoot::min_serialized_size()
    }
}
