//! Contains the metadata definition for each persisted tree in the forest.

use miden_serde_utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};
use serde::{Deserialize, Serialize};

use crate::{Word, merkle::smt::VersionId};

/// The basic metadata stored for each tree in the forest.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct TreeMetadata {
    /// The version to which the tree belongs.
    pub version: VersionId,

    /// The current value of the tree's root.
    pub root_value: Word,

    /// The number of entries that are populated on disk.
    pub entry_count: u64,
}

impl Serializable for TreeMetadata {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.version);
        target.write(self.root_value);
        target.write(self.entry_count);
    }

    fn get_size_hint(&self) -> usize {
        size_of::<VersionId>() + size_of::<Word>() + size_of::<u64>()
    }
}

impl Deserializable for TreeMetadata {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let version = source.read::<VersionId>()?;
        let root_value = source.read::<Word>()?;
        let entry_count = source.read_u64()?;

        Ok(Self { version, root_value, entry_count })
    }
}
