use alloc::string::String;

use miden_core::utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};

use crate::Word;

pub(crate) mod resolver;

/// The name of a dependency
#[derive(Debug, Clone, PartialEq, Eq, derive_more::From)]
#[cfg_attr(feature = "arbitrary", derive(proptest_derive::Arbitrary))]
pub struct DependencyName(String);

impl Serializable for DependencyName {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.0.get_size_hint()
    }
}

impl Deserializable for DependencyName {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let name = String::read_from(source)?;
        Ok(Self(name))
    }
}

/// A package dependency
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(proptest_derive::Arbitrary))]
pub struct Dependency {
    /// The name of the dependency.
    /// Serves as a human-readable identifier for the dependency and a search hint for the resolver
    pub name: DependencyName,
    /// The digest of the dependency.
    /// Serves as an ultimate source of truth for identifying the dependency.
    #[cfg_attr(feature = "arbitrary", proptest(value = "Word::default()"))]
    pub digest: Word,
}

impl Serializable for Dependency {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { name, digest } = self;

        name.write_into(target);
        digest.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        let Self { name, digest } = self;

        name.get_size_hint() + digest.get_size_hint()
    }
}

impl Deserializable for Dependency {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let name = DependencyName(String::read_from(source)?);
        let digest = Word::read_from(source)?;
        Ok(Self { name, digest })
    }
}
