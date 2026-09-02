use core::fmt::{self, Display, LowerHex};

use crate::{
    Felt,
    serde::{self, Deserializable, Serializable},
};

// EXECUTION CONTEXT
// ================================================================================================

/// Identifies an execution context.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContextId(u32);

impl ContextId {
    /// Returns the root execution context ID.
    pub const fn root() -> Self {
        Self(0)
    }

    /// Returns true when this is the root execution context.
    pub const fn is_root(self) -> bool {
        self.0 == 0
    }

    /// Returns this context ID as a `u32`.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl From<u32> for ContextId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<ContextId> for u32 {
    fn from(context_id: ContextId) -> Self {
        context_id.0
    }
}

impl From<ContextId> for u64 {
    fn from(context_id: ContextId) -> Self {
        context_id.0.into()
    }
}

impl From<ContextId> for Felt {
    fn from(context_id: ContextId) -> Self {
        Felt::from_u32(context_id.0)
    }
}

impl Serializable for ContextId {
    fn write_into<W: serde::ByteWriter>(&self, target: &mut W) {
        Serializable::write_into(&self.0, target);
    }
}

impl Deserializable for ContextId {
    fn read_from<R: serde::ByteReader>(
        source: &mut R,
    ) -> Result<Self, serde::DeserializationError> {
        Ok(Self(<u32 as Deserializable>::read_from(source)?))
    }

    fn min_serialized_size() -> usize {
        <u32 as Deserializable>::min_serialized_size()
    }
}

impl Display for ContextId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

// MEMORY ADDRESS
// ================================================================================================

/// Identifies an element address in VM memory.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MemoryAddress(u32);

impl MemoryAddress {
    /// Creates a memory address.
    pub const fn new(address: u32) -> Self {
        Self(address)
    }

    /// Returns this address as a `u32`.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl From<u32> for MemoryAddress {
    fn from(address: u32) -> Self {
        Self(address)
    }
}

impl From<MemoryAddress> for u32 {
    fn from(address: MemoryAddress) -> Self {
        address.0
    }
}

impl Display for MemoryAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl LowerHex for MemoryAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        LowerHex::fmt(&self.0, f)
    }
}

impl core::ops::Add<MemoryAddress> for MemoryAddress {
    type Output = Self;

    fn add(self, rhs: MemoryAddress) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl core::ops::Add<u32> for MemoryAddress {
    type Output = Self;

    fn add(self, rhs: u32) -> Self::Output {
        Self(self.0 + rhs)
    }
}
