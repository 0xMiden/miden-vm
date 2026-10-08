use core::{
    fmt::{self, Display, LowerHex},
    num::TryFromIntError,
};

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

impl TryFrom<u64> for MemoryAddress {
    type Error = TryFromIntError;

    fn try_from(address: u64) -> Result<Self, Self::Error> {
        u32::try_from(address).map(Self)
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
