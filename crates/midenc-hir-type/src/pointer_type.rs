use core::{fmt, str::FromStr};

use super::Type;

/// A pointer to an object in memory
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PointerType {
    /// The address space used by pointers of this type.
    pub addrspace: AddressSpace,
    /// The type of value located at the pointed-to address
    pub pointee: Type,
}

impl PointerType {
    /// Create a new byte-addressable pointer type to `pointee`
    pub fn new(pointee: Type) -> Self {
        Self {
            addrspace: AddressSpace::Byte,
            pointee,
        }
    }

    /// Create a new pointer type to `pointee` in `addrspace`
    pub fn new_with_address_space(pointee: Type, addrspace: AddressSpace) -> Self {
        Self { addrspace, pointee }
    }

    /// Returns the type pointed to by pointers of this type
    pub fn pointee(&self) -> &Type {
        &self.pointee
    }

    /// Returns the address space of this pointer type
    pub fn addrspace(&self) -> AddressSpace {
        self.addrspace
    }

    /// Returns true if this pointer type represents a byte pointer
    pub fn is_byte_pointer(&self) -> bool {
        matches!(self.addrspace, AddressSpace::Byte)
    }
}

impl fmt::Display for PointerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use miden_formatting::prettier::PrettyPrint;
        self.pretty_print(f)
    }
}

impl miden_formatting::prettier::PrettyPrint for PointerType {
    fn render(&self) -> miden_formatting::prettier::Document {
        use miden_formatting::prettier::*;

        const_text("ptr<")
            + self.addrspace.render()
            + const_text(", ")
            + self.pointee.render()
            + const_text(">")
    }
}

/// This error is raised when parsing an [AddressSpace]
#[derive(Debug, thiserror::Error)]
pub enum InvalidAddressSpaceError {
    #[error("invalid address space identifier: expected 'byte' or 'element'")]
    InvalidId,
}

/// The address space a pointer address is evaluated in.
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AddressSpace {
    /// The pointer address is evaluated as a byte address.
    ///
    /// This is the default unit type for pointers in HIR.
    #[default]
    Byte,
    /// The pointer address is evaluated as an element address.
    ///
    /// This is the unit type for native Miden VM addresses.
    ///
    /// All byte-addressable pointers must be converted to element pointers at runtime before
    /// loading/storing memory.
    Element,
}

impl fmt::Display for AddressSpace {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use miden_formatting::prettier::PrettyPrint;
        self.pretty_print(f)
    }
}

impl miden_formatting::prettier::PrettyPrint for AddressSpace {
    fn render(&self) -> miden_formatting::prettier::Document {
        use miden_formatting::prettier::*;

        match self {
            Self::Byte => const_text("byte"),
            Self::Element => const_text("element"),
        }
    }
}

impl FromStr for AddressSpace {
    type Err = InvalidAddressSpaceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "byte" => Ok(Self::Byte),
            "element" => Ok(Self::Element),
            _ => Err(InvalidAddressSpaceError::InvalidId),
        }
    }
}
