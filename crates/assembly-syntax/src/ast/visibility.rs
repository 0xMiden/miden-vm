use core::fmt;

// ITEM VISIBILITY
// ================================================================================================

/// Represents the visibility of an item (procedure, constant, etc.) globally.
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Visibility {
    /// The item is visible outside its defining module
    Public = 0,
    /// The item is visible only within its defining module
    #[default]
    Private = 1,
    /// The item is visible outside its module, but is not exported from the package.
    Internal = 2,
}

impl fmt::Display for Visibility {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Public => f.write_str("pub"),
            Self::Internal => f.write_str("pub(package)"),
            Self::Private => Ok(()),
        }
    }
}

impl Visibility {
    /// Returns true if the item is visible outside its defining module
    pub fn is_public(&self) -> bool {
        matches!(self, Self::Public | Self::Internal)
    }

    /// Returns true if the item is eligible for export from the package.
    pub fn is_exported(&self) -> bool {
        matches!(self, Self::Public)
    }
}
