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
    Private = 2,
}

impl fmt::Display for Visibility {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_public() { f.write_str("pub") } else { Ok(()) }
    }
}

impl Visibility {
    /// Returns true if the current item has public visibility
    pub fn is_public(&self) -> bool {
        matches!(self, Self::Public)
    }
}
