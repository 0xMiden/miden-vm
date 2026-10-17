//! Selection of optional hash chiplets in the precompile relation.

/// Optional hash precompiles included in a PVM AIR relation.
///
/// All variants retain the shared Eidos, transcript, uint, curve, and byte-pair lookup AIRs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PvmAirVariant(u8);

impl PvmAirVariant {
    /// No optional hash precompiles.
    pub const NONE: Self = Self(0);
    /// Keccak-256, including its chunk, node, sponge, and round chiplets.
    pub const KECCAK: Self = Self(1);
    /// SHA-256.
    pub const SHA256: Self = Self(2);
    /// SHA-512.
    pub const SHA512: Self = Self(4);
    /// All supported hash precompiles, matching the original PVM relation.
    pub const ALL: Self = Self(7);

    /// Every supported selection in ascending encoded order.
    pub const ALL_VARIANTS: [Self; 8] =
        [Self(0), Self(1), Self(2), Self(3), Self(4), Self(5), Self(6), Self(7)];

    /// Returns whether every hash in `other` is selected.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns the selection containing the hashes from both variants.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns the compact three-bit encoding of this selection.
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// Decodes a selection, rejecting bits outside the supported hash set.
    pub const fn from_u8(value: u8) -> Option<Self> {
        if value <= Self::ALL.0 { Some(Self(value)) } else { None }
    }
}

impl Default for PvmAirVariant {
    fn default() -> Self {
        Self::ALL
    }
}
