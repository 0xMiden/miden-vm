//! Transcript node discriminants for the currently integrated prover slices.

/// Canonical uint operation discriminant.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum UintOpId {
    Add = 1,
    Sub = 2,
    Mul = 3,
    Is = 4,
    /// Internal arithmetic helper with no canonical uint deferred node.
    Neg = 255,
}

impl UintOpId {
    pub const fn canonical_id(self) -> u64 {
        match self {
            Self::Add => 1,
            Self::Sub => 2,
            Self::Mul => 3,
            Self::Is => 4,
            Self::Neg => panic!("uint neg has no canonical deferred node"),
        }
    }
}

/// Canonical curve operation discriminant.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum EcOpId {
    Add = 1,
    Sub = 2,
    Is = 3,
    /// Internal helper with no canonical curve deferred node.
    Neg = 255,
}

impl EcOpId {
    pub const fn canonical_id(self) -> u64 {
        match self {
            Self::Add => 1,
            Self::Sub => 2,
            Self::Is => 3,
            Self::Neg => panic!("EC neg has no canonical deferred node"),
        }
    }
}
