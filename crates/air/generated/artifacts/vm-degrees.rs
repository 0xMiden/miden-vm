// GENERATED constraint degree multiples -- do not edit.
// Regenerate with `make regenerate-constraints`.
// Periodic values: 1; transition selectors: 0; empty classes: 0; no advisory hints.

impl Air {
    /// Raw symbolic degree multiples for this canonical AIR, without evaluating constraints.
    pub const fn degrees(self) -> ConstraintDegrees {
        match self {
            Self::Core => ConstraintDegrees { base: 9, ext: 9 },
            Self::Chiplets => ConstraintDegrees { base: 9, ext: 9 },
            Self::EidosCompression => ConstraintDegrees { base: 3, ext: 3 },
            Self::And8Lookup => ConstraintDegrees { base: 0, ext: 3 },
        }
    }
}
