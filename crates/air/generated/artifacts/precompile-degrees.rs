// GENERATED constraint degree multiples -- do not edit.
// Regenerate with `make regenerate-constraints`.
// Periodic values: 1; transition selectors: 0; empty classes: 0; no advisory hints.

impl Air {
    /// Raw symbolic degree multiples for this canonical AIR, without evaluating constraints.
    pub const fn degrees(self) -> ConstraintDegrees {
        match self {
            Self::ChunkNodeSponge => ConstraintDegrees { base: 5, ext: 5 },
            Self::EidosCompression => ConstraintDegrees { base: 3, ext: 3 },
            Self::KeccakRound => ConstraintDegrees { base: 4, ext: 5 },
            Self::BytePairLut => ConstraintDegrees { base: 0, ext: 3 },
            Self::TranscriptEval => ConstraintDegrees { base: 3, ext: 3 },
            Self::UintStoreMul => ConstraintDegrees { base: 3, ext: 3 },
            Self::UintAdd => ConstraintDegrees { base: 3, ext: 3 },
            Self::EcPointStoreGroups => ConstraintDegrees { base: 2, ext: 3 },
            Self::EcGroupAdd => ConstraintDegrees { base: 3, ext: 3 },
            Self::EcMsm => ConstraintDegrees { base: 3, ext: 3 },
            Self::Sha512 => ConstraintDegrees { base: 5, ext: 5 },
            Self::Sha256 => ConstraintDegrees { base: 5, ext: 5 },
        }
    }
}
