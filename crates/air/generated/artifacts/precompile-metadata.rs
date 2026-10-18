// GENERATED per-AIR facts -- do not edit.
// Regenerate with `make regenerate-constraints`.
// Raw auxiliary widths are extension-valued; counts come from captured assertion roots.

impl Air {
    /// Canonical facts keyed by identity, independent of a selected slice's position.
    pub const fn metadata(self) -> crate::metadata::AirMetadata {
        use crate::metadata::{AirMetadata, ColumnWidths};
        use miden_stark::{air::ConstraintCounts, security::LookupShape};
        let (preprocessed, main, aux, base, ext, fractions_per_row, max_message_width) = match self {
            Self::ChunkNodeSponge => (0, 93, 18, 81, 19, 49, 18),
            Self::EidosCompression => (0, 111, 20, 165, 22, 39, 18),
            Self::KeccakRound => (0, 64, 10, 15, 11, 34, 18),
            Self::BytePairLut => (5, 7, 4, 0, 5, 7, 18),
            Self::TranscriptEval => (0, 37, 10, 60, 11, 15, 18),
            Self::UintStoreMul => (0, 44, 27, 24, 33, 47, 18),
            Self::UintAdd => (0, 30, 3, 22, 5, 5, 18),
            Self::EcPointStoreGroups => (0, 24, 4, 18, 5, 7, 18),
            Self::EcGroupAdd => (0, 21, 10, 32, 11, 19, 18),
            Self::EcMsm => (0, 35, 12, 53, 13, 24, 18),
            Self::Sha512 => (0, 54, 14, 115, 15, 26, 18),
            Self::Sha256 => (0, 40, 11, 99, 12, 19, 18),
        };
        AirMetadata {
            widths: ColumnWidths { preprocessed, main, aux },
            constraints: ConstraintCounts { base, ext },
            degrees: self.degrees(),
            lookup: LookupShape { fractions_per_row, max_message_width },
        }
    }
}

/// Derive geometry from an explicit nonempty AIR slice in its caller-supplied order.
pub const fn geometry(airs: &[Air], alignment: usize) -> crate::metadata::RelationGeometry {
    assert!(!airs.is_empty(), "a relation needs at least one AIR");
    let mut result = crate::metadata::RelationGeometry::new(alignment);
    let mut i = 0;
    while i < airs.len() {
        result = result.with_air(airs[i].metadata());
        i += 1;
    }
    result
}
