// GENERATED per-AIR facts -- do not edit.
// Regenerate with `make regenerate-constraints`.
// Raw auxiliary widths are extension-valued; counts come from captured assertion roots.

impl Air {
    /// Canonical facts keyed by identity, independent of a selected slice's position.
    pub const fn metadata(self) -> crate::metadata::AirMetadata {
        use crate::metadata::{AirMetadata, ColumnWidths};
        use miden_stark::{air::ConstraintCounts, security::LookupShape};
        let (preprocessed, main, aux, base, ext, fractions_per_row, max_message_width) = match self {
            Self::Core => (0, 48, 4, 250, 5, 18, 16),
            Self::Chiplets => (0, 24, 4, 175, 5, 13, 16),
            Self::EidosCompression => (0, 108, 20, 165, 23, 40, 16),
            Self::And8Lookup => (5, 7, 4, 0, 5, 7, 16),
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
