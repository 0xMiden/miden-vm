//! Relation geometry shared by host tooling and production consumers.
//!
//! These are derived facts, not security policy or accepted protocol identities. Authored schema
//! and equations remain the inputs; production supplies generated per-AIR facts.

use miden_core::{
    Felt,
    field::{BasedVectorSpace, QuadFelt},
};
use miden_stark::{
    air::{ConstraintCounts, ConstraintDegrees},
    security::{AirShape, LookupShape},
};

/// Base coordinates per extension-valued column.
pub const EXTENSION_DEGREE: usize = <QuadFelt as BasedVectorSpace<Felt>>::DIMENSION;
/// The authored relations open local and next rotations.
pub const NUM_OOD_POINTS: u32 = 2;

/// Raw columns before commitment padding. Auxiliary columns are extension-valued.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ColumnWidths {
    pub preprocessed: usize,
    pub main: usize,
    pub aux: usize,
}

impl ColumnWidths {
    /// Each trace is a separate matrix, padded separately after extension-coordinate expansion.
    pub const fn committed(self, alignment: usize) -> CommittedWidths {
        assert!(alignment > 0, "commitment alignment must be positive");
        CommittedWidths {
            preprocessed: aligned(self.preprocessed, alignment),
            main: aligned(self.main, alignment),
            aux: aligned(mul(self.aux, EXTENSION_DEGREE), alignment),
        }
    }
}

/// Separately padded matrix widths, all in base coordinates. Cannot be expanded a second time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CommittedWidths {
    pub preprocessed: usize,
    pub main: usize,
    pub aux: usize,
}

impl CommittedWidths {
    pub const fn total(self) -> usize {
        add(add(self.preprocessed, self.main), self.aux)
    }
}

/// Canonical facts for one AIR. Lookup fractions exclude once-per-proof boundary messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AirMetadata {
    pub widths: ColumnWidths,
    pub constraints: ConstraintCounts,
    pub degrees: ConstraintDegrees,
    pub lookup: LookupShape,
}

/// Geometry of an explicit nonempty ordered AIR slice. No canonical-position indexing is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelationGeometry {
    pub num_airs: usize,
    pub constraints: ConstraintCounts,
    pub max_constraint_degree: usize,
    /// Sums of separately padded base-coordinate matrix widths.
    pub committed: CommittedWidths,
    pub lookup: LookupShape,
    pub alignment: usize,
}

impl RelationGeometry {
    /// Start an ordered fold; call `with_air` for each selected identity before reading its shape.
    pub const fn new(alignment: usize) -> Self {
        assert!(alignment > 0, "commitment alignment must be positive");
        Self {
            num_airs: 0,
            constraints: ConstraintCounts { base: 0, ext: 0 },
            max_constraint_degree: 0,
            committed: CommittedWidths { preprocessed: 0, main: 0, aux: 0 },
            lookup: LookupShape {
                fractions_per_row: 0,
                max_message_width: 0,
            },
            alignment,
        }
    }

    pub const fn with_air(mut self, air: AirMetadata) -> Self {
        self.num_airs = add(self.num_airs, 1);
        self.constraints.base = add(self.constraints.base, air.constraints.base);
        self.constraints.ext = add(self.constraints.ext, air.constraints.ext);
        if air.degrees.base > self.max_constraint_degree {
            self.max_constraint_degree = air.degrees.base;
        }
        if air.degrees.ext > self.max_constraint_degree {
            self.max_constraint_degree = air.degrees.ext;
        }
        let columns = air.widths.committed(self.alignment);
        self.committed.preprocessed = add(self.committed.preprocessed, columns.preprocessed);
        self.committed.main = add(self.committed.main, columns.main);
        self.committed.aux = add(self.committed.aux, columns.aux);
        self.lookup.fractions_per_row = self
            .lookup
            .fractions_per_row
            .checked_add(air.lookup.fractions_per_row)
            .expect("lookup fraction count overflow");
        if air.lookup.max_message_width > self.lookup.max_message_width {
            self.lookup.max_message_width = air.lookup.max_message_width;
        }
        self
    }

    pub const fn num_composed_constraints(self) -> usize {
        assert!(self.num_airs > 0, "a relation needs at least one AIR");
        add(add(self.constraints.base, self.constraints.ext), self.num_airs - 1)
    }

    /// Unpadded degree bound after division by the vanishing polynomial, at least one.
    pub const fn logical_quotient_chunks(self) -> usize {
        let degree = self.max_constraint_degree.saturating_sub(1);
        if degree == 0 { 1 } else { degree }
    }

    /// Power-of-two extension-valued chunks, distinct from padded committed base columns.
    pub const fn quotient_chunks(self) -> usize {
        self.logical_quotient_chunks()
            .checked_next_power_of_two()
            .expect("quotient chunk count overflow")
    }

    pub const fn quotient_width(self) -> usize {
        aligned(mul(self.quotient_chunks(), EXTENSION_DEGREE), self.alignment)
    }

    pub const fn num_deep_terms(self) -> u32 {
        narrow(add(add(self.committed.total(), self.quotient_width()), NUM_OOD_POINTS as usize))
    }

    pub const fn air_shape(self) -> AirShape {
        AirShape {
            num_composed_constraints: narrow(self.num_composed_constraints()),
            max_constraint_degree: narrow(self.max_constraint_degree),
            num_quotient_chunks: narrow(self.quotient_chunks()),
            max_combo: NUM_OOD_POINTS,
            num_deep_terms: Some(self.num_deep_terms()),
            lookup: Some(self.lookup),
        }
    }
}

// Metadata describes trusted code-owned relations. Fail in release as well as debug rather than
// allowing a large alignment or shape to wrap into an unsound security input.
const fn add(a: usize, b: usize) -> usize {
    a.checked_add(b).expect("relation geometry addition overflow")
}
const fn mul(a: usize, b: usize) -> usize {
    a.checked_mul(b).expect("relation geometry multiplication overflow")
}
const fn aligned(width: usize, alignment: usize) -> usize {
    assert!(alignment > 0, "commitment alignment must be positive");
    let remainder = width % alignment;
    if remainder == 0 {
        width
    } else {
        add(width, alignment - remainder)
    }
}
const fn narrow(value: usize) -> u32 {
    assert!(value <= u32::MAX as usize, "relation shape exceeds u32");
    value as u32
}
