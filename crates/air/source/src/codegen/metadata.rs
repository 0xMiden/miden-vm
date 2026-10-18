//! Per-AIR facts from authored schema and capture. No production metadata is an input.
use alloc::string::String;
use core::fmt::{Debug, Write};

use miden_core::{Felt, field::QuadFelt};
use miden_stark::{air::LiftedAir, capture::ir::capture};

pub const VM_FILE: &str = "vm-metadata.rs";
pub const PRECOMPILE_FILE: &str = "precompile-metadata.rs";

pub fn generate() -> [(&'static str, String); 2] {
    [
        (
            VM_FILE,
            table(&crate::vm::AIRS, |air| {
                (air.column_shape().iter().sum(), crate::vm::logup::MIDEN_MAX_MESSAGE_WIDTH)
            }),
        ),
        (
            PRECOMPILE_FILE,
            table(&crate::precompile::Air::all(), |air| {
                crate::precompile::air::lookup_shape(air.clone())
            }),
        ),
    ]
}

fn table<A: LiftedAir<Felt, QuadFelt> + Debug>(
    airs: &[A],
    lookup: impl Fn(&A) -> (usize, usize),
) -> String {
    let mut output = String::from("\
// GENERATED per-AIR facts -- do not edit.
// Regenerate with `make regenerate-constraints`.
// Raw auxiliary widths are extension-valued; counts come from captured assertion roots.

impl Air {
    /// Canonical facts keyed by identity, independent of a selected slice's position.
    pub const fn metadata(self) -> crate::metadata::AirMetadata {
        use crate::metadata::{AirMetadata, ColumnWidths};
        use miden_stark::{air::ConstraintCounts, security::LookupShape};
        let (preprocessed, main, aux, base, ext, fractions_per_row, max_message_width) = match self {
");
    for air in airs {
        let (_, constraints) = capture(air);
        let (fractions, message_width) = lookup(air);
        writeln!(
            output,
            "            Self::{air:?} => ({}, {}, {}, {}, {}, {fractions}, {message_width}),",
            air.preprocessed_width(),
            air.width(),
            air.aux_width(),
            constraints.base_roots.len(),
            constraints.ext_roots.len()
        )
        .unwrap();
    }
    output.push_str(
        "        };
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
    assert!(!airs.is_empty(), \"a relation needs at least one AIR\");
    let mut result = crate::metadata::RelationGeometry::new(alignment);
    let mut i = 0;
    while i < airs.len() {
        result = result.with_air(airs[i].metadata());
        i += 1;
    }
    result
}
",
    );
    output
}
