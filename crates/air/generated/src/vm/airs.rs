//! Production VM AIR adapters backed by build-generated evaluators.

use miden_air_definitions::vm::{self as source, MidenAir as Source};

use crate::kernel::define_dispatch;

/// Production evaluator for an authored VM AIR.
///
/// Kernel capabilities are implemented by generated dispatch alongside this wrapper; authored
/// source and witness capabilities retain their independent source ownership.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MidenAir(pub source::MidenAir);

impl MidenAir {
    pub const CORE: Self = Self(source::MidenAir::CORE);
    pub const CHIPLETS: Self = Self(source::MidenAir::CHIPLETS);
    pub const EIDOS_COMPRESSION: Self = Self(source::MidenAir::EIDOS_COMPRESSION);
    pub const AND8_LOOKUP: Self = Self(source::MidenAir::AND8_LOOKUP);

    pub const fn instance_index(self) -> usize {
        self.0.instance_index()
    }
    pub const fn name(self) -> &'static str {
        self.0.name()
    }
    /// Lookup fractions emitted per row, one entry per auxiliary lookup column.
    ///
    /// Available without naming a lookup builder, so callers that only need the shape — such as
    /// the security estimator — do not have to pick an unrelated builder type to read it.
    pub fn column_shape(self) -> &'static [usize] {
        self.0.column_shape()
    }

    pub const fn file_token(self) -> &'static str {
        self.0.file_token()
    }
}

#[allow(clippy::eq_op)]
mod evaluators {
    include!(concat!(env!("OUT_DIR"), "/native_evaluators.rs"));
}

mod descriptors {
    include!(concat!(env!("OUT_DIR"), "/native_descriptors.rs"));
}

define_dispatch!(MidenAir, Source, VmPrepared;
    Core => (CORE_DESCRIPTOR, descriptor_core, CORE_GEOMETRY, precompute_core, eval_core, CORE_PREPARED_TERMS),
    Chiplets => (CHIPLETS_DESCRIPTOR, descriptor_chiplets, CHIPLETS_GEOMETRY, precompute_chiplets, eval_chiplets, CHIPLETS_PREPARED_TERMS),
    EidosCompression => (EIDOS_DESCRIPTOR, descriptor_eidos_compression, EIDOS_COMPRESSION_GEOMETRY, precompute_eidos_compression, eval_eidos_compression, EIDOS_COMPRESSION_PREPARED_TERMS),
    And8Lookup => (AND8_DESCRIPTOR, descriptor_and8_lookup, AND8_LOOKUP_GEOMETRY, precompute_and8_lookup, eval_and8_lookup, AND8_LOOKUP_PREPARED_TERMS),
);
