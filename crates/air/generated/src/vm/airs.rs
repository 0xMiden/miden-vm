//! Production VM AIR adapters backed by build-generated evaluators.

use miden_air_definitions::vm as source;

/// Production evaluator for an authored VM AIR.
///
/// Native kernel capabilities are implemented by the generated dispatch module; authored
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
