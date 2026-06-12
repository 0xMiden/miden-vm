//! Byte-AND table LogUp lookup AIR.

use core::borrow::Borrow;

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::WindowAccess;

use super::messages::And8Msg;
use crate::{
    Felt,
    constraints::and8_lookup::columns::{And8LookupCols, And8LookupPreprocessedCols},
    lookup::{Deg, LookupBuilder, LookupColumn, LookupGroup},
};

/// Extension trait required by the byte-AND table [`LookupAir`](crate::lookup::LookupAir).
pub(crate) trait And8LookupBuilder: LookupBuilder<F = Felt> {}

/// Per-column fraction stride for the byte-AND table AIR.
pub(crate) const AND8_LOOKUP_COLUMN_SHAPE: [usize; 1] = [1];

/// Emit the table side of the byte-AND lookup.
pub(crate) fn emit_and8_lookup_columns<LB>(builder: &mut LB, local: &And8LookupCols<LB::Var>)
where
    LB: And8LookupBuilder,
{
    let preprocessed = builder.preprocessed();
    let fixed: &And8LookupPreprocessedCols<LB::Var> = preprocessed.current_slice().borrow();
    let a: LB::Expr = fixed.a.into();
    let b: LB::Expr = fixed.b.into();
    let result: LB::Expr = fixed.result.into();

    builder.next_column(
        |col| {
            col.group(
                "and8_table",
                |g| {
                    g.insert(
                        "and8_row",
                        LB::Expr::ONE,
                        local.multiplicity.into(),
                        || And8Msg::new(a, b, result),
                        Deg { v: 1, u: 1 },
                    );
                },
                Deg { v: 1, u: 1 },
            );
        },
        Deg { v: 1, u: 1 },
    );
}
