//! Byte-pair table LogUp lookup AIR.

use core::borrow::Borrow;

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::WindowAccess;

use super::messages::And8Msg;
use crate::{
    Felt,
    constraints::and8_lookup::columns::{
        And8LookupCols, And8LookupPreprocessedCols, BYTE_LOOKUP_KIND_COUNT,
    },
    lookup::{Deg, LookupBuilder, LookupColumn, LookupGroup, LookupMessage},
};

/// Extension trait required by the byte-pair table [`LookupAir`](crate::lookup::LookupAir).
pub(crate) trait And8LookupBuilder: LookupBuilder<F = Felt> {}

/// Per-column fraction stride for the byte-pair table AIR.
pub(crate) const AND8_LOOKUP_COLUMN_SHAPE: [usize; BYTE_LOOKUP_KIND_COUNT] =
    [1; BYTE_LOOKUP_KIND_COUNT];

const BYTE_TABLE_DEG: Deg = Deg { v: 1, u: 1 };

fn emit_byte_table_column<LB, M>(
    builder: &mut LB,
    group_name: &'static str,
    row_name: &'static str,
    multiplicity: LB::Expr,
    msg: impl FnOnce() -> M,
) where
    LB: And8LookupBuilder,
    M: LookupMessage<LB::Expr, LB::ExprEF>,
{
    builder.next_column(
        |col| {
            col.group(
                group_name,
                |g| {
                    g.insert(row_name, LB::Expr::ONE, multiplicity, msg, BYTE_TABLE_DEG);
                },
                BYTE_TABLE_DEG,
            );
        },
        BYTE_TABLE_DEG,
    );
}

/// Emit the table side of the byte-pair lookup.
pub(crate) fn emit_and8_lookup_columns<LB>(builder: &mut LB, local: &And8LookupCols<LB::Var>)
where
    LB: And8LookupBuilder,
{
    let preprocessed = builder.preprocessed();
    let fixed: &And8LookupPreprocessedCols<LB::Var> = preprocessed.current_slice().borrow();
    let a: LB::Expr = fixed.a.into();
    let b: LB::Expr = fixed.b.into();
    let and: LB::Expr = fixed.and.into();
    let rot12 = [
        fixed.rot12_pos0.into(),
        fixed.rot12_pos1.into(),
        fixed.rot12_pos2.into(),
        fixed.rot12_pos3.into(),
    ];
    let rot7 = [
        fixed.rot7_pos0.into(),
        fixed.rot7_pos1.into(),
        fixed.rot7_pos2.into(),
        fixed.rot7_pos3.into(),
    ];

    emit_byte_table_column(
        builder,
        "and8_table",
        "and8_row",
        local.and_multiplicity.into(),
        || And8Msg::new(a.clone(), b.clone(), and.clone()),
    );

    let rot12_mults = [
        local.rot12_pos0_multiplicity,
        local.rot12_pos1_multiplicity,
        local.rot12_pos2_multiplicity,
        local.rot12_pos3_multiplicity,
    ];
    for (pos, (result, multiplicity)) in rot12.into_iter().zip(rot12_mults).enumerate() {
        emit_byte_table_column(
            builder,
            "and8_table_rot12",
            "rot12_row",
            multiplicity.into(),
            || And8Msg::blakeg_rot12(pos, a.clone(), b.clone(), result.clone()),
        );
    }

    let rot7_mults = [
        local.rot7_pos0_multiplicity,
        local.rot7_pos1_multiplicity,
        local.rot7_pos2_multiplicity,
        local.rot7_pos3_multiplicity,
    ];
    for (pos, (result, multiplicity)) in rot7.into_iter().zip(rot7_mults).enumerate() {
        emit_byte_table_column(builder, "and8_table_rot7", "rot7_row", multiplicity.into(), || {
            And8Msg::blakeg_rot7(pos, a.clone(), b.clone(), result.clone())
        });
    }
}
