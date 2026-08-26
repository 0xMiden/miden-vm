//! Byte-pair table LogUp lookup AIR.

use core::borrow::Borrow;

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::WindowAccess;

use super::messages::{And8Msg, RangeMsg};
use crate::{
    Felt,
    constraints::and8_lookup::columns::{
        And8LookupCols, And8LookupPreprocessedCols, BYTE_LOOKUP_COLUMN_COUNT,
    },
    lookup::{Deg, LookupBatch, LookupBuilder, LookupColumn, LookupGroup, LookupMessage},
};

/// Extension trait required by the byte-pair table [`LookupAir`](crate::lookup::LookupAir).
pub(crate) trait And8LookupBuilder: LookupBuilder<F = Felt> {}

/// Per-column fraction stride for the byte-pair table AIR.
pub(crate) const AND8_LOOKUP_COLUMN_SHAPE: [usize; BYTE_LOOKUP_COLUMN_COUNT / 2] =
    [2; BYTE_LOOKUP_COLUMN_COUNT / 2];
const _: () = assert!(BYTE_LOOKUP_COLUMN_COUNT.is_multiple_of(2));

const BYTE_TABLE_DEG: Deg = Deg { v: 1, u: 1 };
const BYTE_TABLE_PAIR_DEG: Deg = Deg { v: 2, u: 2 };

fn emit_byte_table_pair<LB, M0, M1>(
    builder: &mut LB,
    group_name: &'static str,
    row0_name: &'static str,
    multiplicity0: LB::Expr,
    msg0: impl FnOnce() -> M0,
    row1_name: &'static str,
    multiplicity1: LB::Expr,
    msg1: impl FnOnce() -> M1,
) where
    LB: And8LookupBuilder,
    M0: LookupMessage<LB::Expr, LB::ExprEF>,
    M1: LookupMessage<LB::Expr, LB::ExprEF>,
{
    builder.next_column(
        |col| {
            col.group(
                group_name,
                |g| {
                    g.batch(
                        group_name,
                        LB::Expr::ONE,
                        |batch| {
                            batch.insert(row0_name, multiplicity0, msg0(), BYTE_TABLE_DEG);
                            batch.insert(row1_name, multiplicity1, msg1(), BYTE_TABLE_DEG);
                        },
                        BYTE_TABLE_PAIR_DEG,
                    );
                },
                BYTE_TABLE_PAIR_DEG,
            );
        },
        BYTE_TABLE_PAIR_DEG,
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

    emit_byte_table_pair(
        builder,
        "and8_and_range_tables",
        "and8_row",
        local.and_multiplicity.into(),
        || And8Msg::new(a.clone(), b.clone(), and.clone()),
        "range_row",
        local.range_multiplicity.into(),
        || {
            let value = a.clone() * LB::Expr::from_u16(256) + b.clone();
            RangeMsg { value }
        },
    );

    let rot12_mults = [
        local.rot12_pos0_multiplicity,
        local.rot12_pos1_multiplicity,
        local.rot12_pos2_multiplicity,
        local.rot12_pos3_multiplicity,
    ];
    let rot7_mults = [
        local.rot7_pos0_multiplicity,
        local.rot7_pos1_multiplicity,
        local.rot7_pos2_multiplicity,
        local.rot7_pos3_multiplicity,
    ];
    let rotations = rot12.into_iter().zip(rot12_mults).zip(rot7.into_iter().zip(rot7_mults));
    for (pos, ((rot12_result, rot12_multiplicity), (rot7_result, rot7_multiplicity))) in
        rotations.enumerate()
    {
        emit_byte_table_pair(
            builder,
            "and8_rotation_tables",
            "rot12_row",
            rot12_multiplicity.into(),
            || And8Msg::eidos_compression_rot12(pos, a.clone(), b.clone(), rot12_result),
            "rot7_row",
            rot7_multiplicity.into(),
            || And8Msg::eidos_compression_rot7(pos, a.clone(), b.clone(), rot7_result),
        );
    }
}
