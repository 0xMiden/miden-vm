//! Byte-pair table LogUp lookup AIR.

use core::borrow::Borrow;

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::WindowAccess;

use super::messages::{BytePairLookupMsg, EidosRotationMsg, RangeMsg};
use crate::{
    Felt,
    constraints::and8_lookup::{
        columns::{And8LookupCols, And8LookupPreprocessedCols},
        eidos::{self, BytePairRelation},
    },
    lookup::{Deg, LookupBatch, LookupBuilder, LookupColumn, LookupGroup, LookupMessage},
};

/// Extension trait required by the byte-pair table [`LookupAir`](crate::lookup::LookupAir).
pub(crate) trait And8LookupBuilder: LookupBuilder<F = Felt> {}

/// Per-column fraction stride for the byte-pair table AIR.
pub(crate) const AND8_LOOKUP_COLUMN_SHAPE: [usize; 4] = [1, 2, 2, 2];

const BYTE_TABLE_DEG: Deg = Deg { v: 1, u: 1 };
const BYTE_TABLE_PAIR_DEG: Deg = Deg { v: 2, u: 2 };

fn emit_byte_table_single<LB, M>(
    builder: &mut LB,
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
                "byte_pair_table",
                |g| {
                    g.batch(
                        "byte_pair_table",
                        LB::Expr::ONE,
                        |batch| {
                            batch.insert(row_name, multiplicity, msg(), BYTE_TABLE_DEG);
                        },
                        BYTE_TABLE_DEG,
                    );
                },
                BYTE_TABLE_DEG,
            );
        },
        BYTE_TABLE_DEG,
    );
}

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
    let x: LB::Expr = fixed.xor.into();
    let relation_values =
        eidos::provider_values(x.clone(), fixed.wrap12.into(), fixed.wrap7.into());

    emit_byte_table_single(
        builder,
        "canonical_xor",
        local.relation_multiplicities[BytePairRelation::CanonicalXor.index()].into(),
        || BytePairLookupMsg::from_xor(a.clone(), b.clone(), x),
    );

    for (relation0, relation1) in [
        (BytePairRelation::Rot12Pos1, BytePairRelation::Rot7Pos0),
        (BytePairRelation::Rot7Pos2, BytePairRelation::Rot12Pos3),
    ] {
        emit_byte_table_pair(
            builder,
            "eidos_rotation_tables",
            "rotation_row_0",
            local.relation_multiplicities[relation0.index()].into(),
            || {
                EidosRotationMsg::from_normalized(
                    relation0,
                    a.clone(),
                    b.clone(),
                    relation_values[relation0.index()].clone(),
                )
            },
            "rotation_row_1",
            local.relation_multiplicities[relation1.index()].into(),
            || {
                EidosRotationMsg::from_normalized(
                    relation1,
                    a.clone(),
                    b.clone(),
                    relation_values[relation1.index()].clone(),
                )
            },
        );
    }

    emit_byte_table_pair(
        builder,
        "eidos_rotation_and_range_tables",
        "rot7_pos3_row",
        local.relation_multiplicities[BytePairRelation::Rot7Pos3.index()].into(),
        || {
            EidosRotationMsg::from_normalized(
                BytePairRelation::Rot7Pos3,
                a.clone(),
                b.clone(),
                relation_values[BytePairRelation::Rot7Pos3.index()].clone(),
            )
        },
        "range_row",
        local.range_multiplicity.into(),
        || RangeMsg {
            value: a.clone() * LB::Expr::from_u16(256) + b.clone(),
        },
    );
}
