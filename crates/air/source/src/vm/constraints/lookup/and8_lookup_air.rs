//! Byte-pair table LogUp lookup AIR.

use core::borrow::Borrow;

use miden_core::field::PrimeCharacteristicRing;
use miden_stark::lookup::{Deg, LookupBatch, LookupColumn, LookupGroup, LookupMessage, native};
use p3_field::Dup;

use super::messages::{BytePairLookupMsg, EidosRotationMsg, RangeMsg};
use crate::vm::{
    Felt,
    constraints::and8_lookup::{
        columns::{And8LookupCols, And8LookupPreprocessedCols},
        eidos::{self, BytePairRelation},
    },
};

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
    LB: native::LookupBuilder<F = Felt>,
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
    LB: native::LookupBuilder<F = Felt>,
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
pub(crate) fn emit_and8_lookup_columns<LB>(
    frame: &native::LookupFrame<'_, LB::Expr>,
    builder: &mut LB,
) where
    LB: native::LookupBuilder<F = Felt>,
{
    let local: &And8LookupCols<LB::Expr> = frame.main.current.borrow();
    let fixed: &And8LookupPreprocessedCols<LB::Expr> = frame.preprocessed.current.borrow();
    let a = fixed.a.dup();
    let b = fixed.b.dup();
    let x = fixed.xor.dup();
    let relation_values = eidos::provider_values(x.clone(), fixed.wrap12.dup(), fixed.wrap7.dup());

    emit_byte_table_single(
        builder,
        "canonical_xor",
        local.relation_multiplicities[BytePairRelation::CanonicalXor.index()].dup(),
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
            local.relation_multiplicities[relation0.index()].dup(),
            || {
                EidosRotationMsg::from_normalized(
                    relation0,
                    a.clone(),
                    b.clone(),
                    relation_values[relation0.index()].clone(),
                )
            },
            "rotation_row_1",
            local.relation_multiplicities[relation1.index()].dup(),
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
        local.relation_multiplicities[BytePairRelation::Rot7Pos3.index()].dup(),
        || {
            EidosRotationMsg::from_normalized(
                BytePairRelation::Rot7Pos3,
                a.clone(),
                b.clone(),
                relation_values[BytePairRelation::Rot7Pos3.index()].clone(),
            )
        },
        "range_row",
        local.range_multiplicity.dup(),
        || RangeMsg {
            value: a.clone() * LB::Expr::from_u16(256) + b.clone(),
        },
    );
}
