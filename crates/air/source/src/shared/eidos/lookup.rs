//! Narrow lookup columns shared by the VM and PVM Eidos compression adapters.

use core::borrow::Borrow;

use miden_core::{Felt, field::PrimeCharacteristicRing};
use miden_stark::lookup::{Deg, LookupBuilder, LookupColumn, LookupGroup};

use super::{
    algebra::{missing_rotation_result, xor_from_and},
    layout::*,
    narrow::{NARROW_SLOTS, NarrowSlotBus, NarrowSlotFields},
    rotation_lookup as eidos_lookup,
    selectors::EidosCompressionSelectors,
};

/// Typed view of the 108 Eidos compression main-trace columns.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct EidosCompressionCols<T> {
    /// Physical columns in the layout documented by the Eidos compression module.
    pub columns: [T; NUM_COLS],
}

impl<T> Borrow<EidosCompressionCols<T>> for [T] {
    fn borrow(&self) -> &EidosCompressionCols<T> {
        debug_assert_eq!(self.len(), NUM_COLS);
        // SAFETY: `EidosCompressionCols<T>` is `repr(C)` and contains exactly one `[T; NUM_COLS]`
        // field. It therefore has the same alignment, size, and valid bit patterns as the input
        // slice after the length check above.
        let (prefix, cols, suffix) = unsafe { self.align_to::<EidosCompressionCols<T>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(cols.len(), 1);
        &cols[0]
    }
}

pub(crate) const NARROW_BATCH_COLUMNS: usize = NARROW_SLOTS.len() / 2;
/// Relation namespace and algebraic conventions for the shared narrow compression lookups.
#[derive(Copy, Clone, Debug)]
#[doc(hidden)]
pub struct NarrowLookupConfig {
    /// Bus carrying each normalized byte-pair relation. The canonical XOR relation's bus also
    /// carries the bytewise AND lookups.
    pub relation_bus: fn(eidos_lookup::BytePairRelation) -> usize,
    /// Bus carrying 16-bit range checks.
    pub range_check_bus: usize,
    /// Bus carrying scheduled message words.
    pub message_word_bus: usize,
    /// Sign of byte-table and range-check multiplicities.
    pub table_multiplicity_sign: LookupMultiplicitySign,
    /// Algebraic form used to reconstruct XOR.
    pub xor_expression: XorExpression,
    /// Diagnostic label for a paired lookup column.
    pub pair_name: &'static str,
}

impl NarrowLookupConfig {
    /// Bus carrying bytewise AND relations.
    fn and8_bus(&self) -> usize {
        (self.relation_bus)(eidos_lookup::BytePairRelation::CanonicalXor)
    }

    /// Bus of the relation serving `byte_position` of a `rotation` step.
    fn rotation_bus(&self, rotation: eidos_lookup::Rotation, byte_position: usize) -> usize {
        (self.relation_bus)(eidos_lookup::BytePairRelation::for_rotation(rotation, byte_position))
    }
}

/// Sign applied to byte-table and range-check lookup multiplicities.
#[derive(Copy, Clone, Debug)]
#[doc(hidden)]
pub enum LookupMultiplicitySign {
    /// Emit the multiplicity unchanged.
    Positive,
    /// Emit the negated multiplicity.
    Negative,
}

/// Expression used to reconstruct XOR from an AND witness.
#[derive(Copy, Clone, Debug)]
#[doc(hidden)]
pub enum XorExpression {
    /// Encode `a xor b` as `a + b - 2(a and b)`.
    DoubleAnd,
    /// Encode `a xor b` as `a + b - (a and b) - (a and b)`.
    RepeatedSubtraction,
}

/// Emits the 18 byte, range, rotation, and message-word lookup columns shared by both wrappers.
#[doc(hidden)]
pub fn emit_narrow_lookup_columns<LB>(
    builder: &mut LB,
    local: &EidosCompressionCols<LB::Var>,
    next: &EidosCompressionCols<LB::Var>,
    selectors: &EidosCompressionSelectors<LB::Expr>,
    config: NarrowLookupConfig,
) where
    LB: LookupBuilder<F = Felt>,
{
    for aux_col in 0..NARROW_BATCH_COLUMNS {
        let column_deg = Deg { v: 2, u: 2 };
        builder.next_column(
            |col| {
                col.group(
                    "eidos_compression",
                    |group| {
                        let slot0 = 2 * aux_col;
                        let slot1 = slot0 + 1;
                        let slot0_multiplicity =
                            narrow_slot_multiplicity::<LB>(slot0, selectors, config);
                        let slot1_multiplicity =
                            narrow_slot_multiplicity::<LB>(slot1, selectors, config);
                        let slot0_encoding = narrow_slot_encoding::<LB, _>(
                            &*group, local, next, selectors, slot0, config,
                        );
                        let slot1_encoding = narrow_slot_encoding::<LB, _>(
                            &*group, local, next, selectors, slot1, config,
                        );

                        group.selected_batch2_encoded(
                            config.pair_name,
                            "slot0",
                            slot0_multiplicity,
                            || slot0_encoding,
                            "slot1",
                            slot1_multiplicity,
                            || slot1_encoding,
                        );
                    },
                    column_deg,
                );
            },
            column_deg,
        );
    }
}

fn narrow_slot_multiplicity<LB>(
    slot: usize,
    selectors: &EidosCompressionSelectors<LB::Expr>,
    config: NarrowLookupConfig,
) -> LB::Expr
where
    LB: LookupBuilder<F = Felt>,
{
    let fused = is_fused::<LB>(selectors);
    let footer = selectors.is_footer();
    let spec = NARROW_SLOTS[slot];

    match (spec.fused_bus, spec.footer_bus) {
        (NarrowSlotBus::MessageWord, Some(NarrowSlotBus::MessageWord)) => {
            fused - LB::Expr::from_u64(7) * footer
        },
        (NarrowSlotBus::MessageWord, None) => fused,
        (_, Some(_)) => signed_table_multiplicity::<LB>(fused + footer, config),
        (_, None) => signed_table_multiplicity::<LB>(fused, config),
    }
}

fn signed_table_multiplicity<LB>(multiplicity: LB::Expr, config: NarrowLookupConfig) -> LB::Expr
where
    LB: LookupBuilder<F = Felt>,
{
    match config.table_multiplicity_sign {
        LookupMultiplicitySign::Positive => multiplicity,
        LookupMultiplicitySign::Negative => -multiplicity,
    }
}

fn narrow_slot_encoding<LB, G>(
    group: &G,
    local: &EidosCompressionCols<LB::Var>,
    next: &EidosCompressionCols<LB::Var>,
    selectors: &EidosCompressionSelectors<LB::Expr>,
    slot: usize,
    config: NarrowLookupConfig,
) -> G::ExprEF
where
    LB: LookupBuilder<F = Felt>,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    let spec = NARROW_SLOTS[slot];
    let fused = is_fused::<LB>(selectors);
    let footer = selectors.is_footer();
    let mut encoded = G::ExprEF::ZERO;

    match spec.fused_bus {
        NarrowSlotBus::And8 => {
            encoded += group.bus_prefix(config.and8_bus()) * fused.clone();
        },
        NarrowSlotBus::Rotation(byte) => {
            let byte_position = byte as usize;
            encoded += group
                .bus_prefix(config.rotation_bus(eidos_lookup::Rotation::Rot12, byte_position))
                * selectors.is_ab();
            encoded += group
                .bus_prefix(config.rotation_bus(eidos_lookup::Rotation::Rot7, byte_position))
                * selectors.is_cd();
        },
        NarrowSlotBus::MessageWord => {
            let activity = if matches!(spec.footer_bus, Some(NarrowSlotBus::MessageWord)) {
                fused.clone() + footer.clone()
            } else {
                fused.clone()
            };
            encoded += group.bus_prefix(config.message_word_bus) * activity;
        },
        NarrowSlotBus::RangeCheck => {
            unreachable!("range checks are not used on fused rows")
        },
    }

    match spec.footer_bus {
        Some(NarrowSlotBus::And8) => {
            encoded += group.bus_prefix(config.and8_bus()) * footer.clone();
        },
        Some(NarrowSlotBus::RangeCheck) => {
            encoded += group.bus_prefix(config.range_check_bus) * footer.clone();
        },
        Some(NarrowSlotBus::MessageWord) => {},
        Some(NarrowSlotBus::Rotation(_)) => {
            unreachable!("rotations are not used on footer rows")
        },
        None => {},
    }

    // Route every inactive slot to the range-check bus.
    let activity = fused
        + if spec.footer_bus.is_some() {
            footer
        } else {
            LB::Expr::ZERO
        };
    encoded += group.bus_prefix(config.range_check_bus) * (LB::Expr::ONE - activity);
    let fields = narrow_slot_fields::<LB>(local, next, selectors, slot, config);
    for (idx, field) in fields.into_iter().enumerate() {
        encoded += group.beta_powers()[idx].clone() * field;
    }
    encoded
}

fn narrow_slot_fields<LB>(
    local: &EidosCompressionCols<LB::Var>,
    next: &EidosCompressionCols<LB::Var>,
    selectors: &EidosCompressionSelectors<LB::Expr>,
    slot: usize,
    config: NarrowLookupConfig,
) -> [LB::Expr; 3]
where
    LB: LookupBuilder<F = Felt>,
{
    match NARROW_SLOTS[slot].fields {
        NarrowSlotFields::StoredByte(stored_slot) => {
            let base = byte_slot_base(0, stored_slot as usize);
            let a = LB::Expr::from(local.columns[base]);
            let b = LB::Expr::from(local.columns[base + 1]);
            let stored = LB::Expr::from(local.columns[base + 2]);
            let value = if slot <= 15 {
                match config.xor_expression {
                    XorExpression::DoubleAnd => xor_from_and(a.clone(), b.clone(), stored),
                    XorExpression::RepeatedSubtraction => {
                        a.clone() + b.clone() - stored.clone() - stored
                    },
                }
            } else {
                eidos_lookup::normalize(slot % BYTES_PER_WORD, stored)
            };
            [a, b, value]
        },
        NarrowSlotFields::MissingRotation => [
            LB::Expr::from(
                local.columns[g_bd_rot_slot_col(MISSING_ROTATION_G, MISSING_ROTATION_BYTE, 0)],
            ),
            LB::Expr::from(
                local.columns[g_bd_rot_slot_col(MISSING_ROTATION_G, MISSING_ROTATION_BYTE, 1)],
            ),
            eidos_lookup::normalize(
                MISSING_ROTATION_BYTE,
                missing_rotation_result(
                    |col| LB::Expr::from(local.columns[col]),
                    |col| LB::Expr::from(next.columns[col]),
                ),
            ),
        ],
        NarrowSlotFields::MessageWord(g) => {
            let g = g as usize;
            [
                message_index::<LB>(selectors, g),
                LB::Expr::from(local.columns[g_msg_word_col(g)]),
                LB::Expr::from(local.columns[G_COMPRESSION_CYCLE_ID_COL]),
            ]
        },
    }
}

fn message_index<LB>(selectors: &EidosCompressionSelectors<LB::Expr>, g: usize) -> LB::Expr
where
    LB: LookupBuilder<F = Felt>,
{
    let footer = selectors.is_footer();
    let footer_idx = selectors.is_footer_row(1)
        + LB::Expr::from_u64(2) * selectors.is_footer_row(2)
        + LB::Expr::from_u64(3) * selectors.is_footer_row(3);
    selectors.sigma_msg_index(g)
        + LB::Expr::from_u64(g as u64) * footer
        + LB::Expr::from_u64(4) * footer_idx
}

fn is_fused<LB>(selectors: &EidosCompressionSelectors<LB::Expr>) -> LB::Expr
where
    LB: LookupBuilder<F = Felt>,
{
    selectors.is_ab() + selectors.is_cd()
}
