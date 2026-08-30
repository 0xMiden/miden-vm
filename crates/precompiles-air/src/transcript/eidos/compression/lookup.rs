//! Lookup columns for the 32-row Eidos compression layout.

use core::borrow::Borrow;

use miden_air::eidos_compression::{NARROW_SLOTS, NarrowSlotBus, NarrowSlotFields};
use miden_core::{Felt, field::PrimeCharacteristicRing};

use super::{algebra::missing_rotation_result, layout::*, selectors::EidosCompressionSelectors};
use crate::{
    logup::{Deg, LookupBuilder, LookupColumn, LookupGroup},
    relations::{BusId, eidos_rot7_bus, eidos_rot12_bus},
};

/// Typed view of the PVM-owned Eidos compression main-trace columns.
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

/// Number of lookup fractions grouped into each Eidos compression auxiliary column.
pub(crate) const EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE: [usize; AUX_COLS] = [2; AUX_COLS];

const _: () = assert!(AUX_COLS * 2 == NARROW_SLOTS.len());

/// Emits all Eidos compression lookup groups in their fixed auxiliary-column order.
pub(in crate::transcript::eidos) fn emit_lookup_columns<LB>(
    builder: &mut LB,
    local: &EidosCompressionCols<LB::Var>,
    next: &EidosCompressionCols<LB::Var>,
    selectors: &EidosCompressionSelectors<LB::Expr>,
) where
    LB: LookupBuilder<F = Felt>,
{
    for aux_col in 0..EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE.len() {
        let column_deg = Deg { v: 2, u: 2 };
        builder.next_column(
            |col| {
                col.group(
                    "eidos_compression",
                    |group| {
                        // Each column pairs adjacent slots under their row-specific multiplicities.
                        let slot0 = 2 * aux_col;
                        let slot1 = slot0 + 1;
                        let slot0_multiplicity = slot_multiplicity::<LB>(slot0, selectors);
                        let slot1_multiplicity = slot_multiplicity::<LB>(slot1, selectors);
                        let slot0_encoding =
                            slot_encoding::<LB, _>(&*group, local, next, selectors, slot0);
                        let slot1_encoding =
                            slot_encoding::<LB, _>(&*group, local, next, selectors, slot1);

                        group.selected_batch2_encoded(
                            "lookup_pair",
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

fn slot_multiplicity<LB>(slot: usize, selectors: &EidosCompressionSelectors<LB::Expr>) -> LB::Expr
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
        // The byte-pair table provides these relations with negative multiplicity, so Eidos
        // consumes them with positive multiplicity.
        (_, Some(_)) => fused + footer,
        (_, None) => fused,
    }
}

fn slot_encoding<LB, G>(
    group: &G,
    local: &EidosCompressionCols<LB::Var>,
    next: &EidosCompressionCols<LB::Var>,
    selectors: &EidosCompressionSelectors<LB::Expr>,
    slot: usize,
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
            encoded += group.bus_prefix(BusId::BytePairLut as usize) * fused.clone();
        },
        NarrowSlotBus::Rotation(byte) => {
            let byte = byte as usize;
            encoded += group.bus_prefix(eidos_rot12_bus(byte) as usize) * selectors.is_ab();
            encoded += group.bus_prefix(eidos_rot7_bus(byte) as usize) * selectors.is_cd();
        },
        NarrowSlotBus::MessageWord => {
            let activity = if matches!(spec.footer_bus, Some(NarrowSlotBus::MessageWord)) {
                fused.clone() + footer.clone()
            } else {
                fused.clone()
            };
            encoded += group.bus_prefix(BusId::EidosWord as usize) * activity;
        },
        NarrowSlotBus::RangeCheck => {
            unreachable!("range checks are not used on fused rows")
        },
    }

    match spec.footer_bus {
        Some(NarrowSlotBus::And8) => {
            encoded += group.bus_prefix(BusId::BytePairLut as usize) * footer.clone();
        },
        Some(NarrowSlotBus::RangeCheck) => {
            encoded += group.bus_prefix(BusId::Range16 as usize) * footer.clone();
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
    encoded += group.bus_prefix(BusId::Range16 as usize) * (LB::Expr::ONE - activity);
    let fields = slot_fields::<LB>(local, next, selectors, slot);
    for (idx, field) in fields.into_iter().enumerate() {
        encoded += group.beta_powers()[idx].clone() * field;
    }
    encoded
}

fn slot_fields<LB>(
    local: &EidosCompressionCols<LB::Var>,
    next: &EidosCompressionCols<LB::Var>,
    selectors: &EidosCompressionSelectors<LB::Expr>,
    slot: usize,
) -> [LB::Expr; 3]
where
    LB: LookupBuilder<F = Felt>,
{
    match NARROW_SLOTS[slot].fields {
        NarrowSlotFields::StoredByte(stored_slot) => {
            let base = byte_slot_base(0, stored_slot as usize);
            [
                LB::Expr::from(local.columns[base]),
                LB::Expr::from(local.columns[base + 1]),
                LB::Expr::from(local.columns[base + 2]),
            ]
        },
        NarrowSlotFields::MissingRotation => [
            LB::Expr::from(
                local.columns[g_bd_rot_slot_col(MISSING_ROTATION_G, MISSING_ROTATION_BYTE, 0)],
            ),
            LB::Expr::from(
                local.columns[g_bd_rot_slot_col(MISSING_ROTATION_G, MISSING_ROTATION_BYTE, 1)],
            ),
            missing_rotation_result(
                |col| LB::Expr::from(local.columns[col]),
                |col| LB::Expr::from(next.columns[col]),
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
