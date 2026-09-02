//! Lookup columns for the 32-row Eidos compression layout.

use core::borrow::Borrow;

use miden_air::{
    logup::{BusId, eidos_compression_rot7_bus, eidos_compression_rot12_bus},
    lookup::{Deg, LookupBuilder, LookupColumn, LookupGroup},
};
use miden_core::{Felt, field::PrimeCharacteristicRing};

use super::{algebra::missing_rotation_result, layout::*, selectors::EidosCompressionSelectors};
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

/// Lookup builder accepted by the Eidos compression AIR.
pub(in crate::transcript::eidos) trait EidosCompressionLookupBuilder:
    LookupBuilder<F = Felt>
{
}

impl<T> EidosCompressionLookupBuilder for T where T: LookupBuilder<F = Felt> {}

/// Emits all Eidos compression lookup groups in their fixed auxiliary-column order.
pub(in crate::transcript::eidos) fn emit_lookup_columns<LB>(
    builder: &mut LB,
    local: &EidosCompressionCols<LB::Var>,
    next: &EidosCompressionCols<LB::Var>,
    selectors: &EidosCompressionSelectors<LB::Expr>,
) where
    LB: EidosCompressionLookupBuilder,
{
    for aux_col in 0..EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE.len() {
        let column_deg = Deg { v: 2, u: 2 };
        builder.next_column(
            |col| {
                col.group(
                    "eidos_compression",
                    |group| {
                        // Narrow columns pair adjacent slots under their row-specific
                        // multiplicities.
                        let slot0 = 2 * aux_col;
                        let slot1 = slot0 + 1;
                        let slot0_multiplicity = narrow_slot_multiplicity::<LB>(slot0, selectors);
                        let slot1_multiplicity = narrow_slot_multiplicity::<LB>(slot1, selectors);
                        let slot0_encoding =
                            narrow_slot_encoding::<LB, _>(&*group, local, next, selectors, slot0);
                        let slot1_encoding =
                            narrow_slot_encoding::<LB, _>(&*group, local, next, selectors, slot1);

                        group.selected_batch2_encoded(
                            "narrow_pair",
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
) -> LB::Expr
where
    LB: EidosCompressionLookupBuilder,
{
    let fused = is_fused::<LB>(selectors);
    let footer = selectors.is_footer();

    match slot {
        0..=17 => -(fused + footer),
        18..=21 | 27 | 30..=31 => -fused,
        22..=26 | 28..=29 => -(fused + footer),
        32..=35 => fused - LB::Expr::from_u64(7) * footer,
        _ => unreachable!("32-row EidosCompression narrow slot out of range"),
    }
}

fn narrow_slot_encoding<LB, G>(
    group: &G,
    local: &EidosCompressionCols<LB::Var>,
    next: &EidosCompressionCols<LB::Var>,
    selectors: &EidosCompressionSelectors<LB::Expr>,
    slot: usize,
) -> G::ExprEF
where
    LB: EidosCompressionLookupBuilder,
    G: LookupGroup<Expr = LB::Expr, ExprEF = LB::ExprEF>,
{
    let mut encoded = G::ExprEF::ZERO;

    if slot <= 15 {
        // These byte slots carry And8 relations on fused and footer rows.
        encoded += group.bus_prefix(BusId::And8Lookup as usize) * is_fused::<LB>(selectors);
        encoded += group.bus_prefix(BusId::And8Lookup as usize) * selectors.is_footer();
    } else if slot <= 31 {
        // Fused rows use these slots for rotations; footer rows reuse them for And8 and range
        // relations.
        let byte = slot % BYTES_PER_WORD;
        encoded += group.bus_prefix(eidos_compression_rot12_bus(byte) as usize) * selectors.is_ab();
        encoded += group.bus_prefix(eidos_compression_rot7_bus(byte) as usize) * selectors.is_cd();

        let footer = selectors.is_footer();
        match slot {
            16 => {
                encoded += group.bus_prefix(BusId::And8Lookup as usize) * footer;
            },
            17 | 22..=26 | 28..=29 => {
                encoded += group.bus_prefix(BusId::RangeCheck as usize) * footer;
            },
            _ => {},
        }
    } else if slot <= 35 {
        encoded += group.bus_prefix(BusId::EidosCompressionMessageWord as usize)
            * (is_fused::<LB>(selectors) + selectors.is_footer());
    } else {
        unreachable!("32-row EidosCompression narrow slot out of range");
    }

    // Route every inactive slot to the range-check bus.
    let activity = narrow_slot_activity::<LB>(slot, selectors);
    encoded += group.bus_prefix(BusId::RangeCheck as usize) * (LB::Expr::ONE - activity);
    let fields = narrow_slot_fields::<LB>(local, next, selectors, slot);
    for (idx, field) in fields.into_iter().enumerate() {
        encoded += group.beta_powers()[idx].clone() * field;
    }
    encoded
}

fn narrow_slot_activity<LB>(
    slot: usize,
    selectors: &EidosCompressionSelectors<LB::Expr>,
) -> LB::Expr
where
    LB: EidosCompressionLookupBuilder,
{
    match slot {
        0..=17 | 22..=26 | 28..=29 | 32..=35 => is_fused::<LB>(selectors) + selectors.is_footer(),
        18..=21 | 27 | 30..=31 => is_fused::<LB>(selectors),
        _ => unreachable!("32-row EidosCompression narrow slot out of range"),
    }
}

fn narrow_slot_fields<LB>(
    local: &EidosCompressionCols<LB::Var>,
    next: &EidosCompressionCols<LB::Var>,
    selectors: &EidosCompressionSelectors<LB::Expr>,
    slot: usize,
) -> [LB::Expr; 3]
where
    LB: EidosCompressionLookupBuilder,
{
    match slot {
        0..=30 => {
            let base = byte_slot_base(0, slot);
            [
                LB::Expr::from(local.columns[base]),
                LB::Expr::from(local.columns[base + 1]),
                LB::Expr::from(local.columns[base + 2]),
            ]
        },
        31 => [
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
        32..=35 => {
            let g = slot - 32;
            [
                message_index::<LB>(selectors, g),
                LB::Expr::from(local.columns[g_msg_word_col(g)]),
                LB::Expr::from(local.columns[G_COMPRESSION_CYCLE_ID_COL]),
            ]
        },
        _ => unreachable!("32-row EidosCompression narrow slot out of range"),
    }
}

fn message_index<LB>(selectors: &EidosCompressionSelectors<LB::Expr>, g: usize) -> LB::Expr
where
    LB: EidosCompressionLookupBuilder,
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
    LB: EidosCompressionLookupBuilder,
{
    selectors.is_ab() + selectors.is_cd()
}
