//! Miden VM lookup columns around the shared Eidos compression core.

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing},
};
use miden_stark::lookup::{
    Challenges, Deg, LookupBatch, LookupBuilder, LookupColumn, LookupGroup, LookupMessage,
};
use p3_field::Dup;

use super::{
    algebra::{footer_cv_word, footer_message_word, pack_pair, pack_u32_le, xor_from_and},
    layout::*,
    selectors::EidosCompressionSelectors,
};
pub use crate::shared::eidos::lookup::EidosCompressionCols;
pub(crate) use crate::shared::eidos::lookup::NARROW_BATCH_COLUMNS;
use crate::{
    shared::eidos::lookup::{
        LookupMultiplicitySign, NarrowLookupConfig, emit_narrow_lookup_columns,
    },
    vm::constraints::{
        and8_lookup::eidos as eidos_lookup,
        lookup::messages::{AeadEidosCompressionOutputPairMsg, BusId, byte_pair_relation_bus},
    },
};

/// Mode-selected external input with a shared 16-field payload.
///
/// Compression and AEAD use the same `[block_or_state(8), cv_in(4), tail(4)]` field order. Only
/// their domain-separated bus prefixes differ, so selecting the mode never multiplies a witness
/// value and the encoded denominator remains linear.
#[derive(Debug)]
struct FooterInputMsg<E> {
    mode: E,
    block: [E; 8],
    cv_in: [E; 4],
    tail: [E; 4],
}

impl<E, EF> LookupMessage<E, EF> for FooterInputMsg<E>
where
    E: PrimeCharacteristicRing,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        let compression_prefix = challenges.bus_prefix[BusId::HasherCompressionLink as usize].dup();
        let aead_prefix = challenges.bus_prefix[BusId::AeadEidosCompressionInput as usize].dup();
        let prefix =
            compression_prefix.dup() + (aead_prefix - compression_prefix) * self.mode.dup();
        let payload = self
            .block
            .iter()
            .chain(self.cv_in.iter())
            .chain(self.tail.iter())
            .enumerate()
            .map(|(idx, field)| challenges.beta_powers[idx].dup() * field.dup())
            .sum::<EF>();
        prefix + payload
    }
}

/// Number of lookup fractions grouped into each Eidos compression auxiliary column.
pub(crate) const EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE: [usize; NUM_LOGUP_COLS] = {
    let mut shape = [2; NUM_LOGUP_COLS];
    shape[FOOTER_INPUT_COLUMN] = 1;
    shape
};

pub(crate) const FOOTER_INPUT_COLUMN: usize = NARROW_AUX_COLS;
pub(crate) const FOOTER_OUTPUT_COLUMN: usize = FOOTER_INPUT_COLUMN + 1;

const _: () = assert!(FOOTER_INPUT_COLUMN == NARROW_BATCH_COLUMNS);

const FOOTER_INPUT_DEG: Deg = Deg { v: 2, u: 1 };
const FOOTER_OUTPUT_BATCH2_DEG: Deg = Deg { v: 3, u: 2 };

fn mvm_relation_bus(relation: eidos_lookup::BytePairRelation) -> usize {
    byte_pair_relation_bus(relation) as usize
}

const MVM_NARROW_LOOKUP_CONFIG: NarrowLookupConfig = NarrowLookupConfig {
    relation_bus: mvm_relation_bus,
    range_check_bus: BusId::RangeCheck as usize,
    table_multiplicity_sign: LookupMultiplicitySign::Negative,
    pair_name: "narrow_pair",
};

/// Emits all Eidos compression lookup groups in their fixed auxiliary-column order.
pub(crate) fn emit_lookup_columns<LB>(
    builder: &mut LB,
    local: &EidosCompressionCols<LB::Expr>,
    next: &EidosCompressionCols<LB::Expr>,
    selectors: &EidosCompressionSelectors<LB::Expr>,
) where
    LB: LookupBuilder<F = Felt>,
{
    emit_narrow_lookup_columns(builder, local, next, selectors, MVM_NARROW_LOOKUP_CONFIG);

    for aux_col in FOOTER_INPUT_COLUMN..EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE.len() {
        let column_deg = match aux_col {
            FOOTER_INPUT_COLUMN => FOOTER_INPUT_DEG,
            FOOTER_OUTPUT_COLUMN => FOOTER_OUTPUT_BATCH2_DEG,
            _ => unreachable!("32-row EidosCompression lookup aux column out of range"),
        };
        builder.next_column(
            |col| {
                col.group(
                    "eidos_compression",
                    |group| match aux_col {
                        FOOTER_INPUT_COLUMN => {
                            let mode = local.columns[F_MODE_COL].dup();
                            let input_multiplicity = -selectors.is_footer_row(FOOTER_ROWS - 1)
                                * (local.columns[F_COMPRESSION_MULTIPLICITY_COL].dup()
                                    + mode.clone());
                            group.insert(
                                "compression_or_aead_input",
                                LB::Expr::ONE,
                                input_multiplicity,
                                || FooterInputMsg {
                                    mode,
                                    block: footer_block::<LB>(local),
                                    cv_in: core::array::from_fn(|idx| {
                                        pack_pair(
                                            cv_word::<LB>(local, 2 * idx),
                                            cv_word::<LB>(local, 2 * idx + 1),
                                        )
                                    }),
                                    tail: core::array::from_fn(|idx| {
                                        local.columns[footer_interface_tail_col(idx)].dup()
                                    }),
                                },
                                FOOTER_INPUT_DEG,
                            );
                        },
                        FOOTER_OUTPUT_COLUMN => {
                            // Both output relations are active only in AEAD mode. Their shared
                            // degree-two multiplicity gives degree two for U and degree three for
                            // V; the inactive-row constraint pins this column everywhere else,
                            // including when a denominator is zero.
                            let mode = local.columns[F_MODE_COL].dup();
                            let multiplicity = -selectors.is_footer() * mode;
                            group.batch(
                                "aead_output_pairs",
                                LB::Expr::ONE,
                                |batch| {
                                    batch.insert(
                                        "aead_low_output_pair",
                                        multiplicity.clone(),
                                        aead_output_pair_msg_for_current_footer::<LB>(
                                            local, selectors, 0,
                                        ),
                                        Deg { v: 2, u: 1 },
                                    );
                                    batch.insert(
                                        "aead_high_output_pair",
                                        multiplicity,
                                        aead_output_pair_msg_for_current_footer::<LB>(
                                            local, selectors, 8,
                                        ),
                                        Deg { v: 2, u: 1 },
                                    );
                                },
                                FOOTER_OUTPUT_BATCH2_DEG,
                            );
                        },
                        _ => unreachable!("32-row EidosCompression lookup aux column out of range"),
                    },
                    column_deg,
                );
            },
            column_deg,
        );
    }
}

fn footer_block<LB>(local: &EidosCompressionCols<LB::Expr>) -> [LB::Expr; 8]
where
    LB: LookupBuilder<F = Felt>,
{
    core::array::from_fn(|idx| {
        if idx < 6 {
            local.columns[footer_r_col(FOOTER_ROWS - 1, idx)].dup()
        } else {
            let pair = idx - 6;
            pack_pair(
                footer_message_word(|col| local.columns[col].dup(), 2 * pair),
                footer_message_word(|col| local.columns[col].dup(), 2 * pair + 1),
            )
        }
    })
}

fn cv_word<LB>(local: &EidosCompressionCols<LB::Expr>, idx: usize) -> LB::Expr
where
    LB: LookupBuilder<F = Felt>,
{
    footer_cv_word(|col| local.columns[col].dup(), idx)
}

fn aead_output_pair_msg_for_current_footer<LB>(
    local: &EidosCompressionCols<LB::Expr>,
    selectors: &EidosCompressionSelectors<LB::Expr>,
    lane_offset: usize,
) -> AeadEidosCompressionOutputPairMsg<LB::Expr>
where
    LB: LookupBuilder<F = Felt>,
{
    let footer_idx = selectors.is_footer_row(1)
        + selectors.is_footer_row(2).double()
        + LB::Expr::from_u64(3) * selectors.is_footer_row(3);
    let [value0, value1] = if lane_offset == 0 {
        [
            footer_xor_word::<LB>(local, F_OUTPUT_EVEN_SLOT_BASE),
            footer_xor_word::<LB>(local, F_OUTPUT_ODD_SLOT_BASE),
        ]
    } else {
        [
            footer_xor_word::<LB>(local, F_HIGH_EVEN_SLOT_BASE),
            footer_xor_word::<LB>(local, F_HIGH_ODD_SLOT_BASE),
        ]
    };

    AeadEidosCompressionOutputPairMsg {
        clk: local.columns[F_CLK_COL].dup(),
        first_lane_idx: LB::Expr::from_u64(lane_offset as u64) + footer_idx.double(),
        value0,
        value1,
    }
}

fn footer_xor_word<LB>(local: &EidosCompressionCols<LB::Expr>, slot_base: usize) -> LB::Expr
where
    LB: LookupBuilder<F = Felt>,
{
    pack_u32_le(
        footer_xor_byte::<LB>(local, slot_base),
        footer_xor_byte::<LB>(local, slot_base + 1),
        footer_xor_byte::<LB>(local, slot_base + 2),
        footer_xor_byte::<LB>(local, slot_base + 3),
    )
}

fn footer_xor_byte<LB>(local: &EidosCompressionCols<LB::Expr>, slot: usize) -> LB::Expr
where
    LB: LookupBuilder<F = Felt>,
{
    let base = footer_xor_slot_col(slot, 0);
    let lhs = local.columns[base].dup();
    let rhs = local.columns[base + 1].dup();
    let and = local.columns[base + 2].dup();
    xor_from_and(lhs, rhs, and)
}
