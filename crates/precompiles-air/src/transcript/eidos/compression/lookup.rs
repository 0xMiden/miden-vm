//! PVM lookup namespace for the shared 32-row Eidos compression core.

use miden_air::eidos_compression::core::{
    EidosCompressionCols, EidosCompressionSelectors, LookupMultiplicitySign, NarrowLookupConfig,
    XorExpression, emit_narrow_lookup_columns,
};
use miden_core::Felt;

use super::layout::AUX_COLS;
use crate::{logup::LookupBuilder, relations::BusId};

/// Number of lookup fractions grouped into each Eidos compression auxiliary column.
pub(crate) const EIDOS_COMPRESSION_LOOKUP_COLUMN_SHAPE: [usize; AUX_COLS] = [2; AUX_COLS];

const PVM_NARROW_LOOKUP_CONFIG: NarrowLookupConfig = NarrowLookupConfig {
    and8_bus: BusId::BytePairLut as usize,
    range_check_bus: BusId::Range16 as usize,
    rot12_buses: [
        BusId::BytePairLut as usize,
        BusId::EidosRot12Pos1 as usize,
        BusId::BytePairLut as usize,
        BusId::EidosRot12Pos3 as usize,
    ],
    rot7_buses: [
        BusId::EidosRot7Pos0 as usize,
        BusId::BytePairLut as usize,
        BusId::EidosRot7Pos2 as usize,
        BusId::EidosRot7Pos3 as usize,
    ],
    message_word_bus: BusId::EidosWord as usize,
    table_multiplicity_sign: LookupMultiplicitySign::Positive,
    xor_expression: XorExpression::RepeatedSubtraction,
    pair_name: "lookup_pair",
};

/// Emits the shared narrow lookups using the PVM relation namespace.
pub(in crate::transcript::eidos) fn emit_lookup_columns<LB>(
    builder: &mut LB,
    local: &EidosCompressionCols<LB::Var>,
    next: &EidosCompressionCols<LB::Var>,
    selectors: &EidosCompressionSelectors<LB::Expr>,
) where
    LB: LookupBuilder<F = Felt>,
{
    emit_narrow_lookup_columns(builder, local, next, selectors, PVM_NARROW_LOOKUP_CONFIG);
}
