//! Trace composition for the fixed byte-pair and And8 tables.

use miden_core::{Felt, utils::RowMajorMatrix};

use crate::{
    composite::concatenate_bands, primitives::byte_pair_lut::TRACE_HEIGHT as BPL_TRACE_HEIGHT,
};

/// Concatenate the two byte tables, requiring their fixed row ranges to match exactly.
pub(crate) fn byte_pair_and8_trace(
    bpl: RowMajorMatrix<Felt>,
    and8: RowMajorMatrix<Felt>,
) -> RowMajorMatrix<Felt> {
    assert_eq!(bpl.values.len() / bpl.width, BPL_TRACE_HEIGHT);
    assert_eq!(and8.values.len() / and8.width, BPL_TRACE_HEIGHT);
    concatenate_bands(&bpl, &and8)
}

#[cfg(test)]
mod tests {
    use miden_air::and8_lookup::columns::{AND8_LOOKUP_TRACE_HEIGHT, NUM_AND8_LOOKUP_COLS};
    use miden_lifted_air::ConstraintDegrees;

    use super::*;
    use crate::primitives::byte_pair_lut::{
        BytePairLutRequires, BytePairOp, COL_MULT_XOR, generate_trace,
    };

    fn test_challenges() -> [QuadFelt; NUM_RANDOMNESS] {
        [
            QuadFelt::new([Felt::from(3u32), Felt::from(5u32)]),
            QuadFelt::new([Felt::from(7u32), Felt::from(11u32)]),
        ]
    }

    fn and8_main_fixture() -> RowMajorMatrix<Felt> {
        let mut values = vec![Felt::ZERO; AND8_LOOKUP_TRACE_HEIGHT * NUM_AND8_LOOKUP_COLS];
        for column in 0..NUM_AND8_LOOKUP_COLS {
            let row = if column + 1 == NUM_AND8_LOOKUP_COLS {
                AND8_LOOKUP_TRACE_HEIGHT - 1
            } else {
                ((column + 1) << 8) | (0xf0 - column)
            };
            values[row * NUM_AND8_LOOKUP_COLS + column] = Felt::from((column + 1) as u32);
        }
        RowMajorMatrix::new(values, NUM_AND8_LOOKUP_COLS)
    }

    fn composite_main_fixture() -> RowMajorMatrix<Felt> {
        let mut bpl = BytePairLutRequires::new();
        bpl.require(BytePairOp::Xor, 0x05, 0x03);
        bpl.require(BytePairOp::AndNot, 0x10, 0x20);
        bpl.require_range16(0x4321);
        byte_pair_and8_trace(generate_trace(bpl), and8_main_fixture())
    }

    #[test]
    fn byte_pair_and8_shape_and_degree_match_design() {
        let air = BytePairAnd8Air;

        assert_eq!(air.width(), 13);
        assert_eq!(air.preprocessed_width(), 15);
        assert_eq!(air.aux_width(), 7);
        assert_eq!(air.num_aux_values(), 2);
        assert_eq!(
            ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&air),
            ConstraintDegrees { base: 0, ext: 3 }
        );
        assert_eq!(miden_lifted_stark::log_quotient_degree::<Felt, QuadFelt, _>(&air), 1);
    }

    #[test]
    fn embedded_and8_auxiliary_band_matches_standalone_and_is_component_local() {
        let air = BytePairAnd8Air;
        let challenges = test_challenges();
        let main = composite_main_fixture();
        let and8_main = extract_band(&main, BPL_MAIN_COLS..air.width());

        let (standalone_aux, standalone_values) =
            MidenAir::And8Lookup.build_aux_trace(&and8_main, &[], &[], &challenges);
        let (composite_aux, composite_values) = air.build_aux_trace(&main, &[], &[], &challenges);
        let embedded_and8_aux = extract_band(&composite_aux, BPL_AUX_COLS..air.aux_width());

        assert_eq!(embedded_and8_aux.width, standalone_aux.width);
        assert_eq!(embedded_and8_aux.values, standalone_aux.values);
        assert_eq!(composite_values[AND8_VALUE_OFFSET], standalone_values[0]);
        assert_ne!(composite_values[BPL_VALUE_OFFSET], QuadFelt::ZERO);
        assert_ne!(composite_values[AND8_VALUE_OFFSET], QuadFelt::ZERO);

        let baseline_bpl_aux = extract_band(&composite_aux, 0..BPL_AUX_COLS);

        let mut bpl_mutation = main.clone();
        let bpl_row = (usize::from(0x05u8) << 8) | usize::from(0x03u8);
        bpl_mutation.values[bpl_row * air.width() + COL_MULT_XOR] += Felt::ONE;
        let (bpl_mutated_aux, bpl_mutated_values) =
            air.build_aux_trace(&bpl_mutation, &[], &[], &challenges);
        assert_ne!(extract_band(&bpl_mutated_aux, 0..BPL_AUX_COLS).values, baseline_bpl_aux.values);
        assert_ne!(bpl_mutated_values[BPL_VALUE_OFFSET], composite_values[BPL_VALUE_OFFSET]);
        assert_eq!(
            extract_band(&bpl_mutated_aux, BPL_AUX_COLS..air.aux_width()).values,
            embedded_and8_aux.values
        );
        assert_eq!(bpl_mutated_values[AND8_VALUE_OFFSET], composite_values[AND8_VALUE_OFFSET]);

        let mut and8_mutation = main.clone();
        let and8_row = (1usize << 8) | 0xf0;
        and8_mutation.values[and8_row * air.width() + BPL_MAIN_COLS + NUM_AND8_LOOKUP_COLS - 1] +=
            Felt::ONE;
        let (and8_mutated_aux, and8_mutated_values) =
            air.build_aux_trace(&and8_mutation, &[], &[], &challenges);
        assert_eq!(
            extract_band(&and8_mutated_aux, 0..BPL_AUX_COLS).values,
            baseline_bpl_aux.values
        );
        assert_eq!(and8_mutated_values[BPL_VALUE_OFFSET], composite_values[BPL_VALUE_OFFSET]);
        assert_ne!(
            extract_band(&and8_mutated_aux, BPL_AUX_COLS..air.aux_width()).values,
            embedded_and8_aux.values
        );
        assert_ne!(and8_mutated_values[AND8_VALUE_OFFSET], composite_values[AND8_VALUE_OFFSET]);
    }
}
