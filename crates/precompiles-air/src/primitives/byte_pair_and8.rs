//! Composite fixed-table AIR used to keep the PVM relation at ten registered instances.
//!
//! Each component retains its own constraints, lookup accumulator, and committed residue. The
//! composite only places component traces in disjoint column bands and commits them together.

use alloc::{vec, vec::Vec};

use miden_air::MidenAir;
use miden_core::{Felt, field::QuadFelt, utils::RowMajorMatrix};
use miden_lifted_air::{BaseAir, LiftedAir, LiftedAirBuilder};

use crate::{
    composite::{SubAirBuilder, concatenate_bands, extract_band},
    logup::{NUM_PUBLIC_VALUES, NUM_RANDOMNESS},
    primitives::byte_pair_lut::{
        BytePairLutAir, NUM_AUX_COLS as BPL_AUX_COLS, NUM_MAIN_COLS as BPL_MAIN_COLS,
        NUM_PREPROCESSED_COLS as BPL_PREPROCESSED_COLS, TRACE_HEIGHT as BPL_TRACE_HEIGHT,
    },
};

const BPL_VALUE_OFFSET: usize = 0;
const AND8_VALUE_OFFSET: usize = 1;

/// The PVM byte-pair table and Miden Eidos compression byte table in disjoint column bands.
///
/// Both tables enumerate `(a, b) in [0, 256)^2` in the same row order at the same fixed 2^16
/// height. Combining their commitments therefore adds no padding cells.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct BytePairAnd8Air;

impl BytePairAnd8Air {
    fn and8_main_width(self) -> usize {
        MidenAir::And8Lookup.width()
    }

    fn and8_preprocessed_width(self) -> usize {
        MidenAir::And8Lookup.preprocessed_width()
    }

    fn and8_aux_width(self) -> usize {
        <MidenAir as LiftedAir<Felt, QuadFelt>>::aux_width(&MidenAir::And8Lookup)
    }
}

impl BaseAir<Felt> for BytePairAnd8Air {
    fn width(&self) -> usize {
        BPL_MAIN_COLS + self.and8_main_width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        let bpl = BytePairLutAir.preprocessed_trace().expect("byte-pair table is preprocessed");
        let and8 = MidenAir::And8Lookup.preprocessed_trace().expect("And8 table is preprocessed");
        assert_eq!(
            bpl.values.len() / bpl.width,
            BPL_TRACE_HEIGHT,
            "byte-pair table height changed"
        );
        assert_eq!(
            and8.values.len() / and8.width,
            BPL_TRACE_HEIGHT,
            "And8 and byte-pair tables must share the exact row range"
        );
        Some(concatenate_bands(&bpl, &and8))
    }

    fn preprocessed_width(&self) -> usize {
        BPL_PREPROCESSED_COLS + self.and8_preprocessed_width()
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

impl LiftedAir<Felt, QuadFelt> for BytePairAnd8Air {
    fn num_randomness(&self) -> usize {
        NUM_RANDOMNESS
    }

    fn aux_width(&self) -> usize {
        BPL_AUX_COLS + self.and8_aux_width()
    }

    fn num_aux_values(&self) -> usize {
        2
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        let bpl_main = extract_band(main, 0..BPL_MAIN_COLS);
        let and8_main = extract_band(main, BPL_MAIN_COLS..self.width());
        let (bpl_aux, bpl_values) =
            BytePairLutAir.build_aux_trace(&bpl_main, air_inputs, aux_inputs, challenges);
        let (and8_aux, and8_values) =
            MidenAir::And8Lookup.build_aux_trace(&and8_main, air_inputs, aux_inputs, challenges);
        assert_eq!(bpl_values.len(), 1);
        assert_eq!(and8_values.len(), 1);

        let aux = concatenate_bands(&bpl_aux, &and8_aux);
        (aux, vec![bpl_values[0], and8_values[0]])
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        {
            let mut bpl = SubAirBuilder::new(
                builder,
                0..BPL_MAIN_COLS,
                0..BPL_PREPROCESSED_COLS,
                0..BPL_AUX_COLS,
                BPL_VALUE_OFFSET..BPL_VALUE_OFFSET + 1,
                0..0,
            );
            <BytePairLutAir as LiftedAir<Felt, QuadFelt>>::eval(&BytePairLutAir, &mut bpl);
        }
        {
            let and8_preprocessed_offset = BPL_PREPROCESSED_COLS;
            let and8_aux_offset = BPL_AUX_COLS;
            let mut and8 = SubAirBuilder::new(
                builder,
                BPL_MAIN_COLS..self.width(),
                and8_preprocessed_offset..self.preprocessed_width(),
                and8_aux_offset..self.aux_width(),
                AND8_VALUE_OFFSET..AND8_VALUE_OFFSET + 1,
                0..0,
            );
            <MidenAir as LiftedAir<Felt, QuadFelt>>::eval(&MidenAir::And8Lookup, &mut and8);
        }
    }
}
