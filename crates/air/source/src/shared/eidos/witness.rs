//! Full-width lookup witnesses with the per-compression fingerprint suffix.

use miden_core::{Felt, field::ExtensionField};
use miden_stark::{
    air::{AuxTrace, AuxTraceInputs, LiftedAir},
    lookup::{LookupAir, LookupError, ProverLookupBuilder, build_logup_aux_trace},
};
use thiserror::Error;

use super::{
    fill_aux_register,
    layout::{BLOCK_PERIOD, NUM_COLS},
};

/// Recoverable input failures for a complete VM or PVM Eidos compression witness.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum EidosWitnessError {
    #[error(transparent)]
    Lookup(#[from] LookupError),
    #[error("Eidos trace height {height} does not contain complete 32-row cycles")]
    CycleHeight { height: usize },
}

/// Collect the declared lookup prefix once, then fill its existing register suffix in place.
///
/// Only full compression wrappers use this helper. The hidden interface has no fingerprint
/// writer and uses ordinary lookup construction instead. Denominators retain the lookup
/// arithmetic's nonzero assumption.
pub(crate) fn build_aux_trace<A, EF>(
    air: &A,
    inputs: AuxTraceInputs<'_, Felt, EF>,
    register_column: usize,
) -> Result<AuxTrace<EF>, EidosWitnessError>
where
    EF: ExtensionField<Felt>,
    A: LiftedAir<F = Felt>,
    for<'a> A: LookupAir<ProverLookupBuilder<'a, Felt, EF>>,
{
    // Preserve the lookup driver's width/empty/incomplete-row errors. Once rows have the
    // shared physical shape, reject a partial cycle before allocating full-width storage.
    let main = inputs.main;
    if main.width == NUM_COLS
        && !main.values.is_empty()
        && main.values.len().is_multiple_of(NUM_COLS)
    {
        let height = main.values.len() / NUM_COLS;
        if !height.is_multiple_of(BLOCK_PERIOD) {
            return Err(EidosWitnessError::CycleHeight { height });
        }
    }
    let mut aux = build_logup_aux_trace(air, inputs)?;
    // The driver checked the declared challenge count. Source configuration owns the register
    // index and full auxiliary width; fill_aux_register preserves the normalized export and prefix.
    fill_aux_register(main, &mut aux.columns, register_column, inputs.challenges[1]);
    Ok(aux)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use miden_core::{
        field::{PrimeCharacteristicRing, QuadFelt},
        utils::RowMajorMatrix,
    };
    use miden_stark::{
        air::{self, ProverAir},
        lookup::{Challenges, accumulate_slow, build_lookup_fractions, validate_native},
    };

    use super::*;
    use crate::{
        precompiles::transcript::eidos::{
            EidosCompressionAir as PvmEidos, EidosCompressionInterfaceAir as Interface,
        },
        vm::EidosCompressionAir as VmEidos,
    };

    #[test]
    fn eidos_sources_emit_lookup_after_ordinary_assertions() {
        for (captured, base, ext) in [
            (air::capture_with::<_, QuadFelt>(&VmEidos).unwrap(), 157, 23),
            (air::capture_with::<_, QuadFelt>(&PvmEidos).unwrap(), 151, 23),
            (air::capture_with::<_, QuadFelt>(&Interface).unwrap(), 5, 4),
        ] {
            let layout = captured.descriptor.analysis().layout();
            assert!(layout.base_indices().iter().copied().eq(0..base));
            assert!(layout.ext_indices().iter().copied().eq(base..base + ext));
        }
        validate_native(&PvmEidos, &PvmEidos.spec()).unwrap();
        validate_native(&Interface, &Interface.spec()).unwrap();
    }

    #[test]
    fn full_witnesses_reject_partial_cycles_and_preserve_lookup_shape_errors() {
        let challenges = [QuadFelt::from_u8(17), QuadFelt::from_u8(31)];
        for (width, cells, expected) in [
            (104, 104, EidosWitnessError::CycleHeight { height: 1 }),
            (
                103,
                103,
                EidosWitnessError::Lookup(LookupError::MainWidth { expected: 104, actual: 103 }),
            ),
            (104, 0, EidosWitnessError::Lookup(LookupError::MainShape)),
            (104, 105, EidosWitnessError::Lookup(LookupError::MainShape)),
        ] {
            let mut main = RowMajorMatrix::new(vec![Felt::ZERO; width], width);
            // Mutate after construction so the incomplete-row case reaches source validation.
            main.values.resize(cells, Felt::ZERO);
            let inputs = AuxTraceInputs {
                main: &main,
                preprocessed: None,
                public_values: &[],
                statement: &[],
                challenges: &challenges,
            };
            assert_eq!(VmEidos.build_aux_trace(inputs).unwrap_err(), expected);
            assert_eq!(PvmEidos.build_aux_trace(inputs).unwrap_err(), expected);
        }
    }

    #[test]
    fn pvm_full_witness_preserves_lookup_prefix_and_export() {
        let main = RowMajorMatrix::new(vec![Felt::ZERO; NUM_COLS * BLOCK_PERIOD], NUM_COLS);
        let challenges = [QuadFelt::from_u8(17), QuadFelt::from_u8(31)];
        let inputs = AuxTraceInputs {
            main: &main,
            preprocessed: None,
            public_values: &[],
            statement: &[],
            challenges: &challenges,
        };

        let encoding = Challenges::new(
            challenges[0],
            challenges[1],
            crate::precompiles::relations::MAX_MESSAGE_WIDTH,
            crate::precompiles::relations::NUM_BUS_IDS,
        );
        let fractions = build_lookup_fractions(
            &PvmEidos,
            &main,
            None,
            &PvmEidos.spec().periodic_columns,
            &encoding,
        );
        let (expected, sigma) = accumulate_slow(&fractions);
        let actual = PvmEidos.build_aux_trace(inputs).unwrap();
        assert_eq!(actual.columns.width, 20);
        assert_eq!(actual.columns.values.len(), BLOCK_PERIOD * 20);
        assert_eq!(expected.len(), 19);
        assert_eq!(actual.exports, [sigma]);
        for (row, values) in actual.columns.values.chunks_exact(20).enumerate() {
            for column in 0..19 {
                assert_eq!(values[column], expected[column][row], "row {row}, column {column}");
            }
        }

        // The hidden lookup-only source has no fingerprint fill or additional cycle restriction.
        // This constructs an auxiliary witness only; setup still owns its periodic minimum height.
        let one_row = RowMajorMatrix::new(vec![Felt::ZERO; NUM_COLS], NUM_COLS);
        let hidden =
            Interface.build_aux_trace(AuxTraceInputs { main: &one_row, ..inputs }).unwrap();
        assert_eq!(hidden.columns.width, 3);
        assert_eq!(hidden.columns.values.len(), 3);
        assert_eq!(hidden.exports.len(), 1);
    }
}
