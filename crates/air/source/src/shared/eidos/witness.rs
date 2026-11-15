//! Full-width lookup witnesses with the per-compression fingerprint suffix.

use miden_core::{Felt, field::ExtensionField};
use miden_stark::{
    air::native::{AuxTrace, AuxTraceInputs, LiftedAir},
    lookup::native::{LookupAir, LookupError, ProverLookupBuilder, build_logup_aux_trace},
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
    use alloc::{vec, vec::Vec};

    use miden_core::{
        field::{PrimeCharacteristicRing, QuadFelt},
        utils::{Matrix, RowMajorMatrix},
    };
    use miden_stark::air::native::{self, AirKernel, ProverAir};

    use super::*;
    use crate::{
        precompiles::transcript::eidos::{
            EidosCompressionAir as PvmEidos, EidosCompressionInterfaceAir as Interface,
        },
        vm::EidosCompressionAir as VmEidos,
    };

    fn slow_lookup_prefix<A>(
        air: &A,
        main: &RowMajorMatrix<Felt>,
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>)
    where
        A: LiftedAir<F = Felt>,
        for<'a> A: LookupAir<ProverLookupBuilder<'a, Felt, QuadFelt>>,
    {
        let spec = air.spec();
        let encoding = miden_stark::lookup::Challenges::new(
            challenges[0],
            challenges[1],
            <A as LookupAir<ProverLookupBuilder<'_, Felt, QuadFelt>>>::max_message_width(air),
            <A as LookupAir<ProverLookupBuilder<'_, Felt, QuadFelt>>>::num_bus_ids(air),
        );
        let fractions = miden_stark::lookup::native::build_lookup_fractions(
            air,
            main,
            None,
            &spec.periodic_columns,
            &encoding,
        );
        let (columns, sigma) = miden_stark::lookup::accumulate_slow(&fractions);
        let width = columns.len();
        let values = (0..main.height())
            .flat_map(|row| columns.iter().map(move |column| column[row]))
            .collect();
        (RowMajorMatrix::new(values, width), vec![sigma])
    }

    fn capture_geometry<A: LiftedAir<F = Felt>>(air: A, aux_width: usize, base: usize, ext: usize) {
        // Source capture uses non-Copy owned expressions; direct execution is the comparison subject.
        let captured = native::capture_with::<_, QuadFelt>(&air).unwrap();
        let descriptor = &captured.descriptor;
        let spec = descriptor.spec();
        assert_eq!((spec.main_width, spec.aux_width), (104, aux_width));
        assert_eq!((spec.num_public_values, spec.num_challenges, spec.num_exports), (0, 2, 1));
        assert_eq!(spec.preprocessed, None);
        assert_eq!(spec.periodic_columns.len(), 10);
        assert!(spec.periodic_columns.iter().all(|column| column.len() == 32));
        assert_eq!(descriptor.analysis().counts(), native::ConstraintCounts { base, ext });
        assert_eq!(descriptor.analysis().layout().base_indices(), &(0..base).collect::<Vec<_>>());
        assert_eq!(
            descriptor.analysis().layout().ext_indices(),
            &(base..base + ext).collect::<Vec<_>>()
        );

        let kernel = native::DirectKernel::new(air).unwrap();
        let direct = native::capture_from_spec::<Felt, QuadFelt>(
            spec.as_borrowed(),
            |frame, inputs, sink| {
                kernel.bind(inputs).unwrap().eval(frame, sink);
            },
        )
        .unwrap();
        assert_eq!(direct.descriptor.fingerprint(), descriptor.fingerprint());
    }

    #[test]
    fn native_eidos_sources_preserve_geometry_and_global_classes() {
        capture_geometry(VmEidos, 19, 157, 23);
        capture_geometry(PvmEidos, 20, 151, 23);
        capture_geometry(Interface, 3, 5, 4);
        miden_stark::lookup::native::validate_native(&VmEidos, &VmEidos.spec()).unwrap();
        miden_stark::lookup::native::validate_native(&PvmEidos, &PvmEidos.spec()).unwrap();
        miden_stark::lookup::native::validate_native(&Interface, &Interface.spec()).unwrap();
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
    fn native_full_witness_keeps_slow_lookup_prefix_and_export() {
        let main = RowMajorMatrix::new(vec![Felt::ZERO; NUM_COLS * BLOCK_PERIOD], NUM_COLS);
        let challenges = [QuadFelt::from_u8(17), QuadFelt::from_u8(31)];
        let inputs = AuxTraceInputs {
            main: &main,
            preprocessed: None,
            public_values: &[],
            statement: &[],
            challenges: &challenges,
        };

        // Slow fraction accumulation is independent of full witness suffix construction.
        let (expected, exports) = slow_lookup_prefix(&VmEidos, &main, &challenges);
        let actual = VmEidos.build_aux_trace(inputs).unwrap();
        assert_eq!(actual.columns.width, 19);
        assert_eq!(actual.columns.values.len(), BLOCK_PERIOD * 19);
        assert_eq!(expected.width, 18);
        assert_eq!(actual.exports, exports);
        for (actual, expected) in actual
            .columns
            .values
            .as_chunks::<19>()
            .0
            .iter()
            .zip(expected.values.as_chunks::<18>().0.iter())
        {
            assert_eq!(&actual[..18], expected);
        }

        let (expected, exports) = slow_lookup_prefix(&PvmEidos, &main, &challenges);
        let actual = PvmEidos.build_aux_trace(inputs).unwrap();
        assert_eq!(actual.columns.width, 20);
        assert_eq!(actual.columns.values.len(), BLOCK_PERIOD * 20);
        assert_eq!(expected.width, 19);
        assert_eq!(actual.exports, exports);
        for (actual, expected) in actual
            .columns
            .values
            .as_chunks::<20>()
            .0
            .iter()
            .zip(expected.values.as_chunks::<19>().0.iter())
        {
            assert_eq!(&actual[..19], expected);
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
