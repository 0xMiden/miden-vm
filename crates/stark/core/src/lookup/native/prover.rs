//! Fallible lookup witness construction using the shared collector and arithmetic.

use alloc::{vec, vec::Vec};
use core::ops::Range;

use p3_field::{ExtensionField, Field};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use thiserror::Error;

use super::{LookupAir, LookupFrame};
use crate::{
    air::native::{AuxTrace, AuxTraceInputs, LiftedAir, SpecError},
    lookup::{
        Challenges, LookupFractions, ProverLookupBuilder,
        aux_builder::{
            ACCUMULATE_ROWS_PER_CHUNK, accumulate_fraction_chunk, write_centered_accumulator,
        },
        prover::{build_lookup_fraction_chunk_with, collect_lookup_chunks},
    },
};

/// Recoverable source metadata and witness-input shape failures.
/// Lookup denominators and the normalization divisor are assumed nonzero.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum LookupError {
    #[error(transparent)]
    Spec(#[from] SpecError),
    #[error("main trace width {actual} differs from declared width {expected}")]
    MainWidth { expected: usize, actual: usize },
    #[error("main trace must have positive, complete rows")]
    MainShape,
    #[error("preprocessed trace presence or shape differs from its declaration and main height")]
    PreprocessedShape,
    #[error("public input count {actual} differs from declared count {expected}")]
    PublicValues { expected: usize, actual: usize },
    #[error("challenge count {actual} differs from declared count {expected}, or is below two")]
    Challenges { expected: usize, actual: usize },
    #[error("a lookup must declare columns, message slots, bus IDs and at least one export")]
    LookupShape,
    #[error("auxiliary width {width} cannot hold {columns} lookup columns")]
    AuxiliaryWidth { width: usize, columns: usize },
    #[error("lookup witness storage overflows host indexing")]
    Overflow,
}

/// Collect a complete trace through the native declaration surface.
///
/// This low-level collector retains the existing fraction layout and trusted shape contracts.
/// It does no inversion. Witness construction should normally use [`build_logup_aux_trace`],
/// which validates caller dimensions before constructing the witness.
pub fn build_lookup_fractions<A, F, EF>(
    air: &A,
    main: &RowMajorMatrix<F>,
    preprocessed: Option<&RowMajorMatrix<F>>,
    periodic: &[Vec<F>],
    challenges: &Challenges<EF>,
) -> LookupFractions<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
    A: Sync,
    for<'a> A: LookupAir<ProverLookupBuilder<'a, F, EF>>,
{
    collect_lookup_chunks(air.column_shape(), main.height(), |rows| {
        collect_chunk(air, main, preprocessed, periodic, challenges, rows)
    })
}

fn collect_chunk<A, F, EF>(
    air: &A,
    main: &RowMajorMatrix<F>,
    preprocessed: Option<&RowMajorMatrix<F>>,
    periodic: &[Vec<F>],
    challenges: &Challenges<EF>,
    rows: Range<usize>,
) -> LookupFractions<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
    for<'a> A: LookupAir<ProverLookupBuilder<'a, F, EF>>,
{
    build_lookup_fraction_chunk_with(
        main,
        preprocessed,
        periodic,
        challenges,
        air.column_shape(),
        rows,
        |frame: &LookupFrame<'_, F>, builder| air.eval(frame, builder),
    )
}

/// Build the normalized cyclic LogUp witness without rebuilding any fixed matrices.
///
/// Columns occupy the declared lookup prefix. The returned matrix has the source's full auxiliary
/// width with any suffix zero-initialized; the source witness fills its own additional registers.
/// Exactly one export, `sigma / height`, is initialized here. A source with further exports must
/// append them in its own declared order before returning its complete `ProverAir` result.
///
/// Chunk collection, inversion and centering share the prover callback arithmetic.
/// All active lookup denominators and the trace-length divisor are assumed nonzero.
pub fn build_logup_aux_trace<A, F, EF>(
    air: &A,
    inputs: AuxTraceInputs<'_, F, EF>,
) -> Result<AuxTrace<EF>, LookupError>
where
    F: Field,
    EF: ExtensionField<F>,
    A: LiftedAir<F = F>,
    for<'a> A: LookupAir<ProverLookupBuilder<'a, F, EF>>,
{
    let spec = air.spec();
    spec.validate()?;
    if inputs.main.width() != spec.main_width {
        return Err(LookupError::MainWidth {
            expected: spec.main_width,
            actual: inputs.main.width(),
        });
    }
    if !inputs.main.values.len().is_multiple_of(spec.main_width) || inputs.main.values.is_empty() {
        return Err(LookupError::MainShape);
    }
    let height = inputs.main.height();
    match (spec.preprocessed, inputs.preprocessed) {
        (None, None) => {},
        (Some(shape), Some(matrix))
            if matrix.width() == shape.width
                && matrix.values.len() == shape.width * (1usize << shape.log_height)
                && matrix.height() == height => {},
        _ => return Err(LookupError::PreprocessedShape),
    }
    if inputs.public_values.len() != spec.num_public_values {
        return Err(LookupError::PublicValues {
            expected: spec.num_public_values,
            actual: inputs.public_values.len(),
        });
    }
    if inputs.challenges.len() != spec.num_challenges || inputs.challenges.len() < 2 {
        return Err(LookupError::Challenges {
            expected: spec.num_challenges,
            actual: inputs.challenges.len(),
        });
    }
    let shape = air.column_shape();
    let columns = shape.len();
    if columns == 0
        || air.max_message_width() == 0
        || air.num_bus_ids() == 0
        || air.num_bus_ids() > u32::MAX as usize
        || spec.num_exports == 0
    {
        return Err(LookupError::LookupShape);
    }
    if spec.aux_width < columns {
        return Err(LookupError::AuxiliaryWidth { width: spec.aux_width, columns });
    }
    // Collection reserves height*sum(shape) fractions and height*columns count slots.
    shape
        .iter()
        .try_fold(0usize, |sum, &count| sum.checked_add(count))
        .and_then(|sum| sum.checked_mul(height))
        .ok_or(LookupError::Overflow)?;
    let cells = height.checked_mul(spec.aux_width).ok_or(LookupError::Overflow)?;
    let rows_per_chunk = ACCUMULATE_ROWS_PER_CHUNK.min(height);
    let challenges = Challenges::new(
        inputs.challenges[0],
        inputs.challenges[1],
        air.max_message_width(),
        air.num_bus_ids(),
    );
    let mut output = EF::zero_vec(cells);
    let mut row_totals = EF::zero_vec(height);

    use miden_crypto::parallel::*;
    output
        .par_chunks_mut(rows_per_chunk * spec.aux_width)
        .zip(row_totals.par_chunks_mut(rows_per_chunk))
        .enumerate()
        .for_each(|(chunk_index, (out, totals))| {
            let row_lo = chunk_index * rows_per_chunk;
            let chunk = collect_chunk(
                air,
                inputs.main,
                inputs.preprocessed,
                &spec.periodic_columns,
                &challenges,
                row_lo..row_lo + totals.len(),
            );
            accumulate_fraction_chunk(
                chunk.fractions(),
                chunk.counts(),
                columns,
                spec.aux_width,
                out,
                totals,
            );
        });
    let mean = write_centered_accumulator(&row_totals, &mut output, spec.aux_width);
    Ok(AuxTrace {
        columns: RowMajorMatrix::new(output, spec.aux_width),
        exports: vec![mean],
    })
}

#[cfg(test)]
mod tests {
    use alloc::borrow::Cow;

    use miden_core::{Felt, field::QuadFelt};
    use p3_field::{Algebra, Dup, PrimeCharacteristicRing};

    use super::*;
    use crate::{
        air::native::{AirSpec, Frame, Inputs, LiftedAirBuilder, ProverAir},
        lookup::{Deg, LookupBatch, LookupColumn, LookupGroup, LookupMessage},
    };

    #[derive(Debug)]
    struct RowMessage<E>(E);

    impl<E: PrimeCharacteristicRing, EE: Algebra<E>> LookupMessage<E, EE> for RowMessage<E> {
        fn encode(&self, challenges: &Challenges<EE>) -> EE {
            challenges.bus_prefix[0].dup() + challenges.beta_powers[0].dup() * self.0.dup()
        }
    }

    struct Fixture {
        active: bool,
        aux_width: usize,
        periodic: Vec<Vec<Felt>>,
    }

    impl Fixture {
        fn new(active: bool) -> Self {
            Self {
                active,
                aux_width: 3,
                periodic: vec![vec![Felt::ZERO; 2]],
            }
        }
    }

    impl<LB: super::super::LookupBuilder<F = Felt>> LookupAir<LB> for Fixture {
        fn column_shape(&self) -> &[usize] {
            &[1, 2]
        }
        fn max_message_width(&self) -> usize {
            1
        }
        fn num_bus_ids(&self) -> usize {
            1
        }

        fn eval(&self, frame: &LookupFrame<'_, LB::Expr>, builder: &mut LB) {
            let value = frame.main.current[0].dup() + frame.periodic[0].dup();
            let flag = if self.active { LB::Expr::ONE } else { LB::Expr::ZERO };
            let single = if self.active {
                Deg { v: 0, u: 1 }
            } else {
                Deg { v: 0, u: 0 }
            };
            builder.next_column(
                |column| {
                    column.group(
                        "one",
                        |group| {
                            group.add("row", flag.dup(), || RowMessage(value.dup()), single);
                        },
                        single,
                    );
                },
                single,
            );
            let batch = if self.active {
                Deg { v: 1, u: 2 }
            } else {
                Deg { v: 0, u: 0 }
            };
            builder.next_column(
                |column| {
                    column.group(
                        "two",
                        |group| {
                            group.batch(
                                "pair",
                                flag,
                                |batch| {
                                    batch.add(
                                        "first",
                                        RowMessage(value.dup() + LB::Expr::ONE),
                                        Deg { v: 0, u: 1 },
                                    );
                                    batch.add(
                                        "second",
                                        RowMessage(value + LB::Expr::TWO),
                                        Deg { v: 0, u: 1 },
                                    );
                                },
                                batch,
                            );
                        },
                        batch,
                    );
                },
                batch,
            );
        }
    }

    impl LiftedAir for Fixture {
        type F = Felt;

        fn spec(&self) -> AirSpec<'_, Felt> {
            AirSpec {
                main_width: 1,
                aux_width: self.aux_width,
                num_public_values: 0,
                num_challenges: 2,
                num_exports: 1,
                preprocessed: None,
                periodic_columns: Cow::Borrowed(&self.periodic),
            }
        }

        fn eval<B: LiftedAirBuilder<F = Felt>>(
            &self,
            frame: &Frame<'_, B>,
            inputs: Inputs<'_, B>,
            sink: &mut B,
        ) {
            super::super::eval_lookup(self, frame, inputs, sink);
        }
    }

    impl ProverAir<QuadFelt> for Fixture {
        type Error = LookupError;
        fn build_aux_trace(
            &self,
            inputs: AuxTraceInputs<'_, Felt, QuadFelt>,
        ) -> Result<AuxTrace<QuadFelt>, LookupError> {
            build_logup_aux_trace(self, inputs)
        }
    }

    fn inputs<'a>(
        main: &'a RowMajorMatrix<Felt>,
        challenges: &'a [QuadFelt],
    ) -> AuxTraceInputs<'a, Felt, QuadFelt> {
        AuxTraceInputs {
            main,
            preprocessed: None,
            public_values: &[],
            statement: &[],
            challenges,
        }
    }

    #[test]
    fn native_witness_matches_independent_slow_accumulation_and_preserves_suffix() {
        let source = Fixture::new(true);
        let main = RowMajorMatrix::new((0..1025).map(Felt::from_usize).collect(), 1);
        let values = [QuadFelt::from_u64(7), QuadFelt::ZERO];
        let witness = source.build_aux_trace(inputs(&main, &values)).unwrap();
        let challenges = Challenges::new(values[0], values[1], 1, 1);
        let fractions = build_lookup_fractions(&source, &main, None, &source.periodic, &challenges);
        let (expected, mean) = crate::lookup::accumulate_slow(&fractions);
        assert_eq!(witness.exports, vec![mean]);
        assert_eq!(witness.columns.width(), 3);
        assert_eq!(witness.columns.height(), main.height());
        let (rows, remainder) = witness.columns.values.as_chunks::<3>();
        assert!(remainder.is_empty());
        for ((&accumulator, &fraction), row) in expected[0].iter().zip(&expected[1]).zip(rows) {
            assert_eq!(row[0], accumulator);
            assert_eq!(row[1], fraction);
            assert_eq!(row[2], QuadFelt::ZERO);
        }
        let _captured = crate::air::native::capture(&source).unwrap();
    }

    #[test]
    fn inactive_interactions_and_invalid_trace_shapes() {
        let source = Fixture::new(false);
        let main = RowMajorMatrix::new(vec![Felt::ONE; 4], 1);
        let values = [QuadFelt::from_u64(7), QuadFelt::ZERO];
        let witness = source.build_aux_trace(inputs(&main, &values)).unwrap();
        assert!(witness.columns.values.iter().all(Field::is_zero));
        assert_eq!(witness.exports, vec![QuadFelt::ZERO]);
        let undersized = Fixture { aux_width: 1, ..Fixture::new(false) };
        assert_eq!(
            undersized.build_aux_trace(inputs(&main, &values)).unwrap_err(),
            LookupError::AuxiliaryWidth { width: 1, columns: 2 }
        );
        let empty = RowMajorMatrix::new(vec![], 1);
        assert_eq!(
            source.build_aux_trace(inputs(&empty, &values)).unwrap_err(),
            LookupError::MainShape
        );
    }
}
