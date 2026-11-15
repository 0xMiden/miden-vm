//! Dummy AIR mimicking the Miden VM workload profile.
//!
//! Two trace shapes: 51-column (2^18 rows) and 20-column (2^19 rows), with a
//! single degree-9 base constraint producing 8 quotient chunks, and 8 extension-field
//! auxiliary columns (= 16 base-field columns with Goldilocks `ext_degree=2`).

use alloc::borrow::Cow;
use core::{convert::Infallible, marker::PhantomData};

use p3_field::{Dup, ExtensionField, Field, PrimeCharacteristicRing};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::air::native;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Main trace width for the first (shorter) trace.
pub const TRACE1_WIDTH: usize = 51;
/// Main trace width for the second (taller) trace.
pub const TRACE2_WIDTH: usize = 20;
/// Log₂ height of the first trace (2^18 = 262144 rows).
pub const TRACE1_LOG_HEIGHT: u8 = 18;
/// Log₂ height of the second trace (2^19 = 524288 rows).
pub const TRACE2_LOG_HEIGHT: u8 = 19;
/// Number of extension-field auxiliary columns.
pub const NUM_AUX_COLS: usize = 8;

// ---------------------------------------------------------------------------
// AIR definition
// ---------------------------------------------------------------------------

/// A dummy AIR with a single degree-9 constraint and auxiliary columns.
///
/// The constraint is `local[0] * local[1] * ... * local[8] == 0`, which has
/// degree 9 and produces `log_quotient_degree = 3` (8 quotient chunks).
pub struct DummyMidenAir<F> {
    width: usize,
    num_aux_cols: usize,
    _field: PhantomData<fn() -> F>,
}

impl<F> DummyMidenAir<F> {
    pub fn new(width: usize, num_aux_cols: usize) -> Self {
        assert!(width >= 9, "DummyMidenAir needs at least 9 columns for the degree-9 constraint");
        Self { width, num_aux_cols, _field: PhantomData }
    }
}

// ---------------------------------------------------------------------------
// Trait impls for lifted STARK path
// ---------------------------------------------------------------------------

impl<F: Field> native::LiftedAir for DummyMidenAir<F> {
    type F = F;

    fn spec(&self) -> native::AirSpec<'_, F> {
        native::AirSpec {
            main_width: self.width,
            aux_width: self.num_aux_cols,
            num_public_values: 0,
            num_challenges: 2,
            num_exports: self.num_aux_cols,
            preprocessed: None,
            periodic_columns: Cow::Borrowed(&[]),
        }
    }

    fn eval<AB: native::LiftedAirBuilder<F = F>>(
        &self,
        frame: &native::Frame<'_, AB>,
        _inputs: native::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        // Preserve the original degree-nine product and multiplication order.
        let local = frame.main.current;
        let product = (0..9).fold(AB::Expr::ONE, |acc, j| acc * local[j].dup());
        builder.assert_zero(product);
    }
}

impl<F: Field, EF: ExtensionField<F>> native::ProverAir<EF> for DummyMidenAir<F> {
    type Error = Infallible;

    fn build_aux_trace(
        &self,
        inputs: native::AuxTraceInputs<'_, F, EF>,
    ) -> Result<native::AuxTrace<EF>, Self::Error> {
        // Constraints touch only the main trace: preserve the configured all-zero auxiliary data.
        let columns = RowMajorMatrix::new(
            EF::zero_vec(inputs.main.height() * self.num_aux_cols),
            self.num_aux_cols,
        );
        Ok(native::AuxTrace {
            columns,
            exports: EF::zero_vec(self.num_aux_cols),
        })
    }
}

// ---------------------------------------------------------------------------
// Trace generation
// ---------------------------------------------------------------------------

/// Generate a dummy trace with the given width and log₂ height.
///
/// Column 0 is zero everywhere (satisfying the product constraint).
/// Columns 1..width are filled with deterministic pseudo-random values.
pub fn generate_dummy_trace<F, R>(width: usize, log_height: u8, rng: &mut R) -> RowMajorMatrix<F>
where
    F: Field,
    R: rand::Rng,
    rand::distr::StandardUniform: rand::distr::Distribution<F>,
{
    use rand::RngExt;

    let height = 1 << log_height as usize;
    let mut values = F::zero_vec(height * width);

    for row in 0..height {
        // Column 0 stays zero (already initialized).
        for col in 1..width {
            values[row * width + col] = rng.random();
        }
    }

    RowMajorMatrix::new(values, width)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air::native::AirKernel;

    fn native_dummy_pilot<F: Field, EF: ExtensionField<F>>() {
        for (width, auxiliary_width) in [(9, 1), (TRACE2_WIDTH, 3), (TRACE1_WIDTH, NUM_AUX_COLS)] {
            let source = DummyMidenAir::<F>::new(width, auxiliary_width);
            let expected = native::capture_with::<_, EF>(&source).unwrap();
            assert_eq!(expected.descriptor.analysis().layout().base_indices(), &[0]);
            assert!(expected.descriptor.analysis().layout().ext_indices().is_empty());
            assert_eq!(
                expected.descriptor.analysis().raw_degrees(),
                native::ConstraintDegrees { base: 9, ext: 0 },
            );
            let kernel = native::DirectKernel::new(source).unwrap();
            let main = RowMajorMatrix::new(F::zero_vec(2 * width), width);
            let challenges = [EF::from_u32(7), EF::from_u32(13)];
            let auxiliary = native::ProverAir::build_aux_trace(
                &kernel,
                native::AuxTraceInputs {
                    main: &main,
                    preprocessed: None,
                    public_values: &[],
                    statement: &[],
                    challenges: &challenges,
                },
            )
            .unwrap();
            assert_eq!(auxiliary.columns.width(), auxiliary_width);
            assert_eq!(auxiliary.columns.height(), 2);
            assert_eq!(auxiliary.columns.values, EF::zero_vec(2 * auxiliary_width));
            assert_eq!(auxiliary.exports, EF::zero_vec(auxiliary_width));
            let observed = native::capture_from_spec::<F, EF>(
                kernel.descriptor().spec().as_borrowed(),
                |frame, inputs, sink| kernel.bind(inputs).unwrap().eval(frame, sink),
            )
            .unwrap();
            assert_eq!(observed.descriptor.fingerprint(), expected.descriptor.fingerprint());
            assert_eq!(observed.descriptor.analysis(), expected.descriptor.analysis());
        }

        // Metadata can still represent no auxiliaries without selecting an aux-free proof path.
        let no_aux = DummyMidenAir::<F>::new(9, 0);
        let descriptor = native::capture(&no_aux).unwrap().descriptor;
        assert_eq!(descriptor.spec().aux_width, 0);
        assert_eq!(descriptor.spec().num_exports, 0);
    }

    #[test]
    fn typed_dummy_sources_keep_native_eidos_and_goldilocks_runner_fields() {
        native_dummy_pilot::<
            miden_crypto::Felt,
            miden_crypto::field::BinomialExtensionField<miden_crypto::Felt, 2>,
        >();
        native_dummy_pilot::<crate::testing::configs::Felt, crate::testing::configs::QuadFelt>();
    }
}
