//! Dummy AIR mimicking the Miden VM workload profile.
//!
//! Two trace shapes: 51-column (2^18 rows) and 20-column (2^19 rows), with a
//! single degree-9 base constraint producing 8 quotient chunks, and 8 extension-field
//! auxiliary columns (= 16 base-field columns with Goldilocks `ext_degree=2`).

use miden_lifted_air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;

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
pub struct DummyMidenAir {
    width: usize,
    num_aux_cols: usize,
}

impl DummyMidenAir {
    pub fn new(width: usize, num_aux_cols: usize) -> Self {
        assert!(width >= 9, "DummyMidenAir needs at least 9 columns for the degree-9 constraint");
        Self { width, num_aux_cols }
    }
}

/// Shared constraint logic: `local[0] * local[1] * ... * local[8] == 0`.
fn eval_miden_constraints<AB: AirBuilder>(builder: &mut AB) {
    let main = builder.main();
    let local = main.current_slice();
    let product = (0..9).fold(AB::Expr::ONE, |acc, j| acc * local[j].into());
    builder.assert_zero(product);
}

// ---------------------------------------------------------------------------
// Trait impls for lifted STARK path
// ---------------------------------------------------------------------------

impl<F> BaseAir<F> for DummyMidenAir {
    fn width(&self) -> usize {
        self.width
    }
}

impl<F: Field, EF: Field> LiftedAir<F, EF> for DummyMidenAir {
    fn num_randomness(&self) -> usize {
        2
    }

    fn aux_width(&self) -> usize {
        self.num_aux_cols
    }

    fn num_aux_values(&self) -> usize {
        self.num_aux_cols
    }

    fn eval<AB: LiftedAirBuilder<F = F>>(&self, builder: &mut AB) {
        eval_miden_constraints(builder);
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
