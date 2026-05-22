//! Wraps Plonky3's [`KeccakAir`] as a [`LiftedAir`].

use alloc::vec::Vec;

use miden_lifted_air::{Air, BaseAir, LiftedAir, LiftedAirBuilder};
use p3_field::{Field, PrimeField64};
use p3_keccak_air::{KeccakAir, NUM_KECCAK_COLS, NUM_ROUNDS};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

/// [`KeccakAir`] adapted for the lifted STARK prover.
///
/// Keccak is a main-trace-only AIR with no preprocessed, periodic, or auxiliary columns.
pub struct LiftedKeccakAir;

impl Default for LiftedKeccakAir {
    fn default() -> Self {
        Self
    }
}

impl<F> BaseAir<F> for LiftedKeccakAir {
    fn width(&self) -> usize {
        NUM_KECCAK_COLS
    }
}

impl<F: PrimeField64, EF: Field> LiftedAir<F, EF> for LiftedKeccakAir {
    fn num_randomness(&self) -> usize {
        1
    }

    fn aux_width(&self) -> usize {
        1
    }

    fn num_aux_values(&self) -> usize {
        0
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<F>,
        _air_inputs: &[F],
        _aux_inputs: &[F],
        _challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        // Main-trace-only AIR: a single all-zero aux column.
        (RowMajorMatrix::new(EF::zero_vec(main.height()), 1), Vec::new())
    }

    fn eval<AB: LiftedAirBuilder<F = F>>(&self, builder: &mut AB) {
        Air::eval(&KeccakAir {}, builder);
    }
}

/// Generate a Keccak trace for the given inputs.
///
/// Each input is a Keccak-f\[1600\] state (5x5 = 25 `u64` values).
/// The trace has `next_power_of_two(inputs.len() * 24)` rows and
/// [`NUM_KECCAK_COLS`] columns.
pub fn generate_keccak_trace<F: PrimeField64>(inputs: Vec<[u64; 25]>) -> RowMajorMatrix<F> {
    p3_keccak_air::generate_trace_rows(inputs, 0)
}

/// The number of trace rows per Keccak-f permutation (24 rounds).
pub const ROWS_PER_HASH: usize = NUM_ROUNDS;
