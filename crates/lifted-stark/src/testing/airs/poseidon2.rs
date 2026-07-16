//! Wraps Plonky3's [`Poseidon2Air`] as a [`LiftedAir`].
//!
//! Uses the standard Goldilocks configuration: WIDTH=12, SBOX_DEGREE=7, SBOX_REGISTERS=1,
//! HALF_FULL_ROUNDS=4, PARTIAL_ROUNDS=22.

use alloc::vec::Vec;

use miden_lifted_air::{Air, BaseAir, LiftedAir, LiftedAirBuilder};
use p3_field::Field;
use p3_goldilocks::{GenericPoseidon2LinearLayersGoldilocks, Goldilocks};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_poseidon2_air::{Poseidon2Air, RoundConstants, num_cols};

/// Goldilocks Poseidon2 configuration constants.
pub const WIDTH: usize = 12;
pub const SBOX_DEGREE: u64 = 7;
pub const SBOX_REGISTERS: usize = 1;
pub const HALF_FULL_ROUNDS: usize = 4;
pub const PARTIAL_ROUNDS: usize = 22;

/// Number of trace columns for the Goldilocks Poseidon2 AIR.
pub const NUM_POSEIDON2_COLS: usize =
    num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();

type GoldilocksRoundConstants = RoundConstants<Goldilocks, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>;

type InnerAir = Poseidon2Air<
    Goldilocks,
    GenericPoseidon2LinearLayersGoldilocks,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

/// [`Poseidon2Air`] adapted for the lifted STARK prover.
///
/// Poseidon2 is a main-trace-only AIR with no preprocessed, periodic, or auxiliary columns.
/// Each row represents one full Poseidon2 permutation (1 row per hash).
pub struct LiftedPoseidon2Air {
    inner: InnerAir,
}

impl LiftedPoseidon2Air {
    pub fn new(constants: GoldilocksRoundConstants) -> Self {
        Self { inner: InnerAir::new(constants) }
    }
}

impl<F> BaseAir<F> for LiftedPoseidon2Air {
    fn width(&self) -> usize {
        NUM_POSEIDON2_COLS
    }
}

impl<EF: Field> LiftedAir<Goldilocks, EF> for LiftedPoseidon2Air {
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
        main: &RowMajorMatrix<Goldilocks>,
        _air_inputs: &[Goldilocks],
        _aux_inputs: &[Goldilocks],
        _challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        // Main-trace-only AIR: a single all-zero aux column.
        (RowMajorMatrix::new(EF::zero_vec(main.height()), 1), Vec::new())
    }

    fn eval<AB: LiftedAirBuilder<F = Goldilocks>>(&self, builder: &mut AB) {
        Air::eval(&self.inner, builder);
    }
}

/// Generate a Poseidon2 trace for the given inputs.
///
/// Each input is a WIDTH=12 element Goldilocks array. The number of inputs must
/// be a power of two. The trace has `inputs.len()` rows and
/// [`NUM_POSEIDON2_COLS`] columns.
pub fn generate_poseidon2_trace(
    inputs: Vec<[Goldilocks; WIDTH]>,
    constants: &GoldilocksRoundConstants,
) -> RowMajorMatrix<Goldilocks> {
    p3_poseidon2_air::generate_trace_rows::<
        Goldilocks,
        GenericPoseidon2LinearLayersGoldilocks,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(inputs, constants, 0)
}
