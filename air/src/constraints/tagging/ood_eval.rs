//! OOD evaluation helper for tagged constraint parity tests.

use alloc::vec::Vec;

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
};
use miden_crypto::stark::{air::MidenAirBuilder, matrix::RowMajorMatrix};

use super::{ids::TAG_TOTAL_COUNT, state};

/// Captured evaluation for a single tagged constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvalRecord {
    /// Stable numeric ID (zero-based).
    pub id: usize,
    /// Human-readable namespace for debugging.
    pub namespace: &'static str,
    /// Constraint evaluation in the quadratic extension field.
    pub value: QuadFelt,
}

/// AIR builder that evaluates each constraint at a random OOD point.
///
/// All main/aux trace values, row flags, and challenges are pseudo-random but deterministic
/// for a given seed. Each constraint's evaluation is recorded in ID order.
pub struct OodEvalAirBuilder {
    main: RowMajorMatrix<Felt>,
    preprocessed: RowMajorMatrix<Felt>,
    permutation: RowMajorMatrix<QuadFelt>,
    permutation_randomness: Vec<QuadFelt>,
    aux_bus_boundary_values: Vec<QuadFelt>,
    public_values: Vec<Felt>,
    periodic_values: Vec<Felt>,
    first_row: Felt,
    last_row: Felt,
    transition: Felt,
    records: Vec<EvalRecord>,
    used: Vec<Option<&'static str>>,
    prev_enabled: bool,
}

impl OodEvalAirBuilder {
    /// Build an OOD evaluator seeded with `seed`.
    ///
    /// The seed deterministically fills the trace matrices, row flags, and random challenges.
    pub fn new(seed: u64) -> Self {
        let prev_enabled = state::is_enabled();
        state::set_enabled(true);

        let mut rng = SeededRng::new(seed);
        let main = RowMajorMatrix::new(
            (0..crate::trace::TRACE_WIDTH * 2).map(|_| rng.next_felt()).collect(),
            crate::trace::TRACE_WIDTH,
        );
        let preprocessed = RowMajorMatrix::new(Vec::new(), 1);
        let permutation = RowMajorMatrix::new(
            (0..crate::trace::AUX_TRACE_WIDTH * 2).map(|_| rng.next_quad()).collect(),
            crate::trace::AUX_TRACE_WIDTH,
        );
        let raw_randomness: Vec<QuadFelt> =
            (0..crate::trace::AUX_TRACE_RAND_ELEMENTS).map(|_| rng.next_quad()).collect();
        let alpha = raw_randomness.first().copied().expect("aux randomness missing alpha");
        let beta = raw_randomness.get(1).copied().expect("aux randomness missing beta");
        let mut permutation_randomness = Vec::with_capacity(crate::trace::AUX_TRACE_RAND_ELEMENTS);
        if crate::trace::AUX_TRACE_RAND_ELEMENTS > 0 {
            permutation_randomness.push(alpha);
        }
        if crate::trace::AUX_TRACE_RAND_ELEMENTS > 1 {
            permutation_randomness.push(QuadFelt::ONE);
        }
        if crate::trace::AUX_TRACE_RAND_ELEMENTS > 2 {
            let mut beta_power = beta;
            for _ in 2..crate::trace::AUX_TRACE_RAND_ELEMENTS {
                permutation_randomness.push(beta_power);
                beta_power *= beta;
            }
        }
        let aux_bus_boundary_values =
            (0..crate::trace::AUX_TRACE_WIDTH).map(|_| rng.next_quad()).collect();
        let first_row = rng.next_felt();
        let last_row = rng.next_felt();
        let transition = rng.next_felt();
        // Minimal constraints in this branch do not use periodic values.
        // When chiplet constraints are added, update this to seed the full periodic set.
        let periodic_values = Vec::new();

        Self {
            main,
            preprocessed,
            permutation,
            permutation_randomness,
            aux_bus_boundary_values,
            public_values: Vec::new(),
            periodic_values,
            first_row,
            last_row,
            transition,
            records: Vec::new(),
            used: vec![None; TAG_TOTAL_COUNT],
            prev_enabled,
        }
    }

    pub fn records(&self) -> &[EvalRecord] {
        &self.records
    }

    /// Panics if any expected ID was not recorded.
    pub fn assert_complete(&self) {
        let missing: Vec<usize> = self
            .used
            .iter()
            .enumerate()
            .filter_map(|(id, entry)| entry.is_none().then_some(id))
            .collect();

        if !missing.is_empty() {
            panic!("missing constraint ids: {missing:?}");
        }
    }

    fn record(&mut self, id: usize, namespace: &'static str, value: QuadFelt) {
        let expected = self.records.len();
        if id != expected {
            panic!("constraint id {} out of order (expected {})", id, expected);
        }
        if id >= self.used.len() {
            panic!("constraint id {} is out of range (max {})", id, self.used.len() - 1);
        }
        if let Some(prev) = self.used[id] {
            panic!("constraint id {} already used (previous namespace: {})", id, prev);
        }
        self.used[id] = Some(namespace);
        self.records.push(EvalRecord { id, namespace, value });
    }
}

impl Drop for OodEvalAirBuilder {
    fn drop(&mut self) {
        state::set_enabled(self.prev_enabled);
    }
}

impl MidenAirBuilder for OodEvalAirBuilder {
    type F = Felt;
    type Expr = Felt;
    type Var = Felt;
    type M = RowMajorMatrix<Felt>;
    type PublicVar = Felt;
    type PeriodicVal = Felt;
    type EF = QuadFelt;
    type ExprEF = QuadFelt;
    type VarEF = QuadFelt;
    type MP = RowMajorMatrix<QuadFelt>;
    type RandomVar = QuadFelt;

    fn main(&self) -> Self::M {
        self.main.clone()
    }

    fn is_first_row(&self) -> Self::Expr {
        self.first_row
    }

    fn is_last_row(&self) -> Self::Expr {
        self.last_row
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        if size == 2 {
            self.transition
        } else {
            panic!("OOD eval only supports a window size of 2");
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let (id, namespace) = state::consume_tag();
        let value = QuadFelt::from(x.into());
        self.record(id, namespace, value);
    }

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        let (id, namespace) = state::consume_tag();
        let value = x.into();
        self.record(id, namespace, value);
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        &self.public_values
    }

    fn periodic_evals(&self) -> &[Self::PeriodicVal] {
        &self.periodic_values
    }

    fn preprocessed(&self) -> Self::M {
        self.preprocessed.clone()
    }

    fn permutation(&self) -> Self::MP {
        self.permutation.clone()
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        &self.permutation_randomness
    }

    fn aux_bus_boundary_values(&self) -> &[Self::VarEF] {
        &self.aux_bus_boundary_values
    }
}

/// Deterministic RNG based on a seed and counter.
struct SeededRng {
    seed: u64,
    counter: u64,
}

impl SeededRng {
    fn new(seed: u64) -> Self {
        Self { seed, counter: 0 }
    }

    fn next_felt(&mut self) -> Felt {
        let bytes = self.next_seed_bytes();
        miden_crypto::rand::test_utils::prng_value::<Felt>(bytes)
    }

    fn next_quad(&mut self) -> QuadFelt {
        QuadFelt::new([self.next_felt(), self.next_felt()])
    }

    fn next_seed_bytes(&mut self) -> [u8; 32] {
        let counter = self.counter;
        self.counter = self.counter.wrapping_add(1);
        let mix = self.seed ^ counter;
        let sum = self.seed.wrapping_add(counter);
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&self.seed.to_le_bytes());
        out[8..16].copy_from_slice(&counter.to_le_bytes());
        out[16..24].copy_from_slice(&mix.to_le_bytes());
        out[24..32].copy_from_slice(&sum.to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_core::{Felt, field::QuadFelt};
    use miden_crypto::stark::air::MidenAir;

    use super::{
        super::fixtures::{OOD_SEED, active_expected_ood_evals},
        EvalRecord, OodEvalAirBuilder, TAG_TOTAL_COUNT,
    };
    use crate::ProcessorAir;

    fn run_group_parity_test(expected: Vec<EvalRecord>) {
        assert_eq!(expected.len(), TAG_TOTAL_COUNT);
        let mut builder = OodEvalAirBuilder::new(OOD_SEED);
        let air = ProcessorAir::new();
        MidenAir::<Felt, QuadFelt>::eval(&air, &mut builder);
        builder.assert_complete();

        let actual = builder.records();
        assert_eq!(actual.len(), expected.len());
        for (actual, expected) in actual.iter().zip(expected.iter()) {
            assert_eq!(actual.id, expected.id);
            assert_eq!(actual.namespace, expected.namespace);
            assert_eq!(actual.value, expected.value);
        }
    }

    #[test]
    fn ood_system_range_matches_expected() {
        run_group_parity_test(active_expected_ood_evals());
    }
}
