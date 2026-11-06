//! Shared approximate peak-memory model for lifted-STARK proving.
//!
//! Counts main, auxiliary, and preprocessed traces with their LDEs, the quotient accumulator,
//! and LMCS trees and leaf-hashing scratch. Preprocessed traces use their AIR's supplied height,
//! matching the prover's requirement that main and preprocessed heights agree; estimating never
//! constructs a trace. The hash allowance uses 32-byte digests and 200-byte leaf states, covering
//! the current Miden hash configurations uniformly. A 5/4 safety factor allows for smaller
//! allocations such as FRI, DEEP, and per-AIR scratch. This is a capacity estimate, not a bound
//! on total process RSS or concurrent proofs and cached setups for other configurations.

use p3_field::{ExtensionField, Field};

use crate::{
    air::{LiftedAir, MultiAir},
    log_quotient_degree,
    pcs::PcsParams,
};

const DIGEST_BYTES: u64 = 32;
// Keccak's 1600-bit state is the largest leaf-hashing state used by Miden's configurations.
const MAX_LEAF_STATE_BYTES: u64 = 200;
// The digest-tree allowance already charges one digest per leaf.
const EXTRA_LEAF_SCRATCH_BYTES: u64 = MAX_LEAF_STATE_BYTES - DIGEST_BYTES;
const TREE_BYTES_PER_LEAF: u64 = 2 * DIGEST_BYTES;
// Main, auxiliary, and quotient LMCS trees coexist at proof-opening time.
const PROOF_LMCS_TREES_AT_PEAK: u64 = 3;
const SAFETY_NUMERATOR: u64 = 5;
const SAFETY_DENOMINATOR: u64 = 4;

/// Costs of one AIR before applying heights or the safety factor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct AirMemoryCost {
    trace_bytes_per_row: u64,
    has_preprocessed: bool,
}

fn air_memory_cost<F, EF, A>(air: &A, params: &PcsParams) -> Option<AirMemoryCost>
where
    F: Field,
    EF: ExtensionField<F>,
    A: LiftedAir<F, EF>,
{
    let field_bytes = u64::try_from(size_of::<F>()).ok()?;
    let extension_dimension = u64::try_from(EF::DIMENSION).ok()?;
    let blowup = 1u64.checked_shl(u32::from(params.log_blowup()))?;
    let width = u64::try_from(air.width()).ok()?;
    let aux_width = u64::try_from(air.aux_width()).ok()?;
    let preprocessed_width = u64::try_from(air.preprocessed_width()).ok()?;
    let columns = width
        .checked_add(aux_width.checked_mul(extension_dimension)?)?
        .checked_add(preprocessed_width)?;
    let trace_bytes_per_row =
        field_bytes.checked_mul(blowup.checked_add(1)?)?.checked_mul(columns)?;
    Some(AirMemoryCost {
        trace_bytes_per_row,
        has_preprocessed: preprocessed_width > 0,
    })
}

/// Shared proof and preprocessing costs, independent of the supplied heights.
fn shared_memory_costs<F, EF, MA>(multi_air: &MA, params: &PcsParams) -> Option<(u64, u64)>
where
    F: Field,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
{
    let airs = multi_air.airs();
    if airs.is_empty() {
        return Some((0, 0));
    }
    let mut log_degree = 0u8;
    let mut has_preprocessed = false;
    for air in airs {
        // Reject unrepresentable trace geometry before degree inference can allocate.
        let cost = air_memory_cost::<F, EF, _>(air, params)?;
        has_preprocessed |= cost.has_preprocessed;
        log_degree = log_degree.max(log_quotient_degree::<F, EF, _>(air));
    }
    let extension_bytes = u64::try_from(size_of::<F>())
        .ok()?
        .checked_mul(u64::try_from(EF::DIMENSION).ok()?)?;
    let blowup = 1u64.checked_shl(u32::from(params.log_blowup()))?;
    let quotient_degree = 1u64.checked_shl(u32::from(log_degree))?;
    // Three proof trees coexist. Each is built separately, so charge one leaf scratch buffer.
    let proof_bytes_per_max_row = extension_bytes
        .checked_mul(quotient_degree)?
        .checked_add(PROOF_LMCS_TREES_AT_PEAK * TREE_BYTES_PER_LEAF + EXTRA_LEAF_SCRATCH_BYTES)?
        .checked_mul(blowup)?;
    let setup_bytes_per_preprocessed_row = if has_preprocessed {
        (TREE_BYTES_PER_LEAF + EXTRA_LEAF_SCRATCH_BYTES).checked_mul(blowup)?
    } else {
        0
    };
    Some((proof_bytes_per_max_row, setup_bytes_per_preprocessed_row))
}

fn peak_bytes(
    rows: impl Iterator<Item = (Option<AirMemoryCost>, usize)>,
    proof_bytes_per_max_row: u64,
    setup_bytes_per_preprocessed_row: u64,
) -> Option<u64> {
    let mut trace_bytes = 0u64;
    let mut max_height = 0u64;
    let mut max_preprocessed_height = 0u64;
    for (cost, height) in rows {
        let cost = cost?;
        let height = u64::try_from(height).ok()?;
        trace_bytes = trace_bytes.checked_add(cost.trace_bytes_per_row.checked_mul(height)?)?;
        max_height = max_height.max(height);
        // Only AIRs with preprocessed columns contribute to the setup bundle's height.
        if cost.has_preprocessed {
            max_preprocessed_height = max_preprocessed_height.max(height);
        }
    }
    trace_bytes
        .checked_add(proof_bytes_per_max_row.checked_mul(max_height)?)?
        .checked_add(setup_bytes_per_preprocessed_row.checked_mul(max_preprocessed_height)?)
        .and_then(apply_safety_factor)
}

fn apply_safety_factor(bytes: u64) -> Option<u64> {
    bytes
        .checked_mul(SAFETY_NUMERATOR)
        .map(|bytes| bytes.div_ceil(SAFETY_DENOMINATOR))
}

/// Estimates peak proving memory from padded heights in [`MultiAir::airs`] order.
///
/// Zero heights are allowed for capacity calculations. Returns `None` on arithmetic overflow
/// or if the number of heights differs from the number of AIRs.
pub fn prover_peak_bytes<F, EF, MA>(
    multi_air: &MA,
    heights: &[usize],
    params: &PcsParams,
) -> Option<u64>
where
    F: Field,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
{
    let airs = multi_air.airs();
    if heights.len() != airs.len() {
        return None;
    }
    let (proof_bytes_per_max_row, setup_bytes_per_preprocessed_row) =
        shared_memory_costs::<F, EF, _>(multi_air, params)?;
    peak_bytes(
        airs.iter()
            .map(|air| air_memory_cost::<F, EF, _>(air, params))
            .zip(heights.iter().copied()),
        proof_bytes_per_max_row,
        setup_bytes_per_preprocessed_row,
    )
}

/// Largest single-AIR height that can fit the budget, choosing the cheapest AIR while holding
/// the other heights at zero. This permissive cap never rejects a shape the estimator accepts.
pub fn max_any_height_for_budget<F, EF, MA>(
    multi_air: &MA,
    budget_bytes: u64,
    params: &PcsParams,
) -> usize
where
    F: Field,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
{
    let Some((proof_bytes_per_max_row, setup_bytes_per_preprocessed_row)) =
        shared_memory_costs::<F, EF, _>(multi_air, params)
    else {
        return 0;
    };
    height_cap(
        multi_air.airs().iter().map(|air| air_memory_cost::<F, EF, _>(air, params)),
        proof_bytes_per_max_row,
        setup_bytes_per_preprocessed_row,
        budget_bytes,
    )
}

fn height_cap(
    costs: impl Iterator<Item = Option<AirMemoryCost>>,
    proof_bytes_per_max_row: u64,
    setup_bytes_per_preprocessed_row: u64,
    limit_bytes: u64,
) -> usize {
    let mut cheapest: Option<u64> = None;
    for cost in costs {
        let Some(cost) = cost else {
            return 0;
        };
        let setup_cost = if cost.has_preprocessed {
            setup_bytes_per_preprocessed_row
        } else {
            0
        };
        // Overflowing coefficients cannot support a positive height, but other AIRs may fit.
        if let Some(coefficient) = cost
            .trace_bytes_per_row
            .checked_add(proof_bytes_per_max_row)
            .and_then(|bytes| bytes.checked_add(setup_cost))
        {
            cheapest = Some(cheapest.map_or(coefficient, |best| best.min(coefficient)));
        }
    }
    let Some(coefficient) = cheapest else {
        return 0;
    };
    let fits = |height| {
        u64::try_from(height)
            .ok()
            .and_then(|height| coefficient.checked_mul(height))
            .and_then(apply_safety_factor)
            .is_some_and(|bytes| bytes <= limit_bytes)
    };
    if fits(usize::MAX) {
        return usize::MAX;
    }
    let mut lo = 0;
    let mut hi = usize::MAX;
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        if fits(mid) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    lo
}

/// Precomputed costs for a relation's padded AIR heights, in [`MultiAir::airs`] order.
///
/// [`Self::from_multi_air`] derives the shared STARK model described in this module. Trace builders
/// can query it without retaining the AIRs or their proving configuration. The safety factor is
/// applied once to the checked total, with ceiling division.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProverMemoryModel<const N: usize> {
    costs: [AirMemoryCost; N],
    proof_bytes_per_max_row: u64,
    setup_bytes_per_preprocessed_row: u64,
}

impl<const N: usize> ProverMemoryModel<N> {
    /// Derives costs from AIR metadata and PCS parameters without constructing traces.
    ///
    /// Returns `None` on arithmetic overflow or if the relation does not contain exactly `N` AIRs.
    pub fn from_multi_air<F, EF, MA>(multi_air: &MA, params: &PcsParams) -> Option<Self>
    where
        F: Field,
        EF: ExtensionField<F>,
        MA: MultiAir<F, EF>,
    {
        let airs = multi_air.airs();
        if airs.len() != N {
            return None;
        }
        let (proof_bytes_per_max_row, setup_bytes_per_preprocessed_row) =
            shared_memory_costs::<F, EF, _>(multi_air, params)?;
        let mut costs = [AirMemoryCost::default(); N];
        for (cost, air) in costs.iter_mut().zip(airs) {
            *cost = air_memory_cost::<F, EF, _>(air, params)?;
        }
        Some(Self {
            costs,
            proof_bytes_per_max_row,
            setup_bytes_per_preprocessed_row,
        })
    }

    /// Returns estimated peak bytes for padded AIR heights, or `None` on arithmetic overflow.
    pub fn prover_peak_bytes(&self, heights: &[usize; N]) -> Option<u64> {
        peak_bytes(
            self.costs.iter().copied().map(Some).zip(heights.iter().copied()),
            self.proof_bytes_per_max_row,
            self.setup_bytes_per_preprocessed_row,
        )
    }

    /// Largest single-AIR height that fits the budget, using the cheapest single-AIR row cost.
    ///
    /// This permissive cap never rejects a shape accepted by the model.
    pub fn max_any_height_for_budget(&self, limit_bytes: u64) -> usize {
        height_cap(
            self.costs.iter().copied().map(Some),
            self.proof_bytes_per_max_row,
            self.setup_bytes_per_preprocessed_row,
            limit_bytes,
        )
    }
}

/// A caller-selected byte limit and the relation model used to enforce it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvingBudget<const N: usize> {
    model: ProverMemoryModel<N>,
    limit_bytes: u64,
}

impl<const N: usize> ProvingBudget<N> {
    pub const fn new(model: ProverMemoryModel<N>, limit_bytes: u64) -> Self {
        Self { model, limit_bytes }
    }

    pub const fn model(&self) -> &ProverMemoryModel<N> {
        &self.model
    }

    pub const fn limit_bytes(&self) -> u64 {
        self.limit_bytes
    }

    pub fn prover_peak_bytes(&self, heights: &[usize; N]) -> Option<u64> {
        self.model.prover_peak_bytes(heights)
    }

    pub fn max_any_height(&self) -> usize {
        self.model.max_any_height_for_budget(self.limit_bytes)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;

    use super::*;
    use crate::{
        air::{BaseAir, LiftedAirBuilder, WindowAccess},
        testing::configs::{Felt, QuadFelt},
    };

    struct TestAir {
        width: usize,
        aux_width: usize,
        preprocessed_width: usize,
        constraint_degree: u64,
    }

    impl BaseAir<Felt> for TestAir {
        fn width(&self) -> usize {
            self.width
        }

        fn preprocessed_width(&self) -> usize {
            self.preprocessed_width
        }

        fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
            panic!("memory estimation must not allocate preprocessed traces")
        }
    }

    impl LiftedAir<Felt, QuadFelt> for TestAir {
        fn num_randomness(&self) -> usize {
            0
        }

        fn aux_width(&self) -> usize {
            self.aux_width
        }

        fn num_aux_values(&self) -> usize {
            0
        }

        fn build_aux_trace(
            &self,
            _: &RowMajorMatrix<Felt>,
            _: &[Felt],
            _: &[Felt],
            _: &[QuadFelt],
        ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
            panic!("memory estimation must not allocate auxiliary traces")
        }

        fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
            let value: AB::Expr = builder.main().current_slice()[0].into();
            builder.assert_zero(value.exp_u64(self.constraint_degree));
        }
    }

    struct TestMultiAir<const N: usize = 2> {
        airs: [TestAir; N],
    }

    impl<const N: usize> MultiAir<Felt, QuadFelt> for TestMultiAir<N> {
        type Air = TestAir;

        fn airs(&self) -> &[TestAir] {
            &self.airs
        }
    }

    fn multi_air() -> TestMultiAir {
        TestMultiAir {
            airs: [
                TestAir {
                    width: 3,
                    aux_width: 1,
                    preprocessed_width: 0,
                    constraint_degree: 2,
                },
                TestAir {
                    width: 1,
                    aux_width: 2,
                    preprocessed_width: 3,
                    constraint_degree: 5,
                },
            ],
        }
    }

    fn params(log_blowup: u8) -> PcsParams {
        PcsParams::new(log_blowup, 1, 3, 0, 0, 1, 0).expect("valid PCS params")
    }

    fn model<const N: usize>(trace_costs: [u64; N], proof_cost: u64) -> ProverMemoryModel<N> {
        ProverMemoryModel {
            costs: trace_costs.map(|trace_bytes_per_row| AirMemoryCost {
                trace_bytes_per_row,
                has_preprocessed: false,
            }),
            proof_bytes_per_max_row: proof_cost,
            setup_bytes_per_preprocessed_row: 0,
        }
    }

    fn estimate(multi_air: &TestMultiAir, heights: [usize; 2], params: &PcsParams) -> Option<u64> {
        let direct = prover_peak_bytes::<Felt, QuadFelt, _>(multi_air, &heights, params);
        let supplied =
            ProverMemoryModel::<2>::from_multi_air::<Felt, QuadFelt, _>(multi_air, params)
                .and_then(|model| model.prover_peak_bytes(&heights));
        assert_eq!(supplied, direct);
        direct
    }

    #[test]
    fn zero_heights_and_overflow() {
        let mut multi_air = multi_air();
        assert_eq!(estimate(&multi_air, [0; 2], &params(3)), Some(0));
        assert_eq!(estimate(&multi_air, [1; 2], &params(64)), None);
        assert_eq!(prover_peak_bytes::<Felt, QuadFelt, _>(&multi_air, &[1], &params(3)), None);
        // Overflow the byte calculation on both 32-bit and 64-bit hosts.
        multi_air.airs[0].width = usize::MAX;
        let overflowing_params = params(32);
        assert_eq!(estimate(&multi_air, [usize::MAX; 2], &overflowing_params), None);
        assert_eq!(
            max_any_height_for_budget::<Felt, QuadFelt, _>(
                &multi_air,
                u64::MAX,
                &overflowing_params
            ),
            0
        );
        assert!(
            ProverMemoryModel::<2>::from_multi_air::<Felt, QuadFelt, _>(
                &multi_air,
                &overflowing_params,
            )
            .is_none()
        );
    }

    #[test]
    fn pinned_bytes_for_unequal_heights_and_quotient_degrees() {
        let mut multi_air = multi_air();
        // Felt/QuadFelt occupy 8/16 bytes. With blowup 8 and heights [16, 8]:
        // - main + auxiliary + preprocessed traces and LDEs: 5_760 + 4_608 = 10_368;
        // - three proof trees: 16 * 8 * (3 * 2 * 32) = 24_576;
        // - proof leaf scratch: 16 * 8 * (200 - 32) = 21_504;
        // - setup tree and scratch: 8 * 8 * (2 * 32 + 200 - 32) = 14_848;
        // - quotient accumulator: 16 * 8 * 16 * max_quotient_degree = 2_048 * degree.
        // Apply 5/4 to these independently calculated totals. Do not derive expectations
        // from the estimator's constants or helpers: omitting any charge must fail this test.
        for (constraint_degrees, log_quotient_degrees, expected) in [
            ([2, 2], [0, 0], 91_680),
            ([2, 3], [0, 1], 94_240),
            ([2, 5], [0, 2], 99_360),
            ([9, 2], [3, 0], 109_600),
        ] {
            for (air, degree) in multi_air.airs.iter_mut().zip(constraint_degrees) {
                air.constraint_degree = degree;
            }
            assert_eq!(
                multi_air.airs.each_ref().map(log_quotient_degree::<Felt, QuadFelt, _>),
                log_quotient_degrees
            );
            assert_eq!(estimate(&multi_air, [16, 8], &params(3)), Some(expected));
        }

        multi_air.airs[0].constraint_degree = 2;
        multi_air.airs[1].constraint_degree = 5;
        // The inactive higher-degree AIR still determines the shared proof coefficient:
        // (360 trace bytes + 3_392 proof bytes) * 5/4 = 4_690, with no setup-height charge.
        assert_eq!(estimate(&multi_air, [1, 0], &params(3)), Some(4_690));
        // Swap heights: traces cost 12_096; proof trees/scratch still cost 46_080;
        // setup tree/scratch now cost 29_696; quotient costs 8_192. Total * 5/4 = 120_080.
        assert_eq!(estimate(&multi_air, [8, 16], &params(3)), Some(120_080));
        // At blowup 2, [16, 8] costs 3_456 in traces, 11_520 in proof trees/scratch,
        // 3_712 in setup tree/scratch, and 2_048 in quotient: total * 5/4 = 25_920.
        assert_eq!(estimate(&multi_air, [16, 8], &params(1)), Some(25_920));
    }

    #[test]
    fn preprocessed_dimensions_are_charged_without_allocating_traces() {
        let mut multi_air = multi_air();
        assert_eq!(estimate(&multi_air, [16, 8], &params(3)), Some(99_360));
        multi_air.airs[1].preprocessed_width += 1;
        // One more preprocessed column costs 8 rows * 9 * 8 bytes * 5/4 = 720 bytes.
        assert_eq!(estimate(&multi_air, [16, 8], &params(3)), Some(100_080));
        multi_air.airs[1].preprocessed_width = 0;
        // Removing setup drops 1_728 trace bytes plus 14_848 tree/scratch bytes, before 5/4.
        assert_eq!(estimate(&multi_air, [16, 8], &params(3)), Some(78_640));
    }

    #[test]
    fn increasing_heights_and_blowup_never_decreases_the_estimate() {
        let mut multi_air = multi_air();
        for heights in [[0, 0], [1, 3], [16, 65_536], [1 << 20, 8]] {
            let base = estimate(&multi_air, heights, &params(3)).unwrap();
            assert!(estimate(&multi_air, heights, &params(4)).unwrap() >= base);
            for i in 0..heights.len() {
                let mut bumped = heights;
                bumped[i] += 1;
                assert!(estimate(&multi_air, bumped, &params(3)).unwrap() >= base);
            }
            multi_air.airs.reverse();
            assert_eq!(estimate(&multi_air, [heights[1], heights[0]], &params(3)), Some(base));
            multi_air.airs.reverse();
        }
    }

    #[test]
    fn row_cap_never_rejects_a_shape_that_fits() {
        let mut multi_air = multi_air();
        let params = params(3);
        for heights in [[0, 0], [1, 3], [16, 65_536], [1 << 20, 8]] {
            let budget = estimate(&multi_air, heights, &params).unwrap();
            let cap = max_any_height_for_budget::<Felt, QuadFelt, _>(&multi_air, budget, &params);
            assert!(heights.into_iter().all(|height| height <= cap));
        }
        for budget in [0, 1, 1 << 20, u64::MAX] {
            let cap = max_any_height_for_budget::<Felt, QuadFelt, _>(&multi_air, budget, &params);
            let model =
                ProverMemoryModel::<2>::from_multi_air::<Felt, QuadFelt, _>(&multi_air, &params)
                    .unwrap();
            assert_eq!(model.max_any_height_for_budget(budget), cap);
            let fits = |height| {
                [[height, 0], [0, height]].into_iter().any(|heights| {
                    estimate(&multi_air, heights, &params).is_some_and(|bytes| bytes <= budget)
                })
            };
            assert!(fits(cap));
            if let Some(next) = cap.checked_add(1) {
                assert!(!fits(next));
            }
            multi_air.airs.reverse();
            assert_eq!(
                max_any_height_for_budget::<Felt, QuadFelt, _>(&multi_air, budget, &params),
                cap
            );
            assert_eq!(
                ProverMemoryModel::<2>::from_multi_air::<Felt, QuadFelt, _>(&multi_air, &params)
                    .unwrap()
                    .max_any_height_for_budget(budget),
                cap
            );
            multi_air.airs.reverse();
        }
    }
    #[test]
    fn safety_rounds_once_after_adding_shared_and_per_air_costs() {
        let model = model([1, 2], 2);
        assert_eq!(model.prover_peak_bytes(&[1, 2]), Some(12));
        assert_eq!(model.prover_peak_bytes(&[0, 0]), Some(0));
    }

    #[test]
    fn permissive_cap_accepts_every_height_in_a_fitting_shape() {
        let model = model([7, 2], 3);
        let heights = [8, 16];
        let bytes = model.prover_peak_bytes(&heights).unwrap();
        let budget = ProvingBudget::new(model, bytes);
        let cap = budget.max_any_height();
        assert!(heights.into_iter().all(|height| height <= cap));
        assert!(model.prover_peak_bytes(&[0, cap]).unwrap() <= bytes);
        assert!(model.prover_peak_bytes(&[0, cap + 1]).unwrap() > bytes);
    }

    #[test]
    fn overflow_is_rejected_before_safety_rounding() {
        for (trace_cost, proof_cost, height) in
            [(u64::MAX, 0, 2), (u64::MAX, 1, 1), (u64::MAX / 5 + 1, 0, 1)]
        {
            assert_eq!(model([trace_cost], proof_cost).prover_peak_bytes(&[height]), None);
        }
    }

    #[test]
    fn cap_skips_overflowing_coefficients_without_rejecting_zero_heights() {
        let mut preprocessed = model([1, 1], 1);
        preprocessed.costs[1].has_preprocessed = true;
        preprocessed.setup_bytes_per_preprocessed_row = u64::MAX;
        for model in [model([1, u64::MAX], 1), preprocessed] {
            assert_eq!(model.prover_peak_bytes(&[4, 0]), Some(10));
            assert_eq!(model.max_any_height_for_budget(10), 4);
            assert_eq!(model.prover_peak_bytes(&[5, 0]), Some(13));
        }
        let model = model([u64::MAX], 1);
        assert_eq!(model.prover_peak_bytes(&[0]), Some(0));
        assert_eq!(model.max_any_height_for_budget(u64::MAX), 0);
    }

    #[test]
    fn empty_relations_and_zero_cost_airs_have_distinct_caps() {
        let empty = TestMultiAir { airs: [] };
        let params = params(64);
        assert_eq!(prover_peak_bytes::<Felt, QuadFelt, _>(&empty, &[], &params), Some(0));
        assert_eq!(max_any_height_for_budget::<Felt, QuadFelt, _>(&empty, 0, &params), 0);
        let empty =
            ProverMemoryModel::<0>::from_multi_air::<Felt, QuadFelt, _>(&empty, &params).unwrap();
        assert_eq!(empty.prover_peak_bytes(&[]), Some(0));
        assert_eq!(empty.max_any_height_for_budget(0), 0);
        let zero = model([0], 0);
        assert_eq!(zero.prover_peak_bytes(&[usize::MAX]), Some(0));
        assert_eq!(zero.max_any_height_for_budget(0), usize::MAX);
    }
}
