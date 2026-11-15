//! Illustrates the per-AIR quotient-degree optimization.
//!
//! Compares per-AIR quotient degrees against a common maximum degree using
//! [`OverrideConstraintDegree`]. The low-degree AIR uses its own quotient domain before its
//! quotient is lifted to the common commitment domain.
//!
//! Matching native kernels validate allocation/profile and memory metadata before the timer;
//! the timed path retains the existing legacy collection until runtime activation.
//!
//! Runs `prove` with two AIRs:
//! - Synthetic Core AIR: width 72, max constraint degree 9 (so `D = 8`).
//! - Synthetic Chip AIR: width 72, max constraint degree 5 (so `D = 4`).
//!
//! Two variants:
//! - **Baseline**: both AIRs are forced to `constraint_degree = 9` (so `D = 8`). Chip's constraints
//!   are evaluated on `chip_height * 8` points (the full target domain) rather than its natural
//!   `chip_height * 4`.
//! - **Optimized**: Core forced to `constraint_degree = 9` (`D = 8`), Chip to `constraint_degree =
//!   5` (`D = 4`). Chip evaluates on its native domain (size `chip_height * 4`), divides by the
//!   native vanishing polynomial, and `upsample_evals` lifts the resulting quotient to the target
//!   (`chip_height * 8`).
//!
//! Run:
//! ```bash
//! RUSTFLAGS="-Ctarget-cpu=native" cargo bench -p miden-bench \
//!     --bench per_air_degree_opt --features concurrent
//! ```

#[path = "support/eidos.rs"]
mod eidos;
use std::{borrow::Cow, convert::Infallible, time::Instant};

use eidos::{Dft, Felt, QuadFelt, test_challenger, test_lmcs};
use miden_stark::air::native::LiftedAirBuilder as _;
use miden_stark::{
    GenericStarkConfig, ProverInstance,
    air::{BaseAir, ConstraintDegrees, LiftedAir, LiftedAirBuilder, native},
    memory::ProverMemoryModel,
    testing::{MultiAir, PcsParams, ProverStatement, Statement},
};
use p3_field::{Algebra, Dup, PrimeCharacteristicRing};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use tracing_subscriber::EnvFilter;

// -----------------------------------------------------------------------------
// AIR
// -----------------------------------------------------------------------------

const WIDTH: usize = 72;

/// Number of redundant recurrence constraints per column. Each copy is a separate
/// `assert_eq` call (so the symbolic analyzer counts them independently) but all
/// reduce to the same `next[c] == local[c]^power` identity, so any trace satisfying
/// one copy satisfies all of them. This dials up per-point constraint-evaluation
/// work without changing trace semantics or constraint degree.
const CONSTRAINTS_PER_COLUMN: usize = 20;

/// Per-row transition kind used by the benchmark AIR.
#[derive(Clone, Copy, Debug)]
enum BenchAirKind {
    Core,
    Chip,
}

impl BenchAirKind {
    fn log2_hi(self) -> usize {
        match self {
            BenchAirKind::Core => 3,
            BenchAirKind::Chip => 2,
        }
    }

    fn recurrence_power(self) -> u64 {
        match self {
            BenchAirKind::Core => 9,
            BenchAirKind::Chip => 5,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct BenchAir {
    kind: BenchAirKind,
}

impl BaseAir<Felt> for BenchAir {
    fn width(&self) -> usize {
        WIDTH
    }
}

impl LiftedAir<Felt, QuadFelt> for BenchAir {
    type EvalData<B: Algebra<Felt>, E: Algebra<B>> = ();

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
        main: &RowMajorMatrix<Felt>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        let aux = native::ProverAir::build_aux_trace(
            self,
            native::AuxTraceInputs {
                main,
                preprocessed: None,
                public_values: air_inputs,
                statement: aux_inputs,
                challenges,
            },
        )
        .expect("benchmark witness is infallible");
        (aux.columns, aux.exports)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB, _data: &()) {
        native::migration::eval_source(self, builder);
    }
}

impl native::LiftedAir for BenchAir {
    type F = Felt;

    fn spec(&self) -> native::AirSpec<'_, Felt> {
        native::AirSpec {
            main_width: WIDTH,
            aux_width: 1,
            num_public_values: 0,
            num_challenges: 1,
            num_exports: 0,
            preprocessed: None,
            periodic_columns: Cow::Borrowed(&[]),
        }
    }

    fn eval<AB: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, AB>,
        inputs: native::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        let local = frame.main.current;
        let next = frame.main.next;
        let log2_hi = self.kind.log2_hi();

        // Main recurrence on every column: `next[c] = local[c]^(2^log2_hi + 1)`.
        // Preserve every repeated assertion and its transition selector.
        for _ in 0..CONSTRAINTS_PER_COLUMN {
            for c in 0..WIDTH {
                let x: AB::Expr = local[c].dup();
                let x_hi: AB::Expr = x.exp_power_of_2(log2_hi);
                builder.when(frame.transition()).assert_eq(next[c].dup(), x_hi * x);
            }
        }
        builder.assert_eq_ext(frame.aux.current[0].dup(), inputs.challenge(0));
    }
}

impl native::ProverAir<QuadFelt> for BenchAir {
    type Error = Infallible;

    fn build_aux_trace(
        &self,
        inputs: native::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<native::AuxTrace<QuadFelt>, Self::Error> {
        // Benchmark-owned inputs carry the one challenge and a validated main matrix.
        Ok(native::AuxTrace {
            columns: RowMajorMatrix::new(vec![inputs.challenges[0]; inputs.main.height()], 1),
            exports: vec![],
        })
    }
}

/// Benchmark execution capacity without modifying the authored relation's diagnostics.
struct ConservativeKernel {
    direct: native::DirectKernel<BenchAir>,
    chunks: usize,
}

impl ConservativeKernel {
    fn new(source: BenchAir, chunks: usize) -> Result<Self, native::QuotientAllocationError> {
        let kernel = Self {
            direct: native::DirectKernel::new(source).expect("valid benchmark AIR"),
            chunks,
        };
        native::resolve_quotient_chunks(&kernel)?;
        Ok(kernel)
    }
}

impl native::AirKernel for ConservativeKernel {
    type F = Felt;
    type Prepared<B: Algebra<Felt>, E: Algebra<B>> =
        <native::DirectKernel<BenchAir> as native::AirKernel>::Prepared<B, E>;

    fn descriptor(&self) -> &native::AirDescriptor<Felt> {
        native::AirKernel::descriptor(&self.direct)
    }

    fn quotient_chunks(&self) -> Option<usize> {
        Some(self.chunks)
    }

    fn prepare<B: Algebra<Felt>, E: Algebra<B>>(
        &self,
        inputs: native::UniformInputs<'_, B, E>,
    ) -> Self::Prepared<B, E> {
        native::AirKernel::prepare(&self.direct, inputs)
    }

    fn eval_row<S: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, S>,
        inputs: native::Inputs<'_, S>,
        prepared: &Self::Prepared<S::Expr, S::ExtExpr>,
        sink: &mut S,
    ) {
        native::AirKernel::eval_row(&self.direct, frame, inputs, prepared, sink);
    }
}

impl native::LiftedAir for ConservativeKernel {
    type F = Felt;

    fn spec(&self) -> native::AirSpec<'_, Felt> {
        native::LiftedAir::spec(&self.direct)
    }

    fn eval<S: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, S>,
        inputs: native::Inputs<'_, S>,
        sink: &mut S,
    ) {
        native::LiftedAir::eval(&self.direct, frame, inputs, sink);
    }
}

impl native::ProverAir<QuadFelt> for ConservativeKernel {
    type Error = Infallible;

    fn build_aux_trace(
        &self,
        inputs: native::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<native::AuxTrace<QuadFelt>, Self::Error> {
        native::ProverAir::build_aux_trace(&self.direct, inputs)
    }
}

/// Test wrapper that forces [`LiftedAir::constraint_degree`] to a chosen value
/// (quotient chunking — and hence `log_quotient_degree` — is derived from it).
///
/// Delegates everything else to the inner AIR. Used by this bench to toggle between
/// the baseline (force every AIR to the global-max degree) and the optimized path
/// (each AIR at its natural degree).
///
/// Overriding *higher* than the AIR actually needs is safe: the prover/verifier just
/// use a larger quotient domain than necessary. Overriding *lower* than needed would
/// produce an invalid proof.
#[derive(Clone, Copy, Debug)]
struct OverrideConstraintDegree<A> {
    inner: A,
    constraint_degree: usize,
}

/// Constraint degree that yields `log_quotient_degree == l`:
/// `log2_ceil(((1 << l) + 1) - 1) == log2_ceil(1 << l) == l`.
fn constraint_degree_for_log_qd(l: usize) -> usize {
    (1 << l) + 1
}

impl<A: BaseAir<Felt>> BaseAir<Felt> for OverrideConstraintDegree<A> {
    fn width(&self) -> usize {
        self.inner.width()
    }
    fn num_public_values(&self) -> usize {
        self.inner.num_public_values()
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        self.inner.periodic_columns()
    }
}

impl<A: LiftedAir<Felt, QuadFelt>> LiftedAir<Felt, QuadFelt> for OverrideConstraintDegree<A> {
    type EvalData<B: Algebra<Felt>, E: Algebra<B>> = A::EvalData<B, E>;

    fn num_randomness(&self) -> usize {
        self.inner.num_randomness()
    }
    fn aux_width(&self) -> usize {
        self.inner.aux_width()
    }
    fn num_aux_values(&self) -> usize {
        self.inner.num_aux_values()
    }
    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        self.inner.build_aux_trace(main, air_inputs, aux_inputs, challenges)
    }
    fn prepare<B: Algebra<Felt>, E: Algebra<B>>(
        &self,
        inputs: miden_stark::air::EvalInputs<'_, B, E>,
    ) -> Self::EvalData<B, E> {
        self.inner.prepare(inputs)
    }
    fn eval<AB: LiftedAirBuilder<F = Felt>>(
        &self,
        builder: &mut AB,
        data: &Self::EvalData<AB::Expr, AB::ExprEF>,
    ) {
        self.inner.eval(builder, data)
    }
    fn constraint_degree(&self) -> ConstraintDegrees
    where
        Self: Sized,
    {
        ConstraintDegrees { base: self.constraint_degree, ext: 0 }
    }
}

// -----------------------------------------------------------------------------
// MultiAir (trivial: constant-challenge aux column for each trace)
// -----------------------------------------------------------------------------

struct BenchMultiAir {
    airs: Vec<OverrideConstraintDegree<BenchAir>>,
}

impl MultiAir<Felt, QuadFelt> for BenchMultiAir {
    type Air = OverrideConstraintDegree<BenchAir>;

    fn airs(&self) -> &[Self::Air] {
        &self.airs
    }
}

// -----------------------------------------------------------------------------
// Trace generation
// -----------------------------------------------------------------------------

/// Generate a `WIDTH x height` trace satisfying `next[c] = local[c]^power`.
///
/// Column `c` starts at `c + 2` (so rows are non-constant and all-distinct at t=0).
fn generate_trace(power: u64, height: usize) -> RowMajorMatrix<Felt> {
    let mut data = Vec::with_capacity(WIDTH * height);
    // Row 0: col c = c + 2 (base field).
    for c in 0..WIDTH {
        data.push(Felt::from_u64((c + 2) as u64));
    }
    // Rows 1..height: col c = prev^power.
    for r in 1..height {
        let prev_row_start = (r - 1) * WIDTH;
        for c in 0..WIDTH {
            let prev = data[prev_row_start + c];
            data.push(prev.exp_u64(power));
        }
    }
    RowMajorMatrix::new(data, WIDTH)
}

// -----------------------------------------------------------------------------
// Driver
// -----------------------------------------------------------------------------

/// Custom PCS params for this bench: `log_blowup = 3` to permit `log_qd = 3`.
fn bench_pcs_params() -> PcsParams {
    PcsParams::new(
        3,  // log_blowup (must be >= max log_qd = 3)
        2,  // log_folding_arity (arity 4)
        2,  // log_final_degree
        0,  // folding_pow_bits
        0,  // deep_pow_bits
        30, // num_queries
        0,  // query_pow_bits
    )
    .expect("valid PCS params")
}

/// Inspect matching native execution metadata before entering the unchanged timed proof path.
fn native_preflight(
    core: &OverrideConstraintDegree<BenchAir>,
    chip: &OverrideConstraintDegree<BenchAir>,
    log_degrees: [usize; 2],
    heights: [usize; 2],
    params: &PcsParams,
) {
    let kernels = [
        ConservativeKernel::new(core.inner, 1usize << log_degrees[0])
            .expect("conservative Core capacity"),
        ConservativeKernel::new(chip.inner, 1usize << log_degrees[1])
            .expect("conservative Chip capacity"),
    ];
    for (kernel, height) in kernels.iter().zip(heights) {
        let chunks = native::resolve_quotient_chunks(kernel).expect("valid execution allocation");
        assert!(
            chunks <= 1usize << params.log_blowup(),
            "benchmark allocation exceeds PCS blowup"
        );
        native::AirKernel::descriptor(kernel)
            .analysis()
            .degree_profile()
            .validate_capacity(height, chunks)
            .expect("benchmark degree fits actual height");
    }
    let model = ProverMemoryModel::<2>::from_kernels::<QuadFelt, _>(&kernels, params)
        .expect("native benchmark memory metadata");
    assert!(
        model.prover_peak_bytes(&heights).is_some(),
        "benchmark memory estimate fits host arithmetic"
    );
    assert_eq!(model.prover_peak_bytes(&[0, 0]), Some(0));
}

fn run_prove(
    label: &str,
    core_log_qd: usize,
    chip_log_qd: usize,
    core_height: usize,
    chip_height: usize,
) {
    let config =
        GenericStarkConfig::new(bench_pcs_params(), test_lmcs(), Dft::default(), test_challenger());

    let core_air = OverrideConstraintDegree {
        inner: BenchAir { kind: BenchAirKind::Core },
        constraint_degree: constraint_degree_for_log_qd(core_log_qd),
    };
    let chip_air = OverrideConstraintDegree {
        inner: BenchAir { kind: BenchAirKind::Chip },
        constraint_degree: constraint_degree_for_log_qd(chip_log_qd),
    };

    native_preflight(
        &core_air,
        &chip_air,
        [core_log_qd, chip_log_qd],
        [core_height, chip_height],
        &bench_pcs_params(),
    );

    let core_trace = generate_trace(BenchAirKind::Core.recurrence_power(), core_height);
    let chip_trace = generate_trace(BenchAirKind::Chip.recurrence_power(), chip_height);

    let statement =
        Statement::new(BenchMultiAir { airs: vec![core_air, chip_air] }, Vec::new(), Vec::new())
            .unwrap();
    let prover_statement = ProverStatement::new(statement, vec![core_trace, chip_trace]).unwrap();

    eprintln!("\n{}", "=".repeat(70));
    eprintln!(
        "=== {label}: core(h={core_height}, log_qd={core_log_qd})  chip(h={chip_height}, log_qd={chip_log_qd}) ==="
    );
    eprintln!("{}\n", "=".repeat(70));

    let start = Instant::now();
    let _output = ProverInstance::new(&config, prover_statement, None)
        .expect("no preprocessed columns")
        .prove(test_challenger())
        .expect("prove succeeds");
    let elapsed = start.elapsed();

    eprintln!(">>> Total prove time: {elapsed:.3?}\n");
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug")),
        )
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .init();

    // Sizes chosen so eval makes a substantive fraction of prove time while keeping
    // the bench under ~1 minute. core @ 2^14, chip @ 2^16.
    let core_height = 1 << 14;
    let chip_height = 1 << 16;

    // Baseline: force both AIRs to report log_qd = 3 (global max). Chip loses the
    // optimization and evaluates on chip_height*8 points directly, no upsample.
    run_prove("baseline (no upsample)", 3, 3, core_height, chip_height);

    // Optimized: Core at natural log_qd=3, Chip at natural log_qd=2. Chip evaluates
    // on chip_height*4 points natively, then upsamples to chip_height*8.
    run_prove("optimized (upsample fires)", 3, 2, core_height, chip_height);
}

#[cfg(test)]
mod tests {
    #[test]
    fn conservative_capacity_does_not_modify_source_identity_or_analysis() {
        let source = super::BenchAir { kind: super::BenchAirKind::Chip };
        let canonical = super::native::capture_with::<_, super::QuadFelt>(&source).unwrap();
        let natural = super::ConservativeKernel::new(source, 4).unwrap();
        let raised = super::ConservativeKernel::new(source, 8).unwrap();
        for kernel in [&natural, &raised] {
            let descriptor = super::native::AirKernel::descriptor(kernel);
            assert_eq!(descriptor.fingerprint(), canonical.descriptor.fingerprint());
            assert_eq!(descriptor.analysis(), canonical.descriptor.analysis());
            assert_eq!(
                descriptor.analysis().raw_degrees(),
                super::native::ConstraintDegrees { base: 5, ext: 1 }
            );
            let counts = descriptor.analysis().counts();
            assert_eq!(
                (counts.base, counts.ext),
                (super::CONSTRAINTS_PER_COLUMN * super::WIDTH, 1)
            );
            let recaptured = super::native::capture_with::<_, super::QuadFelt>(kernel).unwrap();
            assert_eq!(recaptured.descriptor.fingerprint(), canonical.descriptor.fingerprint());
        }
        assert_eq!(super::native::resolve_quotient_chunks(&natural).unwrap(), 4);
        assert_eq!(super::native::resolve_quotient_chunks(&raised).unwrap(), 8);
        let minimum = super::native::AirKernel::descriptor(&raised)
            .analysis()
            .degree_profile()
            .validate_capacity(16, 8)
            .unwrap();
        assert_eq!(minimum.quotient_chunks, 4);
        assert_eq!(super::native::resolve_quotient_chunks(&raised).unwrap(), 8);
        assert!(matches!(
            super::ConservativeKernel::new(source, 2),
            Err(super::native::QuotientAllocationError::BelowConservative {
                allocated: 2,
                conservative: 4
            })
        ));
        assert!(matches!(
            super::ConservativeKernel::new(source, 3),
            Err(super::native::QuotientAllocationError::InvalidChunks { chunks: 3 })
        ));
    }

    #[test]
    fn baseline_and_optimized_native_metadata_reuse_the_same_memory_accounting() {
        for chip_chunks in [4, 8] {
            let kernels = [
                super::ConservativeKernel::new(
                    super::BenchAir { kind: super::BenchAirKind::Core },
                    8,
                )
                .unwrap(),
                super::ConservativeKernel::new(
                    super::BenchAir { kind: super::BenchAirKind::Chip },
                    chip_chunks,
                )
                .unwrap(),
            ];
            let model = super::ProverMemoryModel::<2>::from_kernels::<super::QuadFelt, _>(
                &kernels,
                &super::bench_pcs_params(),
            )
            .unwrap();
            assert_eq!(model.prover_peak_bytes(&[0, 0]), Some(0));
            // 74 coordinates * 8 bytes * (8+1) * (16+32), plus 3904*32 shared bytes,
            // followed by the one 5/4 safety ceiling. Core retains the common maximum8.
            assert_eq!(model.prover_peak_bytes(&[16, 32]), Some(475_840));
        }
    }
}
