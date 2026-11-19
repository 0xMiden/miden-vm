//! Illustrates the per-AIR quotient-degree optimization.
//!
//! Compares per-AIR quotient degrees against a common maximum degree using
//! native execution capacity. The low-degree AIR uses its own quotient domain before its
//! quotient is lifted to the common commitment domain.
//!
//! Runs `prove` with two AIRs:
//! - Synthetic Core AIR: width 72, max constraint degree 9 (so `D = 8`).
//! - Synthetic Chip AIR: width 72, max constraint degree 5 (so `D = 4`).
//!
//! Two variants:
//! - **Baseline**: both AIRs allocate eight quotient chunks (`D = 8`). Chip's constraints are
//!   evaluated on `chip_height * 8` points (the full target domain) rather than its natural
//!   `chip_height * 4`.
//! - **Optimized**: Core allocates eight chunks (`D = 8`), Chip four (`D = 4`). Chip evaluates on
//!   its native domain (size `chip_height * 4`), divides by the native vanishing polynomial, and
//!   `upsample_evals` lifts the resulting quotient to the target (`chip_height * 8`).
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
use miden_stark::{
    GenericStarkConfig, ProverInstance, air,
    air::LiftedAirBuilder as _,
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

impl air::LiftedAir for BenchAir {
    type F = Felt;

    fn spec(&self) -> air::AirSpec<'_, Felt> {
        air::AirSpec {
            main_width: WIDTH,
            aux_width: 1,
            num_public_values: 0,
            num_challenges: 1,
            num_exports: 0,
            preprocessed: None,
            periodic_columns: Cow::Borrowed(&[]),
        }
    }

    fn eval<AB: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, AB>,
        inputs: air::Inputs<'_, AB>,
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

impl air::ProverAir<QuadFelt> for BenchAir {
    type Error = Infallible;

    fn build_aux_trace(
        &self,
        inputs: air::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<air::AuxTrace<QuadFelt>, Self::Error> {
        // Benchmark-owned inputs carry the one challenge and a validated main matrix.
        Ok(air::AuxTrace {
            columns: RowMajorMatrix::new(vec![inputs.challenges[0]; inputs.main.height()], 1),
            exports: vec![],
        })
    }
}

/// Benchmark execution capacity without modifying the authored relation's diagnostics.
struct ConservativeKernel {
    direct: air::DirectKernel<BenchAir>,
    chunks: usize,
}

impl ConservativeKernel {
    fn new(source: BenchAir, chunks: usize) -> Result<Self, air::QuotientAllocationError> {
        let kernel = Self {
            direct: air::DirectKernel::new(source).expect("valid benchmark AIR"),
            chunks,
        };
        air::resolve_quotient_chunks(&kernel)?;
        Ok(kernel)
    }
}

impl air::AirKernel for ConservativeKernel {
    type F = Felt;
    type Prepared<B: Algebra<Felt>, E: Algebra<B>> =
        <air::DirectKernel<BenchAir> as air::AirKernel>::Prepared<B, E>;

    fn descriptor(&self) -> &air::AirDescriptor<Felt> {
        air::AirKernel::descriptor(&self.direct)
    }

    fn quotient_chunks(&self) -> Option<usize> {
        Some(self.chunks)
    }

    fn prepare<B: Algebra<Felt>, E: Algebra<B>>(
        &self,
        inputs: air::UniformInputs<'_, B, E>,
    ) -> Self::Prepared<B, E> {
        air::AirKernel::prepare(&self.direct, inputs)
    }

    fn eval_row<S: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, S>,
        inputs: air::Inputs<'_, S>,
        prepared: &Self::Prepared<S::Expr, S::ExtExpr>,
        sink: &mut S,
    ) {
        air::AirKernel::eval_row(&self.direct, frame, inputs, prepared, sink);
    }
}

impl air::LiftedAir for ConservativeKernel {
    type F = Felt;

    fn spec(&self) -> air::AirSpec<'_, Felt> {
        air::LiftedAir::spec(&self.direct)
    }

    fn eval<S: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, S>,
        inputs: air::Inputs<'_, S>,
        sink: &mut S,
    ) {
        air::LiftedAir::eval(&self.direct, frame, inputs, sink);
    }
}

impl air::ProverAir<QuadFelt> for ConservativeKernel {
    type Error = Infallible;

    fn build_aux_trace(
        &self,
        inputs: air::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<air::AuxTrace<QuadFelt>, Self::Error> {
        air::ProverAir::build_aux_trace(&self.direct, inputs)
    }
}

// -----------------------------------------------------------------------------
// MultiAir (trivial: constant-challenge aux column for each trace)
// -----------------------------------------------------------------------------

struct BenchMultiAir {
    airs: Vec<ConservativeKernel>,
}

impl MultiAir<Felt, QuadFelt> for BenchMultiAir {
    type Air = ConservativeKernel;

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

fn run_prove(
    label: &str,
    core_log_qd: usize,
    chip_log_qd: usize,
    core_height: usize,
    chip_height: usize,
) {
    let config =
        GenericStarkConfig::new(bench_pcs_params(), test_lmcs(), Dft::default(), test_challenger());

    let core_air =
        ConservativeKernel::new(BenchAir { kind: BenchAirKind::Core }, 1usize << core_log_qd)
            .expect("conservative Core capacity");
    let chip_air =
        ConservativeKernel::new(BenchAir { kind: BenchAirKind::Chip }, 1usize << chip_log_qd)
            .expect("conservative Chip capacity");

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
    let env_filter = match std::env::var("RUST_LOG") {
        Ok(value) => EnvFilter::try_new(value).expect("invalid RUST_LOG"),
        Err(std::env::VarError::NotPresent) => EnvFilter::new("debug,miden::vm::prove=trace"),
        Err(error) => panic!("invalid RUST_LOG: {error}"),
    };
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .init();

    // Sizes chosen so eval makes a substantive fraction of prove time while keeping
    // the bench under ~1 minute. core @ 2^14, chip @ 2^16.
    let core_height = 1 << 14;
    let chip_height = 1 << 16;

    // Baseline: allocate log_qd = 3 to both AIRs (global max). Chip loses the
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
        let canonical = super::air::capture_with::<_, super::QuadFelt>(&source).unwrap();
        let natural = super::ConservativeKernel::new(source, 4).unwrap();
        let raised = super::ConservativeKernel::new(source, 8).unwrap();
        for kernel in [&natural, &raised] {
            let descriptor = super::air::AirKernel::descriptor(kernel);
            assert_eq!(descriptor.fingerprint(), canonical.descriptor.fingerprint());
            assert_eq!(descriptor.analysis(), canonical.descriptor.analysis());
            assert_eq!(
                descriptor.analysis().raw_degrees(),
                super::air::ConstraintDegrees { base: 5, ext: 1 }
            );
            let counts = descriptor.analysis().counts();
            assert_eq!(
                (counts.base, counts.ext),
                (super::CONSTRAINTS_PER_COLUMN * super::WIDTH, 1)
            );
            let recaptured = super::air::capture_with::<_, super::QuadFelt>(kernel).unwrap();
            assert_eq!(recaptured.descriptor.fingerprint(), canonical.descriptor.fingerprint());
        }
        assert_eq!(super::air::resolve_quotient_chunks(&natural).unwrap(), 4);
        assert_eq!(super::air::resolve_quotient_chunks(&raised).unwrap(), 8);
        let minimum = super::air::AirKernel::descriptor(&raised)
            .analysis()
            .degree_profile()
            .validate_capacity(16, 8)
            .unwrap();
        assert_eq!(minimum.quotient_chunks, 4);
        assert_eq!(super::air::resolve_quotient_chunks(&raised).unwrap(), 8);
        assert!(matches!(
            super::ConservativeKernel::new(source, 2),
            Err(super::air::QuotientAllocationError::BelowConservative {
                allocated: 2,
                conservative: 4
            })
        ));
        assert!(matches!(
            super::ConservativeKernel::new(source, 3),
            Err(super::air::QuotientAllocationError::InvalidChunks { chunks: 3 })
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
            let model = miden_stark::memory::ProverMemoryModel::<2>::from_kernels::<
                super::QuadFelt,
                _,
            >(&kernels, &super::bench_pcs_params())
            .unwrap();
            assert_eq!(model.prover_peak_bytes(&[0, 0]), Some(0));
            // 74 coordinates * 8 bytes * (8+1) * (16+32), plus 3904*32 shared bytes,
            // followed by the one 5/4 safety ceiling. Core retains the common maximum8.
            assert_eq!(model.prover_peak_bytes(&[16, 32]), Some(475_840));
        }
    }
}
