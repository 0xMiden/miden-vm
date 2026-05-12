//! Illustrates the per-AIR quotient-degree optimization.
//!
//! This bench compares two synthetic configurations of the **same** code path,
//! toggled via [`OverrideLogQuotientDegree`]. It is **not** a comparison against
//! the codebase's pre-PR state; it isolates the speedup attributable to evaluating
//! a low-degree AIR on its native quotient domain rather than the global one.
//!
//! Runs `prove_multi` with two AIRs:
//! - Core AIR: width 72, max constraint degree 9 (so `D = 8`).
//! - Chip AIR: width 72, max constraint degree 5 (so `D = 4`).
//!
//! Two variants:
//! - **Baseline**: both AIRs report `log_quotient_degree = 3` (`D = 8`). Chip's constraints are
//!   evaluated on `chip_height * 8` points (the full target domain) rather than its natural
//!   `chip_height * 4`.
//! - **Optimized**: Core reports `log_qd = 3`, Chip reports `log_qd = 2`. Chip evaluates on its
//!   native domain (size `chip_height * 4`), divides by the native vanishing polynomial, and
//!   `upsample_evals` lifts the resulting quotient to the target (`chip_height * 8`).
//!
//! Run:
//! ```bash
//! RUSTFLAGS="-Ctarget-cpu=native" cargo bench -p miden-lifted-stark \
//!     --bench per_air_degree_opt --features testing,parallel
//! ```

use std::time::Instant;

use miden_lifted_air::{
    AirBuilder, AuxBuilder, BaseAir, LiftedAir, LiftedAirBuilder, WindowAccess,
};
use miden_lifted_stark::{
    AirWitness, GenericStarkConfig, PcsParams, prove_multi,
    testing::configs::goldilocks_poseidon2::{Dft, Felt, QuadFelt, test_challenger, test_lmcs},
};
use p3_field::PrimeCharacteristicRing;
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
    fn num_randomness(&self) -> usize {
        1
    }

    fn aux_width(&self) -> usize {
        1
    }

    fn num_aux_values(&self) -> usize {
        0
    }

    fn num_var_len_public_inputs(&self) -> usize {
        0
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.current_slice().to_vec(), main.next_slice().to_vec());
        let log2_hi = self.kind.log2_hi();

        // Main recurrence on every column: `next[c] = local[c]^(2^log2_hi + 1)`.
        // Duplicate the constraint `CONSTRAINTS_PER_COLUMN` times to densify eval work
        // without changing the trace or the max constraint degree.
        for _ in 0..CONSTRAINTS_PER_COLUMN {
            for c in 0..WIDTH {
                let x: AB::Expr = local[c].into();
                let x_hi: AB::Expr = x.clone().exp_power_of_2(log2_hi);
                builder.when_transition().assert_eq(next[c].into(), x_hi * x);
            }
        }

        // Aux constraint: `aux_local == challenge`, trivial degree-1 identity.
        let aux = builder.permutation();
        let aux_local = aux.current_slice().to_vec();
        let challenge = builder.permutation_randomness()[0];
        let aux_expr: AB::ExprEF = aux_local[0].into();
        let challenge_expr: AB::ExprEF = challenge.into();
        builder.assert_eq_ext(aux_expr, challenge_expr);
    }
}

/// Test wrapper that forces [`LiftedAir::log_quotient_degree`] to a chosen value.
///
/// Delegates everything else to the inner AIR. Used by this bench to toggle between
/// the baseline (force `log_qd = global_max`) and the optimized path (natural `log_qd`).
///
/// Overriding *higher* than the AIR actually needs is safe: the prover/verifier just
/// use a larger quotient domain than necessary. Overriding *lower* than needed would
/// produce an invalid proof.
#[derive(Clone, Copy, Debug)]
struct OverrideLogQuotientDegree<A> {
    inner: A,
    log_qd: usize,
}

impl<A: BaseAir<Felt>> BaseAir<Felt> for OverrideLogQuotientDegree<A> {
    fn width(&self) -> usize {
        self.inner.width()
    }
    fn num_public_values(&self) -> usize {
        self.inner.num_public_values()
    }
}

impl<A: LiftedAir<Felt, QuadFelt>> LiftedAir<Felt, QuadFelt> for OverrideLogQuotientDegree<A> {
    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        self.inner.periodic_columns()
    }
    fn num_randomness(&self) -> usize {
        self.inner.num_randomness()
    }
    fn aux_width(&self) -> usize {
        self.inner.aux_width()
    }
    fn num_aux_values(&self) -> usize {
        self.inner.num_aux_values()
    }
    fn num_var_len_public_inputs(&self) -> usize {
        self.inner.num_var_len_public_inputs()
    }
    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        self.inner.eval(builder)
    }
    fn log_quotient_degree(&self) -> usize
    where
        Self: Sized,
    {
        self.log_qd
    }
}

// -----------------------------------------------------------------------------
// Aux builder (trivial: constant-challenge column)
// -----------------------------------------------------------------------------

struct BenchAuxBuilder;

impl AuxBuilder<Felt, QuadFelt> for BenchAuxBuilder {
    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        let height = main.height();
        let column = vec![challenges[0]; height];
        (RowMajorMatrix::new(column, 1), vec![])
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

    let core_air = OverrideLogQuotientDegree {
        inner: BenchAir { kind: BenchAirKind::Core },
        log_qd: core_log_qd,
    };
    let chip_air = OverrideLogQuotientDegree {
        inner: BenchAir { kind: BenchAirKind::Chip },
        log_qd: chip_log_qd,
    };

    let core_trace = generate_trace(BenchAirKind::Core.recurrence_power(), core_height);
    let chip_trace = generate_trace(BenchAirKind::Chip.recurrence_power(), chip_height);

    let core_witness = AirWitness::new(&core_trace, &[], &[]);
    let chip_witness = AirWitness::new(&chip_trace, &[], &[]);

    let builder = BenchAuxBuilder;
    let instances = &[(&core_air, core_witness, &builder), (&chip_air, chip_witness, &builder)];

    eprintln!("\n{}", "=".repeat(70));
    eprintln!(
        "=== {label}: core(h={core_height}, log_qd={core_log_qd})  chip(h={chip_height}, log_qd={chip_log_qd}) ==="
    );
    eprintln!("{}\n", "=".repeat(70));

    let start = Instant::now();
    let _output = prove_multi::<Felt, QuadFelt, _, _, _>(&config, instances, test_challenger())
        .expect("prove succeeds");
    let elapsed = start.elapsed();

    eprintln!(">>> Total prove_multi time: {elapsed:.3?}\n");
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
