//! Uint-throughput bench: prove + verify the sign-alternation Horner
//! statement — `P(−x)` computed by two different DAG shapes over the
//! secp256k1 base field and closed by the `is` predicate — at an
//! adjustable polynomial degree.
//!
//! Usage: `cargo run --release --example bench_uint_horner -- [N]`
//!
//! Default: `N=64` (polynomial degree ≥ 1).
//!
//! A degree-`N` statement costs `2N` `UintMul` + `2N + 1` `UintAdd`
//! relation ops, `N + 2` value leaves, and one `Is` — arithmetic
//! dominates and the keccak chiplets stay empty, so the wall-times read
//! as uint throughput. The construction is the shared
//! [`horner_sign_paths`]; the same shape (at degree 3) runs asserted in
//! `tests::uint_dag`.
//!
//! Reports trace heights, prove + verify wall-time, and derived
//! ops/sec. The wall-times are preliminary, not final-perf numbers: the
//! lifted protocol has no preprocessed-trace commitment (fixed columns
//! aren't amortized across proofs) and no heterogeneous
//! constraint-degree blowup (every AIR shares one uniform max-degree
//! LDE). Both inflate prove time.

use std::time::Instant;

use miden_lifted_air::LiftedAir;
use miden_precompiles::K1_BASE_BOUND_PTR;
use miden_precompiles_prover::{
    math::{U256, from_hex},
    session::{ChipletAir, Session, statements::horner_sign_paths},
};
use p3_matrix::Matrix;
use rand::{Rng, SeedableRng, rngs::StdRng};

/// VM fixed secp256k1 base-field bound pointer.
const FP: u32 = K1_BASE_BOUND_PTR;

/// A random uint strictly below the bound: the top 16 bits are reduced
/// below the bound's (k1's are 0xFFFF), the lower bits are free.
fn random_uint_below(rng: &mut impl Rng, bound: U256) -> U256 {
    let mut limbs: [u64; 4] = core::array::from_fn(|_| rng.random());
    let top = u64::from(rng.random::<u16>() % (bound.as_limbs()[3] >> 48) as u16);
    limbs[3] = limbs[3] & 0xffff_ffff_ffff | top << 48;
    U256::from_limbs(limbs)
}

fn main() {
    // `PROFILE=1` installs a span timer (stderr) so the prover's phase
    // breakdown — `evaluate constraints` (ext-field eval) vs `LDE` /
    // `quotient DFT/iDFT` / `commit *` (FFT + hashing) — is visible. Research
    // only; off by default so normal bench output stays clean.
    if std::env::var("PROFILE").is_ok() {
        use tracing_subscriber::fmt::format::FmtSpan;
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_span_events(FmtSpan::CLOSE)
            .with_writer(std::io::stderr)
            .init();
    }

    let n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(64);
    assert!(n >= 1, "polynomial degree must be ≥ 1");

    // secp256k1 Fp − 1: the chiplet stack is modulus-agnostic, the k1
    // prime is just this bench's pinned choice.
    let p_minus_1 = from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E");

    let n_mul = 2 * n;
    let n_add = 2 * n + 1;

    println!("=================================================");
    println!("bench_uint_horner: degree N={n} over secp256k1 Fp");
    println!("  {n_mul} UintMul + {n_add} UintAdd relation ops");
    println!("=================================================");

    // ------ trace generation -------------------------------------------
    let gen_start = Instant::now();

    let mut session = Session::new();

    let mut rng = StdRng::seed_from_u64(0x4042_1d06);
    let x = random_uint_below(&mut rng, p_minus_1);
    let coeffs: Vec<U256> = (0..=n).map(|_| random_uint_below(&mut rng, p_minus_1)).collect();

    let (acc_a, acc_b) = horner_sign_paths(&mut session, x, &coeffs, FP);
    let claim = session.uint_is(&acc_a, &acc_b);
    let root = session.assert_and_fold([claim]);

    let traces = session.finish(root);
    let public_root = traces.public_root();
    let mains = traces.mains();

    let gen_elapsed = gen_start.elapsed();

    // Names line up with `SessionTraces::mains()` canonical order.
    let names = [
        "chunk    ",
        "poseidon2",
        "round    ",
        "bitwise64",
        "bpl      ",
        "sponge   ",
        "kn       ",
        "eval     ",
        "uint     ",
        "uintadd  ",
        "uintmul  ",
        "ec_groups",
        "ec_points",
        "ec_add   ",
    ];

    // Each chiplet commits `base` main columns plus `ext` extension-field
    // (QuadFelt) LogUp columns; `aux_width` is a static AIR property, so
    // even an empty padded chiplet still reports its extension width.
    let airs = ChipletAir::all();
    println!();
    println!("trace heights  (cols = base + extension):");
    for ((name, m), air) in std::iter::zip(std::iter::zip(names, mains), airs) {
        let (base, ext) = (m.width(), air.aux_width());
        println!(
            "  {name} {:>8} rows × {base:>3} base + {ext:>2} ext = {:>3} cols",
            m.height(),
            base + ext,
        );
    }
    println!();
    println!("trace gen        : {gen_elapsed:?}");

    // ------ per-chiplet sanity (catch local-constraint regressions
    // before the more opaque prove failure) ----------------------------
    traces.check();
    println!("per-chiplet check : ok");

    // ------ prove ------------------------------------------------------
    let prove_start = Instant::now();
    let proof = traces.prove();
    let prove_elapsed = prove_start.elapsed();
    let ops_per_s = (n_mul + n_add) as f64 / prove_elapsed.as_secs_f64();
    println!("prove_multi      : {prove_elapsed:?}");
    println!("uint throughput  : {ops_per_s:.1} relation ops/s ({n_mul} mul + {n_add} add)");

    // ------ verify -----------------------------------------------------
    let verify_start = Instant::now();
    let verify_result = proof.verify();
    let verify_elapsed = verify_start.elapsed();

    println!();
    println!("public root      : {:?}", public_root.as_array());
    println!();

    match verify_result {
        Ok(()) => {
            println!("verify_multi     : {verify_elapsed:?}");
            println!("✓ prove+verify roundtrip OK");
        },
        Err(err) => {
            println!("verify_multi     : {verify_elapsed:?} → {err:?}");
            println!();
            println!("⚠ verify failed. On `InvalidReducedAux` the cross-chiplet bus");
            println!("  identity (Σ σ = 0) didn't close — sum miden-air's");
            println!("  `check_trace_balance` net multiplicities per encoded denom");
            println!("  across all chiplets to localize the unmatched tuple.");
        },
    }

    println!();
    println!("note: prove/verify timings are preliminary, not final-perf numbers —");
    println!("  • fixed tables (BytePairLut, …) are re-committed every proof: the");
    println!("    0.26 preprocessed-column path is unused pending the soundness flip;");
    println!("  • per-AIR quotient degrees are native under 0.26, but the shared");
    println!("    quotient commitment still upsamples each AIR to the max constraint");
    println!("    degree (see docs/forward-looking.md).");
    println!("  Both inflate prove time.");
}
