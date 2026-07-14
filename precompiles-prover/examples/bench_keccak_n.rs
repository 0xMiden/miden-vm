//! End-to-end Keccak transcript bench: prove + verify N Keccaks of a
//! fixed input length, all stitched into one left-leaning transcript
//! eval tree that commits to a single public root.
//!
//! Usage: `cargo run --release --example bench_keccak_n -- [N] [L]`
//!
//! Defaults: `N=8` invocations of `L=32` bytes each.
//!
//! Wires the full eleven-chiplet stack:
//!   chunk · poseidon2 · keccak/round · bitwise64 · byte_pair_lut ·
//!   keccak/sponge · keccak/node · transcript/eval · uint-store ·
//!   uint-add · uint-mul (the uint chiplets lay empty padded traces in a
//!   keccak-only session)
//!
//! [`Session`] hides the cross-chiplet plumbing: each keccak yields a claim
//! handle, folded into one transcript root, and `SessionTraces::prove` /
//! `verify_deferred` run the whole round-trip.
//!
//! Reports trace heights, prove + verify wall-time, and the resulting
//! public root.
//!
//! The wall-times are preliminary, not final-perf numbers: fixed tables
//! aren't committed as preprocessed columns yet (the 0.26 path is unused
//! pending the soundness flip), and the shared quotient commitment
//! upsamples every AIR to the max constraint degree (per-AIR evaluation
//! is already native). Both inflate prove time.

use std::time::Instant;

use miden_core::utils::Matrix;
use miden_lifted_air::LiftedAir;
use miden_precompiles_prover::session::{ChipletAir, Session, verify_deferred};
use rand::{RngExt, SeedableRng, rngs::StdRng};

fn main() {
    // `PROFILE=1` installs a span timer (stderr) so the prover's phase
    // breakdown — `evaluate constraints` (ext eval) vs `commit *` (LDE +
    // Merkle hash) vs `open` (FRI) — is visible. Research only.
    if std::env::var("PROFILE").is_ok() {
        use tracing_subscriber::fmt::format::FmtSpan;
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_span_events(FmtSpan::CLOSE)
            .with_writer(std::io::stderr)
            .init();
    }

    let n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(8);
    let l: usize = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(32);

    // Both degenerate cases are supported: N = 0 (empty batch → the
    // all-dead, valid empty-transcript trace) and L = 0 (empty input →
    // keccak256("")).

    println!("================================================");
    println!("bench_keccak_n: N={n} invocations, L={l} bytes");
    println!("================================================");

    // ------ trace generation -------------------------------------------
    let gen_start = Instant::now();

    let mut session = Session::new();

    // Derive N distinct deterministic inputs from one seed; PRF the
    // bytes so adjacent indices don't accidentally collide. Each keccak
    // yields a claim handle; fold them into the transcript root.
    let seed = 0xc0ffee_decade_u64;
    let mut input = vec![0u8; l];
    let mut claims = Vec::with_capacity(n);
    for k in 0..n {
        let mut rng = StdRng::seed_from_u64(seed ^ (k as u64).wrapping_mul(0x9e3779b97f4a7c15));
        for b in &mut input {
            *b = rng.random();
        }
        let (_, claim) = session.keccak(&input);
        claims.push(claim);
    }
    let root = session.assert_and_fold(claims);

    let traces = session.finish(root);
    let public_root = traces.public_root();
    let mains = traces.mains();

    let gen_elapsed = gen_start.elapsed();

    // Names line up with `SessionTraces::mains()` canonical order (and
    // must match its length — `zip` would silently truncate the report).
    let names = [
        "chunk    ",
        "poseidon2",
        "round    ",
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
    println!("prove_multi      : {prove_elapsed:?}");

    // ------ verify -----------------------------------------------------
    let verify_start = Instant::now();
    let verify_result = verify_deferred(&proof);
    let verify_elapsed = verify_start.elapsed();

    println!();
    println!("public root      : {:?}", public_root.as_array());
    println!();

    match verify_result {
        Ok(_) => {
            println!("verify_multi     : {verify_elapsed:?}");
            println!("✓ prove+verify roundtrip OK");
        },
        Err(err) => {
            println!("verify_multi     : {verify_elapsed:?} → {err:?}");
            println!();
            println!("⚠ verify failed. On `InvalidReducedAux` the cross-chiplet bus");
            println!("  identity (Σ σ = 0) didn't close — sum miden-air's");
            println!("  `check_trace_balance` net multiplicities per encoded denom");
            println!("  across all chiplets (as `full_stack_bus_balance_closes` does)");
            println!("  to localize the unmatched (bus, payload) tuple.");
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
