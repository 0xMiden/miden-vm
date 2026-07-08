//! EC multi-scalar bench: prove **N** scalar multiplications `kᵢ·G` on
//! secp256k1 in a single proof, with **full-size 256-bit scalars**.
//!
//! Usage: `cargo run --release --example ec_scalar_mul -- [N] [seed]`
//!
//! Defaults: `N=8` instances, `seed=0xEC`.
//!
//! Each `kᵢ·G` is computed in the transcript EC DAG by double-and-add
//! (seeded at the top set bit) and cross-checked against the RustCrypto
//! `k256` reference via `ec_is` inside the statement — a wrong result
//! panics at trace-gen.
//!
//! The scalars are **seeded-pseudorandom and distinct** on purpose: the
//! DAG dedups by relation identity, so identical or structured scalars
//! would collapse the instances (sharing whole chains) and the bench
//! would prove fewer than `N`. Random 256-bit scalars diverge after the
//! top bit, so only the shared base `G` and the first doubling (`2G`)
//! amortize — the recorded EcGroupAdd blocks track the naive op count,
//! and the run is `N` genuinely-independent scalar muls.
//!
//! Reports trace heights, prove + verify wall-time, and EC ops/sec. As
//! with the uint bench the timings are preliminary (fixed tables not yet
//! committed as preprocessed columns; the shared quotient commit upsamples
//! to the max constraint degree — see `docs/forward-looking.md`).

use std::time::Instant;

use k256::{
    FieldBytes, ProjectivePoint, Scalar,
    elliptic_curve::{PrimeField, sec1::ToEncodedPoint},
};
use miden_core::utils::Matrix;
use miden_lifted_air::LiftedAir;
use miden_precompiles::CurveId;
use miden_precompiles_prover::{
    math::{U256, from_hex},
    session::{ChipletAir, EcNode, Session, verify_deferred},
};
use rand::{Rng, RngExt, SeedableRng, rngs::StdRng};

/// secp256k1 VM-owned uint/group pointers.
const FP: u32 = CurveId::Secp256k1.base_domain().bound_ptr();
const GROUP_PTR: u32 = CurveId::Secp256k1.group_ptr();

/// Big-endian field bytes → our `U256` (the KAT hex path).
fn be(bytes: impl AsRef<[u8]>) -> U256 {
    let hex: String = bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    from_hex(&hex)
}

/// Affine coordinates of a finite k256 point as a `U256` pair.
fn coords(p: &ProjectivePoint) -> (U256, U256) {
    let enc = p.to_affine().to_encoded_point(false);
    (be(enc.x().expect("finite point")), be(enc.y().expect("finite point")))
}

/// A pseudorandom full-size scalar in `[2^255, n)`: the top bit is forced
/// (so it's a full 256-bit instance) and the value is kept below the
/// group order `n` by rejection — `n` is within `2^128` of `2^256`, so
/// rejections are vanishingly rare.
fn random_scalar(rng: &mut impl Rng, n: U256) -> U256 {
    loop {
        let mut limbs: [u64; 4] = core::array::from_fn(|_| rng.random());
        limbs[3] |= 1 << 63; // bit 255 → full width
        let k = U256::from_limbs(limbs);
        if k < n {
            return k;
        }
    }
}

/// `k·base` in the DAG by double-and-add (MSB→LSB, seeded at the top set
/// bit so there is no leading ∞). `k ≥ 1`.
fn scalar_mul(session: &mut Session, base: &EcNode, k: U256) -> EcNode {
    let bitlen = k.bit_len();
    let mut acc = *base; // top set bit
    for i in (0..bitlen - 1).rev() {
        acc = session.ec_add(&acc, &acc); // double
        if k.bit(i) {
            acc = session.ec_add(&acc, base); // add base
        }
    }
    acc
}

fn main() {
    let n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(8);
    let seed: u64 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(0xec);
    assert!(n >= 1, "need at least one instance");

    // secp256k1: y² = x³ + 7 over Fp, base point G, group order `order`.
    let order = from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    let g = ProjectivePoint::GENERATOR;
    let (gx, gy) = coords(&g);

    // Distinct pseudorandom full-size (256-bit) scalars: random scalars
    // diverge under double-and-add, so the DAG dedup can't collapse the N
    // instances into fewer.
    let mut rng = StdRng::seed_from_u64(seed);
    let scalars: Vec<U256> = (0..n).map(|_| random_scalar(&mut rng, order)).collect();
    let naive_ops: usize = scalars
        .iter()
        .map(|k| (k.bit_len() - 1) + (k.count_ones() - 1)) // doublings + adds
        .sum();

    println!("=================================================");
    println!("ec_scalar_mul: {n} scalar muls kᵢ·G on secp256k1 (seed 0x{seed:X})");
    println!("  256-bit scalars, ~{naive_ops} EC ops naive (255 dbl + popcount-1 add each)");
    println!("=================================================");

    // ------ trace generation -------------------------------------------
    let gen_start = Instant::now();

    let mut session = Session::new();
    let mut claims = Vec::with_capacity(n);

    // G as a shared EC-DAG node (the base, reused across all instances).
    let gx_n = session.uint_leaf(gx, FP);
    let gy_n = session.uint_leaf(gy, FP);
    let g_pt = session.ec_create(GROUP_PTR, &gx_n, &gy_n);

    for &k in &scalars {
        let acc = scalar_mul(&mut session, &g_pt, k);
        // Cross-check vs k256: acc must intern to k256's k·G ptr.
        let scalar: Scalar =
            Option::from(Scalar::from_repr(FieldBytes::from(k.to_be_bytes::<32>())))
                .expect("scalar < n");
        let (kgx, kgy) = coords(&(g * scalar));
        let kgx_n = session.uint_leaf(kgx, FP);
        let kgy_n = session.uint_leaf(kgy, FP);
        let expected = session.ec_create(GROUP_PTR, &kgx_n, &kgy_n);
        claims.push(session.ec_is(&acc, &expected)); // panics if k·G ≠ k256
    }

    let root = session.assert_and_fold(claims);
    let traces = session.finish(root);
    let public_root = traces.public_root();
    let mains = traces.mains();
    let gen_elapsed = gen_start.elapsed();

    println!("✓ all {n} results match k256 (every ec_is held at trace-gen)");

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
    println!();
    // Each chiplet commits `base` main columns plus `ext` extension-field
    // (QuadFelt) LogUp columns; `aux_width` is a static AIR property, so
    // even an empty padded chiplet still reports its extension width.
    let airs = ChipletAir::all();
    println!("trace heights  (cols = base + extension):");
    for ((name, m), air) in std::iter::zip(std::iter::zip(names, mains), airs) {
        let (base, ext) = (m.width(), air.aux_width());
        println!(
            "  {name} {:>8} rows × {base:>3} base + {ext:>2} ext = {:>3} cols",
            m.height(),
            base + ext,
        );
    }
    // ec_add lays one PERIOD=4-row block per *recorded* (deduped) add,
    // padded to a power of two. For random scalars dedup is minimal, so
    // the block capacity (height/4) brackets the naive op count — i.e.
    // the N instances really are independent.
    println!();
    println!(
        "EC ops (naive)   : {naive_ops} over {n} scalar muls  (ec_add trace {} rows)",
        mains[13].height(),
    );
    println!("trace gen        : {gen_elapsed:?}");

    // ------ per-chiplet sanity, then prove / verify --------------------
    traces.check();
    println!("per-chiplet check : ok");

    let prove_start = Instant::now();
    let proof = traces.prove();
    let prove_elapsed = prove_start.elapsed();
    let ops_per_s = naive_ops as f64 / prove_elapsed.as_secs_f64();
    println!("prove_multi      : {prove_elapsed:?}");
    println!("EC throughput    : {ops_per_s:.1} EC ops/s over {n} scalar muls");

    let verify_start = Instant::now();
    let verify_result = verify_deferred(&proof);
    let verify_elapsed = verify_start.elapsed();

    println!();
    println!("public root      : {:?}", public_root.as_array());
    println!();
    match verify_result {
        Ok(_) => {
            println!("verify_multi     : {verify_elapsed:?}");
            println!("✓ prove+verify roundtrip OK — proved {n} scalar muls on secp256k1");
        },
        Err(err) => println!("verify_multi     : {verify_elapsed:?} → {err:?}"),
    }
}
