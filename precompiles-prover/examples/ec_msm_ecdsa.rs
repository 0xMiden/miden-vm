//! EcMsm bench: prove **N** 2-base multi-scalar multiplications
//! `R = u₁·G + u₂·Q` on secp256k1 — the ECDSA-verification shape — batched
//! into one proof. Each is built in the transcript EcMsm chiplet by
//! **Shamir's trick** (joint double-and-add over a 4-entry table
//! `{∞, G, Q, G+Q}`) and resolved in-circuit; the N claims fold into one
//! transcript root, exactly as `bench_keccak_n` batches N Keccaks.
//!
//! Usage: `cargo run --release --example ec_msm_ecdsa -- [N] [bits] [strategy] [seed]`
//!
//! Defaults: `N=4`, `bits=255` (full-size scalars), `strategy=straus`,
//! `seed=0xEC5DA`. `strategy` ∈ {`straus`, `joint_naf`, `wnaf`, `glv`} selects
//! the addition-chain heuristic — run them to compare EC/uint trace heights
//! and prove time. The two joint strategies build one interleaved table per
//! signature; `wnaf` instead lays `u₁·G` and `u₂·Q` as **separate**
//! windowed-NAF scalar-muls and precomputes `G`'s odd-multiple table **once**
//! for the whole batch (its `2^{w-2}` combines amortize across all N).
//! `glv` uses the secp256k1 endomorphism to recast each `uᵢ·Pᵢ` as a 2-term
//! split `kᵢₐ·Pᵢ + kᵢᵦ·φ(Pᵢ)`, so the whole verification becomes a **4-base
//! ~128-bit** joint MSM — ~half the doublings of the 256-bit form, the
//! doubling floor a joint 2-base ladder otherwise hits. The halves come from
//! a real lattice reduction, so they are **signed**: each sign rides its base
//! via `ec_neg` (`|k|·(−P) = (−|k|)·P`), keeping the four MSM scalars
//! non-negative ~128-bit magnitudes — which is what actually caps the ladder
//! near 128 (a non-negative-only split would need the 256-bit `mod n`
//! representative, no win). `glv` is sound, not a shortcut: each `φ(P)` is
//! certified in-circuit (`x_{φP} = β·x_P mod p`, on-curve via `EcCreate`) and
//! each signed split is checked (`uᵢ ≡ ±kᵢₐ + (±kᵢᵦ)·λ mod n`). The generator
//! `G` (and, for `glv`, the fixed `φ(G)`) dedups across all N regardless.
//!
//! The prover lays an arbitrary addition chain in the chiplet — here
//! Shamir — and the AIR checks only that each `combine` is sound (values
//! add via `EcGroupAdd`, shared-base scalars merge via `UintAdd`, and the
//! strict pointer order grounds the induction). The final expression is
//! then **resolved in-circuit**: the eval `EcMsm` node hashes the claim's
//! `(Pᵢ, sᵢ)` terms as a chaining sponge, binds the chain's value point,
//! and an `Is` ties it to `R` — so `R = u₁·G + u₂·Q` enters the transcript
//! root. (`R` is also cross-checked against the RustCrypto `k256`
//! reference off-circuit as a sanity guard.)
//!
//! Reports trace heights, prove + verify wall-time. Timings are
//! preliminary (fixed tables not yet committed as preprocessed columns;
//! the shared quotient commit upsamples to the max constraint degree —
//! see `docs/forward-looking.md`).

use std::time::Instant;

use k256::FieldBytes;
use k256::ProjectivePoint;
use k256::Scalar;
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use miden_lifted_air::LiftedAir;
use p3_matrix::Matrix;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use precompile_experiments::math::{U256, U512, U576, from_hex};
use precompile_experiments::session::strategies::{
    WnafTable, joint_naf, joint_wnaf, straus, wnaf_msm, wnaf_table,
};
use precompile_experiments::session::{ChipletAir, EcNode, Session, Truthy, UintNode};

const FP: u32 = 1;
const A_PTR: u32 = 2;
const B_PTR: u32 = 3;
/// The scalar-field modulus slot — the curve order `n`, distinct from the
/// coordinate field `p` at [`FP`]. MSM scalars route under `n` (a real
/// secp256k1: `n ≠ p`); [`Session::constrain_scalar_bound`] points the
/// group's scalars here.
const SN_PTR: u32 = 4;
/// wNAF window for the `wnaf` strategy (digits odd, `|d| < 2^{w-1}`; the
/// table is `2^{w-2}` odd multiples per base).
const WNAF_W: usize = 5;
/// Window for GLV's interleaved wNAF chain. `w = 4` (digits `{±1,±3,±5,±7}`)
/// minimizes the *adds* across the four ~128-bit halves: ~`1/5` digit density
/// vs Straus's ~`15/16` columns, the tables (`2^{w-2} = 4` odds/base) still
/// cheap.
const GLV_W: usize = 4;

/// secp256k1 GLV scalar `λ` (`λ³ ≡ 1 mod n`). The endomorphism
/// `φ(x, y) = (β·x, y)` is multiplication-by-`λ`, so `k·P = k₁·P + k₂·φ(P)`
/// with `k₁, k₂` ≈ half-width — turning a 256-bit 2-base MSM into a 128-bit
/// **4-base** one and ~halving the (shared) doublings.
const LAMBDA: &str = "5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72";
/// secp256k1 GLV constant `β` (`β³ ≡ 1 mod p`) — the endomorphism's
/// coordinate twist: `φ(x, y) = (β·x mod p, y)`. The in-circuit `β·x`
/// (a `UintMul` under the coordinate field) is the endomorphism cert.
const BETA: &str = "7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee";
/// secp256k1 group order minus one (`n − 1`) — the stored scalar-field
/// modulus pinned at [`SN_PTR`].
const N_MINUS_1: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
/// GLV scalar-piece width: each `kᵢ` splits into two ~128-bit halves.
const GLV_BITS: usize = 128;

fn be(bytes: impl AsRef<[u8]>) -> U256 {
    let hex: String = bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    from_hex(&hex)
}

fn coords(p: &ProjectivePoint) -> (U256, U256) {
    let enc = p.to_affine().to_encoded_point(false);
    (
        be(enc.x().expect("finite point")),
        be(enc.y().expect("finite point")),
    )
}

/// A `bits`-bit scalar (`bits ≤ 255`, so always `< n`), top bit forced.
fn scalar(rng: &mut impl Rng, bits: usize) -> U256 {
    let limbs: [u64; 4] = core::array::from_fn(|_| rng.random());
    let mask = (U256::from(1u64) << bits) - U256::from(1u64);
    (U256::from_limbs(limbs) & mask) | (U256::from(1u64) << (bits - 1))
}

fn create(s: &mut Session, p: &ProjectivePoint) -> EcNode {
    let (x, y) = coords(p);
    let xn = s.uint_leaf(x, FP);
    let yn = s.uint_leaf(y, FP);
    s.ec_create(A_PTR, B_PTR, &xn, &yn)
}

/// Create the endomorphism image `φ(P) = (β·x_P mod p, y_P)` as a curve
/// node, **certified in-circuit** rather than trusted: its x-coordinate is
/// bound to `β·x_P` by a `UintMul` under the coordinate field `p` (`beta_p`
/// is `β` interned there), its y reuses `P`'s, and `EcCreate` proves the
/// result on-curve. Since the secp256k1 endomorphism is exactly the map
/// `(x, y) ↦ (β·x, y) = [λ]`, these together pin `φ(P) = λ·P` — so the MSM's
/// `φ`-bases are sound without trusting an off-circuit `λ·P`.
fn create_phi(s: &mut Session, beta_p: &UintNode, p: &ProjectivePoint) -> EcNode {
    let (x, y) = coords(p);
    let xn = s.uint_leaf(x, FP);
    let yn = s.uint_leaf(y, FP);
    let phi_x = s.uint_mul(beta_p, &xn); // β·x_P mod p — the endomorphism cert
    s.ec_create(A_PTR, B_PTR, &phi_x, &yn)
}

/// A k256 scalar from a `U256` (which must be `< n`).
fn to_scalar(k: U256) -> Scalar {
    Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(k.to_be_bytes::<32>())))
        .expect("scalar < n")
}

/// The addition-chain strategy each MSM is laid with — selectable on the
/// command line. Both prove the *same* claim by different chains, so the EC
/// / uint trace heights differ: a direct comparison of the heuristics.
#[derive(Clone, Copy)]
enum Strategy {
    /// Unsigned joint double-and-add over `{∞, G, Q, G+Q}`.
    Straus,
    /// Signed joint double-and-add over `{±G, ±Q, ±(G±Q)}` (NAF digits,
    /// negatives via `neg` nodes) — sparser columns, fewer additions.
    JointNaf,
    /// **Separate** per-base wNAF: `u₁·G` and `u₂·Q` are each laid by their
    /// own windowed-NAF double-and-add over a precomputed odd-multiple table,
    /// then combined. `G`'s table is built **once** and reused across all N
    /// signatures (the win of the two-stage [`wnaf_table`] / `wnaf_scalarmul`
    /// split); only each fresh `Q`'s table is per-instance.
    Wnaf,
    /// **GLV**: decompose each `uᵢ·Pᵢ` via the endomorphism into
    /// `kᵢₐ·Pᵢ + kᵢᵦ·φ(Pᵢ)` with **signed** `~128-bit` halves (a real lattice
    /// reduction), routing each sign onto its base with `ec_neg` so the four
    /// scalars are non-negative ~128-bit magnitudes; then lay the resulting
    /// **4-base** MSM by joint Straus — ~half the doublings of the 256-bit
    /// 2-base form (the four bases share each doubling). `φ(G)` is fixed, so it
    /// (like `G`) is created once and shared across the batch.
    Glv,
}

impl Strategy {
    fn parse(s: &str) -> Self {
        match s {
            "naf" | "joint_naf" | "jsf" => Strategy::JointNaf,
            "wnaf" => Strategy::Wnaf,
            "glv" => Strategy::Glv,
            _ => Strategy::Straus,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Strategy::Straus => "straus",
            Strategy::JointNaf => "joint_naf",
            Strategy::Wnaf => "wnaf",
            Strategy::Glv => "glv",
        }
    }
}

/// Build + resolve one ECDSA-shape verification `R = u₁·G + u₂·Q`,
/// returning its in-circuit claim, laying the addition chain with the
/// chosen `strat`. Draws a fresh public key `Q` and scalars `u₁, u₂` from
/// `seed`. The generator node `g_pt` is created once by the caller and
/// shared across all N (its `EcCreate` dedups anyway); for `wnaf`, `g_table`
/// is `G`'s precomputed odd-multiple table — built once, reused every call.
fn verify_signature(
    s: &mut Session,
    g: ProjectivePoint,
    g_pt: &EcNode,
    g_table: Option<&WnafTable>,
    bits: usize,
    seed: u64,
    strat: Strategy,
) -> Truthy {
    let mut rng = StdRng::seed_from_u64(seed);
    let q = g * to_scalar(scalar(&mut rng, 255)); // a real pubkey Q = q·G
    let (u1, u2) = (scalar(&mut rng, bits), scalar(&mut rng, bits));
    let r_ref = g * to_scalar(u1) + q * to_scalar(u2); // k256 R = u₁·G + u₂·Q
    let (rx, ry) = coords(&r_ref);

    let q_pt = create(s, &q);

    // Lay the addition chain with the chosen packaged strategy. Swap in your
    // own — the chiplet only checks the chain is sound, not which one it is.
    let acc = match strat {
        Strategy::Straus => straus(s, &[(*g_pt, u1), (q_pt, u2)]),
        Strategy::JointNaf => joint_naf(s, &[(*g_pt, u1), (q_pt, u2)]),
        Strategy::Wnaf => {
            // Separate per-base wNAF: `G`'s table is the shared one (built
            // once); only this signature's fresh `Q` pays a new table.
            let q_table = wnaf_table(s, &q_pt, WNAF_W);
            wnaf_msm(
                s,
                &[
                    (g_table.expect("the wnaf strategy needs G's table"), u1),
                    (&q_table, u2),
                ],
            )
        }
        Strategy::Glv => unreachable!("glv is routed to verify_signature_glv"),
    };

    // Off-circuit sanity (the in-circuit resolve below proves it for real).
    let (vx, vy) = s.msm_value_coords(acc);
    assert_eq!((vx, vy), (rx, ry), "EcMsm result must match k256 R");

    // In-circuit resolve: the eval EcMsm node hashes the claim's terms
    // (G×u₁, Q×u₂), binds its value point; the Is ties it to R. The scalars
    // route under the group's scalar bound `n` (set in `main`), not `p`.
    let u1_node = s.uint_leaf(u1, SN_PTR);
    let u2_node = s.uint_leaf(u2, SN_PTR);
    let r_pt = create(s, &r_ref);
    let value = s.ec_msm(acc, &[(*g_pt, u1_node), (q_pt, u2_node)]);
    s.ec_is(&value, &r_pt)
}

/// A sign-magnitude integer over [`U512`] — the GLV lattice arithmetic
/// (products of ~256-bit operands) overflows [`U256`]. Magnitude `0` is
/// normalized non-negative.
#[derive(Clone, Copy)]
struct Signed {
    neg: bool,
    mag: U512,
}

impl Signed {
    fn new(neg: bool, mag: U512) -> Self {
        Self {
            neg: neg && mag != U512::ZERO,
            mag,
        }
    }
    fn from_u256(v: U256) -> Self {
        Self::new(false, U512::from(v))
    }
    fn negate(self) -> Self {
        Self::new(!self.neg, self.mag)
    }
    fn add(self, o: Self) -> Self {
        if self.neg == o.neg {
            Self::new(self.neg, self.mag + o.mag)
        } else if self.mag >= o.mag {
            Self::new(self.neg, self.mag - o.mag)
        } else {
            Self::new(o.neg, o.mag - self.mag)
        }
    }
    fn sub(self, o: Self) -> Self {
        self.add(o.negate())
    }
    fn mul(self, o: Self) -> Self {
        Self::new(self.neg ^ o.neg, self.mag * o.mag)
    }
    /// `round(self / d)` for `d > 0` (round half up on the magnitude).
    fn div_round(self, d: U512) -> Self {
        Self::new(self.neg, (self.mag + (d >> 1)) / d)
    }
    /// `(sign, magnitude-as-U256)` — the magnitude must fit (it does for the
    /// ~128-bit decomposition outputs).
    fn split(self) -> (bool, U256) {
        let l = self.mag.as_limbs();
        (self.neg, U256::from_limbs([l[0], l[1], l[2], l[3]]))
    }
}

/// GLV decomposition: split `k ∈ [0, n)` into a **signed** short pair
/// `[(s_a, m_a), (s_b, m_b)]` with `k ≡ ±m_a + (±m_b)·λ (mod n)` and
/// `m_a, m_b ≲ √n` (~128 bits). The short basis of the GLV lattice
/// `{(x, y) : x + yλ ≡ 0 (mod n)}` is computed from `(n, λ)` by the half
/// extended-Euclid (no hard-coded curve constants), then one Babai rounding
/// step gives the remainder. (Hankerson–Menezes–Vanstone, Alg. 3.74.)
/// Off-circuit + untrusted — the in-circuit split cert re-checks it.
fn glv_decompose(k: U256, lambda: U256, n: U256) -> [(bool, U256); 2] {
    let n_wide = U512::from(n);
    let below_sqrt_n = |r: U512| r * r < n_wide; // r < √n
    // Half extended-Euclid: keep (r, t) with r ≡ t·λ (mod n); stop at the
    // first remainder below √n.
    let (mut r0, mut r1) = (U512::from(n), U512::from(lambda));
    let (mut t0, mut t1) = (
        Signed::from_u256(U256::ZERO),
        Signed::from_u256(U256::from(1u64)),
    );
    while !below_sqrt_n(r1) {
        let q = r0 / r1;
        let (r2, t2) = (r0 - q * r1, t0.sub(Signed::new(false, q).mul(t1)));
        (r0, r1, t0, t1) = (r1, r2, t1, t2);
    }
    // (a1, b1) = (r_{ℓ+1}, −t_{ℓ+1}); for (a2, b2) take the shorter of
    // (r_ℓ, −t_ℓ) and (r_{ℓ+2}, −t_{ℓ+2}).
    let (a1, b1) = (Signed::new(false, r1), t1.negate());
    let q = r0 / r1;
    let (r2, t2) = (r0 - q * r1, t0.sub(Signed::new(false, q).mul(t1)));
    let widen = |v: U512| {
        let l = v.as_limbs();
        U576::from_limbs([l[0], l[1], l[2], l[3], l[4], l[5], l[6], l[7], 0])
    };
    let norm = |r: U512, t: U512| widen(r) * widen(r) + widen(t) * widen(t);
    let (a2, b2) = if norm(r0, t0.mag) <= norm(r2, t2.mag) {
        (Signed::new(false, r0), t0.negate())
    } else {
        (Signed::new(false, r2), t2.negate())
    };
    // Babai: c1 = round(b2·k/n), c2 = round(−b1·k/n); the short remainder is
    // k1 = k − c1·a1 − c2·a2,  k2 = −c1·b1 − c2·b2.
    let k_s = Signed::from_u256(k);
    let c1 = b2.mul(k_s).div_round(n_wide);
    let c2 = b1.negate().mul(k_s).div_round(n_wide);
    let k1 = k_s.sub(c1.mul(a1)).sub(c2.mul(a2));
    let k2 = c1.negate().mul(b1).sub(c2.mul(b2));
    [k1.split(), k2.split()]
}

/// A k256 scalar from a signed magnitude (`mag < n`), negated in the field
/// when the sign is set.
fn signed_to_scalar((neg, mag): (bool, U256)) -> Scalar {
    let s = to_scalar(mag);
    if neg { -s } else { s }
}

/// A uniform scalar in `[0, n)` (full-width — a realistic ECDSA `uᵢ`).
fn rand_scalar(rng: &mut impl Rng, n: U256) -> U256 {
    let limbs: [u64; 4] = core::array::from_fn(|_| rng.random());
    U256::from_limbs(limbs) % n
}

/// `âⱼ = ±|halfⱼ| (mod n)` for a split term: `uint_neg(|half|)` when the half
/// is negative, mirroring its `ec_neg`'d MSM base; the magnitude node itself
/// otherwise. Same node the MSM consumed, so the signed split binds the chain.
fn signed_hat(s: &mut Session, neg: bool, mag: &UintNode) -> UintNode {
    if neg { s.uint_neg(mag) } else { *mag }
}

/// Build + resolve one ECDSA-shape verification via **GLV**, *fully
/// certified in-circuit*: the 4-base ~128-bit MSM
/// `k₁ₐ·G + k₁ᵦ·φ(G) + k₂ₐ·Q + k₂ᵦ·φ(Q)` (laid by joint Straus), plus the
/// soundness claims that make it an honest `R = u₁·G + u₂·Q` rather than an
/// arbitrary 4-base sum:
///
/// 1. **Endomorphism.** Each `φ(P)` base is built by [`create_phi`]: its
///    x-coordinate is bound to `β·x_P mod p` (a `UintMul`) and `EcCreate`
///    proves it on-curve — so `φ(P) = λ·P` is enforced, not trusted.
/// 2. **Split.** `uᵢ ≡ k_iₐ + k_iᵦ·λ (mod n)` is checked by `UintMul` +
///    `UintAdd` + `Is` over the scalar field `n`, on the *same* scalar nodes
///    the MSM consumes.
///
/// Unlike a generated split, the halves come from a real [`glv_decompose`]
/// of each full `uᵢ`, so they are **signed**. The sign rides the *base* via
/// [`ec_neg`](Session::ec_neg) — `|k|·(−P) = (−|k|)·P` — leaving the four MSM
/// scalars as non-negative ~128-bit magnitudes, which is what actually caps
/// the joint ladder near 128 doublings (a non-negative-only split would need
/// the full 256-bit `mod n` representative). The split cert mirrors each
/// negated base with a `uint_neg` on its `âⱼ`. All scalars route under the
/// group's scalar bound `n` (set in `main`). `g_pt` / `phi_g_pt` + `β`/`λ` are
/// shared; only `Q` / `φ(Q)` are per-signature. Returns the MSM claim plus the
/// two split certs (all folded into the root).
fn verify_signature_glv(
    s: &mut Session,
    g: ProjectivePoint,
    g_pt: &EcNode,
    phi_g_pt: &EcNode,
    beta_p: &UintNode,
    lambda_n: &UintNode,
    seed: u64,
) -> Vec<Truthy> {
    let mut rng = StdRng::seed_from_u64(seed);
    let lambda_u = from_hex(LAMBDA);
    let lambda = to_scalar(lambda_u);
    let n = from_hex(N_MINUS_1) + U256::from(1u64);

    // A real pubkey Q and two real full-width ECDSA scalars u₁, u₂ ∈ [0, n).
    let q = g * to_scalar(rand_scalar(&mut rng, n));
    let (u1, u2) = (rand_scalar(&mut rng, n), rand_scalar(&mut rng, n));
    let q_pt = create(s, &q);
    // φ(Q) certified in-circuit: x_{φQ} = β·x_Q mod p, on-curve ⇒ φ(Q) = λ·Q.
    let phi_q_pt = create_phi(s, beta_p, &q);

    // Real GLV reduction of each scalar → a SIGNED ~128-bit pair (k_iₐ, k_iᵦ).
    let [k1a, k1b] = glv_decompose(u1, lambda_u, n);
    let [k2a, k2b] = glv_decompose(u2, lambda_u, n);
    // Off-circuit sanity: each pair recomposes its scalar, and the magnitudes
    // stay ~128-bit — so the joint ladder is ~128 doublings, not 256.
    assert_eq!(
        signed_to_scalar(k1a) + lambda * signed_to_scalar(k1b),
        to_scalar(u1),
        "GLV decomposition of u₁ must recompose",
    );
    assert_eq!(
        signed_to_scalar(k2a) + lambda * signed_to_scalar(k2b),
        to_scalar(u2),
        "GLV decomposition of u₂ must recompose",
    );
    let bound = U256::from(1u64) << (GLV_BITS + 2); // √n basis is ≤ ~129 bits
    for (_, m) in [k1a, k1b, k2a, k2b] {
        assert!(
            m < bound,
            "GLV half exceeds the ~{}-bit ladder bound",
            GLV_BITS
        );
    }
    // Show the signed ~128-bit halves — the `−` ones are routed through ec_neg;
    // the max bit-width is the joint ladder's doubling count (vs 256 unsplit).
    let bits = |(_, m): (bool, U256)| 256 - m.leading_zeros();
    let sign = |(neg, _): (bool, U256)| if neg { '−' } else { '+' };
    println!(
        "  glv: u₁→({}{}b·G, {}{}b·φG)  u₂→({}{}b·Q, {}{}b·φQ)  ⇒ {}-bit ladder",
        sign(k1a),
        bits(k1a),
        sign(k1b),
        bits(k1b),
        sign(k2a),
        bits(k2a),
        sign(k2b),
        bits(k2b),
        [k1a, k1b, k2a, k2b].iter().map(|&h| bits(h)).max().unwrap(),
    );

    // The sign of each half rides the BASE via ec_neg (`|k|·(−P) = (−|k|)·P`),
    // so the four MSM scalars are non-negative ~128-bit magnitudes — this is
    // what caps the doublings near 128. The negated bases are distinct points,
    // so the 4-base claim stays canonical.
    let base_g = if k1a.0 { s.ec_neg(g_pt) } else { *g_pt };
    let base_pg = if k1b.0 { s.ec_neg(phi_g_pt) } else { *phi_g_pt };
    let base_q = if k2a.0 { s.ec_neg(&q_pt) } else { q_pt };
    let base_pq = if k2b.0 { s.ec_neg(&phi_q_pt) } else { phi_q_pt };

    // r_ref = u₁·G + u₂·Q — the real verification target.
    let r_ref = g * to_scalar(u1) + q * to_scalar(u2);
    let (rx, ry) = coords(&r_ref);

    // 4-base interleaved wNAF (w=4) over the 128-bit magnitudes: the four
    // signed bases share each doubling (~128), and the sparse wNAF digits cut
    // the adds well below Straus's ~one-per-column — the real lever now that
    // GLV has already halved the doublings.
    let acc = joint_wnaf(
        s,
        &[
            (base_g, k1a.1),
            (base_pg, k1b.1),
            (base_q, k2a.1),
            (base_pq, k2b.1),
        ],
        GLV_W,
    );
    let (vx, vy) = s.msm_value_coords(acc);
    assert_eq!((vx, vy), (rx, ry), "GLV 4-term MSM must match k256 R");

    // Magnitude nodes under `n` — reused by the MSM terms and the split certs.
    let m1a = s.uint_leaf(k1a.1, SN_PTR);
    let m1b = s.uint_leaf(k1b.1, SN_PTR);
    let m2a = s.uint_leaf(k2a.1, SN_PTR);
    let m2b = s.uint_leaf(k2b.1, SN_PTR);
    let r_pt = create(s, &r_ref);
    let value = s.ec_msm(
        acc,
        &[(base_g, m1a), (base_pg, m1b), (base_q, m2a), (base_pq, m2b)],
    );
    let msm_claim = s.ec_is(&value, &r_pt);

    // Split certs: uᵢ ≡ âₐ + âᵦ·λ (mod n), âⱼ = ±|kⱼ| (uint_neg for a negative
    // half, mirroring its ec_neg'd base), on the SAME magnitude nodes the MSM
    // consumed — tying the signed split to the chain.
    let u1_n = s.uint_leaf(u1, SN_PTR);
    let u2_n = s.uint_leaf(u2, SN_PTR);
    let split1 = {
        let a_hat = signed_hat(s, k1a.0, &m1a);
        let b_hat = signed_hat(s, k1b.0, &m1b);
        let prod = s.uint_mul(&b_hat, lambda_n); // âᵦ·λ mod n
        let sum = s.uint_add(&a_hat, &prod); // âₐ + âᵦ·λ mod n
        s.uint_is(&sum, &u1_n)
    };
    let split2 = {
        let a_hat = signed_hat(s, k2a.0, &m2a);
        let b_hat = signed_hat(s, k2b.0, &m2b);
        let prod = s.uint_mul(&b_hat, lambda_n);
        let sum = s.uint_add(&a_hat, &prod);
        s.uint_is(&sum, &u2_n)
    };

    vec![msm_claim, split1, split2]
}

fn main() {
    // `PROFILE=1` installs a span timer (stderr) so the prover's phase
    // breakdown — `evaluate constraints` (ext eval) vs `commit *` (LDE +
    // Merkle hash) vs `open` (FRI) — is visible. Research only.
    if std::env::var("PROFILE").is_ok() {
        use tracing_subscriber::fmt::format::FmtSpan;
        let level = if std::env::var("PROFILE_DEBUG").is_ok() {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        };
        tracing_subscriber::fmt()
            .with_max_level(level)
            .with_span_events(FmtSpan::CLOSE)
            .with_writer(std::io::stderr)
            .init();
    }

    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);
    let bits: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(255);
    let strat = Strategy::parse(&std::env::args().nth(3).unwrap_or_default());
    let seed: u64 = std::env::args()
        .nth(4)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0xEC5DA);
    assert!(n >= 1, "N >= 1");
    assert!((1..=255).contains(&bits), "bits in 1..=255");

    let p_minus_1 = from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E");
    let g = ProjectivePoint::GENERATOR;

    println!("=================================================");
    println!("ec_msm_ecdsa: prove {n} × (R = u1*G + u2*Q) on secp256k1");
    println!(
        "  {bits}-bit scalars, seed 0x{seed:X}, strategy: {}",
        strat.name(),
    );
    println!("=================================================");

    let gen_start = Instant::now();
    let mut session = Session::new();
    let mut claims = vec![
        session.pin_uint(FP, p_minus_1, FP),
        session.pin_uint(A_PTR, from_hex("0"), FP),
        session.pin_uint(B_PTR, from_hex("7"), FP),
        // The scalar field `n` (self-referential modulus): MSM scalars route
        // under it on every strategy.
        session.pin_uint(SN_PTR, from_hex(N_MINUS_1), SN_PTR),
    ];

    // Create the generator node once (shared across all N — its EcCreate
    // dedups anyway). For `wnaf`, precompute G's odd-multiple table once; for
    // `glv`, the shared β/λ constants + the fixed φ(G) base. All are shared
    // across every signature (only each fresh Q pays its own).
    let g_pt = create(&mut session, &g);
    // Route this group's MSM scalars under the curve order `n` (not the coord
    // field `p`) — universally, for every strategy (`n ≠ p` on secp256k1).
    session.constrain_scalar_bound(&g_pt, SN_PTR);
    let g_table = matches!(strat, Strategy::Wnaf).then(|| wnaf_table(&mut session, &g_pt, WNAF_W));
    // GLV shared setup: `β` (coordinate field) and `λ` (scalar field)
    // constants, plus the certified fixed base `φ(G) = λ·G` — `create_phi`
    // binds `x_{φG} = β·x_G mod p` and proves it on-curve, so φ(G) is sound
    // without trusting an off-circuit `λ·G`.
    let glv = matches!(strat, Strategy::Glv).then(|| {
        let lambda = to_scalar(from_hex(LAMBDA));
        assert_eq!(
            lambda * lambda * lambda,
            to_scalar(from_hex("1")),
            "λ must be an order-3 scalar (λ³ ≡ 1 mod n)",
        );
        let beta_p = session.uint_leaf(from_hex(BETA), FP);
        let lambda_n = session.uint_leaf(from_hex(LAMBDA), SN_PTR);
        let phi_g_pt = create_phi(&mut session, &beta_p, &g);
        (beta_p, lambda_n, phi_g_pt)
    });

    // Each signature draws a fresh pubkey + scalars, lays its own chain
    // (the selected strategy), and resolves in-circuit; all N claims fold
    // into one root.
    for k in 0..n {
        let sig_seed = seed ^ (k as u64).wrapping_mul(0x9E3779B97F4A7C15);
        match strat {
            Strategy::Glv => {
                let (beta_p, lambda_n, phi_g_pt) = glv.as_ref().expect("glv sets up shared bases");
                // The MSM claim + the two GLV split certs all fold into the root.
                claims.extend(verify_signature_glv(
                    &mut session,
                    g,
                    &g_pt,
                    phi_g_pt,
                    beta_p,
                    lambda_n,
                    sig_seed,
                ));
            }
            _ => claims.push(verify_signature(
                &mut session,
                g,
                &g_pt,
                g_table.as_ref(),
                bits,
                sig_seed,
                strat,
            )),
        }
    }
    println!("✓ {n} ECDSA-shape MSM claims resolved in-circuit (k256-matched)");
    println!(
        "  chain cost: {} MSM expressions (intros + combines + negs)",
        session.msm_expr_count(),
    );

    let root = session.assert_and_fold(claims);
    let traces = session.finish(root);
    let mains = traces.mains();
    let gen_elapsed = gen_start.elapsed();

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
        "ec_msm   ",
    ];
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

    traces.check();
    println!("per-chiplet check : ok");

    let prove_start = Instant::now();
    let proof = traces.prove();
    let prove_elapsed = prove_start.elapsed();
    println!("prove_multi      : {prove_elapsed:?}");

    let verify_start = Instant::now();
    let verify_result = proof.verify();
    let verify_elapsed = verify_start.elapsed();
    println!();
    match verify_result {
        Ok(()) => {
            println!("verify_multi     : {verify_elapsed:?}");
            println!(
                "✓ prove+verify OK — proved {n} × 2-base MSM ({}) on secp256k1",
                strat.name(),
            );
        }
        Err(err) => println!("verify_multi     : {verify_elapsed:?} → {err:?}"),
    }
}
