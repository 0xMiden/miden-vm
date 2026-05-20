//! secp256k1 base- and scalar-field primes in u16 and u32 little-endian limb forms, plus the
//! GLV-decomposition constants (cube-root-of-unity multipliers in F_n and F_p, lattice basis).
//! Used by the SZ modmul and inverse handlers (`u256_modmul_k1`, `u256_inv_k1`), the GLV scalar
//! splitter (`glv_split_k1`), and the corresponding MASM modules. Each constant is defined once
//! here; the const-eval consistency check below pins the u16 and u32 prime forms to the same
//! integer.

/// secp256k1 base-field prime `p_k1 = 2^256 - 2^32 - 977` as 16 u16 limbs.
pub const SECP256K1_BASE_PRIME_U16: [u16; 16] = [
    0xfc2f, 0xffff, 0xfffe, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    0xffff, 0xffff, 0xffff, 0xffff,
];

/// `p_k1` packed as 8 u32 limbs.
pub const SECP256K1_BASE_PRIME_U32: [u32; 8] = [
    0xffff_fc2f,
    0xffff_fffe,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
];

/// secp256k1 scalar-field prime (group order)
/// `n_k1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141` as 16 u16 limbs.
pub const SECP256K1_SCALAR_PRIME_U16: [u16; 16] = [
    0x4141, 0xd036, 0x5e8c, 0xbfd2, 0xa03b, 0xaf48, 0xdce6, 0xbaae, 0xfffe, 0xffff, 0xffff, 0xffff,
    0xffff, 0xffff, 0xffff, 0xffff,
];

/// `n_k1` packed as 8 u32 limbs.
pub const SECP256K1_SCALAR_PRIME_U32: [u32; 8] = [
    0xd036_4141,
    0xbfd2_5e8c,
    0xaf48_a03b,
    0xbaae_dce6,
    0xffff_fffe,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
];

const _: () = {
    let mut i = 0;
    while i < 8 {
        let base_recombined = SECP256K1_BASE_PRIME_U16[2 * i] as u32
            | ((SECP256K1_BASE_PRIME_U16[2 * i + 1] as u32) << 16);
        assert!(
            base_recombined == SECP256K1_BASE_PRIME_U32[i],
            "SECP256K1_BASE_PRIME_U16 and SECP256K1_BASE_PRIME_U32 disagree"
        );
        let scalar_recombined = SECP256K1_SCALAR_PRIME_U16[2 * i] as u32
            | ((SECP256K1_SCALAR_PRIME_U16[2 * i + 1] as u32) << 16);
        assert!(
            scalar_recombined == SECP256K1_SCALAR_PRIME_U32[i],
            "SECP256K1_SCALAR_PRIME_U16 and SECP256K1_SCALAR_PRIME_U32 disagree"
        );
        i += 1;
    }
};

// GLV CONSTANTS
// ================================================================================================
//
// secp256k1 admits an efficient endomorphism `φ: (x, y) -> (β·x mod p, y)` whose action on
// the curve corresponds to scalar multiplication by `λ` modulo `n`, i.e. `φ(P) = [λ]P`. Both
// `β` and `λ` are primitive cube roots of unity (in F_p and F_n respectively); each prime
// has two such roots and we pick the canonical pair so that `φ(P) = [λ]P` holds with the
// signs documented below.
//
// GLV decomposition splits any 256-bit scalar `k` into a pair `(k_a, k_b)` of signed
// integers with `|k_a|, |k_b| < 2^128` such that `k ≡ k_a + k_b·λ (mod n)`. A scalar
// multiplication `[k]P` is then computed as `[k_a]P + [k_b]·φ(P)`, where each scalar in
// the multi-scalar mul has half the bit length of `k`. See Gallant, Lambert, Vanstone,
// "Faster Point Multiplication on Elliptic Curves with Efficient Endomorphisms" (CRYPTO
// 2001) for the technique, and Hankerson, Menezes, Vanstone, "Guide to Elliptic Curve
// Cryptography" (Springer, 2004) for the basis derivation via extended Euclidean reduction.

/// Cube root of unity in `F_n`: `λ ≡ φ` on the curve.
/// `λ = 0x5363ad4c c05c30e0 a5261c02 8812645a 122e22ea 20816678 df02967c 1b23bd72`.
pub const SECP256K1_LAMBDA_N_U32: [u32; 8] = [
    0x1b23_bd72,
    0xdf02_967c,
    0x2081_6678,
    0x122e_22ea,
    0x8812_645a,
    0xa526_1c02,
    0xc05c_30e0,
    0x5363_ad4c,
];

/// Cube root of unity in `F_p` used by the endomorphism `φ(x, y) = (β·x mod p, y)`.
/// `β = 0x7ae96a2b 657c0710 6e64479e ac3434e9 9cf04975 12f58995 c1396c28 719501ee`.
pub const SECP256K1_BETA_P_U32: [u32; 8] = [
    0x7195_01ee,
    0xc139_6c28,
    0x12f5_8995,
    0x9cf0_4975,
    0xac34_34e9,
    0x6e64_479e,
    0x657c_0710,
    0x7ae9_6a2b,
];

/// Lattice basis row 1: `a1 + b1·λ ≡ 0 (mod n)`. `b1 < 0`, the others are positive.
/// `a1 = b2 = 0x3086d221 a7d46bcd e86c90e4 9284eb15` (128 bits).
pub const SECP256K1_GLV_A1_U32: [u32; 4] = [0x9284_eb15, 0xe86c_90e4, 0xa7d4_6bcd, 0x3086_d221];

/// Magnitude of `b1`; the actual basis component is `-SECP256K1_GLV_B1_NEG_MAG_U32`.
/// `|b1| = 0xe4437ed6 010e8828 6f547fa9 0abfe4c3` (128 bits).
pub const SECP256K1_GLV_B1_NEG_MAG_U32: [u32; 4] =
    [0x0abf_e4c3, 0x6f54_7fa9, 0x010e_8828, 0xe443_7ed6];

/// Lattice basis row 2: `a2 + b2·λ ≡ 0 (mod n)`. Both positive.
/// `a2 = 0x1 14ca50f7 a8e2f3f6 57c1108d 9d44cfd8` (129 bits — needs 5 u32 limbs).
pub const SECP256K1_GLV_A2_U32: [u32; 5] =
    [0x9d44_cfd8, 0x57c1_108d, 0xa8e2_f3f6, 0x14ca_50f7, 0x0000_0001];

/// `b2 = a1 = 0x3086d221 a7d46bcd e86c90e4 9284eb15` (128 bits).
pub const SECP256K1_GLV_B2_U32: [u32; 4] = SECP256K1_GLV_A1_U32;
