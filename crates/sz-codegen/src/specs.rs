//! Concrete modmul specs. One static [`LinearRelation`] per SZ verifier the emitter supports.

use crate::spec::{
    AuxCheck, CarryTerm, Identity, Linear, LinearRelation, Output, OutputForm, Poly, PolyRef,
    PolyRole, Product, Sign, Storage,
};

/// W = 2^16: the limb base for all u16-limb SZ verifiers.
const W: u64 = 1 << 16;

/// secp256k1 base-field prime `p_k1 = 2^256 - 2^32 - 977` as 16 u16 limbs in little-endian
/// order. Must encode the same integer as `SECP256K1_BASE_PRIME_U16` in the matching witness
/// handler (`crates/lib/core/src/handlers/u256_modmul_k1.rs`).
const SECP256K1_BASE_PRIME: &[u16] = &[
    0xfc2f, 0xffff, 0xfffe, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    0xffff, 0xffff, 0xffff, 0xffff,
];

/// secp256k1 scalar-field modulus (group order)
/// `n_k1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`
/// as 16 u16 limbs in little-endian order. Must encode the same integer as
/// `SECP256K1_SCALAR_PRIME_U16` in the matching witness handler
/// (`crates/lib/core/src/handlers/u256_modmul_k1.rs`).
const SECP256K1_SCALAR_MODULUS: &[u16] = &[
    0x4141, 0xd036, 0x5e8c, 0xbfd2, 0xa03b, 0xaf48, 0xdce6, 0xbaae, 0xfffe, 0xffff, 0xffff, 0xffff,
    0xffff, 0xffff, 0xffff, 0xffff,
];

/// `modmul_k1_base(b: u256, a: u256) -> u256` computing `a * b mod (2^256 - 2^32 - 977)`.
///
/// Identity: `a(alpha) * b(alpha) - q(alpha) * p(alpha) - c(alpha) - (W - alpha) * (e_pos(alpha)
/// - e_neg(alpha)) = 0` over u16 limbs, where `p` is the fixed secp256k1 base-field modulus.
/// - `a`, `b`: 16 u16 coefficients each (input, 8 u32 limbs). Caller must provide reduced inputs
///   (a, b < p); the proc does not check this.
/// - `q`, `c`: 16 coefficients each (witness). Honest witnesses use u16 coefficients; the VM
///   accepts u32-bounded non-canonical coefficients. The aux check enforces `c(W) < p`, and for a
///   valid identity `q(W) = floor(a*b / p) < p` follows from `a, b < p`.
/// - `e_pos`, `e_neg`: 32 u32 carry coefficients each; the top two coefficients (`[30]` and `[31]`)
///   are zero.
/// - `p`: 16 u16 coefficients for the fixed modulus. The verifier advice-loads these coefficients
///   to evaluate `p(alpha)`, but first checks them against a hardcoded Poseidon2 commitment.
///
/// Soundness: with `a, b < p`, the SZ identity implies `a(W) * b(W) = q(W) * p(W) + c(W)`
/// up to the Schwartz-Zippel failure probability. The `c(W) < p` check pins c as the
/// canonical residue and forces `q(W) = floor(a*b / p) < p`.
///
/// The witness `q` and `c` are not required to be canonical u16 digits, only u32-bounded
/// coefficients. The identity carries an explicit `(W - x) * e(x)` term to absorb
/// non-canonical coefficient representations (e.g., `c_0 = W, c_1 = 0` evaluates to the same
/// integer at `x = W` as `c_0 = 0, c_1 = 1`). Soundness depends on the returned integer,
/// which `c(W) < p` pins; per-coefficient canonicality is unnecessary.
///
/// The u32 bound keeps all coefficient-level arithmetic far below the Goldilocks modulus
/// (per-term products `q_i * p_j` sum to `< 2^52`, `W * e_i < 2^48`, `c_i < 2^32`), so
/// Goldilocks wraparound cannot masquerade as an integer carry. Tightening to `< W` per
/// limb would add range-check cycles without strengthening the soundness argument.
pub static MODMUL_K1_BASE: LinearRelation = LinearRelation {
    name: "modmul_k1_base",
    signature: "(b: u256, a: u256) -> u256",
    polys: &[
        Poly {
            name: "a",
            role: PolyRole::OperandStack { depth_start: 9 },
            u16_coeff_count: 16,
            storage: Storage::PerU32,
        },
        Poly {
            name: "b",
            role: PolyRole::OperandStack { depth_start: 1 },
            u16_coeff_count: 16,
            storage: Storage::PerU32,
        },
        Poly {
            name: "q",
            role: PolyRole::Witness,
            u16_coeff_count: 16,
            storage: Storage::PerU16,
        },
        Poly {
            name: "c",
            role: PolyRole::Witness,
            u16_coeff_count: 16,
            storage: Storage::PerU16,
        },
        Poly {
            name: "e_pos",
            role: PolyRole::Witness,
            u16_coeff_count: 32,
            storage: Storage::PerU16,
        },
        Poly {
            name: "e_neg",
            role: PolyRole::Witness,
            u16_coeff_count: 32,
            storage: Storage::PerU16,
        },
        Poly {
            name: "p",
            role: PolyRole::Constant { u16_limbs: SECP256K1_BASE_PRIME },
            u16_coeff_count: 16,
            storage: Storage::PerU16,
        },
    ],
    identity: Identity {
        products: &[
            Product {
                sign: Sign::Plus,
                lhs: PolyRef("a"),
                rhs: PolyRef("b"),
            },
            Product {
                sign: Sign::Minus,
                lhs: PolyRef("q"),
                rhs: PolyRef("p"),
            },
        ],
        linears: &[Linear { sign: Sign::Minus, poly: PolyRef("c") }],
        carry: CarryTerm {
            pos: PolyRef("e_pos"),
            neg: PolyRef("e_neg"),
            multiplier: W,
        },
    },
    aux_checks: &[
        AuxCheck::LimbIsZero { poly: PolyRef("e_pos"), index: 30 },
        AuxCheck::LimbIsZero { poly: PolyRef("e_pos"), index: 31 },
        AuxCheck::LimbIsZero { poly: PolyRef("e_neg"), index: 30 },
        AuxCheck::LimbIsZero { poly: PolyRef("e_neg"), index: 31 },
        AuxCheck::LessThan { lhs: PolyRef("c"), rhs: PolyRef("p") },
    ],
    expose: &[Output {
        poly: PolyRef("c"),
        form: OutputForm::U32Limbs,
    }],
};

/// `modmul_k1_scalar(b: u256, a: u256) -> u256` computing `a * b mod n_k1` where `n_k1` is the
/// secp256k1 group order.
///
/// Same identity and witness shape as [`MODMUL_K1_BASE`]; the fixed modulus is the group order
/// polynomial `n`.
pub static MODMUL_K1_SCALAR: LinearRelation = LinearRelation {
    name: "modmul_k1_scalar",
    signature: "(b: u256, a: u256) -> u256",
    polys: &[
        Poly {
            name: "a",
            role: PolyRole::OperandStack { depth_start: 9 },
            u16_coeff_count: 16,
            storage: Storage::PerU32,
        },
        Poly {
            name: "b",
            role: PolyRole::OperandStack { depth_start: 1 },
            u16_coeff_count: 16,
            storage: Storage::PerU32,
        },
        Poly {
            name: "q",
            role: PolyRole::Witness,
            u16_coeff_count: 16,
            storage: Storage::PerU16,
        },
        Poly {
            name: "c",
            role: PolyRole::Witness,
            u16_coeff_count: 16,
            storage: Storage::PerU16,
        },
        Poly {
            name: "e_pos",
            role: PolyRole::Witness,
            u16_coeff_count: 32,
            storage: Storage::PerU16,
        },
        Poly {
            name: "e_neg",
            role: PolyRole::Witness,
            u16_coeff_count: 32,
            storage: Storage::PerU16,
        },
        Poly {
            name: "n",
            role: PolyRole::Constant { u16_limbs: SECP256K1_SCALAR_MODULUS },
            u16_coeff_count: 16,
            storage: Storage::PerU16,
        },
    ],
    identity: Identity {
        products: &[
            Product {
                sign: Sign::Plus,
                lhs: PolyRef("a"),
                rhs: PolyRef("b"),
            },
            Product {
                sign: Sign::Minus,
                lhs: PolyRef("q"),
                rhs: PolyRef("n"),
            },
        ],
        linears: &[Linear { sign: Sign::Minus, poly: PolyRef("c") }],
        carry: CarryTerm {
            pos: PolyRef("e_pos"),
            neg: PolyRef("e_neg"),
            multiplier: W,
        },
    },
    aux_checks: &[
        AuxCheck::LimbIsZero { poly: PolyRef("e_pos"), index: 30 },
        AuxCheck::LimbIsZero { poly: PolyRef("e_pos"), index: 31 },
        AuxCheck::LimbIsZero { poly: PolyRef("e_neg"), index: 30 },
        AuxCheck::LimbIsZero { poly: PolyRef("e_neg"), index: 31 },
        AuxCheck::LessThan { lhs: PolyRef("c"), rhs: PolyRef("n") },
    ],
    expose: &[Output {
        poly: PolyRef("c"),
        form: OutputForm::U32Limbs,
    }],
};
