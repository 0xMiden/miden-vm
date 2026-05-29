//! Concrete modmul specs. One static [`LinearRelation`] per SZ verifier the emitter supports.

use crate::spec::{
    AuxCheck, CarryTerm, Identity, Linear, LinearRelation, Output, OutputForm, Poly, PolyRef,
    PolyRole, Product, Sign, Storage,
};

/// W = 2^16: the limb base for all u16-limb SZ verifiers.
const W: u64 = 1 << 16;

/// Host-side shift added to every signed-carry coefficient so the landed felt is always a valid
/// u32. The verifier subtracts the matching [`CarryTerm::offset`] polynomial inside the identity
/// check.
const CARRY_SHIFT: u32 = 1 << 31;

/// Coefficients of the offset polynomial pinned alongside the modulus: 32 copies of
/// [`CARRY_SHIFT`].
const CARRY_OFFSET_VECTOR: &[u32; 32] = &[CARRY_SHIFT; 32];

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
/// Contract:
/// - `a`, `b`: operand-stack inputs encoded as 8 u32 limbs. The generated proc assumes this bound;
///   callers must validate untrusted or advice-derived values before calling.
/// - On success, the proc returns the canonical residue `c = a * b mod p`, with `c < p`.
/// - The standard witness handler is complete when `floor(a * b / p) < 2^256`. This holds if
///   either input is canonical (`< p`) and the other is any well-formed u256.
/// - Malformed or inconsistent advice traps.
///
/// Identity: `a(alpha) * b(alpha) - q(alpha) * p(alpha) - c(alpha)
///   - (W - alpha) * (e_shifted(alpha) - offset(alpha)) = 0` over u16 limbs.
/// - `q`, `c`: 16-coefficient witness. Honest witnesses use u16 coefficients; the VM accepts
///   u32-bounded non-canonical ones. The aux check enforces `c(W) < p`.
/// - `e_shifted`: 32-coefficient signed-carry witness in shifted form (`signed_carry + 2^31`). Top
///   two coefficients equal `2^31` (the shifted encoding of zero), pinned by aux checks.
/// - `p`: fixed modulus.
/// - `offset`: fixed `[2^31; 32]` vector. Absorbed alongside `p` in the same fixed-statement prefix
///   and pinned by a single combined Poseidon2 digest.
///
/// Soundness: with u32-bounded input limbs, the SZ identity implies
/// `a(W) * b(W) = q(W) * p(W) + c(W)` up to the Schwartz-Zippel failure probability. `c(W) < p`
/// then pins c as the canonical residue.
///
/// The witness `q` and `c` are not required to be canonical u16 digits, only u32-bounded
/// coefficients. The explicit `(W - x) * e(x)` term absorbs non-canonical representations
/// (e.g., `c_0 = W, c_1 = 0` evaluates the same as `c_0 = 0, c_1 = 1` at `x = W`); soundness
/// depends on the integer value, which `c(W) < p` pins.
///
/// The u32 bound on every coefficient (including the shifted carry) keeps coefficient-level
/// arithmetic far below the Goldilocks modulus, so wraparound cannot masquerade as an integer
/// carry.
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
            name: "e_shifted",
            role: PolyRole::Witness,
            u16_coeff_count: 32,
            storage: Storage::PerU16,
        },
        // Placed directly after `e_shifted` so the two h-storage cells are word-adjacent;
        // the identity check uses a single `loadw` to bring both ext2 values onto the stack.
        Poly {
            name: "offset",
            role: PolyRole::FixedU32Vector { u32_values: CARRY_OFFSET_VECTOR },
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
            shifted: PolyRef("e_shifted"),
            offset: PolyRef("offset"),
            multiplier: W,
        },
    },
    aux_checks: &[
        AuxCheck::LimbEquals {
            poly: PolyRef("e_shifted"),
            index: 30,
            value: CARRY_SHIFT,
        },
        AuxCheck::LimbEquals {
            poly: PolyRef("e_shifted"),
            index: 31,
            value: CARRY_SHIFT,
        },
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
/// Same contract, identity, and witness shape as [`MODMUL_K1_BASE`]; the fixed modulus is the
/// group order polynomial `n`.
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
            name: "e_shifted",
            role: PolyRole::Witness,
            u16_coeff_count: 32,
            storage: Storage::PerU16,
        },
        // Placed directly after `e_shifted` so the two h-storage cells are word-adjacent;
        // the identity check uses a single `loadw` to bring both ext2 values onto the stack.
        Poly {
            name: "offset",
            role: PolyRole::FixedU32Vector { u32_values: CARRY_OFFSET_VECTOR },
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
            shifted: PolyRef("e_shifted"),
            offset: PolyRef("offset"),
            multiplier: W,
        },
    },
    aux_checks: &[
        AuxCheck::LimbEquals {
            poly: PolyRef("e_shifted"),
            index: 30,
            value: CARRY_SHIFT,
        },
        AuxCheck::LimbEquals {
            poly: PolyRef("e_shifted"),
            index: 31,
            value: CARRY_SHIFT,
        },
        AuxCheck::LessThan { lhs: PolyRef("c"), rhs: PolyRef("n") },
    ],
    expose: &[Output {
        poly: PolyRef("c"),
        form: OutputForm::U32Limbs,
    }],
};
