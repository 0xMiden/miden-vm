use core::cmp::Ordering;

use miden_core::{
    Felt, ZERO,
    deferred::{Node, TRUE_DIGEST, Tag, precompile_id},
};

/// Little-endian 256-bit value represented as eight `u32` limbs.
pub type Limbs = [u32; 8];

pub const ZERO_LIMBS: Limbs = [0; 8];
pub const ONE_LIMBS: Limbs = [1, 0, 0, 0, 0, 0, 0, 0];
pub const TWO_LIMBS: Limbs = [2, 0, 0, 0, 0, 0, 0, 0];

/// VM-owned store pointer for the U256 wrapping-domain bound (`2^256 - 1`).
pub const U256_BOUND_PTR: u32 = 1;
/// VM-owned store pointer for the secp256k1 base-field bound (`p - 1`).
pub const K1_BASE_BOUND_PTR: u32 = 2;
/// VM-owned store pointer for the secp256k1 scalar-field bound (`n - 1`).
pub const K1_SCALAR_BOUND_PTR: u32 = 3;
/// VM-owned store pointer for the secp256r1 base-field bound (`p - 1`).
pub const R1_BASE_BOUND_PTR: u32 = 4;
/// VM-owned store pointer for the secp256r1 scalar-field bound (`n - 1`).
pub const R1_SCALAR_BOUND_PTR: u32 = 5;

/// VM-owned store pointer for the secp256k1 curve coefficient `A`.
pub const K1_A_PTR: u32 = 8;
/// VM-owned store pointer for the secp256k1 curve coefficient `B`.
pub const K1_B_PTR: u32 = 9;
/// VM-owned store pointer for the secp256r1 curve coefficient `A`.
pub const R1_A_PTR: u32 = 10;
/// VM-owned store pointer for the secp256r1 curve coefficient `B`.
pub const R1_B_PTR: u32 = 11;

/// VM-owned store pointer for the secp256k1 group configuration.
pub const K1_GROUP_PTR: u32 = 1;
/// VM-owned store pointer for the secp256r1 group configuration.
pub const R1_GROUP_PTR: u32 = 2;

/// Marker for arithmetic modulo `2^256`.
#[derive(Debug, Default, Clone, Copy)]
pub struct U256;

impl U256 {
    /// Encoded modulus sentinel for arithmetic modulo `2^256`.
    pub const ENCODED_MODULUS: Limbs = [0; 8];

    /// Maximum canonical U256 value, `2^256 - 1`.
    pub const MAX: Limbs = [u32::MAX; 8];
}

/// Marker type for the secp256k1 base field.
#[derive(Debug, Default, Clone, Copy)]
pub struct K1Base;

impl K1Base {
    /// Modulus of the secp256k1 base field, little-endian u32 limbs.
    pub const MODULUS: Limbs = [
        0xffff_fc2f,
        0xffff_fffe,
        0xffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
    ];
}

/// Marker type for the secp256k1 scalar field.
#[derive(Debug, Default, Clone, Copy)]
pub struct K1Scalar;

impl K1Scalar {
    /// Modulus of the secp256k1 scalar field, little-endian u32 limbs.
    pub const MODULUS: Limbs = [
        0xd036_4141,
        0xbfd2_5e8c,
        0xaf48_a03b,
        0xbaae_dce6,
        0xffff_fffe,
        0xffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
    ];
}

/// Marker type for the secp256r1 base field.
#[derive(Debug, Default, Clone, Copy)]
pub struct R1Base;

impl R1Base {
    /// Modulus of the secp256r1 base field, little-endian u32 limbs.
    pub const MODULUS: Limbs = [
        0xffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
        0x0000_0000,
        0x0000_0000,
        0x0000_0000,
        0x0000_0001,
        0xffff_ffff,
    ];
}

/// Marker type for the secp256r1 scalar field.
#[derive(Debug, Default, Clone, Copy)]
pub struct R1Scalar;

impl R1Scalar {
    /// Modulus of the secp256r1 scalar field, little-endian u32 limbs.
    pub const MODULUS: Limbs = [
        0xfc63_2551,
        0xf3b9_cac2,
        0xa717_9e84,
        0xbce6_faad,
        0xffff_ffff,
        0xffff_ffff,
        0x0000_0000,
        0xffff_ffff,
    ];
}

/// Spec for one fixed uint arithmetic domain.
pub trait UintSpec: 'static {
    /// Encoded modulus limbs. `[0; 8]` is the `2^256` wrapping-domain sentinel.
    const ENCODED_MODULUS: Limbs;

    /// Barrett constant `floor(2^512 / modulus)` derived from [`Self::ENCODED_MODULUS`]. Unused by
    /// the `2^256` wrapping sentinel, for which it is `[0; 9]`.
    const BARRETT_MU: [u32; 9] = barrett_mu(Self::ENCODED_MODULUS);

    /// Whether this domain supports prime-field helpers such as inversion.
    const IS_PRIME_FIELD: bool = false;

    /// Returns whether `value` is canonical for this domain.
    fn is_canonical(value: &Limbs) -> bool {
        if Self::ENCODED_MODULUS == ZERO_LIMBS {
            true
        } else {
            cmp(value, &Self::ENCODED_MODULUS) == Ordering::Less
        }
    }

    /// Adds two canonical values in this domain.
    fn add(lhs: Limbs, rhs: Limbs) -> Limbs {
        if Self::ENCODED_MODULUS == ZERO_LIMBS {
            wrapping_add(lhs, rhs)
        } else {
            add_mod(lhs, rhs, Self::ENCODED_MODULUS)
        }
    }

    /// Subtracts two canonical values in this domain.
    fn sub(lhs: Limbs, rhs: Limbs) -> Limbs {
        if Self::ENCODED_MODULUS == ZERO_LIMBS {
            wrapping_sub(lhs, rhs)
        } else {
            sub_mod(lhs, rhs, Self::ENCODED_MODULUS)
        }
    }

    /// Multiplies two canonical values in this domain.
    fn mul(lhs: Limbs, rhs: Limbs) -> Limbs {
        if Self::ENCODED_MODULUS == ZERO_LIMBS {
            wrapping_mul(lhs, rhs)
        } else {
            mul_mod_barrett(lhs, rhs, Self::ENCODED_MODULUS, Self::BARRETT_MU)
        }
    }

    /// Returns the multiplicative inverse of `value` for declared prime-field domains.
    fn inv(value: Limbs) -> Option<Limbs> {
        if Self::IS_PRIME_FIELD && Self::ENCODED_MODULUS != ZERO_LIMBS {
            inv_mod_prime_barrett(value, Self::ENCODED_MODULUS, Self::BARRETT_MU)
        } else {
            None
        }
    }

    /// Returns the canonical value `modulus - 1`, or `2^256 - 1` for U256.
    fn minus_one() -> Limbs {
        if Self::ENCODED_MODULUS == ZERO_LIMBS {
            [u32::MAX; 8]
        } else {
            sub_small(Self::ENCODED_MODULUS, 1)
        }
    }

    /// Returns the field constant `1 / 2`, if this is a declared prime-field domain.
    fn half() -> Option<Limbs> {
        Self::inv(TWO_LIMBS)
    }

    /// Returns `2^exponent` reduced into this prime-field domain.
    fn pow2_mod(exponent: usize) -> Option<Limbs> {
        if !Self::IS_PRIME_FIELD || Self::ENCODED_MODULUS == ZERO_LIMBS {
            return None;
        }

        let mut value = ONE_LIMBS;
        for _ in 0..exponent {
            value = Self::add(value, value);
        }
        Some(value)
    }
}

impl UintSpec for U256 {
    const ENCODED_MODULUS: Limbs = U256::ENCODED_MODULUS;
}

impl UintSpec for K1Base {
    const ENCODED_MODULUS: Limbs = K1Base::MODULUS;
    const IS_PRIME_FIELD: bool = true;
}

impl UintSpec for K1Scalar {
    const ENCODED_MODULUS: Limbs = K1Scalar::MODULUS;
    const IS_PRIME_FIELD: bool = true;
}

impl UintSpec for R1Base {
    const ENCODED_MODULUS: Limbs = R1Base::MODULUS;
    const IS_PRIME_FIELD: bool = true;
}

impl UintSpec for R1Scalar {
    const ENCODED_MODULUS: Limbs = R1Scalar::MODULUS;
    const IS_PRIME_FIELD: bool = true;
}

/// Fixed uint arithmetic domains supported by the native uint precompile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UintDomain {
    /// Arithmetic modulo `2^256`.
    U256,
    /// secp256k1 base field.
    K1Base,
    /// secp256k1 scalar field.
    K1Scalar,
    /// secp256r1 base field.
    R1Base,
    /// secp256r1 scalar field.
    R1Scalar,
}

impl UintDomain {
    /// All fixed domains in deterministic precompile initialization order.
    pub const ALL: [Self; 5] =
        [Self::U256, Self::K1Base, Self::K1Scalar, Self::R1Base, Self::R1Scalar];

    /// Returns the VM-owned store pointer for this domain's fixed bound/modulus.
    pub const fn bound_ptr(self) -> u32 {
        match self {
            Self::U256 => U256_BOUND_PTR,
            Self::K1Base => K1_BASE_BOUND_PTR,
            Self::K1Scalar => K1_SCALAR_BOUND_PTR,
            Self::R1Base => R1_BASE_BOUND_PTR,
            Self::R1Scalar => R1_SCALAR_BOUND_PTR,
        }
    }

    /// Returns the uint domain assigned to the fixed bound pointer `ptr`.
    pub const fn from_bound_ptr(ptr: u32) -> Option<Self> {
        match ptr {
            U256_BOUND_PTR => Some(Self::U256),
            K1_BASE_BOUND_PTR => Some(Self::K1Base),
            K1_SCALAR_BOUND_PTR => Some(Self::K1Scalar),
            R1_BASE_BOUND_PTR => Some(Self::R1Base),
            R1_SCALAR_BOUND_PTR => Some(Self::R1Scalar),
            _ => None,
        }
    }

    /// Returns the encoded modulus limbs. `[0; 8]` is the `2^256` sentinel.
    pub fn encoded_modulus(self) -> Limbs {
        match self {
            Self::U256 => <U256 as UintSpec>::ENCODED_MODULUS,
            Self::K1Base => <K1Base as UintSpec>::ENCODED_MODULUS,
            Self::K1Scalar => <K1Scalar as UintSpec>::ENCODED_MODULUS,
            Self::R1Base => <R1Base as UintSpec>::ENCODED_MODULUS,
            Self::R1Scalar => <R1Scalar as UintSpec>::ENCODED_MODULUS,
        }
    }

    /// Returns whether this domain is declared to be a prime field.
    pub fn is_prime_field(self) -> bool {
        match self {
            Self::U256 => <U256 as UintSpec>::IS_PRIME_FIELD,
            Self::K1Base => <K1Base as UintSpec>::IS_PRIME_FIELD,
            Self::K1Scalar => <K1Scalar as UintSpec>::IS_PRIME_FIELD,
            Self::R1Base => <R1Base as UintSpec>::IS_PRIME_FIELD,
            Self::R1Scalar => <R1Scalar as UintSpec>::IS_PRIME_FIELD,
        }
    }

    /// Returns whether `value` is canonical for this domain.
    pub fn is_canonical(self, value: &Limbs) -> bool {
        match self {
            Self::U256 => U256::is_canonical(value),
            Self::K1Base => K1Base::is_canonical(value),
            Self::K1Scalar => K1Scalar::is_canonical(value),
            Self::R1Base => R1Base::is_canonical(value),
            Self::R1Scalar => R1Scalar::is_canonical(value),
        }
    }

    /// Adds two canonical values in this domain.
    pub fn add(self, lhs: Limbs, rhs: Limbs) -> Limbs {
        match self {
            Self::U256 => U256::add(lhs, rhs),
            Self::K1Base => K1Base::add(lhs, rhs),
            Self::K1Scalar => K1Scalar::add(lhs, rhs),
            Self::R1Base => R1Base::add(lhs, rhs),
            Self::R1Scalar => R1Scalar::add(lhs, rhs),
        }
    }

    /// Subtracts two canonical values in this domain.
    pub fn sub(self, lhs: Limbs, rhs: Limbs) -> Limbs {
        match self {
            Self::U256 => U256::sub(lhs, rhs),
            Self::K1Base => K1Base::sub(lhs, rhs),
            Self::K1Scalar => K1Scalar::sub(lhs, rhs),
            Self::R1Base => R1Base::sub(lhs, rhs),
            Self::R1Scalar => R1Scalar::sub(lhs, rhs),
        }
    }

    /// Multiplies two canonical values in this domain.
    pub fn mul(self, lhs: Limbs, rhs: Limbs) -> Limbs {
        match self {
            Self::U256 => U256::mul(lhs, rhs),
            Self::K1Base => K1Base::mul(lhs, rhs),
            Self::K1Scalar => K1Scalar::mul(lhs, rhs),
            Self::R1Base => R1Base::mul(lhs, rhs),
            Self::R1Scalar => R1Scalar::mul(lhs, rhs),
        }
    }

    /// Returns the multiplicative inverse of `value` for declared prime-field domains.
    pub fn inv(self, value: Limbs) -> Option<Limbs> {
        match self {
            Self::U256 => U256::inv(value),
            Self::K1Base => K1Base::inv(value),
            Self::K1Scalar => K1Scalar::inv(value),
            Self::R1Base => R1Base::inv(value),
            Self::R1Scalar => R1Scalar::inv(value),
        }
    }

    /// Returns the maximum canonical value for U256.
    pub fn max(self) -> Option<Limbs> {
        match self {
            Self::U256 => Some(U256::MAX),
            _ => None,
        }
    }

    /// Returns the canonical value `modulus - 1`, or `2^256 - 1` for U256.
    pub fn minus_one(self) -> Limbs {
        match self {
            Self::U256 => U256::minus_one(),
            Self::K1Base => K1Base::minus_one(),
            Self::K1Scalar => K1Scalar::minus_one(),
            Self::R1Base => R1Base::minus_one(),
            Self::R1Scalar => R1Scalar::minus_one(),
        }
    }

    /// Returns the field constant `1 / 2`, if this is a declared prime-field domain.
    pub fn half(self) -> Option<Limbs> {
        match self {
            Self::U256 => U256::half(),
            Self::K1Base => K1Base::half(),
            Self::K1Scalar => K1Scalar::half(),
            Self::R1Base => R1Base::half(),
            Self::R1Scalar => R1Scalar::half(),
        }
    }

    /// Returns `2^exponent` reduced into this prime-field domain.
    pub fn pow2_mod(self, exponent: usize) -> Option<Limbs> {
        match self {
            Self::U256 => U256::pow2_mod(exponent),
            Self::K1Base => K1Base::pow2_mod(exponent),
            Self::K1Scalar => K1Scalar::pow2_mod(exponent),
            Self::R1Base => R1Base::pow2_mod(exponent),
            Self::R1Scalar => R1Scalar::pow2_mod(exponent),
        }
    }

    pub fn field_constants(self) -> Option<[Limbs; 5]> {
        if self.is_prime_field() {
            Some([
                self.minus_one(),
                self.half()?,
                self.pow2_mod(128)?,
                self.pow2_mod(256)?,
                self.pow2_mod(384)?,
            ])
        } else {
            None
        }
    }
}

pub struct UintPrecompileDescriptor;

impl UintPrecompileDescriptor {
    pub const NAME: &'static str = "uint256";
    pub const VALUE_OP_ID: u64 = 0;
    pub const ADD_OP_ID: u64 = 1;
    pub const SUB_OP_ID: u64 = 2;
    pub const MUL_OP_ID: u64 = 3;
    pub const EQ_OP_ID: u64 = 4;

    pub fn id() -> Felt {
        precompile_id(Self::NAME)
    }

    pub fn value_tag(domain: UintDomain) -> Tag {
        let op_id = Felt::new(Self::VALUE_OP_ID).expect("uint VALUE op id must fit in a felt");
        Tag::precompile(Self::id(), [op_id, Felt::from(domain.bound_ptr()), ZERO])
            .expect("uint precompile id is not framework-reserved")
    }

    pub fn op_tag(op_id: u64) -> Tag {
        let op_id = Felt::new(op_id).expect("uint op id must fit in a felt");
        Tag::precompile(Self::id(), [op_id, ZERO, ZERO])
            .expect("uint precompile id is not framework-reserved")
    }

    pub fn value_node(domain: UintDomain, limbs: Limbs) -> Node {
        debug_assert!(domain.is_canonical(&limbs));
        Node::value(Self::value_tag(domain), limbs.map(Felt::from_u32))
            .expect("value tag is precompile-owned")
    }
}

/// Fixed curves supported by the native curve precompile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodegenCurveId {
    Secp256k1,
    Secp256r1,
}

impl CodegenCurveId {
    pub const ALL: [Self; 2] = [Self::Secp256k1, Self::Secp256r1];

    pub fn id(self) -> Felt {
        match self {
            Self::Secp256k1 => SECP256K1_ID,
            Self::Secp256r1 => SECP256R1_ID,
        }
    }

    pub const fn base_domain(self) -> UintDomain {
        match self {
            Self::Secp256k1 => UintDomain::K1Base,
            Self::Secp256r1 => UintDomain::R1Base,
        }
    }

    pub const fn group_ptr(self) -> u32 {
        match self {
            Self::Secp256k1 => K1_GROUP_PTR,
            Self::Secp256r1 => R1_GROUP_PTR,
        }
    }

    pub const fn from_group_ptr(ptr: u32) -> Option<Self> {
        match ptr {
            K1_GROUP_PTR => Some(Self::Secp256k1),
            R1_GROUP_PTR => Some(Self::Secp256r1),
            _ => None,
        }
    }

    pub const fn a_ptr(self) -> u32 {
        match self {
            Self::Secp256k1 => K1_A_PTR,
            Self::Secp256r1 => R1_A_PTR,
        }
    }

    pub const fn b_ptr(self) -> u32 {
        match self {
            Self::Secp256k1 => K1_B_PTR,
            Self::Secp256r1 => R1_B_PTR,
        }
    }

    pub const fn scalar_domain(self) -> UintDomain {
        match self {
            Self::Secp256k1 => UintDomain::K1Scalar,
            Self::Secp256r1 => UintDomain::R1Scalar,
        }
    }

    pub fn generator(self) -> (Limbs, Limbs) {
        match self {
            Self::Secp256k1 => (SECP256K1_GENERATOR_X, SECP256K1_GENERATOR_Y),
            Self::Secp256r1 => (SECP256R1_GENERATOR_X, SECP256R1_GENERATOR_Y),
        }
    }
}

pub const SECP256K1_ID: Felt = Felt::new_unchecked(1);
pub const SECP256R1_ID: Felt = Felt::new_unchecked(2);

pub const SECP256K1_GENERATOR_X: Limbs = [
    0x16f8_1798,
    0x59f2_815b,
    0x2dce_28d9,
    0x029b_fcdb,
    0xce87_0b07,
    0x55a0_6295,
    0xf9dc_bbac,
    0x79be_667e,
];

pub const SECP256K1_GENERATOR_Y: Limbs = [
    0xfb10_d4b8,
    0x9c47_d08f,
    0xa685_5419,
    0xfd17_b448,
    0x0e11_08a8,
    0x5da4_fbfc,
    0x26a3_c465,
    0x483a_da77,
];

pub const SECP256R1_GENERATOR_X: Limbs = [
    0xd898_c296,
    0xf4a1_3945,
    0x2deb_33a0,
    0x7703_7d81,
    0x63a4_40f2,
    0xf8bc_e6e5,
    0xe12c_4247,
    0x6b17_d1f2,
];

pub const SECP256R1_GENERATOR_Y: Limbs = [
    0x37bf_51f5,
    0xcbb6_4068,
    0x6b31_5ece,
    0x2bce_3357,
    0x7c0f_9e16,
    0x8ee7_eb4a,
    0xfe1a_7f9b,
    0x4fe3_42e2,
];

pub struct CurvePrecompileDescriptor;

impl CurvePrecompileDescriptor {
    pub const NAME: &'static str = "curve";
    pub const VALUE_OP_ID: u64 = 0;
    pub const ADD_OP_ID: u64 = 1;
    pub const SUB_OP_ID: u64 = 2;
    pub const EQ_OP_ID: u64 = 3;
    pub const MSM_OP_ID: u64 = 4;

    pub fn id() -> Felt {
        precompile_id(Self::NAME)
    }

    pub fn value_tag(curve: CodegenCurveId) -> Tag {
        let op_id = Felt::new(Self::VALUE_OP_ID).expect("curve VALUE op id must fit in a felt");
        Tag::precompile(Self::id(), [op_id, Felt::from(curve.group_ptr()), ZERO])
            .expect("curve precompile id is not framework-reserved")
    }

    pub fn op_tag(op_id: u64) -> Tag {
        let op_id = Felt::new(op_id).expect("curve op id must fit in a felt");
        Tag::precompile(Self::id(), [op_id, ZERO, ZERO])
            .expect("curve precompile id is not framework-reserved")
    }

    pub fn msm_tag() -> Tag {
        Self::op_tag(Self::MSM_OP_ID)
    }

    pub fn identity_node(curve: CodegenCurveId) -> Node {
        Node::join(Self::value_tag(curve), TRUE_DIGEST, TRUE_DIGEST)
            .expect("curve value tag is precompile-owned")
    }

    pub fn generator_node(curve: CodegenCurveId) -> Node {
        let (x, y) = curve.generator();
        let x = UintPrecompileDescriptor::value_node(curve.base_domain(), x);
        let y = UintPrecompileDescriptor::value_node(curve.base_domain(), y);
        Node::join(Self::value_tag(curve), x.digest(), y.digest())
            .expect("curve value tag is precompile-owned")
    }
}

fn wrapping_add(lhs: Limbs, rhs: Limbs) -> Limbs {
    add_raw(lhs, rhs).0
}

fn wrapping_sub(lhs: Limbs, rhs: Limbs) -> Limbs {
    sub_raw(lhs, rhs).0
}

fn wrapping_mul(lhs: Limbs, rhs: Limbs) -> Limbs {
    let wide = mul_wide(lhs, rhs);
    let mut out = [0u32; 8];
    out.copy_from_slice(&wide[..8]);
    out
}

fn add_mod(lhs: Limbs, rhs: Limbs, modulus: Limbs) -> Limbs {
    let (sum, carry) = add_raw(lhs, rhs);
    if carry != 0 || !cmp(&sum, &modulus).is_lt() {
        sub_raw(sum, modulus).0
    } else {
        sum
    }
}

fn sub_mod(lhs: Limbs, rhs: Limbs, modulus: Limbs) -> Limbs {
    let (diff, borrow) = sub_raw(lhs, rhs);
    if borrow != 0 { add_raw(diff, modulus).0 } else { diff }
}

// BARRETT REDUCTION
// ================================================================================================

/// Computes the Barrett constant `mu = floor(2^512 / modulus)` for a 256-bit modulus.
///
/// Returns `[0; 9]` for the `2^256` wrapping sentinel (`modulus == 0`), which never reaches the
/// Barrett path. Intended to be evaluated at compile time, once per fixed domain.
const fn barrett_mu(modulus: Limbs) -> [u32; 9] {
    let mut nonzero = false;
    let mut i = 0;
    while i < 8 {
        if modulus[i] != 0 {
            nonzero = true;
        }
        i += 1;
    }
    if !nonzero {
        return [0; 9];
    }

    // Bit-by-bit long division of 2^512 by `modulus`. The quotient has at most 257 bits, so every
    // set bit lands within the nine quotient limbs.
    let mut quotient = [0u32; 9];
    let mut remainder = [0u32; 9];
    let mut bit: i32 = 512;
    while bit >= 0 {
        remainder = shl1_limbs9(remainder);
        if bit == 512 {
            remainder[0] |= 1;
        }
        if limbs9_ge_mod(&remainder, &modulus) {
            remainder = limbs9_sub_mod(remainder, &modulus);
            let b = bit as usize;
            if b < 288 {
                quotient[b / 32] |= 1 << (b % 32);
            }
        }
        bit -= 1;
    }
    quotient
}

/// Multiplies two 256-bit values modulo `modulus` using Barrett reduction.
///
/// `mu` must equal `barrett_mu(modulus)`; the modulus must occupy its full 256-bit width (nonzero
/// top limb), which holds for every fixed prime domain.
fn mul_mod_barrett(lhs: Limbs, rhs: Limbs, modulus: Limbs, mu: [u32; 9]) -> Limbs {
    if lhs == ZERO_LIMBS || rhs == ZERO_LIMBS {
        return ZERO_LIMBS;
    }
    if lhs == ONE_LIMBS {
        return rhs;
    }
    if rhs == ONE_LIMBS {
        return lhs;
    }

    reduce_barrett(mul_wide(lhs, rhs), modulus, mu)
}

/// Exponentiates `base^exponent mod modulus` using Barrett reduction.
fn pow_mod_barrett(mut base: Limbs, exponent: Limbs, modulus: Limbs, mu: [u32; 9]) -> Limbs {
    let mut result = ONE_LIMBS;
    for bit in 0..256 {
        if bit_is_set(&exponent, bit) {
            result = mul_mod_barrett(result, base, modulus, mu);
        }
        base = mul_mod_barrett(base, base, modulus, mu);
    }
    result
}

/// Computes `value^-1 mod modulus` for nonzero values in a prime field, using Barrett reduction.
fn inv_mod_prime_barrett(value: Limbs, modulus: Limbs, mu: [u32; 9]) -> Option<Limbs> {
    if value == ZERO_LIMBS || modulus == ZERO_LIMBS {
        return None;
    }
    if value == ONE_LIMBS {
        return Some(ONE_LIMBS);
    }

    // Fermat's little theorem: a^(p - 2) is the multiplicative inverse modulo prime p.
    Some(pow_mod_barrett(value, sub_small(modulus, 2), modulus, mu))
}

/// Reduces a 512-bit little-endian product modulo a 256-bit modulus (Barrett, HAC 14.42, base
/// `2^32`, `k = 8`). Requires `value < modulus^2 < 2^512`.
fn reduce_barrett(value: [u32; 16], modulus: Limbs, mu: [u32; 9]) -> Limbs {
    // q1 = floor(value / 2^224): the top nine limbs of the product.
    let mut q1 = [0u32; 9];
    q1.copy_from_slice(&value[7..16]);

    // q3 = floor(q1 * mu / 2^288): drop the low nine limbs of the product.
    let mut q2 = [0u32; 18];
    mul_limbs(&q1, &mu, &mut q2);
    let mut q3 = [0u32; 9];
    q3.copy_from_slice(&q2[9..18]);

    // r = (value mod 2^288) - (q3 * modulus mod 2^288), taken modulo 2^288.
    let mut r1 = [0u32; 9];
    r1.copy_from_slice(&value[0..9]);
    let mut q3m = [0u32; 18];
    mul_limbs(&q3, &modulus, &mut q3m);
    let mut r2 = [0u32; 9];
    r2.copy_from_slice(&q3m[0..9]);
    let mut r = sub_limbs9(r1, r2);

    // The Barrett estimate leaves at most two extra multiples of the modulus.
    while limbs9_ge_mod(&r, &modulus) {
        r = limbs9_sub_mod(r, &modulus);
    }

    let mut out = [0u32; 8];
    out.copy_from_slice(&r[0..8]);
    out
}

/// Schoolbook multiply of little-endian limb slices into `out` (length `>= a.len() + b.len()`).
fn mul_limbs(a: &[u32], b: &[u32], out: &mut [u32]) {
    for slot in out.iter_mut() {
        *slot = 0;
    }
    for (i, &a_limb) in a.iter().enumerate() {
        let mut carry = 0u64;
        for (j, &b_limb) in b.iter().enumerate() {
            let idx = i + j;
            let cur = out[idx] as u64 + a_limb as u64 * b_limb as u64 + carry;
            out[idx] = cur as u32;
            carry = cur >> 32;
        }
        let mut idx = i + b.len();
        while carry != 0 {
            let cur = out[idx] as u64 + carry;
            out[idx] = cur as u32;
            carry = cur >> 32;
            idx += 1;
        }
    }
}

/// Shifts a nine-limb little-endian value left by one bit.
const fn shl1_limbs9(mut limbs: [u32; 9]) -> [u32; 9] {
    let mut carry = 0u32;
    let mut i = 0;
    while i < 9 {
        let next_carry = limbs[i] >> 31;
        limbs[i] = (limbs[i] << 1) | carry;
        carry = next_carry;
        i += 1;
    }
    limbs
}

/// Compares a nine-limb value against an eight-limb modulus (zero-extended), returning `r >=
/// modulus`.
const fn limbs9_ge_mod(r: &[u32; 9], modulus: &Limbs) -> bool {
    if r[8] != 0 {
        return true;
    }
    let mut i = 8;
    while i > 0 {
        i -= 1;
        if r[i] != modulus[i] {
            return r[i] > modulus[i];
        }
    }
    true
}

/// Subtracts an eight-limb modulus (zero-extended) from a nine-limb value, wrapping modulo 2^288.
const fn limbs9_sub_mod(mut r: [u32; 9], modulus: &Limbs) -> [u32; 9] {
    let mut borrow = 0u64;
    let mut i = 0;
    while i < 9 {
        let modulus_limb = if i < 8 { modulus[i] as u64 } else { 0 };
        let subtrahend = modulus_limb + borrow;
        let diff = (r[i] as u64).wrapping_sub(subtrahend);
        borrow = ((r[i] as u64) < subtrahend) as u64;
        r[i] = diff as u32;
        i += 1;
    }
    r
}

/// Subtracts two nine-limb values, wrapping modulo 2^288.
fn sub_limbs9(a: [u32; 9], b: [u32; 9]) -> [u32; 9] {
    let mut out = [0u32; 9];
    let mut borrow = 0u64;
    for i in 0..9 {
        let subtrahend = b[i] as u64 + borrow;
        out[i] = (a[i] as u64).wrapping_sub(subtrahend) as u32;
        borrow = u64::from((a[i] as u64) < subtrahend);
    }
    out
}

fn mul_wide(lhs: Limbs, rhs: Limbs) -> [u32; 16] {
    let mut out = [0u32; 16];
    for (i, lhs_limb) in lhs.iter().enumerate() {
        let mut carry = 0u64;
        for (j, rhs_limb) in rhs.iter().enumerate() {
            let idx = i + j;
            let cur = out[idx] as u64 + *lhs_limb as u64 * *rhs_limb as u64 + carry;
            out[idx] = cur as u32;
            carry = cur >> 32;
        }

        let mut idx = i + 8;
        while carry != 0 {
            let cur = out[idx] as u64 + carry;
            out[idx] = cur as u32;
            carry = cur >> 32;
            idx += 1;
        }
    }
    out
}

fn sub_small(value: Limbs, rhs: u32) -> Limbs {
    let mut out = value;
    let mut borrow = rhs as u64;
    for limb in &mut out {
        if borrow == 0 {
            break;
        }
        let original = *limb as u64;
        *limb = limb.wrapping_sub(borrow as u32);
        borrow = u64::from(original < borrow);
    }
    out
}

fn cmp(lhs: &Limbs, rhs: &Limbs) -> Ordering {
    for i in (0..8).rev() {
        match lhs[i].cmp(&rhs[i]) {
            Ordering::Equal => {},
            ordering => return ordering,
        }
    }
    Ordering::Equal
}

fn bit_is_set<const N: usize>(limbs: &[u32; N], bit: usize) -> bool {
    ((limbs[bit / 32] >> (bit % 32)) & 1) == 1
}

fn add_raw(lhs: Limbs, rhs: Limbs) -> (Limbs, u32) {
    let mut out = [0u32; 8];
    let mut carry = 0u64;
    for i in 0..8 {
        let sum = lhs[i] as u64 + rhs[i] as u64 + carry;
        out[i] = sum as u32;
        carry = sum >> 32;
    }
    (out, carry as u32)
}

fn sub_raw(lhs: Limbs, rhs: Limbs) -> (Limbs, u32) {
    let mut out = [0u32; 8];
    let mut borrow = 0u64;
    for i in 0..8 {
        let subtrahend = rhs[i] as u64 + borrow;
        out[i] = lhs[i].wrapping_sub(subtrahend as u32);
        borrow = u64::from((lhs[i] as u64) < subtrahend);
    }
    (out, borrow as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference path retained as a differential oracle for the Barrett implementation.
    fn mul_mod(lhs: Limbs, rhs: Limbs, modulus: Limbs) -> Limbs {
        reduce_wide(mul_wide(lhs, rhs), modulus)
    }

    /// Reference path retained as a differential oracle for the Barrett implementation.
    fn inv_mod_prime(value: Limbs, modulus: Limbs) -> Option<Limbs> {
        if value == ZERO_LIMBS || modulus == ZERO_LIMBS {
            return None;
        }

        let exponent = sub_small(modulus, 2);
        Some(pow_mod(value, exponent, modulus))
    }

    fn pow_mod(mut base: Limbs, exponent: Limbs, modulus: Limbs) -> Limbs {
        let mut result = ONE_LIMBS;

        for bit in 0..256 {
            if bit_is_set(&exponent, bit) {
                result = mul_mod(result, base, modulus);
            }
            base = mul_mod(base, base, modulus);
        }
        result
    }

    fn reduce_wide(value: [u32; 16], modulus: Limbs) -> Limbs {
        let mut remainder = [0u32; 8];
        for bit in (0..512).rev() {
            let overflow = shl1(&mut remainder);
            if bit_is_set(&value, bit) {
                remainder[0] |= 1;
            }
            if overflow != 0 || !cmp(&remainder, &modulus).is_lt() {
                remainder = sub_raw(remainder, modulus).0;
            }
        }
        remainder
    }

    /// Shifts a little-endian 256-bit value left by one bit and returns the overflow bit. Used by
    /// the reference reduction path.
    fn shl1(limbs: &mut Limbs) -> u32 {
        let mut carry = 0u32;
        for limb in limbs.iter_mut() {
            let next_carry = *limb >> 31;
            *limb = (*limb << 1) | carry;
            carry = next_carry;
        }
        carry
    }

    #[test]
    fn fixed_bound_pointers_round_trip_domains() {
        for (domain, expected_ptr) in UintDomain::ALL.into_iter().zip(1u32..) {
            assert_eq!(domain.bound_ptr(), expected_ptr);
            assert_eq!(UintDomain::from_bound_ptr(expected_ptr), Some(domain));
        }

        assert_eq!(UintDomain::from_bound_ptr(0), None);
        assert_eq!(UintDomain::from_bound_ptr(8), None);
    }

    #[test]
    fn barrett_matches_reference_over_prime_fields() {
        fn next_u32(state: &mut u64) -> u32 {
            *state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (*state >> 32) as u32
        }

        fn rand_reduced(state: &mut u64, modulus: Limbs) -> Limbs {
            let mut wide = [0u32; 16];
            for limb in wide.iter_mut().take(8) {
                *limb = next_u32(state);
            }
            reduce_wide(wide, modulus)
        }

        let moduli = [K1Base::MODULUS, K1Scalar::MODULUS, R1Base::MODULUS, R1Scalar::MODULUS];

        let mut state: u64 = 0x1234_5678_9abc_def0;
        for modulus in moduli {
            let mu = barrett_mu(modulus);
            let max = sub_small(modulus, 1);

            // Edge cases: zero, one, and the largest canonical value.
            let edges = [ZERO_LIMBS, ONE_LIMBS, max];
            for a in edges {
                for b in edges {
                    assert_eq!(mul_mod_barrett(a, b, modulus, mu), mul_mod(a, b, modulus));
                }
            }

            for _ in 0..4000 {
                let a = rand_reduced(&mut state, modulus);
                let b = rand_reduced(&mut state, modulus);
                assert_eq!(
                    mul_mod_barrett(a, b, modulus, mu),
                    mul_mod(a, b, modulus),
                    "barrett mul mismatch"
                );
            }

            for _ in 0..400 {
                let value = rand_reduced(&mut state, modulus);
                assert_eq!(
                    inv_mod_prime_barrett(value, modulus, mu),
                    inv_mod_prime(value, modulus),
                    "barrett inverse mismatch"
                );
            }
        }
    }
}
