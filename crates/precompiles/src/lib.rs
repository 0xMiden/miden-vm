#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use miden_core::deferred::PrecompileRegistry;

mod codec;
mod hash;
mod math;

pub use codec::{chunks_to_bytes_exact, n_chunks};
pub use hash::{
    HashAssertNode, HashFunction, HashPrecompile, keccak256::Keccak256Precompile,
    sha512::Sha512Precompile,
};
pub use math::{
    curve::{
        CurveBinaryOp, CurveCoefficient, CurveId, CurveNodeRef, CurveOp, CurvePoint,
        CurvePrecompile, CurveSpec, ED25519_A_PTR, ED25519_B_PTR, ED25519_GENERATOR_X,
        ED25519_GENERATOR_Y, ED25519_GROUP_PTR, ED25519_ID, K1_A_PTR, K1_B_PTR, K1_GROUP_PTR,
        SECP256K1_BETA, SECP256K1_GENERATOR_X, SECP256K1_GENERATOR_Y, SECP256K1_ID,
        SECP256K1_LAMBDA, ShortWeierstrassSpec, curve_coefficients, ed25519_decompress_x,
        glv_decompose, phi_generator, scalar_mul_mod_n,
    },
    ed25519_base::Ed25519Base,
    ed25519_order::Ed25519Order,
    ed25519_scalar::Ed25519Scalar,
    k1_base::K1Base,
    k1_scalar::K1Scalar,
    u256::U256,
    uint::{
        ED25519_BASE_BOUND_PTR, ED25519_ORDER_BOUND_PTR, ED25519_SCALAR_BOUND_PTR,
        K1_BASE_BOUND_PTR, K1_SCALAR_BOUND_PTR, Limbs, ONE_LIMBS, TWO_LIMBS, U256_BOUND_PTR,
        UintBinaryOp, UintDomain, UintNodeRef, UintOp, UintPrecompile, UintSpec, ZERO_LIMBS,
    },
};

// REGISTRY
// ================================================================================================

/// Returns a [`PrecompileRegistry`] containing the precompiles provided by this crate.
///
/// TODO: If constructing the official registry becomes measurable overhead, consider a
/// cached/shared registry for default processor initialization.
pub fn registry() -> PrecompileRegistry {
    PrecompileRegistry::new()
        .with_precompile(Keccak256Precompile::default())
        .with_precompile(Sha512Precompile::default())
        .with_precompile(UintPrecompile)
        .with_precompile(CurvePrecompile)
}
