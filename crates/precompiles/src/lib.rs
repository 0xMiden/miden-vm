#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub use miden_core::deferred::MAX_DEFERRED_NODES;
use miden_core::deferred::PrecompileRegistry;

mod codec;
mod hash;
mod math;

pub use codec::{chunks_to_bytes_exact, n_chunks};
pub use hash::{HashAssertNode, HashFunction, HashPrecompile, keccak256::Keccak256Precompile};
pub use math::{
    curve::{
        CurveCoefficient, CurveId, CurveNodeRef, CurvePoint, CurvePrecompile, CurveSpec, K1_A_PTR,
        K1_B_PTR, K1_GROUP_PTR, SECP256K1_BETA, SECP256K1_GENERATOR_X, SECP256K1_GENERATOR_Y,
        SECP256K1_ID, SECP256K1_LAMBDA, ShortWeierstrassSpec, curve_coefficients, glv_decompose,
        phi_generator, scalar_mul_mod_n,
    },
    k1_base::K1Base,
    k1_scalar::K1Scalar,
    u256::U256,
    uint::{
        K1_BASE_BOUND_PTR, K1_SCALAR_BOUND_PTR, Limbs, ONE_LIMBS, TWO_LIMBS, U256_BOUND_PTR,
        UintDomain, UintNodeRef, UintPrecompile, UintSpec, ZERO_LIMBS,
    },
};

/// Hard maximum structural depth reachable from a deferred expression root.
pub const MAX_EXPRESSION_DEPTH: usize = miden_core::deferred::MAX_DEFERRED_DAG_DEPTH;

/// Hard maximum logical byte capacity of one deferred data/chunk node.
pub const MAX_CHUNK_NODE_BYTES: usize = miden_core::deferred::MAX_DEFERRED_DATA_BYTES;

/// Hard maximum number of terms accepted by one MSM node.
pub const MAX_MSM_TERMS: usize = miden_core::deferred::MAX_DEFERRED_PAIR_LIST_PAIRS;

/// Hard maximum number of input bytes accepted by one hash precompile assertion.
///
/// This matches [`MAX_CHUNK_NODE_BYTES`], so a maximum-sized hash preimage fits in one framework
/// chunk-list node.
pub const MAX_HASH_INPUT_BYTES: usize = MAX_CHUNK_NODE_BYTES;

// REGISTRY
// ================================================================================================

/// Returns a [`PrecompileRegistry`] containing the precompiles provided by this crate.
///
/// TODO: If constructing the official registry becomes measurable overhead, consider a
/// cached/shared registry for default processor initialization.
pub fn registry() -> PrecompileRegistry {
    PrecompileRegistry::new()
        .with_precompile(Keccak256Precompile::default())
        .with_precompile(UintPrecompile)
        .with_precompile(CurvePrecompile)
}
