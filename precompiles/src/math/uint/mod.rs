//! Fixed-domain 256-bit uint deferred precompile support.

mod domain;
pub(crate) mod handlers;
mod precompile;

pub(crate) use self::domain::ZERO_LIMBS;
pub use self::{
    domain::{
        ED25519_BASE_BOUND_PTR, ED25519_SCALAR_BOUND_PTR, K1_BASE_BOUND_PTR, K1_SCALAR_BOUND_PTR,
        Limbs, R1_BASE_BOUND_PTR, R1_SCALAR_BOUND_PTR, U256_BOUND_PTR, UintDomain, UintSpec,
    },
    precompile::UintPrecompile,
};
