//! Fixed-domain 256-bit uint precompile support for deferred evaluation.

mod domain;
pub(crate) mod handlers;
mod precompile;

pub(crate) use self::domain::ZERO_LIMBS;
pub use self::{
    domain::{K1_BASE_BOUND_PTR, K1_SCALAR_BOUND_PTR, Limbs, U256_BOUND_PTR, UintDomain, UintSpec},
    precompile::{UintNodeRef, UintPrecompile},
};
