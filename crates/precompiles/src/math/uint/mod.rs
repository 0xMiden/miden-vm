//! Fixed-domain 256-bit uint precompile support for deferred evaluation.

mod arithmetic;
mod domain;
mod precompile;
mod spec;

pub use self::{
    domain::{K1_BASE_BOUND_PTR, K1_SCALAR_BOUND_PTR, U256_BOUND_PTR, UintDomain},
    precompile::{UintNodeRef, UintPrecompile},
    spec::{Limbs, ONE_LIMBS, TWO_LIMBS, UintSpec, ZERO_LIMBS},
};
