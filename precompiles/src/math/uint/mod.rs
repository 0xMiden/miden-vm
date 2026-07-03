//! Fixed-domain 256-bit uint precompile support for deferred evaluation.

mod domain;
pub(crate) mod handlers;
mod precompile;

pub(crate) use self::domain::ZERO_LIMBS;
pub use self::{
    domain::{Limbs, UintDomain, UintSpec},
    precompile::UintPrecompile,
};
