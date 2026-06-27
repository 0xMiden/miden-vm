//! Fixed-domain 256-bit uint deferred precompile support.

mod arithmetic;
mod domain;
pub(crate) mod handlers;
mod precompile;

pub(crate) use self::domain::ZERO_LIMBS;
#[cfg(feature = "codegen-tools")]
pub(crate) use self::domain::{ONE_LIMBS, TWO_LIMBS};
pub use self::{
    domain::{Limbs, UintDomain, UintSpec},
    precompile::UintPrecompile,
};
