//! A unified `Felt` for Miden Rust code.
//!
//! This crate provides a single `Felt` type that can be used in both:
//! - On-chain (Wasm + `miden`): `Felt` is backed by a Miden VM felt via compiler intrinsics.
//! - Off-chain (native / non-Miden Wasm): `Felt` is backed by Plonky3's Goldilocks field element.

#![no_std]
#![deny(warnings)]

extern crate alloc;

#[cfg(all(target_family = "wasm", miden))]
mod wasm_miden;
#[cfg(all(target_family = "wasm", miden))]
pub use wasm_miden::{Felt, FeltFromIntError};

#[cfg(not(all(target_family = "wasm", miden)))]
mod native;
#[cfg(all(
    not(all(target_family = "wasm", miden)),
    any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(target_arch = "aarch64", target_feature = "neon"),
        all(target_arch = "wasm32", target_feature = "simd128"),
    )
))]
pub use native::PackedFelt;
#[cfg(not(all(target_family = "wasm", miden)))]
pub use native::{Felt, FeltFromIntError};

pub mod utils;

pub mod word;

// RE-EXPORTS
// ================================================================================================
#[cfg(not(all(target_family = "wasm", miden)))]
pub use p3_field::{
    Algebra, BasedVectorSpace, BoundedPowers, ExtensionField, Field, InjectiveMonomial, Packable,
    PackedValue, PermutationMonomial, Powers, PrimeCharacteristicRing, PrimeField, PrimeField64,
    RawDataSerializable, TwoAdicField, batch_multiplicative_inverse,
    extension::{
        Binomial, BinomialExtensionField, BinomiallyExtendable, ExtensionAlgebra,
        HasTwoAdicBinomialExtension,
    },
    integers::QuotientMap,
};
pub use word::{Word, WordError};
