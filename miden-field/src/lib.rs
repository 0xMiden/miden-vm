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
pub use wasm_miden::Felt;

#[cfg(not(all(target_family = "wasm", miden)))]
mod native;
#[cfg(not(all(target_family = "wasm", miden)))]
pub use native::{Felt, FeltFromIntError};

pub mod utils;

pub mod word;

// RE-EXPORTS
// ================================================================================================
#[cfg(not(all(target_family = "wasm", miden)))]
pub use p3_field::{
    Algebra, BasedVectorSpace, BoundedPowers, ExtensionField, Field, InjectiveMonomial, Packable,
    PermutationMonomial, Powers, PrimeCharacteristicRing, PrimeField, PrimeField64,
    RawDataSerializable, TwoAdicField, batch_multiplicative_inverse,
    extension::{
        BinomialExtensionField, BinomiallyExtendable, BinomiallyExtendableAlgebra,
        HasTwoAdicBinomialExtension,
    },
    integers::QuotientMap,
};
pub use word::{Word, WordError};
