//! Stateful sponge-like hashers for cryptographic hashing.
//!
//! This crate provides the [`StatefulHasher`] trait and implementations that maintain
//! an evolving state during hashing. This interface is used by commitment schemes and
//! Merkle trees to incrementally absorb data and squeeze out digests.
//!
//! # Implementations
//!
//! - [`StatefulSponge`]: Wraps a permutation with proper sponge semantics
//! - [`SerializingStatefulSponge`]: Serializes field elements to binary before absorbing
//! - [`ChainingHasher`]: Uses chaining mode `H(state || input)` with a regular hasher
//! - [`TruncatingHasher`]: Wraps a hasher and returns a shorter fixed digest (prefix)

#![no_std]

#[cfg(test)]
extern crate alloc;

mod chaining;
mod field_sponge;
mod serializing_sponge;
mod truncating;

#[cfg(test)]
pub mod testing;

pub use chaining::*;
pub use field_sponge::*;
pub use serializing_sponge::*;
pub use truncating::*;

/// Trait for stateful sponge-like hashers.
///
/// A stateful hasher maintains an external state value that evolves as input is
/// absorbed, and from which fixed-size outputs can be squeezed. This interface
/// is used pervasively by commitment schemes and Merkle trees to incrementally
/// absorb rows of matrices and later read out the final digest.
///
/// # Alignment
///
/// Alignment semantics are defined by the separate [`Alignable`] trait.
/// Types implementing `StatefulHasher` typically also implement `Alignable`
/// to expose their alignment characteristics. Callers needing alignment
/// information should require `H: StatefulHasher<...> + Alignable<...>`.
pub trait StatefulHasher<Item, Out>: Clone {
    /// The internal state type that evolves during absorption.
    type State;

    /// Absorb elements into the state with overwrite-mode and zero-padding semantics if applicable.
    fn absorb_into(&self, state: &mut Self::State, input: impl IntoIterator<Item = Item>);

    /// Squeeze an output from the current state.
    fn squeeze(&self, state: &Self::State) -> Out;

    /// One-shot hash of multiple row slices.
    ///
    /// Creates a fresh state, absorbs all rows, and squeezes the result.
    fn hash_rows<'a>(&self, rows: impl IntoIterator<Item = &'a [Item]>) -> Out
    where
        Item: Copy + 'a,
        Self::State: Default,
    {
        let mut state = Self::State::default();
        for row in rows {
            self.absorb_into(&mut state, row.iter().copied());
        }
        self.squeeze(&state)
    }
}

/// Defines alignment for stateful hashers.
///
/// `ALIGNMENT` is the maximum number of "virtual zero input elements" that could
/// be added due to padding. Padding always uses `Default::default()` (zero).
///
/// - `ALIGNMENT = 1` means no padding (always aligned)
/// - `ALIGNMENT = N` means up to `N-1` virtual zero elements could be added
///
/// # Type Parameters
///
/// - `Input`: The type being absorbed (e.g., field element `F`)
/// - `Target`: The type underlying the hasher's state. For a field-native sponge this equals
///   `Input` (e.g., `Alignable<F, F>`); for a serializing sponge it is the binary word type of the
///   inner hasher (e.g., `u32`, `u64`)
///
/// The two type parameters allow distinguishing between different serialization
/// targets. For example, `SerializingStatefulSponge` can implement both
/// `Alignable<F, u32>` and `Alignable<F, u64>` with different alignment values.
///
/// # Examples
///
/// - A field-native sponge with rate `R` implements `Alignable<T, T>` with `ALIGNMENT = R`
/// - A chaining hasher implements `Alignable<F, Target>` with `ALIGNMENT = 1` (no padding)
/// - A serializing wrapper implements `Alignable<F, u32>` and `Alignable<F, u64>` with alignment
///   derived from field size and inner hasher's alignment
pub trait Alignable<Input, Target> {
    /// The alignment width in units of `Input`.
    ///
    /// This represents the maximum number of virtual zero input elements that
    /// could be added due to padding when absorbing input.
    const ALIGNMENT: usize;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{MockBinaryHasher, MockBinaryPermutation};

    /// Compile-time verification that all StatefulHasher implementations
    /// satisfy their generic bounds with mock types.
    #[test]
    fn types_instantiate() {
        // Native sponge: T -> [T; WIDTH] -> [T; OUT]
        let _sponge = StatefulSponge::<_, 8, 4, 2>::new(MockBinaryPermutation::<u64, 8>::default());
        let _: [u64; 8] = Default::default();

        // Serializing sponge: F -> [binary; WIDTH] -> [binary; OUT]
        let inner = StatefulSponge::<_, 8, 4, 2>::new(MockBinaryPermutation::<u64, 8>::default());
        let _serializing: SerializingStatefulSponge<_> = SerializingStatefulSponge::new(inner);
        let _: [u64; 8] = Default::default();

        // Chaining hasher: F -> [binary; N] (digest = state)
        let _chaining: ChainingHasher<MockBinaryHasher> = ChainingHasher::new(MockBinaryHasher);
        let _: [u64; 4] = Default::default();
    }
}
