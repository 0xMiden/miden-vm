//! Data structures related to Merkle trees based on Poseidon2 hash function.

use super::{EMPTY_WORD, Felt, Word, hash::poseidon2::Poseidon2};

// SUBMODULES
// ================================================================================================

mod empty_roots;
mod error;
mod index;
mod merkle_tree;
mod node;
mod partial_mt;
mod path;
mod sparse_path;

pub mod mmr;
pub mod smt;
pub mod store;

// REEXPORTS
// ================================================================================================

pub use empty_roots::EmptySubtreeRoots;
pub use error::MerkleError;
pub use index::NodeIndex;
pub use merkle_tree::{MerkleTree, path_to_text, tree_to_text};
pub use node::InnerNodeInfo;
pub use partial_mt::PartialMerkleTree;
pub use path::{MerklePath, MerkleProof, RootPath};
pub use sparse_path::SparseMerklePath;

// SERDE HELPERS
// ================================================================================================

/// A sequence whose deserializer never allocates or materializes more than `MAX_LEN` elements.
#[cfg(feature = "serde")]
struct BoundedVec<T, const MAX_LEN: usize>(alloc::vec::Vec<T>);

#[cfg(feature = "serde")]
impl<'de, T, const MAX_LEN: usize> serde::Deserialize<'de> for BoundedVec<T, MAX_LEN>
where
    T: serde::Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct BoundedVecVisitor<T, const MAX_LEN: usize>(core::marker::PhantomData<T>);

        impl<'de, T, const MAX_LEN: usize> serde::de::Visitor<'de> for BoundedVecVisitor<T, MAX_LEN>
        where
            T: serde::Deserialize<'de>,
        {
            type Value = BoundedVec<T, MAX_LEN>;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_fmt(format_args!("a sequence with at most {MAX_LEN} elements"))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                // A deserializer controls the size hint, so cap the initial allocation as well as
                // the number of materialized elements.
                let capacity = seq.size_hint().unwrap_or_default().min(MAX_LEN);
                let mut values = alloc::vec::Vec::with_capacity(capacity);

                while values.len() < MAX_LEN {
                    match seq.next_element()? {
                        Some(value) => values.push(value),
                        None => return Ok(BoundedVec(values)),
                    }
                }

                // Probe for one excess element without deserializing it into `T`. If present,
                // abort immediately rather than consuming the rest of an attacker-sized input.
                if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::invalid_length(MAX_LEN + 1, &self));
                }

                Ok(BoundedVec(values))
            }
        }

        deserializer.deserialize_seq(BoundedVecVisitor(core::marker::PhantomData))
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use alloc::rc::Rc;
    use core::cell::Cell;

    use serde::Deserialize;

    use super::BoundedVec;

    #[test]
    fn bounded_vec_stops_after_the_first_excess_element() {
        struct CountingIter {
            remaining: usize,
            consumed: Rc<Cell<usize>>,
        }

        impl Iterator for CountingIter {
            type Item = serde::de::value::U8Deserializer<serde::de::value::Error>;

            fn next(&mut self) -> Option<Self::Item> {
                if self.remaining == 0 {
                    return None;
                }

                self.remaining -= 1;
                self.consumed.set(self.consumed.get() + 1);
                Some(serde::de::value::U8Deserializer::new(0))
            }

            fn size_hint(&self) -> (usize, Option<usize>) {
                (self.remaining, Some(self.remaining))
            }
        }

        let consumed = Rc::new(Cell::new(0));
        let iter = CountingIter {
            remaining: 100,
            consumed: Rc::clone(&consumed),
        };
        let deserializer =
            serde::de::value::SeqDeserializer::<_, serde::de::value::Error>::new(iter);

        let result = BoundedVec::<u8, 2>::deserialize(deserializer);

        assert!(result.is_err());
        assert_eq!(consumed.get(), 3);
    }
}

// HELPER FUNCTIONS
// ================================================================================================

#[cfg(test)]
const fn int_to_node(value: u64) -> Word {
    use super::ZERO;
    Word::new([Felt::new_unchecked(value), ZERO, ZERO, ZERO])
}

#[cfg(test)]
const fn int_to_leaf(value: u64) -> Word {
    use super::ZERO;
    Word::new([Felt::new_unchecked(value), ZERO, ZERO, ZERO])
}
