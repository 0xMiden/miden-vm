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

/// A sequence deserializer that caps its initial allocation and materialized element count at
/// `MAX_LEN`.
#[cfg(feature = "serde")]
struct BoundedVec<T, const MAX_LEN: usize>(alloc::vec::Vec<T>);

#[cfg(feature = "serde")]
struct RejectExcessElement<const MAX_LEN: usize>;

#[cfg(feature = "serde")]
impl<'de, const MAX_LEN: usize> serde::de::DeserializeSeed<'de> for RejectExcessElement<MAX_LEN> {
    type Value = ();

    fn deserialize<D>(self, _deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Err(serde::de::Error::custom(format_args!(
            "sequence contains more than {MAX_LEN} elements"
        )))
    }
}

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

                // The seed reports an error as soon as `SeqAccess` observes another element. It
                // does not deserialize the element, which may itself be attacker-sized.
                let _ = seq.next_element_seed(RejectExcessElement::<MAX_LEN>)?;

                Ok(BoundedVec(values))
            }
        }

        deserializer.deserialize_seq(BoundedVecVisitor(core::marker::PhantomData))
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use core::cell::Cell;

    use serde::Deserialize;

    use super::BoundedVec;

    #[test]
    fn bounded_vec_caps_allocation_and_stops_after_the_first_excess_element() {
        let consumed = Cell::new(0);
        // Model an attacker-controlled length prefix without materializing the input.
        let iter = (0..usize::MAX).map(|_| {
            consumed.set(consumed.get() + 1);
            serde::de::value::U8Deserializer::<serde::de::value::Error>::new(0)
        });
        let deserializer =
            serde::de::value::SeqDeserializer::<_, serde::de::value::Error>::new(iter);

        let result = BoundedVec::<u8, 2>::deserialize(deserializer);

        assert!(result.is_err());
        assert_eq!(consumed.get(), 3);
    }

    #[test]
    fn bounded_vec_does_not_deserialize_the_first_excess_element() {
        // The third value is deliberately malformed. Once the length limit is reached, its
        // contents must not be visited.
        let error = match serde_json::from_str::<BoundedVec<u8, 2>>("[0, 0, ?]") {
            Ok(_) => panic!("an excess element must be rejected"),
            Err(error) => error,
        };

        let message = format!("{error}");
        assert!(
            message.contains("sequence contains more than 2 elements"),
            "unexpected error: {message}"
        );
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
