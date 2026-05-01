use alloc::{string::ToString, vec::Vec};

use super::EMPTY_WORD;
use crate::{
    Felt, Word,
    hash::poseidon2::Poseidon2,
    merkle::smt::{LEAF_DOMAIN, LeafIndex, MAX_LEAF_ENTRIES, SMT_DEPTH, SmtLeafError},
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

/// The number of field elements in a key-value pair (two Words, 4 Felts each).
const DOUBLE_WORD_LEN: usize = 8;

/// Represents a leaf node in the Sparse Merkle Tree.
///
/// A leaf can be empty, hold a single key-value pair, or multiple key-value pairs.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum SmtLeaf {
    /// An empty leaf at the specified index.
    Empty(LeafIndex<SMT_DEPTH>),
    /// A leaf containing a single key-value pair.
    Single((Word, Word)),
    /// A leaf containing multiple key-value pairs.
    Multiple(Vec<(Word, Word)>),
}

impl SmtLeaf {
    // CONSTRUCTORS
    // ---------------------------------------------------------------------------------------------

    /// Returns a new leaf with the specified entries
    ///
    /// # Errors
    ///   - Returns an error if 2 keys in `entries` map to a different leaf index
    ///   - Returns an error if 1 or more keys in `entries` map to a leaf index different from
    ///     `leaf_index`
    pub fn new(
        entries: Vec<(Word, Word)>,
        leaf_index: LeafIndex<SMT_DEPTH>,
    ) -> Result<Self, SmtLeafError> {
        match entries.len() {
            0 => Ok(Self::new_empty(leaf_index)),
            1 => {
                let (key, value) = entries[0];

                let computed_index = LeafIndex::<SMT_DEPTH>::from(key);
                if computed_index != leaf_index {
                    return Err(SmtLeafError::InconsistentSingleLeafIndices {
                        key,
                        expected_leaf_index: leaf_index,
                        actual_leaf_index: computed_index,
                    });
                }

                Ok(Self::new_single(key, value))
            },
            _ => {
                let leaf = Self::new_multiple(entries)?;

                // `new_multiple()` checked that all keys map to the same leaf index. We still need
                // to ensure that leaf index is `leaf_index`.
                if leaf.index() != leaf_index {
                    Err(SmtLeafError::InconsistentMultipleLeafIndices {
                        leaf_index_from_keys: leaf.index(),
                        leaf_index_supplied: leaf_index,
                    })
                } else {
                    Ok(leaf)
                }
            },
        }
    }

    /// Returns a new empty leaf with the specified leaf index
    pub fn new_empty(leaf_index: LeafIndex<SMT_DEPTH>) -> Self {
        Self::Empty(leaf_index)
    }

    /// Returns a new single leaf with the specified entry. The leaf index is derived from the
    /// entry's key.
    pub fn new_single(key: Word, value: Word) -> Self {
        Self::Single((key, value))
    }

    /// Returns a new multiple leaf with the specified entries. The leaf index is derived from the
    /// entries' keys.
    ///
    /// # Errors
    ///   - Returns an error if 2 keys in `entries` map to a different leaf index
    ///   - Returns an error if the number of entries exceeds [`MAX_LEAF_ENTRIES`]
    pub fn new_multiple(entries: Vec<(Word, Word)>) -> Result<Self, SmtLeafError> {
        if entries.len() < 2 {
            return Err(SmtLeafError::MultipleLeafRequiresTwoEntries(entries.len()));
        }

        if entries.len() > MAX_LEAF_ENTRIES {
            return Err(SmtLeafError::TooManyLeafEntries { actual: entries.len() });
        }

        // Check that all keys map to the same leaf index
        {
            let mut keys = entries.iter().map(|(key, _)| key);

            let first_key = *keys.next().expect("ensured at least 2 entries");
            let first_leaf_index: LeafIndex<SMT_DEPTH> = first_key.into();

            for &next_key in keys {
                let next_leaf_index: LeafIndex<SMT_DEPTH> = next_key.into();

                if next_leaf_index != first_leaf_index {
                    return Err(SmtLeafError::InconsistentMultipleLeafKeys {
                        key_1: first_key,
                        key_2: next_key,
                    });
                }
            }
        }

        Ok(Self::Multiple(entries))
    }

    // PUBLIC ACCESSORS
    // ---------------------------------------------------------------------------------------------

    /// Returns the value associated with `key` in the leaf, or `None` if `key` maps to another
    /// leaf.
    pub fn get_value(&self, key: &Word) -> Option<Word> {
        // Ensure that `key` maps to this leaf
        if self.index() != (*key).into() {
            return None;
        }

        match self {
            SmtLeaf::Empty(_) => Some(EMPTY_WORD),
            SmtLeaf::Single((key_in_leaf, value_in_leaf)) => {
                if key == key_in_leaf {
                    Some(*value_in_leaf)
                } else {
                    Some(EMPTY_WORD)
                }
            },
            SmtLeaf::Multiple(kv_pairs) => {
                for (key_in_leaf, value_in_leaf) in kv_pairs {
                    if key == key_in_leaf {
                        return Some(*value_in_leaf);
                    }
                }

                Some(EMPTY_WORD)
            },
        }
    }

    /// Returns true if the leaf is empty
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Empty(_))
    }

    /// Returns the leaf's index in the [`super::Smt`]
    pub fn index(&self) -> LeafIndex<SMT_DEPTH> {
        match self {
            SmtLeaf::Empty(leaf_index) => *leaf_index,
            SmtLeaf::Single((key, _)) => (*key).into(),
            SmtLeaf::Multiple(entries) => {
                // Note: All keys are guaranteed to have the same leaf index
                let (first_key, _) = entries[0];
                first_key.into()
            },
        }
    }

    /// Returns the number of entries stored in the leaf
    pub fn num_entries(&self) -> usize {
        match self {
            SmtLeaf::Empty(_) => 0,
            SmtLeaf::Single(_) => 1,
            SmtLeaf::Multiple(entries) => entries.len(),
        }
    }

    /// Computes the hash of the leaf
    pub fn hash(&self) -> Word {
        match self {
            SmtLeaf::Empty(_) => EMPTY_WORD,
            SmtLeaf::Single((key, value)) => {
                Poseidon2::merge_in_domain(&[*key, *value], LEAF_DOMAIN)
            },
            SmtLeaf::Multiple(kvs) => {
                let elements: Vec<Felt> = kvs.iter().copied().flat_map(kv_to_elements).collect();
                Poseidon2::hash_elements_in_domain(&elements, LEAF_DOMAIN)
            },
        }
    }

    // ITERATORS
    // ---------------------------------------------------------------------------------------------

    /// Returns a slice with key-value pairs in the leaf.
    pub fn entries(&self) -> &[(Word, Word)] {
        match self {
            SmtLeaf::Empty(_) => &[],
            SmtLeaf::Single(kv_pair) => core::slice::from_ref(kv_pair),
            SmtLeaf::Multiple(kv_pairs) => kv_pairs,
        }
    }

    // CONVERSIONS
    // ---------------------------------------------------------------------------------------------

    /// Returns an iterator over the field elements representing this leaf.
    pub fn to_elements(&self) -> impl Iterator<Item = Felt> + '_ {
        self.entries().iter().copied().flat_map(kv_to_elements)
    }

    /// Returns an iterator over the key-value pairs in the leaf.
    pub fn to_entries(&self) -> impl Iterator<Item = (&Word, &Word)> + '_ {
        // Needed for type conversion from `&(T, T)` to `(&T, &T)`.
        self.entries().iter().map(|(k, v)| (k, v))
    }

    /// Converts a leaf to a list of field elements.
    pub fn into_elements(self) -> Vec<Felt> {
        self.into_entries().into_iter().flat_map(kv_to_elements).collect()
    }

    /// Converts a leaf the key-value pairs in the leaf
    pub fn into_entries(self) -> Vec<(Word, Word)> {
        match self {
            SmtLeaf::Empty(_) => Vec::new(),
            SmtLeaf::Single(kv_pair) => vec![kv_pair],
            SmtLeaf::Multiple(kv_pairs) => kv_pairs,
        }
    }

    /// Converts a list of elements into a leaf
    pub fn try_from_elements(
        elements: &[Felt],
        leaf_index: LeafIndex<SMT_DEPTH>,
    ) -> Result<SmtLeaf, SmtLeafError> {
        if elements.is_empty() {
            return Ok(SmtLeaf::new_empty(leaf_index));
        }

        // Elements should be organized into a contiguous array of K/V Words (4 Felts each).
        if !elements.len().is_multiple_of(DOUBLE_WORD_LEN) {
            return Err(SmtLeafError::DecodingError(
                "elements length is not a multiple of 8".into(),
            ));
        }

        let num_entries = elements.len() / DOUBLE_WORD_LEN;

        if num_entries == 1 {
            // Single entry.
            let key = Word::new([elements[0], elements[1], elements[2], elements[3]]);
            let value = Word::new([elements[4], elements[5], elements[6], elements[7]]);
            Ok(SmtLeaf::new_single(key, value))
        } else {
            // Multiple entries.
            let mut entries = Vec::with_capacity(num_entries);
            // Read k/v pairs from each entry.
            for i in 0..num_entries {
                let base_idx = i * DOUBLE_WORD_LEN;
                let key = Word::new([
                    elements[base_idx],
                    elements[base_idx + 1],
                    elements[base_idx + 2],
                    elements[base_idx + 3],
                ]);
                let value = Word::new([
                    elements[base_idx + 4],
                    elements[base_idx + 5],
                    elements[base_idx + 6],
                    elements[base_idx + 7],
                ]);
                entries.push((key, value));
            }
            let leaf = SmtLeaf::new_multiple(entries)?;
            Ok(leaf)
        }
    }

    // HELPERS
    // ---------------------------------------------------------------------------------------------

    /// Inserts key-value pair into the leaf; returns the previous value associated with `key`, if
    /// any.
    ///
    /// The caller needs to ensure that `key` has the same leaf index as all other keys in the leaf
    ///
    /// # Errors
    /// Returns an error if inserting the key-value pair would exceed [`MAX_LEAF_ENTRIES`] (1024
    /// entries) in the leaf.
    pub(in crate::merkle::smt) fn insert(
        &mut self,
        key: Word,
        value: Word,
    ) -> Result<Option<Word>, SmtLeafError> {
        match self {
            SmtLeaf::Empty(_) => {
                *self = SmtLeaf::new_single(key, value);
                Ok(None)
            },
            SmtLeaf::Single(kv_pair) => {
                if kv_pair.0 == key {
                    // the key is already in this leaf. Update the value and return the previous
                    // value
                    let old_value = kv_pair.1;
                    kv_pair.1 = value;
                    Ok(Some(old_value))
                } else {
                    // Another entry is present in this leaf. Transform the entry into a list
                    // entry, and make sure the key-value pairs are sorted by key
                    // This stays within MAX_LEAF_ENTRIES limit. We're only adding one entry to a
                    // single leaf
                    let mut pairs = vec![*kv_pair, (key, value)];
                    pairs.sort_by(|(key_1, _), (key_2, _)| key_1.cmp(key_2));
                    *self = SmtLeaf::Multiple(pairs);
                    Ok(None)
                }
            },
            SmtLeaf::Multiple(kv_pairs) => {
                match kv_pairs.binary_search_by(|kv_pair| kv_pair.0.cmp(&key)) {
                    Ok(pos) => {
                        let old_value = kv_pairs[pos].1;
                        kv_pairs[pos].1 = value;
                        Ok(Some(old_value))
                    },
                    Err(pos) => {
                        if kv_pairs.len() >= MAX_LEAF_ENTRIES {
                            return Err(SmtLeafError::TooManyLeafEntries {
                                actual: kv_pairs.len() + 1,
                            });
                        }
                        kv_pairs.insert(pos, (key, value));
                        Ok(None)
                    },
                }
            },
        }
    }

    /// Removes key-value pair from the leaf stored at key; returns the previous value associated
    /// with `key`, if any. Also returns an `is_empty` flag, indicating whether the leaf became
    /// empty, and must be removed from the data structure it is contained in.
    pub(in crate::merkle::smt) fn remove(&mut self, key: Word) -> (Option<Word>, bool) {
        match self {
            SmtLeaf::Empty(_) => (None, false),
            SmtLeaf::Single((key_at_leaf, value_at_leaf)) => {
                if *key_at_leaf == key {
                    // our key was indeed stored in the leaf, so we return the value that was stored
                    // in it, and indicate that the leaf should be removed
                    let old_value = *value_at_leaf;

                    // Note: this is not strictly needed, since the caller is expected to drop this
                    // `SmtLeaf` object.
                    *self = SmtLeaf::new_empty(key.into());

                    (Some(old_value), true)
                } else {
                    // another key is stored at leaf; nothing to update
                    (None, false)
                }
            },
            SmtLeaf::Multiple(kv_pairs) => {
                match kv_pairs.binary_search_by(|kv_pair| kv_pair.0.cmp(&key)) {
                    Ok(pos) => {
                        let old_value = kv_pairs[pos].1;

                        let _ = kv_pairs.remove(pos);
                        debug_assert!(!kv_pairs.is_empty());

                        if kv_pairs.len() == 1 {
                            // convert the leaf into `Single`
                            *self = SmtLeaf::Single(kv_pairs[0]);
                        }

                        (Some(old_value), false)
                    },
                    Err(_) => {
                        // other keys are stored at leaf; nothing to update
                        (None, false)
                    },
                }
            },
        }
    }
}

impl Serializable for SmtLeaf {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        // Write: num entries
        self.num_entries().write_into(target);

        // Write: leaf index
        let leaf_index: u64 = self.index().position();
        leaf_index.write_into(target);

        // Write: entries
        for (key, value) in self.entries() {
            key.write_into(target);
            value.write_into(target);
        }
    }
}

impl Deserializable for SmtLeaf {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        // Read: num entries
        let num_entries = source.read_usize()?;

        // Read: leaf index
        let leaf_index: LeafIndex<SMT_DEPTH> = {
            let value = source.read_u64()?;
            LeafIndex::new_max_depth(value)
        };

        // Read: entries using read_many_iter to avoid eager allocation
        let entries: Vec<(Word, Word)> =
            source.read_many_iter(num_entries)?.collect::<Result<_, _>>()?;

        Self::new(entries, leaf_index)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }

    /// Minimum serialized size: vint64 (num_entries) + u64 (leaf_index) with 0 entries.
    fn min_serialized_size() -> usize {
        1 + 8
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Converts a key-value tuple to an iterator of `Felt`s
pub(crate) fn kv_to_elements((key, value): (Word, Word)) -> impl Iterator<Item = Felt> {
    let key_elements = key.into_iter();
    let value_elements = value.into_iter();

    key_elements.chain(value_elements)
}
