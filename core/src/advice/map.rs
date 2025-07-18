use alloc::{
    collections::{
        BTreeMap,
        btree_map::{Entry, IntoIter},
    },
    sync::Arc,
    vec::Vec,
};

use crate::{
    Felt, Word,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// ADVICE MAP
// ================================================================================================

/// Defines a set of non-deterministic (advice) inputs which the VM can access by their keys.
///
/// Each key maps to one or more field element. To access the elements, the VM can move the values
/// associated with a given key onto the advice stack using `adv.push_mapval` instruction. The VM
/// can also insert new values into the advice map during execution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdviceMap(BTreeMap<Word, Arc<[Felt]>>);

/// Pair representing a key-value entry in an [`AdviceMap`]
type MapEntry = (Word, Arc<[Felt]>);

impl AdviceMap {
    /// Returns the values associated with given key.
    pub fn get(&self, key: &Word) -> Option<&Arc<[Felt]>> {
        self.0.get(key)
    }

    /// Returns true if the key has a corresponding value in the map.
    pub fn contains_key(&self, key: &Word) -> bool {
        self.0.contains_key(key)
    }

    /// Inserts a value, returning the previous value if the key was already set.
    ///
    /// # Detail
    /// If the existing value is equal to the one provided as input, the entry is left unchanged
    /// and the input is dropped.
    pub fn insert(&mut self, key: Word, value: impl Into<Arc<[Felt]>>) -> Option<Arc<[Felt]>> {
        let value = value.into();
        match self.0.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(value);
            },
            Entry::Occupied(mut entry) => {
                if entry.get() != &value {
                    return Some(entry.insert(value));
                }
            },
        }
        None
    }

    /// Removes the value associated with the key and returns the removed element.
    pub fn remove(&mut self, key: &Word) -> Option<Arc<[Felt]>> {
        self.0.remove(key)
    }

    /// Return an iteration over all entries in the map.
    pub fn iter(&self) -> impl Iterator<Item = (&Word, &Arc<[Felt]>)> {
        self.0.iter()
    }

    /// Returns the number of key value pairs in the advice map.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the advice map is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Gets the given key's corresponding entry in the map for in-place manipulation.
    pub fn entry(&mut self, key: Word) -> Entry<'_, Word, Arc<[Felt]>> {
        self.0.entry(key)
    }

    /// Merges all entries from the given [`AdviceMap`] into the current advice map.
    ///
    /// If an entry from the new map already exists with the same key but different value,
    /// an error is returned containing the existing entry along with the value that would replace
    /// it. The current map remains unchanged.
    pub fn merge(&mut self, other: &Self) -> Result<(), (MapEntry, Arc<[Felt]>)> {
        if let Some(conflict) = self.find_conflicting_entry(other) {
            return Err(conflict);
        }

        for (key, value) in other.iter() {
            self.0.entry(*key).or_insert_with(|| value.clone());
        }
        Ok(())
    }

    /// Finds the first key that exists in both `self` and `other` with different values.
    ///
    /// # Returns
    /// - `Some` containing the conflicting key, its value from `self`, and the value from `other`.
    /// - `None` if there are no conflicting values.
    fn find_conflicting_entry(&self, other: &Self) -> Option<(MapEntry, Arc<[Felt]>)> {
        for (key, new_value) in other.iter() {
            if let Some(existing_value) = self.get(key)
                && existing_value != new_value
            {
                // Found a conflict.
                return Some(((*key, existing_value.clone()), new_value.clone()));
            }
        }
        // No conflicts found.
        None
    }
}

impl From<BTreeMap<Word, Arc<[Felt]>>> for AdviceMap {
    fn from(value: BTreeMap<Word, Arc<[Felt]>>) -> Self {
        Self(value)
    }
}

impl From<BTreeMap<Word, Vec<Felt>>> for AdviceMap {
    fn from(value: BTreeMap<Word, Vec<Felt>>) -> Self {
        value.into_iter().collect()
    }
}

impl IntoIterator for AdviceMap {
    type Item = (Word, Arc<[Felt]>);
    type IntoIter = IntoIter<Word, Arc<[Felt]>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<V> FromIterator<(Word, V)> for AdviceMap
where
    V: Into<Arc<[Felt]>>,
{
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (Word, V)>,
    {
        iter.into_iter()
            .map(|(key, value)| (key, value.into()))
            .collect::<BTreeMap<Word, Arc<[Felt]>>>()
            .into()
    }
}

impl<V> Extend<(Word, V)> for AdviceMap
where
    V: Into<Arc<[Felt]>>,
{
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = (Word, V)>,
    {
        self.0.extend(iter.into_iter().map(|(key, value)| (key, value.into())))
    }
}

impl Serializable for AdviceMap {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.0.len());
        for (key, values) in self.0.iter() {
            target.write((key, values.to_vec()));
        }
    }
}

impl Deserializable for AdviceMap {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut map = BTreeMap::new();
        let count = source.read_usize()?;
        for _ in 0..count {
            let (key, values): (Word, Vec<Felt>) = source.read()?;
            map.insert(key, Arc::from(values));
        }
        Ok(Self(map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_advice_map_serialization() {
        let mut map1 = AdviceMap::default();
        map1.insert(Word::default(), vec![Felt::from(1u32), Felt::from(2u32)]);

        let bytes = map1.to_bytes();

        let map2 = AdviceMap::read_from_bytes(&bytes).unwrap();

        assert_eq!(map1, map2);
    }
}
