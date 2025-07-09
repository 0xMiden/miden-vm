use alloc::{
    boxed::Box,
    collections::{BTreeMap, btree_map::IntoIter},
    vec::Vec,
};

use miden_crypto::{Felt, Word, utils::collections::KvMap};

use crate::utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable};

// ADVICE MAP
// ================================================================================================

/// Defines a set of non-deterministic (advice) inputs which the VM can access by their keys.
///
/// Each key maps to one or more field element. To access the elements, the VM can move the values
/// associated with a given key onto the advice stack using `adv.push_mapval` instruction. The VM
/// can also insert new values into the advice map during execution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdviceMap(BTreeMap<Word, Vec<Felt>>);

/// Pair representing a key-value entry in an [`AdviceMap`]
type MapEntry = (Word, Vec<Felt>);

impl AdviceMap {
    /// Creates a new advice map.
    pub fn new() -> Self {
        Self(BTreeMap::<Word, Vec<Felt>>::new())
    }

    /// Returns the values associated with given key.
    pub fn get(&self, key: &Word) -> Option<&[Felt]> {
        self.0.get(key).map(|v| v.as_slice())
    }

    /// Inserts a key value pair in the advice map and returns the inserted value.
    pub fn insert(&mut self, key: Word, value: Vec<Felt>) -> Option<Vec<Felt>> {
        self.0.insert(key, value)
    }

    /// Removes the value associated with the key and returns the removed element.
    pub fn remove(&mut self, key: &Word) -> Option<Vec<Felt>> {
        self.0.remove(key)
    }

    /// Returns the number of key value pairs in the advice map.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the advice map is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Merges all entries from the given [`AdviceMap`] into the current advice map.
    ///
    /// If an entry from the new map already exists with the same key but different value,
    /// an error is returned containing the existing entry along with the value that would replace
    /// it. The current map remains unchanged.
    pub fn merge_advice_map(&mut self, other: &AdviceMap) -> Result<(), (MapEntry, Vec<Felt>)> {
        // Check if any values are already present and different from those we are merging.
        for (key, value) in other.iter() {
            if let Some(existing) = self.get(key)
                && existing != value
            {
                return Err(((*key, existing.to_vec()), value.to_vec()));
            }
        }

        // Insert all other values, overwriting existing ones which we have checked are the same.
        for (key, value) in other.iter() {
            self.insert(*key, value.clone());
        }
        Ok(())
    }
}

impl From<BTreeMap<Word, Vec<Felt>>> for AdviceMap {
    fn from(value: BTreeMap<Word, Vec<Felt>>) -> Self {
        Self(value)
    }
}

impl IntoIterator for AdviceMap {
    type Item = (Word, Vec<Felt>);
    type IntoIter = IntoIter<Word, Vec<Felt>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl FromIterator<(Word, Vec<Felt>)> for AdviceMap {
    fn from_iter<T: IntoIterator<Item = (Word, Vec<Felt>)>>(iter: T) -> Self {
        iter.into_iter().collect::<BTreeMap<Word, Vec<Felt>>>().into()
    }
}

impl KvMap<Word, Vec<Felt>> for AdviceMap {
    fn get(&self, key: &Word) -> Option<&Vec<Felt>> {
        self.0.get(key)
    }

    fn contains_key(&self, key: &Word) -> bool {
        self.0.contains_key(key)
    }

    fn len(&self) -> usize {
        self.len()
    }

    fn insert(&mut self, key: Word, value: Vec<Felt>) -> Option<Vec<Felt>> {
        self.insert(key, value)
    }

    fn remove(&mut self, key: &Word) -> Option<Vec<Felt>> {
        self.remove(key)
    }

    fn iter(&self) -> Box<dyn Iterator<Item = (&Word, &Vec<Felt>)> + '_> {
        Box::new(self.0.iter())
    }
}

impl Extend<(Word, Vec<Felt>)> for AdviceMap {
    fn extend<T: IntoIterator<Item = (Word, Vec<Felt>)>>(&mut self, iter: T) {
        self.0.extend(iter)
    }
}

impl Serializable for AdviceMap {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.0.len());
        for (key, values) in self.0.iter() {
            target.write((key, values));
        }
    }
}

impl Deserializable for AdviceMap {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mut map = BTreeMap::new();
        let count = source.read_usize()?;
        for _ in 0..count {
            let (key, values) = source.read()?;
            map.insert(key, values);
        }
        Ok(Self(map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_advice_map_serialization() {
        let mut map1 = AdviceMap::new();
        map1.insert(Word::default(), vec![Felt::from(1u32), Felt::from(2u32)]);

        let bytes = map1.to_bytes();

        let map2 = AdviceMap::read_from_bytes(&bytes).unwrap();

        assert_eq!(map1, map2);
    }
}
