use alloc::{
    boxed::Box,
    collections::{BTreeMap, btree_map::IntoIter},
    vec::Vec,
};

use miden_crypto::{Felt, utils::collections::KvMap};

use crate::{
    crypto::hash::RpoDigest,
    // utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable}, TODO(Al)
};

// ADVICE MAP
// ================================================================================================

/// Defines a set of non-deterministic (advice) inputs which the VM can access by their keys.
///
/// Each key maps to one or more field element. To access the elements, the VM can move the values
/// associated with a given key onto the advice stack using `adv.push_mapval` instruction. The VM
/// can also insert new values into the advice map during execution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdviceMap(BTreeMap<RpoDigest, Vec<Felt>>);

impl AdviceMap {
    /// Creates a new advice map.
    pub fn new() -> Self {
        Self(BTreeMap::<RpoDigest, Vec<Felt>>::new())
    }

    /// Returns the values associated with given key.
    pub fn get(&self, key: &RpoDigest) -> Option<&[Felt]> {
        self.0.get(key).map(|v| v.as_slice())
    }

    /// Inserts a key value pair in the advice map and returns the inserted value.
    pub fn insert(&mut self, key: RpoDigest, value: Vec<Felt>) -> Option<Vec<Felt>> {
        self.0.insert(key, value)
    }

    /// Removes the value associated with the key and returns the removed element.
    pub fn remove(&mut self, key: &RpoDigest) -> Option<Vec<Felt>> {
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
}

impl From<BTreeMap<RpoDigest, Vec<Felt>>> for AdviceMap {
    fn from(value: BTreeMap<RpoDigest, Vec<Felt>>) -> Self {
        Self(value)
    }
}

impl IntoIterator for AdviceMap {
    type Item = (RpoDigest, Vec<Felt>);
    type IntoIter = IntoIter<RpoDigest, Vec<Felt>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl FromIterator<(RpoDigest, Vec<Felt>)> for AdviceMap {
    fn from_iter<T: IntoIterator<Item = (RpoDigest, Vec<Felt>)>>(iter: T) -> Self {
        iter.into_iter().collect::<BTreeMap<RpoDigest, Vec<Felt>>>().into()
    }
}

impl KvMap<RpoDigest, Vec<Felt>> for AdviceMap {
    fn get(&self, key: &RpoDigest) -> Option<&Vec<Felt>> {
        self.0.get(key)
    }

    fn contains_key(&self, key: &RpoDigest) -> bool {
        self.0.contains_key(key)
    }

    fn len(&self) -> usize {
        self.len()
    }

    fn insert(&mut self, key: RpoDigest, value: Vec<Felt>) -> Option<Vec<Felt>> {
        self.insert(key, value)
    }

    fn remove(&mut self, key: &RpoDigest) -> Option<Vec<Felt>> {
        self.remove(key)
    }

    fn iter(&self) -> Box<dyn Iterator<Item = (&RpoDigest, &Vec<Felt>)> + '_> {
        Box::new(self.0.iter())
    }
}

impl Extend<(RpoDigest, Vec<Felt>)> for AdviceMap {
    fn extend<T: IntoIterator<Item = (RpoDigest, Vec<Felt>)>>(&mut self, iter: T) {
        self.0.extend(iter)
    }
}
/*
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
    use miden_crypto::PrimeCharacteristicRing;

    use super::*;

    #[test]
    fn test_advice_map_serialization() {
        let mut map1 = AdviceMap::new();
        map1.insert(RpoDigest::default(), vec![Felt::from_u32(1u32), Felt::from_u32(2u32)]);

        let bytes = map1.to_bytes();

        let map2 = AdviceMap::read_from_bytes(&bytes).unwrap();

        assert_eq!(map1, map2);
    }
}
 */
