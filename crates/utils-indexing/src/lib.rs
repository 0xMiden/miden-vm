//! Type-safe u32-indexed vector utilities for Miden
//!
//! This module provides utilities for working with u32-indexed vectors in a type-safe manner,
//! including the `IndexVec` type and related functionality.
#![no_std]

extern crate alloc;

#[doc = include_str!("../README.md")]
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{fmt::Debug, marker::PhantomData, ops};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error returned when too many items are added to an IndexedVec.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IndexedVecError {
    /// The number of items exceeds the maximum supported by ID type.
    #[error("IndexedVec contains maximum number of items")]
    TooManyItems,
}

/// A trait for u32-backed, 0-based IDs.
pub trait Idx: Copy + Eq + Ord + Debug + From<u32> + Into<u32> {
    /// Convert from this ID type to usize.
    #[inline]
    fn to_usize(self) -> usize {
        self.into() as usize
    }
}

/// Macro to create a newtyped ID that implements Idx.
#[macro_export]
macro_rules! newtype_id {
    ($name:ident) => {
        #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
        #[repr(transparent)]
        pub struct $name(u32);

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }
        impl From<u32> for $name {
            fn from(v: u32) -> Self {
                Self(v)
            }
        }
        impl From<$name> for u32 {
            fn from(v: $name) -> Self {
                v.0
            }
        }
        impl $crate::Idx for $name {}
    };
}

/// A dense vector indexed by ID types.
///
/// This provides O(1) access and storage for dense ID-indexed data.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IndexVec<I: Idx, T> {
    raw: Vec<T>,
    _m: PhantomData<I>,
}

impl<I: Idx, T> Default for IndexVec<I, T> {
    fn default() -> Self {
        Self { raw: Vec::new(), _m: PhantomData }
    }
}

impl<I: Idx, T> IndexVec<I, T> {
    /// Create a new empty IndexVec.
    #[inline]
    pub fn new() -> Self {
        Self { raw: Vec::new(), _m: PhantomData }
    }

    /// Create a new IndexVec with pre-allocated capacity.
    #[inline]
    pub fn with_capacity(n: usize) -> Self {
        Self {
            raw: Vec::with_capacity(n),
            _m: PhantomData,
        }
    }

    /// Get the number of elements in the IndexVec.
    #[inline]
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    /// Check if the IndexVec is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// Push an element and return its ID.
    ///
    /// Returns an error if the length would exceed the maximum representable by the ID type.
    #[inline]
    pub fn push(&mut self, v: T) -> Result<I, IndexedVecError> {
        if self.raw.len() >= u32::MAX as usize {
            return Err(IndexedVecError::TooManyItems);
        }
        let id = I::from(self.raw.len() as u32);
        self.raw.push(v);
        Ok(id)
    }

    /// Insert an element at the specified ID.
    ///
    /// This sets the value at the given index. It does **not** insert or shift elements.
    /// If you need to append elements, use `push()` instead.
    ///
    /// # Panics
    /// - If the ID is out of bounds.
    #[inline]
    pub(crate) fn insert_at(&mut self, idx: I, v: T) {
        self.raw[idx.to_usize()] = v;
    }

    /// Get an element by ID, returning None if the ID is out of bounds.
    #[inline]
    pub fn get(&self, idx: I) -> Option<&T> {
        self.raw.get(idx.to_usize())
    }

    /// Get a slice of all elements.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.raw
    }

    /// Consume this IndexVec and return the underlying Vec.
    #[inline]
    pub fn into_inner(self) -> Vec<T> {
        self.raw
    }

    /// Remove an element at the specified index and return it.
    pub fn swap_remove(&mut self, index: usize) -> T {
        self.raw.swap_remove(index)
    }

    /// Check if this IndexVec contains a specific element.
    pub fn contains(&self, item: &T) -> bool
    where
        T: PartialEq,
    {
        self.raw.contains(item)
    }

    /// Get an iterator over the elements in this IndexVec.
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.raw.iter()
    }

    /// Get a mutable iterator over the elements in this IndexVec.
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, T> {
        self.raw.iter_mut()
    }
}

impl<I: Idx, T> ops::Index<I> for IndexVec<I, T> {
    type Output = T;
    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        &self.raw[index.to_usize()]
    }
}

impl<I: Idx, T> ops::IndexMut<I> for IndexVec<I, T> {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        &mut self.raw[index.to_usize()]
    }
}

/// A dense mapping from ID to ID.
///
/// This is equivalent to `IndexVec<From, Option<To>>` and provides
/// efficient dense ID remapping.
#[derive(Clone)]
pub struct DenseIdMap<From: Idx, To: Idx> {
    inner: IndexVec<From, Option<To>>,
}

impl<From: Idx, To: Idx> DenseIdMap<From, To> {
    /// Create a new dense ID mapping with the specified length.
    #[inline]
    pub fn with_len(length: usize) -> Self {
        Self {
            inner: IndexVec { raw: vec![None; length], _m: PhantomData },
        }
    }

    /// Insert a mapping from source ID to target ID.
    ///
    /// # Panics
    ///
    /// Panics if the source ID is beyond the length of this DenseIdMap.
    /// This DenseIdMap should be created with sufficient length to accommodate
    /// all expected source IDs.
    #[inline]
    pub fn insert(&mut self, k: From, v: To) {
        let idx = k.to_usize();
        let len = self.len();

        assert!(idx < len, "source ID {idx} exceeds DenseIdMap length {len}");
        self.inner.insert_at(k, Some(v));
    }

    /// Get the target ID for the given source ID.
    #[inline]
    pub fn get(&self, k: From) -> Option<To> {
        *self.inner.get(k)?
    }

    /// Get the number of source IDs in this mapping.
    #[inline]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the mapping is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// A trait for looking up values by ID.
pub trait LookupByIdx<ID, V>
where
    ID: Idx,
{
    /// Get the value for the given ID.
    fn get(&self, id: ID) -> Option<&V>;
}

/// A trait for looking up values by key that doesn't need to implement Idx.
pub trait LookupByKey<K, V> {
    /// Get the value for the given key.
    fn get(&self, key: &K) -> Option<&V>;
}

impl<I, T> LookupByIdx<I, T> for IndexVec<I, T>
where
    I: Idx,
{
    fn get(&self, id: I) -> Option<&T> {
        IndexVec::get(self, id)
    }
}

impl<K, V> LookupByKey<K, V> for BTreeMap<K, V>
where
    K: Ord,
{
    fn get(&self, key: &K) -> Option<&V> {
        BTreeMap::get(self, key)
    }
}

impl<K, V> LookupByIdx<K, V> for BTreeMap<K, V>
where
    K: Idx,
{
    fn get(&self, id: K) -> Option<&V> {
        BTreeMap::get(self, &id)
    }
}

impl<I, T> LookupByIdx<I, T> for DenseIdMap<I, T>
where
    I: Idx,
    T: Idx,
{
    fn get(&self, id: I) -> Option<&T> {
        IndexVec::get(&self.inner, id).and_then(Option::as_ref)
    }
}

impl<I: Idx, T> IntoIterator for IndexVec<I, T> {
    type Item = T;
    type IntoIter = alloc::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.raw.into_iter()
    }
}

impl<'a, I: Idx, T> IntoIterator for &'a IndexVec<I, T> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::{String, ToString};

    use super::*;

    // Test ID types
    newtype_id!(TestId);
    newtype_id!(TestId2);

    #[test]
    fn test_indexvec_basic() {
        let mut vec = IndexVec::<TestId, String>::new();
        let id1 = vec.push("hello".to_string()).unwrap();
        let id2 = vec.push("world".to_string()).unwrap();

        assert_eq!(vec.len(), 2);
        assert_eq!(&vec[id1], "hello");
        assert_eq!(&vec[id2], "world");
        assert_eq!(vec.get(TestId::from(0)), Some(&"hello".to_string()));
        assert_eq!(vec.get(TestId::from(2)), None);
    }

    #[test]
    fn test_dense_id_map() {
        let mut map = DenseIdMap::<TestId, TestId2>::with_len(2);
        map.insert(TestId::from(0), TestId2::from(10));
        map.insert(TestId::from(1), TestId2::from(11));

        assert_eq!(map.len(), 2);
        assert_eq!(map.get(TestId::from(0)), Some(TestId2::from(10)));
        assert_eq!(map.get(TestId::from(1)), Some(TestId2::from(11)));
        assert_eq!(map.get(TestId::from(2)), None);
    }
}
