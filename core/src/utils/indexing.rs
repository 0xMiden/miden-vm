use alloc::{collections::BTreeMap, vec::Vec};
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
        impl $crate::utils::indexing::Idx for $name {}
    };
}

/// A dense vector indexed by ID types.
///
/// This provides O(1) access and storage for dense ID-indexed data.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IndexVec<I: Idx, T> {
    raw: Vec<T>,
    _m: PhantomData<I>,
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
    /// # Panics
    /// - If the ID is out of bounds.
    #[inline]
    pub fn insert_at(&mut self, idx: I, v: T) {
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
/// This is equivalent to IndexVec<From, Option<To>> and provides
/// efficient dense ID remapping.
#[derive(Clone)]
pub struct DenseIdMap<From: Idx, To: Idx> {
    inner: IndexVec<From, Option<To>>,
}

impl<From: Idx, To: Idx> DenseIdMap<From, To> {
    /// Create a new dense ID mapping with the specified number of source IDs.
    #[inline]
    pub fn new(num_from: usize) -> Self {
        Self {
            inner: IndexVec {
                raw: vec![None; num_from],
                _m: PhantomData,
            },
        }
    }

    /// Insert a mapping from source ID to target ID.
    #[inline]
    pub fn insert(&mut self, k: From, v: To) {
        let idx = k.to_usize();
        // Ensure the vector is large enough to accommodate this index
        if idx >= self.inner.len() {
            self.inner.raw.resize(idx + 1, None);
        }
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

/// A trait for looking up fingerprints by node ID with generic fingerprint type.
pub trait FingerPrintLookup<ID, F>
where
    ID: Idx,
{
    /// Get the fingerprint for the given node ID.
    fn get(&self, id: ID) -> Option<&F>;
}

impl<I, T> FingerPrintLookup<I, T> for IndexVec<I, T>
where
    I: Idx,
{
    fn get(&self, id: I) -> Option<&T> {
        IndexVec::get(self, id)
    }
}

impl<K, V> FingerPrintLookup<K, V> for BTreeMap<K, V>
where
    K: Idx,
{
    fn get(&self, id: K) -> Option<&V> {
        self.get(&id)
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
        let mut map = DenseIdMap::<TestId, TestId2>::new(2);
        map.insert(TestId::from(0), TestId2::from(10));
        map.insert(TestId::from(1), TestId2::from(11));

        assert_eq!(map.len(), 2);
        assert_eq!(map.get(TestId::from(0)), Some(TestId2::from(10)));
        assert_eq!(map.get(TestId::from(1)), Some(TestId2::from(11)));
        assert_eq!(map.get(TestId::from(2)), None);
    }
}
