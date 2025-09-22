use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::*;
use crate::ast::Ident;

/// An [AttributeSet] provides storage and access to all of the attributes attached to a Miden
/// Assembly item, e.g. procedure definition.
///
/// Attributes are unique by name, so if you attempt to add multiple attributes with the same name,
/// the last write wins. In Miden Assembly syntax, multiple key-value attributes are merged
/// automatically, and a syntax error is only generated when keys conflict. All other attribute
/// types produce an error if they are declared multiple times on the same item.
#[derive(Default, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AttributeSet {
    /// The attributes in this set.
    ///
    /// The [AttributeSet] structure has map-like semantics, so why are we using a vector here?
    ///
    /// * We expect attributes to be relatively rare, with no more than a handful on the same item
    ///   at any given time.
    /// * A vector is much more space and time efficient to search for small numbers of items
    /// * We can achieve map-like semantics without O(N) complexity by keeping the vector sorted by
    ///   the attribute name, and using binary search to search it. This gives us O(1) best-case
    ///   performance, and O(log N) in the worst case.
    attrs: Vec<Attribute>,
}

impl AttributeSet {
    /// Create a new [AttributeSet] from `attrs`
    ///
    /// If the input attributes have duplicate entries for the same name, only one will be selected,
    /// but it is unspecified which.
    pub fn new<I>(attrs: I) -> Self
    where
        I: IntoIterator<Item = Attribute>,
    {
        let mut this = Self { attrs: attrs.into_iter().collect() };
        this.attrs.sort_by_key(|attr| attr.id());
        this.attrs.dedup_by_key(|attr| attr.id());
        this
    }

    /// Returns true if there are no attributes in this set
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.attrs.is_empty()
    }

    /// Returns the number of attributes in this set
    #[inline]
    pub fn len(&self) -> usize {
        self.attrs.len()
    }

    /// Check if this set has an attributed named `name`
    pub fn has(&self, name: impl AsRef<str>) -> bool {
        self.get(name).is_some()
    }

    /// Get the attribute named `name`, if one is present.
    pub fn get(&self, name: impl AsRef<str>) -> Option<&Attribute> {
        let name = name.as_ref();
        match self.attrs.binary_search_by_key(&name, |attr| attr.name()) {
            Ok(index) => self.attrs.get(index),
            Err(_) => None,
        }
    }

    /// Get a mutable reference to the attribute named `name`, if one is present.
    pub fn get_mut(&mut self, name: impl AsRef<str>) -> Option<&mut Attribute> {
        let name = name.as_ref();
        match self.attrs.binary_search_by_key(&name, |attr| attr.name()) {
            Ok(index) => self.attrs.get_mut(index),
            Err(_) => None,
        }
    }

    /// Get an iterator over the attributes in this set
    #[inline]
    pub fn iter(&self) -> core::slice::Iter<'_, Attribute> {
        self.attrs.iter()
    }

    /// Get a mutable iterator over the attributes in this set
    #[inline]
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, Attribute> {
        self.attrs.iter_mut()
    }

    /// Insert `attr` in the attribute set, replacing any existing attribute with the same name
    ///
    /// Returns true if the insertion was new, or false if the insertion replaced an existing entry.
    pub fn insert(&mut self, attr: Attribute) -> bool {
        let name = attr.name();
        match self.attrs.binary_search_by_key(&name, |attr| attr.name()) {
            Ok(index) => {
                // Replace existing attribute
                self.attrs[index] = attr;
                false
            },
            Err(index) => {
                self.attrs.insert(index, attr);
                true
            },
        }
    }

    /// Insert `attr` in the attribute set, but only if there is no existing attribute with the same
    /// name.
    ///
    /// Returns `Err` with `attr` if there is already an existing attribute with the same name.
    pub fn insert_new(&mut self, attr: Attribute) -> Result<(), Attribute> {
        if self.has(attr.name()) {
            Err(attr)
        } else {
            self.insert(attr);
            Ok(())
        }
    }

    /// Removes the attribute named `name`, if present.
    pub fn remove(&mut self, name: impl AsRef<str>) -> Option<Attribute> {
        let name = name.as_ref();
        match self.attrs.binary_search_by_key(&name, |attr| attr.name()) {
            Ok(index) => Some(self.attrs.remove(index)),
            Err(_) => None,
        }
    }

    /// Gets the given key's corresponding entry in the set for in-place modfication
    pub fn entry(&mut self, key: Ident) -> AttributeSetEntry<'_> {
        match self.attrs.binary_search_by_key(&key.as_str(), |attr| attr.name()) {
            Ok(index) => AttributeSetEntry::occupied(self, index),
            Err(index) => AttributeSetEntry::vacant(self, key, index),
        }
    }

    /// Clear all attributes from the set
    #[inline]
    pub fn clear(&mut self) {
        self.attrs.clear();
    }
}

impl fmt::Debug for AttributeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_map();
        for attr in self.iter() {
            match attr.metadata() {
                None => {
                    builder.entry(&attr.name(), &"None");
                },
                Some(meta) => {
                    builder.entry(&attr.name(), &meta);
                },
            }
        }
        builder.finish()
    }
}

impl FromIterator<Attribute> for AttributeSet {
    #[inline]
    fn from_iter<T: IntoIterator<Item = Attribute>>(iter: T) -> Self {
        Self::new(iter)
    }
}

impl Extend<Attribute> for AttributeSet {
    fn extend<T: IntoIterator<Item = Attribute>>(&mut self, iter: T) {
        for attr in iter {
            self.insert(attr);
        }
    }
}

/// Represents an entry under a specific key in a [AttributeSet]
pub enum AttributeSetEntry<'a> {
    /// The entry is currently occupied with a value
    Occupied(AttributeSetOccupiedEntry<'a>),
    /// The entry is currently vacant
    Vacant(AttributeSetVacantEntry<'a>),
}
impl<'a> AttributeSetEntry<'a> {
    fn occupied(set: &'a mut AttributeSet, index: usize) -> Self {
        Self::Occupied(AttributeSetOccupiedEntry { set, index })
    }

    fn vacant(set: &'a mut AttributeSet, key: Ident, index: usize) -> Self {
        Self::Vacant(AttributeSetVacantEntry { set, key, index })
    }
}

#[doc(hidden)]
pub struct AttributeSetOccupiedEntry<'a> {
    set: &'a mut AttributeSet,
    index: usize,
}
impl AttributeSetOccupiedEntry<'_> {
    #[inline]
    pub fn get(&self) -> &Attribute {
        &self.set.attrs[self.index]
    }

    #[inline]
    pub fn get_mut(&mut self) -> &mut Attribute {
        &mut self.set.attrs[self.index]
    }

    pub fn insert(self, attr: Attribute) {
        if attr.name() != self.get().name() {
            self.set.insert(attr);
        } else {
            self.set.attrs[self.index] = attr;
        }
    }

    #[inline]
    pub fn remove(self) -> Attribute {
        self.set.attrs.remove(self.index)
    }
}

#[doc(hidden)]
pub struct AttributeSetVacantEntry<'a> {
    set: &'a mut AttributeSet,
    key: Ident,
    index: usize,
}
impl AttributeSetVacantEntry<'_> {
    pub fn insert(self, attr: Attribute) {
        if self.key != attr.id() {
            self.set.insert(attr);
        } else {
            self.set.attrs.insert(self.index, attr);
        }
    }
}

#[cfg(feature = "arbitrary")]
impl proptest::arbitrary::Arbitrary for AttributeSet {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::{arbitrary::any, strategy::Strategy};

        let items = proptest::collection::vec(any::<Attribute>(), 1..3);
        items.prop_map(|attrs| Self { attrs }).boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

impl Serializable for AttributeSet {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.attrs.write_into(target)
    }
}

impl Deserializable for AttributeSet {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let attrs = Vec::read_from(source)?;
        Ok(Self { attrs })
    }
}
