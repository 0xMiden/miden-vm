use alloc::{borrow::Cow, collections::BTreeMap, vec::Vec};
use core::mem::size_of;

use super::{
    MastNodeEntry, MastNodeInfo,
    layout::{OffsetTrackingReader, TrackingReader},
};
use crate::{
    Felt, Word,
    advice::AdviceMap,
    mast::MastNodeId,
    serde::{ByteReader, Deserializable, DeserializationError, SliceReader},
};

const FELT_SERIALIZED_SIZE: usize = size_of::<u64>();

/// Read-only view over a value from forest advice.
#[derive(Debug)]
pub struct AdviceValueView<'a> {
    inner: Cow<'a, [Felt]>,
}

impl<'a> AdviceValueView<'a> {
    pub(crate) fn borrowed(values: &'a [Felt]) -> Self {
        Self { inner: Cow::Borrowed(values) }
    }

    fn owned(values: Vec<Felt>) -> Self {
        Self { inner: Cow::Owned(values) }
    }

    /// Returns the advice values as a slice.
    pub fn as_slice(&self) -> &[Felt] {
        self.inner.as_ref()
    }

    /// Returns the number of field elements in this advice value.
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Returns true when this advice value contains no field elements.
    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }
}

impl AsRef<[Felt]> for AdviceValueView<'_> {
    fn as_ref(&self) -> &[Felt] {
        self.as_slice()
    }
}

/// Read-only view over forest advice.
#[derive(Debug)]
pub struct AdviceMapView<'a> {
    inner: AdviceMapViewInner<'a>,
}

#[derive(Debug)]
enum AdviceMapViewInner<'a> {
    Materialized(&'a AdviceMap),
    Wire(&'a WireAdviceMapView<'a>),
}

impl<'a> AdviceMapView<'a> {
    pub(crate) fn materialized(advice_map: &'a AdviceMap) -> Self {
        Self {
            inner: AdviceMapViewInner::Materialized(advice_map),
        }
    }

    pub(crate) fn wire(advice_map: &'a WireAdviceMapView<'a>) -> Self {
        Self {
            inner: AdviceMapViewInner::Wire(advice_map),
        }
    }

    /// Returns the number of key-value entries in this advice map.
    pub fn len(&self) -> usize {
        match self.inner {
            AdviceMapViewInner::Materialized(advice_map) => advice_map.len(),
            AdviceMapViewInner::Wire(advice_map) => advice_map.len(),
        }
    }

    /// Returns true when this advice map has no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns true when the key has a corresponding value in the map.
    pub fn contains_key(&self, key: &Word) -> bool {
        match self.inner {
            AdviceMapViewInner::Materialized(advice_map) => advice_map.contains_key(key),
            AdviceMapViewInner::Wire(advice_map) => advice_map.contains_key(key),
        }
    }

    /// Returns the values associated with a key, if present.
    pub fn get(&self, key: &Word) -> Result<Option<AdviceValueView<'a>>, DeserializationError> {
        match self.inner {
            AdviceMapViewInner::Materialized(advice_map) => {
                Ok(advice_map.get(key).map(|values| AdviceValueView::borrowed(values.as_ref())))
            },
            AdviceMapViewInner::Wire(advice_map) => advice_map.get(key),
        }
    }
}

#[derive(Debug)]
pub(crate) struct WireAdviceMapView<'a> {
    bytes: &'a [u8],
    entries: BTreeMap<Word, AdviceValueRange>,
    end_offset: usize,
}

#[derive(Debug, Clone, Copy)]
struct AdviceValueRange {
    offset: usize,
    len: usize,
}

impl<'a> WireAdviceMapView<'a> {
    pub(crate) fn new(bytes: &'a [u8], offset: usize) -> Result<Self, DeserializationError> {
        let slice = bytes.get(offset..).ok_or(DeserializationError::UnexpectedEOF)?;
        let mut reader = SliceReader::new(slice);
        let mut reader = TrackingReader::new(&mut reader);
        let entry_count = reader.read_usize()?;
        let mut entries = BTreeMap::new();

        for _ in 0..entry_count {
            let key = Word::read_from(&mut reader)?;
            let len = reader.read_usize()?;
            let value_offset = offset.checked_add(reader.offset()).ok_or_else(|| {
                DeserializationError::InvalidValue("advice value offset overflow".into())
            })?;
            let value_byte_len = len.checked_mul(FELT_SERIALIZED_SIZE).ok_or_else(|| {
                DeserializationError::InvalidValue("advice value length overflow".into())
            })?;
            reader.read_slice(value_byte_len)?;

            if entries.insert(key, AdviceValueRange { offset: value_offset, len }).is_some() {
                return Err(DeserializationError::InvalidValue(
                    "duplicate advice key in wire payload".into(),
                ));
            }
        }

        let end_offset = offset.checked_add(reader.offset()).ok_or_else(|| {
            DeserializationError::InvalidValue("advice map offset overflow".into())
        })?;

        Ok(Self { bytes, entries, end_offset })
    }

    pub(crate) fn end_offset(&self) -> usize {
        self.end_offset
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn contains_key(&self, key: &Word) -> bool {
        self.entries.contains_key(key)
    }

    fn get(&self, key: &Word) -> Result<Option<AdviceValueView<'a>>, DeserializationError> {
        let Some(range) = self.entries.get(key) else {
            return Ok(None);
        };

        let byte_len = range.len.checked_mul(FELT_SERIALIZED_SIZE).ok_or_else(|| {
            DeserializationError::InvalidValue("advice value length overflow".into())
        })?;
        let end = range.offset.checked_add(byte_len).ok_or_else(|| {
            DeserializationError::InvalidValue("advice value offset overflow".into())
        })?;
        let bytes = self.bytes.get(range.offset..end).ok_or(DeserializationError::UnexpectedEOF)?;
        let mut reader = SliceReader::new(bytes);
        let mut values = Vec::with_capacity(range.len);

        for _ in 0..range.len {
            values.push(Felt::read_from(&mut reader)?);
        }

        Ok(Some(AdviceValueView::owned(values)))
    }
}

/// Read-only view over serialization-oriented MAST node metadata.
///
/// This trait lives alongside [`super::MastForestWireView`] because its surface is defined in
/// terms of serialized-equivalent node entries and digests, even though both
/// [`super::MastForestWireView`] and in-memory [`crate::mast::MastForest`] implement it.
pub trait MastForestView {
    /// Returns the number of nodes in the forest.
    fn node_count(&self) -> usize;

    /// Returns fixed-width structural metadata for a node at the specified index.
    ///
    /// Returns an error if `index >= self.node_count()`.
    fn node_entry_at(&self, index: usize) -> Result<MastNodeEntry, DeserializationError>;

    /// Returns the digest of the node at the specified index.
    ///
    /// Returns an error if `index >= self.node_count()`.
    fn node_digest_at(&self, index: usize) -> Result<Word, DeserializationError>;

    /// Returns serialized-equivalent metadata for a node at the specified index.
    ///
    /// Returns an error if `index >= self.node_count()`.
    fn node_info_at(&self, index: usize) -> Result<MastNodeInfo, DeserializationError> {
        Ok(MastNodeInfo::from_entry(
            self.node_entry_at(index)?,
            self.node_digest_at(index)?,
        ))
    }

    /// Returns the number of procedure roots in the forest.
    fn procedure_root_count(&self) -> usize;

    /// Returns the procedure root id at the specified index.
    ///
    /// Returns an error if `index >= self.procedure_root_count()`.
    fn procedure_root_at(&self, index: usize) -> Result<MastNodeId, DeserializationError>;

    /// Returns a read-only view over the forest advice map.
    fn advice_map(&self) -> AdviceMapView<'_>;

    /// Returns true when the forest contains no nodes.
    fn is_empty(&self) -> bool {
        self.node_count() == 0
    }

    /// Returns true when `index` is a valid node index.
    fn has_node(&self, index: usize) -> bool {
        index < self.node_count()
    }

    /// Returns all node infos in index order.
    fn all_node_infos(&self) -> Result<Vec<MastNodeInfo>, DeserializationError> {
        (0..self.node_count()).map(|index| self.node_info_at(index)).collect()
    }

    /// Returns all procedure roots in index order.
    fn procedure_roots(&self) -> Result<Vec<MastNodeId>, DeserializationError> {
        (0..self.procedure_root_count())
            .map(|index| self.procedure_root_at(index))
            .collect()
    }
}
