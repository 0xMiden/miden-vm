use alloc::{string::ToString, vec::Vec};

use super::{
    FLAG_HASHLESS, FLAG_STRIPPED, FLAGS_RESERVED_MASK, MAGIC, MastForest, MastNodeEntry, VERSION,
};
use crate::{
    mast::serialization::info::MastNodeType,
    serde::{ByteReader, Deserializable, DeserializationError},
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct ForestLayout {
    pub(super) node_count: usize,
    pub(super) roots_count: usize,
    pub(super) roots_offset: usize,
    pub(super) basic_block_offset: usize,
    pub(super) basic_block_len: usize,
    pub(super) node_entry_offset: usize,
    pub(super) node_entry_size: usize,
    pub(super) external_digest_offset: usize,
    #[cfg(test)]
    pub(super) external_digest_count: usize,
    pub(super) node_hash_offset: Option<usize>,
    #[cfg(test)]
    pub(super) node_hash_count: usize,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct WireFlags(u8);

impl ForestLayout {
    pub(crate) fn is_hashless(&self) -> bool {
        self.node_hash_offset.is_none()
    }

    pub(super) fn resolve(mut self) -> Result<Self, DeserializationError> {
        let header_len = MAGIC.len() + 1 + VERSION.len();
        self.roots_offset = header_len.checked_add(self.roots_offset).ok_or_else(|| {
            DeserializationError::InvalidValue("roots offset overflow".to_string())
        })?;
        self.basic_block_offset =
            header_len.checked_add(self.basic_block_offset).ok_or_else(|| {
                DeserializationError::InvalidValue("basic-block offset overflow".to_string())
            })?;
        self.node_entry_offset =
            header_len.checked_add(self.node_entry_offset).ok_or_else(|| {
                DeserializationError::InvalidValue("node entry offset overflow".to_string())
            })?;
        self.external_digest_offset =
            header_len.checked_add(self.external_digest_offset).ok_or_else(|| {
                DeserializationError::InvalidValue("external digest offset overflow".to_string())
            })?;
        self.node_hash_offset = self
            .node_hash_offset
            .map(|offset| {
                header_len.checked_add(offset).ok_or_else(|| {
                    DeserializationError::InvalidValue("node hash offset overflow".to_string())
                })
            })
            .transpose()?;

        Ok(self)
    }
}

impl WireFlags {
    pub(super) fn new(bits: u8) -> Result<Self, DeserializationError> {
        let flags = Self(bits);
        if flags.is_hashless() && !flags.is_stripped() {
            return Err(DeserializationError::InvalidValue(
                "HASHLESS flag requires STRIPPED flag to be set".to_string(),
            ));
        }

        Ok(flags)
    }

    pub(super) fn bits(self) -> u8 {
        self.0
    }

    pub(super) fn is_stripped(self) -> bool {
        self.0 & FLAG_STRIPPED != 0
    }

    pub(super) fn is_hashless(self) -> bool {
        self.0 & FLAG_HASHLESS != 0
    }
}

pub(super) fn read_header_and_scan_layout<R: OffsetTrackingReader>(
    source: &mut R,
    allow_hashless: bool,
) -> Result<(WireFlags, ForestLayout), DeserializationError> {
    let (raw_flags, _version) = read_and_validate_header(source)?;
    let flags = WireFlags::new(raw_flags)?;
    if flags.is_hashless() && !allow_hashless {
        return Err(DeserializationError::InvalidValue(
            "HASHLESS flag is set; use UntrustedMastForest for untrusted input".to_string(),
        ));
    }
    let layout = scan_layout_sections(source, flags.is_hashless())?;

    Ok((flags, layout))
}

pub(super) trait OffsetTrackingReader: ByteReader {
    fn offset(&self) -> usize;
}

pub(super) struct TrackingReader<'a, R> {
    inner: &'a mut R,
    offset: usize,
    recorded: Option<Vec<u8>>,
}

impl<'a, R> TrackingReader<'a, R> {
    pub(super) fn new(inner: &'a mut R) -> Self {
        Self { inner, offset: 0, recorded: None }
    }

    pub(super) fn new_recording(inner: &'a mut R) -> Self {
        Self {
            inner,
            offset: 0,
            recorded: Some(Vec::new()),
        }
    }

    pub(super) fn into_recorded(self) -> Vec<u8> {
        self.recorded.unwrap_or_default()
    }

    fn advance_offset(&mut self, len: usize) -> Result<(), DeserializationError> {
        self.offset = self
            .offset
            .checked_add(len)
            .ok_or_else(|| DeserializationError::InvalidValue("offset overflow".to_string()))?;
        Ok(())
    }

    fn record_slice(&mut self, slice: &[u8]) {
        if let Some(recorded) = &mut self.recorded {
            recorded.extend_from_slice(slice);
        }
    }
}

impl<R: ByteReader> ByteReader for TrackingReader<'_, R> {
    fn read_u8(&mut self) -> Result<u8, DeserializationError> {
        let byte = self.inner.read_u8()?;
        self.advance_offset(1)?;
        self.record_slice(&[byte]);
        Ok(byte)
    }

    fn peek_u8(&self) -> Result<u8, DeserializationError> {
        self.inner.peek_u8()
    }

    fn read_slice(&mut self, len: usize) -> Result<&[u8], DeserializationError> {
        let slice = self.inner.read_slice(len)?;
        self.offset = self
            .offset
            .checked_add(len)
            .ok_or_else(|| DeserializationError::InvalidValue("offset overflow".to_string()))?;
        if let Some(recorded) = &mut self.recorded {
            recorded.extend_from_slice(slice);
        }
        Ok(slice)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError> {
        let array = self.inner.read_array::<N>()?;
        self.advance_offset(N)?;
        self.record_slice(&array);
        Ok(array)
    }

    fn check_eor(&self, num_bytes: usize) -> Result<(), DeserializationError> {
        self.inner.check_eor(num_bytes)
    }

    fn has_more_bytes(&self) -> bool {
        self.inner.has_more_bytes()
    }

    fn max_alloc(&self, element_size: usize) -> usize {
        self.inner.max_alloc(element_size)
    }
}

impl<R: ByteReader> OffsetTrackingReader for TrackingReader<'_, R> {
    fn offset(&self) -> usize {
        self.offset
    }
}

fn scan_layout_sections<R: OffsetTrackingReader>(
    source: &mut R,
    is_hashless: bool,
) -> Result<ForestLayout, DeserializationError> {
    let body_start = source.offset();

    let node_count = source.read_usize()?;
    if node_count > MastForest::MAX_NODES {
        return Err(DeserializationError::InvalidValue(format!(
            "node count {} exceeds maximum allowed {}",
            node_count,
            MastForest::MAX_NODES
        )));
    }
    let _decorator_count = source.read_usize()?;

    let roots_count = source.read_usize()?;
    let roots_offset = source
        .offset()
        .checked_sub(body_start)
        .ok_or_else(|| DeserializationError::InvalidValue("roots offset underflow".to_string()))?;
    let roots_len_bytes = roots_count
        .checked_mul(core::mem::size_of::<u32>())
        .ok_or_else(|| DeserializationError::InvalidValue("roots length overflow".to_string()))?;
    let _roots_data = source.read_slice(roots_len_bytes)?;

    let basic_block_len = source.read_usize()?;
    let basic_block_offset = source.offset().checked_sub(body_start).ok_or_else(|| {
        DeserializationError::InvalidValue("basic-block offset underflow".to_string())
    })?;
    let _basic_block_data = source.read_slice(basic_block_len)?;

    let node_entry_size = MastNodeEntry::min_serialized_size();
    let node_entry_offset = source.offset().checked_sub(body_start).ok_or_else(|| {
        DeserializationError::InvalidValue("node entry offset underflow".to_string())
    })?;
    let mut external_digest_count = 0usize;
    for _ in 0..node_count {
        let node_entry = MastNodeEntry::read_from(source)?;
        if matches!(node_entry.node_type(), MastNodeType::External) {
            external_digest_count = external_digest_count.checked_add(1).ok_or_else(|| {
                DeserializationError::InvalidValue("external digest count overflow".to_string())
            })?;
        }
    }

    let external_digest_offset = source.offset().checked_sub(body_start).ok_or_else(|| {
        DeserializationError::InvalidValue("external digest offset underflow".to_string())
    })?;
    let external_digests_len = external_digest_count
        .checked_mul(crate::Word::min_serialized_size())
        .ok_or_else(|| {
            DeserializationError::InvalidValue("external digest length overflow".to_string())
        })?;
    let _external_digests = source.read_slice(external_digests_len)?;

    let node_hash_count = node_count.checked_sub(external_digest_count).ok_or_else(|| {
        DeserializationError::InvalidValue("node hash count underflow".to_string())
    })?;
    let node_hash_offset = if is_hashless {
        None
    } else {
        let offset = source.offset().checked_sub(body_start).ok_or_else(|| {
            DeserializationError::InvalidValue("node hash offset underflow".to_string())
        })?;
        let node_hash_len =
            node_hash_count.checked_mul(crate::Word::min_serialized_size()).ok_or_else(|| {
                DeserializationError::InvalidValue("node hash length overflow".to_string())
            })?;
        let _node_hashes = source.read_slice(node_hash_len)?;
        Some(offset)
    };

    Ok(ForestLayout {
        node_count,
        roots_count,
        roots_offset,
        basic_block_offset,
        basic_block_len,
        node_entry_offset,
        node_entry_size,
        external_digest_offset,
        #[cfg(test)]
        external_digest_count,
        node_hash_offset,
        #[cfg(test)]
        node_hash_count,
    })
}

fn read_and_validate_header<R: ByteReader>(
    source: &mut R,
) -> Result<(u8, [u8; 3]), DeserializationError> {
    let magic: [u8; 4] = source.read_array()?;
    if magic != *MAGIC {
        return Err(DeserializationError::InvalidValue(format!(
            "Invalid magic bytes. Expected '{:?}', got '{:?}'",
            *MAGIC, magic
        )));
    }

    let flags: u8 = source.read_u8()?;

    let version: [u8; 3] = source.read_array()?;
    if version != VERSION {
        return Err(DeserializationError::InvalidValue(format!(
            "Unsupported version. Got '{version:?}', but only '{VERSION:?}' is supported",
        )));
    }

    if flags & FLAGS_RESERVED_MASK != 0 {
        return Err(DeserializationError::InvalidValue(format!(
            "Unknown flags set in MAST header: {:#04x}. Reserved bits must be zero.",
            flags & FLAGS_RESERVED_MASK
        )));
    }

    Ok((flags, version))
}
