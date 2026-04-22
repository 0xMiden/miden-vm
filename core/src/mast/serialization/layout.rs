use alloc::{format, string::ToString, vec::Vec};

use super::{
    FLAG_HASHLESS, FLAG_STRIPPED, FLAGS_RESERVED_MASK, MAGIC, MastForest, MastNodeEntry, VERSION,
};
use crate::{
    mast::MastNodeId,
    serde::{ByteReader, Deserializable, DeserializationError, SliceReader},
};

// FOREST LAYOUT
// ================================================================================================

/// Fixed offsets and counts for the structural sections of a serialized MAST forest.
///
/// This is the shared substrate used by both serialized random-access views and the reader-based
/// deserialization paths. All offsets are absolute byte offsets into the full serialized blob.
/// `ForestLayout` itself is not a trust marker; it only says the structural sections fit within
/// the scanned byte slice.
///
/// The scanner validates section sizes immediately. For budgeted readers, it also bounds wire
/// counts via [`ByteReader::max_alloc`] before those counts are used to size fixed-width sections.
/// Plain [`SliceReader`] leaves `max_alloc` unconstrained, so trusted inspection paths keep their
/// previous behavior. Full untrusted validation lives above this layer in
/// [`crate::mast::UntrustedMastForest`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct ForestLayout {
    pub(super) node_count: usize,
    pub(super) roots_count: usize,
    pub(super) roots_offset: usize,
    pub(super) basic_block_offset: usize,
    pub(super) basic_block_len: usize,
    pub(super) node_entry_offset: usize,
    pub(super) external_digest_offset: usize,
    #[cfg(test)]
    pub(super) external_digest_count: usize,
    pub(super) node_hash_offset: Option<usize>,
    #[cfg(test)]
    pub(super) node_hash_count: usize,
}

/// Raw wire flags from the MAST header.
///
/// These flags describe which optional sections are present in the payload. Trust policy lives in
/// the caller that reads the payload, not in the flags themselves.
#[derive(Debug, Clone, Copy)]
pub(super) struct WireFlags(u8);

impl ForestLayout {
    pub(crate) fn is_hashless(&self) -> bool {
        self.node_hash_offset.is_none()
    }

    pub(super) fn read_procedure_root_at(
        &self,
        bytes: &[u8],
        index: usize,
    ) -> Result<MastNodeId, DeserializationError> {
        if index >= self.roots_count {
            return Err(DeserializationError::InvalidValue(format!(
                "root index {} out of bounds for {} roots",
                index, self.roots_count
            )));
        }

        let mut raw = [0u8; core::mem::size_of::<u32>()];
        raw.copy_from_slice(read_fixed_section_entry(
            bytes,
            self.roots_offset,
            core::mem::size_of::<u32>(),
            index,
            "root",
        )?);
        MastNodeId::from_u32_with_node_count(u32::from_le_bytes(raw), self.node_count)
    }

    pub(super) fn read_node_entry_at(
        &self,
        bytes: &[u8],
        index: usize,
    ) -> Result<MastNodeEntry, DeserializationError> {
        if index >= self.node_count {
            return Err(DeserializationError::InvalidValue(format!(
                "node index {} out of bounds for {} nodes",
                index, self.node_count
            )));
        }

        let mut reader = SliceReader::new(read_fixed_section_entry(
            bytes,
            self.node_entry_offset,
            MastNodeEntry::SERIALIZED_SIZE,
            index,
            "node entry",
        )?);
        MastNodeEntry::read_from(&mut reader)
    }

    #[cfg(test)]
    pub(super) fn advice_map_offset(
        &self,
        bytes_len: usize,
    ) -> Result<usize, DeserializationError> {
        let digest_section_end = if let Some(node_hash_offset) = self.node_hash_offset {
            node_hash_offset
                .checked_add(self.node_hash_count * crate::Word::min_serialized_size())
                .ok_or_else(|| {
                    DeserializationError::InvalidValue("node hash section overflow".to_string())
                })?
        } else {
            self.external_digest_offset
                .checked_add(self.external_digest_count * crate::Word::min_serialized_size())
                .ok_or_else(|| {
                    DeserializationError::InvalidValue(
                        "external digest section overflow".to_string(),
                    )
                })?
        };

        if digest_section_end > bytes_len {
            return Err(DeserializationError::UnexpectedEOF);
        }

        Ok(digest_section_end)
    }
}

// WIRE FLAGS
// ================================================================================================

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

// LAYOUT SCANNING
// ================================================================================================

pub(super) fn read_header_and_scan_layout<R: OffsetTrackingReader>(
    source: &mut R,
    allow_hashless: bool,
) -> Result<(WireFlags, ForestLayout), DeserializationError> {
    // This scanner always enforces syntactic layout validity. Reader choice determines the trust
    // policy for counts: e.g. `SliceReader` for trusted inspection versus `BudgetedReader` for the
    // untrusted deserialization path.
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
    let node_count = source.read_usize()?;
    if node_count > MastForest::MAX_NODES {
        return Err(DeserializationError::InvalidValue(format!(
            "node count {} exceeds maximum allowed {}",
            node_count,
            MastForest::MAX_NODES
        )));
    }
    validate_budgeted_count(source, node_count, MastNodeEntry::SERIALIZED_SIZE, "node count")?;

    let roots_count = source.read_usize()?;
    validate_budgeted_count(source, roots_count, core::mem::size_of::<u32>(), "root count")?;
    let roots_offset = source.offset();
    let roots_len_bytes = roots_count
        .checked_mul(core::mem::size_of::<u32>())
        .ok_or_else(|| DeserializationError::InvalidValue("roots length overflow".to_string()))?;
    let _roots_data = source.read_slice(roots_len_bytes)?;

    let basic_block_len = source.read_usize()?;
    let basic_block_offset = source.offset();
    let _basic_block_data = source.read_slice(basic_block_len)?;

    let node_entry_offset = source.offset();
    let mut external_digest_count = 0usize;
    for _ in 0..node_count {
        let node_entry = MastNodeEntry::read_from(source)?;
        if matches!(node_entry, MastNodeEntry::External) {
            external_digest_count = external_digest_count.checked_add(1).ok_or_else(|| {
                DeserializationError::InvalidValue("external digest count overflow".to_string())
            })?;
        }
    }

    let external_digest_offset = source.offset();
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
        let offset = source.offset();
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
        external_digest_offset,
        #[cfg(test)]
        external_digest_count,
        node_hash_offset,
        #[cfg(test)]
        node_hash_count,
    })
}

fn validate_budgeted_count<R: ByteReader>(
    source: &R,
    count: usize,
    element_size: usize,
    label: &str,
) -> Result<(), DeserializationError> {
    let max_count = source.max_alloc(element_size);
    if count > max_count {
        return Err(DeserializationError::InvalidValue(format!(
            "{label} {count} exceeds reader allocation bound {max_count} for {element_size}-byte elements",
        )));
    }

    Ok(())
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

// HELPERS
// ================================================================================================

pub(super) fn read_fixed_section_entry<'a>(
    bytes: &'a [u8],
    section_offset: usize,
    entry_size: usize,
    index: usize,
    section_name: &str,
) -> Result<&'a [u8], DeserializationError> {
    let entry_offset = index
        .checked_mul(entry_size)
        .and_then(|delta| section_offset.checked_add(delta))
        .ok_or_else(|| {
            DeserializationError::InvalidValue(format!("{section_name} offset overflow"))
        })?;
    let entry_end = entry_offset.checked_add(entry_size).ok_or_else(|| {
        DeserializationError::InvalidValue(format!("{section_name} length overflow"))
    })?;
    if entry_end > bytes.len() {
        return Err(DeserializationError::UnexpectedEOF);
    }

    Ok(&bytes[entry_offset..entry_end])
}
