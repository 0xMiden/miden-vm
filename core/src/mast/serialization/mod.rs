//! The serialization format of MastForest is as follows:
//!
//! (Metadata)
//! - MAGIC (4 bytes) + FLAGS (1 byte) + VERSION (3 bytes)
//!
//! (Counts)
//! - nodes count (`usize`)
//! - decorators count (`usize`) - 0 if stripped, reserved for future use in lazy loading (#2504)
//!
//! (Procedure roots section)
//! - procedure roots (`Vec<u32>` as MastNodeId values)
//!
//! (Basic block data section)
//! - basic block data (padded operations + batch metadata)
//!
//! (Node entries section)
//! - fixed-width structural node entries (`Vec<MastNodeEntry>`)
//!
//! (External digest section)
//! - digests for `External` nodes only (`Vec<Word>`, ordered by node index)
//!
//! (Node hash section - omitted if FLAGS bit 1 is set)
//! - digests for all non-external nodes (`Vec<Word>`, ordered by node index)
//!
//! (Advice map section)
//! - Advice map (`AdviceMap`)
//!
//! (DebugInfo section - omitted if FLAGS bit 0 is set)
//! - Decorator data (raw bytes for decorator payloads)
//! - String table (deduplicated strings)
//! - Decorator infos (`Vec<DecoratorInfo>`)
//! - Error codes map (`BTreeMap<u64, String>`)
//! - OpToDecoratorIds CSR (operation-indexed decorators, dense representation)
//! - NodeToDecoratorIds CSR (before_enter and after_exit decorators, dense representation)
//! - Procedure names map (`BTreeMap<Word, String>`)
//!
//! # Stripped Format
//!
//! When serializing with [`MastForest::write_stripped`], the FLAGS byte has bit 0 set
//! and the entire DebugInfo section is omitted. Deserialization auto-detects the format
//! and creates an empty `DebugInfo` with valid CSR structures when reading stripped files.
//!
//! # Hashless Format
//!
//! When serializing with [`MastForest::write_hashless`], the FLAGS byte has bit 1 set, and
//! bit 0 is also set (hashless implies stripped). In this format, the general node-hash section
//! is omitted entirely. Trusted deserialization rejects hashless inputs; use
//! [`UntrustedMastForest`] instead.

#[cfg(test)]
use alloc::string::ToString;
use alloc::vec::Vec;

use super::{MastForest, MastNode, MastNodeId};
use crate::{
    advice::AdviceMap,
    mast::node::MastNodeExt,
    serde::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable, SliceReader,
    },
};

pub(crate) mod asm_op;
pub(crate) mod decorator;

mod info;
pub use info::{MastNodeEntry, MastNodeInfo};

mod layout;
pub(super) use layout::ForestLayout;
use layout::{TrackingReader, WireFlags, read_header_and_scan_layout};

mod resolved;
use resolved::{ResolvedSerializedForest, basic_block_offset_for_node_index};

mod basic_blocks;
use basic_blocks::{BasicBlockDataBuilder, basic_block_data_len};

pub(crate) mod string_table;
pub(crate) use string_table::StringTable;

#[cfg(test)]
mod seed_gen;

#[cfg(test)]
mod tests;

// TYPE ALIASES
// ================================================================================================

/// Specifies an offset into the `node_data` section of an encoded [`MastForest`].
type NodeDataOffset = u32;

/// Specifies an offset into the `decorator_data` section of an encoded [`MastForest`].
type DecoratorDataOffset = u32;

/// Specifies an offset into the `strings_data` section of an encoded [`MastForest`].
type StringDataOffset = usize;

/// Specifies an offset into the strings table of an encoded [`MastForest`].
type StringIndex = usize;

// CONSTANTS
// ================================================================================================

/// Magic bytes for detecting that a file is binary-encoded MAST.
///
/// The format uses 4 bytes for identification followed by a flags byte:
/// - Bytes 0-3: `b"MAST"` - Magic identifier
/// - Byte 4: Flags byte (see [`FLAG_STRIPPED`] and [`FLAGS_RESERVED_MASK`] constants)
///
/// This design repurposes the original null terminator (`b"MAST\0"`) as a flags byte,
/// maintaining backward compatibility: old files have flags=0x00 (the null byte),
/// which means "debug info present".
const MAGIC: &[u8; 4] = b"MAST";

/// Flag indicating debug info is stripped from the serialized MastForest.
///
/// When this bit is set in the flags byte, the DebugInfo section is omitted entirely.
/// The deserializer will create an empty `DebugInfo` with valid CSR structures.
const FLAG_STRIPPED: u8 = 0x01;

/// Flag indicating the serialized MastForest should be treated as hashless.
///
/// When this bit is set, the general node-hash section is omitted. External digests remain
/// serialized in their dedicated section because they cannot be reconstructed locally.
/// Trusted deserialization rejects this format. This flag implies [`FLAG_STRIPPED`].
pub(super) const FLAG_HASHLESS: u8 = 0x02;

/// Mask for reserved flag bits that must be zero.
///
/// Bits 2-7 are reserved for future use. If any are set, deserialization fails.
const FLAGS_RESERVED_MASK: u8 = 0xfc;

/// The format version.
///
/// If future modifications are made to this format, the version should be incremented by 1. A
/// version of `[255, 255, 255]` is reserved for future extensions that require extending the
/// version field itself, but should be considered invalid for now.
///
/// Version history:
/// - [0, 0, 0]: Initial format
/// - [0, 0, 1]: Added batch metadata to basic blocks (operations serialized in padded form with
///   indptr, padding, and group metadata for exact OpBatch reconstruction). Direct decorator
///   serialization in CSR format (eliminates per-node decorator sections and round-trip
///   conversions). Header changed from `MAST\0` to `MAST` + flags byte.
/// - [0, 0, 2]: Removed AssemblyOp from Decorator enum serialization. AssemblyOps are now stored
///   separately in DebugInfo. Removed `should_break` field from AssemblyOp serialization (#2646).
///   Removed `breakpoint` instruction (#2655).
/// - [0, 0, 3]: Added HASHLESS flag (bit 1). HASHLESS implies STRIPPED. Trusted deserialization
///   rejects HASHLESS.
/// - [0, 0, 4]: Split fixed-width node entries from digest storage. External digests moved to a
///   dedicated section. Hashless serialization omits the general node-hash section entirely.
const VERSION: [u8; 3] = [0, 0, 4];

// MAST FOREST SERIALIZATION/DESERIALIZATION
// ================================================================================================

impl Serializable for MastForest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.write_into_with_options(target, false, false);
    }
}

impl MastForest {
    /// Internal serialization with options.
    ///
    /// When `stripped` is true, the DebugInfo section is omitted and the FLAGS byte
    /// has bit 0 set.
    fn write_into_with_options<W: ByteWriter>(
        &self,
        target: &mut W,
        stripped: bool,
        hashless: bool,
    ) {
        let mut basic_block_data_builder = BasicBlockDataBuilder::new();

        // magic & flags
        target.write_bytes(MAGIC);
        let flags = if stripped || hashless { FLAG_STRIPPED } else { 0 }
            | if hashless { FLAG_HASHLESS } else { 0 };
        target.write_u8(flags);

        // version
        target.write_bytes(&VERSION);

        // node & decorator counts
        target.write_usize(self.nodes.len());
        target.write_usize(if stripped { 0 } else { self.debug_info.num_decorators() });

        // roots
        let roots: Vec<u32> = self.roots.iter().copied().map(u32::from).collect();
        roots.write_into(target);

        let mut mast_node_entries = Vec::with_capacity(self.nodes.len());
        let mut external_digests = Vec::new();
        let mut node_hashes = Vec::new();

        for mast_node in self.nodes.iter() {
            let ops_offset = if let MastNode::Block(basic_block) = mast_node {
                basic_block_data_builder.encode_basic_block(basic_block)
            } else {
                0
            };

            mast_node_entries.push(MastNodeEntry::new(mast_node, ops_offset));
            if mast_node.is_external() {
                external_digests.push(mast_node.digest());
            } else if !hashless {
                node_hashes.push(mast_node.digest());
            }
        }

        let basic_block_data = basic_block_data_builder.finalize();
        basic_block_data.write_into(target);

        for mast_node_entry in mast_node_entries {
            mast_node_entry.write_into(target);
        }

        for digest in external_digests {
            digest.write_into(target);
        }

        if !hashless {
            for digest in node_hashes {
                digest.write_into(target);
            }
        }

        self.advice_map.write_into(target);

        // Serialize DebugInfo only if not stripped
        if !stripped {
            self.debug_info.write_into(target);
        }
    }
}

pub(super) fn stripped_size_hint(forest: &MastForest) -> usize {
    serialized_size_hint(forest, true, false)
}

fn hashless_size_hint(forest: &MastForest) -> usize {
    serialized_size_hint(forest, true, true)
}

fn serialized_size_hint(forest: &MastForest, stripped: bool, hashless: bool) -> usize {
    let node_count = forest.nodes.len();
    let external_count = forest.nodes.iter().filter(|node| node.is_external()).count();
    let non_external_count = node_count - external_count;

    let mut size = MAGIC.len() + 1 + VERSION.len();
    size += node_count.get_size_hint();
    size += if stripped {
        0usize
    } else {
        forest.debug_info.num_decorators()
    }
    .get_size_hint();

    let roots_len = forest.roots.len();
    size += roots_len.get_size_hint();
    size += roots_len * core::mem::size_of::<u32>();

    let mut basic_block_len = 0usize;
    for node in forest.nodes.iter() {
        if let MastNode::Block(block) = node {
            basic_block_len += basic_block_data_len(block);
        }
    }
    size += basic_block_len.get_size_hint() + basic_block_len;

    size += node_count * MastNodeEntry::min_serialized_size();
    size += external_count * crate::Word::min_serialized_size();
    if !hashless {
        size += non_external_count * crate::Word::min_serialized_size();
    }
    size += forest.advice_map.serialized_size_hint();
    if !stripped {
        size += forest.debug_info.get_size_hint();
    }

    size
}

/// A zero-copy view over a stripped, serialized MAST forest.
///
/// This is intended for trusted inputs and supports random access to `MastNodeInfo`
/// entries without deserializing the full forest.
///
/// # Examples
///
/// ```
/// use miden_core::{
///     mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor, SerializedMastForest},
///     operations::Operation,
/// };
///
/// let mut forest = MastForest::new();
/// let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
///     .add_to_forest(&mut forest)
///     .unwrap();
/// forest.make_root(block_id);
///
/// let mut bytes = Vec::new();
/// forest.write_stripped(&mut bytes);
///
/// let view = SerializedMastForest::new(&bytes).unwrap();
/// assert_eq!(view.node_count(), forest.nodes().len());
/// assert!(view.node_info_at(0).is_ok());
/// ```
#[derive(Debug)]
pub struct SerializedMastForest<'a> {
    flags: WireFlags,
    forest: ResolvedSerializedForest<'a>,
}

impl<'a> SerializedMastForest<'a> {
    /// Creates a new view from serialized bytes.
    ///
    /// The input may be either full or stripped format.
    /// Structural parsing is delegated to the same single-pass scanner used by reader-based
    /// deserialization paths.
    ///
    /// This constructor is layout-oriented: it validates the header and sections needed for
    /// node/roots/random-access metadata only. It does not validate or fully parse trailing
    /// `AdviceMap` / `DebugInfo` payloads.
    ///
    /// For strict full-payload validation, use
    /// [`crate::mast::MastForest::read_from_bytes`].
    ///
    /// Conventions:
    /// - If `HASHLESS` is not set, node digests are read from wire data.
    /// - If `HASHLESS` is set, wire digests are ignored and node digests are recomputed during
    ///   construction whenever possible.
    /// - For `External` nodes in `HASHLESS` mode, digests are marshaled opaquely from wire data;
    ///   this view does not attempt semantic resolution of external references.
    ///
    /// # Examples
    ///
    /// ```
    /// use miden_core::{
    ///     mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor, SerializedMastForest},
    ///     operations::Operation,
    /// };
    ///
    /// let mut forest = MastForest::new();
    /// let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
    ///     .add_to_forest(&mut forest)
    ///     .unwrap();
    /// forest.make_root(block_id);
    ///
    /// let mut bytes = Vec::new();
    /// forest.write_stripped(&mut bytes);
    ///
    /// let view = SerializedMastForest::new(&bytes).unwrap();
    /// assert_eq!(view.node_count(), 1);
    /// ```
    pub fn new(bytes: &'a [u8]) -> Result<Self, DeserializationError> {
        let mut reader = SliceReader::new(bytes);
        let mut scanner = TrackingReader::new(&mut reader);
        let (flags, layout) = read_header_and_scan_layout(&mut scanner, true)?;
        let forest = ResolvedSerializedForest::new(bytes, layout)?;

        Ok(Self { flags, forest })
    }

    /// Returns the number of nodes in the serialized forest.
    pub fn node_count(&self) -> usize {
        self.forest.node_count()
    }

    /// Returns `true` when this view uses hashless convention and recomputed digests.
    pub fn is_hashless(&self) -> bool {
        self.flags.is_hashless()
    }

    /// Returns `true` when this view represents stripped serialization.
    pub fn is_stripped(&self) -> bool {
        self.flags.is_stripped()
    }

    /// Returns the number of procedure roots in the serialized forest.
    pub fn procedure_root_count(&self) -> usize {
        self.forest.procedure_root_count()
    }

    /// Returns the procedure root id at the specified index.
    pub fn procedure_root_at(&self, index: usize) -> Result<MastNodeId, DeserializationError> {
        self.forest.procedure_root_at(index)
    }

    /// Returns the `MastNodeInfo` at the specified index.
    ///
    /// # Examples
    ///
    /// ```
    /// use miden_core::{
    ///     mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor, SerializedMastForest},
    ///     operations::Operation,
    /// };
    ///
    /// let mut forest = MastForest::new();
    /// let block_id = BasicBlockNodeBuilder::new(vec![Operation::Add], Vec::new())
    ///     .add_to_forest(&mut forest)
    ///     .unwrap();
    /// forest.make_root(block_id);
    ///
    /// let mut bytes = Vec::new();
    /// forest.write_stripped(&mut bytes);
    ///
    /// let view = SerializedMastForest::new(&bytes).unwrap();
    /// assert!(view.node_info_at(0).is_ok());
    /// ```
    pub fn node_info_at(&self, index: usize) -> Result<MastNodeInfo, DeserializationError> {
        Ok(MastNodeInfo::from_entry(
            self.node_entry_at(index)?,
            self.node_digest_at(index)?,
        ))
    }

    /// Returns the fixed-width structural node entry at the specified index.
    pub fn node_entry_at(&self, index: usize) -> Result<MastNodeEntry, DeserializationError> {
        self.forest.node_entry_at(index)
    }

    /// Returns the digest for the node at the specified index.
    pub fn node_digest_at(&self, index: usize) -> Result<crate::Word, DeserializationError> {
        self.forest.node_digest_at(index)
    }

    #[cfg(test)]
    fn advice_map_offset(&self) -> Result<usize, DeserializationError> {
        self.forest.advice_map_offset()
    }

    #[cfg(test)]
    fn node_entry_offset(&self) -> usize {
        self.forest.node_entry_offset()
    }

    #[cfg(test)]
    fn node_entry_size(&self) -> usize {
        self.forest.node_entry_size()
    }

    #[cfg(test)]
    fn node_hash_offset(&self) -> Option<usize> {
        self.forest.node_hash_offset()
    }

    #[cfg(test)]
    fn digest_slot_at(&self, index: usize) -> usize {
        self.forest.digest_slot_at(index)
    }
}

impl super::MastForestView for SerializedMastForest<'_> {
    fn node_count(&self) -> usize {
        SerializedMastForest::node_count(self)
    }

    fn node_entry_at(&self, index: usize) -> Result<MastNodeEntry, DeserializationError> {
        SerializedMastForest::node_entry_at(self, index)
    }

    fn node_digest_at(&self, index: usize) -> Result<crate::Word, DeserializationError> {
        SerializedMastForest::node_digest_at(self, index)
    }

    fn procedure_root_count(&self) -> usize {
        SerializedMastForest::procedure_root_count(self)
    }

    fn procedure_root_at(&self, index: usize) -> Result<MastNodeId, DeserializationError> {
        SerializedMastForest::procedure_root_at(self, index)
    }
}

impl super::MastForestView for MastForest {
    fn node_count(&self) -> usize {
        self.nodes.len()
    }

    fn node_entry_at(&self, index: usize) -> Result<MastNodeEntry, DeserializationError> {
        let node = self.nodes.as_slice().get(index).ok_or_else(|| {
            DeserializationError::InvalidValue(format!("node index {index} out of bounds"))
        })?;
        let ops_offset = if matches!(node, MastNode::Block(_)) {
            basic_block_offset_for_node_index(self.nodes.as_slice(), index)?
        } else {
            0
        };

        Ok(MastNodeEntry::new(node, ops_offset))
    }

    fn node_digest_at(&self, index: usize) -> Result<crate::Word, DeserializationError> {
        self.nodes.as_slice().get(index).map(MastNode::digest).ok_or_else(|| {
            DeserializationError::InvalidValue(format!("node index {index} out of bounds"))
        })
    }

    fn procedure_root_count(&self) -> usize {
        self.roots.len()
    }

    fn procedure_root_at(&self, index: usize) -> Result<MastNodeId, DeserializationError> {
        self.roots.get(index).copied().ok_or_else(|| {
            DeserializationError::InvalidValue(format!(
                "root index {} out of bounds for {} roots",
                index,
                self.roots.len()
            ))
        })
    }
}

#[cfg(test)]
fn read_u8_at(bytes: &[u8], offset: &mut usize) -> Result<u8, DeserializationError> {
    read_slice_at(bytes, offset, 1).map(|slice| slice[0])
}

#[cfg(test)]
fn read_array_at<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<[u8; N], DeserializationError> {
    let slice = read_slice_at(bytes, offset, N)?;
    let mut result = [0u8; N];
    result.copy_from_slice(slice);
    Ok(result)
}

#[cfg(test)]
fn read_slice_at<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    len: usize,
) -> Result<&'a [u8], DeserializationError> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| DeserializationError::InvalidValue("offset overflow".to_string()))?;
    if end > bytes.len() {
        return Err(DeserializationError::UnexpectedEOF);
    }
    let slice = &bytes[*offset..end];
    *offset = end;
    Ok(slice)
}

// NOTE: Mirrors ByteReader::read_usize (vint64) decoding to preserve wire compatibility.
#[cfg(test)]
fn read_usize_at(bytes: &[u8], offset: &mut usize) -> Result<usize, DeserializationError> {
    if *offset >= bytes.len() {
        return Err(DeserializationError::UnexpectedEOF);
    }
    let first_byte = bytes[*offset];
    let length = first_byte.trailing_zeros() as usize + 1;

    let result = if length == 9 {
        let _marker = read_u8_at(bytes, offset)?;
        let value = read_array_at::<8>(bytes, offset)?;
        u64::from_le_bytes(value)
    } else {
        let mut encoded = [0u8; 8];
        let value = read_slice_at(bytes, offset, length)?;
        encoded[..length].copy_from_slice(value);
        u64::from_le_bytes(encoded) >> length
    };

    if result > usize::MAX as u64 {
        return Err(DeserializationError::InvalidValue(format!(
            "Encoded value must be less than {}, but {} was provided",
            usize::MAX,
            result
        )));
    }

    Ok(result as usize)
}

impl Deserializable for MastForest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let (_flags, forest) = decode_from_reader(source, false)?;
        forest.into_materialized()
    }
}

impl super::UntrustedMastForest {
    pub(super) fn into_materialized(self) -> Result<MastForest, DeserializationError> {
        ResolvedSerializedForest::new(&self.bytes, self.layout)?
            .materialize(self.advice_map, self.debug_info)
    }
}

pub(super) fn read_untrusted_with_flags<R: ByteReader>(
    source: &mut R,
) -> Result<(super::UntrustedMastForest, u8), DeserializationError> {
    let (flags, forest) = decode_from_reader(source, true)?;
    log_untrusted_overspecification(flags);
    Ok((forest, flags.bits()))
}

fn log_untrusted_overspecification(flags: WireFlags) {
    if !flags.is_hashless() {
        log::error!(
            "UntrustedMastForest expected HASHLESS input; supplied artifact includes wire node hashes that will be ignored and recomputed during validation"
        );
    }

    if !flags.is_stripped() {
        log::error!(
            "UntrustedMastForest expected STRIPPED input; supplied artifact includes DebugInfo and other optional payloads over the wire"
        );
    }
}

fn decode_from_reader<R: ByteReader>(
    source: &mut R,
    allow_hashless: bool,
) -> Result<(WireFlags, super::UntrustedMastForest), DeserializationError> {
    let mut recording = TrackingReader::new_recording(source);
    let (flags, layout) = read_header_and_scan_layout(&mut recording, allow_hashless)?;

    let advice_map = AdviceMap::read_from(&mut recording)?;
    let debug_info = if flags.is_stripped() {
        super::DebugInfo::empty_for_nodes(layout.node_count)
    } else {
        super::DebugInfo::read_from(&mut recording)?
    };

    Ok((
        flags,
        super::UntrustedMastForest {
            bytes: recording.into_recorded(),
            layout,
            advice_map,
            debug_info,
        },
    ))
}

// UNTRUSTED DESERIALIZATION
// ================================================================================================

impl Deserializable for super::UntrustedMastForest {
    /// Deserializes an [`super::UntrustedMastForest`] from a byte reader.
    ///
    /// Note: This method does not apply budgeting. For untrusted input, prefer using
    /// [`read_from_bytes`](Self::read_from_bytes) which applies budgeted deserialization.
    ///
    /// After deserialization, callers should use [`super::UntrustedMastForest::validate()`]
    /// to verify structural integrity and recompute all node hashes before using
    /// the forest.
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        read_untrusted_with_flags(source).map(|(forest, _flags)| forest)
    }

    /// Deserializes an [`super::UntrustedMastForest`] from bytes using budgeted deserialization.
    ///
    /// This method uses a [`crate::serde::BudgetedReader`] with a budget equal to the input size
    /// to protect against denial-of-service attacks from malicious input.
    ///
    /// After deserialization, callers should use [`super::UntrustedMastForest::validate()`]
    /// to verify structural integrity and recompute all node hashes before using
    /// the forest.
    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        super::UntrustedMastForest::read_from_bytes(bytes)
    }
}

// STRIPPED SERIALIZATION
// ================================================================================================

/// Wrapper for serializing a [`MastForest`] without debug information.
///
/// This newtype enables an alternative serialization format that omits the DebugInfo section,
/// producing smaller output files suitable for production deployment where debug info is not
/// needed.
///
/// The resulting bytes can be deserialized with the standard [`Deserializable`] impl for
/// [`MastForest`], which auto-detects the format via the flags byte in the header.
pub(super) struct StrippedMastForest<'a>(pub(super) &'a MastForest);

impl Serializable for StrippedMastForest<'_> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into_with_options(target, true, false);
    }

    fn get_size_hint(&self) -> usize {
        stripped_size_hint(self.0)
    }
}

/// Wrapper for serializing a [`MastForest`] with the HASHLESS flag set.
pub(super) struct HashlessMastForest<'a>(pub(super) &'a MastForest);

impl Serializable for HashlessMastForest<'_> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.0.write_into_with_options(target, true, true);
    }

    fn get_size_hint(&self) -> usize {
        hashless_size_hint(self.0)
    }
}
