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
//! (Node info section)
//! - MAST node infos (`Vec<MastNodeInfo>`)
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
//! bit 0 is also set (hashless implies stripped). This does not change the wire format.
//! It is a declaration of intent that stored digests must be recomputed during validation.
//! The trusted deserializer rejects hashless inputs; use [`UntrustedMastForest`] instead.

use alloc::{string::ToString, vec::Vec};

use super::{CallNode, DynNode, JoinNode, LoopNode, MastForest, MastNode, MastNodeId, SplitNode};
use crate::{
    Felt,
    advice::AdviceMap,
    chiplets::hasher,
    serde::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable, SliceReader,
    },
};

pub(crate) mod asm_op;
pub(crate) mod decorator;

mod info;
pub use info::MastNodeInfo;
use info::MastNodeType;

mod basic_blocks;
use basic_blocks::{BasicBlockDataBuilder, BasicBlockDataDecoder, basic_block_data_len};

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
/// This flag does not affect the wire format; digests are still serialized. It declares that
/// digests must be recomputed during validation, so trusted deserialization rejects it.
/// This flag implies [`FLAG_STRIPPED`].
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
const VERSION: [u8; 3] = [0, 0, 3];

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

        // Prepare MAST node infos, but don't store them yet. We store them at the end to make
        // deserialization more efficient.
        let mast_node_infos: Vec<MastNodeInfo> = self
            .nodes
            .iter()
            .map(|mast_node| {
                let ops_offset = if let MastNode::Block(basic_block) = mast_node {
                    basic_block_data_builder.encode_basic_block(basic_block)
                } else {
                    0
                };

                MastNodeInfo::new(mast_node, ops_offset)
            })
            .collect();

        let basic_block_data = basic_block_data_builder.finalize();
        basic_block_data.write_into(target);

        // Write node infos
        for mast_node_info in mast_node_infos {
            mast_node_info.write_into(target);
        }

        self.advice_map.write_into(target);

        // Serialize DebugInfo only if not stripped
        if !stripped {
            self.debug_info.write_into(target);
        }
    }
}

pub(super) fn stripped_size_hint(forest: &MastForest) -> usize {
    let node_count = forest.nodes.len();

    let mut size = MAGIC.len() + 1 + VERSION.len();
    size += node_count.get_size_hint();
    size += 0usize.get_size_hint(); // decorator count (always 0 in stripped)

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

    let node_info_size = MastNodeInfo::min_serialized_size();
    size += node_count * node_info_size;
    size += forest.advice_map.serialized_size_hint();

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
    bytes: &'a [u8],
    is_stripped: bool,
    is_hashless: bool,
    hash_table: Option<Vec<crate::Word>>,
    node_count: usize,
    roots_count: usize,
    roots_offset: usize,
    basic_block_offset: usize,
    basic_block_len: usize,
    node_info_offset: usize,
    node_info_size: usize,
}

#[derive(Debug, Clone, Copy)]
struct ScannedForestLayout {
    node_count: usize,
    roots_count: usize,
    roots_offset: usize,
    basic_block_offset: usize,
    basic_block_len: usize,
    node_info_offset: usize,
    node_info_size: usize,
}

/// Canonical decoded representation for reader-based deserialization paths.
///
/// Parsing yields a serialized backing buffer plus section metadata; materialization into
/// [`MastForest`] is an explicit final step.
#[derive(Debug, Clone)]
pub(super) struct DecodedSerializedForest {
    flags: u8,
    bytes: Vec<u8>,
    layout: ScannedForestLayout,
    advice_map: AdviceMap,
    debug_info: super::DebugInfo,
}

impl DecodedSerializedForest {
    pub(super) fn flags(&self) -> u8 {
        self.flags
    }

    pub(super) fn is_hashless(&self) -> bool {
        self.flags & FLAG_HASHLESS != 0
    }

    pub(super) fn into_mast_forest(self) -> Result<MastForest, DeserializationError> {
        let view = SerializedMastForest::from_scanned_parts(&self.bytes, self.flags, self.layout)?;
        view.to_mast_forest_with_sections(self.advice_map, self.debug_info)
    }
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
        let (flags, _version) = read_and_validate_header(&mut reader)?;
        let is_stripped = flags & FLAG_STRIPPED != 0;
        if flags & FLAG_HASHLESS != 0 && !is_stripped {
            return Err(DeserializationError::InvalidValue(
                "HASHLESS flag requires STRIPPED flag to be set".to_string(),
            ));
        }

        let mut scanner = CountingReader::new(&mut reader);
        let layout = scan_layout_sections(&mut scanner)?;

        Self::from_scanned_parts(bytes, flags, layout)
    }

    fn from_scanned_parts(
        bytes: &'a [u8],
        flags: u8,
        layout: ScannedForestLayout,
    ) -> Result<Self, DeserializationError> {
        let is_stripped = flags & FLAG_STRIPPED != 0;
        let is_hashless = flags & FLAG_HASHLESS != 0;
        if is_hashless && !is_stripped {
            return Err(DeserializationError::InvalidValue(
                "HASHLESS flag requires STRIPPED flag to be set".to_string(),
            ));
        }

        let header_len = MAGIC.len() + 1 + VERSION.len();
        let roots_offset = header_len.checked_add(layout.roots_offset).ok_or_else(|| {
            DeserializationError::InvalidValue("roots offset overflow".to_string())
        })?;
        let basic_block_offset =
            header_len.checked_add(layout.basic_block_offset).ok_or_else(|| {
                DeserializationError::InvalidValue("basic-block offset overflow".to_string())
            })?;
        let node_info_offset =
            header_len.checked_add(layout.node_info_offset).ok_or_else(|| {
                DeserializationError::InvalidValue("node info offset overflow".to_string())
            })?;
        let hash_table = if is_hashless {
            Some(recompute_hash_table(
                bytes,
                layout.node_count,
                node_info_offset,
                layout.node_info_size,
                basic_block_offset,
                layout.basic_block_len,
            )?)
        } else {
            None
        };

        Ok(Self {
            bytes,
            is_stripped,
            is_hashless,
            hash_table,
            node_count: layout.node_count,
            roots_count: layout.roots_count,
            roots_offset,
            basic_block_offset,
            basic_block_len: layout.basic_block_len,
            node_info_offset,
            node_info_size: layout.node_info_size,
        })
    }

    /// Returns the number of nodes in the serialized forest.
    pub fn node_count(&self) -> usize {
        self.node_count
    }

    /// Returns `true` when this view uses hashless convention and recomputed digests.
    pub fn is_hashless(&self) -> bool {
        self.is_hashless
    }

    /// Returns `true` when this view represents stripped serialization.
    pub fn is_stripped(&self) -> bool {
        self.is_stripped
    }

    /// Returns the number of procedure roots in the serialized forest.
    pub fn procedure_root_count(&self) -> usize {
        self.roots_count
    }

    /// Returns the procedure root id at the specified index.
    pub fn procedure_root_at(&self, index: usize) -> Result<MastNodeId, DeserializationError> {
        if index >= self.roots_count {
            return Err(DeserializationError::InvalidValue(format!(
                "root index {} out of bounds for {} roots",
                index, self.roots_count
            )));
        }

        let entry_offset = index
            .checked_mul(core::mem::size_of::<u32>())
            .and_then(|delta| self.roots_offset.checked_add(delta))
            .ok_or_else(|| {
                DeserializationError::InvalidValue("root offset overflow".to_string())
            })?;
        let entry_end = entry_offset.checked_add(core::mem::size_of::<u32>()).ok_or_else(|| {
            DeserializationError::InvalidValue("root length overflow".to_string())
        })?;
        if entry_end > self.bytes.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }

        let mut raw = [0u8; core::mem::size_of::<u32>()];
        raw.copy_from_slice(&self.bytes[entry_offset..entry_end]);
        MastNodeId::from_u32_with_node_count(u32::from_le_bytes(raw), self.node_count)
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
        if index >= self.node_count {
            return Err(DeserializationError::InvalidValue(format!(
                "node index {} out of bounds for {} nodes",
                index, self.node_count
            )));
        }

        let info =
            read_node_info_entry(self.bytes, self.node_info_offset, self.node_info_size, index)?;
        if let Some(hash_table) = &self.hash_table {
            let digest = hash_table[index];
            Ok(MastNodeInfo::from_parts(info.node_type(), digest))
        } else {
            Ok(info)
        }
    }

    fn basic_block_data(&self) -> Result<&[u8], DeserializationError> {
        let end = self.basic_block_offset.checked_add(self.basic_block_len).ok_or_else(|| {
            DeserializationError::InvalidValue("basic-block data overflow".to_string())
        })?;
        if end > self.bytes.len() {
            return Err(DeserializationError::UnexpectedEOF);
        }
        Ok(&self.bytes[self.basic_block_offset..end])
    }

    fn to_mast_forest_with_sections(
        &self,
        advice_map: AdviceMap,
        debug_info: super::DebugInfo,
    ) -> Result<MastForest, DeserializationError> {
        let basic_block_data_decoder = BasicBlockDataDecoder::new(self.basic_block_data()?);
        let mut mast_forest = MastForest::new();
        mast_forest.debug_info = debug_info;

        for index in 0..self.node_count {
            let node_info = self.node_info_at(index)?;
            let mast_node_builder =
                node_info.try_into_mast_node_builder(self.node_count, &basic_block_data_decoder)?;

            mast_node_builder.add_to_forest_relaxed(&mut mast_forest).map_err(|e| {
                DeserializationError::InvalidValue(format!(
                    "failed to add node to MAST forest while deserializing: {e}",
                ))
            })?;
        }

        for index in 0..self.procedure_root_count() {
            mast_forest.make_root(self.procedure_root_at(index)?);
        }

        mast_forest.advice_map = advice_map;
        Ok(mast_forest)
    }
}

fn read_node_info_entry(
    bytes: &[u8],
    node_info_offset: usize,
    node_info_size: usize,
    index: usize,
) -> Result<MastNodeInfo, DeserializationError> {
    let entry_offset = index
        .checked_mul(node_info_size)
        .and_then(|delta| node_info_offset.checked_add(delta))
        .ok_or_else(|| {
            DeserializationError::InvalidValue("node info offset overflow".to_string())
        })?;
    let entry_end = entry_offset.checked_add(node_info_size).ok_or_else(|| {
        DeserializationError::InvalidValue("node info length overflow".to_string())
    })?;
    if entry_end > bytes.len() {
        return Err(DeserializationError::UnexpectedEOF);
    }

    let mut reader = SliceReader::new(&bytes[entry_offset..entry_end]);
    MastNodeInfo::read_from(&mut reader)
}

fn recompute_hash_table(
    bytes: &[u8],
    node_count: usize,
    node_info_offset: usize,
    node_info_size: usize,
    basic_block_offset: usize,
    basic_block_len: usize,
) -> Result<Vec<crate::Word>, DeserializationError> {
    let basic_block_end = basic_block_offset.checked_add(basic_block_len).ok_or_else(|| {
        DeserializationError::InvalidValue("basic-block data overflow".to_string())
    })?;
    if basic_block_end > bytes.len() {
        return Err(DeserializationError::UnexpectedEOF);
    }
    let basic_block_data_decoder =
        BasicBlockDataDecoder::new(&bytes[basic_block_offset..basic_block_end]);

    let mut digests = Vec::with_capacity(node_count);

    for index in 0..node_count {
        let info = read_node_info_entry(bytes, node_info_offset, node_info_size, index)?;
        let computed = match info.node_type() {
            MastNodeType::Block { ops_offset } => {
                let op_batches = basic_block_data_decoder.decode_operations(ops_offset)?;
                let op_groups: Vec<Felt> =
                    op_batches.iter().flat_map(|batch| *batch.groups()).collect();
                hasher::hash_elements(&op_groups)
            },
            MastNodeType::Join { left_child_id, right_child_id } => {
                let left = checked_child_index(index, left_child_id, node_count)?;
                let right = checked_child_index(index, right_child_id, node_count)?;
                hasher::merge_in_domain(&[digests[left], digests[right]], JoinNode::DOMAIN)
            },
            MastNodeType::Split { if_branch_id, else_branch_id } => {
                let on_true = checked_child_index(index, if_branch_id, node_count)?;
                let on_false = checked_child_index(index, else_branch_id, node_count)?;
                hasher::merge_in_domain(&[digests[on_true], digests[on_false]], SplitNode::DOMAIN)
            },
            MastNodeType::Loop { body_id } => {
                let body = checked_child_index(index, body_id, node_count)?;
                hasher::merge_in_domain(&[digests[body], crate::Word::default()], LoopNode::DOMAIN)
            },
            MastNodeType::Call { callee_id } => {
                let callee = checked_child_index(index, callee_id, node_count)?;
                hasher::merge_in_domain(
                    &[digests[callee], crate::Word::default()],
                    CallNode::CALL_DOMAIN,
                )
            },
            MastNodeType::SysCall { callee_id } => {
                let callee = checked_child_index(index, callee_id, node_count)?;
                hasher::merge_in_domain(
                    &[digests[callee], crate::Word::default()],
                    CallNode::SYSCALL_DOMAIN,
                )
            },
            MastNodeType::Dyn => DynNode::DYN_DEFAULT_DIGEST,
            MastNodeType::Dyncall => DynNode::DYNCALL_DEFAULT_DIGEST,
            MastNodeType::External => {
                // External digests cannot be reconstructed from local structure alone.
                // In HASHLESS mode we treat them as opaque payload to be resolved by later
                // semantic checks in higher layers.
                info.digest()
            },
        };

        digests.push(computed);
    }

    Ok(digests)
}

fn checked_child_index(
    parent_index: usize,
    child_id: u32,
    node_count: usize,
) -> Result<usize, DeserializationError> {
    let child_index = child_id as usize;
    if child_index >= node_count {
        return Err(DeserializationError::InvalidValue(format!(
            "child id {} out of bounds for {} nodes",
            child_id, node_count
        )));
    }
    if child_index >= parent_index {
        return Err(DeserializationError::InvalidValue(format!(
            "forward reference from node {} to {} in HASHLESS data",
            parent_index, child_id
        )));
    }
    Ok(child_index)
}

impl super::MastForestView for SerializedMastForest<'_> {
    fn node_count(&self) -> usize {
        SerializedMastForest::node_count(self)
    }

    fn node_info_at(&self, index: usize) -> Result<MastNodeInfo, DeserializationError> {
        SerializedMastForest::node_info_at(self, index)
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

    fn node_info_at(&self, index: usize) -> Result<MastNodeInfo, DeserializationError> {
        let node = self.nodes.as_slice().get(index).ok_or_else(|| {
            DeserializationError::InvalidValue(format!("node index {index} out of bounds"))
        })?;
        let ops_offset = if matches!(node, MastNode::Block(_)) {
            basic_block_offset_for_node_index(self.nodes.as_slice(), index)?
        } else {
            0
        };

        Ok(MastNodeInfo::new(node, ops_offset))
    }

    fn all_node_infos(&self) -> Result<Vec<MastNodeInfo>, DeserializationError> {
        let mut node_infos = Vec::with_capacity(self.nodes.len());
        let mut basic_block_data_offset = 0usize;

        for node in self.nodes.iter() {
            let ops_offset = if matches!(node, MastNode::Block(_)) {
                basic_block_data_offset.try_into().map_err(|_| {
                    DeserializationError::InvalidValue(
                        "basic-block data offset does not fit in u32".to_string(),
                    )
                })?
            } else {
                0
            };

            node_infos.push(MastNodeInfo::new(node, ops_offset));

            if let MastNode::Block(block) = node {
                basic_block_data_offset = basic_block_data_offset
                    .checked_add(basic_block_data_len(block))
                    .ok_or_else(|| {
                        DeserializationError::InvalidValue(
                            "basic-block data offset overflow".to_string(),
                        )
                    })?;
            }
        }

        Ok(node_infos)
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

fn basic_block_offset_for_node_index(
    nodes: &[MastNode],
    node_index: usize,
) -> Result<u32, DeserializationError> {
    let mut offset = 0usize;
    for node in nodes.iter().take(node_index) {
        if let MastNode::Block(block) = node {
            offset = offset.checked_add(basic_block_data_len(block)).ok_or_else(|| {
                DeserializationError::InvalidValue("basic-block data offset overflow".to_string())
            })?;
        }
    }

    offset.try_into().map_err(|_| {
        DeserializationError::InvalidValue(
            "basic-block data offset does not fit in u32".to_string(),
        )
    })
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
        decode_from_reader(source, ReaderDecodeMode::Trusted)?.into_mast_forest()
    }
}

pub(super) fn read_untrusted_with_flags<R: ByteReader>(
    source: &mut R,
) -> Result<(super::UntrustedMastForest, u8), DeserializationError> {
    let decoded = decode_from_reader(source, ReaderDecodeMode::Untrusted)?;
    let flags = decoded.flags();
    Ok((super::UntrustedMastForest { decoded }, flags))
}

enum ReaderDecodeMode {
    Trusted,
    Untrusted,
}

fn decode_from_reader<R: ByteReader>(
    source: &mut R,
    mode: ReaderDecodeMode,
) -> Result<DecodedSerializedForest, DeserializationError> {
    let mut recording = RecordingReader::new(source);
    let (flags, _version) = read_and_validate_header(&mut recording)?;
    let is_stripped = flags & FLAG_STRIPPED != 0;
    if flags & FLAG_HASHLESS != 0 && !is_stripped {
        return Err(DeserializationError::InvalidValue(
            "HASHLESS flag requires STRIPPED flag to be set".to_string(),
        ));
    }
    if flags & FLAG_HASHLESS != 0 && matches!(mode, ReaderDecodeMode::Trusted) {
        return Err(DeserializationError::InvalidValue(
            "HASHLESS flag is set; use UntrustedMastForest for untrusted input".to_string(),
        ));
    }

    let layout = scan_layout_sections(&mut recording)?;
    let advice_map = AdviceMap::read_from(&mut recording)?;
    let debug_info = if is_stripped {
        super::DebugInfo::empty_for_nodes(layout.node_count)
    } else {
        super::DebugInfo::read_from(&mut recording)?
    };

    Ok(DecodedSerializedForest {
        flags,
        bytes: recording.into_recorded(),
        layout,
        advice_map,
        debug_info,
    })
}

/// Scans the structural section layout in a single pass.
///
/// This is the canonical structural parser for counts and offsets used by both
/// reader-based deserialization and [`SerializedMastForest::new`].
fn scan_layout_sections<R: OffsetTrackingReader>(
    source: &mut R,
) -> Result<ScannedForestLayout, DeserializationError> {
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

    let node_info_size = MastNodeInfo::min_serialized_size();
    let node_info_offset = source.offset().checked_sub(body_start).ok_or_else(|| {
        DeserializationError::InvalidValue("node info offset underflow".to_string())
    })?;
    let node_infos_len = node_count.checked_mul(node_info_size).ok_or_else(|| {
        DeserializationError::InvalidValue("node info length overflow".to_string())
    })?;
    let _node_infos = source.read_slice(node_infos_len)?;

    Ok(ScannedForestLayout {
        node_count,
        roots_count,
        roots_offset,
        basic_block_offset,
        basic_block_len,
        node_info_offset,
        node_info_size,
    })
}

trait OffsetTrackingReader: ByteReader {
    fn offset(&self) -> usize;
}

struct RecordingReader<'a, R> {
    inner: &'a mut R,
    recorded: Vec<u8>,
}

impl<'a, R> RecordingReader<'a, R> {
    fn new(inner: &'a mut R) -> Self {
        Self { inner, recorded: Vec::new() }
    }

    fn into_recorded(self) -> Vec<u8> {
        self.recorded
    }
}

impl<R: ByteReader> ByteReader for RecordingReader<'_, R> {
    fn read_u8(&mut self) -> Result<u8, DeserializationError> {
        let byte = self.inner.read_u8()?;
        self.recorded.push(byte);
        Ok(byte)
    }

    fn peek_u8(&self) -> Result<u8, DeserializationError> {
        self.inner.peek_u8()
    }

    fn read_slice(&mut self, len: usize) -> Result<&[u8], DeserializationError> {
        let slice = self.inner.read_slice(len)?;
        self.recorded.extend_from_slice(slice);
        Ok(slice)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError> {
        let array = self.inner.read_array::<N>()?;
        self.recorded.extend_from_slice(&array);
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

impl<R: ByteReader> OffsetTrackingReader for RecordingReader<'_, R> {
    fn offset(&self) -> usize {
        self.recorded.len()
    }
}

struct CountingReader<'a, R> {
    inner: &'a mut R,
    offset: usize,
}

impl<'a, R> CountingReader<'a, R> {
    fn new(inner: &'a mut R) -> Self {
        Self { inner, offset: 0 }
    }
}

impl<R: ByteReader> ByteReader for CountingReader<'_, R> {
    fn read_u8(&mut self) -> Result<u8, DeserializationError> {
        let byte = self.inner.read_u8()?;
        self.offset = self
            .offset
            .checked_add(1)
            .ok_or_else(|| DeserializationError::InvalidValue("offset overflow".to_string()))?;
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
        Ok(slice)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DeserializationError> {
        let array = self.inner.read_array::<N>()?;
        self.offset = self
            .offset
            .checked_add(N)
            .ok_or_else(|| DeserializationError::InvalidValue("offset overflow".to_string()))?;
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

impl<R: ByteReader> OffsetTrackingReader for CountingReader<'_, R> {
    fn offset(&self) -> usize {
        self.offset
    }
}

/// Reads and validates the MAST header (magic, flags, version).
///
/// Returns the flags byte on success.
fn read_and_validate_header<R: ByteReader>(
    source: &mut R,
) -> Result<(u8, [u8; 3]), DeserializationError> {
    // Read magic
    let magic: [u8; 4] = source.read_array()?;
    if magic != *MAGIC {
        return Err(DeserializationError::InvalidValue(format!(
            "Invalid magic bytes. Expected '{:?}', got '{:?}'",
            *MAGIC, magic
        )));
    }

    // Read flags
    let flags: u8 = source.read_u8()?;

    // Read and validate version
    let version: [u8; 3] = source.read_array()?;
    if version != VERSION {
        return Err(DeserializationError::InvalidValue(format!(
            "Unsupported version. Got '{version:?}', but only '{VERSION:?}' is supported",
        )));
    }

    // Validate flags
    if flags & FLAGS_RESERVED_MASK != 0 {
        return Err(DeserializationError::InvalidValue(format!(
            "Unknown flags set in MAST header: {:#04x}. Reserved bits must be zero.",
            flags & FLAGS_RESERVED_MASK
        )));
    }

    Ok((flags, version))
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
        stripped_size_hint(self.0)
    }
}
