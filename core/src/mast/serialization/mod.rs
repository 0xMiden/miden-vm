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

use alloc::vec::Vec;

use super::{MastForest, MastNode, MastNodeId};
use crate::{
    AdviceMap,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

pub(crate) mod decorator;

mod info;
use info::MastNodeInfo;

mod basic_blocks;
use basic_blocks::{BasicBlockDataBuilder, BasicBlockDataDecoder};

pub(crate) mod string_table;
pub(crate) use string_table::StringTable;

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

/// Mask for reserved flag bits that must be zero.
///
/// Bits 1-7 are reserved for future use. If any are set, deserialization fails.
const FLAGS_RESERVED_MASK: u8 = 0xfe;

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
const VERSION: [u8; 3] = [0, 0, 1];

// MAST FOREST SERIALIZATION/DESERIALIZATION
// ================================================================================================

impl Serializable for MastForest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.write_into_with_options(target, false);
    }
}

impl MastForest {
    /// Internal serialization with options.
    ///
    /// When `stripped` is true, the DebugInfo section is omitted and the FLAGS byte
    /// has bit 0 set.
    fn write_into_with_options<W: ByteWriter>(&self, target: &mut W, stripped: bool) {
        let mut basic_block_data_builder = BasicBlockDataBuilder::new();

        // magic & flags
        target.write_bytes(MAGIC);
        target.write_u8(if stripped { FLAG_STRIPPED } else { 0x00 });

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

impl Deserializable for MastForest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let flags = read_and_validate_header(source)?;
        let is_stripped = flags & FLAG_STRIPPED != 0;

        // Reading sections metadata
        let node_count = source.read_usize()?;
        let _decorator_count = source.read_usize()?; // Read for wire format compatibility

        // Reading procedure roots
        let roots: Vec<u32> = Deserializable::read_from(source)?;

        // Reading nodes
        let basic_block_data: Vec<u8> = Deserializable::read_from(source)?;
        let mast_node_infos: Vec<MastNodeInfo> = node_infos_iter(source, node_count)
            .collect::<Result<Vec<MastNodeInfo>, DeserializationError>>()?;

        let advice_map = AdviceMap::read_from(source)?;

        // Deserialize DebugInfo or create empty one if stripped
        let debug_info = if is_stripped {
            super::DebugInfo::empty_for_nodes(node_count)
        } else {
            super::DebugInfo::read_from(source)?
        };

        // Constructing MastForest
        let mast_forest = {
            let mut mast_forest = MastForest::new();

            // Set the fully deserialized debug_info - it already contains all mappings
            mast_forest.debug_info = debug_info;

            // Convert node infos to builders
            let basic_block_data_decoder = BasicBlockDataDecoder::new(&basic_block_data);
            let mast_builders = mast_node_infos
                .into_iter()
                .map(|node_info| {
                    node_info.try_into_mast_node_builder(node_count, &basic_block_data_decoder)
                })
                .collect::<Result<Vec<_>, _>>()?;

            // Add all builders to forest using relaxed validation
            for mast_node_builder in mast_builders {
                mast_node_builder.add_to_forest_relaxed(&mut mast_forest).map_err(|e| {
                    DeserializationError::InvalidValue(format!(
                        "failed to add node to MAST forest while deserializing: {e}",
                    ))
                })?;
            }

            // roots
            for root in roots {
                // make sure the root is valid in the context of the MAST forest
                let root = MastNodeId::from_u32_safe(root, &mast_forest)?;
                mast_forest.make_root(root);
            }

            mast_forest.advice_map = advice_map;

            mast_forest
        };

        // Note: Full validation of deserialized MastForests (e.g., checking that procedure name
        // digests correspond to procedure roots) is intentionally not performed here.
        // The serialized format is expected to come from a trusted source (e.g., the assembler
        // or a verified package). Callers should use MastForest::validate() if validation of
        // untrusted input is needed.

        Ok(mast_forest)
    }
}

/// Reads and validates the MAST header (magic, flags, version).
///
/// Returns the flags byte on success.
fn read_and_validate_header<R: ByteReader>(source: &mut R) -> Result<u8, DeserializationError> {
    // Read magic
    let magic: [u8; 4] = source.read_array()?;
    if magic != *MAGIC {
        return Err(DeserializationError::InvalidValue(format!(
            "Invalid magic bytes. Expected '{:?}', got '{:?}'",
            *MAGIC, magic
        )));
    }

    // Read and validate flags
    let flags: u8 = source.read_u8()?;
    if flags & FLAGS_RESERVED_MASK != 0 {
        return Err(DeserializationError::InvalidValue(format!(
            "Unknown flags set in MAST header: {:#04x}. Reserved bits must be zero.",
            flags & FLAGS_RESERVED_MASK
        )));
    }

    // Read and validate version
    let version: [u8; 3] = source.read_array()?;
    if version != VERSION {
        return Err(DeserializationError::InvalidValue(format!(
            "Unsupported version. Got '{version:?}', but only '{VERSION:?}' is supported",
        )));
    }

    Ok(flags)
}

fn node_infos_iter<'a, R>(
    source: &'a mut R,
    node_count: usize,
) -> impl Iterator<Item = Result<MastNodeInfo, DeserializationError>> + 'a
where
    R: ByteReader + 'a,
{
    let mut remaining = node_count;
    core::iter::from_fn(move || {
        if remaining == 0 {
            return None;
        }
        remaining -= 1;
        Some(MastNodeInfo::read_from(source))
    })
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
        self.0.write_into_with_options(target, true);
    }
}
