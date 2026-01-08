//! The serialization format of MastForest is as follows:
//!
//! (Metadata)
//! - MAGIC (5 bytes)
//! - VERSION (3 bytes)
//!
//! (Counts)
//! - nodes count (`usize`)
//! - decorators count (`usize`) - reserved for future use in lazy loading (#2504)
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
//! (DebugInfo section)
//! - Decorator data (raw bytes for decorator payloads)
//! - String table (deduplicated strings)
//! - Decorator infos (`Vec<DecoratorInfo>`)
//! - Error codes map (`BTreeMap<u64, String>`)
//! - OpToDecoratorIds CSR (operation-indexed decorators, dense representation)
//! - NodeToDecoratorIds CSR (before_enter and after_exit decorators, dense representation)
//! - Procedure names map (`BTreeMap<Word, String>`)

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

/// Magic string for detecting that a file is binary-encoded MAST.
const MAGIC: &[u8; 5] = b"MAST\0";

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
///   conversions).
const VERSION: [u8; 3] = [0, 0, 1];

// MAST FOREST SERIALIZATION/DESERIALIZATION
// ================================================================================================

impl Serializable for MastForest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let mut basic_block_data_builder = BasicBlockDataBuilder::new();

        // magic & version
        target.write_bytes(MAGIC);
        target.write_bytes(&VERSION);

        // decorator & node counts
        target.write_usize(self.nodes.len());
        // Expected to be used in #2504. Remove if this issue is resolved without using.
        target.write_usize(self.debug_info.num_decorators());

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

        // Serialize DebugInfo directly (includes decorators, error_codes, CSR structures,
        // and procedure_names)
        self.debug_info.write_into(target);
    }
}

impl Deserializable for MastForest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        read_and_validate_magic(source)?;
        read_and_validate_version(source)?;

        // Reading sections metadata
        let node_count = source.read_usize()?;
        // Expected to be used in #2504. Remove if this issue is resolved without using.
        let _decorator_count = source.read_usize()?; // Read for wire format compatibility

        // Reading procedure roots
        let roots: Vec<u32> = Deserializable::read_from(source)?;

        // Reading nodes
        let basic_block_data: Vec<u8> = Deserializable::read_from(source)?;
        let mast_node_infos: Vec<MastNodeInfo> = node_infos_iter(source, node_count)
            .collect::<Result<Vec<MastNodeInfo>, DeserializationError>>()?;

        let advice_map = AdviceMap::read_from(source)?;

        // Deserialize DebugInfo directly (includes decorators, error_codes, CSR structures,
        // and procedure_names)
        let debug_info = super::DebugInfo::read_from(source)?;

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

fn read_and_validate_magic<R: ByteReader>(source: &mut R) -> Result<[u8; 5], DeserializationError> {
    let magic: [u8; 5] = source.read_array()?;
    if magic != *MAGIC {
        return Err(DeserializationError::InvalidValue(format!(
            "Invalid magic bytes. Expected '{:?}', got '{:?}'",
            *MAGIC, magic
        )));
    }
    Ok(magic)
}

fn read_and_validate_version<R: ByteReader>(
    source: &mut R,
) -> Result<[u8; 3], DeserializationError> {
    let version: [u8; 3] = source.read_array()?;
    if version != VERSION {
        return Err(DeserializationError::InvalidValue(format!(
            "Unsupported version. Got '{version:?}', but only '{VERSION:?}' is supported",
        )));
    }
    Ok(version)
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
