//! The serialization format of MastForest is as follows:
//!
//! (Metadata)
//! - MAGIC
//! - VERSION
//!
//! (sections metadata)
//! - nodes length (`usize`)
//! - decorator data section offset (`usize`) (not implemented, see issue #1580)
//! - decorators length (`usize`)
//!
//! (procedure roots section)
//! - procedure roots (`Vec<MastNodeId>`)
//!
//! (basic block data section)
//! - basic block data
//!
//! (node info section)
//! - MAST node infos (`Vec<MastNodeInfo>`)
//!
//! (advice map section)
//! - Advice map (AdviceMap)
//!
//! (error_codes map section)
//! - Error codes map (BTreeMap<u64, String>)
//!
//! (decorator data section)
//! - Decorator data
//! - String table
//!
//! (decorator info section)
//! - decorator infos (`Vec<DecoratorInfo>`)
//!
//! (basic block decorator lists section)
//! - basic block decorator lists (`Vec<(MastNodeId, Vec<(usize, DecoratorId)>)>`)
//!
//! (before enter and after exit decorators section)
//! - before enter decorators (`Vec<(MastNodeId, Vec<DecoratorId>)>`)
//! - after exit decorators (`Vec<(MastNodeId, Vec<DecoratorId>)>`)

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use decorator::{DecoratorDataBuilder, DecoratorInfo};
use string_table::StringTable;

use super::{DecoratedOpLink, DecoratorId, MastForest, MastNode, MastNodeId};
use crate::{
    AdviceMap,
    mast::{MastForestContributor, MastNodeBuilder, node::MastNodeExt},
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

mod decorator;

mod info;
use info::MastNodeInfo;

mod basic_blocks;
use basic_blocks::{BasicBlockDataBuilder, BasicBlockDataDecoder};

use crate::DecoratorList;

mod string_table;

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
const VERSION: [u8; 3] = [0, 0, 0];

// MAST FOREST SERIALIZATION/DESERIALIZATION
// ================================================================================================

impl Serializable for MastForest {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let mut basic_block_data_builder = BasicBlockDataBuilder::new();

        // Set up "before enter" and "after exit" decorators by `MastNodeId`
        let mut before_enter_decorators: Vec<(usize, Vec<DecoratorId>)> = Vec::new();
        let mut after_exit_decorators: Vec<(usize, Vec<DecoratorId>)> = Vec::new();

        let mut basic_block_decorators: Vec<(usize, Vec<DecoratedOpLink>)> = Vec::new();

        // magic & version
        target.write_bytes(MAGIC);
        target.write_bytes(&VERSION);

        // decorator & node counts
        target.write_usize(self.nodes.len());
        target.write_usize(self.decorators.len());

        // roots
        let roots: Vec<u32> = self.roots.iter().copied().map(u32::from).collect();
        roots.write_into(target);

        // Prepare MAST node infos, but don't store them yet. We store them at the end to make
        // deserialization more efficient.
        let mast_node_infos: Vec<MastNodeInfo> = self
            .nodes
            .iter()
            .enumerate()
            .map(|(mast_node_id, mast_node)| {
                if !mast_node.before_enter().is_empty() {
                    before_enter_decorators.push((mast_node_id, mast_node.before_enter().to_vec()));
                }
                if !mast_node.after_exit().is_empty() {
                    after_exit_decorators.push((mast_node_id, mast_node.after_exit().to_vec()));
                }

                let ops_offset = if let MastNode::Block(basic_block) = mast_node {
                    let ops_offset = basic_block_data_builder.encode_basic_block(basic_block);

                    basic_block_decorators
                        .push((mast_node_id, basic_block.raw_op_indexed_decorators(self)));

                    ops_offset
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
        let error_codes: BTreeMap<u64, String> =
            self.error_codes.iter().map(|(k, v)| (*k, v.to_string())).collect();
        error_codes.write_into(target);

        // write all decorator data below

        let mut decorator_data_builder = DecoratorDataBuilder::new();
        for decorator in &self.decorators {
            decorator_data_builder.add_decorator(decorator)
        }

        let (decorator_data, decorator_infos, string_table) = decorator_data_builder.finalize();

        // decorator data buffers
        decorator_data.write_into(target);
        string_table.write_into(target);

        // Write decorator infos
        for decorator_info in decorator_infos {
            decorator_info.write_into(target);
        }

        basic_block_decorators.write_into(target);

        // Write "before enter" and "after exit" decorators
        before_enter_decorators.write_into(target);
        after_exit_decorators.write_into(target);
    }
}

impl Deserializable for MastForest {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        read_and_validate_magic(source)?;
        read_and_validate_version(source)?;

        // Reading sections metadata
        let node_count = source.read_usize()?;
        let decorator_count = source.read_usize()?;

        // Reading procedure roots
        let roots: Vec<u32> = Deserializable::read_from(source)?;

        // Reading nodes
        let basic_block_data: Vec<u8> = Deserializable::read_from(source)?;
        let mast_node_infos: Vec<MastNodeInfo> = node_infos_iter(source, node_count)
            .collect::<Result<Vec<MastNodeInfo>, DeserializationError>>()?;

        let advice_map = AdviceMap::read_from(source)?;

        let error_codes: BTreeMap<u64, String> = Deserializable::read_from(source)?;
        let error_codes: BTreeMap<u64, Arc<str>> =
            error_codes.into_iter().map(|(k, v)| (k, Arc::from(v))).collect();

        // Reading Decorators
        let decorator_data: Vec<u8> = Deserializable::read_from(source)?;
        let string_table: StringTable = Deserializable::read_from(source)?;
        let decorator_infos = decorator_infos_iter(source, decorator_count);

        // Constructing MastForest
        let mut mast_forest = {
            let mut mast_forest = MastForest::new();

            for decorator_info in decorator_infos {
                let decorator_info = decorator_info?;
                let decorator =
                    decorator_info.try_into_decorator(&string_table, &decorator_data)?;

                mast_forest.add_decorator(decorator).map_err(|e| {
                    DeserializationError::InvalidValue(format!(
                        "failed to add decorator to MAST forest while deserializing: {e}",
                    ))
                })?;
            }

            // nodes
            let basic_block_data_decoder = BasicBlockDataDecoder::new(&basic_block_data);
            let mut mast_builders = mast_node_infos
                .into_iter()
                .map(|node_info| {
                    node_info.try_into_mast_node_builder(node_count, &basic_block_data_decoder)
                })
                .collect::<Result<Vec<_>, _>>()?;

            let basic_block_decorators: Vec<(usize, DecoratorList)> =
                read_block_decorators(source, mast_forest.decorators.len())?;
            for (node_id, decorator_list) in basic_block_decorators {
                match &mut mast_builders[node_id] {
                    MastNodeBuilder::BasicBlock(basic_block) => {
                        basic_block.set_decorators(decorator_list);
                    },
                    other => {
                        return Err(DeserializationError::InvalidValue(format!(
                            "expected mast node with id {node_id} to be a basic block, found {other:?}"
                        )));
                    },
                }
            }

            // read "before enter" and "after exit" decorators, and update the corresponding nodes
            let before_enter_decorators: Vec<(usize, Vec<DecoratorId>)> =
                read_before_after_decorators(source, mast_forest.decorators.len())?;
            for (node_id, decorator_ids) in before_enter_decorators {
                mast_builders[node_id].append_before_enter(decorator_ids);
            }

            let after_exit_decorators: Vec<(usize, Vec<DecoratorId>)> =
                read_before_after_decorators(source, mast_forest.decorators.len())?;
            for (node_id, decorator_ids) in after_exit_decorators {
                mast_builders[node_id].append_after_exit(decorator_ids);
            }

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

        mast_forest.error_codes = error_codes;

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

fn read_block_decorators<R: ByteReader>(
    source: &mut R,
    decorator_count: usize,
) -> Result<Vec<(usize, DecoratorList)>, DeserializationError> {
    let vec_len: usize = source.read()?;
    let mut out_vec: Vec<_> = Vec::with_capacity(vec_len);

    for _ in 0..vec_len {
        let node_id: usize = source.read()?;

        let decorator_vec_len: usize = source.read()?;
        let mut inner_vec: Vec<DecoratedOpLink> = Vec::with_capacity(decorator_vec_len);
        for _ in 0..decorator_vec_len {
            let op_id: usize = source.read()?;
            let decorator_id = DecoratorId::from_u32_bounded(source.read()?, decorator_count)?;
            inner_vec.push((op_id, decorator_id));
        }

        out_vec.push((node_id, inner_vec));
    }

    Ok(out_vec)
}

fn decorator_infos_iter<'a, R>(
    source: &'a mut R,
    decorator_count: usize,
) -> impl Iterator<Item = Result<DecoratorInfo, DeserializationError>> + 'a
where
    R: ByteReader + 'a,
{
    let mut remaining = decorator_count;
    core::iter::from_fn(move || {
        if remaining == 0 {
            return None;
        }
        remaining -= 1;
        Some(DecoratorInfo::read_from(source))
    })
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

/// Reads the `before_enter_decorators` and `after_exit_decorators` of the serialized `MastForest`
/// format.
///
/// Note that we need this custom format because we cannot implement `Deserializable` for
/// `DecoratorId` (in favor of using [`DecoratorId::from_u32_bounded`]).
fn read_before_after_decorators<R: ByteReader>(
    source: &mut R,
    decorator_count: usize,
) -> Result<Vec<(usize, Vec<DecoratorId>)>, DeserializationError> {
    let vec_len: usize = source.read()?;
    let mut out_vec: Vec<_> = Vec::with_capacity(vec_len);

    for _ in 0..vec_len {
        let node_id: usize = source.read()?;

        let inner_vec_len: usize = source.read()?;
        let mut inner_vec: Vec<DecoratorId> = Vec::with_capacity(inner_vec_len);
        for _ in 0..inner_vec_len {
            let decorator_id = DecoratorId::from_u32_bounded(source.read()?, decorator_count)?;
            inner_vec.push(decorator_id);
        }

        out_vec.push((node_id, inner_vec));
    }

    Ok(out_vec)
}
