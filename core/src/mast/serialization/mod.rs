//! MAST forest serialization keeps one fixed structural layout for full, stripped, and hashless
//! payloads.
//!
//! The main goal is to keep random access cheap in stripped and hashless modes. Node structure
//! stays in one fixed-width section. Variable-size data lives in separate sections. Internal node
//! digests also live in a separate section so hashless payloads can omit them without changing the
//! structural layout.
//!
//! Wire flags describe serializer intent, not reader trust policy. Trusted [`MastForest`] reads
//! reject hashless payloads. [`crate::mast::UntrustedMastForest`] accepts them and rebuilds
//! non-external digests before use. If a non-hashless payload is sent down the untrusted path,
//! validation recomputes those digests and requires them to match the serialized values.
//! Budgeted untrusted reads always bound wire counts during layout scanning via
//! [`ByteReader::max_alloc`]. Callers that opt into validation budgeting also get a second check:
//! - later stripped/hashless helper allocations are charged against an explicit validation budget
//!   before the corresponding `Vec` or CSR scaffolding is created
//! - the default convenience path uses a coarse validation budget derived from the input size; this
//!   is intentionally a simple bound for common callers, not an exact peak-memory formula
//!
//! The main layers fit together like this:
//!
//! ```text
//! wire bytes
//!     |
//!     +--> ForestLayout -----------> SerializedMastForest --+
//!     |        absolute offsets         structural view      |
//!     |                                                     v
//!     +--> UntrustedMastForest ----validate----> ResolvedSerializedForest ---> MastForest
//!              bytes + parsed state                digest-backed view            trusted runtime
//!
//! MastForestView is the shared random-access API implemented by SerializedMastForest and
//! MastForest.
//! ```
//!
//! The format is:
//!
//! (Metadata)
//! - MAGIC (4 bytes) + FLAGS (1 byte) + VERSION (3 bytes)
//!
//! (Counts)
//! - nodes count (`usize`)
//!
//! (Procedure roots section)
//! - procedure roots (`Vec<u32>` as MastNodeId values)
//!
//! (Basic block data section)
//! - basic block data (padded operations + batch metadata)
//!
//! (Node entries section)
//! - fixed-width structural node entries (`Vec<MastNodeEntry>`)
//! - `Block` entries store offsets into the basic-block section above
//!
//! (External digest section)
//! - digests for `External` nodes only (`Vec<Word>`, ordered by node index)
//! - lookup is dense-by-kind: the Nth external node uses slot N in this section
//!
//! (Node hash section - omitted if FLAGS bit 1 is set)
//! - digests for all non-external nodes (`Vec<Word>`, ordered by node index)
//! - lookup is also dense-by-kind: the Nth non-external node uses slot N in this section
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
//! In stripped format, the `DebugInfo` section is omitted and readers materialize an empty
//! `DebugInfo`.
//!
//! In hashless format, the internal node-hash section is omitted and `HASHLESS` also implies
//! `STRIPPED`. External node digests still stay on the wire because they cannot be rebuilt from
//! local structure. This keeps hashless focused on the untrusted-validation use case: trusted
//! reads reject `HASHLESS`, and the untrusted path rebuilds the data it actually trusts before
//! use, so supporting a separate "hashless but with debug info" mode would add another wire mode
//! without changing the validation semantics.
//!
//! Readers recover per-node digest lookup by scanning node entries once and building a compact
//! "slot by node index" table. This preserves random access without forcing all digests into the
//! same contiguous array on the wire.
//!
//! Public entry points adopt these policies:
//! - [`MastForest::read_from_bytes`]: trusted full payload, no hashless support.
//! - [`SerializedMastForest::new`]: structural inspection for local tooling, including hashless
//!   payloads; not an untrusted-validation entry point.
//! - [`crate::mast::UntrustedMastForest::read_from_bytes`] /
//!   [`crate::mast::UntrustedMastForest::read_from_bytes_with_budgets`]: untrusted parsing plus
//!   later validation before use.

#[cfg(test)]
use alloc::string::ToString;
use alloc::{format, vec::Vec};

use miden_utils_sync::OnceLockCompat;

use super::{MastForest, MastNode, MastNodeId};
use crate::{
    advice::AdviceMap,
    mast::node::MastNodeExt,
    serde::{
        BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        SliceReader,
    },
};

pub(crate) mod asm_op;
pub(crate) mod decorator;

mod info;
pub use info::{MastNodeEntry, MastNodeInfo};

mod view;
pub use view::MastForestView;

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

/// Default multiplier for the untrusted validation allocation budget.
///
/// The budgeted byte reader limits wire-driven parsing. Hashless and stripped validation also
/// needs transient per-node allocations for the slot table, empty debug-info scaffolding, and
/// rebuilt digest table. The generic untrusted path also retains a recorded copy of the consumed
/// serialized payload for deferred validation.
///
/// This convenience multiplier is therefore a coarse "wire bytes plus worst-case helper
/// headroom" bound:
/// - `* 6` covers the helper-allocation model introduced with explicit validation budgeting
/// - `+ 1 * bytes_len` covers the retained serialized copy recorded during untrusted reads
///
/// It is deliberately conservative and exists to make the default
/// [`crate::mast::UntrustedMastForest::read_from_bytes`] path usable without forcing callers to
/// size each helper allocation themselves. Callers with stricter limits should use
/// [`crate::mast::UntrustedMastForest::read_from_bytes_with_budgets`] and choose explicit parsing
/// and validation budgets.
const DEFAULT_UNTRUSTED_ALLOCATION_BUDGET_MULTIPLIER: usize = 7;

/// Byte-read budget multiplier for trusted full deserialization from a byte slice.
///
/// The budget is intentionally finite to reject malicious length prefixes, but larger than the
/// source length because collection deserialization uses conservative per-element size estimates.
const TRUSTED_BYTE_READ_BUDGET_MULTIPLIER: usize = 64;

// CONSTANTS
// ================================================================================================

/// Magic bytes for detecting that a file is binary-encoded MAST.
///
/// The header is `b"MAST"` + flags byte + version bytes.
///
/// This repurposes the old `b"MAST\0"` terminator as the flags byte, so legacy payloads still
/// decode as "debug info present".
const MAGIC: &[u8; 4] = b"MAST";

/// Flag indicating that the `DebugInfo` section is omitted from the wire payload.
///
/// Readers treat this as serializer intent about the wire layout, not as a trust decision.
const FLAG_STRIPPED: u8 = 0x01;

/// Flag indicating that the internal node-hash section is omitted from the wire payload.
///
/// External digests still remain serialized in their own section because they cannot be rebuilt
/// from local structure. This flag implies [`FLAG_STRIPPED`] because no supported consumer treats
/// wire `DebugInfo` as trusted in hashless mode: [`crate::mast::MastForest`] rejects `HASHLESS`,
/// [`SerializedMastForest::new`] accepts it only for structural inspection, and the untrusted path
/// rebuilds the data it actually trusts before use.
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
///   rejects HASHLESS. Split fixed-width node entries from digest storage. External digests moved
///   to a dedicated section. Hashless serialization omits the general node-hash section entirely.
///   Dropped the serialized decorator-count field because it was not used by the wire layout or
///   deserializers.
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

        // node count
        target.write_usize(self.nodes.len());

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

pub(super) fn write_stripped_into<W: ByteWriter>(forest: &MastForest, target: &mut W) {
    forest.write_into_with_options(target, true, false);
}

pub(super) fn write_hashless_into<W: ByteWriter>(forest: &MastForest, target: &mut W) {
    forest.write_into_with_options(target, true, true);
}

pub(super) fn stripped_size_hint(forest: &MastForest) -> usize {
    serialized_size_hint(forest, true, false)
}

fn serialized_size_hint(forest: &MastForest, stripped: bool, hashless: bool) -> usize {
    let node_count = forest.nodes.len();
    let external_count = forest.nodes.iter().filter(|node| node.is_external()).count();
    let non_external_count = node_count - external_count;

    let mut size = MAGIC.len() + 1 + VERSION.len();
    size += node_count.get_size_hint();

    let roots_len = forest.roots.len();
    size += roots_len.get_size_hint();
    size += roots_len * size_of::<u32>();

    let mut basic_block_len = 0usize;
    for node in forest.nodes.iter() {
        if let MastNode::Block(block) = node {
            basic_block_len += basic_block_data_len(block);
        }
    }
    size += basic_block_len.get_size_hint() + basic_block_len;

    size += node_count * MastNodeEntry::SERIALIZED_SIZE;
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

/// A zero-copy structural view over serialized MAST forest bytes.
///
/// This view accepts full, stripped, and hashless payloads. It validates the header and the
/// fixed-width structural sections needed for random access, but it does not fully materialize the
/// forest.
///
/// Use this when callers need random access to roots or node metadata without deserializing the
/// full forest. For strict trusted deserialization, use
/// [`crate::mast::MastForest::read_from_bytes`].
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
    flags: WireFlags,
    layout: ForestLayout,
    resolved: OnceLockCompat<Result<ResolvedSerializedForest<'a>, DeserializationError>>,
}

impl<'a> SerializedMastForest<'a> {
    /// Creates a new view from serialized bytes.
    ///
    /// The input may be full, stripped, or hashless format.
    /// Structural parsing is delegated to the same single-pass scanner used by reader-based
    /// deserialization paths.
    ///
    /// This constructor is layout-oriented: it validates the header and sections needed for
    /// node/roots/random-access metadata only. It does not validate or fully parse trailing
    /// `AdviceMap` / `DebugInfo` payloads.
    ///
    /// Treat this as a trusted inspection API, not as an untrusted-validation entry point. It is
    /// appropriate for local tools that need random access over serialized structure, but callers
    /// handling adversarial bytes should use [`crate::mast::UntrustedMastForest`] instead.
    ///
    /// In particular, this constructor does **not** protect callers from untrusted-input concerns
    /// that are enforced by [`crate::mast::UntrustedMastForest::validate`]. It does not:
    /// - verify that serialized non-external digests match the structure they describe
    /// - check topological ordering / forward-reference constraints
    /// - validate basic-block batch invariants or procedure-name-root consistency
    /// - fully parse or validate trailing `AdviceMap` / `DebugInfo` payloads
    /// - provide a bounded-work guarantee for hashless digest-backed inspection
    ///
    /// For strict full-payload validation, use
    /// [`crate::mast::MastForest::read_from_bytes`].
    ///
    /// Wire flags describe serializer intent, not trust policy. This constructor accepts
    /// hashless payloads for inspection even though trusted [`crate::mast::MastForest`]
    /// deserialization rejects them.
    ///
    /// Digest lookup follows the wire layout:
    /// - If the internal-hash section is present, non-external node digests are read from it.
    /// - If the internal-hash section is absent, the first digest-backed access rebuilds all
    ///   non-external node digests from structure and caches them.
    /// - External node digests are always read from the external-digest section.
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

        Ok(Self {
            bytes,
            flags,
            layout,
            resolved: OnceLockCompat::new(),
        })
    }

    /// Returns the number of nodes in the serialized forest.
    pub fn node_count(&self) -> usize {
        self.layout.node_count
    }

    /// Returns `true` when the wire header says that the internal-hash section is omitted.
    pub fn is_hashless(&self) -> bool {
        self.flags.is_hashless()
    }

    /// Returns `true` when the wire header says that the `DebugInfo` section is omitted.
    pub fn is_stripped(&self) -> bool {
        self.flags.is_stripped()
    }

    /// Returns the number of procedure roots in the serialized forest.
    pub fn procedure_root_count(&self) -> usize {
        self.layout.roots_count
    }

    /// Returns the procedure root id at the specified index.
    ///
    /// Returns an error if `index >= self.procedure_root_count()`.
    pub fn procedure_root_at(&self, index: usize) -> Result<MastNodeId, DeserializationError> {
        self.layout.read_procedure_root_at(self.bytes, index)
    }

    /// Returns the `MastNodeInfo` at the specified index.
    ///
    /// On hashless payloads, this may trigger the first digest-backed access and therefore the
    /// one-time rebuild of the non-external digest table described in [`Self::node_digest_at`].
    ///
    /// Returns an error if `index >= self.node_count()`.
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
    ///
    /// Returns an error if `index >= self.node_count()`.
    pub fn node_entry_at(&self, index: usize) -> Result<MastNodeEntry, DeserializationError> {
        self.layout.read_node_entry_at(self.bytes, index)
    }

    /// Returns the digest for the node at the specified index.
    ///
    /// This resolves digests lazily. If the internal-hash section is absent, the first
    /// digest-backed access rebuilds all non-external node digests and caches them.
    ///
    /// This means the hashless cost model is:
    /// - `node_count()`, `node_entry_at()`, and `procedure_root_at()` stay cheap and structural
    /// - the first `node_digest_at()` / `node_info_at()` call does `O(node_count)` digest rebuild
    ///   work and allocates the cached digest table
    /// - later digest lookups reuse that cache
    ///
    /// Returns an error if `index >= self.node_count()`.
    pub fn node_digest_at(&self, index: usize) -> Result<crate::Word, DeserializationError> {
        self.resolved()?.node_digest_at(index)
    }

    fn resolved(&self) -> Result<&ResolvedSerializedForest<'a>, DeserializationError> {
        self.resolved
            .get_or_init(|| ResolvedSerializedForest::new(self.bytes, self.layout))
            .as_ref()
            .map_err(Clone::clone)
    }
}

impl MastForestView for SerializedMastForest<'_> {
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

impl MastForestView for MastForest {
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

// TEST HELPERS
// ================================================================================================

#[cfg(test)]
impl SerializedMastForest<'_> {
    fn advice_map_offset(&self) -> Result<usize, DeserializationError> {
        self.layout.advice_map_offset(self.bytes.len())
    }

    fn node_entry_offset(&self) -> usize {
        self.layout.node_entry_offset
    }

    fn node_hash_offset(&self) -> Option<usize> {
        self.layout.node_hash_offset
    }

    fn digest_slot_at(&self, index: usize) -> usize {
        self.resolved()
            .expect("digest slots should be readable for a valid serialized view")
            .digest_slot_at(index)
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

    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let budget = bytes.len().saturating_mul(TRUSTED_BYTE_READ_BUDGET_MULTIPLIER);
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), budget);
        Self::read_from(&mut reader)
    }
}

impl super::UntrustedMastForest {
    pub(super) fn into_materialized(self) -> Result<MastForest, DeserializationError> {
        let resolved = if let Some(allocation_budget) = self.remaining_allocation_budget {
            ResolvedSerializedForest::new_with_allocation_budget(
                &self.bytes,
                self.layout,
                allocation_budget,
            )?
        } else {
            ResolvedSerializedForest::new(&self.bytes, self.layout)?
        };

        resolved.materialize(self.advice_map, self.debug_info)
    }
}

pub(super) fn read_untrusted_with_flags<R: ByteReader>(
    source: &mut R,
) -> Result<(super::UntrustedMastForest, u8), DeserializationError> {
    let (flags, forest) = decode_from_reader(source, true)?;
    log_untrusted_overspecification(flags);
    Ok((forest, flags.bits()))
}

pub(super) fn read_untrusted_with_flags_and_allocation_budget<R: ByteReader>(
    source: &mut R,
    allocation_budget: usize,
) -> Result<(super::UntrustedMastForest, u8), DeserializationError> {
    let (flags, forest) = decode_from_reader_inner(source, true, Some(allocation_budget))?;
    log_untrusted_overspecification(flags);
    Ok((forest, flags.bits()))
}

fn log_untrusted_overspecification(flags: WireFlags) {
    if !flags.is_hashless() {
        log::error!(
            "UntrustedMastForest expected HASHLESS input; supplied artifact includes wire node hashes, and validation will recompute them and require them to match"
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
    decode_from_reader_inner(source, allow_hashless, None)
}

fn decode_from_reader_inner<R: ByteReader>(
    source: &mut R,
    allow_hashless: bool,
    mut remaining_allocation_budget: Option<usize>,
) -> Result<(WireFlags, super::UntrustedMastForest), DeserializationError> {
    let mut recording = TrackingReader::new_recording(source);
    let (flags, layout) = read_header_and_scan_layout(&mut recording, allow_hashless)?;

    let advice_map = AdviceMap::read_from(&mut recording)?;
    let debug_info = if flags.is_stripped() {
        if let Some(allocation_budget) = &mut remaining_allocation_budget {
            reserve_allocation::<usize>(
                allocation_budget,
                layout.node_count.checked_add(1).ok_or_else(|| {
                    DeserializationError::InvalidValue("debug-info node count overflow".into())
                })?,
                "empty debug-info scaffolding",
            )?;
        }
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
            remaining_allocation_budget,
        },
    ))
}

pub(super) fn reserve_allocation<T>(
    remaining_budget: &mut usize,
    count: usize,
    label: &str,
) -> Result<(), DeserializationError> {
    let bytes_needed = count
        .checked_mul(size_of::<T>())
        .ok_or_else(|| DeserializationError::InvalidValue(format!("{label} size overflow")))?;
    if bytes_needed > *remaining_budget {
        return Err(DeserializationError::InvalidValue(format!(
            "{label} requires {bytes_needed} bytes, exceeding the remaining untrusted allocation budget of {} bytes",
            *remaining_budget
        )));
    }

    *remaining_budget -= bytes_needed;
    Ok(())
}

pub(super) fn default_untrusted_allocation_budget(bytes_len: usize) -> usize {
    bytes_len.saturating_mul(DEFAULT_UNTRUSTED_ALLOCATION_BUDGET_MULTIPLIER)
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
    /// This method uses the default untrusted wire/validation budget from
    /// [`super::UntrustedMastForest::read_from_bytes`].
    ///
    /// After deserialization, callers should use [`super::UntrustedMastForest::validate()`]
    /// to verify structural integrity and recompute all node hashes before using
    /// the forest.
    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        super::UntrustedMastForest::read_from_bytes(bytes)
    }
}
