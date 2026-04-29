//! MAST forest serialization keeps one fixed structural layout for full, stripped, and hashless
//! payloads.
//!
//! The main goal is to keep random access cheap in stripped and hashless modes. Node structure
//! stays in one fixed-width section. Variable-size data lives in separate sections. Internal node
//! digests live in the internal suffix of the node-digest section so hashless payloads can omit
//! them without changing the structural layout. External digests remain in the prefix because they
//! cannot be rebuilt from local structure.
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
//!     +--> ForestLayout -----------> MastForestWireView ----+
//!     |        absolute offsets         trusted cache view   |
//!     |                                                     v
//!     +--> UntrustedMastForest ----validate----> ResolvedSerializedForest ---> MastForest
//!              bytes + parsed state                digest-backed view            trusted runtime
//!
//! MastForestView is the shared random-access API implemented by MastForestWireView and
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
//! - internal nodes count (`usize`)
//! - external nodes count (`usize`)
//!
//! (Procedure roots section)
//! - procedure roots (`Vec<u32>` as MastNodeId values)
//!
//! (Basic block data section)
//! - basic block data (padded operations + batch metadata)
//!
//! (Node digest section)
//! - sorted external-node digest prefix (`Vec<Word>`, sorted lexicographically by wire bytes)
//! - internal-node digest suffix (`Vec<Word>`, ordered by node index; omitted if FLAGS bit 1 is
//!   set)
//!
//! (Node entries section)
//! - fixed-width structural node entries (`Vec<MastNodeEntry>`)
//! - `Block` entries store offsets into the basic-block section above
//! - serialized `External` entries store a digest slot into the sorted external prefix above
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
//! "slot by node index" table. This preserves random access while keeping external digest lookup
//! explicit and independent from in-memory node order.
//!
//! Public entry points adopt these policies:
//! - [`MastForest::read_from_bytes`]: trusted full payload, no hashless support.
//! - [`MastForestWireView::new`]: trusted wire-backed cache access; rejects hashless payloads.
//! - [`crate::mast::UntrustedMastForest::read_from_bytes`] /
//!   [`crate::mast::UntrustedMastForest::read_from_bytes_with_options`]: untrusted parsing plus
//!   later validation before use.

#[cfg(test)]
use alloc::string::ToString;
use alloc::{format, vec::Vec};
use core::mem::size_of;

use miden_utils_sync::OnceLockCompat;

use super::{MastForest, MastNode, MastNodeId};
use crate::{
    Word,
    advice::AdviceMap,
    mast::node::MastNodeExt,
    serde::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable, SliceReader,
    },
};

pub(crate) mod asm_op;
use asm_op::AsmOpInfo;
pub(crate) mod decorator;
use decorator::DecoratorInfo;

mod info;
use info::MastNodeWireEntry;
pub use info::{MastNodeEntry, MastNodeInfo};

mod view;
use view::WireAdviceMapView;
pub use view::{AdviceMapView, AdviceValueView, MastForestView};

mod layout;
pub(super) use layout::ForestLayout;
use layout::{OffsetTrackingReader, TrackingReader, WireFlags, read_header_and_scan_layout};

mod resolved;
pub(super) use resolved::external_digest_order_violation;
use resolved::{
    ResolvedSerializedForest, basic_block_offset_for_node_index, compare_words_by_wire,
};

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
/// rebuilt digest data.
/// The generic untrusted path also retains a recorded copy of the consumed
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
/// [`crate::mast::UntrustedMastForest::read_from_bytes_with_options`] and choose explicit parsing
/// and validation budgets.
const DEFAULT_UNTRUSTED_ALLOCATION_BUDGET_MULTIPLIER: usize = 7;

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
/// External digests still remain serialized in the node-digest prefix because they cannot be
/// rebuilt from local structure. This flag implies [`FLAG_STRIPPED`] because no supported consumer
/// treats wire `DebugInfo` as trusted in hashless mode: [`crate::mast::MastForest`] rejects
/// `HASHLESS`, and the untrusted path rebuilds the data it actually trusts before use.
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
///   to a sorted node-digest prefix and serialized `External` entries now carry a digest slot.
///   Hashless serialization omits the internal node-digest suffix entirely. Dropped the serialized
///   decorator-count field because it was not used by the wire layout or deserializers. Before any
///   public release on this branch, the same unreleased wire version also grew explicit
///   internal/external node counts in the header.
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

        // header counts
        let node_count = self.nodes.len();
        let external_node_count = self.nodes.iter().filter(|node| node.is_external()).count();
        let internal_node_count = node_count - external_node_count;
        target.write_usize(node_count);
        target.write_usize(internal_node_count);
        target.write_usize(external_node_count);

        // roots
        let roots: Vec<u32> = self.roots.iter().copied().map(u32::from).collect();
        roots.write_into(target);

        let mut sorted_external_digests = Vec::with_capacity(external_node_count);
        for (node_index, mast_node) in self.nodes.iter().enumerate() {
            if mast_node.is_external() {
                sorted_external_digests.push((mast_node.digest(), node_index));
            }
        }
        sorted_external_digests.sort_unstable_by(
            |(left_digest, left_index), (right_digest, right_index)| {
                compare_words_by_wire(left_digest, right_digest)
                    .then_with(|| left_index.cmp(right_index))
            },
        );

        let mut external_digest_slot_by_node = Vec::new();
        external_digest_slot_by_node.resize(node_count, None);
        for (slot, (_, node_index)) in sorted_external_digests.iter().enumerate() {
            let slot = u32::try_from(slot)
                .expect("external digest slot should fit in u32 because MastForest node ids do");
            external_digest_slot_by_node[*node_index] = Some(slot);
        }

        let mut mast_node_entries = Vec::with_capacity(self.nodes.len());
        let mut node_hashes = Vec::new();

        for (node_index, mast_node) in self.nodes.iter().enumerate() {
            let ops_offset = if let MastNode::Block(basic_block) = mast_node {
                basic_block_data_builder.encode_basic_block(basic_block)
            } else {
                0
            };

            let mast_node_entry = MastNodeEntry::new(mast_node, ops_offset);
            let external_digest_slot = if mast_node.is_external() {
                let digest_slot = external_digest_slot_by_node[node_index]
                    .expect("external node should have a digest slot");
                Some(digest_slot)
            } else if !hashless {
                node_hashes.push(mast_node.digest());
                None
            } else {
                None
            };
            mast_node_entries.push(MastNodeWireEntry::new(mast_node_entry, external_digest_slot));
        }

        let basic_block_data = basic_block_data_builder.finalize();
        basic_block_data.write_into(target);

        for (digest, _) in sorted_external_digests {
            digest.write_into(target);
        }

        if !hashless {
            for digest in node_hashes {
                digest.write_into(target);
            }
        }

        for mast_node_entry in mast_node_entries {
            mast_node_entry.write_into(target);
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
    size += non_external_count.get_size_hint();
    size += external_count.get_size_hint();

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
    size += external_count * Word::min_serialized_size();
    if !hashless {
        size += non_external_count * Word::min_serialized_size();
    }
    size += forest.advice_map.serialized_size_hint();
    if !stripped {
        size += forest.debug_info.get_size_hint();
    }

    size
}

/// Trusted read backing mode for read-only MAST forest access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MastForestReadMode {
    /// Deserialize the full trusted cache into a materialized [`MastForest`].
    Materialized,
    /// Borrow complete trusted cache bytes and serve read-only data by random access.
    WireBacked,
}

/// Read-only trusted MAST forest handle.
#[derive(Debug)]
pub enum MastForestReadView<'a> {
    /// A fully materialized forest.
    Materialized(MastForest),
    /// A trusted wire-backed cache view.
    WireBacked(MastForestWireView<'a>),
}

/// A trusted wire-backed view over serialized MAST forest bytes.
///
/// This view accepts complete full or stripped payloads with hashes. It validates the header and
/// the fixed-width structural sections needed for random access, but it does not fully materialize
/// the forest. Hashless payloads are rejected because trusted cache bytes must be complete.
///
/// Use this when callers need random access to roots or node metadata without deserializing the
/// full forest. For strict trusted deserialization, use
/// [`crate::mast::MastForest::read_from_bytes`].
///
/// # Examples
///
/// ```
/// use miden_core::{
///     mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor, MastForestWireView},
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
/// let view = MastForestWireView::new(&bytes).unwrap();
/// assert_eq!(view.node_count(), forest.nodes().len());
/// assert!(view.node_info_at(0).is_ok());
/// ```
#[derive(Debug)]
pub struct MastForestWireView<'a> {
    bytes: &'a [u8],
    flags: WireFlags,
    layout: ForestLayout,
    advice_map: WireAdviceMapView<'a>,
    resolved: OnceLockCompat<Result<ResolvedSerializedForest<'a>, DeserializationError>>,
}

impl<'a> MastForestWireView<'a> {
    /// Creates a new view from serialized bytes.
    ///
    /// The input may be full or stripped format, but must include all node hashes.
    /// Structural parsing is delegated to the same single-pass scanner used by reader-based
    /// deserialization paths.
    ///
    /// This constructor validates the header and sections needed for node/roots/random-access
    /// metadata, indexes `AdviceMap` keys for on-demand lookup, and length-walks any trailing
    /// `DebugInfo` payload before ignoring it.
    ///
    /// Treat this as a trusted cache API, not as an untrusted-validation entry point. It is
    /// appropriate for local tools that need random access over serialized structure, but callers
    /// handling adversarial bytes should use [`crate::mast::UntrustedMastForest`] instead.
    ///
    /// In particular, this constructor does **not** protect callers from untrusted-input concerns
    /// that are enforced by [`crate::mast::UntrustedMastForest::validate`]. It does not:
    /// - verify that serialized non-external digests match the structure they describe
    /// - check topological ordering / forward-reference constraints
    /// - validate basic-block batch invariants or procedure-name-root consistency
    /// - materialize or expose trailing `DebugInfo` payloads
    ///
    /// For strict full-payload validation, use
    /// [`crate::mast::MastForest::read_from_bytes`].
    ///
    /// Digest lookup follows the wire layout:
    /// - Non-external node digests are read from the internal-hash suffix.
    /// - External node digests are always read from the sorted external prefix.
    ///
    /// # Examples
    ///
    /// ```
    /// use miden_core::{
    ///     mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor, MastForestWireView},
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
    /// let view = MastForestWireView::new(&bytes).unwrap();
    /// assert_eq!(view.node_count(), 1);
    /// ```
    pub fn new(bytes: &'a [u8]) -> Result<Self, DeserializationError> {
        let mut reader = SliceReader::new(bytes);
        let mut scanner = TrackingReader::new(&mut reader);
        let (flags, layout) = read_header_and_scan_layout(&mut scanner, false)?;
        let advice_map = WireAdviceMapView::new(bytes, layout.advice_map_offset)?;
        check_ignored_debug_payload(bytes, flags, advice_map.end_offset())?;

        Ok(Self {
            bytes,
            flags,
            layout,
            advice_map,
            resolved: OnceLockCompat::new(),
        })
    }

    /// Returns the number of nodes in the serialized forest.
    pub fn node_count(&self) -> usize {
        self.layout.node_count
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
    /// Returns an error if `index >= self.node_count()`.
    ///
    /// # Examples
    ///
    /// ```
    /// use miden_core::{
    ///     mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor, MastForestWireView},
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
    /// let view = MastForestWireView::new(&bytes).unwrap();
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
    /// Returns an error if `index >= self.node_count()`.
    pub fn node_digest_at(&self, index: usize) -> Result<Word, DeserializationError> {
        self.resolved()?.node_digest_at(index)
    }

    /// Returns a read-only view over the serialized forest advice map.
    pub fn advice_map(&self) -> AdviceMapView<'_> {
        AdviceMapView::wire(&self.advice_map)
    }

    fn resolved(&self) -> Result<&ResolvedSerializedForest<'a>, DeserializationError> {
        self.resolved
            .get_or_init(|| ResolvedSerializedForest::new(self.bytes, self.layout))
            .as_ref()
            .map_err(Clone::clone)
    }
}

fn check_ignored_debug_payload(
    bytes: &[u8],
    flags: WireFlags,
    debug_info_offset: usize,
) -> Result<(), DeserializationError> {
    let payload = bytes.get(debug_info_offset..).ok_or(DeserializationError::UnexpectedEOF)?;
    if payload.is_empty() {
        return Ok(());
    }

    if flags.is_stripped() {
        log::warn!(
            "MastForestWireView ignored {} trailing bytes after a STRIPPED MastForest payload",
            payload.len()
        );
        return Ok(());
    }

    let mut reader = SliceReader::new(payload);
    skip_debug_info(&mut reader)?;
    if reader.has_more_bytes() {
        return Err(DeserializationError::InvalidValue(
            "extra bytes after DebugInfo section".into(),
        ));
    }

    log::warn!(
        "MastForestWireView ignored {} bytes of DebugInfo because MastForestView is debug-less",
        payload.len()
    );
    Ok(())
}

fn skip_debug_info<R: ByteReader>(source: &mut R) -> Result<(), DeserializationError> {
    skip_len_prefixed_bytes(source)?; // decorator_data
    skip_string_table(source)?;
    skip_fixed_vec(source, DecoratorInfo::min_serialized_size())?;
    skip_btree_map_u64_string(source)?;
    skip_op_to_u32_ids(source)?;
    skip_csr_u32_data(source)?;
    skip_csr_u32_data(source)?;
    skip_btree_map_word_string(source)?;
    skip_len_prefixed_bytes(source)?; // asm_op_data
    skip_string_table(source)?;
    skip_fixed_vec(source, AsmOpInfo::min_serialized_size())?;
    skip_csr_operation_id_pairs(source)?;
    skip_debug_var_infos(source)?;
    skip_op_to_u32_ids(source)?;
    Ok(())
}

fn skip_string_table<R: ByteReader>(source: &mut R) -> Result<(), DeserializationError> {
    skip_usize_vec(source)?;
    skip_len_prefixed_bytes(source)
}

fn skip_fixed_vec<R: ByteReader>(
    source: &mut R,
    element_size: usize,
) -> Result<(), DeserializationError> {
    let len = source.read_usize()?;
    let byte_len = len.checked_mul(element_size).ok_or_else(|| {
        DeserializationError::InvalidValue("fixed-width vector length overflow".into())
    })?;
    source.read_slice(byte_len).map(|_| ())
}

fn skip_btree_map_u64_string<R: ByteReader>(source: &mut R) -> Result<(), DeserializationError> {
    let len = source.read_usize()?;
    for _ in 0..len {
        source.read_u64()?;
        skip_string(source)?;
    }
    Ok(())
}

fn skip_btree_map_word_string<R: ByteReader>(source: &mut R) -> Result<(), DeserializationError> {
    let len = source.read_usize()?;
    for _ in 0..len {
        Word::read_from(source)?;
        skip_string(source)?;
    }
    Ok(())
}

fn skip_op_to_u32_ids<R: ByteReader>(source: &mut R) -> Result<(), DeserializationError> {
    skip_u32_vec(source)?;
    skip_usize_vec(source)?;
    skip_usize_vec(source)
}

fn skip_csr_u32_data<R: ByteReader>(source: &mut R) -> Result<(), DeserializationError> {
    skip_u32_vec(source)?;
    skip_usize_vec(source)
}

fn skip_csr_operation_id_pairs<R: ByteReader>(source: &mut R) -> Result<(), DeserializationError> {
    let data_len = source.read_usize()?;
    for _ in 0..data_len {
        source.read_usize()?;
        source.read_u32()?;
    }
    skip_usize_vec(source)
}

fn skip_debug_var_infos<R: ByteReader>(source: &mut R) -> Result<(), DeserializationError> {
    let len = source.read_usize()?;
    for _ in 0..len {
        skip_string(source)?;
        skip_debug_var_location(source)?;
        skip_option(source, |source| source.read_u32().map(|_| ()))?;
        skip_option(source, |source| {
            let value = source.read_u32()?;
            if value == 0 {
                return Err(DeserializationError::InvalidValue(
                    "arg_index must be non-zero".into(),
                ));
            }
            Ok(())
        })?;
        skip_option(source, skip_file_line_col)?;
    }
    Ok(())
}

fn skip_debug_var_location<R: ByteReader>(source: &mut R) -> Result<(), DeserializationError> {
    match source.read_u8()? {
        0 => source.read_u8().map(|_| ()),
        1 => source.read_u32().map(|_| ()),
        2 => source.read_u64().map(|_| ()),
        3 => source.read_array::<2>().map(|_| ()),
        4 => skip_len_prefixed_bytes(source),
        5 => {
            source.read_u32()?;
            source.read_array::<8>().map(|_| ())
        },
        tag => Err(DeserializationError::InvalidValue(format!(
            "invalid DebugVarLocation tag: {tag}"
        ))),
    }
}

fn skip_file_line_col<R: ByteReader>(source: &mut R) -> Result<(), DeserializationError> {
    skip_string(source)?;
    for label in ["line", "column"] {
        let value = source.read_u32()?;
        if value == 0 {
            return Err(DeserializationError::InvalidValue(format!(
                "{label} number cannot be zero"
            )));
        }
    }
    Ok(())
}

fn skip_option<R, F>(source: &mut R, skip_value: F) -> Result<(), DeserializationError>
where
    R: ByteReader,
    F: FnOnce(&mut R) -> Result<(), DeserializationError>,
{
    if source.read_bool()? {
        skip_value(source)
    } else {
        Ok(())
    }
}

fn skip_u32_vec<R: ByteReader>(source: &mut R) -> Result<(), DeserializationError> {
    skip_fixed_vec(source, size_of::<u32>())
}

fn skip_usize_vec<R: ByteReader>(source: &mut R) -> Result<(), DeserializationError> {
    let len = source.read_usize()?;
    for _ in 0..len {
        source.read_usize()?;
    }
    Ok(())
}

fn skip_string<R: ByteReader>(source: &mut R) -> Result<(), DeserializationError> {
    let bytes = read_len_prefixed_bytes(source)?;
    core::str::from_utf8(bytes)
        .map_err(|err| DeserializationError::InvalidValue(format!("{err}")))?;
    Ok(())
}

fn skip_len_prefixed_bytes<R: ByteReader>(source: &mut R) -> Result<(), DeserializationError> {
    read_len_prefixed_bytes(source).map(|_| ())
}

fn read_len_prefixed_bytes<R: ByteReader>(source: &mut R) -> Result<&[u8], DeserializationError> {
    let len = source.read_usize()?;
    source.read_slice(len)
}

impl MastForest {
    /// Reads trusted MAST forest bytes using the requested backing mode.
    ///
    /// [`MastForestReadMode::Materialized`] is equivalent to [`Self::read_from_bytes`].
    /// [`MastForestReadMode::WireBacked`] returns a trusted random-access cache view and rejects
    /// hashless payloads because trusted cache bytes must be complete.
    pub fn read_view_from_bytes(
        bytes: &[u8],
        mode: MastForestReadMode,
    ) -> Result<MastForestReadView<'_>, DeserializationError> {
        match mode {
            MastForestReadMode::Materialized => {
                Self::read_from_bytes(bytes).map(MastForestReadView::Materialized)
            },
            MastForestReadMode::WireBacked => {
                MastForestWireView::new(bytes).map(MastForestReadView::WireBacked)
            },
        }
    }
}

impl MastForestView for MastForestWireView<'_> {
    fn node_count(&self) -> usize {
        MastForestWireView::node_count(self)
    }

    fn node_entry_at(&self, index: usize) -> Result<MastNodeEntry, DeserializationError> {
        MastForestWireView::node_entry_at(self, index)
    }

    fn node_digest_at(&self, index: usize) -> Result<Word, DeserializationError> {
        MastForestWireView::node_digest_at(self, index)
    }

    fn procedure_root_count(&self) -> usize {
        MastForestWireView::procedure_root_count(self)
    }

    fn procedure_root_at(&self, index: usize) -> Result<MastNodeId, DeserializationError> {
        MastForestWireView::procedure_root_at(self, index)
    }

    fn advice_map(&self) -> AdviceMapView<'_> {
        MastForestWireView::advice_map(self)
    }
}

impl MastForestView for MastForestReadView<'_> {
    fn node_count(&self) -> usize {
        match self {
            MastForestReadView::Materialized(forest) => MastForestView::node_count(forest),
            MastForestReadView::WireBacked(view) => view.node_count(),
        }
    }

    fn node_entry_at(&self, index: usize) -> Result<MastNodeEntry, DeserializationError> {
        match self {
            MastForestReadView::Materialized(forest) => {
                MastForestView::node_entry_at(forest, index)
            },
            MastForestReadView::WireBacked(view) => view.node_entry_at(index),
        }
    }

    fn node_digest_at(&self, index: usize) -> Result<Word, DeserializationError> {
        match self {
            MastForestReadView::Materialized(forest) => {
                MastForestView::node_digest_at(forest, index)
            },
            MastForestReadView::WireBacked(view) => view.node_digest_at(index),
        }
    }

    fn procedure_root_count(&self) -> usize {
        match self {
            MastForestReadView::Materialized(forest) => {
                MastForestView::procedure_root_count(forest)
            },
            MastForestReadView::WireBacked(view) => view.procedure_root_count(),
        }
    }

    fn procedure_root_at(&self, index: usize) -> Result<MastNodeId, DeserializationError> {
        match self {
            MastForestReadView::Materialized(forest) => {
                MastForestView::procedure_root_at(forest, index)
            },
            MastForestReadView::WireBacked(view) => view.procedure_root_at(index),
        }
    }

    fn advice_map(&self) -> AdviceMapView<'_> {
        match self {
            MastForestReadView::Materialized(forest) => MastForestView::advice_map(forest),
            MastForestReadView::WireBacked(view) => view.advice_map(),
        }
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

    fn node_digest_at(&self, index: usize) -> Result<Word, DeserializationError> {
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

    fn advice_map(&self) -> AdviceMapView<'_> {
        AdviceMapView::materialized(&self.advice_map)
    }
}

// TEST HELPERS
// ================================================================================================

#[cfg(test)]
impl MastForestWireView<'_> {
    fn debug_info_offset(&self) -> usize {
        self.advice_map.end_offset()
    }

    fn node_entry_offset(&self) -> usize {
        self.layout.node_entry_offset
    }

    fn node_digest_offset(&self) -> usize {
        self.layout.node_digest_offset
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
    debug_assert_eq!(recording.offset(), layout.advice_map_offset);

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
