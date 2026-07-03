//! MAST forest serialization keeps one fixed structural layout for normal and hashless payloads.
//!
//! The main goal is to keep random access cheap in both modes. Node structure
//! stays in one fixed-width section. Variable-size data lives in separate sections. Internal node
//! digests also live in a separate section so hashless payloads can omit them without changing the
//! structural layout.
//!
//! Wire flags describe serializer intent, not reader trust policy. Trusted [`MastForest`] reads
//! reject hashless payloads. [`crate::mast::UntrustedMastForest`] accepts them and rebuilds
//! non-external digests before use. If a non-hashless payload is sent down the untrusted path,
//! validation recomputes those digests and requires them to match the serialized values.
//! Budgeted untrusted reads always bound wire counts during layout scanning via
//! [`ByteReader::max_alloc`]. Validation also gets a second check:
//! - later hashless helper allocations are charged against a validation budget before the
//!   corresponding `Vec` or CSR scaffolding is created
//! - that budget is derived from the wire budget by a coarse multiplier; this is intentionally a
//!   simple bound for common callers, not an exact peak-memory formula
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
//! - internal nodes count (`usize`)
//! - external nodes count (`usize`)
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
//! (Commitment input sections)
//! - root node digests (`Vec<Word>`, sorted by digest)
//! - external node digests (`Vec<Word>`, sorted by digest)
//!
//! (Advice map section)
//! - Advice map (`AdviceMap`)
//!
//! (No trailing debug section)
//!
//! Readers reject any trailing payload after the advice map. Package-owned debug sections are now
//! the only supported debug serialization path.
//!
//! In hashless format, the internal node-hash section is omitted. External node digests still stay
//! on the wire because they cannot be rebuilt from local structure. This keeps hashless focused on
//! the untrusted-validation use case: trusted reads reject `HASHLESS`, and the untrusted path
//! rebuilds the data it actually trusts before use.
//!
//! Readers recover per-node digest lookup by scanning node entries once and building a compact
//! "slot by node index" table. This preserves random access without forcing all digests into the
//! same contiguous array on the wire.
//!
//! Public entry points adopt these policies:
//! - [`MastForest::read_from_bytes`]: trusted dense execution payload, no hashless support.
//! - [`MastForestWireView::new`]: trusted wire-backed cache access; rejects hashless and legacy
//!   debug-bearing payloads.
//! - [`crate::mast::SparseMastForest::read_from_bytes`] /
//!   [`crate::mast::SparseMastForest::read_from_bytes_with_options`]: separate trusted sparse
//!   replay payloads for serialized trace-generation inputs. Sparse payloads currently carry
//!   full-node digests and do not recompute them on read.
//! - [`crate::mast::UntrustedMastForest::read_from_bytes`] /
//!   [`crate::mast::UntrustedMastForest::read_from_bytes_with_options`]: untrusted parsing plus
//!   later validation before use.

#[cfg(test)]
use alloc::string::ToString;
use alloc::{boxed::Box, format, vec::Vec};
use core::mem::size_of;

use miden_utils_sync::OnceLockCompat;

use super::{MastForest, MastNode, MastNodeId};
use crate::{
    Word,
    advice::AdviceMap,
    mast::node::MastNodeExt,
    serde::{
        BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        SliceReader,
    },
};

mod info;
pub use info::{MastNodeEntry, MastNodeInfo};

mod view;
use view::WireAdviceMapView;
pub use view::{AdviceMapView, AdviceValueView, MastForestView};

mod layout;
pub(super) use layout::ForestLayout;
use layout::{OffsetTrackingReader, TrackingReader, WireFlags, read_header_and_scan_layout};

mod sparse;
pub use sparse::SparseMastForestReadOptions;

mod resolved;
use resolved::{ResolvedSerializedForest, basic_block_offset_for_node_index};

mod basic_blocks;
use basic_blocks::{BasicBlockDataBuilder, basic_block_data_len};

#[cfg(test)]
mod seed_gen;

#[cfg(test)]
mod tests;

// TYPE ALIASES
// ================================================================================================

/// Specifies an offset into the `node_data` section of an encoded [`MastForest`].
type NodeDataOffset = u32;

/// Default multiplier for the untrusted validation allocation budget.
///
/// The budgeted byte reader limits wire-driven parsing. Hashless validation also needs transient
/// per-node allocations for the slot table and rebuilt digest data.
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
/// [`crate::mast::UntrustedMastForest::read_from_bytes_with_options`] and choose an explicit wire
/// budget; the validation helper budget is derived from it.
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
/// This repurposes the old `b"MAST\0"` terminator as the flags byte.
const MAGIC: &[u8; 4] = b"MAST";

/// Flag indicating that the internal node-hash section is omitted from the wire payload.
///
/// External digests still remain serialized in their own section because they cannot be rebuilt
/// from local structure.
pub(super) const FLAG_HASHLESS: u8 = 0x02;

/// Mask for reserved flag bits that must be zero.
///
/// Bit 0 and bits 2-7 are reserved for future use. If any are set, deserialization fails.
const FLAGS_RESERVED_MASK: u8 = 0xfd;

/// The format version.
///
/// If future modifications are made to this format, the version should be incremented by 1. A
/// version of `[255, 255, 255]` is reserved for future extensions that require extending the
/// version field itself, but should be considered invalid for now.
///
/// Version history:
/// - [0, 0, 0]: Initial format.
/// - [0, 0, 1]: Added batch metadata to basic blocks (operations serialized in padded form with
///   indptr, padding, and group metadata for exact OpBatch reconstruction). Added asm-op metadata
///   and debug-variable storage in CSR layout (eliminates per-node metadata sections and round-trip
///   conversions). Header changed from `MAST\0` to `MAST` + flags byte.
/// - [0, 0, 2]: AssemblyOps moved out of inline metadata into a dedicated DebugInfo section.
///   Removed `should_break` field from AssemblyOp serialization (#2646). Removed `breakpoint`
///   instruction (#2655).
/// - [0, 0, 3]: Added HASHLESS flag (bit 1). Trusted deserialization rejects HASHLESS. Split
///   fixed-width node entries from digest storage. External digests moved to a dedicated section.
///   Hashless serialization omits the general node-hash section entirely. Removed the unused
///   metadata-count field from the wire header. Before any public release on this branch, the same
///   unreleased wire version also grew explicit internal/external node counts in the header.
/// - [0, 0, 4]: Removed the legacy inline metadata wire slots entirely. All assembly op metadata
///   and debug variable metadata are now stored in the DebugInfo section as separate indexed
///   records. MAST nodes are metadata-free identifiers. Before any public release on this branch,
///   the same unreleased wire version also reserved bit 0 and stopped using it as a forest-level
///   debug-presence flag.
/// - [0, 0, 5]: Added sorted root digest and sorted external digest commitment input sections.
///
/// Legacy wire versions (pre-#3192 decorator terminology):
///   [0,0,1] stored metadata as serialized decorator variants in CSR per-node slots.
///   [0,0,2] removed AssemblyOp from the decorator enum and stored them separately in DebugInfo.
///   [0,0,3] removed the unused decorator-count wire field.
///   [0,0,4] eliminated the decorator wire slots entirely.
const VERSION: [u8; 3] = [0, 0, 5];

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
    /// Current writers encode normal execution payloads or hashless validation payloads.
    fn write_into_with_options<W: ByteWriter>(&self, target: &mut W, hashless: bool) {
        self.validate_dense_node_order()
            .expect("dense MAST forest must be canonical before serialization");

        let mut basic_block_data_builder = BasicBlockDataBuilder::new();

        // magic & flags
        target.write_bytes(MAGIC);
        let flags = if hashless { FLAG_HASHLESS } else { 0 };
        target.write_u8(flags);

        // version
        target.write_bytes(&VERSION);

        // header counts
        let node_count = self.nodes.len();
        let external_node_count = self.nodes.iter().take_while(|node| node.is_external()).count();
        let internal_node_count = node_count - external_node_count;
        target.write_usize(internal_node_count);
        target.write_usize(external_node_count);

        // roots
        let roots: Vec<u32> = self.roots.iter().copied().map(u32::from).collect();
        roots.write_into(target);

        let mut mast_node_entries = Vec::with_capacity(self.nodes.len());
        let mut external_digests = Vec::with_capacity(external_node_count);
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

        for &digest in &external_digests {
            digest.write_into(target);
        }

        if !hashless {
            for digest in node_hashes {
                digest.write_into(target);
            }
        }

        for digest in sorted_root_digests(self) {
            digest.write_into(target);
        }

        for digest in external_digests {
            digest.write_into(target);
        }

        self.advice_map.write_into(target);
    }
}

pub(super) fn write_hashless_into<W: ByteWriter>(forest: &MastForest, target: &mut W) {
    forest.write_into_with_options(target, true);
}

fn sorted_root_digests(forest: &MastForest) -> Vec<Word> {
    let mut digests: Vec<Word> =
        forest.roots.iter().map(|&root_id| forest.nodes[root_id].digest()).collect();
    digests.sort_unstable();
    digests
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
    WireBacked(Box<MastForestWireView<'a>>),
}

/// A trusted wire-backed view over serialized MAST forest bytes.
///
/// This view accepts complete payloads with hashes. It validates the header and the fixed-width
/// structural sections needed for random access, but it does not fully materialize the forest.
/// Hashless payloads are rejected because trusted cache bytes must be complete. Trailing payloads
/// are rejected because debug metadata now belongs to package-owned debug sections.
///
/// Use this when callers need random access to roots or node metadata without deserializing the
/// full forest. For strict trusted deserialization, use
/// [`crate::mast::MastForest::read_from_bytes`].
///
/// # Examples
///
/// ```
/// use miden_core::{
///     mast::{BasicBlockNodeBuilder, DenseMastForestBuilder, MastForestWireView},
///     operations::Operation,
///     serde::Serializable,
/// };
///
/// let mut builder = DenseMastForestBuilder::new();
/// let block_id = builder.push_node(BasicBlockNodeBuilder::new(vec![Operation::Add])).unwrap();
/// builder.mark_root(block_id);
/// let forest = builder.finish().unwrap();
///
/// let mut bytes = Vec::new();
/// forest.write_into(&mut bytes);
///
/// let view = MastForestWireView::new(&bytes).unwrap();
/// assert_eq!(view.node_count(), forest.nodes().len());
/// assert!(view.node_info_at(0).is_ok());
/// ```
#[derive(Debug)]
pub struct MastForestWireView<'a> {
    bytes: &'a [u8],
    layout: ForestLayout,
    advice_map: WireAdviceMapView<'a>,
    resolved: OnceLockCompat<Result<ResolvedSerializedForest<'a>, DeserializationError>>,
}

impl<'a> MastForestWireView<'a> {
    /// Creates a new view from serialized bytes.
    ///
    /// The input must include all node hashes. Structural parsing is
    /// delegated to the same single-pass scanner used by reader-based deserialization paths.
    ///
    /// This constructor validates the header and sections needed for node/roots/random-access
    /// metadata, indexes `AdviceMap` keys for on-demand lookup, and rejects trailing payloads.
    ///
    /// Treat this as a trusted cache API, not as an untrusted-validation entry point. It is
    /// appropriate for local tools that need random access over serialized structure, but callers
    /// handling adversarial bytes should use [`crate::mast::UntrustedMastForest`] instead.
    ///
    /// In particular, this constructor does **not** protect callers from untrusted-input concerns
    /// that are enforced by [`crate::mast::UntrustedMastForest::validate`]. It does not:
    /// - verify that serialized non-external digests match the structure they describe
    /// - check topological ordering / forward-reference constraints
    /// - validate basic-block batch invariants
    /// - materialize or expose package-owned debug sections
    ///
    /// For strict materialized validation, use
    /// [`crate::mast::MastForest::read_from_bytes`].
    ///
    /// Digest lookup follows the wire layout:
    /// - Non-external node digests are read from the internal-hash section.
    /// - External node digests are read from the external-digest section.
    ///
    /// # Examples
    ///
    /// ```
    /// use miden_core::{
    ///     mast::{BasicBlockNodeBuilder, DenseMastForestBuilder, MastForestWireView},
    ///     operations::Operation,
    ///     serde::Serializable,
    /// };
    ///
    /// let mut builder = DenseMastForestBuilder::new();
    /// let block_id = builder.push_node(BasicBlockNodeBuilder::new(vec![Operation::Add])).unwrap();
    /// builder.mark_root(block_id);
    /// let forest = builder.finish().unwrap();
    ///
    /// let mut bytes = Vec::new();
    /// forest.write_into(&mut bytes);
    ///
    /// let view = MastForestWireView::new(&bytes).unwrap();
    /// assert_eq!(view.node_count(), 1);
    /// ```
    pub fn new(bytes: &'a [u8]) -> Result<Self, DeserializationError> {
        let mut reader = SliceReader::new(bytes);
        let mut scanner = TrackingReader::new(&mut reader);
        let (_flags, layout) = read_header_and_scan_layout(&mut scanner, false)?;
        let advice_map = WireAdviceMapView::new(bytes, layout.advice_map_offset())?;
        check_no_trailing_payload(bytes, advice_map.end_offset())?;
        ResolvedSerializedForest::new(bytes, layout)?.validate_commitment_input_sections()?;

        Ok(Self {
            bytes,
            layout,
            advice_map,
            resolved: OnceLockCompat::new(),
        })
    }

    /// Returns the number of nodes in the serialized forest.
    pub fn node_count(&self) -> usize {
        self.layout.node_count
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
    ///     mast::{BasicBlockNodeBuilder, DenseMastForestBuilder, MastForestWireView},
    ///     operations::Operation,
    ///     serde::Serializable,
    /// };
    ///
    /// let mut builder = DenseMastForestBuilder::new();
    /// let block_id = builder.push_node(BasicBlockNodeBuilder::new(vec![Operation::Add])).unwrap();
    /// builder.mark_root(block_id);
    /// let forest = builder.finish().unwrap();
    ///
    /// let mut bytes = Vec::new();
    /// forest.write_into(&mut bytes);
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

fn check_no_trailing_payload(
    bytes: &[u8],
    debug_info_offset: usize,
) -> Result<(), DeserializationError> {
    let payload = bytes.get(debug_info_offset..).ok_or(DeserializationError::UnexpectedEOF)?;
    if payload.is_empty() {
        return Ok(());
    }
    Err(extra_bytes_after_mast_forest_payload_error())
}

fn extra_bytes_after_mast_forest_payload_error() -> DeserializationError {
    DeserializationError::InvalidValue("extra bytes after MastForest payload".into())
}

impl MastForest {
    /// Reads trusted MAST forest bytes using the requested backing mode.
    ///
    /// [`MastForestReadMode::Materialized`] is equivalent to [`Self::read_from_bytes`].
    /// [`MastForestReadMode::WireBacked`] returns a trusted random-access cache view and rejects
    /// hashless and trailing payloads because trusted cache bytes must be complete execution
    /// payloads.
    pub fn read_view_from_bytes(
        bytes: &[u8],
        mode: MastForestReadMode,
    ) -> Result<MastForestReadView<'_>, DeserializationError> {
        match mode {
            MastForestReadMode::Materialized => {
                Self::read_from_bytes(bytes).map(MastForestReadView::Materialized)
            },
            MastForestReadMode::WireBacked => {
                MastForestWireView::new(bytes).map(Box::new).map(MastForestReadView::WireBacked)
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
        self.layout.node_entry_offset()
    }

    fn external_digest_offset(&self) -> usize {
        self.layout.external_digest_offset()
    }

    fn node_hash_offset(&self) -> Option<usize> {
        self.layout.node_hash_offset()
    }

    fn root_digest_offset(&self) -> usize {
        self.layout.root_digest_offset()
    }

    fn dependency_digest_offset(&self) -> usize {
        self.layout.dependency_digest_offset()
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
        forest.validate_commitment_input_sections()?;
        forest.into_materialized()
    }

    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let budget = bytes.len().saturating_mul(TRUSTED_BYTE_READ_BUDGET_MULTIPLIER);
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), budget);
        let forest = Self::read_from(&mut reader)?;
        if reader.has_more_bytes() {
            return Err(extra_bytes_after_mast_forest_payload_error());
        }
        Ok(forest)
    }
}

impl super::UntrustedMastForest {
    pub(super) fn validate_commitment_input_sections(&self) -> Result<(), DeserializationError> {
        validate_commitment_input_sections_from_parts(
            &self.bytes,
            self.layout,
            self.remaining_allocation_budget,
        )
    }

    pub(super) fn into_materialized(self) -> Result<MastForest, DeserializationError> {
        let (forest, _bytes, _layout, _remaining_allocation_budget) =
            self.into_materialized_with_serialized_parts()?;
        Ok(forest)
    }

    pub(super) fn into_materialized_with_serialized_parts(
        self,
    ) -> Result<(MastForest, Vec<u8>, ForestLayout, Option<usize>), DeserializationError> {
        let bytes = self.bytes;
        let layout = self.layout;
        let advice_map = self.advice_map;
        let remaining_allocation_budget = self.remaining_allocation_budget;

        let resolved = if let Some(allocation_budget) = remaining_allocation_budget {
            ResolvedSerializedForest::new_with_allocation_budget(&bytes, layout, allocation_budget)?
        } else {
            ResolvedSerializedForest::new(&bytes, layout)?
        };

        let forest = resolved.materialize(advice_map)?;
        Ok((forest, bytes, layout, remaining_allocation_budget))
    }
}

pub(super) fn validate_commitment_input_sections_from_parts(
    bytes: &[u8],
    layout: ForestLayout,
    remaining_allocation_budget: Option<usize>,
) -> Result<(), DeserializationError> {
    let resolved = if let Some(allocation_budget) = remaining_allocation_budget {
        ResolvedSerializedForest::new_with_allocation_budget(bytes, layout, allocation_budget)?
    } else {
        ResolvedSerializedForest::new(bytes, layout)?
    };

    resolved.validate_commitment_input_sections()
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
    remaining_allocation_budget: Option<usize>,
) -> Result<(WireFlags, super::UntrustedMastForest), DeserializationError> {
    let mut recording = TrackingReader::new_recording(source);
    let (flags, layout) = read_header_and_scan_layout(&mut recording, allow_hashless)?;
    debug_assert_eq!(recording.offset(), layout.advice_map_offset());

    let advice_map = AdviceMap::read_from(&mut recording)?;
    Ok((
        flags,
        super::UntrustedMastForest {
            bytes: recording.into_recorded(),
            layout,
            advice_map,
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
