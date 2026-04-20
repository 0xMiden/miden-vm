//! Miden's bus identifier enumeration and the width of the β-power table used by
//! [`Challenges`](crate::trace::Challenges) when encoding this AIR's bus messages.
//!
//! Every Miden bus emitter in `buses/*.rs` and every
//! [`LookupMessage`](crate::constraints::lookup::LookupMessage) impl in `logup_msg.rs` picks its
//! bus by name from the [`bus_types`] sub-module or the `BUS_*` re-exports below.
//! [`MidenLookupAir`](super::MidenLookupAir) reports [`MIDEN_MAX_MESSAGE_WIDTH`] from
//! `max_message_width()` and [`NUM_BUS_IDS`] from `num_bus_ids()`;
//! [`Challenges::new`](crate::trace::Challenges::new) uses those two numbers to size its
//! `beta_powers` and `bus_prefix` tables.

/// Width of the `beta_powers` table `Challenges` precomputes for Miden's bus
/// messages, i.e. the exponent of `gamma = beta^MIDEN_MAX_MESSAGE_WIDTH` used in
/// `bus_prefix[i] = alpha + (i + 1) * gamma`.
///
/// Must match the Poseidon2 absorption loop in `crates/lib/core/asm/stark/` which
/// reads the same β-power table during recursive verification.
pub const MIDEN_MAX_MESSAGE_WIDTH: usize = 16;

/// Miden's bus interaction type constants for domain separation.
///
/// Each constant identifies a distinct bus interaction type. When encoding a message,
/// the bus index is passed to [`Challenges::encode`](crate::trace::Challenges::encode)
/// or [`Challenges::encode_sparse`](crate::trace::Challenges::encode_sparse), which
/// uses `bus_prefix[bus]` as the additive base instead of bare `alpha`.
///
/// This ensures messages from different buses are always distinct, even if they share
/// the same coefficient layout and labels.
pub mod bus_types {
    /// All chiplet interactions: hasher, bitwise, memory, ACE, kernel ROM.
    pub const CHIPLETS_BUS: usize = 0;
    /// Block stack table (decoder p1): tracks control flow block nesting.
    pub const BLOCK_STACK_TABLE: usize = 1;
    /// Block hash table (decoder p2): tracks block digest computation.
    pub const BLOCK_HASH_TABLE: usize = 2;
    /// Op group table (decoder p3): tracks operation batch consumption.
    pub const OP_GROUP_TABLE: usize = 3;
    /// Stack overflow table.
    pub const STACK_OVERFLOW_TABLE: usize = 4;
    /// Sibling table: shares Merkle tree sibling nodes between old/new root computations.
    pub const SIBLING_TABLE: usize = 5;
    /// Log-precompile transcript: tracks capacity state transitions for LOGPRECOMPILE.
    pub const LOG_PRECOMPILE_TRANSCRIPT: usize = 6;
    /// Range checker bus (LogUp): verifies values are in the valid range.
    pub const RANGE_CHECK_BUS: usize = 7;
    /// ACE wiring bus (LogUp): verifies arithmetic circuit wire connections.
    pub const ACE_WIRING_BUS: usize = 8;
    /// Hasher perm-link bus: links hasher controller rows to permutation segment rows on
    /// `v_wiring`.
    pub const HASHER_PERM_LINK: usize = 9;
    /// Total number of distinct bus interaction types.
    pub const NUM_BUS_TYPES: usize = 10;
}

pub const BUS_CHIPLETS: usize = bus_types::CHIPLETS_BUS;
pub const BUS_BLOCK_STACK_TABLE: usize = bus_types::BLOCK_STACK_TABLE;
pub const BUS_BLOCK_HASH_TABLE: usize = bus_types::BLOCK_HASH_TABLE;
pub const BUS_OP_GROUP_TABLE: usize = bus_types::OP_GROUP_TABLE;
pub const BUS_STACK_OVERFLOW_TABLE: usize = bus_types::STACK_OVERFLOW_TABLE;
pub const BUS_SIBLING_TABLE: usize = bus_types::SIBLING_TABLE;
pub const BUS_LOG_PRECOMPILE_TRANSCRIPT: usize = bus_types::LOG_PRECOMPILE_TRANSCRIPT;
pub const BUS_RANGE_CHECK: usize = bus_types::RANGE_CHECK_BUS;
pub const BUS_ACE_WIRING: usize = bus_types::ACE_WIRING_BUS;
pub const BUS_HASHER_PERM_LINK: usize = bus_types::HASHER_PERM_LINK;

pub const NUM_BUS_IDS: usize = bus_types::NUM_BUS_TYPES;
