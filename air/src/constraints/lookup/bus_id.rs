//! Central bus-ID registry for Miden's LookupAir.
//!
//! There are exactly 9 LogUp buses in the Miden VM. All "chiplet"
//! operations (hasher, memory, bitwise, ACE init, kernel ROM) share a
//! single bus (`BUS_CHIPLETS`); they are distinguished at encoding time
//! by a `label` placed at β⁰ in the message payload, not by separate
//! bus IDs. The other 8 buses each own their auxiliary running-sum
//! column directly.
//!
//! See `../vm-constraints/air/src/trace/mod.rs` for the canonical
//! `bus_types` enum this file mirrors.

#![expect(
    dead_code,
    reason = "Task #6 consumes BUS_BLOCK_HASH_TABLE / NUM_BUS_IDS directly; the remaining BUS_* constants go live in Task #7."
)]

/// Chiplet bus — multiplexes hasher, memory, bitwise, ACE init, and
/// kernel ROM interactions. Operations are disambiguated by a label at
/// β⁰ in each message payload (see the `label_value` / `op_value`
/// fields in the `*Msg` constructors in `logup_msg.rs`).
pub const BUS_CHIPLETS: u16 = 0;

/// Decoder block-stack virtual table.
pub const BUS_BLOCK_STACK_TABLE: u16 = 1;

/// Decoder block-hash queue.
pub const BUS_BLOCK_HASH_TABLE: u16 = 2;

/// Decoder op-group table.
pub const BUS_OP_GROUP_TABLE: u16 = 3;

/// Stack overflow virtual table.
pub const BUS_STACK_OVERFLOW_TABLE: u16 = 4;

/// Merkle sibling virtual table (serviced by the hash-kernel column).
pub const BUS_SIBLING_TABLE: u16 = 5;

/// Log-precompile transcript / capacity transitions.
pub const BUS_LOG_PRECOMPILE_TRANSCRIPT: u16 = 6;

/// Range checker.
pub const BUS_RANGE_CHECK: u16 = 7;

/// ACE wiring bus (C3).
pub const BUS_ACE_WIRING: u16 = 8;

/// Number of bus IDs. Every `LookupAir<LB>::num_bus_ids()` impl reports
/// this constant, and every adapter sizes its `bus_prefix` table to
/// match.
pub const NUM_BUS_IDS: usize = 9;
