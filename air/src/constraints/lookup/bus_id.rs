//! Compatibility shim re-exporting [`crate::trace::bus_types`] under the legacy
//! `BUS_*` / `NUM_BUS_IDS` names used by the lookup module's bus emitters and
//! the `LookupMessage` impls in `logup_msg.rs`.
//!
//! All constants are `usize` (matching the upstream `bus_types` definitions);
//! the original `u16` typing is no longer required because `LookupAir` indexes
//! `Challenges::bus_prefix` with `usize` directly.

use crate::trace::bus_types;

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
