//! Bus shared definitions.
//!
//! This module provides shared indices for auxiliary (bus) constraints.
//! The bus columns live in the auxiliary trace and are ordered as follows:
//! - p1/p2/p3 (decoder)
//! - p1 (stack overflow, stack aux segment)
//! - b_range (range checker LogUp)
//! - b_hash_kernel (chiplets virtual table)
//! - b_chiplets (chiplets bus)
//! - v_wiring (ACE wiring LogUp)

/// Auxiliary trace column indices.
pub mod indices {
    /// Block stack table (decoder control flow)
    pub const P1_BLOCK_STACK: usize = 0;
    /// Block hash table (decoder digest tracking)
    pub const P2_BLOCK_HASH: usize = 1;
    /// Op group table (decoder operation batching)
    pub const P3_OP_GROUP: usize = 2;
    /// Stack overflow table (stack p1)
    pub const P1_STACK: usize = 3;
    /// Range checker bus
    pub const B_RANGE: usize = 4;
    /// Hash kernel bus: sibling table + ACE memory + log_precompile
    pub const B_HASH_KERNEL: usize = 5;
    /// Main chiplets bus
    pub const B_CHIPLETS: usize = 6;
    /// Wiring bus for ACE circuit connections
    pub const V_WIRING: usize = 7;
}
