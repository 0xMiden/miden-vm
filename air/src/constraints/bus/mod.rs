//! Bus shared definitions.
//!
//! This module provides shared definitions for auxiliary (bus) constraints.
//! The bus constraints themselves live under each component:
//! - `decoder::bus` (p1/p2/p3)
//! - `stack::bus` (s_aux)
//! - `range::bus` (b_range)
//! - `chiplets::bus` (b_chiplets, b_hash_kernel, v_wiring)
//!
//! ## What Makes a Bus Constraint
//!
//! A constraint is a bus constraint if it:
//! 1. Accesses `builder.permutation()` (auxiliary trace columns)
//! 2. Uses `builder.permutation_randomness()` (random challenges)
//! 3. Enforces LogUp/multiset check properties
//!
//! ## Auxiliary Trace Column Layout
//!
//! | Index | Column | Component | Description |
//! |-------|--------|-----------|-------------|
//! | 0 | p1 | Decoder | Block stack table (push/pop for control flow) |
//! | 1 | p2 | Decoder | Block hash table (block digest tracking) |
//! | 2 | p3 | Decoder | Op group table (operation batching) |
//! | 3 | s_aux | Stack | Stack overflow table (deep stack entries) |
//! | 4 | b_range | Range | Range checker bus (16-bit value validation) |
//! | 5 | b_hash_kernel | Chiplets | Sibling table + ACE memory + log_precompile |
//! | 6 | b_chiplets | Chiplets | Main chiplets bus (hasher, bitwise, memory, ACE) |
//! | 7 | v_wiring | Chiplets | Wiring bus for ACE circuit wiring |
//!
//! ## Implementation Locations
//!
//! | Bus | Location |
//! |-----|----------|
//! | p1/p2/p3 | `constraints/decoder/bus.rs` |
//! | s_aux | `constraints/stack/bus.rs` |
//! | b_range | `constraints/range/bus.rs` |
//! | b_hash_kernel | `constraints/chiplets/bus/hash_kernel.rs` |
//! | b_chiplets | `constraints/chiplets/bus/chiplets.rs` |
//! | v_wiring | `constraints/chiplets/bus/wiring.rs` |
//!
//! ## Kernel Verification via aux_finals
//!
//! The chiplets bus (b_chiplets) uses aux_finals for kernel verification:
//! - First row: b_chiplets[0] = 1 (AIR boundary constraint)
//! - Last row: b_chiplets[last] = reduced_kernel_digests (verified via aux_finals)
//!
//! The verifier checks aux_final[b_chiplets] against the expected value computed from
//! kernel hashes provided as variable-length public inputs.

// CONSTANTS
// ================================================================================================

/// Auxiliary trace column indices.
pub mod indices {
    /// Block stack table (decoder control flow)
    pub const P1_BLOCK_STACK: usize = 0;
    /// Block hash table (decoder digest tracking)
    pub const P2_BLOCK_HASH: usize = 1;
    /// Op group table (decoder operation batching)
    pub const P3_OP_GROUP: usize = 2;
    /// Stack overflow table
    pub const S_AUX_STACK: usize = 3;
    /// Range checker bus
    pub const B_RANGE: usize = 4;
    /// Hash kernel bus: sibling table (Merkle) + ACE memory + log_precompile
    pub const B_HASH_KERNEL: usize = 5;
    /// Main chiplets bus
    pub const B_CHIPLETS: usize = 6;
    /// Wiring bus for ACE circuit connections
    pub const V_WIRING: usize = 7;
}
