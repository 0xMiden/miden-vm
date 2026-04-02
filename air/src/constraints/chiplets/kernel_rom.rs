//! Kernel ROM chiplet constraints.
//!
//! The kernel ROM chiplet exposes the digest table used by kernel (system) calls.
//! This module only enforces shape constraints (binary selectors, digest contiguity, and the
//! start-of-block marker). Validity of syscall selection is enforced by decoder and chiplets' bus.
//!
//! ## Column layout (5 columns within chiplet)
//!
//! | Column  | Purpose                                           |
//! |---------|---------------------------------------------------|
//! | sfirst  | 1 = first row of digest block, 0 = continuation   |
//! | r0-r3   | 4-element kernel procedure digest                 |
//!
//! ## Operations
//!
//! - **KERNELPROCINIT** (sfirst=1): first row of a digest block (public input digests)
//! - **KERNELPROCCALL** (sfirst=0): continuation rows used by SYSCALL
//!
//! ## Constraints
//!
//! 1. sfirst must be binary
//! 2. Digest contiguity: when sfirst'=0 and s4'=0, digest values stay the same
//! 3. First row: when entering kernel ROM, sfirst' must be 1

use miden_crypto::stark::air::AirBuilder;

use super::selectors::ChipletFlags;
use crate::{
    MainTraceRow, MidenAirBuilder,
    constraints::utils::BoolNot,
    trace::{KernelRomCols, chiplets::borrow_chiplet},
};

// ENTRY POINTS
// ================================================================================================

/// Enforce kernel ROM chiplet constraints.
pub fn enforce_kernel_rom_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    flags: &ChipletFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let s4_next = next.chiplets[4];

    let kernel_rom_flag = flags.is_active.clone();

    // Zero-copy borrow of kernel ROM columns (sfirst + 4-word digest).
    let krom: &KernelRomCols<AB::Var> = borrow_chiplet(&local.chiplets[5..10]);
    let krom_next: &KernelRomCols<AB::Var> = borrow_chiplet(&next.chiplets[5..10]);

    let not_s4_next = s4_next.into().not();

    // ==========================================================================
    // SELECTOR CONSTRAINT
    // ==========================================================================

    // sfirst must be binary
    builder.when(kernel_rom_flag.clone()).assert_bool(krom.s_first);

    // ==========================================================================
    // DIGEST CONTIGUITY CONSTRAINTS
    // ==========================================================================

    // When sfirst' = 0 (not the start of a new digest block) and s4' = 0 (not exiting kernel ROM),
    // the digest values must remain unchanged.
    let contiguity_condition = not_s4_next * krom_next.s_first.into().not();

    // Use a combined gate to share `kernel_rom_flag * contiguity_condition` across all 4 lanes.
    {
        let transition_gate = flags.is_transition.clone() * contiguity_condition;
        let builder = &mut builder.when(transition_gate);
        builder.assert_eq(krom_next.root[0], krom.root[0]);
        builder.assert_eq(krom_next.root[1], krom.root[1]);
        builder.assert_eq(krom_next.root[2], krom.root[2]);
        builder.assert_eq(krom_next.root[3], krom.root[3]);
    }

    // ==========================================================================
    // FIRST ROW CONSTRAINT
    // ==========================================================================

    // First row of kernel ROM must have sfirst' = 1.
    // Uses the precomputed next_is_first flag to detect ACE→KernelROM boundary.
    let flag_next_row_first_kernel_rom = flags.next_is_first.clone();
    builder.when(flag_next_row_first_kernel_rom).assert_one(krom_next.s_first);
}
