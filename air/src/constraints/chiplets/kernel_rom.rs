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

use super::selectors::ChipletSelectors;
use crate::{MainTraceRow, MidenAirBuilder, constraints::utils::BoolNot};
// CONSTANTS
// ================================================================================================

// Kernel ROM chiplet offset from CHIPLETS_OFFSET (after s0, s1, s2, s3, s4).
const KERNEL_ROM_OFFSET: usize = 5;

// Column indices within the kernel ROM chiplet
const SFIRST_IDX: usize = 0;
const R0_IDX: usize = 1;
const R1_IDX: usize = 2;
const R2_IDX: usize = 3;
const R3_IDX: usize = 4;

// ENTRY POINTS
// ================================================================================================

/// Enforce kernel ROM chiplet constraints.
pub fn enforce_kernel_rom_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    selectors: &ChipletSelectors<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let s4_next = next.chiplets[4];

    let kernel_rom_flag = selectors.kernel_rom.is_active.clone();

    // Load kernel ROM columns (sfirst + 4-word digest).
    let sfirst = load_kernel_rom_col::<AB>(local, SFIRST_IDX);
    let sfirst_next = load_kernel_rom_col::<AB>(next, SFIRST_IDX);
    let r0 = load_kernel_rom_col::<AB>(local, R0_IDX);
    let r0_next = load_kernel_rom_col::<AB>(next, R0_IDX);
    let r1 = load_kernel_rom_col::<AB>(local, R1_IDX);
    let r1_next = load_kernel_rom_col::<AB>(next, R1_IDX);
    let r2 = load_kernel_rom_col::<AB>(local, R2_IDX);
    let r2_next = load_kernel_rom_col::<AB>(next, R2_IDX);
    let r3 = load_kernel_rom_col::<AB>(local, R3_IDX);
    let r3_next = load_kernel_rom_col::<AB>(next, R3_IDX);

    let not_s4_next = AB::Expr::from(s4_next).not();

    // ==========================================================================
    // SELECTOR CONSTRAINT
    // ==========================================================================

    // sfirst must be binary
    builder.when(kernel_rom_flag.clone()).assert_bool(sfirst.clone());

    // ==========================================================================
    // DIGEST CONTIGUITY CONSTRAINTS
    // ==========================================================================

    // When sfirst' = 0 (not the start of a new digest block) and s4' = 0 (not exiting kernel ROM),
    // the digest values must remain unchanged.
    let contiguity_condition = not_s4_next * sfirst_next.not();

    // Use a combined gate to share `kernel_rom_flag * contiguity_condition` across all 4 lanes.
    {
        let transition_gate = selectors.kernel_rom.is_transition.clone() * contiguity_condition;
        let builder = &mut builder.when(transition_gate);
        builder.assert_eq(r0_next, r0);
        builder.assert_eq(r1_next, r1);
        builder.assert_eq(r2_next, r2);
        builder.assert_eq(r3_next, r3);
    }

    // ==========================================================================
    // FIRST ROW CONSTRAINT
    // ==========================================================================

    // First row of kernel ROM must have sfirst' = 1.
    // Uses selectors.ace.is_last to detect ACE→KernelROM boundary.
    let flag_next_row_first_kernel_rom = selectors.kernel_rom.next_is_first.clone();
    builder.when(flag_next_row_first_kernel_rom).assert_one(sfirst_next);
}

// INTERNAL HELPERS
// ================================================================================================

/// Load a column from the kernel ROM section of chiplets.
fn load_kernel_rom_col<AB>(row: &MainTraceRow<AB::Var>, col_idx: usize) -> AB::Expr
where
    AB: MidenAirBuilder,
{
    // Kernel ROM columns start after s0, s1, s2, s3, s4 (5 selectors)
    let local_idx = KERNEL_ROM_OFFSET + col_idx;
    row.chiplets[local_idx].into()
}
