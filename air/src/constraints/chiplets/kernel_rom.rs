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
use crate::{MainCols, MidenAirBuilder, constraints::utils::BoolNot};

// ENTRY POINTS
// ================================================================================================

/// Enforce kernel ROM chiplet constraints.
pub fn enforce_kernel_rom_constraints<AB>(
    builder: &mut AB,
    local: &MainCols<AB::Var>,
    next: &MainCols<AB::Var>,
    flags: &ChipletFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let krom = local.kernel_rom();
    let krom_next = next.kernel_rom();

    // ==========================================================================
    // SELECTOR CONSTRAINT
    // ==========================================================================

    // sfirst must be binary
    builder.when(flags.is_active.clone()).assert_bool(krom.s_first);

    // ==========================================================================
    // DIGEST CONTIGUITY CONSTRAINTS
    // ==========================================================================

    // In all rows but last, ensure that the digest repeats except when the next
    // row is the start of a new digest (i.e., s_first' = 0)
    {
        let gate = flags.is_transition.clone() * krom_next.s_first.into().not();
        let builder = &mut builder.when(gate);

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
    builder.when(flags.next_is_first.clone()).assert_one(krom_next.s_first);
}
