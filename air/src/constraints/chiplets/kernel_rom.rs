//! Kernel ROM chiplet constraints.
//!
//! The kernel ROM chiplet tracks execution of kernel (system) calls.
//! It maintains digest values for all available kernel procedures and ensures that only kernel
//! procedures can be syscalled.
//!
//! ## Column Layout (5 columns within chiplet)
//!
//! | Column  | Purpose                                           |
//! |---------|---------------------------------------------------|
//! | sfirst  | 1 = first row of digest block, 0 = continuation   |
//! | r0-r3   | 4-element kernel procedure digest                 |
//!
//! ## Operations
//!
//! - **KERNELPROCINIT** (sfirst=1): Responds to public input kernel digests
//! - **KERNELPROCCALL** (sfirst=0): Responds to SYSCALL operations
//!
//! ## Constraints
//!
//! 1. sfirst must be binary
//! 2. Digest contiguity: when sfirst'=0 and s4'=0, digest values stay the same
//! 3. First row: sfirst'=1 when entering kernel ROM

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use super::selectors::kernel_rom_chiplet_flag;
use crate::{Felt, MainTraceRow};

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
///
/// This enforces:
/// 1. sfirst is binary
/// 2. Digest contiguity (when sfirst'=0 and s4'=0, digest values stay the same)
pub fn enforce_kernel_rom_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    // Compute kernel ROM active flag from top-level selectors
    let s0: AB::Expr = local.chiplets[0].clone().into();
    let s1: AB::Expr = local.chiplets[1].clone().into();
    let s2: AB::Expr = local.chiplets[2].clone().into();
    let s3: AB::Expr = local.chiplets[3].clone().into();
    let s4: AB::Expr = local.chiplets[4].clone().into();
    let s4_next: AB::Expr = next.chiplets[4].clone().into();

    let kernel_rom_flag =
        kernel_rom_chiplet_flag(s0.clone(), s1.clone(), s2.clone(), s3.clone(), s4.clone());

    // Load kernel ROM columns
    let sfirst: AB::Expr = load_kernel_rom_col::<AB>(local, SFIRST_IDX);
    let sfirst_next: AB::Expr = load_kernel_rom_col::<AB>(next, SFIRST_IDX);
    let r0: AB::Expr = load_kernel_rom_col::<AB>(local, R0_IDX);
    let r0_next: AB::Expr = load_kernel_rom_col::<AB>(next, R0_IDX);
    let r1: AB::Expr = load_kernel_rom_col::<AB>(local, R1_IDX);
    let r1_next: AB::Expr = load_kernel_rom_col::<AB>(next, R1_IDX);
    let r2: AB::Expr = load_kernel_rom_col::<AB>(local, R2_IDX);
    let r2_next: AB::Expr = load_kernel_rom_col::<AB>(next, R2_IDX);
    let r3: AB::Expr = load_kernel_rom_col::<AB>(local, R3_IDX);
    let r3_next: AB::Expr = load_kernel_rom_col::<AB>(next, R3_IDX);

    let one: AB::Expr = AB::Expr::ONE;

    // Gate transition constraints by is_transition() to avoid last-row issues
    let is_transition: AB::Expr = builder.is_transition();

    // ==========================================================================
    // SELECTOR CONSTRAINT
    // ==========================================================================

    // sfirst must be binary
    builder.assert_zero(kernel_rom_flag.clone() * sfirst.clone() * (sfirst.clone() - one.clone()));

    // ==========================================================================
    // DIGEST CONTIGUITY CONSTRAINTS
    // ==========================================================================

    // When sfirst' = 0 (not the start of a new digest block) and s4' = 0 (not exiting kernel ROM),
    // the digest values must remain unchanged.
    let not_exiting = one.clone() - s4_next;
    let not_new_block = one.clone() - sfirst_next;
    let contiguity_condition = is_transition * not_exiting * not_new_block;

    // Use a combined gate to share `kernel_rom_flag * contiguity_condition` across all 4 lanes.
    let gate = kernel_rom_flag * contiguity_condition;
    builder
        .when(gate)
        .assert_zeros([r0_next - r0, r1_next - r1, r2_next - r2, r3_next - r3]);
}

/// Enforce kernel ROM first row constraints.
///
/// On the first row of kernel ROM chiplet, sfirst' must be 1.
pub fn enforce_kernel_rom_constraints_first_row<AB>(
    builder: &mut AB,
    _local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
    flag_next_row_first_kernel_rom: AB::Expr,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    let sfirst_next: AB::Expr = load_kernel_rom_col::<AB>(next, SFIRST_IDX);
    let one: AB::Expr = AB::Expr::ONE;

    // First row of kernel ROM must have sfirst' = 1
    builder.assert_zero(flag_next_row_first_kernel_rom * (sfirst_next - one));
}

// INTERNAL HELPERS
// ================================================================================================

/// Load a column from the kernel ROM section of chiplets.
fn load_kernel_rom_col<AB>(row: &MainTraceRow<AB::Var>, col_idx: usize) -> AB::Expr
where
    AB: MidenAirBuilder<F = Felt>,
{
    // Kernel ROM columns start after s0, s1, s2, s3, s4 (5 selectors)
    let local_idx = KERNEL_ROM_OFFSET + col_idx;
    row.chiplets[local_idx].clone().into()
}
