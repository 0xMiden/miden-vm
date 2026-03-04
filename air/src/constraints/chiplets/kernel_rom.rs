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

use miden_core::field::PrimeCharacteristicRing;

use super::selectors::{ace_chiplet_flag, kernel_rom_chiplet_flag};
use crate::{
    Felt, MainTraceRow,
    constraints::tagging::{
        TagGroup, TaggingAirBuilderExt, tagged_assert_zero, tagged_assert_zero_integrity,
    },
};

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

// TAGGING CONSTANTS
// ================================================================================================

pub(super) const KERNEL_ROM_BASE_ID: usize =
    super::memory::MEMORY_BASE_ID + super::memory::MEMORY_COUNT + super::ace::ACE_COUNT;
const KERNEL_ROM_SFIRST_ID: usize = KERNEL_ROM_BASE_ID;
const KERNEL_ROM_DIGEST_BASE_ID: usize = KERNEL_ROM_BASE_ID + 1;
const KERNEL_ROM_FIRST_ROW_ID: usize = KERNEL_ROM_BASE_ID + 5;

const KERNEL_ROM_SFIRST_NAMESPACE: &str = "chiplets.kernel_rom.sfirst.binary";
const KERNEL_ROM_DIGEST_NAMESPACE: &str = "chiplets.kernel_rom.digest.contiguity";
const KERNEL_ROM_FIRST_ROW_NAMESPACE: &str = "chiplets.kernel_rom.first_row.start";

const KERNEL_ROM_SFIRST_NAMES: [&str; 1] = [KERNEL_ROM_SFIRST_NAMESPACE; 1];
const KERNEL_ROM_DIGEST_NAMES: [&str; 4] = [KERNEL_ROM_DIGEST_NAMESPACE; 4];
const KERNEL_ROM_FIRST_ROW_NAMES: [&str; 1] = [KERNEL_ROM_FIRST_ROW_NAMESPACE; 1];

const KERNEL_ROM_SFIRST_TAGS: TagGroup = TagGroup {
    base: KERNEL_ROM_SFIRST_ID,
    names: &KERNEL_ROM_SFIRST_NAMES,
};
const KERNEL_ROM_DIGEST_TAGS: TagGroup = TagGroup {
    base: KERNEL_ROM_DIGEST_BASE_ID,
    names: &KERNEL_ROM_DIGEST_NAMES,
};
const KERNEL_ROM_FIRST_ROW_TAGS: TagGroup = TagGroup {
    base: KERNEL_ROM_FIRST_ROW_ID,
    names: &KERNEL_ROM_FIRST_ROW_NAMES,
};

// ENTRY POINTS
// ================================================================================================

/// Enforce kernel ROM chiplet constraints.
pub fn enforce_kernel_rom_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    // Chiplet selector columns; kernel ROM rows are selected by (s0..s4).
    let s0: AB::Expr = local.chiplets[0].clone().into();
    let s1: AB::Expr = local.chiplets[1].clone().into();
    let s2: AB::Expr = local.chiplets[2].clone().into();
    let s3: AB::Expr = local.chiplets[3].clone().into();
    let s4: AB::Expr = local.chiplets[4].clone().into();
    let s3_next: AB::Expr = next.chiplets[3].clone().into();
    let s4_next: AB::Expr = next.chiplets[4].clone().into();

    let kernel_rom_flag =
        kernel_rom_chiplet_flag(s0.clone(), s1.clone(), s2.clone(), s3.clone(), s4.clone());
    let ace_flag = ace_chiplet_flag(s0.clone(), s1.clone(), s2.clone(), s3.clone());

    // Load kernel ROM columns (sfirst + 4-word digest).
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

    // Gate transition constraints by is_transition() to avoid last-row access.
    // ==========================================================================
    // SELECTOR CONSTRAINT
    // ==========================================================================

    // sfirst must be binary
    let mut idx = 0;
    tagged_assert_zero_integrity(
        builder,
        &KERNEL_ROM_SFIRST_TAGS,
        &mut idx,
        kernel_rom_flag.clone() * sfirst.clone() * (sfirst.clone() - one.clone()),
    );

    // ==========================================================================
    // DIGEST CONTIGUITY CONSTRAINTS
    // ==========================================================================

    // When sfirst' = 0 (not the start of a new digest block) and s4' = 0 (not exiting kernel ROM),
    // the digest values must remain unchanged.
    let not_exiting = one.clone() - s4_next.clone();
    let not_new_block = one.clone() - sfirst_next.clone();
    let contiguity_condition = not_exiting * not_new_block;

    // Use a combined gate to share `kernel_rom_flag * contiguity_condition` across all 4 lanes.
    let gate = kernel_rom_flag * contiguity_condition;
    let mut idx = 0;
    tagged_assert_zero(builder, &KERNEL_ROM_DIGEST_TAGS, &mut idx, gate.clone() * (r0_next - r0));
    tagged_assert_zero(builder, &KERNEL_ROM_DIGEST_TAGS, &mut idx, gate.clone() * (r1_next - r1));
    tagged_assert_zero(builder, &KERNEL_ROM_DIGEST_TAGS, &mut idx, gate.clone() * (r2_next - r2));
    tagged_assert_zero(builder, &KERNEL_ROM_DIGEST_TAGS, &mut idx, gate * (r3_next - r3));

    // ==========================================================================
    // FIRST ROW CONSTRAINT
    // ==========================================================================

    // s0..s2 are stable once 1 (selector constraints), so ACE -> kernel ROM transition is
    // determined by s3' = 1 and s4' = 0.
    let kernel_rom_next = s3_next * (one.clone() - s4_next.clone());
    let flag_next_row_first_kernel_rom = ace_flag * kernel_rom_next;

    // First row of kernel ROM must have sfirst' = 1.
    let mut idx = 0;
    tagged_assert_zero(
        builder,
        &KERNEL_ROM_FIRST_ROW_TAGS,
        &mut idx,
        flag_next_row_first_kernel_rom * (sfirst_next - one),
    );
}

// INTERNAL HELPERS
// ================================================================================================

/// Load a column from the kernel ROM section of chiplets.
fn load_kernel_rom_col<AB>(row: &MainTraceRow<AB::Var>, col_idx: usize) -> AB::Expr
where
    AB: TaggingAirBuilderExt<F = Felt>,
{
    // Kernel ROM columns start after s0, s1, s2, s3, s4 (5 selectors)
    let local_idx = KERNEL_ROM_OFFSET + col_idx;
    row.chiplets[local_idx].clone().into()
}
