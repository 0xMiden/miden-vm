//! Chiplets constraints module.
//!
//! This module contains constraints for all chiplets in the Miden VM:
//!
//! - [`hasher`]: Poseidon2 hasher chiplet (hashing, Merkle tree operations)
//! - [`bitwise`]: Bitwise operations chiplet (AND, XOR)
//! - [`memory`]: Memory access chiplet
//! - [`ace`]: Arithmetic Circuit Evaluation chiplet
//! - [`kernel_rom`]: Kernel ROM chiplet
//! - [`selectors`]: Chiplet selector system
//!
//! ## Chiplet Hierarchy
//!
//! The chiplet system uses 5 selector columns `s[0..4]` to identify active chiplets:
//!
//! | Chiplet     | Active when                    |
//! |-------------|--------------------------------|
//! | Hasher      | `!s0`                          |
//! | Bitwise     | `s0 * !s1`                     |
//! | Memory      | `s0 * s1 * !s2`                |
//! | ACE         | `s0 * s1 * s2 * !s3`           |
//! | Kernel ROM  | `s0 * s1 * s2 * s3 * !s4`      |

pub mod ace;
pub mod bitwise;
pub mod bus;
pub mod hasher;
pub mod kernel_rom;
pub mod memory;
pub mod selectors;

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;
use selectors::memory_chiplet_flag;

use crate::{Felt, MainTraceRow};

// ENTRY POINTS
// ================================================================================================

/// Enforces chiplets main-trace constraints (entry point).
///
/// This orchestrates:
/// 1. Chiplet selector constraints
/// 2. Hasher chiplet constraints
/// 3. Bitwise chiplet constraints
/// 4. Memory chiplet constraints
/// 5. ACE chiplet constraints
/// 6. Kernel ROM chiplet constraints
pub fn enforce_main<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    // ==========================================================================
    // CHIPLET SELECTOR CONSTRAINTS
    // ==========================================================================
    selectors::enforce_chiplet_selectors(builder, local, next);

    // ==========================================================================
    // HASHER CHIPLET
    // ==========================================================================
    hasher::enforce_hasher_constraints(builder, local, next);

    // ==========================================================================
    // BITWISE CHIPLET
    // ==========================================================================
    let (k_first, k_transition) = {
        // Clone out what we need to avoid holding a borrow of `builder` while asserting
        // constraints.
        let periodic = builder.periodic_evals();
        debug_assert!(periodic.len() > bitwise::P_BITWISE_K_TRANSITION);
        (
            periodic[bitwise::P_BITWISE_K_FIRST].into(),
            periodic[bitwise::P_BITWISE_K_TRANSITION].into(),
        )
    };
    bitwise::enforce_bitwise_constraints(builder, local, next, k_first, k_transition);

    // ==========================================================================
    // MEMORY CHIPLET
    // ==========================================================================
    enforce_memory_chiplet(builder, local, next);

    // ==========================================================================
    // ACE CHIPLET
    // ==========================================================================
    enforce_ace_chiplet(builder, local, next);

    // ==========================================================================
    // KERNEL ROM CHIPLET
    // ==========================================================================
    enforce_kernel_rom_chiplet(builder, local, next);
}

// CONSTRAINT HELPERS
// ================================================================================================

/// Enforce memory chiplet constraints with proper transition handling.
fn enforce_memory_chiplet<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    // Load selectors
    let s0: AB::Expr = local.chiplets[0].clone().into();
    let s1: AB::Expr = local.chiplets[1].clone().into();
    let s1_next: AB::Expr = next.chiplets[1].clone().into();
    let s2_next: AB::Expr = next.chiplets[2].clone().into();

    // Gate transition constraints by is_transition() to avoid last-row issues
    let is_transition: AB::Expr = builder.is_transition();

    // Memory constraints on all rows
    memory::enforce_memory_constraints_all_rows(builder, local, next);

    // Memory first row constraints (transitioning from bitwise to memory)
    // Flag: current row is bitwise (!s1), next row is memory (s1' & !s2')
    // Must be gated by is_transition since it accesses next-row values
    let flag_next_row_first_memory = is_transition.clone()
        * memory::flag_next_row_first_memory(
            s0.clone(),
            s1.clone(),
            s1_next.clone(),
            s2_next.clone(),
        );
    memory::enforce_memory_constraints_first_row(builder, local, next, flag_next_row_first_memory);

    // Memory transition constraints (active and not exiting)
    // Flag: s0 * s1 * !s2' (memory active and continuing)
    // Must be gated by is_transition since it accesses next-row values
    let flag_memory_active_not_last =
        is_transition * memory::flag_memory_active_not_last_row(s0, s1, s2_next);
    memory::enforce_memory_constraints_all_rows_except_last(
        builder,
        local,
        next,
        flag_memory_active_not_last,
    );
}

/// Enforce ACE chiplet constraints with proper transition handling.
fn enforce_ace_chiplet<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    // Load selectors
    let s0: AB::Expr = local.chiplets[0].clone().into();
    let s1: AB::Expr = local.chiplets[1].clone().into();
    let s2: AB::Expr = local.chiplets[2].clone().into();
    let s2_next: AB::Expr = next.chiplets[2].clone().into();
    let s3_next: AB::Expr = next.chiplets[3].clone().into();

    // Gate transition constraints by is_transition() to avoid last-row issues
    let is_transition: AB::Expr = builder.is_transition();

    // ACE constraints on all rows (already internally gated)
    ace::enforce_ace_constraints_all_rows(builder, local, next);

    // ACE first row constraints (transitioning from memory to ACE)
    // Flag: current row is memory (s0*s1*!s2), next row is ACE (s2'=1 AND s3'=0)
    // The s3'=0 check is critical because:
    // 1. A trace may skip ACE entirely (going memory → kernel ROM)
    // 2. When not in ACE, chiplets[4] is s4 (selector), not sstart
    // 3. Without the s3'=0 check, we'd read the wrong column
    // Must be gated by is_transition since it accesses next-row values
    let memory_flag = memory_chiplet_flag(s0, s1, s2);
    // ace_next = s2' * !s3'
    let ace_next = s2_next * (AB::Expr::ONE - s3_next);
    let flag_next_row_first_ace = is_transition * memory_flag * ace_next;
    ace::enforce_ace_constraints_first_row(builder, local, next, flag_next_row_first_ace);
}

/// Enforce kernel ROM chiplet constraints with proper transition handling.
fn enforce_kernel_rom_chiplet<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder<F = Felt>,
{
    use selectors::ace_chiplet_flag;

    // Load selectors
    let s0: AB::Expr = local.chiplets[0].clone().into();
    let s1: AB::Expr = local.chiplets[1].clone().into();
    let s2: AB::Expr = local.chiplets[2].clone().into();
    let s3: AB::Expr = local.chiplets[3].clone().into();
    let s3_next: AB::Expr = next.chiplets[3].clone().into();
    let s4_next: AB::Expr = next.chiplets[4].clone().into();

    // Gate transition constraints by is_transition() to avoid last-row issues
    let is_transition: AB::Expr = builder.is_transition();

    // Kernel ROM constraints on all rows
    kernel_rom::enforce_kernel_rom_constraints(builder, local, next);

    // Kernel ROM first row constraints (entering kernel ROM from ACE)
    // Flag: current row is ACE (s0*s1*s2*!s3), next row is kernel ROM (s3'=1 AND s4'=0)
    // The s4'=0 check is critical because:
    // 1. A trace may skip kernel ROM entirely (going ACE → padding)
    // 2. When not in kernel ROM, chiplets[5] is padding column, not sfirst
    // 3. Without the s4'=0 check, we'd read the wrong column
    // Must be gated by is_transition since it accesses next-row values
    let ace_active = ace_chiplet_flag(s0, s1, s2, s3);
    // kernel_rom_next = s3' * !s4'
    let kernel_rom_next = s3_next * (AB::Expr::ONE - s4_next);
    let flag_next_row_first_kernel_rom = is_transition * ace_active * kernel_rom_next;
    kernel_rom::enforce_kernel_rom_constraints_first_row(
        builder,
        local,
        next,
        flag_next_row_first_kernel_rom,
    );
}
