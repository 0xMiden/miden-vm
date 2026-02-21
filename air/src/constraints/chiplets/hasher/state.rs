//! Hasher chiplet state transition constraints.
//!
//! This module enforces the Poseidon2 permutation constraints for the hasher chiplet.
//! The permutation operates on a 32-row cycle with three types of steps:
//!
//! - **Row 0 (init linear)**: Apply external linear layer M_E only
//! - **Rows 1-4, 27-30 (external)**: Add lane RCs, full S-box^7, then M_E
//! - **Rows 5-26 (internal)**: Add RC to lane 0, S-box lane 0 only, then M_I
//! - **Row 31 (boundary)**: No step constraint (output/absorb row)
//!
//! ## Poseidon2 Parameters
//!
//! - State width: 12 field elements
//! - External rounds: 8 (4 initial + 4 terminal)
//! - Internal rounds: 22
//! - S-box: x^7

use miden_core::{chiplets::hasher::Hasher, field::PrimeCharacteristicRing};
use miden_crypto::stark::air::MidenAirBuilder;

use super::periodic::{
    P_ARK_EXT_START, P_ARK_INT, P_CYCLE_ROW_0, P_IS_EXTERNAL, P_IS_INTERNAL, STATE_WIDTH,
};
use crate::{Felt, constraints::tagging::TaggingAirBuilderExt};

// TAGGING NAMESPACES
// ================================================================================================

const PERM_INIT_NAMESPACE: &str = "chiplets.hasher.permutation.init";
const PERM_EXT_NAMESPACE: &str = "chiplets.hasher.permutation.external";
const PERM_INT_NAMESPACE: &str = "chiplets.hasher.permutation.internal";
const ABP_CAP_NAMESPACE: &str = "chiplets.hasher.abp.capacity";

// CONSTRAINT HELPERS
// ================================================================================================

/// Enforces Poseidon2 permutation step constraints.
///
/// ## Step Types
///
/// 1. **Init linear (row 0)**: `h' = M_E(h)`
/// 2. **External round (rows 1-4, 27-30)**: `h' = M_E(S-box(h + ark_ext))`
/// 3. **Internal round (rows 5-26)**: `h' = M_I(h with lane0 = (h[0] + ark_int)^7)`
/// 4. **Boundary (row 31)**: No constraint
pub fn enforce_permutation_steps<AB>(
    builder: &mut AB,
    step_gate: AB::Expr,
    h: &[AB::Expr; STATE_WIDTH],
    h_next: &[AB::Expr; STATE_WIDTH],
    periodic: &[AB::PeriodicVal],
) where
    AB: MidenAirBuilder<F = Felt>,
{
    // Cycle markers and step selectors
    let cycle_row_0: AB::Expr = periodic[P_CYCLE_ROW_0].into();
    let is_external: AB::Expr = periodic[P_IS_EXTERNAL].into();
    let is_internal: AB::Expr = periodic[P_IS_INTERNAL].into();
    let is_init_linear = cycle_row_0.clone();

    // External round constants
    let mut ark_ext = [AB::Expr::ZERO; STATE_WIDTH];
    for lane in 0..STATE_WIDTH {
        ark_ext[lane] = periodic[P_ARK_EXT_START + lane].into();
    }
    let ark_int: AB::Expr = periodic[P_ARK_INT].into();

    // -------------------------------------------------------------------------
    // Compute expected next states for each step type
    // -------------------------------------------------------------------------

    // Init linear: h' = M_E(h)
    let expected_init = apply_matmul_external::<AB>(h);

    // External round: h' = M_E(S-box(h + ark_ext))
    let ext_with_rc: [AB::Expr; STATE_WIDTH] =
        core::array::from_fn(|i| h[i].clone() + ark_ext[i].clone());
    let ext_with_sbox: [AB::Expr; STATE_WIDTH] =
        core::array::from_fn(|i| ext_with_rc[i].clone().exp_const_u64::<7>());
    let expected_ext = apply_matmul_external::<AB>(&ext_with_sbox);

    // Internal round: h' = M_I(h with h[0] = (h[0] + ark_int)^7)
    let mut tmp_int = h.clone();
    tmp_int[0] = (tmp_int[0].clone() + ark_int).exp_const_u64::<7>();
    let expected_int = apply_matmul_internal::<AB>(&tmp_int);

    // -------------------------------------------------------------------------
    // Enforce step constraints
    // -------------------------------------------------------------------------

    // Use combined gates to share `step_gate * step_type` across all lanes.
    let gate_init = step_gate.clone() * is_init_linear;
    let init_ids: [usize; STATE_WIDTH] =
        core::array::from_fn(|i| super::HASHER_PERM_INIT_BASE_ID + i);

    builder.tagged_list(init_ids, PERM_INIT_NAMESPACE, |builder| {
        builder
            .when(gate_init)
            .assert_zeros(core::array::from_fn::<_, STATE_WIDTH, _>(|i| {
                h_next[i].clone() - expected_init[i].clone()
            }));
    });

    let gate_ext = step_gate.clone() * is_external;
    let ext_ids: [usize; STATE_WIDTH] =
        core::array::from_fn(|i| super::HASHER_PERM_EXT_BASE_ID + i);

    builder.tagged_list(ext_ids, PERM_EXT_NAMESPACE, |builder| {
        builder
            .when(gate_ext)
            .assert_zeros(core::array::from_fn::<_, STATE_WIDTH, _>(|i| {
                h_next[i].clone() - expected_ext[i].clone()
            }));
    });

    let gate_int = step_gate * is_internal;
    let int_ids: [usize; STATE_WIDTH] =
        core::array::from_fn(|i| super::HASHER_PERM_INT_BASE_ID + i);

    builder.tagged_list(int_ids, PERM_INT_NAMESPACE, |builder| {
        builder
            .when(gate_int)
            .assert_zeros(core::array::from_fn::<_, STATE_WIDTH, _>(|i| {
                h_next[i].clone() - expected_int[i].clone()
            }));
    });
}

/// Enforces ABP capacity preservation constraint.
///
/// When absorbing the next set of elements during linear hash computation (ABP on row 31),
/// the capacity portion `h[8..12]` is preserved unchanged.
pub fn enforce_abp_capacity_preservation<AB>(
    builder: &mut AB,
    transition_flag: AB::Expr,
    f_abp: AB::Expr,
    h_cap: &[AB::Expr; 4],
    h_cap_next: &[AB::Expr; 4],
) where
    AB: MidenAirBuilder<F = Felt>,
{
    // Use a combined gate to share `transition_flag * f_abp` across all 4 lanes.
    let gate = transition_flag * f_abp;
    let abp_ids: [usize; 4] = core::array::from_fn(|i| super::HASHER_ABP_BASE_ID + i);
    builder.tagged_list(abp_ids, ABP_CAP_NAMESPACE, |builder| {
        builder.when(gate).assert_zeros(core::array::from_fn::<_, 4, _>(|i| {
            h_cap_next[i].clone() - h_cap[i].clone()
        }));
    });
}

// =============================================================================
// LINEAR ALGEBRA HELPERS
// =============================================================================

/// Applies the external linear layer M_E to the state.
///
/// The external layer consists of:
/// 1. Apply M4 to each 4-element block
/// 2. Add cross-block sums to each element
fn apply_matmul_external<AB: MidenAirBuilder<F = Felt>>(
    state: &[AB::Expr; STATE_WIDTH],
) -> [AB::Expr; STATE_WIDTH] {
    // Apply M4 to each block
    let b0 =
        matmul_m4::<AB>(&[state[0].clone(), state[1].clone(), state[2].clone(), state[3].clone()]);
    let b1 =
        matmul_m4::<AB>(&[state[4].clone(), state[5].clone(), state[6].clone(), state[7].clone()]);
    let b2 = matmul_m4::<AB>(&[
        state[8].clone(),
        state[9].clone(),
        state[10].clone(),
        state[11].clone(),
    ]);

    // Compute cross-block sums
    let stored0 = b0[0].clone() + b1[0].clone() + b2[0].clone();
    let stored1 = b0[1].clone() + b1[1].clone() + b2[1].clone();
    let stored2 = b0[2].clone() + b1[2].clone() + b2[2].clone();
    let stored3 = b0[3].clone() + b1[3].clone() + b2[3].clone();

    // Add sums to each element
    [
        b0[0].clone() + stored0.clone(),
        b0[1].clone() + stored1.clone(),
        b0[2].clone() + stored2.clone(),
        b0[3].clone() + stored3.clone(),
        b1[0].clone() + stored0.clone(),
        b1[1].clone() + stored1.clone(),
        b1[2].clone() + stored2.clone(),
        b1[3].clone() + stored3.clone(),
        b2[0].clone() + stored0,
        b2[1].clone() + stored1,
        b2[2].clone() + stored2,
        b2[3].clone() + stored3,
    ]
}

/// Applies the 4x4 MDS matrix M4.
fn matmul_m4<AB: MidenAirBuilder<F = Felt>>(input: &[AB::Expr; 4]) -> [AB::Expr; 4] {
    let [a, b, c, d] = input.clone();

    let t0 = a.clone() + b.clone();
    let t1 = c.clone() + d.clone();
    let t2 = b.clone() + b.clone() + t1.clone(); // 2b + t1
    let t3 = d.clone() + d.clone() + t0.clone(); // 2d + t0
    let t4 = t1.clone() + t1.clone() + t1.clone() + t1.clone() + t3.clone(); // 4*t1 + t3
    let t5 = t0.clone() + t0.clone() + t0.clone() + t0.clone() + t2.clone(); // 4*t0 + t2

    let out0 = t3.clone() + t5.clone();
    let out1 = t5;
    let out2 = t2 + t4.clone();
    let out3 = t4;

    [out0, out1, out2, out3]
}

/// Applies the internal linear layer M_I to the state.
///
/// M_I = I + diag(MAT_DIAG) where all rows share the same sum.
fn apply_matmul_internal<AB: MidenAirBuilder<F = Felt>>(
    state: &[AB::Expr; STATE_WIDTH],
) -> [AB::Expr; STATE_WIDTH] {
    // Sum of all state elements
    let sum: AB::Expr = state.iter().cloned().reduce(|a, b| a + b).unwrap();

    // result[i] = state[i] * MAT_DIAG[i] + sum
    core::array::from_fn(|i| state[i].clone() * AB::Expr::from(Hasher::MAT_DIAG[i]) + sum.clone())
}
