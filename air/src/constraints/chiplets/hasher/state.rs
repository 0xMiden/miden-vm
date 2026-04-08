//! Hasher chiplet state transition constraints.
//!
//! This module enforces the Poseidon2 permutation constraints for the hasher chiplet.
//! The permutation operates on a 16-row cycle with five types of steps:
//!
//! - **Row 0 (init+ext1)**: Merged init linear layer + first external round
//! - **Rows 1-3, 12-14 (external)**: Single external round: add RCs, S-box^7, M_E
//! - **Rows 4-10 (packed internal)**: 3 internal rounds packed per row using s0,s1,s2 as witnesses
//! - **Row 11 (int+ext)**: Last internal round + first trailing external round
//! - **Row 15 (boundary)**: No step constraint (cycle boundary, final permutation state)
//!
//! ## Poseidon2 Parameters
//!
//! - State width: 12 field elements
//! - External rounds: 8 (4 initial + 4 terminal)
//! - Internal rounds: 22
//! - S-box: x^7

use miden_core::{chiplets::hasher::Hasher, field::PrimeCharacteristicRing};
use miden_crypto::stark::air::LiftedAirBuilder;

use super::STATE_WIDTH;
use crate::{Felt, MidenAirBuilder, constraints::chiplets::columns::HasherPeriodicCols};

// CONSTRAINT HELPERS
// ================================================================================================

/// Enforces Poseidon2 permutation step constraints on the 16-row packed cycle.
///
/// These constraints are gated by `perm_gate = perm_seg`, so they only
/// fire on permutation segment rows.
///
/// ## Step Types
///
/// 1. **Init+ext1 (row 0)**: `h' = M_E(S(M_E(h) + ark))` — degree 9
/// 2. **Single ext (rows 1-3, 12-14)**: `h' = M_E(S(h + ark))` — degree 9
/// 3. **Packed 3x internal (rows 4-10)**: witnesses + affine next-state — degree 9 / 3
/// 4. **Int+ext (row 11)**: witness + `h' = M_E(S(y + ark))` — degree 9
/// 5. **Boundary (row 15)**: No constraint
///
/// The witness columns `w[0..2]` correspond to `s0, s1, s2` on permutation rows.
pub fn enforce_permutation_steps<AB>(
    builder: &mut AB,
    perm_gate: AB::Expr,
    h: &[AB::Expr; STATE_WIDTH],
    h_next: &[AB::Expr; STATE_WIDTH],
    w: &[AB::Expr; 3],
    periodic: &HasherPeriodicCols<AB::PeriodicVar>,
) where
    AB: MidenAirBuilder,
{
    // Step-type selectors
    let is_init_ext: AB::Expr = periodic.is_init_ext.into();
    let is_ext: AB::Expr = periodic.is_ext.into();
    let is_packed_int: AB::Expr = periodic.is_packed_int.into();
    let is_int_ext: AB::Expr = periodic.is_int_ext.into();

    // Shared round constants
    let ark: [AB::Expr; STATE_WIDTH] = core::array::from_fn(|i| periodic.ark[i].into());

    // -------------------------------------------------------------------------
    // 0. Unused witness zeroing
    //
    // Unused witness columns are forced to zero. On non-packed rows, this means:
    // - rows 0-3, 12-15: w0 = w1 = w2 = 0
    // - row 11:          w1 = w2 = 0
    // - rows 4-10:       w0, w1, w2 unconstrained here (checked by packed witness equations)
    //
    // These constraints are primarily defensive. They make permutation rows inert when
    // s0/s1/s2 are reused as witnesses and reduce accidental coupling with controller-side selector
    // logic. They may be redundant under the current gating structure, but are kept for now to be
    // on the safe side.
    //
    // Gate degrees:
    // - perm_gate(1) * (1 - is_packed_int - is_int_ext)(1) = 2 for w0
    // - perm_gate(1) * (1 - is_packed_int)(1) = 2 for w1,w2
    // Constraint degree: gate(2) * witness(1) = 3
    // -------------------------------------------------------------------------
    let gate_w0_unused =
        perm_gate.clone() * (AB::Expr::ONE - is_packed_int.clone() - is_int_ext.clone());
    let gate_w12_unused = perm_gate.clone() * (AB::Expr::ONE - is_packed_int.clone());
    builder.assert_zero(gate_w0_unused * w[0].clone());
    builder.assert_zero(gate_w12_unused.clone() * w[1].clone());
    builder.assert_zero(gate_w12_unused * w[2].clone());

    // -------------------------------------------------------------------------
    // 1. Init+ext1 (row 0): h' = M_E(S(M_E(h) + ark)) Gate degree: perm_gate(1) * is_init_ext(1) =
    //    2 Constraint degree: gate(2) * sbox(7) = 9
    // -------------------------------------------------------------------------
    let expected_init_ext = apply_init_plus_ext::<AB>(h, &ark);
    let gate_init_ext = perm_gate.clone() * is_init_ext;
    for i in 0..STATE_WIDTH {
        builder.assert_zero(
            gate_init_ext.clone() * (h_next[i].clone() - expected_init_ext[i].clone()),
        );
    }

    // -------------------------------------------------------------------------
    // 2. Single external round (rows 1-3, 12-14): h' = M_E(S(h + ark)) Gate degree: perm_gate(1) *
    //    is_ext(1) = 2 Constraint degree: gate(2) * sbox(7) = 9
    // -------------------------------------------------------------------------
    let ext_with_rc: [AB::Expr; STATE_WIDTH] =
        core::array::from_fn(|i| h[i].clone() + ark[i].clone());
    let ext_with_sbox: [AB::Expr; STATE_WIDTH] =
        core::array::from_fn(|i| ext_with_rc[i].clone().exp_const_u64::<7>());
    let expected_ext = apply_matmul_external::<AB>(&ext_with_sbox);

    let gate_ext = perm_gate.clone() * is_ext;
    for i in 0..STATE_WIDTH {
        builder.assert_zero(gate_ext.clone() * (h_next[i].clone() - expected_ext[i].clone()));
    }

    // -------------------------------------------------------------------------
    // 3. Packed 3x internal (rows 4-10): witness checks + affine next-state Gate degree:
    //    perm_gate(1) * is_packed_int(1) = 2 Witness constraint degree: gate(2) * sbox(7) = 9
    //    Next-state constraint degree: gate(2) * affine(1) = 3
    // -------------------------------------------------------------------------
    // ark[0..2] hold the 3 internal round constants on packed-int rows
    let ark_int_3: [AB::Expr; 3] = core::array::from_fn(|i| ark[i].clone());
    let (expected_packed, witness_checks) = apply_packed_internals::<AB>(h, w, &ark_int_3);

    let gate_packed = perm_gate.clone() * is_packed_int;
    // 3 witness constraints
    for wc in &witness_checks {
        builder.assert_zero(gate_packed.clone() * wc.clone());
    }
    // 12 next-state constraints
    for i in 0..STATE_WIDTH {
        builder.assert_zero(gate_packed.clone() * (h_next[i].clone() - expected_packed[i].clone()));
    }

    // -------------------------------------------------------------------------
    // 4. Int+ext merged (row 11): 1 internal (ARK_INT[21] hardcoded) + 1 external Gate degree:
    //    perm_gate(1) * is_int_ext(1) = 2 Witness constraint degree: gate(2) * sbox(7) = 9
    //    Next-state constraint degree: gate(2) * sbox(7) = 9
    // -------------------------------------------------------------------------
    let (expected_int_ext, witness_check) =
        apply_internal_plus_ext::<AB>(h, &w[0], Hasher::ARK_INT[21], &ark);

    let gate_int_ext = perm_gate * is_int_ext;
    // 1 witness constraint
    builder.assert_zero(gate_int_ext.clone() * witness_check);
    // 12 next-state constraints
    for i in 0..STATE_WIDTH {
        builder
            .assert_zero(gate_int_ext.clone() * (h_next[i].clone() - expected_int_ext[i].clone()));
    }
}

/// Enforces that the sponge capacity is unchanged across batch boundaries.
///
/// During multi-batch linear hashing (RESPAN), each new batch overwrites the rate
/// (h0..h7) but the capacity (h8..h11) must carry over from the previous permutation
/// output. Without this constraint, a prover could inject arbitrary capacity values on
/// continuation rows, corrupting the sponge state.
///
/// The `gate` is constructed by the caller to fire only when the next row is a sponge
/// continuation input (see `enforce_respan_capacity` in mod.rs for details).
pub fn enforce_respan_capacity_preservation<AB>(
    builder: &mut AB,
    gate: AB::Expr,
    h_cap: &[AB::Expr; 4],
    h_cap_next: &[AB::Expr; 4],
) where
    AB: MidenAirBuilder,
{
    for i in 0..4 {
        builder.assert_zero(gate.clone() * (h_cap_next[i].clone() - h_cap[i].clone()));
    }
}

// =============================================================================
// LINEAR ALGEBRA HELPERS
// =============================================================================

/// Applies the external linear layer M_E to the state.
///
/// The external layer consists of:
/// 1. Apply M4 to each 4-element block
/// 2. Add cross-block sums to each element
fn apply_matmul_external<AB: LiftedAirBuilder<F = Felt>>(
    state: &[AB::Expr; STATE_WIDTH],
) -> [AB::Expr; STATE_WIDTH] {
    // Apply M4 to each 4-element block
    let b0 = matmul_m4::<AB>(&core::array::from_fn(|i| state[i].clone()));
    let b1 = matmul_m4::<AB>(&core::array::from_fn(|i| state[4 + i].clone()));
    let b2 = matmul_m4::<AB>(&core::array::from_fn(|i| state[8 + i].clone()));

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

/// Applies the 4x4 matrix M4 used in Poseidon2's external linear layer.
fn matmul_m4<AB: LiftedAirBuilder<F = Felt>>(input: &[AB::Expr; 4]) -> [AB::Expr; 4] {
    let [a, b, c, d] = input.clone();

    let t0 = a.clone() + b.clone();
    let t1 = c.clone() + d.clone();
    let t2 = b.double() + t1.clone(); // 2b + t1
    let t3 = d.double() + t0.clone(); // 2d + t0
    let t4 = t1.double().double() + t3.clone(); // 4*t1 + t3
    let t5 = t0.double().double() + t2.clone(); // 4*t0 + t2

    let out0 = t3.clone() + t5.clone();
    let out1 = t5;
    let out2 = t2 + t4.clone();
    let out3 = t4;

    [out0, out1, out2, out3]
}

/// Applies the internal linear layer M_I to the state.
///
/// M_I = I + diag(MAT_DIAG) where all rows share the same sum.
fn apply_matmul_internal<AB: LiftedAirBuilder<F = Felt>>(
    state: &[AB::Expr; STATE_WIDTH],
) -> [AB::Expr; STATE_WIDTH] {
    // Sum of all state elements
    let sum: AB::Expr = state.iter().cloned().reduce(|a, b| a + b).expect("STATE_WIDTH > 0");

    // result[i] = state[i] * MAT_DIAG[i] + sum
    core::array::from_fn(|i| state[i].clone() * AB::Expr::from(Hasher::MAT_DIAG[i]) + sum.clone())
}

// =============================================================================
// PACKED ROUND HELPERS
// =============================================================================

/// Computes the expected next state for the merged init linear + first external round.
///
/// h' = M_E(S(M_E(h) + ark_ext))
///
/// The init step applies M_E to the input, then the first external round adds round
/// constants, applies the full S-box, and applies M_E again. This is a single S-box
/// layer over affine expressions, so the constraint degree is 7.
pub fn apply_init_plus_ext<AB: LiftedAirBuilder<F = Felt>>(
    h: &[AB::Expr; STATE_WIDTH],
    ark_ext: &[AB::Expr; STATE_WIDTH],
) -> [AB::Expr; STATE_WIDTH] {
    // Apply M_E to get the pre-round state
    let pre = apply_matmul_external::<AB>(h);

    // Add round constants, apply S-box, apply M_E
    let with_rc: [AB::Expr; STATE_WIDTH] =
        core::array::from_fn(|i| pre[i].clone() + ark_ext[i].clone());
    let with_sbox: [AB::Expr; STATE_WIDTH] =
        core::array::from_fn(|i| with_rc[i].clone().exp_const_u64::<7>());
    apply_matmul_external::<AB>(&with_sbox)
}

/// Computes the expected next state and witness checks for 3 packed internal rounds.
///
/// Each internal round applies: add RC to lane 0, S-box lane 0, then M_I.
/// The S-box output for each round is provided as an explicit witness (w0, w1, w2),
/// which keeps the intermediate states affine and the constraint degree at 7.
///
/// Returns:
/// - `next_state`: expected state after all 3 rounds (affine in trace columns, degree 1)
/// - `witness_checks`: 3 expressions that must be zero (each degree 7): `wk - (y(k)_0 +
///   ark_int[k])^7`
pub fn apply_packed_internals<AB: LiftedAirBuilder<F = Felt>>(
    h: &[AB::Expr; STATE_WIDTH],
    w: &[AB::Expr; 3],
    ark_int: &[AB::Expr; 3],
) -> ([AB::Expr; STATE_WIDTH], [AB::Expr; 3]) {
    let mut state = h.clone();
    let mut witness_checks: [AB::Expr; 3] = core::array::from_fn(|_| AB::Expr::ZERO);

    for k in 0..3 {
        // Witness check: wk = (state[0] + ark_int[k])^7
        let sbox_input = state[0].clone() + ark_int[k].clone();
        witness_checks[k] = w[k].clone() - sbox_input.exp_const_u64::<7>();

        // Substitute witness for lane 0 and apply M_I
        state[0] = w[k].clone();
        state = apply_matmul_internal::<AB>(&state);
    }

    (state, witness_checks)
}

/// Computes the expected next state and witness check for one internal round followed
/// by one external round.
///
/// Used for the int22+ext5 merged row (row 11). The internal round constant ARK_INT[21]
/// is passed as a concrete Felt rather than read from a periodic column. This is valid
/// because row 11 is the only row gated by `is_int_ext` -- no other row needs a different
/// value under the same gate. A periodic column would waste 15 zero entries to deliver
/// one value.
///
/// Returns:
/// - `next_state`: expected state after int + ext (degree 7 in trace columns)
/// - `witness_check`: `w0 - (h[0] + ark_int_const)^7` (degree 7)
pub fn apply_internal_plus_ext<AB: LiftedAirBuilder<F = Felt>>(
    h: &[AB::Expr; STATE_WIDTH],
    w0: &AB::Expr,
    ark_int_const: Felt,
    ark_ext: &[AB::Expr; STATE_WIDTH],
) -> ([AB::Expr; STATE_WIDTH], AB::Expr) {
    // Internal round: witness check and state update
    let sbox_input = h[0].clone() + AB::Expr::from(ark_int_const);
    let witness_check = w0.clone() - sbox_input.exp_const_u64::<7>();

    let mut int_state = h.clone();
    int_state[0] = w0.clone();
    let intermediate = apply_matmul_internal::<AB>(&int_state);

    // External round: add RC, S-box all lanes, M_E
    let with_rc: [AB::Expr; STATE_WIDTH] =
        core::array::from_fn(|i| intermediate[i].clone() + ark_ext[i].clone());
    let with_sbox: [AB::Expr; STATE_WIDTH] =
        core::array::from_fn(|i| with_rc[i].clone().exp_const_u64::<7>());
    let next_state = apply_matmul_external::<AB>(&with_sbox);

    (next_state, witness_check)
}
