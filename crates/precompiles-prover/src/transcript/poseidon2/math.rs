//! Poseidon2 algebra over `PrimeCharacteristicRing`-bound expressions.
//!
//! Pure functions: external/internal matmul and the three packed
//! round-shape helpers (`init+ext1`, `packed 3× internal`, `int22+ext5`).
//! All work for both concrete `Felt` (prover-side trace generation) and
//! symbolic expressions (verifier-side AIR constraints).
//!
//! Constants and step semantics ported from
//! `miden_core::chiplets::hasher::Hasher` (re-export of
//! `miden_crypto::Poseidon2`). The packed-round helpers ported from
//! `miden_vm`'s `air/src/constraints/chiplets/permutation/state.rs`
//! at commit `3176d1f`.

use alloc::vec::Vec;
use core::array;

use miden_core::field::PrimeCharacteristicRing;

/// Poseidon2 sponge state width (12 felts).
pub const STATE_WIDTH: usize = 12;

/// Count of S-boxes evaluated on the busiest cycle row (row 11, the
/// `int22 + ext5` step: one internal S-box over lane 0 plus the 12
/// external S-boxes). Sets the cube-register column count.
pub const MAX_SBOXES_PER_ROW: usize = STATE_WIDTH + 1;

/// Number of cube-register columns reserved in the main trace
/// (one per S-box on the busiest row).
pub const NUM_CUBE_REGS: usize = MAX_SBOXES_PER_ROW;

/// Evaluate one S-box `x^7` via its committed cube register.
///
/// Returns `c^2 · x` (deg 3 in the witness) as the output and `c − x^3`
/// (deg 3) as the consistency check that pins `c = x^3`.
fn sbox<E: PrimeCharacteristicRing>(x: E, reg: &E) -> (E, E) {
    (reg.clone().square() * x.clone(), reg.clone() - x.cube())
}

/// Computes the expected next state and cube-register checks for a
/// single external round: `h' = M_E(S(h + ark))`.
///
/// One S-box layer over the affine `(h + ark)`, with one cube register
/// per lane (`cube_regs[0..12]`): constraint degree 3, plus 12 degree-3
/// `reg − x^3` checks.
///
/// Returns the next state and the per-lane cube checks.
pub fn apply_single_ext<E: PrimeCharacteristicRing>(
    h: &[E; STATE_WIDTH],
    ark: &[E; STATE_WIDTH],
    cube_regs: &[E],
) -> ([E; STATE_WIDTH], Vec<E>) {
    let with_rc: [E; STATE_WIDTH] = array::from_fn(|i| h[i].clone() + ark[i].clone());
    let mut checks = Vec::new();
    let with_sbox: [E; STATE_WIDTH] = array::from_fn(|i| {
        let (out, check) = sbox(with_rc[i].clone(), &cube_regs[i]);
        checks.push(check);
        out
    });
    (apply_matmul_external(&with_sbox), checks)
}

/// Computes the expected next state and cube-register checks for the
/// merged init linear + first external round: `h' = M_E(S(M_E(h) +
/// ark_ext))`.
///
/// Applies `M_E` to the input, adds round constants, applies the S-box
/// lane-wise, then applies `M_E` again. Single S-box layer over affine
/// expressions: constraint degree 3 with one register per lane
/// (`cube_regs[0..12]`) plus 12 degree-3 checks.
pub fn apply_init_plus_ext<E: PrimeCharacteristicRing>(
    h: &[E; STATE_WIDTH],
    ark_ext: &[E; STATE_WIDTH],
    cube_regs: &[E],
) -> ([E; STATE_WIDTH], Vec<E>) {
    let pre = apply_matmul_external(h);
    let with_rc: [E; STATE_WIDTH] = array::from_fn(|i| pre[i].clone() + ark_ext[i].clone());
    let mut checks = Vec::new();
    let with_sbox: [E; STATE_WIDTH] = array::from_fn(|i| {
        let (out, check) = sbox(with_rc[i].clone(), &cube_regs[i]);
        checks.push(check);
        out
    });
    (apply_matmul_external(&with_sbox), checks)
}

/// Computes the expected next state and witness checks for 3 packed
/// internal rounds.
///
/// Each internal round applies: add RC to lane 0, S-box lane 0, then
/// `M_I`. The S-box output for each round is provided as an explicit
/// witness (`w0`, `w1`, `w2`), keeping the intermediate states affine.
///
/// Returns:
/// - `next_state`: state after all 3 rounds, affine (deg 1) in the trace columns.
/// - `witness_checks`: three S-box-output expressions that must each be zero — `w_k − reg_k^2 ·
///   (…)` (deg 3), one register per round.
/// - `cube_checks`: the `reg_k − x_k^3` expressions (deg 3).
pub fn apply_packed_internals<E: PrimeCharacteristicRing>(
    h: &[E; STATE_WIDTH],
    w: &[E; 3],
    ark_int: &[E; 3],
    mat_diag: &[E; STATE_WIDTH],
    cube_regs: &[E],
) -> ([E; STATE_WIDTH], [E; 3], Vec<E>) {
    let mut state = h.clone();
    let mut witness_checks: [E; 3] = array::from_fn(|_| E::ZERO);
    let mut cube_checks = Vec::new();

    for k in 0..3 {
        let sbox_input = state[0].clone() + ark_int[k].clone();
        let (out, check) = sbox(sbox_input, &cube_regs[k]);
        witness_checks[k] = w[k].clone() - out;
        cube_checks.push(check);
        state[0] = w[k].clone();
        state = apply_matmul_internal(&state, mat_diag);
    }

    (state, witness_checks, cube_checks)
}

/// Computes the expected next state and witness check for one internal
/// round followed by one external round (the `int22 + ext5` merged step
/// on cycle row 11).
///
/// The internal round constant `ARK_INT[21]` is passed as a concrete
/// value rather than read from a periodic column — row 11 is the only
/// row gated by `is_int_ext`, and a periodic column would waste 15 zero
/// entries to deliver one value.
///
/// The cube registers are laid out as `cube_regs[0..12]` for the 12
/// external lanes and `cube_regs[12]` for the internal S-box, matching
/// the busiest-row register budget.
///
/// Returns:
/// - `next_state`: state after int + ext, deg 3 in the trace columns.
/// - `witness_check`: the internal S-box-output check `w0 − reg^2 · (…)` (deg 3).
/// - `cube_checks`: the `reg − x^3` checks for the internal and external S-boxes (deg 3).
pub fn apply_internal_plus_ext<E: PrimeCharacteristicRing>(
    h: &[E; STATE_WIDTH],
    w0: &E,
    ark_int_const: E,
    ark_ext: &[E; STATE_WIDTH],
    mat_diag: &[E; STATE_WIDTH],
    cube_regs: &[E],
) -> ([E; STATE_WIDTH], E, Vec<E>) {
    let mut cube_checks = Vec::new();

    let sbox_input = h[0].clone() + ark_int_const;
    let (int_out, int_check) = sbox(sbox_input, &cube_regs[STATE_WIDTH]);
    let witness_check = w0.clone() - int_out;
    cube_checks.push(int_check);

    let mut int_state = h.clone();
    int_state[0] = w0.clone();
    let intermediate = apply_matmul_internal(&int_state, mat_diag);

    let with_rc: [E; STATE_WIDTH] =
        array::from_fn(|i| intermediate[i].clone() + ark_ext[i].clone());
    let with_sbox: [E; STATE_WIDTH] = array::from_fn(|i| {
        let (out, check) = sbox(with_rc[i].clone(), &cube_regs[i]);
        cube_checks.push(check);
        out
    });
    let next_state = apply_matmul_external(&with_sbox);

    (next_state, witness_check, cube_checks)
}

/// Applies the external linear layer `M_E` to the state.
///
/// `M_E = circ(2·M4, M4, M4)` viewed as three 4-element blocks: apply
/// the same 4×4 matrix `M4` to each block, then add the cross-block
/// column sums to every element.
pub fn apply_matmul_external<E: PrimeCharacteristicRing>(
    state: &[E; STATE_WIDTH],
) -> [E; STATE_WIDTH] {
    let b0 = matmul_m4(array::from_fn(|i| state[i].clone()));
    let b1 = matmul_m4(array::from_fn(|i| state[4 + i].clone()));
    let b2 = matmul_m4(array::from_fn(|i| state[8 + i].clone()));

    let sums: [E; 4] = array::from_fn(|j| b0[j].clone() + b1[j].clone() + b2[j].clone());

    array::from_fn(|i| {
        let block = i / 4;
        let lane = i % 4;
        let b = match block {
            0 => &b0,
            1 => &b1,
            _ => &b2,
        };
        b[lane].clone() + sums[lane].clone()
    })
}

/// Applies the 4×4 matrix `M4` used in Poseidon2's external linear
/// layer.
pub fn matmul_m4<E: PrimeCharacteristicRing>(input: [E; 4]) -> [E; 4] {
    let [a, b, c, d] = input;

    let t01 = a.clone() + b.clone();
    let t23 = c.clone() + d.clone();
    let t0123 = t01.clone() + t23.clone();
    let t01123 = t0123.clone() + b;
    let t01233 = t0123 + d;

    let out0 = t01123.clone() + t01;
    let out1 = t01123 + c.double();
    let out2 = t01233.clone() + t23;
    let out3 = t01233 + a.double();

    [out0, out1, out2, out3]
}

/// Applies the internal linear layer `M_I = I + diag(mat_diag)` to the
/// state.
///
/// All rows of `M_I` share the same column sum, so the result simplifies
/// to `state[i] · mat_diag[i] + Σ state`.
pub fn apply_matmul_internal<E: PrimeCharacteristicRing>(
    state: &[E; STATE_WIDTH],
    mat_diag: &[E; STATE_WIDTH],
) -> [E; STATE_WIDTH] {
    let sum = E::sum_array::<STATE_WIDTH>(state);
    array::from_fn(|i| state[i].clone() * mat_diag[i].clone() + sum.clone())
}
