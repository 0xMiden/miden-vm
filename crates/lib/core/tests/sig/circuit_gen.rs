//! Standalone ACE circuit generator for the RPO signature AIR.
//!
//! Produces a flat circuit (constants + operations) that can be loaded by the
//! `eval_circuit` chiplet instruction. This avoids the ace-codegen dependency
//! and its Miden VM-specific conventions (mandatory aux trace, barycentric
//! quotient reconstruction).
//!
//! # Circuit equation
//!
//! ```text
//! root = acc - Q_recon * vanishing = 0
//! ```
//!
//! where:
//! - acc: Horner-folded constraints with selectors (descending alpha powers)
//! - Q_recon: power-sum quotient reconstruction from flattened base-field coords
//! - vanishing = z^N - 1
//!
//! # Input layout (56 EF slots = 112 base felts = 28 words)
//!
//! ```text
//! Slots 0-3:    pk[0..3]         (base field as EF)
//! Slots 4-11:   witness_z[0..7]  (EF)
//! Slots 12-19:  witness_gz[0..7] (EF)
//! Slots 20-49:  quotient_z_coords[0..29] (base field as EF, 15 chunks * 2)
//! Slots 50:     alpha            (EF)
//! Slots 51:     z^N              (EF)
//! Slots 52:     z_k = z          (EF)
//! Slots 53:     is_first         (EF)
//! Slots 54:     is_last          (EF)
//! Slots 55:     is_transition    (EF)
//! ```

use alloc::vec::Vec;

use miden_core::{
    Felt,
    field::{Field, QuadFelt, TwoAdicField},
};
use miden_signature::e2_105_w8 as e2_105;

use crate::sig::{
    instance_seed_goldilocks, message_to_goldilocks, seed_from_label, sign_sig_w8, test_message,
    verify_sig_w8,
};

/// Input slot indices (EF slots).
pub const PK_START: usize = 0;
pub const WZ_START: usize = 4;
pub const WGZ_START: usize = 12;
pub const QZ_COORDS_START: usize = 20;
pub const ALPHA_SLOT: usize = 50;
pub const ZPN_SLOT: usize = 51;
pub const ZK_SLOT: usize = 52;
pub const IS_FIRST_SLOT: usize = 53;
pub const IS_LAST_SLOT: usize = 54;
pub const IS_TRANS_SLOT: usize = 55;
pub const NUM_INPUTS: usize = 56;

const NUM_QUOTIENT_CHUNKS: usize = 15;
const SEGMENT_LEN: usize = 55;
const STATE_WIDTH: usize = 8;

/// Gate operations.
const OP_SUB: u64 = 0;
const OP_MUL: u64 = 1;
const OP_ADD: u64 = 2;

/// Encode a gate: id_l + id_r * 2^30 + op * 2^60
fn encode_gate(id_l: usize, id_r: usize, op: u64) -> u64 {
    (id_l as u64) + ((id_r as u64) << 30) + (op << 60)
}

/// Build the ACE circuit for the RPO signature AIR.
///
/// Returns `(constants, operations, num_vars)` where:
/// - constants: EF values embedded in the circuit
/// - operations: packed gate encodings
/// - num_vars: total wire count (inputs + constants), must be even
///
/// The circuit can be evaluated by `eval_circuit` after writing inputs to
/// memory at the READ section pointer, followed by constants and operations.
/// Circuit builder with wire allocation tracking.
struct CircuitBuilder {
    constants: Vec<QuadFelt>,
    ops: Vec<u64>,
    next_wire: usize,
}

impl CircuitBuilder {
    fn new() -> Self {
        Self {
            constants: Vec::new(),
            ops: Vec::new(),
            next_wire: NUM_INPUTS,
        }
    }

    fn add_const(&mut self, val: QuadFelt) -> usize {
        let id = self.next_wire;
        self.constants.push(val);
        self.next_wire += 1;
        id
    }

    fn add(&mut self, id_l: usize, id_r: usize) -> usize {
        let id = self.next_wire;
        self.ops.push(encode_gate(id_l, id_r, OP_ADD));
        self.next_wire += 1;
        id
    }

    fn sub(&mut self, id_l: usize, id_r: usize) -> usize {
        let id = self.next_wire;
        self.ops.push(encode_gate(id_l, id_r, OP_SUB));
        self.next_wire += 1;
        id
    }

    fn mul(&mut self, id_l: usize, id_r: usize) -> usize {
        let id = self.next_wire;
        self.ops.push(encode_gate(id_l, id_r, OP_MUL));
        self.next_wire += 1;
        id
    }

    /// Compute x^exp via repeated squaring.
    fn pow(&mut self, base: usize, exp: usize) -> usize {
        assert!(exp > 0);
        let bits = usize::BITS - exp.leading_zeros();
        let mut result = base;
        for i in (0..bits - 1).rev() {
            result = self.mul(result, result);
            if (exp >> i) & 1 == 1 {
                result = self.mul(result, base);
            }
        }
        result
    }
}

pub fn build_sig_circuit() -> (Vec<QuadFelt>, Vec<u64>, usize) {
    let mut b = CircuitBuilder::new();

    // ── Phase 0: Constants ──
    // MDS matrix entries (12x12 = 144 constants, but we'll add as needed)
    // Round constant coefficients (24 columns × 8 coefficients = 192 constants)
    // EF basis element beta for quotient reconstruction

    // Add MDS constants (as base-field-in-EF)
    let mds = miden_signature::internal::rpo8::MDS_U64;
    let mut mds_const = [[0usize; STATE_WIDTH]; STATE_WIDTH];
    for r in 0..STATE_WIDTH {
        for c in 0..STATE_WIDTH {
            mds_const[r][c] = b.add_const(QuadFelt::from(Felt::new(mds[r][c])));
        }
    }

    // Add round constant polynomial coefficients.
    // Compute IDFT of periodic columns to get coefficients, then embed as constants.
    let (ark1_coeffs, ark2_coeffs) = compute_round_constant_coefficients();
    let mut ark1_const = [[0usize; 8]; STATE_WIDTH]; // [column][coeff_idx]
    let mut ark2_const = [[0usize; 8]; STATE_WIDTH];
    for j in 0..STATE_WIDTH {
        for k in 0..8 {
            ark1_const[j][k] = b.add_const(ark1_coeffs[j][k]);
            ark2_const[j][k] = b.add_const(ark2_coeffs[j][k]);
        }
    }

    // EF basis element: beta such that EF = F[x]/(x^2 - beta_irr)
    // For Goldilocks quadratic extension: the second basis element is QuadFelt::new([0, 1])
    let beta_basis = b.add_const(QuadFelt::new([Felt::ZERO, Felt::ONE]));

    // One and zero constants
    let one = b.add_const(QuadFelt::new([Felt::ONE, Felt::ZERO]));
    let zero = b.add_const(QuadFelt::new([Felt::ZERO, Felt::ZERO]));

    // `num_vars = num_inputs + num_constants` must be even for eval_circuit.
    // This padding constant must be added before we start emitting gates;
    // adding it later would shift all gate output wire IDs.
    if !(NUM_INPUTS + b.constants.len()).is_multiple_of(2) {
        b.add_const(QuadFelt::new([Felt::ZERO, Felt::ZERO]));
    }

    // ── Phase 1: Evaluate periodic columns at z_k ──
    // For each column: Horner(z_k, coeffs) = coeffs[7] + z_k*(coeffs[6] + z_k*(...))
    let z_k = ZK_SLOT;
    let mut ark1_at_z = [0usize; STATE_WIDTH];
    let mut ark2_at_z = [0usize; STATE_WIDTH];
    for j in 0..STATE_WIDTH {
        // Horner for ark1[j]
        let mut acc = ark1_const[j][7];
        for k in (0..7).rev() {
            acc = b.mul(acc, z_k);
            acc = b.add(acc, ark1_const[j][k]);
        }
        ark1_at_z[j] = acc;

        // Horner for ark2[j]
        let mut acc = ark2_const[j][7];
        for k in (0..7).rev() {
            acc = b.mul(acc, z_k);
            acc = b.add(acc, ark2_const[j][k]);
        }
        ark2_at_z[j] = acc;
    }

    // ── Phase 2: Transition constraints ──
    // t = MDS(witness_z), u = t + ark1, v = sbox(u), w = MDS(v), rhs = w + ark2
    // constraint[j] = witness_gz[j]^7 - rhs[j]

    // Step 1: t = MDS(witness_z)
    let mut t = [0usize; STATE_WIDTH];
    for j in 0..STATE_WIDTH {
        // t[j] = sum_k MDS[j][k] * witness_z[k]
        let first = b.mul(mds_const[j][0], WZ_START);
        let mut acc = first;
        for (k, &coeff) in mds_const[j].iter().enumerate().skip(1) {
            let term = b.mul(coeff, WZ_START + k);
            acc = b.add(acc, term);
        }
        t[j] = acc;
    }

    // Step 2: u = t + ark1_at_z
    let mut u = [0usize; STATE_WIDTH];
    for j in 0..STATE_WIDTH {
        u[j] = b.add(t[j], ark1_at_z[j]);
    }

    // Step 3: v = sbox(u) = u^7 = u^4 * u^2 * u
    let mut v = [0usize; STATE_WIDTH];
    for j in 0..STATE_WIDTH {
        let u2 = b.mul(u[j], u[j]);
        let u4 = b.mul(u2, u2);
        let u3 = b.mul(u2, u[j]);
        v[j] = b.mul(u4, u3);
    }

    // Step 4: w = MDS(v)
    let mut w = [0usize; STATE_WIDTH];
    for j in 0..STATE_WIDTH {
        let first = b.mul(mds_const[j][0], v[0]);
        let mut acc = first;
        for k in 1..STATE_WIDTH {
            let term = b.mul(mds_const[j][k], v[k]);
            acc = b.add(acc, term);
        }
        w[j] = acc;
    }

    // Step 5: rhs = w + ark2_at_z
    let mut rhs = [0usize; STATE_WIDTH];
    for j in 0..STATE_WIDTH {
        rhs[j] = b.add(w[j], ark2_at_z[j]);
    }

    // Transition constraints: witness_gz[j]^7 - rhs[j]
    let mut trans_constraints = [0usize; STATE_WIDTH];
    for j in 0..STATE_WIDTH {
        let gz_j = WGZ_START + j;
        let gz2 = b.mul(gz_j, gz_j);
        let gz4 = b.mul(gz2, gz2);
        let gz3 = b.mul(gz2, gz_j);
        let gz7 = b.mul(gz4, gz3);
        trans_constraints[j] = b.sub(gz7, rhs[j]);
    }

    // ── Phase 3: Boundary constraints ──
    // boundary_first: rate1=0 (witness_z[4..8])
    let bf_indices = [4, 5, 6, 7]; // column indices
    let bf_constraints: Vec<usize> = bf_indices.iter().map(|&j| WZ_START + j).collect();

    // boundary_last: witness_z[0..4] - pk[0..4]
    let mut bl_constraints = [0usize; 4];
    for (j, slot) in bl_constraints.iter_mut().enumerate() {
        *slot = b.sub(WZ_START + j, PK_START + j);
    }

    // ── Phase 4: Apply selectors and Horner-fold ──
    let is_trans = IS_TRANS_SLOT;
    let is_first = IS_FIRST_SLOT;
    let is_last = IS_LAST_SLOT;
    let alpha = ALPHA_SLOT;

    // Start with transition[0]
    let mut acc = b.mul(is_trans, trans_constraints[0]);

    // Remaining transition constraints
    for &constraint in trans_constraints.iter().skip(1) {
        acc = b.mul(acc, alpha);
        let term = b.mul(is_trans, constraint);
        acc = b.add(acc, term);
    }

    // Boundary-first constraints
    for &constraint in &bf_constraints {
        acc = b.mul(acc, alpha);
        let term = b.mul(is_first, constraint);
        acc = b.add(acc, term);
    }

    // Boundary-last constraints
    for &constraint in &bl_constraints {
        acc = b.mul(acc, alpha);
        let term = b.mul(is_last, constraint);
        acc = b.add(acc, term);
    }

    // ── Phase 5: Quotient reconstruction (power-sum) ──
    // Reconstruct each chunk's EF value from 2 flattened base-field coords:
    //   chunk[j] = coord[2j] + coord[2j+1] * beta_basis
    let mut chunks = Vec::with_capacity(NUM_QUOTIENT_CHUNKS);
    for j in 0..NUM_QUOTIENT_CHUNKS {
        let c0 = QZ_COORDS_START + 2 * j;
        let c1 = QZ_COORDS_START + 2 * j + 1;
        let c1_beta = b.mul(c1, beta_basis);
        let chunk = b.add(c0, c1_beta);
        chunks.push(chunk);
    }

    // z_step = z_k^SEGMENT_LEN (via repeated squaring in the circuit)
    let z_step = b.pow(z_k, SEGMENT_LEN);

    // Horner: Q = chunks[k-1] + z_step*(chunks[k-2] + z_step*(...))
    let mut q_acc = chunks[NUM_QUOTIENT_CHUNKS - 1];
    for j in (0..NUM_QUOTIENT_CHUNKS - 1).rev() {
        q_acc = b.mul(q_acc, z_step);
        q_acc = b.add(q_acc, chunks[j]);
    }

    // ── Phase 6: Root check ──
    // vanishing = z^N - 1
    let zpn = ZPN_SLOT;
    let vanishing = b.sub(zpn, one);

    // Q * vanishing
    let q_times_v = b.mul(q_acc, vanishing);

    // root = acc - Q * vanishing (must be zero)
    let _root = b.sub(acc, q_times_v);

    // ── Pad for alignment ──
    // num_eval must be multiple of 4
    while !b.ops.len().is_multiple_of(4) {
        b.ops.push(encode_gate(zero, zero, OP_SUB));
    }

    let num_vars = NUM_INPUTS + b.constants.len();
    (b.constants, b.ops, num_vars)
}

/// Compute x^exp in the circuit via repeated squaring.
#[allow(dead_code)]
fn pow_circuit(ops: &mut Vec<u64>, next_wire: &mut usize, base: usize, exp: usize) -> usize {
    if exp == 0 {
        panic!("pow_circuit: exp must be > 0");
    }
    let mut add_op = |ops: &mut Vec<u64>, id_l: usize, id_r: usize, op: u64| -> usize {
        let id = *next_wire;
        ops.push(encode_gate(id_l, id_r, op));
        *next_wire += 1;
        id
    };

    let bits = usize::BITS - exp.leading_zeros();
    let mut result = base;
    for i in (0..bits - 1).rev() {
        result = add_op(ops, result, result, OP_MUL);
        if (exp >> i) & 1 == 1 {
            result = add_op(ops, result, base, OP_MUL);
        }
    }
    result
}

/// Compute IDFT of round constant periodic columns to get coefficient form.
/// Returns (ark1_coeffs, ark2_coeffs) where each is [column][coeff_idx] as QuadFelt.
fn compute_round_constant_coefficients()
-> ([[QuadFelt; 8]; STATE_WIDTH], [[QuadFelt; 8]; STATE_WIDTH]) {
    use miden_signature::internal::rpo8::{ARK1_U64, ARK2_U64, NUM_ROUNDS};

    let omega = Felt::two_adic_generator(3); // trace_gen = omega_8
    let n_inv = Felt::new(8).inverse();
    let omega_inv = omega.inverse();

    let mut ark1_coeffs = [[QuadFelt::new([Felt::ZERO, Felt::ZERO]); 8]; STATE_WIDTH];
    let mut ark2_coeffs = [[QuadFelt::new([Felt::ZERO, Felt::ZERO]); 8]; STATE_WIDTH];

    for col in 0..STATE_WIDTH {
        // Build evaluation values for this column (8 rows)
        let mut vals1 = [Felt::ZERO; 8];
        let mut vals2 = [Felt::ZERO; 8];
        for r in 0..NUM_ROUNDS {
            vals1[r] = Felt::new(ARK1_U64[r][col]);
            vals2[r] = Felt::new(ARK2_U64[r][col]);
        }
        // Row 7 stays zero (no transition from last row)

        // IDFT: coeffs[k] = (1/N) * sum_j vals[j] * omega^{-jk}
        for k in 0..8 {
            let mut sum1 = QuadFelt::new([Felt::ZERO, Felt::ZERO]);
            let mut sum2 = QuadFelt::new([Felt::ZERO, Felt::ZERO]);
            for j in 0..8 {
                // omega_inv^(j*k)
                let power = omega_inv.exp_u64((j * k) as u64);
                sum1 += QuadFelt::from(vals1[j]) * QuadFelt::from(power);
                sum2 += QuadFelt::from(vals2[j]) * QuadFelt::from(power);
            }
            ark1_coeffs[col][k] = sum1 * QuadFelt::from(n_inv);
            ark2_coeffs[col][k] = sum2 * QuadFelt::from(n_inv);
        }
    }

    (ark1_coeffs, ark2_coeffs)
}

/// Evaluate the circuit on the given inputs (for testing).
/// Returns the value of the last gate (the root).
pub fn eval_circuit(inputs: &[QuadFelt], constants: &[QuadFelt], operations: &[u64]) -> QuadFelt {
    let num_vars = inputs.len() + constants.len();
    let mut wires = Vec::with_capacity(num_vars + operations.len());

    // Inputs
    wires.extend_from_slice(inputs);
    // Constants
    wires.extend_from_slice(constants);

    // Evaluate gates
    for &encoded in operations {
        let id_l = (encoded & ((1 << 30) - 1)) as usize;
        let id_r = ((encoded >> 30) & ((1 << 30) - 1)) as usize;
        let op = encoded >> 60;
        let result = match op {
            0 => wires[id_l] - wires[id_r], // SUB
            1 => wires[id_l] * wires[id_r], // MUL
            2 => wires[id_l] + wires[id_r], // ADD
            _ => panic!("invalid op"),
        };
        wires.push(result);
    }

    // Root = last wire
    *wires.last().unwrap()
}

/// Encode the circuit for eval_circuit consumption.
///
/// The chiplet uses REVERSED wire IDs: input[0] gets the HIGHEST ID, and the
/// last operation gets the lowest. This function remaps the ascending IDs from
/// build_sig_circuit to the descending convention.
///
/// Output: constants as EF pairs (2 base felts each), then remapped operations
/// (1 base felt each), padded to multiple of 8 for adv_pipe.
pub fn encode_for_eval_circuit(
    constants: &[QuadFelt],
    operations: &[u64],
    num_inputs: usize,
) -> Vec<Felt> {
    let num_const_nodes = constants.len();
    let num_op_nodes = operations.len();
    // Padding operations (added by build_sig_circuit) are already in operations.
    // Total nodes for ID mapping:
    let num_nodes = num_inputs + num_const_nodes + num_op_nodes;

    // ID remapping: ascending logical ID → descending chiplet ID
    // Logical: inputs 0..num_inputs, constants num_inputs..num_inputs+num_const, ops after that
    // Chiplet: input[0] = num_nodes-1, input[1] = num_nodes-2, ...
    //          constant[0] = num_nodes-1-num_inputs, ...
    //          operation[0] = num_nodes-1-num_inputs-num_const, ...
    let remap = |logical_id: usize| -> u64 { (num_nodes - 1 - logical_id) as u64 };

    let mut stream = Vec::new();

    // Constants: each QuadFelt as [coeff0, coeff1]
    for c in constants {
        let pair: [Felt; 2] = unsafe { core::mem::transmute(*c) };
        stream.push(pair[0]);
        stream.push(pair[1]);
    }

    // Operations: remap wire IDs
    for &encoded in operations {
        let id_l = (encoded & ((1 << 30) - 1)) as usize;
        let id_r = ((encoded >> 30) & ((1 << 30) - 1)) as usize;
        let op = encoded >> 60;
        let new_encoded = remap(id_l) + (remap(id_r) << 30) + (op << 60);
        stream.push(Felt::new(new_encoded));
    }

    // Pad to multiple of 8
    while stream.len() % 8 != 0 {
        stream.push(Felt::ZERO);
    }

    stream
}

/// Hash the encoded stream to get the circuit commitment.
pub fn circuit_hash(stream: &[Felt]) -> [Felt; 4] {
    use miden_utils_testing::crypto::Poseidon2;
    let digest = Poseidon2::hash_elements(stream);
    let w = digest;
    w.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g2f(g: miden_signature::Goldilocks) -> Felt {
        unsafe { core::mem::transmute(g) }
    }

    fn f2g(f: Felt) -> miden_signature::Goldilocks {
        unsafe { core::mem::transmute(f) }
    }

    fn manual_root_from_inputs(inputs: &[QuadFelt]) -> QuadFelt {
        let z_k = inputs[ZK_SLOT];
        let zpn = inputs[ZPN_SLOT];
        let alpha = inputs[ALPHA_SLOT];
        let is_first = inputs[IS_FIRST_SLOT];
        let is_last = inputs[IS_LAST_SLOT];
        let is_trans = inputs[IS_TRANS_SLOT];

        // Transition constraints.
        let mds = miden_signature::internal::rpo8::MDS_U64;
        let (ark1_coeffs, ark2_coeffs) = compute_round_constant_coefficients();
        let mut ark1_eval = [QuadFelt::new([Felt::ZERO, Felt::ZERO]); STATE_WIDTH];
        let mut ark2_eval = [QuadFelt::new([Felt::ZERO, Felt::ZERO]); STATE_WIDTH];
        for j in 0..STATE_WIDTH {
            let mut a1 = ark1_coeffs[j][7];
            let mut a2 = ark2_coeffs[j][7];
            for k in (0..7).rev() {
                a1 = a1 * z_k + ark1_coeffs[j][k];
                a2 = a2 * z_k + ark2_coeffs[j][k];
            }
            ark1_eval[j] = a1;
            ark2_eval[j] = a2;
        }

        let wz: [QuadFelt; STATE_WIDTH] = core::array::from_fn(|i| inputs[WZ_START + i]);
        let wgz: [QuadFelt; STATE_WIDTH] = core::array::from_fn(|i| inputs[WGZ_START + i]);

        let mut t = [QuadFelt::new([Felt::ZERO, Felt::ZERO]); STATE_WIDTH];
        for r in 0..STATE_WIDTH {
            let mut acc = QuadFelt::new([Felt::ZERO, Felt::ZERO]);
            for c in 0..STATE_WIDTH {
                acc += QuadFelt::from(Felt::new(mds[r][c])) * wz[c];
            }
            t[r] = acc;
        }

        let mut u = [QuadFelt::new([Felt::ZERO, Felt::ZERO]); STATE_WIDTH];
        for j in 0..STATE_WIDTH {
            u[j] = t[j] + ark1_eval[j];
        }

        let mut v = [QuadFelt::new([Felt::ZERO, Felt::ZERO]); STATE_WIDTH];
        for j in 0..STATE_WIDTH {
            let u2 = u[j] * u[j];
            let u4 = u2 * u2;
            let u3 = u2 * u[j];
            v[j] = u4 * u3;
        }

        let mut w = [QuadFelt::new([Felt::ZERO, Felt::ZERO]); STATE_WIDTH];
        for r in 0..STATE_WIDTH {
            let mut acc = QuadFelt::new([Felt::ZERO, Felt::ZERO]);
            for c in 0..STATE_WIDTH {
                acc += QuadFelt::from(Felt::new(mds[r][c])) * v[c];
            }
            w[r] = acc;
        }

        let mut rhs = [QuadFelt::new([Felt::ZERO, Felt::ZERO]); STATE_WIDTH];
        for j in 0..STATE_WIDTH {
            rhs[j] = w[j] + ark2_eval[j];
        }

        let mut trans = [QuadFelt::new([Felt::ZERO, Felt::ZERO]); STATE_WIDTH];
        for j in 0..STATE_WIDTH {
            let gz2 = wgz[j] * wgz[j];
            let gz4 = gz2 * gz2;
            let gz3 = gz2 * wgz[j];
            let gz7 = gz4 * gz3;
            trans[j] = gz7 - rhs[j];
        }

        let bf = [wz[4], wz[5], wz[6], wz[7]];
        let bl = [
            wz[0] - inputs[PK_START],
            wz[1] - inputs[PK_START + 1],
            wz[2] - inputs[PK_START + 2],
            wz[3] - inputs[PK_START + 3],
        ];

        let mut acc = is_trans * trans[0];
        for item in trans.iter().take(STATE_WIDTH).skip(1) {
            acc = acc * alpha + is_trans * *item;
        }
        for item in &bf {
            acc = acc * alpha + is_first * *item;
        }
        for item in &bl {
            acc = acc * alpha + is_last * *item;
        }

        let beta_basis = QuadFelt::new([Felt::ZERO, Felt::ONE]);
        let mut q = QuadFelt::new([Felt::ZERO, Felt::ZERO]);
        let z_step = (0..SEGMENT_LEN).fold(QuadFelt::new([Felt::ONE, Felt::ZERO]), |a, _| a * z_k);
        let mut pow = QuadFelt::new([Felt::ONE, Felt::ZERO]);
        for j in 0..NUM_QUOTIENT_CHUNKS {
            let c0 = inputs[QZ_COORDS_START + 2 * j];
            let c1 = inputs[QZ_COORDS_START + 2 * j + 1];
            let chunk = c0 + c1 * beta_basis;
            q += chunk * pow;
            pow *= z_step;
        }

        acc - q * (zpn - QuadFelt::new([Felt::ONE, Felt::ZERO]))
    }

    #[test]
    fn circuit_generates_successfully() {
        let (constants, ops, num_vars) = build_sig_circuit();
        eprintln!("Circuit generated:");
        eprintln!("  num_inputs: {}", NUM_INPUTS);
        eprintln!("  constants: {}", constants.len());
        eprintln!("  num_vars: {}", num_vars);
        eprintln!("  operations: {}", ops.len());
        assert_eq!(num_vars % 2, 0, "num_vars must be even");
        assert_eq!(ops.len() % 4, 0, "ops must be multiple of 4");

        // Validate all wire references
        for (i, &encoded) in ops.iter().enumerate() {
            let id_l = (encoded & ((1 << 30) - 1)) as usize;
            let id_r = ((encoded >> 30) & ((1 << 30) - 1)) as usize;
            let wire_id = num_vars + i; // this gate's output wire
            assert!(id_l < wire_id, "gate {i}: id_l={id_l} >= wire_id={wire_id}");
            assert!(id_r < wire_id, "gate {i}: id_r={id_r} >= wire_id={wire_id}");
        }
        eprintln!("  all wire references valid");

        let stream = encode_for_eval_circuit(&constants, &ops, NUM_INPUTS);
        eprintln!("  encoded stream: {} felts", stream.len());
        eprintln!("  adv_pipe iterations: {}", stream.len() / 8);

        let hash = circuit_hash(&stream);
        eprintln!("  circuit hash: {:?}", hash.map(|f| f.as_canonical_u64()));

        // Verify hash matches the MASM constants
        assert_eq!(hash[0].as_canonical_u64(), 14521773228882931622u64);
        assert_eq!(hash[1].as_canonical_u64(), 4859693225690906160u64);
        assert_eq!(hash[2].as_canonical_u64(), 10372398481619220715u64);
        assert_eq!(hash[3].as_canonical_u64(), 11760070894366005407u64);
    }

    #[test]
    fn circuit_evaluates_to_zero_on_valid_proof() {
        use miden_signature::{
            QuadExt,
            internal::{air8::Rpo8, serialize, signer::Config},
        };

        // Sign and deserialize
        let (sk, pk) = e2_105::keygen(seed_from_label(b"circuit-gen-test"));
        let message = test_message(2000);
        let signature = sign_sig_w8(&sk, message);
        assert!(verify_sig_w8(&pk, message, &signature).is_ok());

        let config = Config::e2_105bit();
        let stark = &config.stark;
        let pk_felts = *pk.elements();
        let proof = serialize::deserialize_and_reconstruct::<Rpo8, QuadExt>(
            &signature,
            stark,
            11,
            pk_felts,
            message_to_goldilocks(message),
            instance_seed_goldilocks(),
        )
        .expect("deserialization failed");

        // Replay transcript to get challenges
        let msg_felts = message_to_goldilocks(message);
        let seed = crate::sig::transcript::compute_instance_seed();

        fn g2f(g: miden_signature::Goldilocks) -> Felt {
            unsafe { core::mem::transmute(g) }
        }
        let pk_m: [Felt; 4] = core::array::from_fn(|i| g2f(pk_felts[i]));
        let msg_m: [Felt; 4] = core::array::from_fn(|i| g2f(msg_felts[i]));

        let mut t = crate::sig::transcript::SigTranscript::new(seed, pk_m, msg_m);
        let wc: &[miden_signature::Goldilocks; 4] = &proof.witness_commitment;
        t.reseed_direct(core::array::from_fn(|i| g2f(wc[i])));
        t.check_grind(proof.ali_nonce, stark.grinding.ali);
        let lambda = t.sample_ext();
        let qc: &[miden_signature::Goldilocks; 4] = &proof.quotient_commitment;
        t.reseed_direct(core::array::from_fn(|i| g2f(qc[i])));
        t.check_grind(proof.ood_nonce, stark.grinding.ood);
        let z = t.sample_ext();

        let lambda_qf = QuadFelt::new(lambda);
        let z_qf = QuadFelt::new(z);
        let z8_qf = (0..3).fold(z_qf, |acc, _| acc * acc);

        // Build inputs
        let (constants, ops, _num_vars) = build_sig_circuit();
        let mut inputs = vec![QuadFelt::new([Felt::ZERO, Felt::ZERO]); NUM_INPUTS];

        // pk
        for i in 0..4 {
            inputs[PK_START + i] = QuadFelt::from(pk_m[i]);
        }

        // witness_z (EF)
        for i in 0..8 {
            let ef: [Felt; 2] = unsafe { core::mem::transmute(proof.witness_z[i]) };
            inputs[WZ_START + i] = QuadFelt::new(ef);
        }
        // witness_gz (EF)
        for i in 0..8 {
            let ef: [Felt; 2] = unsafe { core::mem::transmute(proof.witness_gz[i]) };
            inputs[WGZ_START + i] = QuadFelt::new(ef);
        }

        // quotient_z coords (flattened base field, each as EF with zero second coord)
        for i in 0..30 {
            inputs[QZ_COORDS_START + i] = QuadFelt::from(g2f(proof.quotient_z[i]));
        }

        // STARK vars
        inputs[ALPHA_SLOT] = lambda_qf;
        inputs[ZPN_SLOT] = z8_qf;
        inputs[ZK_SLOT] = z_qf;

        // Selectors
        let van = z8_qf - QuadFelt::new([Felt::ONE, Felt::ZERO]);
        let omega7 = QuadFelt::from(Felt::two_adic_generator(3).inverse());
        let g_inv = omega7; // omega_8^7 = omega_8^{-1}
        let is_trans = z_qf - g_inv;
        let is_first = van / (z_qf - QuadFelt::new([Felt::ONE, Felt::ZERO]));
        let is_last = van / is_trans;

        inputs[IS_FIRST_SLOT] = is_first;
        inputs[IS_LAST_SLOT] = is_last;
        inputs[IS_TRANS_SLOT] = is_trans;

        // Evaluate
        let result = eval_circuit(&inputs, &constants, &ops);
        let manual = manual_root_from_inputs(&inputs);
        eprintln!("Manual root: {:?}", manual);
        eprintln!("Circuit result: {:?}", result);
        let zero = QuadFelt::new([Felt::ZERO, Felt::ZERO]);
        assert_eq!(manual, zero, "Manual formula should evaluate to zero on valid proof");
        assert_eq!(result, zero, "Circuit should evaluate to zero on valid proof");
    }

    #[test]
    fn circuit_detects_tampered_quotient_coord() {
        use miden_signature::{
            QuadExt,
            internal::{air8::Rpo8, serialize, signer::Config},
        };

        let (sk, pk) = e2_105::keygen(seed_from_label(b"circuit-gen-tamper-test"));
        let message = test_message(2001);
        let signature = sign_sig_w8(&sk, message);
        assert!(verify_sig_w8(&pk, message, &signature).is_ok());

        let config = Config::e2_105bit();
        let stark = &config.stark;
        let pk_felts = *pk.elements();
        let proof = serialize::deserialize_and_reconstruct::<Rpo8, QuadExt>(
            &signature,
            stark,
            11,
            pk_felts,
            message_to_goldilocks(message),
            instance_seed_goldilocks(),
        )
        .expect("deserialization failed");

        let msg_felts = message_to_goldilocks(message);
        let seed = crate::sig::transcript::compute_instance_seed();

        fn g2f(g: miden_signature::Goldilocks) -> Felt {
            unsafe { core::mem::transmute(g) }
        }
        let pk_m: [Felt; 4] = core::array::from_fn(|i| g2f(pk_felts[i]));
        let msg_m: [Felt; 4] = core::array::from_fn(|i| g2f(msg_felts[i]));

        let mut t = crate::sig::transcript::SigTranscript::new(seed, pk_m, msg_m);
        let wc: &[miden_signature::Goldilocks; 4] = &proof.witness_commitment;
        t.reseed_direct(core::array::from_fn(|i| g2f(wc[i])));
        t.check_grind(proof.ali_nonce, stark.grinding.ali);
        let lambda = t.sample_ext();
        let qc: &[miden_signature::Goldilocks; 4] = &proof.quotient_commitment;
        t.reseed_direct(core::array::from_fn(|i| g2f(qc[i])));
        t.check_grind(proof.ood_nonce, stark.grinding.ood);
        let z = t.sample_ext();

        let lambda_qf = QuadFelt::new(lambda);
        let z_qf = QuadFelt::new(z);
        let z8_qf = (0..3).fold(z_qf, |acc, _| acc * acc);

        let (constants, ops, _num_vars) = build_sig_circuit();
        let mut inputs = vec![QuadFelt::new([Felt::ZERO, Felt::ZERO]); NUM_INPUTS];

        for i in 0..4 {
            inputs[PK_START + i] = QuadFelt::from(pk_m[i]);
        }
        for i in 0..8 {
            let ef: [Felt; 2] = unsafe { core::mem::transmute(proof.witness_z[i]) };
            inputs[WZ_START + i] = QuadFelt::new(ef);
        }
        for i in 0..8 {
            let ef: [Felt; 2] = unsafe { core::mem::transmute(proof.witness_gz[i]) };
            inputs[WGZ_START + i] = QuadFelt::new(ef);
        }
        for i in 0..30 {
            inputs[QZ_COORDS_START + i] = QuadFelt::from(g2f(proof.quotient_z[i]));
        }

        inputs[ALPHA_SLOT] = lambda_qf;
        inputs[ZPN_SLOT] = z8_qf;
        inputs[ZK_SLOT] = z_qf;

        let van = z8_qf - QuadFelt::new([Felt::ONE, Felt::ZERO]);
        let omega7 = QuadFelt::from(Felt::two_adic_generator(3).inverse());
        let g_inv = omega7;
        let is_trans = z_qf - g_inv;
        let is_first = van / (z_qf - QuadFelt::new([Felt::ONE, Felt::ZERO]));
        let is_last = van / is_trans;

        inputs[IS_FIRST_SLOT] = is_first;
        inputs[IS_LAST_SLOT] = is_last;
        inputs[IS_TRANS_SLOT] = is_trans;

        // Tamper one quotient coordinate; root should become non-zero.
        inputs[QZ_COORDS_START] += QuadFelt::from(Felt::ONE);

        let result = eval_circuit(&inputs, &constants, &ops);
        let zero = QuadFelt::new([Felt::ZERO, Felt::ZERO]);
        assert_ne!(result, zero, "Tampered quotient coordinate must be rejected");
    }

    #[test]
    fn round_constants_horner_matches_signature_lagrange() {
        use miden_signature::{
            QuadExt,
            internal::{air8, proof::lagrange_interp_at_vec, serialize, signer::Config},
        };

        let (sk, pk) = e2_105::keygen(seed_from_label(b"circuit-gen-ark-test"));
        let message = test_message(2002);
        let signature = sign_sig_w8(&sk, message);
        assert!(verify_sig_w8(&pk, message, &signature).is_ok());

        let config = Config::e2_105bit();
        let stark = &config.stark;
        let pk_felts = *pk.elements();
        let proof = serialize::deserialize_and_reconstruct::<air8::Rpo8, QuadExt>(
            &signature,
            stark,
            11,
            pk_felts,
            message_to_goldilocks(message),
            instance_seed_goldilocks(),
        )
        .expect("deserialization failed");

        let msg_felts = message_to_goldilocks(message);
        let seed = crate::sig::transcript::compute_instance_seed();
        let pk_m: [Felt; 4] = core::array::from_fn(|i| g2f(pk_felts[i]));
        let msg_m: [Felt; 4] = core::array::from_fn(|i| g2f(msg_felts[i]));

        let mut t = crate::sig::transcript::SigTranscript::new(seed, pk_m, msg_m);
        let wc: &[miden_signature::Goldilocks; 4] = &proof.witness_commitment;
        t.reseed_direct(core::array::from_fn(|i| g2f(wc[i])));
        t.check_grind(proof.ali_nonce, stark.grinding.ali);
        let _lambda = t.sample_ext();
        let qc: &[miden_signature::Goldilocks; 4] = &proof.quotient_commitment;
        t.reseed_direct(core::array::from_fn(|i| g2f(qc[i])));
        t.check_grind(proof.ood_nonce, stark.grinding.ood);
        let z = t.sample_ext();

        let z_qf = QuadFelt::new(z);
        let z_sig: QuadExt = unsafe { core::mem::transmute(z_qf) };

        // Evaluate periodic columns in the same way as the circuit (IDFT coeffs + Horner).
        let (ark1_coeffs, ark2_coeffs) = compute_round_constant_coefficients();
        let mut ark1_horner = [QuadFelt::new([Felt::ZERO, Felt::ZERO]); STATE_WIDTH];
        let mut ark2_horner = [QuadFelt::new([Felt::ZERO, Felt::ZERO]); STATE_WIDTH];
        for j in 0..STATE_WIDTH {
            let mut acc1 = ark1_coeffs[j][7];
            let mut acc2 = ark2_coeffs[j][7];
            for k in (0..7).rev() {
                acc1 = acc1 * z_qf + ark1_coeffs[j][k];
                acc2 = acc2 * z_qf + ark2_coeffs[j][k];
            }
            ark1_horner[j] = acc1;
            ark2_horner[j] = acc2;
        }

        // Evaluate periodic columns in the same way as miden-signature verifier (Lagrange).
        let mut ark1_rows = vec![vec![f2g(Felt::ZERO); STATE_WIDTH]; 8];
        let mut ark2_rows = vec![vec![f2g(Felt::ZERO); STATE_WIDTH]; 8];
        for r in 0..miden_signature::internal::rpo8::NUM_ROUNDS {
            for j in 0..STATE_WIDTH {
                ark1_rows[r][j] = f2g(Felt::new(miden_signature::internal::rpo8::ARK1_U64[r][j]));
                ark2_rows[r][j] = f2g(Felt::new(miden_signature::internal::rpo8::ARK2_U64[r][j]));
            }
        }

        let trace_gen = f2g(Felt::two_adic_generator(3));
        let ark1_lagrange = lagrange_interp_at_vec::<QuadExt>(&ark1_rows, z_sig, trace_gen);
        let ark2_lagrange = lagrange_interp_at_vec::<QuadExt>(&ark2_rows, z_sig, trace_gen);

        for j in 0..STATE_WIDTH {
            let a1: QuadFelt = unsafe { core::mem::transmute(ark1_lagrange[j]) };
            let a2: QuadFelt = unsafe { core::mem::transmute(ark2_lagrange[j]) };
            assert_eq!(ark1_horner[j], a1, "ark1 column {j} mismatch");
            assert_eq!(ark2_horner[j], a2, "ark2 column {j} mismatch");
        }
    }

    #[test]
    fn ood_identity_matches_signature_formula() {
        use miden_signature::{
            QuadExt,
            internal::{
                air::SignatureAir,
                air8::{NUM_BOUNDARY_FIRST, NUM_BOUNDARY_LAST, NUM_TRANSITION, Rpo8, Rpo8Air},
                proof::lagrange_interp_at_vec,
                serialize,
                signer::Config,
            },
        };

        let (sk, pk) = e2_105::keygen(seed_from_label(b"circuit-gen-ood-identity-test"));
        let message = test_message(2003);
        let signature = sign_sig_w8(&sk, message);
        assert!(verify_sig_w8(&pk, message, &signature).is_ok());

        let config = Config::e2_105bit();
        let stark = &config.stark;
        let pk_felts = *pk.elements();
        let proof = serialize::deserialize_and_reconstruct::<Rpo8, QuadExt>(
            &signature,
            stark,
            11,
            pk_felts,
            message_to_goldilocks(message),
            instance_seed_goldilocks(),
        )
        .expect("deserialization failed");

        let msg_felts = message_to_goldilocks(message);
        let seed = crate::sig::transcript::compute_instance_seed();
        let pk_m: [Felt; 4] = core::array::from_fn(|i| g2f(pk_felts[i]));
        let msg_m: [Felt; 4] = core::array::from_fn(|i| g2f(msg_felts[i]));

        let mut t = crate::sig::transcript::SigTranscript::new(seed, pk_m, msg_m);
        let wc: &[miden_signature::Goldilocks; 4] = &proof.witness_commitment;
        t.reseed_direct(core::array::from_fn(|i| g2f(wc[i])));
        t.check_grind(proof.ali_nonce, stark.grinding.ali);
        let lambda = t.sample_ext();
        let qc: &[miden_signature::Goldilocks; 4] = &proof.quotient_commitment;
        t.reseed_direct(core::array::from_fn(|i| g2f(qc[i])));
        t.check_grind(proof.ood_nonce, stark.grinding.ood);
        let z = t.sample_ext();

        let lambda_qf = QuadFelt::new(lambda);
        let z_qf = QuadFelt::new(z);
        let z_sig: QuadExt = unsafe { core::mem::transmute(z_qf) };

        let (ark1_rows, ark2_rows) = Rpo8::round_constants();
        let trace_gen = f2g(Felt::two_adic_generator(3));
        let ark1_z = lagrange_interp_at_vec::<QuadExt>(&ark1_rows, z_sig, trace_gen);
        let ark2_z = lagrange_interp_at_vec::<QuadExt>(&ark2_rows, z_sig, trace_gen);

        let wz_arr: [QuadExt; 8] = proof.witness_z.as_slice().try_into().expect("witness_z len");
        let wgz_arr: [QuadExt; 8] = proof.witness_gz.as_slice().try_into().expect("witness_gz len");
        let ark1_arr: [QuadExt; 8] = ark1_z.as_slice().try_into().expect("ark1 len");
        let ark2_arr: [QuadExt; 8] = ark2_z.as_slice().try_into().expect("ark2 len");

        let air = Rpo8Air { pk: pk_felts };
        let constraints_sig =
            air.evaluate_constraints_at_ood(&wz_arr, &wgz_arr, &ark1_arr, &ark2_arr);
        let constraints: Vec<QuadFelt> = constraints_sig
            .iter()
            .map(|c| unsafe { core::mem::transmute_copy(c) })
            .collect();
        assert_eq!(constraints.len(), NUM_TRANSITION + NUM_BOUNDARY_FIRST + NUM_BOUNDARY_LAST);

        // Recompute constraints in the same algebraic shape used by build_sig_circuit.
        let wz_qf: [QuadFelt; STATE_WIDTH] =
            core::array::from_fn(|i| unsafe { core::mem::transmute(proof.witness_z[i]) });
        let wgz_qf: [QuadFelt; STATE_WIDTH] =
            core::array::from_fn(|i| unsafe { core::mem::transmute(proof.witness_gz[i]) });

        let (ark1_coeffs, ark2_coeffs) = compute_round_constant_coefficients();
        let mut ark1_eval = [QuadFelt::new([Felt::ZERO, Felt::ZERO]); STATE_WIDTH];
        let mut ark2_eval = [QuadFelt::new([Felt::ZERO, Felt::ZERO]); STATE_WIDTH];
        for j in 0..STATE_WIDTH {
            let mut a1 = ark1_coeffs[j][7];
            let mut a2 = ark2_coeffs[j][7];
            for k in (0..7).rev() {
                a1 = a1 * z_qf + ark1_coeffs[j][k];
                a2 = a2 * z_qf + ark2_coeffs[j][k];
            }
            ark1_eval[j] = a1;
            ark2_eval[j] = a2;
        }

        let mds = miden_signature::internal::rpo8::MDS_U64;
        let mut t_state = [QuadFelt::new([Felt::ZERO, Felt::ZERO]); STATE_WIDTH];
        for r in 0..STATE_WIDTH {
            let mut acc = QuadFelt::new([Felt::ZERO, Felt::ZERO]);
            for c in 0..STATE_WIDTH {
                acc += QuadFelt::from(Felt::new(mds[r][c])) * wz_qf[c];
            }
            t_state[r] = acc;
        }
        let mut u_state = [QuadFelt::new([Felt::ZERO, Felt::ZERO]); STATE_WIDTH];
        for j in 0..STATE_WIDTH {
            u_state[j] = t_state[j] + ark1_eval[j];
        }
        let mut v_state = [QuadFelt::new([Felt::ZERO, Felt::ZERO]); STATE_WIDTH];
        for j in 0..STATE_WIDTH {
            let u2 = u_state[j] * u_state[j];
            let u4 = u2 * u2;
            let u3 = u2 * u_state[j];
            v_state[j] = u4 * u3;
        }
        let mut w_state = [QuadFelt::new([Felt::ZERO, Felt::ZERO]); STATE_WIDTH];
        for r in 0..STATE_WIDTH {
            let mut acc = QuadFelt::new([Felt::ZERO, Felt::ZERO]);
            for c in 0..STATE_WIDTH {
                acc += QuadFelt::from(Felt::new(mds[r][c])) * v_state[c];
            }
            w_state[r] = acc;
        }
        let mut rhs = [QuadFelt::new([Felt::ZERO, Felt::ZERO]); STATE_WIDTH];
        for j in 0..STATE_WIDTH {
            rhs[j] = w_state[j] + ark2_eval[j];
        }
        for j in 0..NUM_TRANSITION {
            let gz2 = wgz_qf[j] * wgz_qf[j];
            let gz4 = gz2 * gz2;
            let gz3 = gz2 * wgz_qf[j];
            let gz7 = gz4 * gz3;
            let c = gz7 - rhs[j];
            assert_eq!(c, constraints[j], "transition constraint {j} mismatch");
        }
        for j in 0..NUM_BOUNDARY_FIRST {
            assert_eq!(
                wz_qf[4 + j],
                constraints[NUM_TRANSITION + j],
                "boundary-first {j} mismatch"
            );
        }
        for j in 0..NUM_BOUNDARY_LAST {
            let expected = wz_qf[j] - QuadFelt::from(pk_m[j]);
            assert_eq!(
                expected,
                constraints[NUM_TRANSITION + NUM_BOUNDARY_FIRST + j],
                "boundary-last {j} mismatch"
            );
        }

        let one = QuadFelt::new([Felt::ONE, Felt::ZERO]);
        let z8_qf = (0..3).fold(z_qf, |acc, _| acc * acc);
        let van = z8_qf - one;
        let omega7 = QuadFelt::from(Felt::two_adic_generator(3).inverse());
        let sel_trans = z_qf - omega7;
        let sel_first = van / (z_qf - one);
        let sel_last = van / sel_trans;

        // Horner fold used by the circuit.
        let mut horner = sel_trans * constraints[0];
        for &constraint in constraints.iter().take(NUM_TRANSITION).skip(1) {
            horner = horner * lambda_qf + sel_trans * constraint;
        }
        for j in 0..NUM_BOUNDARY_FIRST {
            horner = horner * lambda_qf + sel_first * constraints[NUM_TRANSITION + j];
        }
        for j in 0..NUM_BOUNDARY_LAST {
            horner = horner * lambda_qf
                + sel_last * constraints[NUM_TRANSITION + NUM_BOUNDARY_FIRST + j];
        }

        // Explicit weighted sum with descending lambda powers.
        let mut weights = vec![QuadFelt::new([Felt::ONE, Felt::ZERO]); constraints.len()];
        for i in (0..constraints.len() - 1).rev() {
            weights[i] = weights[i + 1] * lambda_qf;
        }
        let mut weighted = QuadFelt::new([Felt::ZERO, Felt::ZERO]);
        for j in 0..NUM_TRANSITION {
            weighted += weights[j] * constraints[j] * sel_trans;
        }
        for j in 0..NUM_BOUNDARY_FIRST {
            weighted += weights[NUM_TRANSITION + j] * constraints[NUM_TRANSITION + j] * sel_first;
        }
        for j in 0..NUM_BOUNDARY_LAST {
            weighted += weights[NUM_TRANSITION + NUM_BOUNDARY_FIRST + j]
                * constraints[NUM_TRANSITION + NUM_BOUNDARY_FIRST + j]
                * sel_last;
        }
        assert_eq!(horner, weighted, "Horner fold must match explicit weighted sum");

        // Reconstruct quotient(z) from flattened coords, then multiply by vanishing.
        let beta_basis = QuadFelt::new([Felt::ZERO, Felt::ONE]);
        let mut chunks = Vec::with_capacity(NUM_QUOTIENT_CHUNKS);
        for j in 0..NUM_QUOTIENT_CHUNKS {
            let c0 = QuadFelt::from(g2f(proof.quotient_z[2 * j]));
            let c1 = QuadFelt::from(g2f(proof.quotient_z[2 * j + 1]));
            chunks.push(c0 + c1 * beta_basis);
        }

        let z_step =
            (0..SEGMENT_LEN).fold(QuadFelt::new([Felt::ONE, Felt::ZERO]), |acc, _| acc * z_qf);
        let mut q_recon = QuadFelt::new([Felt::ZERO, Felt::ZERO]);
        let mut pow = QuadFelt::new([Felt::ONE, Felt::ZERO]);
        for chunk in chunks {
            q_recon += chunk * pow;
            pow *= z_step;
        }

        assert_eq!(horner, q_recon * van, "OOD identity must hold on valid proof");
    }

    #[test]
    fn pow_builder_matches_direct_power() {
        let mut b = CircuitBuilder::new();
        let pow_wire = b.pow(ZK_SLOT, SEGMENT_LEN);
        assert_eq!(pow_wire, NUM_INPUTS + b.constants.len() + b.ops.len() - 1);

        let mut inputs = vec![QuadFelt::new([Felt::ZERO, Felt::ZERO]); NUM_INPUTS];
        let z = QuadFelt::new([Felt::new(123456789), Felt::new(987654321)]);
        inputs[ZK_SLOT] = z;

        let got = eval_circuit(&inputs, &b.constants, &b.ops);
        let expected =
            (0..SEGMENT_LEN).fold(QuadFelt::new([Felt::ONE, Felt::ZERO]), |acc, _| acc * z);
        assert_eq!(got, expected, "CircuitBuilder::pow must match direct exponentiation");
    }
}
