//! RPO signature AIR for ACE circuit generation.
//!
//! Defines the 24-constraint AIR for the RPO permutation signature scheme:
//!   12 transition: y^7 = MDS(sbox(MDS(x) + ark1)) + ark2
//!    8 boundary-first: capacity=0, rate1=0  (at row 0)
//!    4 boundary-last: rate0 = pk  (at row 7)
//!
//! The AIR has:
//!   - 12 main columns (RPO state: capacity[0..4], rate0[4..8], rate1[8..12])
//!   - 4 public values (pk[0..4])
//!   - 24 periodic columns (ark1[0..12] and ark2[0..12], each length 8)
//!   - No auxiliary trace (no bus/permutation checks)

use miden_core::{Felt, field::QuadFelt};
use miden_crypto::stark::air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder, WindowAccess};
use miden_signature::internal::signer::Config;

type F = Felt;
type EF = QuadFelt;

/// RPO state width (12 elements: capacity[4] + rate0[4] + rate1[4]).
const STATE_WIDTH: usize = 12;

/// Number of RPO rounds (7 rounds, 8 trace rows including initial state).
const NUM_ROUNDS: usize = 7;

/// Digest size (rate0[4..8] = public key output).
const DIGEST_SIZE: usize = 4;

/// RPO MDS matrix (12x12) over Goldilocks.
const MDS: [[u64; STATE_WIDTH]; STATE_WIDTH] = [
    [7, 23, 8, 26, 13, 10, 9, 7, 6, 22, 21, 8],
    [8, 7, 23, 8, 26, 13, 10, 9, 7, 6, 22, 21],
    [21, 8, 7, 23, 8, 26, 13, 10, 9, 7, 6, 22],
    [22, 21, 8, 7, 23, 8, 26, 13, 10, 9, 7, 6],
    [6, 22, 21, 8, 7, 23, 8, 26, 13, 10, 9, 7],
    [7, 6, 22, 21, 8, 7, 23, 8, 26, 13, 10, 9],
    [9, 7, 6, 22, 21, 8, 7, 23, 8, 26, 13, 10],
    [10, 9, 7, 6, 22, 21, 8, 7, 23, 8, 26, 13],
    [13, 10, 9, 7, 6, 22, 21, 8, 7, 23, 8, 26],
    [26, 13, 10, 9, 7, 6, 22, 21, 8, 7, 23, 8],
    [8, 26, 13, 10, 9, 7, 6, 22, 21, 8, 7, 23],
    [23, 8, 26, 13, 10, 9, 7, 6, 22, 21, 8, 7],
];

/// RPO signature AIR.
pub struct RpoSignatureAir;

impl BaseAir<F> for RpoSignatureAir {
    fn width(&self) -> usize {
        STATE_WIDTH // 12 main trace columns
    }

    fn num_public_values(&self) -> usize {
        DIGEST_SIZE // 4 public key elements
    }
}

impl LiftedAir<F, EF> for RpoSignatureAir {
    fn periodic_columns(&self) -> Vec<Vec<F>> {
        // 24 periodic columns: ark1[0..12] and ark2[0..12].
        // Each column has 8 values (one per trace row).
        // Row 7 has zeros (no transition from last row).
        let (ark1, ark2) = rpo_round_constants();
        let mut columns = Vec::with_capacity(24);

        // ark1 columns: one per state element
        for (j, _) in ark1[0].iter().enumerate() {
            let col: Vec<F> = (0..8).map(|r| ark1[r][j]).collect();
            columns.push(col);
        }
        // ark2 columns: one per state element
        for (j, _) in ark2[0].iter().enumerate() {
            let col: Vec<F> = (0..8).map(|r| ark2[r][j]).collect();
            columns.push(col);
        }

        columns
    }

    fn num_randomness(&self) -> usize {
        // Minimal: 1 required by the framework.
        1
    }

    fn aux_width(&self) -> usize {
        // Dummy aux column (framework requires aux_width >= 1 when num_randomness > 0).
        1
    }

    fn num_aux_values(&self) -> usize {
        1
    }

    fn num_var_len_public_inputs(&self) -> usize {
        0
    }

    fn eval<AB: LiftedAirBuilder<F = F>>(&self, builder: &mut AB) {
        let main = builder.main();
        let current = main.current_slice();
        let next = main.next_slice();

        // Copy public values and periodic values to avoid borrow conflicts with builder.
        let pk: Vec<_> = builder.public_values().to_vec();
        let periodic: Vec<_> = builder.periodic_values().to_vec();

        // periodic[0..12]  = ark1[j] for j=0..12
        // periodic[12..24] = ark2[j] for j=0..12

        // ── Transition constraints (12) ──
        //
        // For each column j: next[j]^7 = RHS[j]
        // where RHS = MDS(sbox(MDS(current) + ark1)) + ark2
        //
        // Computed in 5 steps:
        //   1. t = MDS(current)         -- 12x12 matrix-vector multiply
        //   2. u = t + ark1             -- elementwise addition of round constants
        //   3. v = sbox(u) = u^7        -- RPO s-box (x^7)
        //   4. w = MDS(v)               -- second MDS application
        //   5. rhs = w + ark2           -- second round constant addition

        // mds_mul(state) = [sum_k MDS[j][k] * state[k] for j in 0..12]
        let mds_mul = |state: &[AB::Expr]| -> Vec<AB::Expr> {
            (0..STATE_WIDTH)
                .map(|j| {
                    let c0: AB::Expr = F::new(MDS[j][0]).into();
                    let mut acc = state[0].clone() * c0;
                    for k in 1..STATE_WIDTH {
                        let ck: AB::Expr = F::new(MDS[j][k]).into();
                        acc += state[k].clone() * ck;
                    }
                    acc
                })
                .collect()
        };

        // Helper: x^7 = x^4 * x^2 * x
        let pow7 = |x: AB::Expr| -> AB::Expr {
            let x2 = x.clone() * x.clone();
            let x4 = x2.clone() * x2.clone();
            let x3 = x2 * x;
            x4 * x3
        };

        // Current row as Vec<AB::Expr>
        let cur: Vec<AB::Expr> = (0..STATE_WIDTH).map(|j| current[j].into()).collect();

        // Step 1: t = MDS(current)
        let t = mds_mul(&cur);

        // Step 2: u = t + ark1 (elementwise)
        let u: Vec<AB::Expr> = (0..STATE_WIDTH)
            .map(|j| t[j].clone() + Into::<AB::Expr>::into(periodic[j]))
            .collect();

        // Step 3: v = sbox(u) = u^7
        let v: Vec<AB::Expr> = u.into_iter().map(&pow7).collect();

        // Step 4: w = MDS(v)
        let w = mds_mul(&v);

        // Step 5: rhs = w + ark2
        // Constraint: next[j]^7 - rhs[j] = 0 (on transition rows)
        for j in 0..STATE_WIDTH {
            let rhs_j = w[j].clone() + Into::<AB::Expr>::into(periodic[12 + j]);
            let next_j: AB::Expr = next[j].into();
            let next_pow7 = pow7(next_j);

            builder.when_transition().assert_zero(next_pow7 - rhs_j);
        }

        // ── Boundary-first constraints (8) ──
        // At row 0: capacity[0..4] = 0 and rate1[8..12] = 0
        // State layout: capacity=[0..4], rate0=[4..8], rate1=[8..12]

        // capacity = 0
        for cur in current.iter().take(4) {
            let cur_expr: AB::Expr = (*cur).into();
            builder.when_first_row().assert_zero(cur_expr);
        }

        // rate1 = 0
        for cur in current.iter().take(12).skip(8) {
            let cur_expr: AB::Expr = (*cur).into();
            builder.when_first_row().assert_zero(cur_expr);
        }

        // ── Boundary-last constraints (4) ──
        // At row 7: rate0[4..8] = pk[0..4]
        for (cur, pk_j) in current.iter().skip(4).take(DIGEST_SIZE).zip(pk.iter()) {
            let cur_j: AB::Expr = (*cur).into();
            let pk_j: AB::Expr = (*pk_j).into();
            builder.when_last_row().assert_zero(cur_j - pk_j);
        }

        // No aux constraints for this AIR. We still declare a minimal aux width to
        // satisfy the lifted framework, but we do not fold aux values into `acc`.
    }
}

/// RPO round constants (ark1 and ark2) for 7 rounds.
/// Returns (ark1, ark2) where each is [8][12] — values at each of 8 trace rows.
/// Row 7 is zeros (no transition from last row).
fn rpo_round_constants() -> ([[F; STATE_WIDTH]; 8], [[F; STATE_WIDTH]; 8]) {
    // Import from miden-signature's constants
    use miden_signature::internal::rpo::{ARK1_U64, ARK2_U64, NUM_ROUNDS as NR};

    let mut ark1 = [[F::ZERO; STATE_WIDTH]; 8];
    let mut ark2 = [[F::ZERO; STATE_WIDTH]; 8];
    debug_assert_eq!(NR, NUM_ROUNDS);
    for r in 0..NUM_ROUNDS {
        for j in 0..STATE_WIDTH {
            ark1[r][j] = F::new(ARK1_U64[r][j]);
            ark2[r][j] = F::new(ARK2_U64[r][j]);
        }
    }
    // Row 7 stays zero (no transition from last row)
    (ark1, ark2)
}

/// Number of EF input slots in the ACE circuit (from layout.total_inputs).
#[allow(dead_code)]
pub const ACE_NUM_INPUTS: usize = 82;

/// Number of total variables = inputs + constants (from encoded.num_vars()).
#[allow(dead_code)]
pub const ACE_NUM_VARS: usize = 288;

/// Number of eval gate rows in the ACE circuit.
#[allow(dead_code)]
pub const ACE_NUM_EVAL: usize = 1088;

/// Number of adv_pipe iterations to load the circuit (encoded_size / 8).
#[allow(dead_code)]
pub const ACE_NUM_ADV_PIPE: usize = 187;

/// Circuit commitment hash (4 Goldilocks felts).
/// Generated with quotient_extension=true (EF quotient chunks, no coord flattening).
#[allow(dead_code)]
pub const ACE_CIRCUIT_HASH: [u64; 4] = [
    4228612517619167373,
    2108971827550465474,
    14124475933653582058,
    1123493745516390667,
];

#[derive(Debug, Copy, Clone)]
struct QuotientChunking {
    num_chunks: usize,
    segment_len: usize,
}

fn quotient_chunking(
    config: &miden_signature::internal::proof::MultiRowConfig,
) -> QuotientChunking {
    let message_size = config.message_size();
    let base_randomness = config.quotient_randomness;
    let num_coeffs = config.num_quotient_coeffs();
    let max_seg_len = message_size - base_randomness;

    let min_chunks = num_coeffs.div_ceil(max_seg_len);
    let mut num_chunks = min_chunks;
    while !(num_chunks + 1).is_multiple_of(4) {
        num_chunks += 1;
    }

    let segment_len = num_coeffs.div_ceil(num_chunks);

    QuotientChunking { num_chunks, segment_len }
}

fn signature_chunking() -> QuotientChunking {
    let config = Config::e2_105bit();
    quotient_chunking(&config.stark)
}

/// Generate the ACE circuit and return the encoded instructions as u64 values.
///
/// The instructions are keyed by ACE_CIRCUIT_HASH in the advice map.
#[allow(dead_code)]
pub fn generate_circuit_instructions() -> Vec<u64> {
    let air = RpoSignatureAir;
    let chunking = signature_chunking();
    let config = miden_ace_codegen::AceConfig {
        num_quotient_chunks: chunking.num_chunks,
        num_vlpi_groups: 0,
        layout: miden_ace_codegen::LayoutKind::Masm,
        quotient_extension: true,
        quotient_segment_len: chunking.segment_len,
    };

    let artifacts = miden_ace_codegen::build_ace_dag_for_air::<_, F, EF>(&air, config).unwrap();
    let circuit = miden_ace_codegen::emit_circuit(&artifacts.dag, artifacts.layout).unwrap();
    let encoded = circuit.to_ace().unwrap();

    // Verify hash matches our hardcoded constant
    let hash = encoded.circuit_hash();
    for i in 0..4 {
        assert_eq!(
            hash[i].as_canonical_u64(),
            ACE_CIRCUIT_HASH[i],
            "circuit hash mismatch at position {i} — regenerate ACE_CIRCUIT_HASH"
        );
    }

    encoded.instructions().iter().map(|f| f.as_canonical_u64()).collect()
}

#[cfg(test)]
mod tests {
    use miden_ace_codegen::{AceConfig, LayoutKind, build_ace_dag_for_air, emit_circuit};

    use super::{RpoSignatureAir, *};

    #[test]
    fn generate_rpo_signature_circuit() {
        let air = RpoSignatureAir;
        let chunking = signature_chunking();
        let config = AceConfig {
            num_quotient_chunks: chunking.num_chunks,
            num_vlpi_groups: 0,
            layout: LayoutKind::Masm,
            quotient_extension: true,
            quotient_segment_len: chunking.segment_len,
        };

        let artifacts = build_ace_dag_for_air::<_, F, EF>(&air, config).unwrap();
        let layout = artifacts.layout.clone();
        let circuit = emit_circuit(&artifacts.dag, layout.clone()).unwrap();
        let encoded = circuit.to_ace().unwrap();

        eprintln!("RPO signature ACE circuit generated:");
        eprintln!("  total_inputs (EF slots): {}", layout.total_inputs);
        eprintln!("  num_vars: {}", encoded.num_vars());
        eprintln!("  num_eval: {}", encoded.num_eval_rows());
        eprintln!("  encoded size: {} felts", encoded.size_in_felt());
        eprintln!("  num_adv_pipe: {}", encoded.size_in_felt() / 8);
        eprintln!(
            "  circuit hash: {:?}",
            encoded.circuit_hash().iter().map(|f| f.as_canonical_u64()).collect::<Vec<_>>()
        );

        // Print the input layout: which InputKey maps to which slot index
        use miden_ace_codegen::InputKey;
        eprintln!("\n  Input layout (EF slot indices):");
        for i in 0..4 {
            if let Some(idx) = layout.index(InputKey::Public(i)) {
                eprintln!("    Public({i}) -> slot {idx}");
            }
        }
        if let Some(idx) = layout.index(InputKey::AuxRandAlpha) {
            eprintln!("    AuxRandAlpha -> slot {idx}");
        }
        if let Some(idx) = layout.index(InputKey::AuxRandBeta) {
            eprintln!("    AuxRandBeta -> slot {idx}");
        }
        for i in 0..12 {
            if let Some(idx) = layout.index(InputKey::Main { offset: 0, index: i }) {
                eprintln!("    Main(z, {i}) -> slot {idx}");
            }
        }
        for i in 0..12 {
            if let Some(idx) = layout.index(InputKey::Main { offset: 1, index: i }) {
                eprintln!("    Main(gz, {i}) -> slot {idx}");
            }
        }
        // Quotient chunks at z (extension-field: 1 slot per chunk)
        for chunk in 0..chunking.num_chunks {
            if let Some(idx) = layout.index(InputKey::QuotientChunk { offset: 0, chunk }) {
                eprintln!("    QuotientChunk(z, {chunk}) -> slot {idx}");
            }
        }
        // STARK vars
        for (name, key) in [
            ("Alpha", InputKey::Alpha),
            ("ZPowN", InputKey::ZPowN),
            ("ZK", InputKey::ZK),
            ("IsFirst", InputKey::IsFirst),
            ("IsLast", InputKey::IsLast),
            ("IsTransition", InputKey::IsTransition),
            ("Gamma", InputKey::Gamma),
            ("Weight0", InputKey::Weight0),
            ("F", InputKey::F),
            ("S0", InputKey::S0),
        ] {
            if let Some(idx) = layout.index(key) {
                eprintln!("    {name} -> slot {idx}");
            }
        }
    }
}
