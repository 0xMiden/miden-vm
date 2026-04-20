//! ACE circuit integration for ProcessorAir.
//!
//! This module extends the constraint-evaluation DAG produced by
//! `build_ace_dag_for_air` with the LogUp auxiliary-trace boundary check:
//!
//!     0  =  Σ aux_bound[0..LOGUP_AUX_TRACE_WIDTH]
//!             + c_block_hash
//!             + c_log_precompile
//!             + c_kernel_rom
//!
//! Two of the three corrections depend only on fixed-length public inputs
//! (`c_bh`, `c_lp`), so they are rebuilt directly inside the DAG as rational
//! fractions `(n, d)` and folded into a running rational `(N, D)` without any
//! in-circuit inversion. The kernel-ROM correction depends on the variable-
//! length kernel digest list which the circuit can't walk, so MASM computes
//! it (one final `ext2inv`) and hands it in as a single scalar via the
//! existing `VlpiReduction(0)` input. The final boundary check is the
//! quadratic identity `(Σ aux_bound + c_kr) · D + N = 0`.

use alloc::{vec, vec::Vec};

use miden_ace_codegen::{
    AceCircuit, AceConfig, AceDag, AceError, DagBuilder, InputKey, NodeId, build_ace_dag_for_air,
};
use miden_core::{Felt, field::ExtensionField};
use miden_crypto::{
    field::Algebra,
    stark::air::{LiftedAir, symbolic::SymbolicExpressionExt},
};

use crate::{LOGUP_AUX_TRACE_WIDTH, PV_PROGRAM_HASH, PV_TRANSCRIPT_STATE, trace};

// BATCHING TYPES
// ================================================================================================

/// An element in a bus message encoding.
///
/// Bus messages are encoded as `bus_prefix + sum(beta^i * elements[i])` using the
/// aux randomness challenges. Each element is either a constant base-field value
/// or a reference to a fixed-length public input.
#[derive(Debug, Clone)]
pub enum MessageElement {
    /// A constant base-field value.
    Constant(Felt),
    /// A fixed-length public input value, indexed into the public values array.
    PublicInput(usize),
}

/// Sign applied to a `BusFraction` numerator.
#[derive(Debug, Clone, Copy)]
pub enum Sign {
    Plus,
    Minus,
}

/// A rational `±1 / bus_message` contribution to the LogUp boundary sum.
///
/// The bus message denominator is rebuilt inside the ACE DAG from public inputs
/// and aux randomness, so no external input is needed for this term.
#[derive(Debug, Clone)]
pub struct BusFraction {
    pub sign: Sign,
    pub bus: usize,
    pub message: Vec<MessageElement>,
}

/// Configuration for the LogUp auxiliary-trace boundary batching.
///
/// Consumed by [`batch_logup_boundary`] to extend the constraint-check DAG with
/// the boundary identity checked by `ProcessorAir::reduced_aux_values`.
#[derive(Debug, Clone)]
pub struct LogUpBoundaryConfig {
    /// Aux-bus-boundary column indices summed as `Σ aux_bound[col]`.
    pub sum_columns: Vec<usize>,
    /// Rational `(±1, d_i)` fractions folded into the running rational `(N, D)`.
    pub fractions: Vec<BusFraction>,
    /// Scalar EF inputs added directly to the aux-boundary sum. Trusted from
    /// MASM (the VM's own constraint system covers the procedure that produced
    /// them). Typically one entry pointing at `VlpiReduction(0)` for `c_kr`.
    pub scalar_corrections: Vec<InputKey>,
}

// BATCHING FUNCTIONS
// ================================================================================================

/// Extend a constraint DAG with the LogUp auxiliary-trace boundary check.
///
/// Builds:
///
///   `sum_aux   = Σ AuxBusBoundary(col)  +  Σ scalar_corrections`
///   `(N, D)    = fold((0, 1), fractions)` via `(N', D') = (N·d_i + D·n_i, D·d_i)`
///   `boundary  = sum_aux · D  +  N`
///   `root      = constraint_check  +  γ · boundary`
///
/// Returns the new DAG with the batched root.
pub fn batch_logup_boundary<EF>(
    constraint_dag: AceDag<EF>,
    config: &LogUpBoundaryConfig,
) -> AceDag<EF>
where
    EF: ExtensionField<Felt>,
{
    let constraint_root = constraint_dag.root;
    let mut builder = DagBuilder::from_dag(constraint_dag);

    // sum_aux = Σ aux_bound[col] + Σ scalar_corrections
    let mut sum_aux = builder.constant(EF::ZERO);
    for &col in &config.sum_columns {
        let node = builder.input(InputKey::AuxBusBoundary(col));
        sum_aux = builder.add(sum_aux, node);
    }
    for &scalar in &config.scalar_corrections {
        let node = builder.input(scalar);
        sum_aux = builder.add(sum_aux, node);
    }

    // Fold all rational fractions into a single (N, D) running rational.
    let mut num = builder.constant(EF::ZERO);
    let mut den = builder.constant(EF::ONE);
    for fraction in &config.fractions {
        let d_i = encode_bus_message(&mut builder, fraction.bus, &fraction.message);
        let sign_value = match fraction.sign {
            Sign::Plus => EF::ONE,
            Sign::Minus => -EF::ONE,
        };
        let n_i = builder.constant(sign_value);

        // (num', den') = (num * d_i + den * n_i, den * d_i)
        let num_d = builder.mul(num, d_i);
        let den_n = builder.mul(den, n_i);
        num = builder.add(num_d, den_n);
        den = builder.mul(den, d_i);
    }

    // boundary = sum_aux · D + N
    let sum_times_den = builder.mul(sum_aux, den);
    let boundary = builder.add(sum_times_den, num);

    // Batch with the constraint root using gamma.
    let gamma = builder.input(InputKey::Gamma);
    let term = builder.mul(gamma, boundary);
    let root = builder.add(constraint_root, term);

    builder.build(root)
}

/// Encode a bus message as `bus_prefix[bus] + sum(beta^i * elements[i])`.
///
/// The bus prefix provides domain separation: `bus_prefix[bus] = alpha + (bus+1) * gamma_bus`
/// where `gamma_bus = beta^MIDEN_MAX_MESSAGE_WIDTH`. This matches [`lookup::Challenges::encode`].
fn encode_bus_message<EF>(
    builder: &mut DagBuilder<EF>,
    bus: usize,
    elements: &[MessageElement],
) -> NodeId
where
    EF: ExtensionField<Felt>,
{
    use crate::constraints::lookup::bus_id::MIDEN_MAX_MESSAGE_WIDTH;

    let alpha = builder.input(InputKey::AuxRandAlpha);
    let beta = builder.input(InputKey::AuxRandBeta);

    // gamma_bus = beta^MIDEN_MAX_MESSAGE_WIDTH.
    let mut gamma_bus = builder.constant(EF::ONE);
    for _ in 0..MIDEN_MAX_MESSAGE_WIDTH {
        gamma_bus = builder.mul(gamma_bus, beta);
    }

    // bus_prefix = alpha + (bus + 1) * gamma_bus
    let scale = builder.constant(EF::from(Felt::from_u32((bus as u32) + 1)));
    let offset = builder.mul(gamma_bus, scale);
    let bus_prefix = builder.add(alpha, offset);

    // acc = bus_prefix + sum(beta^i * elem_i)
    //
    // Beta powers are built incrementally; the DagBuilder is hash-consed, so
    // identical beta^i nodes across multiple message encodings are shared
    // automatically.
    let mut acc = bus_prefix;
    let mut beta_power = builder.constant(EF::ONE);
    for elem in elements {
        let node = match elem {
            MessageElement::Constant(f) => builder.constant(EF::from(*f)),
            MessageElement::PublicInput(idx) => builder.input(InputKey::Public(*idx)),
        };
        let term = builder.mul(beta_power, node);
        acc = builder.add(acc, term);
        beta_power = builder.mul(beta_power, beta);
    }
    acc
}

// AIR-SPECIFIC CONFIG
// ================================================================================================

/// Build the [`LogUpBoundaryConfig`] for the Miden VM ProcessorAir.
///
/// This mirrors `ProcessorAir::reduced_aux_values` in `air/src/lib.rs`: it sums
/// all `LOGUP_AUX_TRACE_WIDTH` aux boundary columns, adds the scalar kernel-ROM
/// correction supplied by MASM via `VlpiReduction(0)`, and folds the two open-
/// bus corrections `c_block_hash` and `c_log_precompile` as rational fractions
/// whose denominators are rebuilt from public inputs inside the DAG.
///
/// The three fractions are:
///   1. `c_bh  = +1 / encode(BLOCK_HASH_TABLE, [0, ph[0..4], 0, 0])`
///   2. `c_lp_init  = +1 / encode(LOG_PRECOMPILE, [LABEL, 0, 0, 0, 0])`
///   3. `c_lp_final = −1 / encode(LOG_PRECOMPILE, [LABEL, ts[0..4]])`
///
/// `c_lp_init − c_lp_final` matches `transcript_messages` in `lib.rs` (initial
/// minus final contribution). Splitting it into two rationals keeps the code
/// uniform at the cost of two extra mul gates.
pub fn logup_boundary_config() -> LogUpBoundaryConfig {
    use MessageElement::{Constant, PublicInput};

    use crate::constraints::lookup::bus_id::bus_types;

    let log_precompile_label = Felt::from_u8(trace::LOG_PRECOMPILE_LABEL);

    // ph_msg = encode([0, ph[0], ph[1], ph[2], ph[3], 0, 0])
    // Matches `program_hash_message` in lib.rs.
    let ph_msg = vec![
        Constant(Felt::ZERO), // parent_id = 0 (root block)
        PublicInput(PV_PROGRAM_HASH),
        PublicInput(PV_PROGRAM_HASH + 1),
        PublicInput(PV_PROGRAM_HASH + 2),
        PublicInput(PV_PROGRAM_HASH + 3),
        Constant(Felt::ZERO), // is_first_child = false
        Constant(Felt::ZERO), // is_loop_body = false
    ];

    // default_lp_msg = encode([LABEL, 0, 0, 0, 0])
    // Matches `transcript_messages(..).0` (initial default state).
    let default_lp_msg = vec![
        Constant(log_precompile_label),
        Constant(Felt::ZERO),
        Constant(Felt::ZERO),
        Constant(Felt::ZERO),
        Constant(Felt::ZERO),
    ];

    // final_lp_msg = encode([LABEL, ts[0..4]])
    // Matches `transcript_messages(..).1` (final public-input state).
    let final_lp_msg = vec![
        Constant(log_precompile_label),
        PublicInput(PV_TRANSCRIPT_STATE),
        PublicInput(PV_TRANSCRIPT_STATE + 1),
        PublicInput(PV_TRANSCRIPT_STATE + 2),
        PublicInput(PV_TRANSCRIPT_STATE + 3),
    ];

    LogUpBoundaryConfig {
        sum_columns: (0..LOGUP_AUX_TRACE_WIDTH).collect(),
        fractions: vec![
            BusFraction {
                sign: Sign::Plus,
                bus: bus_types::BLOCK_HASH_TABLE,
                message: ph_msg,
            },
            BusFraction {
                sign: Sign::Plus,
                bus: bus_types::LOG_PRECOMPILE_TRANSCRIPT,
                message: default_lp_msg,
            },
            BusFraction {
                sign: Sign::Minus,
                bus: bus_types::LOG_PRECOMPILE_TRANSCRIPT,
                message: final_lp_msg,
            },
        ],
        scalar_corrections: vec![InputKey::VlpiReduction(0)],
    }
}

// CONVENIENCE FUNCTION
// ================================================================================================

/// Build a batched ACE circuit for the provided AIR.
///
/// Builds the constraint-evaluation DAG, extends it with the LogUp auxiliary
/// trace boundary check via [`batch_logup_boundary`], and emits the off-VM
/// circuit representation.
///
/// The output circuit checks `constraint_check + γ · boundary = 0`, where
/// `boundary = (Σ aux_bound + c_kr) · D + N` and `(N, D)` is the rational sum
/// of the in-DAG open-bus corrections.
pub fn build_batched_ace_circuit<A, EF>(
    air: &A,
    config: AceConfig,
    boundary_config: &LogUpBoundaryConfig,
) -> Result<AceCircuit<EF>, AceError>
where
    A: LiftedAir<Felt, EF>,
    EF: ExtensionField<Felt>,
    SymbolicExpressionExt<Felt, EF>: Algebra<EF>,
{
    let artifacts = build_ace_dag_for_air::<A, Felt, EF>(air, config)?;
    let batched_dag = batch_logup_boundary(artifacts.dag, boundary_config);
    miden_ace_codegen::emit_circuit(&batched_dag, artifacts.layout)
}
