//! ACE circuit integration for ProcessorAir.
//!
//! This module contains:
//! - Batching types and functions (`MessageElement`, `ReducedAuxBatchConfig`,
//!   `batch_reduced_aux_values`) that extend a constraint check DAG with the auxiliary trace
//!   boundary checks.
//! - The AIR-specific `reduced_aux_batch_config()` that describes the Miden VM's auxiliary trace
//!   boundary checks.
//! - The convenience function `build_batched_ace_circuit()` that builds the full batched circuit in
//!   one call.
//!
//! The formula checked by the batched circuit is:
//!   `constraint_check + gamma * product_check + gamma^2 * sum_check = 0`

use alloc::vec::Vec;

use miden_ace_codegen::{
    AceCircuit, AceConfig, AceDag, AceError, DagBuilder, InputKey, NodeId, build_ace_dag_for_air,
};
use miden_core::{Felt, field::ExtensionField};
use miden_crypto::{
    field::Algebra,
    stark::air::{LiftedAir, symbolic::SymbolicExpressionExt},
};

use crate::trace;

// BATCHING TYPES
// ================================================================================================

/// An element in a bus message encoding.
///
/// Bus messages are encoded as `alpha + sum(beta^i * elements[i])` using the
/// aux randomness challenges. Each element is either a constant base-field value
/// or a reference to a fixed-length public input.
#[derive(Debug, Clone)]
pub enum MessageElement {
    /// A constant base-field value.
    Constant(Felt),
    /// A fixed-length public input value, indexed into the public values array.
    PublicInput(usize),
}

/// A multiplicative factor in the product check.
///
/// The product check verifies:
///   `product(numerator) - product(denominator) = 0`
#[derive(Debug, Clone)]
pub enum ProductFactor {
    /// Claimed final value of an auxiliary trace column, by column index.
    BusBoundary(usize),
    /// A bus message computed from its elements as `bus_prefix[bus] + sum(beta^i * elements[i])`.
    /// The first field is the bus type index (see `trace::bus_types`).
    Message(usize, Vec<MessageElement>),
    /// Multiset product reduced from variable-length public inputs, by group index.
    Vlpi(usize),
}

/// Configuration for building the reduced_aux_values batching in the ACE DAG.
///
/// Describes the auxiliary trace boundary checks (product_check and sum_check).
/// Constructed by AIR-specific code (see [`reduced_aux_batch_config`]) and
/// consumed by [`batch_reduced_aux_values`].
///
/// The product check verifies:
///   `product(numerator) - product(denominator) = 0`
#[derive(Debug, Clone)]
pub struct ReducedAuxBatchConfig {
    /// Factors multiplied into the numerator of the product check.
    pub numerator: Vec<ProductFactor>,
    /// Factors multiplied into the denominator of the product check.
    pub denominator: Vec<ProductFactor>,
    /// Auxiliary trace column indices whose claimed final values are summed in the sum check.
    pub sum_columns: Vec<usize>,
}

// BATCHING FUNCTIONS
// ================================================================================================

/// Extend an existing constraint DAG with auxiliary trace boundary checks.
///
/// Takes the constraint DAG and appends the running-product identity check
/// (product_check) and the LogUp sum check (sum_check), combining all three
/// checks into a single root with gamma:
///
///   `root = constraint_check + gamma * product_check + gamma^2 * sum_check`
///
/// Returns the new DAG with the batched root.
pub fn batch_reduced_aux_values<EF>(
    constraint_dag: AceDag<EF>,
    config: &ReducedAuxBatchConfig,
) -> AceDag<EF>
where
    EF: ExtensionField<Felt>,
{
    let constraint_root = constraint_dag.root;
    let mut builder = DagBuilder::from_nodes(constraint_dag.nodes);

    // Build product_check.
    let product_check = build_product_check(&mut builder, config);

    // Build sum_check.
    let sum_check = build_sum_check(&mut builder, config);

    // Batch: root = constraint_check + gamma * product_check + gamma^2 * sum_check
    let gamma = builder.input(InputKey::Gamma);
    let gamma2 = builder.mul(gamma, gamma);
    let term2 = builder.mul(gamma, product_check);
    let term3 = builder.mul(gamma2, sum_check);
    let partial = builder.add(constraint_root, term2);
    let root = builder.add(partial, term3);

    AceDag { nodes: builder.into_nodes(), root }
}

/// Build the running-product identity check.
fn build_product_check<EF>(builder: &mut DagBuilder<EF>, config: &ReducedAuxBatchConfig) -> NodeId
where
    EF: ExtensionField<Felt>,
{
    let numerator = build_product(builder, &config.numerator);
    let denominator = build_product(builder, &config.denominator);
    builder.sub(numerator, denominator)
}

/// Build a product of factors as a single DAG node.
fn build_product<EF>(builder: &mut DagBuilder<EF>, factors: &[ProductFactor]) -> NodeId
where
    EF: ExtensionField<Felt>,
{
    let mut acc = builder.constant(EF::ONE);
    for factor in factors {
        let node = match factor {
            ProductFactor::BusBoundary(idx) => builder.input(InputKey::AuxBusBoundary(*idx)),
            ProductFactor::Message(bus, elements) => encode_bus_message(builder, *bus, elements),
            ProductFactor::Vlpi(idx) => builder.input(InputKey::VlpiReduction(*idx)),
        };
        acc = builder.mul(acc, node);
    }
    acc
}

/// Build the LogUp sum check (sum_check).
///
/// Verifies that the LogUp auxiliary columns sum to zero at the boundary.
fn build_sum_check<EF>(builder: &mut DagBuilder<EF>, config: &ReducedAuxBatchConfig) -> NodeId
where
    EF: ExtensionField<Felt>,
{
    let mut sum = builder.constant(EF::ZERO);
    for &col_idx in &config.sum_columns {
        let col = builder.input(InputKey::AuxBusBoundary(col_idx));
        sum = builder.add(sum, col);
    }
    sum
}

/// Encode a bus message as `bus_prefix[bus] + sum(beta^i * elements[i])`.
///
/// The bus prefix provides domain separation: `bus_prefix[bus] = alpha + (bus+1) * gamma`
/// where `gamma = beta^MAX_MESSAGE_WIDTH`. This matches [`trace::Challenges::encode`].
fn encode_bus_message<EF>(
    builder: &mut DagBuilder<EF>,
    bus: usize,
    elements: &[MessageElement],
) -> NodeId
where
    EF: ExtensionField<Felt>,
{
    let alpha = builder.input(InputKey::AuxRandAlpha);
    let beta = builder.input(InputKey::AuxRandBeta);

    // Compute gamma = beta^MAX_MESSAGE_WIDTH.
    let mut gamma = builder.constant(EF::ONE);
    for _ in 0..trace::MAX_MESSAGE_WIDTH {
        gamma = builder.mul(gamma, beta);
    }

    // bus_prefix = alpha + (bus + 1) * gamma
    let scale = builder.constant(EF::from(Felt::from_u32((bus as u32) + 1)));
    let offset = builder.mul(gamma, scale);
    let bus_prefix = builder.add(alpha, offset);

    // acc = bus_prefix + sum(beta^i * elem_i)
    //
    // Beta powers are built incrementally. The DagBuilder is hash-consed, so
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

/// Build the [`ReducedAuxBatchConfig`] for the Miden VM ProcessorAir.
///
/// This encodes the `reduced_aux_values` formula in the Miden VM AIR.
pub fn reduced_aux_batch_config() -> ReducedAuxBatchConfig {
    use MessageElement::{Constant, PublicInput};
    use ProductFactor::{BusBoundary, Message, Vlpi};
    use trace::bus_types;

    // Aux boundary column indices.
    let p1 = trace::DECODER_AUX_TRACE_OFFSET;
    let p2 = trace::DECODER_AUX_TRACE_OFFSET + 1;
    let p3 = trace::DECODER_AUX_TRACE_OFFSET + 2;
    let s_aux = trace::STACK_AUX_TRACE_OFFSET;
    let b_range = trace::RANGE_CHECK_AUX_TRACE_OFFSET;
    let b_hash_kernel = trace::HASH_KERNEL_VTABLE_AUX_TRACE_OFFSET;
    let b_chiplets = trace::CHIPLETS_BUS_AUX_TRACE_OFFSET;
    let v_wiring = trace::ACE_CHIPLET_WIRING_BUS_OFFSET;

    // Public input layout offsets.
    // [0..4] program hash, [4..20] stack inputs, [20..36] stack outputs, [36..40] transcript state
    let pv_program_hash = super::PV_PROGRAM_HASH;
    let pv_transcript_state = super::PV_TRANSCRIPT_STATE;

    // Bus message constants.
    let log_precompile_label = Felt::from_u8(trace::LOG_PRECOMPILE_LABEL);

    // ph_msg = encode([0, ph[0], ph[1], ph[2], ph[3], 0, 0])
    // Matches program_hash_message() in lib.rs.
    let ph_msg = vec![
        Constant(Felt::ZERO),             // parent_id = 0
        PublicInput(pv_program_hash),     // hash[0]
        PublicInput(pv_program_hash + 1), // hash[1]
        PublicInput(pv_program_hash + 2), // hash[2]
        PublicInput(pv_program_hash + 3), // hash[3]
        Constant(Felt::ZERO),             // is_first_child = false
        Constant(Felt::ZERO),             // is_loop_body = false
    ];

    // default_msg = encode([LOG_PRECOMPILE_LABEL, 0, 0, 0, 0])
    // Matches transcript_message(challenges, PrecompileTranscriptState::default()).
    let default_msg = vec![
        Constant(log_precompile_label),
        Constant(Felt::ZERO),
        Constant(Felt::ZERO),
        Constant(Felt::ZERO),
        Constant(Felt::ZERO),
    ];

    // final_msg = encode([LOG_PRECOMPILE_LABEL, ts[0], ts[1], ts[2], ts[3]])
    // Matches transcript_message(challenges, pc_transcript_state).
    let final_msg = vec![
        Constant(log_precompile_label),
        PublicInput(pv_transcript_state),
        PublicInput(pv_transcript_state + 1),
        PublicInput(pv_transcript_state + 2),
        PublicInput(pv_transcript_state + 3),
    ];

    // product_check: product(numerator) - product(denominator) = 0
    // sum_check:     sum(sum_columns) = 0
    ReducedAuxBatchConfig {
        numerator: vec![
            BusBoundary(p1),
            BusBoundary(p2),
            BusBoundary(p3),
            BusBoundary(s_aux),
            BusBoundary(b_hash_kernel),
            BusBoundary(b_chiplets),
            Message(bus_types::BLOCK_HASH_TABLE, ph_msg),
            Message(bus_types::LOG_PRECOMPILE_TRANSCRIPT, default_msg),
        ],
        denominator: vec![Message(bus_types::LOG_PRECOMPILE_TRANSCRIPT, final_msg), Vlpi(0)],
        sum_columns: vec![b_range, v_wiring],
    }
}

// CONVENIENCE FUNCTION
// ================================================================================================

/// Build a batched ACE circuit for the provided AIR.
///
/// This is the highest-level entry point for building the ACE circuit for Miden VM AIR.
/// It builds the constraint-evaluation DAG, extends it with the auxiliary trace
/// boundary checks and emits the off-VM circuit representation.
///
/// The output circuit checks:
///   `constraint_check + gamma * product_check + gamma^2 * sum_check = 0`
pub fn build_batched_ace_circuit<A, EF>(
    air: &A,
    config: AceConfig,
    batch_config: &ReducedAuxBatchConfig,
) -> Result<AceCircuit<EF>, AceError>
where
    A: LiftedAir<Felt, EF>,
    EF: ExtensionField<Felt>,
    SymbolicExpressionExt<Felt, EF>: Algebra<EF>,
{
    let artifacts = build_ace_dag_for_air::<A, Felt, EF>(air, config)?;
    let batched_dag = batch_reduced_aux_values(artifacts.dag, batch_config);
    miden_ace_codegen::emit_circuit(&batched_dag, artifacts.layout)
}
