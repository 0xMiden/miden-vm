use alloc::{vec, vec::Vec};

use miden_ace_codegen::{DagBuilder, InputKey, NodeId};
use miden_core::{Felt, field::ExtensionField};

use crate::{PV_PROGRAM_HASH, PV_TRANSCRIPT_STATE};

/// An element in a bus message encoding.
///
/// Bus messages are encoded as `bus_prefix + sum(beta^i * elements[i])` using the aux randomness
/// challenges. Each element is either a constant base-field value or a reference to a fixed-length
/// public input.
#[derive(Debug, Clone)]
pub enum MessageElement {
    /// A constant base-field value.
    Constant(Felt),
    /// A fixed-length public input value, indexed into the public values array.
    PublicInput(usize),
}

/// Sign applied to a [`BusFraction`] numerator.
#[derive(Debug, Clone, Copy)]
pub enum Sign {
    Plus,
    Minus,
}

/// A rational `+/-1 / bus_message` contribution to the LogUp boundary sum.
///
/// The bus message denominator is rebuilt inside the ACE DAG from public inputs and aux
/// randomness, so no external input is needed for this term.
#[derive(Debug, Clone)]
pub struct BusFraction {
    pub sign: Sign,
    pub bus: usize,
    pub message: Vec<MessageElement>,
}

/// Configuration for the LogUp auxiliary-trace boundary batching.
///
/// Consumed by [`batch_logup_boundary_into_builder`] to extend the constraint-check DAG with the
/// per-AIR LogUp boundary identity checked at runtime by the AIRs.
#[derive(Debug, Clone)]
pub struct LogUpBoundaryConfig {
    /// Aux-bus-boundary column indices summed as `sum(aux_bound[col])`.
    pub sum_columns: Vec<usize>,
    /// Rational `(+/-1, d_i)` fractions folded into the running rational `(N, D)`.
    pub fractions: Vec<BusFraction>,
    /// Scalar EF inputs already reduced by MASM and added to the aux-boundary sum.
    pub scalar_corrections: Vec<InputKey>,
}

/// Appends the LogUp auxiliary-trace boundary check into an existing [`DagBuilder`].
///
/// Builds:
///
/// ```text
/// sum_aux  = sum(AuxBusBoundary(col)) + sum(scalar_corrections)
/// (N, D)   = fold((0, 1), fractions) via (N', D') = (N*d_i + D*n_i, D*d_i)
/// boundary = sum_aux * D + N
/// root     = constraint_check + gamma * boundary
/// ```
///
/// The returned node must remain the final node in the circuit: the MASM ACE chip checks the last
/// evaluated node for zero.
pub fn batch_logup_boundary_into_builder<EF>(
    builder: &mut DagBuilder<EF>,
    constraint_root: NodeId,
    config: &LogUpBoundaryConfig,
) -> NodeId
where
    EF: ExtensionField<Felt>,
{
    let mut sum_aux = builder.constant(EF::ZERO);
    for &col in &config.sum_columns {
        let node = builder.input(InputKey::AuxBusBoundary(col));
        sum_aux = builder.add(sum_aux, node);
    }
    for &scalar in &config.scalar_corrections {
        let node = builder.input(scalar);
        sum_aux = builder.add(sum_aux, node);
    }

    let mut num = builder.constant(EF::ZERO);
    let mut den = builder.constant(EF::ONE);
    for fraction in &config.fractions {
        let d_i = encode_bus_message(builder, fraction.bus, &fraction.message);
        let sign_value = match fraction.sign {
            Sign::Plus => EF::ONE,
            Sign::Minus => -EF::ONE,
        };
        let n_i = builder.constant(sign_value);

        let num_d = builder.mul(num, d_i);
        let den_n = builder.mul(den, n_i);
        num = builder.add(num_d, den_n);
        den = builder.mul(den, d_i);
    }

    let sum_times_den = builder.mul(sum_aux, den);
    let boundary = builder.add(sum_times_den, num);
    let gamma = builder.input(InputKey::Gamma);
    let gamma_boundary = builder.mul(gamma, boundary);
    builder.add(constraint_root, gamma_boundary)
}

/// Build the [`LogUpBoundaryConfig`] for the combined multi-AIR ACE circuit.
///
/// `sum_columns` covers every committed aux-boundary slot. The order of those slots does not matter
/// because the boundary identity uses their sum.
pub fn multi_air_logup_boundary_config(total_aux_values: usize) -> LogUpBoundaryConfig {
    use MessageElement::{Constant, PublicInput};

    use crate::constraints::lookup::messages::BusId;

    // The open-bus corrections are rebuilt in-circuit. The kernel-ROM correction is supplied as a
    // scalar because it depends on the variable-length kernel digest list.
    let ph_msg = vec![
        PublicInput(PV_PROGRAM_HASH),
        PublicInput(PV_PROGRAM_HASH + 1),
        PublicInput(PV_PROGRAM_HASH + 2),
        PublicInput(PV_PROGRAM_HASH + 3),
        Constant(Felt::ZERO),
        Constant(Felt::ZERO),
        Constant(Felt::ZERO),
    ];
    let default_lp_msg = vec![
        Constant(Felt::ZERO),
        Constant(Felt::ZERO),
        Constant(Felt::ZERO),
        Constant(Felt::ZERO),
    ];
    let final_lp_msg = vec![
        PublicInput(PV_TRANSCRIPT_STATE),
        PublicInput(PV_TRANSCRIPT_STATE + 1),
        PublicInput(PV_TRANSCRIPT_STATE + 2),
        PublicInput(PV_TRANSCRIPT_STATE + 3),
    ];

    LogUpBoundaryConfig {
        sum_columns: (0..total_aux_values).collect(),
        fractions: vec![
            BusFraction {
                sign: Sign::Plus,
                bus: BusId::BlockHashTable as usize,
                message: ph_msg,
            },
            BusFraction {
                sign: Sign::Plus,
                bus: BusId::LogPrecompileTranscript as usize,
                message: default_lp_msg,
            },
            BusFraction {
                sign: Sign::Minus,
                bus: BusId::LogPrecompileTranscript as usize,
                message: final_lp_msg,
            },
        ],
        scalar_corrections: vec![InputKey::VlpiReduction(0)],
    }
}

/// Encode a bus message as `bus_prefix[bus] + sum(beta^i * elements[i])`.
///
/// The bus prefix provides domain separation:
/// `bus_prefix[bus] = alpha + (bus + 1) * beta^MIDEN_MAX_MESSAGE_WIDTH`.
fn encode_bus_message<EF>(
    builder: &mut DagBuilder<EF>,
    bus: usize,
    elements: &[MessageElement],
) -> NodeId
where
    EF: ExtensionField<Felt>,
{
    use crate::constraints::lookup::messages::MIDEN_MAX_MESSAGE_WIDTH;

    let alpha = builder.input(InputKey::AuxRandAlpha);
    let beta = builder.input(InputKey::AuxRandBeta);

    let mut gamma_bus = builder.constant(EF::ONE);
    for _ in 0..MIDEN_MAX_MESSAGE_WIDTH {
        gamma_bus = builder.mul(gamma_bus, beta);
    }

    let scale = builder.constant(EF::from(Felt::from_u32((bus as u32) + 1)));
    let offset = builder.mul(gamma_bus, scale);
    let bus_prefix = builder.add(alpha, offset);

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
