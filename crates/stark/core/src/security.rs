//! Security contracts shared by the VM and precompile relations.
//!
//! The estimator consumes compiled relation geometry and parameters returned by verification. It
//! never captures equations, constructs fixed matrices or builds witnesses. Manually assembled
//! numeric inputs are estimates; constructing this type alone does not authenticate a proof.

mod budget;
pub mod fixed;
mod fri;
mod proven;
mod proximity;
mod report;
mod shape;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use report::{
    ErrorBits, ProvenSecurityReport, ProvenSecurityTerm, Regime, RegimeReport, SecurityReport,
    SecurityTerm,
};
pub use shape::{AirShape, InstanceShape, LookupShape};

/// Stable presentation labels for the conjectured and proven security rounds.
pub mod labels {
    pub use super::report::{
        ALI_LABEL, BATCH_LABEL, COLLISION_LABEL, COMPOSITION_LABEL, DEEP_COMPOSITION_LABEL,
        DEEP_LABEL, FOLDING_LABEL, LDT_COMMIT_LABEL, LDT_LABEL, LDT_QUERY_LABEL, LOOKUP_LABEL,
        OUT_OF_DOMAIN_LABEL, QUERY_LABEL,
    };
}

use crate::pcs::PcsParams;
use miden_core::{
    Felt,
    field::{BasedVectorSpace, PrimeField64, QuadFelt},
    proof::HashFunction,
};

const EXTENSION_DEGREE: usize = <QuadFelt as BasedVectorSpace<Felt>>::DIMENSION;

pub const COMMITMENT_ALIGNMENT: usize = miden_crypto::hash::eidos::BLOCK_LEN;
pub const COLLISION_RESISTANCE: u32 = HashFunction::Eidos.collision_resistance();
pub const OOD_POW_BITS: u32 = 0;
pub const LOOKUP_POW_BITS: u32 = 0;

/// Security inputs of a Miden STARK proof.
///
/// Verifiers construct these only after checking the proof and authenticating its statement.
/// Applications select an estimator and acceptance policy. Public fields also support planning;
/// manually constructed or modified parameters do not carry verification provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofSecurityParameters {
    /// The validated PCS configuration used to verify the proof, including its final degree.
    pub pcs_params: PcsParams,
    /// Instance geometry derived from the proof and its commitment scheme.
    pub instance_shape: InstanceShape,
    /// Verified commitment hash and Fiat–Shamir challenger configuration.
    pub hash_fn: HashFunction,
    /// Compiled relation geometry, resolved for the actual committed allocation/alignment.
    pub air_shape: AirShape,
    /// Number of out-of-domain points opened per committed column.
    pub num_ood_points: u32,
    /// Number of lookup fractions contributed by the authenticated boundary messages.
    pub num_lookup_boundary_terms: u32,
}

/// Conservative Q16 lower bound on the quadratic challenge-field cardinality.
///
/// Rounding the base-field value down before doubling keeps this conservative.
pub const CHALLENGE_FIELD_BITS: u64 = EXTENSION_DEGREE as u64 * fixed::floor_log2(Felt::ORDER_U64);

/// Q16 log size of Eidos's challenge support: two uniformly sampled 63-bit coefficients.
///
/// Root-counting uses this support, FRI queries use the polynomial field itself, and commitment
/// collisions use the verified hash's collision resistance. Those quantities are distinct.
pub const EIDOS_CHALLENGE_SAMPLE_BITS: u64 = fixed::from_bits(63 * EXTENSION_DEGREE as u32);

/// A transient numerical projection, shared by real PCS configurations and raw regression cases.
#[derive(Clone, Copy)]
pub(super) struct NumericalInputs {
    pub protocol_params: budget::ProtocolParams,
    pub log_final_degree: u32,
    pub instance_shape: InstanceShape,
    pub hash_fn: HashFunction,
    pub air_shape: AirShape,
    pub num_ood_points: u32,
    pub num_lookup_boundary_terms: u32,
}

/// Project native parameters without narrowing an unrepresentable query/grinding count.
///
/// The round budget's Q16 domain uses u32 counts. An unrepresentable configuration has no
/// estimate in that domain and reports zero security instead of wrapping to a smaller count.
fn project_pcs(params: &PcsParams) -> Option<budget::ProtocolParams> {
    Some(budget::ProtocolParams {
        log_blowup: u32::from(params.log_blowup()),
        log_folding_arity: u32::from(params.log_folding_arity()),
        num_queries: u32::try_from(params.num_queries()).ok()?,
        query_pow_bits: u32::try_from(params.query_pow_bits()).ok()?,
        ood_pow_bits: OOD_POW_BITS,
        deep_pow_bits: u32::try_from(params.deep_pow_bits()).ok()?,
        folding_pow_bits: u32::try_from(params.folding_pow_bits()).ok()?,
        lookup_pow_bits: LOOKUP_POW_BITS,
    })
}

impl ProofSecurityParameters {
    fn numerical_inputs(&self) -> Option<NumericalInputs> {
        Some(NumericalInputs {
            protocol_params: project_pcs(&self.pcs_params)?,
            log_final_degree: u32::from(self.pcs_params.log_final_degree()),
            instance_shape: self.instance_shape,
            hash_fn: self.hash_fn,
            air_shape: self.air_shape,
            num_ood_points: self.num_ood_points,
            num_lookup_boundary_terms: self.num_lookup_boundary_terms,
        })
    }

    /// Conjectured fixed-point round budget, including hash sampling and boundary corrections.
    pub fn conjectured_security_report(&self) -> SecurityReport {
        self.numerical_inputs()
            .map_or_else(SecurityReport::zero, |inputs| budget::native_report(&inputs))
    }

    /// Conjectured security in whole bits, rounded down.
    pub fn conjectured_security_level(&self) -> u32 {
        self.conjectured_security_report().security_level()
    }

    /// Proven round-by-round bounds in unique- and list-decoding regimes.
    ///
    /// Every admissible list-decoding candidate is graded with its own lookup list-size loss,
    /// then complete reports are compared. Hash/Fiat–Shamir assumptions still apply.
    pub fn proven_security_report(&self) -> ProvenSecurityReport {
        self.numerical_inputs().map_or_else(proven::zero_report, |inputs| {
            proven::security_report(&inputs, budget::lookup_bits(&inputs))
        })
    }

    /// Stronger proven decoding-regime bound in whole bits, rounded down.
    pub fn proven_security_level(&self) -> u32 {
        self.proven_security_report().security_bits() as u32
    }
}

/// Upper bound on `log2(1 + boundary / (fractions_per_row · 2^log_max_height))`, in fixed point,
/// via `log2(1 + x) <= x · log2(e)`.
///
/// `num_boundary_terms` is the number of one-time lookup fractions consumed on top of the
/// per-row terms counted by `fractions_per_row`. Both divisions round up, so the correction is
/// never smaller than the true log term, keeping the corrected round conservative. The two-step
/// division order (first by `fractions_per_row`, then by `2^log_max_height`) is what the common
/// MASM estimator mirrors bit-for-bit: a single combined divisor overflows a `u32` at the deployed
/// shape's larger heights.
pub fn lookup_boundary_correction(
    num_boundary_terms: u32,
    fractions_per_row: u32,
    log_max_height: u32,
) -> u64 {
    if num_boundary_terms == 0 {
        return 0;
    }
    assert!(fractions_per_row > 0, "lookup boundary terms require per-row lookup fractions");
    let height = 1u64
        .checked_shl(log_max_height)
        .expect("maximum trace height must fit in a u64");
    (u64::from(num_boundary_terms) * fixed::LOG2_E)
        .div_ceil(u64::from(fractions_per_row))
        .div_ceil(height)
}

#[cfg(test)]
#[path = "security/tests/api.rs"]
mod tests;
