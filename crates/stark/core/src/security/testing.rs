//! Raw numerical cases and independent reference math for estimator regression tests.
//!
//! These inputs intentionally admit configurations that the real Miden PCS rejects. They carry
//! no verification provenance and do not duplicate the production estimator implementation.

use miden_core::proof::HashFunction;

pub use super::budget::ProtocolParams;
use super::{
    AirShape, InstanceShape, NumericalInputs, ProofSecurityParameters, ProvenSecurityReport,
    SecurityReport, SecurityTerm, budget, fixed, labels::LOOKUP_LABEL,
};
use crate::pcs::PcsParams;

pub mod reference;

/// An explicitly synthetic estimator case, including raw grinding/FRI controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityCase {
    pub protocol_params: ProtocolParams,
    pub log_final_degree: u32,
    pub instance_shape: InstanceShape,
    pub hash_fn: HashFunction,
    pub air_shape: AirShape,
    pub num_ood_points: u32,
    pub num_lookup_boundary_terms: u32,
}

impl From<ProofSecurityParameters> for SecurityCase {
    fn from(parameters: ProofSecurityParameters) -> Self {
        Self {
            protocol_params: protocol_params(&parameters.pcs_params),
            log_final_degree: u32::from(parameters.pcs_params.log_final_degree()),
            instance_shape: parameters.instance_shape,
            hash_fn: parameters.hash_fn,
            air_shape: parameters.air_shape,
            num_ood_points: parameters.num_ood_points,
            num_lookup_boundary_terms: parameters.num_lookup_boundary_terms,
        }
    }
}

impl SecurityCase {
    pub(super) fn numerical_inputs(&self) -> NumericalInputs {
        NumericalInputs {
            protocol_params: self.protocol_params,
            log_final_degree: self.log_final_degree,
            instance_shape: self.instance_shape,
            hash_fn: self.hash_fn,
            air_shape: self.air_shape,
            num_ood_points: self.num_ood_points,
            num_lookup_boundary_terms: self.num_lookup_boundary_terms,
        }
    }

    pub fn conjectured_security_report(&self) -> SecurityReport {
        budget::native_report(&self.numerical_inputs())
    }
    pub fn conjectured_security_level(&self) -> u32 {
        self.conjectured_security_report().security_level()
    }
    pub fn proven_security_report(&self) -> ProvenSecurityReport {
        let inputs = self.numerical_inputs();
        super::proven::security_report(&inputs, budget::lookup_bits(&inputs))
    }
    pub fn proven_security_level(&self) -> u32 {
        self.proven_security_report().security_bits() as u32
    }
}

/// Produce raw regression controls from validated native PCS parameters.
/// Unrepresentable counts fail closed by producing a zero-query, ungrounded case.
pub fn protocol_params(params: &PcsParams) -> ProtocolParams {
    super::project_pcs(params).unwrap_or(ProtocolParams {
        log_blowup: 0,
        log_folding_arity: 0,
        num_queries: 0,
        query_pow_bits: 0,
        ood_pow_bits: 0,
        deep_pow_bits: 0,
        folding_pow_bits: 0,
        lookup_pow_bits: 0,
    })
}

/// Uncorrected full-field Q16 budget for independent wrapper/round comparisons.
pub const fn budget_security_report(
    params: &ProtocolParams,
    instance: &InstanceShape,
    air: &AirShape,
) -> SecurityReport {
    budget::security_report(params, instance, air)
}

/// Hash-specific report before the statement-boundary lookup correction.
pub fn security_report_with_hash(
    params: &ProtocolParams,
    instance: &InstanceShape,
    air: &AirShape,
    hash_fn: HashFunction,
) -> SecurityReport {
    budget::native_report(&NumericalInputs {
        protocol_params: *params,
        log_final_degree: 0,
        instance_shape: *instance,
        hash_fn,
        air_shape: *air,
        num_ood_points: 0,
        num_lookup_boundary_terms: 0,
    })
}

/// Apply a boundary correction to the declared first (lookup) round of a Q16 report.
/// Public labels are presentation data; arithmetic uses the report's fixed round ordering.
pub fn apply_lookup_correction(report: SecurityReport, correction: u64) -> SecurityReport {
    let mut terms = *report.terms();
    terms[0] = SecurityTerm::new(LOOKUP_LABEL, terms[0].bits.saturating_sub(correction));
    SecurityReport::new(terms)
}

#[cfg(test)]
#[path = "tests/budget_parity.rs"]
mod budget_parity;
