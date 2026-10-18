//! Relation-independent proof security reporting and protocol budget support.

use miden_core::{
    Felt,
    field::{BasedVectorSpace, PrimeField64, QuadFelt},
    proof::HashFunction,
};
use p3_security::budget::report::{
    COLLISION_LABEL, LOOKUP_LABEL, OUT_OF_DOMAIN_LABEL, QUERY_LABEL,
};
pub use p3_security::{
    budget::{AirShape, InstanceShape, LookupShape, ProtocolParams, SecurityReport, SecurityTerm},
    fixed,
};

use crate::pcs::PcsParams;

const EXTENSION_DEGREE: usize = <QuadFelt as BasedVectorSpace<Felt>>::DIMENSION;
const LOG2_E: u64 = fixed::LOG2_E;

/// Security parameters of a verified Miden STARK proof.
///
/// Native MVM and PVM verifiers return these parameters after deriving them from the proof, the
/// commitment scheme used to verify it, and the AIR relation selected by the verifier. Callers
/// pass the returned value to a security estimator and apply their own acceptance policy.
/// Constructing this type directly does not authenticate its contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofSecurityParameters {
    /// Protocol parameters bound by the proof transcript.
    pub protocol_params: ProtocolParams,
    /// Log2 of the configured final FRI polynomial degree.
    pub log_final_degree: u32,
    /// Instance shape derived from the proof and its commitment scheme.
    pub instance_shape: InstanceShape,
    /// Verified proof-hash configuration, which also selects the Fiat-Shamir challenger.
    pub hash_fn: HashFunction,
    /// Security-relevant shape of the AIR relation and commitment scheme.
    pub air_shape: AirShape,
    /// Number of out-of-domain points opened per committed column.
    pub num_ood_points: u32,
    /// Lookup fractions consumed once per proof in addition to the per-row fractions.
    pub num_lookup_boundary_terms: u32,
}

/// Conservative Q16 lower bound on the log2 of the challenge-field cardinality.
///
/// The challenge field is the quadratic extension of the Goldilocks base field. This value doubles
/// the rounded-down Q16 value for the base field. Rounding before doubling keeps the result
/// conservative.
pub const CHALLENGE_FIELD_BITS: u64 = EXTENSION_DEGREE as u64 * fixed::floor_log2(Felt::ORDER_U64);

/// Size of the Eidos quadratic-extension challenge support, in Q16 bits.
///
/// Each basis coefficient is a uniform 63-bit integer under the Eidos pseudorandomness assumption,
/// so the support has `2^126` elements. Root-counting bounds use this size; the FRI query rate uses
/// the cardinality of the field in which the polynomials are defined instead.
pub const EIDOS_CHALLENGE_SAMPLE_BITS: u64 = fixed::from_bits(63 * EXTENSION_DEGREE as u32);

/// Computes conjectured security bounds for the proof's hash and challenger configuration.
///
/// Eidos root-counting bounds use its 126-bit sampling support. The FRI query rate still uses
/// `instance.field_bits`, and the commitment cap uses `instance.collision_resistance`.
pub fn security_report_with_hash(
    params: &ProtocolParams,
    instance: &InstanceShape,
    air: &AirShape,
    hash_fn: HashFunction,
) -> SecurityReport {
    match hash_fn {
        HashFunction::Eidos => {},
        HashFunction::Blake3_256
        | HashFunction::Rpo256
        | HashFunction::Rpx256
        | HashFunction::Poseidon2
        | HashFunction::Keccak => {
            return p3_security::budget::security_report(params, instance, air);
        },
    }
    let sampling_instance = InstanceShape {
        field_bits: EIDOS_CHALLENGE_SAMPLE_BITS,
        ..*instance
    };
    let report = p3_security::budget::security_report(params, &sampling_instance, air);
    let cap = instance.cap();
    let query_bits = u64::from(params.num_queries)
        * fixed::bits_per_query(params.log_blowup, instance.field_bits)
        + fixed::from_bits(params.query_pow_bits);
    SecurityReport::new((*report.terms()).map(|term| match term.label {
        QUERY_LABEL => SecurityTerm::new(QUERY_LABEL, query_bits.min(cap)),
        COLLISION_LABEL => SecurityTerm::new(COLLISION_LABEL, cap),
        // OOD rejection removes only base-field points. At most 2^63 of the 2^126 Eidos
        // candidates are in the base field; one Q16 unit conservatively covers this conditioning.
        OUT_OF_DOMAIN_LABEL => SecurityTerm::new(OUT_OF_DOMAIN_LABEL, term.bits.saturating_sub(1)),
        _ => term,
    }))
}

/// Grinding applied before the out-of-domain point is sampled.
///
/// Lifted STARK samples the point directly after the quotient commitment; its DEEP grinding runs
/// only after the out-of-domain evaluations are bound.
pub const OOD_POW_BITS: u32 = 0;

/// Lookup grinding applied before the lookup challenges are sampled.
///
/// Lifted STARK samples them directly after the main-trace commitment and exposes no
/// lookup-grinding parameter.
pub const LOOKUP_POW_BITS: u32 = 0;

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
    (u64::from(num_boundary_terms) * LOG2_E)
        .div_ceil(u64::from(fractions_per_row))
        .div_ceil(height)
}

pub fn apply_lookup_correction(report: SecurityReport, correction: u64) -> SecurityReport {
    let terms = (*report.terms()).map(|term| {
        if term.label == LOOKUP_LABEL {
            SecurityTerm::new(term.label, term.bits.saturating_sub(correction))
        } else {
            term
        }
    });
    SecurityReport::new(terms)
}

impl ProofSecurityParameters {
    /// Computes the conjectured security report for the verified proof.
    ///
    /// The same estimator handles MVM and PVM proofs because the parameters include the protocol,
    /// instance, and AIR shapes. Callers must use parameters returned by the verifier that
    /// authenticated the proof rather than values assembled independently.
    pub fn conjectured_security_report(&self) -> SecurityReport {
        let report = security_report_with_hash(
            &self.protocol_params,
            &self.instance_shape,
            &self.air_shape,
            self.hash_fn,
        );
        let correction = lookup_boundary_correction(
            self.num_lookup_boundary_terms,
            self.air_shape.lookup.map_or(0, |lookup| lookup.fractions_per_row),
            self.instance_shape.log_max_height,
        );
        apply_lookup_correction(report, correction)
    }

    /// Returns the conjectured security level for the verified proof.
    pub fn conjectured_security_level(&self) -> u32 {
        self.conjectured_security_report().security_level()
    }
}

/// Maps PCS parameters onto the protocol parameters the round budget reads.
///
/// The transcript observes every field of [`PcsParams`], so computing a proof's security level
/// under these parameters uses the parameters it was actually produced with.
pub fn protocol_params(params: &PcsParams) -> ProtocolParams {
    ProtocolParams {
        log_blowup: u32::from(params.log_blowup()),
        log_folding_arity: u32::from(params.log_folding_arity()),
        num_queries: params.num_queries() as u32,
        query_pow_bits: params.query_pow_bits() as u32,
        ood_pow_bits: OOD_POW_BITS,
        deep_pow_bits: params.deep_pow_bits() as u32,
        folding_pow_bits: params.folding_pow_bits() as u32,
        // The protocol samples the lookup challenges directly after the main-trace commitment,
        // with no grinding in between.
        lookup_pow_bits: LOOKUP_POW_BITS,
    }
}
