//! Security contracts shared by the VM and precompile relations.
use miden_core::{
    Felt,
    field::{BasedVectorSpace, PrimeField64, QuadFelt},
    proof::HashFunction,
};
use miden_stark::pcs::PcsParams;
pub use p3_security::budget::{
    AirShape, InstanceShape, LookupShape, ProtocolParams, SecurityReport, SecurityTerm,
};
use p3_security::{
    budget::report::{COLLISION_LABEL, OUT_OF_DOMAIN_LABEL, QUERY_LABEL},
    fixed,
};
pub const COMMITMENT_ALIGNMENT: usize = miden_crypto::hash::eidos::BLOCK_LEN;
pub const COLLISION_RESISTANCE: u32 = HashFunction::Eidos.collision_resistance();
pub const OOD_POW_BITS: u32 = 0;
pub const LOOKUP_POW_BITS: u32 = 0;
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
        HashFunction::Blake3_256 | HashFunction::Keccak => {
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

/// Base field elements per challenge-field element.
const EXTENSION_DEGREE: usize = <QuadFelt as BasedVectorSpace<Felt>>::DIMENSION;

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
