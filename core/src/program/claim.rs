//! The execution claim: the statement a Miden VM proof attests, and its canonical commitment.
//!
//! An execution claim binds four fields: the program digest `P`, the kernel commitment `K`, the
//! stack inputs `I`, and the stack outputs `O`. The deferred root `D` produced by execution is
//! *not* part of the claim: it is the obligation a verified claim hands back, bound separately
//! into the transcript seed.
//!
//! # Canonical encoding
//!
//! The claim encodes as exactly [`NUM_CLAIM_ELEMENTS`] = 40 field elements:
//!
//! ```text
//! offset  0..8    P ‖ K                       (program digest, kernel commitment)
//! offset  8..24   I  StackInputs, 16 felts    (canonical zero-padded, native order)
//! offset 24..40   O  StackOutputs, 16 felts   (canonical zero-padded, native order)
//! ```
//!
//! The code context comes first so that callsites that pin `(P, K)` can resume the claim hash
//! from a precomputed sponge state; 40 elements is exactly five Poseidon2 rate blocks, so no
//! padding block is absorbed and both read points (the `(P, K)` prefix state and the claim
//! commitment) fall on permutation boundaries.
//!
//! # Claim commitment
//!
//! `CLAIM_HASH = Poseidon2::hash_elements_in_domain(P ‖ K ‖ I ‖ O, CLAIM_DOMAIN_TAG)`, i.e. the
//! domain tag rides in the second capacity element while the first carries the Sponge2 padding
//! rule of <https://eprint.iacr.org/2024/911> (here `40 % 8 = 0`).
//!
//! The commitment is verifier-independent: no relation identity enters its preimage, so a claim
//! can be named — for proof requests, or for binding into a consumer's statement — before any
//! verifier is chosen. The transcript binds it to a relation at seeding time, absorbing this
//! commitment together with the relation digest and the deferred root.

use super::{
    ProgramInfo, StackInputs, StackOutputs,
    domain::{EXECUTION_CLAIM_DOMAIN_ID, domain_selector},
};
use crate::{Felt, Word, ZERO, chiplets::hasher};

// CONSTANTS
// ================================================================================================

/// Number of field elements in the canonical claim encoding: `P ‖ K ‖ I ‖ O`.
pub const NUM_CLAIM_ELEMENTS: usize = 40;

/// Domain tag for the claim commitment: the registered selector
/// `(EXECUTION_CLAIM_DOMAIN_ID << 8) | 1` (see the [`domain`](super::domain) module).
pub const CLAIM_DOMAIN_TAG: Felt = domain_selector(EXECUTION_CLAIM_DOMAIN_ID, 1);

// EXECUTION CLAIM
// ================================================================================================

/// The external statement a Miden VM proof attests: the program digest and kernel commitment
/// identify the executed code and its syscall authorization set; the stack inputs and outputs
/// are the execution's public I/O.
///
/// The deferred root is deliberately absent: verification returns it as an obligation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionClaim {
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
}

impl ExecutionClaim {
    /// Creates a new execution claim from the program info and the stack I/O.
    pub const fn new(
        program_info: ProgramInfo,
        stack_inputs: StackInputs,
        stack_outputs: StackOutputs,
    ) -> Self {
        Self {
            program_info,
            stack_inputs,
            stack_outputs,
        }
    }

    /// Returns the program info (program digest + kernel) of this claim.
    pub const fn program_info(&self) -> &ProgramInfo {
        &self.program_info
    }

    /// Returns the stack inputs of this claim.
    pub const fn stack_inputs(&self) -> &StackInputs {
        &self.stack_inputs
    }

    /// Returns the stack outputs of this claim.
    pub const fn stack_outputs(&self) -> &StackOutputs {
        &self.stack_outputs
    }

    /// Returns the canonical 40-element encoding `P ‖ K ‖ I ‖ O` of this claim.
    pub fn to_elements(&self) -> [Felt; NUM_CLAIM_ELEMENTS] {
        let mut elements = [ZERO; NUM_CLAIM_ELEMENTS];
        elements[0..4].copy_from_slice(self.program_info.program_hash().as_elements());
        elements[4..8].copy_from_slice(self.program_info.kernel_commitment().as_elements());
        elements[8..24].copy_from_slice(&self.stack_inputs[..]);
        elements[24..40].copy_from_slice(&self.stack_outputs[..]);
        elements
    }

    /// Returns the canonical commitment to this claim (`CLAIM_HASH`).
    ///
    /// This is the verifier-independent name of the claim: the value used to request proof
    /// packages and to bind verified claims into a consumer's own statement.
    pub fn commitment(&self) -> Word {
        claim_commitment(&self.to_elements())
    }
}

/// Returns the canonical claim commitment over an already-encoded claim.
///
/// This is the single implementation of `CLAIM_HASH`; every native computation of the claim
/// commitment (including the transcript observation in `miden-air`) must go through it.
pub fn claim_commitment(elements: &[Felt; NUM_CLAIM_ELEMENTS]) -> Word {
    hasher::hash_elements_in_domain(elements, CLAIM_DOMAIN_TAG)
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::{
        super::{KERNEL_DOMAIN_TAG, KernelDescriptor},
        *,
    };

    fn test_claim() -> ExecutionClaim {
        let word = |a: u64| -> Word {
            [
                Felt::new_unchecked(a),
                Felt::new_unchecked(a + 1),
                Felt::new_unchecked(a + 2),
                Felt::new_unchecked(a + 3),
            ]
            .into()
        };
        let kernel = KernelDescriptor::from_hashes(vec![word(100)]).unwrap();
        let program_info = ProgramInfo::new(word(1), kernel);
        let inputs = StackInputs::new(&[Felt::new_unchecked(5), Felt::new_unchecked(6)]).unwrap();
        let outputs = StackOutputs::new(&[Felt::new_unchecked(7)]).unwrap();
        ExecutionClaim::new(program_info, inputs, outputs)
    }

    /// The commitment must bind every field and the I/O order, be domain-separated, and use
    /// the registered selector.
    #[test]
    fn commitment_binds_fields_order_and_domain() {
        let base = test_claim();
        let base_commitment = base.commitment();
        let base_elements = base.to_elements();

        // mutate P
        let mut mutated = base.clone();
        let other_kernel = mutated.program_info.kernel().clone();
        mutated.program_info =
            ProgramInfo::new([Felt::new_unchecked(999), ZERO, ZERO, ZERO].into(), other_kernel);
        assert_ne!(mutated.commitment(), base_commitment, "P not bound");

        // mutate K (different kernel)
        let mut mutated = base.clone();
        let new_kernel = KernelDescriptor::from_hashes(vec![
            [Felt::new_unchecked(200), ZERO, ZERO, ZERO].into(),
        ])
        .unwrap();
        mutated.program_info = ProgramInfo::new(*base.program_info.program_hash(), new_kernel);
        assert_ne!(mutated.commitment(), base_commitment, "K not bound");

        // mutate one element of I
        let mut mutated = base.clone();
        mutated.stack_inputs =
            StackInputs::new(&[Felt::new_unchecked(5), Felt::new_unchecked(60)]).unwrap();
        assert_ne!(mutated.commitment(), base_commitment, "I not bound");

        // mutate one element of O
        let mut mutated = base.clone();
        mutated.stack_outputs = StackOutputs::new(&[Felt::new_unchecked(70)]).unwrap();
        assert_ne!(mutated.commitment(), base_commitment, "O not bound");

        // swap I and O (order binding): same multiset of felts, different positions
        let mut mutated = base;
        mutated.stack_inputs = StackInputs::new(&[Felt::new_unchecked(7)]).unwrap();
        mutated.stack_outputs =
            StackOutputs::new(&[Felt::new_unchecked(5), Felt::new_unchecked(6)]).unwrap();
        assert_ne!(mutated.commitment(), base_commitment, "I/O order not bound");

        // domain separation: differs from the untagged hash and from another registered tag
        let elements = base_elements;
        assert_ne!(
            base_commitment,
            hasher::hash_elements(&elements),
            "claim commitment must differ from the untagged hash"
        );
        assert_ne!(
            base_commitment,
            hasher::hash_elements_in_domain(&elements, KERNEL_DOMAIN_TAG),
            "claim commitment must differ from a kernel-tagged hash of the same data"
        );

        // the tag is the registered selector
        assert_eq!(
            CLAIM_DOMAIN_TAG.as_canonical_u64(),
            (u64::from(EXECUTION_CLAIM_DOMAIN_ID) << 8) | 1
        );
    }
}
