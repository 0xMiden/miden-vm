use alloc::vec::Vec;

use miden_ace_codegen::{
    AceConfig, AceError, FactoredCircuitFactory, LayoutKind, ShuffleEncodeBuffer,
};
use miden_core::{Felt, Word, crypto::hash::Poseidon2};
use miden_crypto::merkle::MerklePath;

use super::multi_air::build_factored_multi_air_ace_circuit;
use crate::{MIDEN_AIR_COUNT, ProofOrder};

/// ACE codegen settings used by the recursive verifier's MASM evaluator.
const RECURSIVE_VERIFIER_ACE_CONFIG: AceConfig = AceConfig {
    num_quotient_chunks: 8,
    layout: LayoutKind::Masm,
    num_airs: MIDEN_AIR_COUNT,
};

/// Encoded recursive-verifier ACE circuit and the metadata consumed by MASM.
///
/// The instruction stream is factored into two `adv_pipe`-aligned segments:
/// - the per-order prefix `[constants | shuffle ops]` of `shuffle_prefix_len` felts, hashed into
///   `shuffle_commitment`;
/// - the order-invariant common section `[common ops | root padding]`, hashed into
///   `common_commitment` (the same digest for every proof order).
///
/// The registry leaf and advice-map key is
/// `commitment = Poseidon2::merge(shuffle_commitment, common_commitment)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecursiveAceCircuit {
    /// Number of ACE READ variables.
    pub num_inputs: usize,
    /// Number of ACE EVAL rows.
    pub num_eval_gates: usize,
    /// Encoded instruction stream length in base-field elements.
    pub stream_len: usize,
    /// Length in felts of the per-order stream prefix (constants + shuffle section).
    pub shuffle_prefix_len: usize,
    /// Poseidon2 digest of the per-order prefix.
    pub shuffle_commitment: Word,
    /// Poseidon2 digest of the order-invariant common section.
    pub common_commitment: Word,
    /// Registry leaf and advice-map key: `merge(shuffle_commitment, common_commitment)`.
    pub commitment: Word,
    /// Encoded ACE instruction stream consumed by `eval_circuit`.
    pub instructions: Vec<Felt>,
}

/// Factory for the recursive-verifier ACE circuits.
///
/// Builds the order-invariant factored composition once; encoding a circuit for a proof
/// order then costs only the shuffle assembly plus a short resumed hash. Use this over
/// [`build_recursive_verifier_ace_circuit`] whenever more than one order is needed —
/// registry construction visits every proof order and must not rebuild the composition
/// or re-hash the order-invariant stream sections per leaf.
pub struct RecursiveAceCircuitFactory {
    /// The generic factory owns all order-invariant caching (post-constants sponge
    /// state, common-section digest) and the construction cross-checks; this type only
    /// maps [`ProofOrder`]s onto instance-index permutations.
    inner: FactoredCircuitFactory<miden_core::field::QuadFelt>,
}

impl RecursiveAceCircuitFactory {
    /// Build the factored composition for the recursive-verifier configuration.
    ///
    /// Construction runs the generic factory's cross-checks on the canonical order
    /// (which for the recursive verifier is the identity instance permutation): the
    /// encode-only shuffle bytes against the assembled stream, and the resumed prefix
    /// hash against hashing the full prefix.
    pub fn new() -> Result<Self, AceError> {
        let factored = build_factored_multi_air_ace_circuit(RECURSIVE_VERIFIER_ACE_CONFIG)?;
        let inner = FactoredCircuitFactory::new(factored.into_inner())?;
        Ok(Self { inner })
    }

    /// Instance-index permutation for one proof order.
    fn order_indices(order: &ProofOrder) -> Vec<usize> {
        order.airs().iter().map(|air| air.instance_index()).collect()
    }

    /// Compute the registry leaf for one proof order without assembling its circuit.
    ///
    /// Encodes only the shuffle section into `buffer` and resumes the cached
    /// post-constants sponge state; see [`FactoredCircuitFactory::leaf_for_order`].
    /// Equality with [`Self::circuit_for_order`]'s `commitment` is pinned at
    /// construction (canonical order), in the config golden test (every order), and at
    /// regen time.
    pub fn leaf_for_order(
        &self,
        order: &ProofOrder,
        buffer: &mut ShuffleEncodeBuffer,
    ) -> Result<Word, AceError> {
        self.inner.leaf_for_order(&Self::order_indices(order), buffer)
    }

    /// Assemble, encode, and hash the circuit for one proof order.
    ///
    /// Only the shuffle section is hashed live (resuming from the cached post-constants
    /// sponge state); the common-section digest is reused. The resulting commitments are
    /// definitionally equal to hashing the full stream segments, which
    /// `recursive_ace_factory_and_factoring_match_the_one_shot_builder` pins per order.
    pub fn circuit_for_order(&self, order: &ProofOrder) -> Result<RecursiveAceCircuit, AceError> {
        let circuit = self.inner.circuit_for_order(&Self::order_indices(order))?;
        Ok(RecursiveAceCircuit {
            num_inputs: circuit.encoded.num_vars(),
            num_eval_gates: circuit.encoded.num_eval_rows(),
            stream_len: circuit.encoded.size_in_felt(),
            shuffle_prefix_len: circuit.shuffle_prefix_len,
            shuffle_commitment: circuit.shuffle_commitment,
            common_commitment: circuit.common_commitment,
            commitment: circuit.commitment,
            instructions: circuit.encoded.instructions().to_vec(),
        })
    }
}

/// The process-wide factory behind the registry-serving path. The registry tree cache in
/// `config` initialises from this same factory, so served entries and the cached tree
/// share one factored composition.
#[cfg(feature = "std")]
pub(crate) fn shared_recursive_factory() -> &'static RecursiveAceCircuitFactory {
    static FACTORY: std::sync::OnceLock<RecursiveAceCircuitFactory> = std::sync::OnceLock::new();
    FACTORY.get_or_init(|| {
        RecursiveAceCircuitFactory::new().expect("recursive-verifier ACE composition must build")
    })
}

/// One proof order's complete registry entry: the encoded circuit the verifier evaluates
/// and the leaf-plus-path that authenticates it in the registry tree.
///
/// Fields are private so an entry only exists once the constructor's leaf-equals-commitment
/// check has passed; consume it with [`Self::into_parts`].
pub struct RecursiveRegistryEntry {
    /// Encoded circuit for the order.
    circuit: RecursiveAceCircuit,
    /// Registry leaf: the circuit's commitment.
    leaf: Word,
    /// Authentication path from the leaf to the registry root.
    path: MerklePath,
}

impl RecursiveRegistryEntry {
    /// Consumes the entry into `(circuit, leaf, path)`.
    pub fn into_parts(self) -> (RecursiveAceCircuit, Word, MerklePath) {
        (self.circuit, self.leaf, self.path)
    }
}

/// Derives circuit, leaf, and path for one proof order from a single factory.
///
/// `std` uses the process-wide factory and the cached registry tree; without `std` one
/// factory and one tree are built for this call and serve both outputs, instead of one
/// build for the path and another for the circuit.
pub fn recursive_registry_entry(order: &ProofOrder) -> Result<RecursiveRegistryEntry, AceError> {
    #[cfg(feature = "std")]
    {
        let circuit = shared_recursive_factory().circuit_for_order(order)?;
        let (leaf, path) = crate::config::ace_registry_path(order.tag())
            .expect("proof-order tags always address registry slots");
        assert_eq!(
            circuit.commitment, leaf,
            "ACE registry tree drifted from the factory's circuits"
        );
        Ok(RecursiveRegistryEntry { circuit, leaf, path })
    }
    #[cfg(not(feature = "std"))]
    {
        let factory = RecursiveAceCircuitFactory::new()?;
        let circuit = factory.circuit_for_order(order)?;
        let tree = crate::config::build_miden_vm_ace_registry_with(&factory);
        let (leaf, path) = crate::config::registry_path_in(&tree, order.tag())
            .expect("proof-order tags always address registry slots");
        assert_eq!(
            circuit.commitment, leaf,
            "ACE registry tree drifted from the factory's circuits"
        );
        Ok(RecursiveRegistryEntry { circuit, leaf, path })
    }
}

/// Builds and encodes the recursive-verifier ACE circuit for one proof order.
///
/// Callers that need several orders should hold a [`RecursiveAceCircuitFactory`] instead;
/// this rebuilds the composition every call.
///
/// This path bypasses the factory and hashes both stream segments
/// from scratch, which is what makes it an independent oracle for the factory's cached
/// prefix state in
/// `recursive_ace_factory_and_factoring_match_the_one_shot_builder`. Reimplementing it
/// in terms of the factory would turn that test into a tautology and retire the only guard
/// on the sponge-resumption arithmetic.
pub fn build_recursive_verifier_ace_circuit(
    order: &ProofOrder,
) -> Result<RecursiveAceCircuit, AceError> {
    let factored = build_factored_multi_air_ace_circuit(RECURSIVE_VERIFIER_ACE_CONFIG)?;
    let circuit = factored.circuit_for_order(order)?;
    let encoded = circuit.to_ace()?;
    let instructions = encoded.instructions();
    let stream_len = encoded.size_in_felt();
    if stream_len != instructions.len() {
        return Err(AceError::InvalidInputLayout {
            message: format!(
                "ACE circuit stream length ({stream_len}) does not match instruction count ({})",
                instructions.len()
            ),
        });
    }
    if !stream_len.is_multiple_of(8) {
        return Err(AceError::InvalidInputLayout {
            message: "ACE circuit stream must be 8-felt aligned for adv_pipe".into(),
        });
    }

    let const_felts = encoded.num_constants() * miden_ace_codegen::EXT_DEGREE;
    let shuffle_prefix_len = const_felts + factored.num_shuffle_ops();
    if !shuffle_prefix_len.is_multiple_of(8) || shuffle_prefix_len >= stream_len {
        return Err(AceError::InvalidInputLayout {
            message: format!(
                "ACE shuffle prefix ({shuffle_prefix_len} of {stream_len} felts) must be a \
                 proper 8-felt-aligned stream prefix"
            ),
        });
    }

    let shuffle_commitment = Poseidon2::hash_elements(&instructions[..shuffle_prefix_len]);
    let common_commitment = Poseidon2::hash_elements(&instructions[shuffle_prefix_len..]);
    let commitment = Poseidon2::merge(&[shuffle_commitment, common_commitment]);

    Ok(RecursiveAceCircuit {
        num_inputs: encoded.num_vars(),
        num_eval_gates: encoded.num_eval_rows(),
        stream_len,
        shuffle_prefix_len,
        shuffle_commitment,
        common_commitment,
        commitment,
        instructions: instructions.to_vec(),
    })
}
