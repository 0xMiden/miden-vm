use alloc::vec::Vec;

use miden_ace_codegen::{
    AceConfig, AceError, FactoredCircuitFactory, InputLayout, LayoutKind, ShuffleEncodeBuffer,
};
use miden_core::{Felt, Word, crypto::hash::Eidos, field::QuadFelt};
use miden_crypto::merkle::MerklePath;

use super::multi_air::{FactoredMultiAirCircuit, build_factored_multi_air_ace_circuit};
use crate::{AIRS, MIDEN_AIR_COUNT, ProofOrder};

/// Number of quotient chunks the recursive verifier and its ACE circuit consume.
///
/// This is the same symbolic derivation the lifted-STARK prover and verifier use. Keeping it
/// executable matters even though the Miden relation currently derives eight chunks: the MASM
/// quotient-recomposition inputs are functions of this value, not of the coincidentally equal
/// blowup factor.
fn recursive_verifier_num_quotient_chunks() -> usize {
    let max_log_quotient_degree = AIRS
        .iter()
        .map(miden_crypto::stark::log_quotient_degree::<Felt, QuadFelt, _>)
        .max()
        .expect("the Miden AIR set is non-empty");
    1usize << max_log_quotient_degree
}

/// ACE codegen settings used by the recursive verifier's MASM evaluator.
fn recursive_verifier_ace_config() -> AceConfig {
    AceConfig {
        num_quotient_chunks: recursive_verifier_num_quotient_chunks(),
        layout: LayoutKind::Masm,
        num_airs: MIDEN_AIR_COUNT,
    }
}

/// Encoded recursive-verifier ACE circuit and the metadata consumed by MASM.
///
/// The instruction stream is factored into two `adv_pipe`-aligned segments:
/// - the per-order prefix `[constants | shuffle ops]` of `shuffle_prefix_len` felts, hashed into
///   `shuffle_commitment`;
/// - the order-invariant common section `[common ops | root padding]`, hashed into
///   `common_commitment` (the same digest for every proof order).
///
/// The registry leaf and advice-map key is
/// `commitment = Eidos::merge(shuffle_commitment, common_commitment)`.
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
    /// Eidos digest of the per-order prefix.
    pub shuffle_commitment: Word,
    /// Eidos digest of the order-invariant common section.
    pub common_commitment: Word,
    /// Registry leaf and advice-map key: `merge(shuffle_commitment, common_commitment)`.
    pub commitment: Word,
    /// Encoded ACE instruction stream consumed by `eval_circuit`.
    pub instructions: Vec<Felt>,
}

/// Factory for the recursive-verifier ACE circuits.
///
/// Builds the order-invariant factored composition once and reuses it while assembling the
/// order-specific circuits. Use this over [`build_recursive_verifier_ace_circuit`] whenever more
/// than one order is needed so registry construction does not rebuild the composition per leaf.
pub struct RecursiveAceCircuitFactory {
    /// The generic factory owns all order-invariant caching (post-constants chaining
    /// state, common-section digest) and the construction cross-checks; this type only
    /// maps [`ProofOrder`]s onto instance-index permutations.
    inner: FactoredCircuitFactory<QuadFelt>,
}

impl RecursiveAceCircuitFactory {
    /// Build the factored composition for the recursive-verifier configuration.
    ///
    /// Construction runs the generic Eidos factory's cross-checks on the canonical order:
    /// the encode-only shuffle bytes against the assembled stream, and the resumed prefix
    /// hash against hashing the full prefix.
    pub fn new() -> Result<Self, AceError> {
        let factored = build_factored_multi_air_ace_circuit(recursive_verifier_ace_config())?;
        let inner = FactoredCircuitFactory::new(factored.into_inner())?;
        Ok(Self { inner })
    }

    /// Instance-index permutation for one proof order.
    fn order_indices(order: &ProofOrder) -> Vec<usize> {
        order.airs().iter().map(|air| air.instance_index()).collect()
    }

    /// Quotient chunk count recorded in the factored circuit's actual READ layout.
    pub fn num_quotient_chunks(&self) -> usize {
        self.inner.factored().layout().counts.num_quotient_chunks
    }

    /// ACE READ layout shared by every recursive-verifier proof order.
    pub fn input_layout(&self) -> &InputLayout {
        self.inner.factored().layout()
    }

    /// Compute the registry leaf for one proof order without assembling its circuit.
    ///
    /// Encodes only the shuffle section and resumes the cached post-constants Eidos
    /// chaining word; equality with [`Self::circuit_for_order`] is pinned by the registry
    /// tests and the factory's construction oracle.
    pub fn leaf_for_order(
        &self,
        order: &ProofOrder,
        buffer: &mut ShuffleEncodeBuffer,
    ) -> Result<Word, AceError> {
        self.inner.leaf_for_order(&Self::order_indices(order), buffer)
    }

    /// Assemble, encode, and hash the circuit for one proof order.
    ///
    /// Only the shuffle section is hashed live; the order-invariant common-section Eidos
    /// digest is reused.
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

/// One proof order's complete registry entry: the encoded circuit the verifier evaluates and the
/// leaf-plus-path that authenticates it in the registry tree.
///
/// Fields are private so an entry only exists once the constructor's leaf-equals-commitment check
/// has passed; consume it with [`Self::into_parts`].
pub struct RecursiveRegistryEntry {
    circuit: RecursiveAceCircuit,
    leaf: Word,
    path: MerklePath,
}

impl RecursiveRegistryEntry {
    /// Consumes the entry into `(circuit, leaf, path)`.
    pub fn into_parts(self) -> (RecursiveAceCircuit, Word, MerklePath) {
        (self.circuit, self.leaf, self.path)
    }
}

/// Derives the circuit and its authentication path for one proof order from a single factory.
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
/// This path builds a fresh factored composition and hashes both stream segments from scratch. It
/// is retained as a determinism oracle for the reusable factory path.
pub fn build_recursive_verifier_ace_circuit(
    order: &ProofOrder,
) -> Result<RecursiveAceCircuit, AceError> {
    let factored = build_factored_multi_air_ace_circuit(recursive_verifier_ace_config())?;
    encode_recursive_circuit(&factored, order)
}

fn encode_recursive_circuit(
    factored: &FactoredMultiAirCircuit,
    order: &ProofOrder,
) -> Result<RecursiveAceCircuit, AceError> {
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

    let shuffle_commitment = Eidos::hash_elements(&instructions[..shuffle_prefix_len]);
    let common_commitment = Eidos::hash_elements(&instructions[shuffle_prefix_len..]);
    let commitment = Eidos::merge(&[shuffle_commitment, common_commitment]);

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
