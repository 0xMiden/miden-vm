use alloc::{
    string::{String, ToString},
    vec::Vec,
};

#[cfg(feature = "arbitrary")]
use proptest::prelude::*;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    crypto::hash::{Blake3_256, Poseidon2, Rpo256, Rpx256},
    deferred::{DeferredRoot, DeferredStateWire, MAX_PRECOMPILE_ROOTS, TRUE_DIGEST},
    serde::{
        BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        SliceReader,
    },
};

// HASH FUNCTION
// ================================================================================================

/// A hash function used during STARK proof generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true))
)]
#[repr(u8)]
pub enum HashFunction {
    /// BLAKE3 hash function with 256-bit output.
    Blake3_256 = 0x01,
    /// RPO hash function with 256-bit output.
    Rpo256 = 0x02,
    /// RPX hash function with 256-bit output.
    Rpx256 = 0x03,
    /// Poseidon2 hash function with 256-bit output.
    Poseidon2 = 0x04,
    /// Keccak hash function with 256-bit output.
    Keccak = 0x05,
}

impl HashFunction {
    /// Returns the collision resistance level (in bits) of this hash function.
    pub const fn collision_resistance(&self) -> u32 {
        match self {
            HashFunction::Blake3_256 => Blake3_256::COLLISION_RESISTANCE,
            HashFunction::Rpo256 => Rpo256::COLLISION_RESISTANCE,
            HashFunction::Rpx256 => Rpx256::COLLISION_RESISTANCE,
            HashFunction::Poseidon2 => Poseidon2::COLLISION_RESISTANCE,
            HashFunction::Keccak => 128,
        }
    }
}

/// Error type for invalid hash function strings.
#[derive(Debug, thiserror::Error)]
#[error(
    "invalid hash function '{hash_function}'. Valid options are: blake3-256, rpo, rpx, poseidon2, keccak"
)]
pub struct InvalidHashFunctionError {
    pub hash_function: String,
}

impl TryFrom<u8> for HashFunction {
    type Error = DeserializationError;

    fn try_from(repr: u8) -> Result<Self, Self::Error> {
        match repr {
            0x01 => Ok(Self::Blake3_256),
            0x02 => Ok(Self::Rpo256),
            0x03 => Ok(Self::Rpx256),
            0x04 => Ok(Self::Poseidon2),
            0x05 => Ok(Self::Keccak),
            _ => Err(DeserializationError::InvalidValue(format!(
                "the hash function representation {repr} is not valid!"
            ))),
        }
    }
}

impl TryFrom<&str> for HashFunction {
    type Error = InvalidHashFunctionError;

    fn try_from(hash_fn_str: &str) -> Result<Self, Self::Error> {
        match hash_fn_str {
            "blake3-256" => Ok(Self::Blake3_256),
            "rpo" => Ok(Self::Rpo256),
            "rpx" => Ok(Self::Rpx256),
            "poseidon2" => Ok(Self::Poseidon2),
            "keccak" => Ok(Self::Keccak),
            _ => Err(InvalidHashFunctionError { hash_function: hash_fn_str.to_string() }),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl Arbitrary for HashFunction {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        any::<u8>()
            .prop_map(|tag| match tag % 5 {
                0 => Self::Blake3_256,
                1 => Self::Rpo256,
                2 => Self::Rpx256,
                3 => Self::Poseidon2,
                _ => Self::Keccak,
            })
            .boxed()
    }
}

impl Serializable for HashFunction {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(*self as u8);
    }
}

impl Deserializable for HashFunction {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        source.read_u8()?.try_into()
    }
}

// PROOF ARTIFACTS
// ================================================================================================

/// Hard encoded-size and per-allocation safety ceiling for every STARK proof.
pub const MAX_STARK_PROOF_BYTES: usize = 64 * 1024 * 1024;

/// A Miden VM STARK proof together with its authenticated precompile obligation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VmProof {
    proof: StarkProof,
    precompile_root: DeferredRoot,
}

impl VmProof {
    /// Creates a VM proof artifact from its STARK proof and authenticated precompile root.
    pub const fn from_parts(proof: StarkProof, precompile_root: DeferredRoot) -> Self {
        Self { proof, precompile_root }
    }

    /// Returns the VM STARK proof.
    pub const fn proof(&self) -> &StarkProof {
        &self.proof
    }

    /// Returns the authenticated precompile obligation.
    pub const fn precompile_root(&self) -> DeferredRoot {
        self.precompile_root
    }

    /// Consumes this artifact and returns its STARK proof and authenticated precompile root.
    pub fn into_parts(self) -> (StarkProof, DeferredRoot) {
        (self.proof, self.precompile_root)
    }
}

impl Serializable for VmProof {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.proof.write_into(target);
        self.precompile_root.write_into(target);
    }
}

impl Deserializable for VmProof {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let proof = StarkProof::read_from(source)?;
        let precompile_root = DeferredRoot::read_from(source)?;
        Ok(Self::from_parts(proof, precompile_root))
    }

    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), bytes.len());
        Self::read_from(&mut reader)
    }

    fn min_serialized_size() -> usize {
        StarkProof::min_serialized_size() + DeferredRoot::min_serialized_size()
    }
}

/// A precompile STARK proof with the ordered, non-empty roots that form its aggregate root.
///
/// Verification folds the entire sequence. [`TRUE_DIGEST`] roots are omitted; order and duplicate
/// multiplicity are significant.
///
/// Binary decoding enforces the fixed root ceiling before reserving root storage.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PrecompileProof {
    proof: StarkProof,
    roots: Vec<DeferredRoot>,
}

impl PrecompileProof {
    /// Creates a precompile proof artifact after validating its constituent root shape.
    ///
    /// This does not verify the STARK proof.
    pub fn from_parts(
        proof: StarkProof,
        roots: Vec<DeferredRoot>,
    ) -> Result<Self, ExecutionProofError> {
        if roots.is_empty() {
            return Err(ExecutionProofError::EmptyPrecompileRoots);
        }
        if roots.len() > MAX_PRECOMPILE_ROOTS {
            return Err(ExecutionProofError::TooManyPrecompileRoots {
                roots: roots.len(),
                max: MAX_PRECOMPILE_ROOTS,
            });
        }
        if let Some(index) = roots.iter().position(|root| *root == TRUE_DIGEST) {
            return Err(ExecutionProofError::SettledPrecompileRoot { index });
        }

        Ok(Self { proof, roots })
    }

    /// Returns the precompile STARK proof.
    pub const fn proof(&self) -> &StarkProof {
        &self.proof
    }

    /// Returns all constituent roots in fold order.
    pub fn roots(&self) -> &[DeferredRoot] {
        &self.roots
    }

    /// Returns the aggregate root obtained by folding all constituent roots in order.
    pub fn aggregate_root(&self) -> DeferredRoot {
        self.roots
            .iter()
            .copied()
            .reduce(crate::deferred::fold_deferred_root)
            .expect("PrecompileProof roots are non-empty by construction")
    }

    /// Consumes this artifact and returns its STARK proof and ordered constituent roots.
    pub fn into_parts(self) -> (StarkProof, Vec<DeferredRoot>) {
        (self.proof, self.roots)
    }

    fn covers<'a>(&self, required_roots: impl Iterator<Item = &'a DeferredRoot>) -> bool {
        let mut proof_roots = self.roots.iter();
        required_roots
            .filter(|root| **root != TRUE_DIGEST)
            .all(|required| proof_roots.any(|provided| provided == required))
    }
}

impl Serializable for PrecompileProof {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.proof.write_into(target);
        self.roots.write_into(target);
    }
}

impl Deserializable for PrecompileProof {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let proof = StarkProof::read_from(source)?;
        let root_count = source.read_usize()?;
        if root_count > MAX_PRECOMPILE_ROOTS {
            return Err(invalid_proof_shape(ExecutionProofError::TooManyPrecompileRoots {
                roots: root_count,
                max: MAX_PRECOMPILE_ROOTS,
            }));
        }
        let roots = source
            .read_many_iter::<DeferredRoot>(root_count)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { proof, roots })
    }

    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), bytes.len());
        Self::read_from(&mut reader)
    }

    fn min_serialized_size() -> usize {
        StarkProof::min_serialized_size()
            + usize::min_serialized_size()
            + DeferredRoot::min_serialized_size()
    }
}

const DEFERRED_PROOF_DISCRIMINANT: u8 = 0;
const COMPLETE_PROOF_DISCRIMINANT: u8 = 1;

/// A Miden VM execution proof, either awaiting precompile proving or complete.
///
/// The public variants may represent inconsistent artifacts. Checked constructors are conveniences;
/// only full verification establishes proof validity.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ExecutionProof {
    /// The VM STARK is available and its passive singleton precompile wire remains to be proved.
    Deferred {
        vm: VmProof,
        precompile: DeferredStateWire,
    },
    /// All proof work is complete. `None` means the VM authenticated [`TRUE_DIGEST`].
    Complete {
        vm: VmProof,
        precompile: Option<PrecompileProof>,
    },
}

impl ExecutionProof {
    /// Creates a deferred proof after checking that the VM authenticated outstanding work.
    ///
    /// The passive wire is not hydrated or semantically validated here.
    pub fn new_deferred(
        vm: VmProof,
        precompile: DeferredStateWire,
    ) -> Result<Self, ExecutionProofError> {
        validate_deferred(&vm)?;
        Ok(Self::Deferred { vm, precompile })
    }

    /// Creates a complete proof after checking its optional precompile proof covers the VM root.
    ///
    /// This only checks artifact structure; it does not verify either STARK proof.
    pub fn new_complete(
        vm: VmProof,
        precompile: Option<PrecompileProof>,
    ) -> Result<Self, ExecutionProofError> {
        validate_complete(&vm, precompile.as_ref())?;
        Ok(Self::Complete { vm, precompile })
    }

    /// Checks that this proof's artifacts have a compatible structure.
    ///
    /// This does not cryptographically verify either STARK proof.
    pub fn validate_structure(&self) -> Result<(), ExecutionProofError> {
        match self {
            Self::Deferred { vm, .. } => validate_deferred(vm),
            Self::Complete { vm, precompile } => validate_complete(vm, precompile.as_ref()),
        }
    }

    /// Returns whether this value has the [`Self::Complete`] representation.
    ///
    /// This is a shape check only. Public variants may be inconsistent; use full verification to
    /// establish validity and determine whether an authenticated obligation remains outstanding.
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete { .. })
    }

    /// Returns the VM proof artifact in either state.
    pub const fn vm(&self) -> &VmProof {
        match self {
            Self::Deferred { vm, .. } | Self::Complete { vm, .. } => vm,
        }
    }

    /// Returns the completed precompile proof, if this is a complete proof that carries one.
    pub const fn precompile(&self) -> Option<&PrecompileProof> {
        match self {
            Self::Complete { precompile, .. } => precompile.as_ref(),
            Self::Deferred { .. } => None,
        }
    }

    /// Attaches a compatible precompile proof to a deferred proof.
    pub fn complete(self, precompile: PrecompileProof) -> Result<Self, ExecutionProofError> {
        let Self::Deferred { vm, .. } = self else {
            return Err(ExecutionProofError::AlreadyComplete);
        };
        validate_deferred(&vm)?;
        validate_complete(&vm, Some(&precompile))?;
        Ok(Self::Complete { vm, precompile: Some(precompile) })
    }

    /// Encodes either state canonically.
    ///
    /// Encoding preserves the public enum representation and does not establish proof validity.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            Self::Deferred { vm, precompile } => {
                bytes.write_u8(DEFERRED_PROOF_DISCRIMINANT);
                vm.write_into(&mut bytes);
                precompile.write_into(&mut bytes);
            },
            Self::Complete { vm, precompile } => {
                bytes.write_u8(COMPLETE_PROOF_DISCRIMINANT);
                vm.write_into(&mut bytes);
                precompile.write_into(&mut bytes);
            },
        }
        bytes
    }

    /// Decodes an execution proof without hydrating passive deferred wire.
    ///
    /// Decoding establishes bounded canonical transport syntax, not proof validity.
    pub fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), bytes.len());
        let discriminant = reader.read_u8()?;
        if !matches!(discriminant, DEFERRED_PROOF_DISCRIMINANT | COMPLETE_PROOF_DISCRIMINANT) {
            return Err(DeserializationError::InvalidValue(format!(
                "invalid execution proof discriminant {discriminant}"
            )));
        }

        let vm = VmProof::read_from(&mut reader)?;
        let proof = match discriminant {
            DEFERRED_PROOF_DISCRIMINANT => {
                let precompile = DeferredStateWire::read_from(&mut reader)?;
                Self::Deferred { vm, precompile }
            },
            COMPLETE_PROOF_DISCRIMINANT => {
                let precompile = Option::<PrecompileProof>::read_from(&mut reader)?;
                Self::Complete { vm, precompile }
            },
            _ => unreachable!("execution proof discriminant was checked before decoding"),
        };

        if reader.has_more_bytes() {
            return Err(DeserializationError::InvalidValue(
                "extra bytes after execution proof payload".into(),
            ));
        }
        if proof.to_bytes() != bytes {
            return Err(DeserializationError::InvalidValue(
                "execution proof bytes are not canonically encoded".into(),
            ));
        }

        Ok(proof)
    }
}

/// Structural errors returned while constructing or composing proof artifacts.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecutionProofError {
    /// A precompile proof must identify at least one constituent root.
    #[error("a precompile proof must contain at least one constituent root")]
    EmptyPrecompileRoots,
    /// The ordered root sequence exceeds the hard allocation and folding safety ceiling.
    #[error("precompile proof contains too many roots: found {roots}, maximum is {max}")]
    TooManyPrecompileRoots { roots: usize, max: usize },
    /// Settled roots are omitted from precompile proof constituent roots.
    #[error("precompile proof constituent root at index {index} is already settled")]
    SettledPrecompileRoot { index: usize },
    /// A deferred proof must authenticate outstanding precompile work.
    #[error("a deferred execution proof cannot authenticate TRUE_DIGEST")]
    DeferredTrueRoot,
    /// A precompile proof was supplied for an already settled VM obligation.
    #[error("a precompile proof was supplied for an already settled VM obligation")]
    UnexpectedPrecompileProof,
    /// A non-empty VM obligation had no precompile proof.
    #[error("a precompile proof is required for a non-empty VM obligation")]
    MissingPrecompileProof,
    /// The proof roots do not cover the VM obligations as an ordered subsequence.
    #[error("precompile proof roots do not cover VM obligations in order")]
    InsufficientPrecompileRootCoverage,
    /// Only a deferred execution proof can be completed.
    #[error("the execution proof is already complete")]
    AlreadyComplete,
}

fn validate_deferred(vm: &VmProof) -> Result<(), ExecutionProofError> {
    if vm.precompile_root == TRUE_DIGEST {
        return Err(ExecutionProofError::DeferredTrueRoot);
    }
    Ok(())
}

fn validate_complete(
    vm: &VmProof,
    precompile: Option<&PrecompileProof>,
) -> Result<(), ExecutionProofError> {
    validate_precompile_coverage(core::iter::once(&vm.precompile_root), precompile)
}

fn validate_precompile_coverage<'a>(
    required_roots: impl Iterator<Item = &'a DeferredRoot>,
    precompile: Option<&PrecompileProof>,
) -> Result<(), ExecutionProofError> {
    let mut required_roots = required_roots.filter(|root| **root != TRUE_DIGEST).peekable();

    if required_roots.peek().is_none() {
        return if precompile.is_none() {
            Ok(())
        } else {
            Err(ExecutionProofError::UnexpectedPrecompileProof)
        };
    }

    let precompile = precompile.ok_or(ExecutionProofError::MissingPrecompileProof)?;
    if precompile.covers(required_roots) {
        Ok(())
    } else {
        Err(ExecutionProofError::InsufficientPrecompileRootCoverage)
    }
}

fn invalid_proof_shape(error: ExecutionProofError) -> DeserializationError {
    DeserializationError::InvalidValue(error.to_string())
}

// STARK PROOF
// ================================================================================================

/// A serialized STARK proof and the hash function used during proof generation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct StarkProof {
    bytes: Vec<u8>,
    hash_fn: HashFunction,
}

impl StarkProof {
    /// Creates a new instance of [StarkProof] from proof bytes and hash function.
    pub const fn new(bytes: Vec<u8>, hash_fn: HashFunction) -> Self {
        Self { bytes, hash_fn }
    }

    /// Returns the serialized STARK proof bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the hash function used during proof generation process.
    pub const fn hash_fn(&self) -> HashFunction {
        self.hash_fn
    }

    /// Returns the serialized STARK proof bytes and hash function.
    pub fn into_parts(self) -> (Vec<u8>, HashFunction) {
        (self.bytes, self.hash_fn)
    }
}

impl Serializable for StarkProof {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.bytes.write_into(target);
        self.hash_fn.write_into(target);
    }
}

impl Deserializable for StarkProof {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let byte_count = source.read_usize()?;
        if byte_count > MAX_STARK_PROOF_BYTES {
            return Err(DeserializationError::InvalidValue(format!(
                "STARK proof contains too many bytes: found {byte_count}, maximum is {MAX_STARK_PROOF_BYTES}"
            )));
        }
        let bytes = source.read_many_iter::<u8>(byte_count)?.collect::<Result<Vec<_>, _>>()?;
        let hash_fn = HashFunction::read_from(source)?;
        Ok(Self::new(bytes, hash_fn))
    }

    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), bytes.len());
        Self::read_from(&mut reader)
    }

    fn min_serialized_size() -> usize {
        Vec::<u8>::min_serialized_size() + HashFunction::min_serialized_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Felt,
        deferred::{DeferredState, Node, PrecompileWitness},
        serde::ByteWriter,
    };

    fn dummy_stark_proof(bytes: &[u8]) -> StarkProof {
        StarkProof::new(bytes.to_vec(), HashFunction::Blake3_256)
    }

    fn root(value: u64) -> DeferredRoot {
        [Felt::new(value).unwrap(), Felt::ZERO, Felt::ZERO, Felt::ZERO].into()
    }

    fn vm_proof(precompile_root: DeferredRoot) -> VmProof {
        VmProof::from_parts(dummy_stark_proof(&[1]), precompile_root)
    }

    fn precompile_proof(roots: &[DeferredRoot]) -> PrecompileProof {
        PrecompileProof::from_parts(dummy_stark_proof(&[2]), roots.to_vec()).unwrap()
    }

    fn wire() -> (DeferredStateWire, DeferredRoot) {
        let mut state = DeferredState::default();
        let statement = state.register(Node::and(TRUE_DIGEST, TRUE_DIGEST)).unwrap();
        state.log_statement(statement).unwrap();
        let witness = PrecompileWitness::new(state).unwrap();
        (witness.state().to_wire().unwrap(), witness.root())
    }

    fn assert_same_execution_proof(actual: &ExecutionProof, expected: &ExecutionProof) {
        match (actual, expected) {
            (
                ExecutionProof::Deferred {
                    vm: actual_vm,
                    precompile: actual_precompile,
                },
                ExecutionProof::Deferred {
                    vm: expected_vm,
                    precompile: expected_precompile,
                },
            ) => {
                assert_eq!(actual_vm.to_bytes(), expected_vm.to_bytes());
                assert_eq!(actual_precompile.to_bytes(), expected_precompile.to_bytes());
            },
            (
                ExecutionProof::Complete {
                    vm: actual_vm,
                    precompile: actual_precompile,
                },
                ExecutionProof::Complete {
                    vm: expected_vm,
                    precompile: expected_precompile,
                },
            ) => {
                assert_eq!(actual_vm.to_bytes(), expected_vm.to_bytes());
                match (actual_precompile, expected_precompile) {
                    (Some(actual), Some(expected)) => {
                        assert_eq!(actual.to_bytes(), expected.to_bytes());
                    },
                    (None, None) => {},
                    _ => panic!("complete proof precompile representations differ"),
                }
            },
            _ => panic!("execution proof variants differ"),
        }
    }

    fn round_trip_execution_proof(proof: &ExecutionProof) {
        let bytes = proof.to_bytes();
        let decoded = ExecutionProof::read_from_bytes(&bytes).unwrap();
        assert_same_execution_proof(&decoded, proof);
        assert_eq!(decoded.to_bytes(), bytes);
    }

    #[test]
    fn proof_minimum_serialized_sizes_match_shortest_canonical_encodings() {
        let stark = StarkProof::new(Vec::new(), HashFunction::Blake3_256);
        assert_eq!(StarkProof::min_serialized_size(), stark.to_bytes().len());
        assert_eq!(StarkProof::min_serialized_size(), 2);

        let vm = VmProof::from_parts(stark, TRUE_DIGEST);
        assert_eq!(VmProof::min_serialized_size(), vm.to_bytes().len());
        assert_eq!(VmProof::min_serialized_size(), 34);

        let precompile = PrecompileProof::from_parts(
            StarkProof::new(Vec::new(), HashFunction::Blake3_256),
            alloc::vec![root(1)],
        )
        .unwrap();
        assert_eq!(PrecompileProof::min_serialized_size(), precompile.to_bytes().len());
        assert_eq!(PrecompileProof::min_serialized_size(), 35);

        let proofs = alloc::vec![precompile.clone(), precompile];
        let bytes = proofs.to_bytes();
        assert_eq!(bytes.len(), 71);
        let decoded =
            Vec::<PrecompileProof>::read_from_bytes_with_budget(&bytes, bytes.len()).unwrap();
        assert_eq!(decoded.to_bytes(), bytes);
    }

    #[test]
    fn stark_proof_decoder_rejects_oversized_length_before_payload() {
        let mut bytes = Vec::new();
        bytes.write_usize(MAX_STARK_PROOF_BYTES + 1);

        let error = StarkProof::read_from_bytes(&bytes).unwrap_err();
        let DeserializationError::InvalidValue(message) = error else {
            panic!("expected excessive STARK proof length to be rejected")
        };
        assert!(message.contains("STARK proof contains too many bytes"));
    }

    #[test]
    fn precompile_proof_decoder_rejects_oversized_root_count_before_payload() {
        let mut bytes = dummy_stark_proof(&[2]).to_bytes();
        bytes.write_usize(MAX_PRECOMPILE_ROOTS + 1);

        let error = PrecompileProof::read_from_bytes(&bytes).unwrap_err();
        let DeserializationError::InvalidValue(message) = error else {
            panic!("expected excessive root count to be rejected")
        };
        assert!(message.contains("precompile proof contains too many roots"));
    }

    #[test]
    fn proof_artifacts_round_trip_canonically() {
        let stark = dummy_stark_proof(&[1, 2, 3]);
        let stark_bytes = stark.to_bytes();
        let decoded_stark = StarkProof::read_from_bytes(&stark_bytes).unwrap();
        assert_eq!(decoded_stark.to_bytes(), stark_bytes);

        let vm = vm_proof(root(3));
        let vm_bytes = vm.to_bytes();
        let decoded_vm = VmProof::read_from_bytes(&vm_bytes).unwrap();
        assert_eq!(decoded_vm.to_bytes(), vm_bytes);

        let precompile = precompile_proof(&[root(1), root(2)]);
        let precompile_bytes = precompile.to_bytes();
        let decoded_precompile = PrecompileProof::read_from_bytes(&precompile_bytes).unwrap();
        assert_eq!(decoded_precompile.to_bytes(), precompile_bytes);

        let (precompile_wire, wire_root) = wire();
        let proofs = [
            ExecutionProof::Deferred {
                vm: vm_proof(wire_root),
                precompile: precompile_wire,
            },
            ExecutionProof::Complete {
                vm: vm_proof(TRUE_DIGEST),
                precompile: None,
            },
            ExecutionProof::Complete {
                vm: vm_proof(root(2)),
                precompile: Some(precompile_proof(&[root(1), root(2), root(3)])),
            },
        ];
        for proof in &proofs {
            round_trip_execution_proof(proof);
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn proof_artifact_serde_round_trips_preserve_representations() {
        fn round_trip<T>(value: &T) -> T
        where
            T: Serialize + for<'de> Deserialize<'de>,
        {
            let encoded = serde_json::to_vec(value).unwrap();
            serde_json::from_slice(&encoded).unwrap()
        }

        let stark = dummy_stark_proof(&[1, 2, 3]);
        assert_eq!(round_trip(&stark).to_bytes(), stark.to_bytes());

        let vm = vm_proof(root(1));
        assert_eq!(round_trip(&vm).to_bytes(), vm.to_bytes());

        let precompile = PrecompileProof {
            proof: dummy_stark_proof(&[2]),
            roots: alloc::vec![root(1), TRUE_DIGEST],
        };
        assert_eq!(round_trip(&precompile).to_bytes(), precompile.to_bytes());

        let (precompile_wire, _) = wire();
        let deferred = ExecutionProof::Deferred {
            vm: vm_proof(TRUE_DIGEST),
            precompile: precompile_wire,
        };
        let decoded_deferred = round_trip(&deferred);
        assert_same_execution_proof(&decoded_deferred, &deferred);

        let complete = ExecutionProof::Complete {
            vm: vm_proof(TRUE_DIGEST),
            precompile: Some(precompile),
        };
        let decoded_complete = round_trip(&complete);
        assert_same_execution_proof(&decoded_complete, &complete);
    }

    #[test]
    fn execution_proof_transport_rejects_bad_discriminants_trailing_bytes_and_bounds() {
        assert!(ExecutionProof::read_from_bytes(&[9]).is_err());

        let mut trailing = ExecutionProof::Complete {
            vm: vm_proof(TRUE_DIGEST),
            precompile: None,
        }
        .to_bytes();
        trailing.push(0);
        assert!(ExecutionProof::read_from_bytes(&trailing).is_err());

        let canonical = ExecutionProof::Complete {
            vm: vm_proof(TRUE_DIGEST),
            precompile: None,
        }
        .to_bytes();
        assert_eq!(canonical[1], 3, "one STARK byte uses a one-byte vint encoding");
        let mut noncanonical = alloc::vec![canonical[0], 0];
        noncanonical.extend_from_slice(&1u64.to_le_bytes());
        noncanonical.extend_from_slice(&canonical[2..]);
        let error = ExecutionProof::read_from_bytes(&noncanonical).unwrap_err();
        assert!(
            matches!(error, DeserializationError::InvalidValue(message) if message.contains("not canonically encoded"))
        );

        let mut oversized_proof = Vec::new();
        oversized_proof.write_u8(COMPLETE_PROOF_DISCRIMINANT);
        oversized_proof.write_usize(usize::MAX);
        assert!(ExecutionProof::read_from_bytes(&oversized_proof).is_err());
    }
}
