use alloc::{
    collections::BTreeSet,
    string::{String, ToString},
    vec::Vec,
};

#[cfg(feature = "arbitrary")]
use proptest::prelude::*;

use crate::{
    Word,
    crypto::hash::{Blake3_256, Poseidon2, Rpo256, Rpx256},
    deferred::{DeferredRoot, DeferredStateWire, MAX_PRECOMPILE_ROOTS},
    serde::{
        BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        SliceReader,
    },
};

// CONSTANTS
// ================================================================================================

/// Hard encoded-size and per-allocation safety ceiling for every STARK proof.
pub const MAX_STARK_PROOF_BYTES: usize = 64 * 1024 * 1024;

const DEFERRED_PROOF_DISCRIMINANT: u8 = 0;
const COMPLETE_PROOF_DISCRIMINANT: u8 = 1;

/// The recursive VM verifier root declared by proofs from the current prover.
pub const CURRENT_VM_VERIFIER_ROOT: Word = Word::new([
    crate::Felt::new_unchecked(4465259443638079335),
    crate::Felt::new_unchecked(17418505147041915588),
    crate::Felt::new_unchecked(17745366771765383900),
    crate::Felt::new_unchecked(5300166905943834781),
]);
/// The recursive precompile verifier root declared by proofs from the current prover.
pub const CURRENT_PVM_VERIFIER_ROOT: Word = Word::new([
    crate::Felt::new_unchecked(2947623151120287659),
    crate::Felt::new_unchecked(14078382412112533261),
    crate::Felt::new_unchecked(16121817997513902205),
    crate::Felt::new_unchecked(3291147646890284397),
]);

// HASH FUNCTION
// ================================================================================================

/// A hash function used during STARK proof generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serialization_macros::serialization_test
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

/// A Miden VM STARK proof together with its authenticated precompile obligation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmProof {
    pub proof: StarkProof,
    pub precompile_root: DeferredRoot,
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
        Ok(Self { proof, precompile_root })
    }

    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), bytes.len());
        let proof = Self::read_from(&mut reader)?;
        if reader.has_more_bytes() {
            return Err(DeserializationError::InvalidValue(
                "extra bytes after VM proof payload".into(),
            ));
        }
        Ok(proof)
    }

    fn min_serialized_size() -> usize {
        StarkProof::min_serialized_size() + DeferredRoot::min_serialized_size()
    }
}

/// A precompile STARK proof with its ordered constituent roots.
///
/// Binary decoding enforces the fixed root ceiling before reserving root storage, but otherwise
/// preserves the encoded artifact shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecompileProof {
    pub proof: StarkProof,
    pub roots: Vec<DeferredRoot>,
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
            return Err(DeserializationError::InvalidValue(format!(
                "precompile proof contains too many roots: found {root_count}, maximum is {MAX_PRECOMPILE_ROOTS}"
            )));
        }
        let roots = source
            .read_many_iter::<DeferredRoot>(root_count)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { proof, roots })
    }

    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), bytes.len());
        let proof = Self::read_from(&mut reader)?;
        if reader.has_more_bytes() {
            return Err(DeserializationError::InvalidValue(
                "extra bytes after precompile proof payload".into(),
            ));
        }
        Ok(proof)
    }

    fn min_serialized_size() -> usize {
        StarkProof::min_serialized_size() + usize::min_serialized_size()
    }
}

/// The transport format and recursive verifier roots declared by an execution proof.
///
/// Verifier roots are listed in chronological order, with the newest root last. Root order does
/// not affect compatibility checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionProofCompatibility {
    format: u8,
    vm_verifier_roots: Vec<Word>,
    pvm_verifier_roots: Vec<Word>,
}

impl ExecutionProofCompatibility {
    /// The first execution proof transport format.
    pub const FORMAT_V1: u8 = 1;

    /// Creates a proof compatibility declaration for format `1`.
    ///
    /// # Errors
    ///
    /// Returns an error if either verifier root list contains duplicates.
    pub fn new(
        vm_verifier_roots: Vec<Word>,
        pvm_verifier_roots: Vec<Word>,
    ) -> Result<Self, ExecutionProofCompatibilityError> {
        if has_duplicate(&vm_verifier_roots) {
            return Err(ExecutionProofCompatibilityError::DuplicateVmVerifierRoot);
        }
        if has_duplicate(&pvm_verifier_roots) {
            return Err(ExecutionProofCompatibilityError::DuplicatePvmVerifierRoot);
        }

        Ok(Self {
            format: Self::FORMAT_V1,
            vm_verifier_roots,
            pvm_verifier_roots,
        })
    }

    /// Returns the compatibility declared by proofs produced by the current prover.
    pub fn current() -> Self {
        Self::new(alloc::vec![CURRENT_VM_VERIFIER_ROOT], alloc::vec![CURRENT_PVM_VERIFIER_ROOT])
            .expect("current execution proof compatibility must not contain duplicate roots")
    }

    /// Returns the transport format.
    pub const fn format(&self) -> u8 {
        self.format
    }

    /// Returns the VM verifier roots which can be used to verify this proof.
    ///
    /// The roots are unique and listed in chronological order with the most recent verifier listed
    /// last.
    pub fn vm_verifier_roots(&self) -> &[Word] {
        &self.vm_verifier_roots
    }

    /// Returns the precompile VM verifier roots which can be used to verify the precompile proof
    /// associated with this execution proof, if any.
    ///
    /// The roots are unique and listed in chronological order with the most recent verifier listed
    /// last.
    pub fn pvm_verifier_roots(&self) -> &[Word] {
        &self.pvm_verifier_roots
    }
}

/// Errors returned while constructing execution proof compatibility metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExecutionProofCompatibilityError {
    /// The VM verifier root list contains a duplicate.
    #[error("VM verifier roots must not contain duplicates")]
    DuplicateVmVerifierRoot,
    /// The precompile VM verifier root list contains a duplicate.
    #[error("PVM verifier roots must not contain duplicates")]
    DuplicatePvmVerifierRoot,
}

/// The state of precompile work associated with an execution proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrecompileStatus {
    /// The VM made no precompile requests.
    Empty,
    /// The VM made precompile requests which have not been proven.
    Deferred(DeferredStateWire),
    /// The VM made precompile requests and their proof is available.
    Proven(PrecompileProof),
}

/// A versioned Miden VM execution proof.
///
/// This type preserves proof artifacts without establishing their validity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionProof {
    compatibility: ExecutionProofCompatibility,
    vm: VmProof,
    precompile: PrecompileStatus,
}

impl ExecutionProof {
    /// Creates an execution proof with the compatibility declared by the current prover.
    pub fn new(vm: VmProof, precompile: PrecompileStatus) -> Self {
        Self::from_parts(ExecutionProofCompatibility::current(), vm, precompile)
    }

    /// Creates an execution proof from its compatibility, VM proof, and precompile state.
    pub const fn from_parts(
        compatibility: ExecutionProofCompatibility,
        vm: VmProof,
        precompile: PrecompileStatus,
    ) -> Self {
        Self { compatibility, vm, precompile }
    }

    /// Returns the compatibility declared by this proof.
    pub const fn compatibility(&self) -> &ExecutionProofCompatibility {
        &self.compatibility
    }

    /// Returns the VM proof.
    pub const fn vm(&self) -> &VmProof {
        &self.vm
    }

    /// Returns the state of the precompile work.
    pub const fn precompile(&self) -> &PrecompileStatus {
        &self.precompile
    }

    /// Splits this proof into its compatibility, VM proof, and precompile state.
    pub fn into_parts(self) -> (ExecutionProofCompatibility, VmProof, PrecompileStatus) {
        (self.compatibility, self.vm, self.precompile)
    }

    /// Returns whether this proof has completed its lifecycle transition.
    pub const fn is_complete(&self) -> bool {
        !matches!(self.precompile, PrecompileStatus::Deferred(_))
    }

    /// Returns whether this proof contains precompile work.
    pub const fn has_precompiles(&self) -> bool {
        !matches!(self.precompile, PrecompileStatus::Empty)
    }

    /// Transitions a deferred proof to complete by attaching a precompile proof.
    ///
    /// This method does not verify the precompile proof or check it against the VM proof. The
    /// verifier performs those checks.
    pub fn complete(mut self, precompile: PrecompileProof) -> Result<Self, ExecutionProofError> {
        if !matches!(self.precompile, PrecompileStatus::Deferred(_)) {
            return Err(ExecutionProofError::AlreadyComplete);
        }
        self.precompile = PrecompileStatus::Proven(precompile);
        Ok(self)
    }

    /// Encodes this proof canonically.
    pub fn to_bytes(&self) -> Vec<u8> {
        Serializable::to_bytes(self)
    }

    /// Decodes a complete versioned proof from canonical bytes.
    pub fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), bytes.len());
        let proof = <Self as Deserializable>::read_from(&mut reader)?;

        if reader.has_more_bytes() {
            return Err(DeserializationError::InvalidValue(
                "extra bytes after versioned proof payload".into(),
            ));
        }
        if proof.to_bytes() != bytes {
            return Err(DeserializationError::InvalidValue(
                "versioned proof bytes are not canonically encoded".into(),
            ));
        }

        Ok(proof)
    }
}

impl Serializable for ExecutionProof {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.compatibility.format);
        self.compatibility.vm_verifier_roots.write_into(target);
        self.compatibility.pvm_verifier_roots.write_into(target);
        self.write_into_v1(target);
    }
}

impl Deserializable for ExecutionProof {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let format = source.read_u8()?;
        if format != ExecutionProofCompatibility::FORMAT_V1 {
            return Err(DeserializationError::InvalidValue(format!(
                "unsupported execution proof format {format}"
            )));
        }

        let vm_verifier_roots = Vec::<Word>::read_from(source)?;
        let pvm_verifier_roots = Vec::<Word>::read_from(source)?;
        let compatibility = ExecutionProofCompatibility::new(vm_verifier_roots, pvm_verifier_roots)
            .map_err(|error| DeserializationError::InvalidValue(error.to_string()))?;

        Self::read_from_v1(source, compatibility)
    }

    fn min_serialized_size() -> usize {
        u8::min_serialized_size()
            + Vec::<Word>::min_serialized_size()
            + Vec::<Word>::min_serialized_size()
            + ExecutionProof::min_serialized_size_v1()
    }
}

impl ExecutionProof {
    fn write_into_v1<W: ByteWriter>(&self, target: &mut W) {
        match &self.precompile {
            PrecompileStatus::Deferred(precompile) => {
                target.write_u8(DEFERRED_PROOF_DISCRIMINANT);
                self.vm.write_into(target);
                precompile.write_into(target);
            },
            PrecompileStatus::Empty => {
                target.write_u8(COMPLETE_PROOF_DISCRIMINANT);
                self.vm.write_into(target);
                Option::<PrecompileProof>::None.write_into(target);
            },
            PrecompileStatus::Proven(precompile) => {
                target.write_u8(COMPLETE_PROOF_DISCRIMINANT);
                self.vm.write_into(target);
                Some(precompile).write_into(target);
            },
        }
    }

    fn read_from_v1<R: ByteReader>(
        source: &mut R,
        compatibility: ExecutionProofCompatibility,
    ) -> Result<Self, DeserializationError> {
        let discriminant = source.read_u8()?;
        if !matches!(discriminant, DEFERRED_PROOF_DISCRIMINANT | COMPLETE_PROOF_DISCRIMINANT) {
            return Err(DeserializationError::InvalidValue(format!(
                "invalid execution proof discriminant {discriminant}"
            )));
        }

        let vm = VmProof::read_from(source)?;
        let precompile = match discriminant {
            DEFERRED_PROOF_DISCRIMINANT => {
                PrecompileStatus::Deferred(DeferredStateWire::read_from(source)?)
            },
            COMPLETE_PROOF_DISCRIMINANT => match Option::<PrecompileProof>::read_from(source)? {
                Some(precompile) => PrecompileStatus::Proven(precompile),
                None => PrecompileStatus::Empty,
            },
            _ => unreachable!("execution proof discriminant was checked before decoding"),
        };

        Ok(Self { compatibility, vm, precompile })
    }

    fn min_serialized_size_v1() -> usize {
        u8::min_serialized_size()
            + VmProof::min_serialized_size()
            + Option::<PrecompileProof>::min_serialized_size()
    }
}

/// Lifecycle errors returned while transitioning an execution proof.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExecutionProofError {
    /// Only a deferred execution proof can be completed.
    #[error("the execution proof is already complete")]
    AlreadyComplete,
}

// STARK PROOF
// ================================================================================================

/// A serialized STARK proof and the hash function used during proof generation.
#[derive(Debug, Clone, PartialEq, Eq)]
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

// HELPER FUNCTIONS
// ================================================================================================

fn has_duplicate(roots: &[Word]) -> bool {
    let mut unique = BTreeSet::new();
    roots.iter().any(|root| !unique.insert(*root))
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Felt,
        deferred::{DeferredState, Node, PrecompileWitness, TRUE_DIGEST},
        serde::ByteWriter,
    };

    fn dummy_stark_proof(bytes: &[u8]) -> StarkProof {
        StarkProof::new(bytes.to_vec(), HashFunction::Blake3_256)
    }

    fn root(value: u64) -> DeferredRoot {
        [Felt::new(value).unwrap(), Felt::ZERO, Felt::ZERO, Felt::ZERO].into()
    }

    fn vm_proof(precompile_root: DeferredRoot) -> VmProof {
        VmProof {
            proof: dummy_stark_proof(&[1]),
            precompile_root,
        }
    }

    fn precompile_proof(roots: &[DeferredRoot]) -> PrecompileProof {
        PrecompileProof {
            proof: dummy_stark_proof(&[2]),
            roots: roots.to_vec(),
        }
    }

    fn wire() -> (DeferredStateWire, DeferredRoot) {
        let mut state = DeferredState::default();
        let statement = state.register(Node::and(TRUE_DIGEST, TRUE_DIGEST)).unwrap();
        state.log_statement(statement).unwrap();
        let witness = PrecompileWitness::new(state).unwrap();
        (witness.state().to_wire().unwrap(), witness.roots()[0])
    }

    fn versioned(vm: VmProof, precompile: PrecompileStatus) -> ExecutionProof {
        ExecutionProof::from_parts(
            ExecutionProofCompatibility::new(vec![root(11), root(12)], vec![root(21)]).unwrap(),
            vm,
            precompile,
        )
    }

    fn version_prefix() -> Vec<u8> {
        let compatibility =
            ExecutionProofCompatibility::new(vec![root(11), root(12)], vec![root(21)]).unwrap();
        let mut bytes = vec![compatibility.format()];
        compatibility.vm_verifier_roots().to_vec().write_into(&mut bytes);
        compatibility.pvm_verifier_roots().to_vec().write_into(&mut bytes);
        bytes
    }

    #[test]
    fn execution_proof_reports_precompile_state() {
        let (precompile_wire, wire_root) = wire();
        let deferred = versioned(vm_proof(wire_root), PrecompileStatus::Deferred(precompile_wire));
        assert!(deferred.has_precompiles());

        let complete_without_precompile = versioned(vm_proof(TRUE_DIGEST), PrecompileStatus::Empty);
        assert!(!complete_without_precompile.has_precompiles());

        let complete_with_precompile =
            versioned(vm_proof(root(1)), PrecompileStatus::Proven(precompile_proof(&[root(1)])));
        assert!(complete_with_precompile.has_precompiles());
    }

    #[test]
    fn versioned_proof_round_trips_with_format_first() {
        let proof = versioned(vm_proof(TRUE_DIGEST), PrecompileStatus::Empty);

        let bytes = proof.to_bytes();
        let decoded = ExecutionProof::read_from_bytes(&bytes).unwrap();

        assert_eq!(bytes[0], ExecutionProofCompatibility::FORMAT_V1);
        assert_eq!(decoded, proof);
        assert_eq!(decoded.compatibility().format(), ExecutionProofCompatibility::FORMAT_V1);
        assert_eq!(decoded.compatibility().vm_verifier_roots(), &[root(11), root(12)]);
        assert_eq!(decoded.compatibility().pvm_verifier_roots(), &[root(21)]);
    }

    #[test]
    fn versioned_proof_decoder_rejects_unknown_format_before_body() {
        let error = ExecutionProof::read_from_bytes(&[ExecutionProofCompatibility::FORMAT_V1 + 1])
            .unwrap_err();

        assert!(
            matches!(error, DeserializationError::InvalidValue(message) if message.contains("unsupported execution proof format 2"))
        );
    }

    #[test]
    fn versioned_proof_decoder_rejects_trailing_and_noncanonical_bytes() {
        let proof = versioned(vm_proof(TRUE_DIGEST), PrecompileStatus::Empty);
        let mut trailing = proof.to_bytes();
        trailing.push(0);
        assert!(ExecutionProof::read_from_bytes(&trailing).is_err());

        let canonical = proof.to_bytes();
        assert_eq!(canonical[1], 5, "two VM roots use a one-byte vint encoding");
        let mut noncanonical = alloc::vec![canonical[0], 0];
        noncanonical.extend_from_slice(&2u64.to_le_bytes());
        noncanonical.extend_from_slice(&canonical[2..]);
        let error = ExecutionProof::read_from_bytes(&noncanonical).unwrap_err();
        assert!(
            matches!(error, DeserializationError::InvalidValue(message) if message.contains("not canonically encoded"))
        );
    }

    #[test]
    fn versioned_proof_decoder_applies_the_input_budget_to_root_lists() {
        let mut bytes = vec![ExecutionProofCompatibility::FORMAT_V1];
        bytes.write_usize(usize::MAX);

        let error = ExecutionProof::read_from_bytes(&bytes).unwrap_err();
        assert!(matches!(error, DeserializationError::InvalidValue(_)));
    }

    #[test]
    fn compatibility_constructor_rejects_duplicate_roots() {
        assert_eq!(
            ExecutionProofCompatibility::new(vec![root(1), root(1)], vec![]),
            Err(ExecutionProofCompatibilityError::DuplicateVmVerifierRoot)
        );
        assert_eq!(
            ExecutionProofCompatibility::new(vec![], vec![root(2), root(2)]),
            Err(ExecutionProofCompatibilityError::DuplicatePvmVerifierRoot)
        );
    }

    #[test]
    fn versioned_proof_decoder_rejects_duplicate_roots() {
        let proof = versioned(vm_proof(TRUE_DIGEST), PrecompileStatus::Empty);
        let proof_bytes = proof.to_bytes();
        let body = &proof_bytes[version_prefix().len()..];

        let mut duplicate_vm = vec![ExecutionProofCompatibility::FORMAT_V1];
        vec![root(1), root(1)].write_into(&mut duplicate_vm);
        Vec::<Word>::new().write_into(&mut duplicate_vm);
        duplicate_vm.extend_from_slice(body);
        let error = ExecutionProof::read_from_bytes(&duplicate_vm).unwrap_err();
        assert!(
            matches!(error, DeserializationError::InvalidValue(message) if message.contains("VM verifier roots must not contain duplicates"))
        );

        let mut duplicate_pvm = vec![ExecutionProofCompatibility::FORMAT_V1];
        Vec::<Word>::new().write_into(&mut duplicate_pvm);
        vec![root(2), root(2)].write_into(&mut duplicate_pvm);
        duplicate_pvm.extend_from_slice(body);
        let error = ExecutionProof::read_from_bytes(&duplicate_pvm).unwrap_err();
        assert!(
            matches!(error, DeserializationError::InvalidValue(message) if message.contains("PVM verifier roots must not contain duplicates"))
        );
    }

    #[test]
    fn proof_minimum_serialized_sizes_match_shortest_canonical_encodings() {
        let stark = StarkProof::new(Vec::new(), HashFunction::Blake3_256);
        assert_eq!(StarkProof::min_serialized_size(), stark.to_bytes().len());
        assert_eq!(StarkProof::min_serialized_size(), 2);

        let vm = VmProof {
            proof: stark,
            precompile_root: TRUE_DIGEST,
        };
        assert_eq!(VmProof::min_serialized_size(), vm.to_bytes().len());
        assert_eq!(VmProof::min_serialized_size(), 34);

        let empty = PrecompileProof {
            proof: StarkProof::new(Vec::new(), HashFunction::Blake3_256),
            roots: Vec::new(),
        };
        assert_eq!(PrecompileProof::min_serialized_size(), empty.to_bytes().len());
        assert_eq!(PrecompileProof::min_serialized_size(), 3);

        let singleton = PrecompileProof {
            proof: StarkProof::new(Vec::new(), HashFunction::Blake3_256),
            roots: alloc::vec![root(1)],
        };
        assert_eq!(singleton.to_bytes().len(), 35);

        let proofs = alloc::vec![singleton.clone(), singleton];
        let bytes = proofs.to_bytes();
        assert_eq!(bytes.len(), 71);
        let decoded = Vec::<PrecompileProof>::read_from_bytes_with_budget(&bytes, 71).unwrap();
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
    fn standalone_proof_decoders_reject_trailing_bytes() {
        let mut vm_bytes = vm_proof(root(3)).to_bytes();
        vm_bytes.push(0);
        assert!(VmProof::read_from_bytes(&vm_bytes).is_err());

        let mut precompile_bytes = precompile_proof(&[root(3)]).to_bytes();
        precompile_bytes.push(0);
        assert!(PrecompileProof::read_from_bytes(&precompile_bytes).is_err());
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

        let precompile = precompile_proof(&[]);
        let precompile_bytes = precompile.to_bytes();
        let decoded_precompile = PrecompileProof::read_from_bytes(&precompile_bytes).unwrap();
        assert_eq!(decoded_precompile.to_bytes(), precompile_bytes);

        let (precompile_wire, wire_root) = wire();
        let proofs = [
            versioned(vm_proof(wire_root), PrecompileStatus::Deferred(precompile_wire)),
            versioned(vm_proof(TRUE_DIGEST), PrecompileStatus::Empty),
            versioned(
                vm_proof(TRUE_DIGEST),
                PrecompileStatus::Proven(precompile_proof(&[TRUE_DIGEST])),
            ),
        ];
        for proof in proofs {
            let bytes = proof.to_bytes();
            assert_eq!(ExecutionProof::read_from_bytes(&bytes).unwrap(), proof);
        }
    }

    #[test]
    fn complete_transitions_deferred_proof_without_validating_artifact_shape() {
        let vm = vm_proof(TRUE_DIGEST);
        let precompile = precompile_proof(&[]);
        let deferred =
            versioned(vm.clone(), PrecompileStatus::Deferred(DeferredStateWire::default()));

        let completed = deferred.complete(precompile.clone()).unwrap();

        let (completed_compatibility, completed_vm, completed_precompile) = completed.into_parts();
        let PrecompileStatus::Proven(completed_precompile) = completed_precompile else {
            panic!("deferred proof should transition to complete")
        };
        assert_eq!(
            completed_compatibility,
            ExecutionProofCompatibility::new(vec![root(11), root(12)], vec![root(21)]).unwrap()
        );
        assert_eq!(completed_vm.to_bytes(), vm.to_bytes());
        assert_eq!(completed_precompile.to_bytes(), precompile.to_bytes());
    }

    #[test]
    fn complete_rejects_an_already_complete_proof() {
        let complete = versioned(vm_proof(TRUE_DIGEST), PrecompileStatus::Empty);

        assert!(matches!(
            complete.complete(precompile_proof(&[])),
            Err(ExecutionProofError::AlreadyComplete)
        ));
    }

    #[test]
    fn versioned_proof_transport_rejects_bad_discriminants_and_stark_bounds() {
        let mut bad_discriminant = version_prefix();
        bad_discriminant.write_u8(9);
        assert!(ExecutionProof::read_from_bytes(&bad_discriminant).is_err());

        let canonical = versioned(vm_proof(TRUE_DIGEST), PrecompileStatus::Empty).to_bytes();
        let prefix_len = version_prefix().len();
        assert_eq!(canonical[prefix_len + 1], 3, "one STARK byte uses a one-byte vint encoding");
        let mut noncanonical = canonical[..prefix_len + 1].to_vec();
        noncanonical.push(0);
        noncanonical.extend_from_slice(&1u64.to_le_bytes());
        noncanonical.extend_from_slice(&canonical[prefix_len + 2..]);
        let error = ExecutionProof::read_from_bytes(&noncanonical).unwrap_err();
        assert!(
            matches!(error, DeserializationError::InvalidValue(message) if message.contains("not canonically encoded"))
        );

        let mut oversized_proof = version_prefix();
        oversized_proof.write_u8(COMPLETE_PROOF_DISCRIMINANT);
        oversized_proof.write_usize(MAX_STARK_PROOF_BYTES + 1);
        let error = ExecutionProof::read_from_bytes(&oversized_proof).unwrap_err();
        assert!(
            matches!(error, DeserializationError::InvalidValue(message) if message.contains("STARK proof contains too many bytes"))
        );
    }
}
