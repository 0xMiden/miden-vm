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
    deferred::{DeferredRoot, DeferredStateWire},
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

// EXECUTION PROOF
// ================================================================================================

/// A proof of correct execution of Miden VM.
///
/// The proof contains the Miden VM STARK proof and deferred proof material for the execution's
/// precompile claims. Verifying the deferred proof returns the root used to check the VM STARK
/// public inputs.
///
/// `Empty` and STARK-backed deferred proofs are final form; wire-backed proofs are partial form.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ExecutionProof {
    miden: StarkProof,
    deferred: DeferredProof,
}

impl ExecutionProof {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Creates a new instance of [ExecutionProof] from a Miden VM STARK proof envelope and deferred
    /// proof material.
    pub const fn new(miden: StarkProof, deferred: DeferredProof) -> Self {
        Self { miden, deferred }
    }

    /// Creates a new instance of [ExecutionProof] from serialized Miden VM STARK proof bytes, hash
    /// function, and deferred proof material.
    pub fn from_parts(
        miden_proof_bytes: Vec<u8>,
        hash_fn: HashFunction,
        deferred: impl Into<DeferredProof>,
    ) -> Self {
        Self::new(StarkProof::new(miden_proof_bytes, hash_fn), deferred.into())
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the Miden VM STARK proof envelope.
    pub const fn miden_proof(&self) -> &StarkProof {
        &self.miden
    }

    /// Returns the deferred proof material associated with the Miden VM proof.
    pub const fn deferred_proof(&self) -> &DeferredProof {
        &self.deferred
    }

    /// Returns `true` if this proof is in final form.
    ///
    /// This is a shape check only: it means the deferred proof is empty or STARK-backed, not that
    /// either the VM STARK proof or the deferred proof has been verified.
    pub const fn is_final(&self) -> bool {
        self.deferred.is_final()
    }

    /// Returns conjectured security level of this proof in bits.
    ///
    /// Currently returns a hardcoded 96 bits. Once the security estimator is implemented
    /// in Plonky3, this should calculate the actual conjectured security level based on:
    /// - Proof parameters (FRI folding factor, number of queries, etc.)
    /// - Hash function collision resistance
    /// - Field size and extension degree
    pub fn security_level(&self) -> u32 {
        96
    }

    // SERIALIZATION / DESERIALIZATION
    // --------------------------------------------------------------------------------------------

    /// Serializes this proof into a vector of bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.write_into(&mut bytes);
        bytes
    }

    /// Reads the source bytes, parsing a new proof instance.
    ///
    /// The serialization layout matches the [`Serializable`] implementation of [`ExecutionProof`].
    pub fn from_bytes(source: &[u8]) -> Result<Self, DeserializationError> {
        <Self as Deserializable>::read_from_bytes(source)
    }
}

impl Serializable for ExecutionProof {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.miden.write_into(target);
        self.deferred.write_into(target);
    }
}

impl Deserializable for ExecutionProof {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let miden = StarkProof::read_from(source)?;
        let deferred = DeferredProof::read_from(source)?;

        Ok(ExecutionProof::new(miden, deferred))
    }

    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), bytes.len());
        Self::read_from(&mut reader)
    }
}

#[cfg(any(test, feature = "testing"))]
impl ExecutionProof {
    /// Creates a dummy `ExecutionProof` for testing purposes only.
    ///
    /// A proof created in this way will not be verifiable against any verifier.
    pub fn new_dummy() -> Self {
        ExecutionProof::new(
            StarkProof::new(Vec::new(), HashFunction::Blake3_256),
            DeferredProof::Empty,
        )
    }
}

// DEFERRED PROOF
// ================================================================================================

/// Proof material for the precompile claims associated with an execution proof.
///
/// Verification returns the deferred root used to check the VM STARK proof. `Wire` is the partial
/// form; `Empty` and `Stark` are final forms.
///
/// Variants are public so callers can construct and inspect deferred proof material directly.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DeferredProof {
    /// No precompile claims were produced. Verifiers resolve this to
    /// [`crate::deferred::TRUE_DIGEST`].
    Empty,
    /// Canonical deferred-state wire for a partial proof.
    Wire(DeferredStateWire),
    /// A precompile VM STARK proof for this execution's exact deferred root.
    ///
    /// After `proof` verifies against `public_root`, that root is used to verify the VM STARK
    /// proof.
    Stark {
        proof: StarkProof,
        public_root: DeferredRoot,
    },
}

impl DeferredProof {
    const EMPTY_TAG: u8 = 0;
    pub(crate) const WIRE_TAG: u8 = 1;
    const STARK_TAG: u8 = 2;

    /// Creates an empty deferred proof.
    pub const fn empty() -> Self {
        Self::Empty
    }

    /// Creates a deferred proof backed by a wire opening.
    pub const fn wire(wire: DeferredStateWire) -> Self {
        Self::Wire(wire)
    }

    /// Creates a deferred proof backed by a precompile VM STARK proof.
    pub const fn stark(proof: StarkProof, public_root: DeferredRoot) -> Self {
        Self::Stark { proof, public_root }
    }

    /// Returns `true` if this deferred proof is [`DeferredProof::Empty`].
    pub const fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }

    /// Returns `true` if this deferred proof is in final form.
    ///
    /// This is a shape check only: it accepts empty and STARK-backed proofs and rejects wire-backed
    /// partial proofs. It does not verify the contained proof material.
    pub const fn is_final(&self) -> bool {
        matches!(self, Self::Empty | Self::Stark { .. })
    }

    /// Returns the wire opening if this deferred proof is [`DeferredProof::Wire`].
    pub const fn as_wire(&self) -> Option<&DeferredStateWire> {
        match self {
            Self::Wire(wire) => Some(wire),
            _ => None,
        }
    }

    /// Returns the nested proof and public root if this proof is [`DeferredProof::Stark`].
    pub const fn as_stark(&self) -> Option<(&StarkProof, DeferredRoot)> {
        match self {
            Self::Stark { proof, public_root } => Some((proof, *public_root)),
            _ => None,
        }
    }
}

impl From<DeferredStateWire> for DeferredProof {
    fn from(wire: DeferredStateWire) -> Self {
        Self::wire(wire)
    }
}

impl Serializable for DeferredProof {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Self::Empty => target.write_u8(Self::EMPTY_TAG),
            Self::Wire(wire) => {
                target.write_u8(Self::WIRE_TAG);
                wire.write_into(target);
            },
            Self::Stark { proof, public_root } => {
                target.write_u8(Self::STARK_TAG);
                proof.write_into(target);
                public_root.write_into(target);
            },
        }
    }
}

impl Deserializable for DeferredProof {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let tag = source.read_u8()?;
        match tag {
            Self::EMPTY_TAG => Ok(Self::Empty),
            Self::WIRE_TAG => Ok(Self::Wire(DeferredStateWire::read_from(source)?)),
            Self::STARK_TAG => {
                let proof = StarkProof::read_from(source)?;
                let public_root = <DeferredRoot as Deserializable>::read_from(source)?;
                Ok(Self::Stark { proof, public_root })
            },
            other => Err(DeserializationError::InvalidValue(format!(
                "invalid deferred proof discriminant: {other}"
            ))),
        }
    }

    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), bytes.len());
        Self::read_from(&mut reader)
    }

    fn min_serialized_size() -> usize {
        1
    }
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
        let bytes = Vec::<u8>::read_from(source)?;
        let hash_fn = HashFunction::read_from(source)?;
        Ok(Self::new(bytes, hash_fn))
    }

    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), bytes.len());
        Self::read_from(&mut reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Felt,
        deferred::{DeferredRoot, TRUE_INDEX, Tag, WireEntry},
        serde::{BudgetedReader, ByteWriter, DeserializationError, SliceReader},
    };

    #[test]
    fn execution_proof_from_bytes_rejects_unbounded_proof_len() {
        let mut bytes = Vec::new();
        bytes.write_usize(usize::MAX);

        let err = ExecutionProof::from_bytes(&bytes).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("requested"));
        assert!(message.contains("reader can provide at most"));
    }

    #[test]
    fn execution_proof_read_from_bytes_rejects_unbounded_proof_len() {
        let mut bytes = Vec::new();
        bytes.write_usize(usize::MAX);

        let err = ExecutionProof::read_from_bytes(&bytes).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("requested"));
        assert!(message.contains("reader can provide at most"));
    }

    #[test]
    fn execution_proof_round_trips_empty_deferred_proof() {
        let proof = ExecutionProof::new(
            StarkProof::new(alloc::vec![1, 2, 3], HashFunction::Blake3_256),
            DeferredProof::empty(),
        );

        let decoded = ExecutionProof::from_bytes(&proof.to_bytes()).unwrap();

        assert_eq!(decoded, proof);
        assert_eq!(decoded.miden_proof().bytes(), &[1, 2, 3]);
        assert_eq!(decoded.miden_proof().hash_fn(), HashFunction::Blake3_256);
        assert!(decoded.deferred_proof().is_empty());
        assert!(decoded.is_final());
    }

    #[test]
    fn execution_proof_round_trips_empty_deferred_wire() {
        let proof = ExecutionProof::from_parts(
            alloc::vec![1, 2, 3],
            HashFunction::Blake3_256,
            DeferredProof::wire(DeferredStateWire::default()),
        );

        let decoded = ExecutionProof::from_bytes(&proof.to_bytes()).unwrap();

        assert_eq!(decoded, proof);
        assert_eq!(decoded.deferred_proof().as_wire(), Some(&DeferredStateWire::default()));
        assert!(!decoded.is_final());
    }

    #[test]
    fn execution_proof_round_trips_non_empty_deferred_wire() {
        let tag = Tag::from_word([
            Felt::new_unchecked(7),
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
        ]);
        let deferred_wire = DeferredStateWire {
            entries: alloc::vec![
                WireEntry::Data {
                    tag,
                    chunks: alloc::vec![[Felt::new_unchecked(1); 8]],
                },
                WireEntry::Join { tag, lhs: TRUE_INDEX, rhs: 1 },
            ],
        };
        let proof = ExecutionProof::from_parts(
            alloc::vec![1, 2, 3],
            HashFunction::Blake3_256,
            deferred_wire,
        );

        let decoded = ExecutionProof::from_bytes(&proof.to_bytes()).unwrap();

        assert_eq!(decoded, proof);
        assert!(!decoded.is_final());
    }

    #[test]
    fn execution_proof_round_trips_stark_deferred_proof() {
        let public_root: DeferredRoot = [
            Felt::new_unchecked(9),
            Felt::new_unchecked(8),
            Felt::new_unchecked(7),
            Felt::new_unchecked(6),
        ]
        .into();
        let deferred_stark_proof = StarkProof::new(alloc::vec![4, 5, 6], HashFunction::Poseidon2);
        let deferred = DeferredProof::stark(deferred_stark_proof.clone(), public_root);
        let proof = ExecutionProof::new(
            StarkProof::new(alloc::vec![1, 2, 3], HashFunction::Blake3_256),
            deferred,
        );

        let decoded = ExecutionProof::from_bytes(&proof.to_bytes()).unwrap();

        assert_eq!(decoded, proof);
        assert_eq!(decoded.deferred_proof().as_stark(), Some((&deferred_stark_proof, public_root)));
        assert!(decoded.is_final());
    }

    #[test]
    fn execution_proof_rejects_invalid_deferred_variant() {
        let mut bytes = Vec::new();
        bytes.write_usize(0);
        bytes.write_u8(HashFunction::Blake3_256 as u8);
        bytes.write_u8(255);

        let err = ExecutionProof::from_bytes(&bytes).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("invalid deferred proof discriminant: 255"));
    }

    #[test]
    fn execution_proof_rejects_over_budget_proof_len() {
        let mut bytes = Vec::new();
        bytes.write_usize(5);

        let budget = bytes.len() + 4;
        let mut reader = BudgetedReader::new(SliceReader::new(&bytes), budget);
        let err = ExecutionProof::read_from(&mut reader).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("requested 5 elements"));
    }

    #[test]
    fn execution_proof_rejects_over_budget_deferred_wire_entries_len() {
        let mut bytes = Vec::new();
        bytes.write_usize(0);
        bytes.write_u8(HashFunction::Blake3_256 as u8);
        bytes.write_u8(DeferredProof::WIRE_TAG);
        bytes.write_usize(2);

        let budget = bytes.len() + 1;
        let mut reader = BudgetedReader::new(SliceReader::new(&bytes), budget);
        let err = ExecutionProof::read_from(&mut reader).unwrap_err();
        let DeserializationError::InvalidValue(message) = err else {
            panic!("expected InvalidValue error");
        };
        assert!(message.contains("requested 2 elements"));
    }
}
