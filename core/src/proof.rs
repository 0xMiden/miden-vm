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
    precompile::PrecompileRequest,
    serde::{
        BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        SliceReader,
    },
};

// EXECUTION PROOF
// ================================================================================================

/// A proof of correct execution of Miden VM.
///
/// The proof contains the STARK proof, the hash function used during proof generation, and a set
/// of precompile requests deferred during proof generation. However, the proof does not contain
/// public inputs needed to verify the proof.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ExecutionProof {
    pub proof: Vec<u8>,
    pub hash_fn: HashFunction,
    pub pc_requests: Vec<PrecompileRequest>,
}

impl ExecutionProof {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Creates a new instance of [ExecutionProof] from the specified STARK proof, hash function,
    /// and list of all deferred [PrecompileRequest]s.
    pub const fn new(
        proof: Vec<u8>,
        hash_fn: HashFunction,
        pc_requests: Vec<PrecompileRequest>,
    ) -> Self {
        Self { proof, hash_fn, pc_requests }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the underlying STARK proof.
    pub fn stark_proof(&self) -> &[u8] {
        &self.proof
    }

    /// Returns the hash function used during proof generation process.
    pub const fn hash_fn(&self) -> HashFunction {
        self.hash_fn
    }

    /// Returns the list of precompile requests made during the execution of the program.
    pub fn precompile_requests(&self) -> &[PrecompileRequest] {
        &self.pc_requests
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

    // DESTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns the hash function, proof bytes, and precompile requests.
    pub fn into_parts(self) -> (HashFunction, Vec<u8>, Vec<PrecompileRequest>) {
        (self.hash_fn, self.proof, self.pc_requests)
    }
}

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

// SERIALIZATION
// ================================================================================================

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

impl Serializable for ExecutionProof {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.proof.write_into(target);
        self.hash_fn.write_into(target);
        self.pc_requests.write_into(target);
    }
}

impl Deserializable for ExecutionProof {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let proof = Vec::<u8>::read_from(source)?;
        let hash_fn = HashFunction::read_from(source)?;
        let pc_requests = Vec::<PrecompileRequest>::read_from(source)?;

        Ok(ExecutionProof { proof, hash_fn, pc_requests })
    }

    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), bytes.len());
        Self::read_from(&mut reader)
    }
}

// HASH FUNCTION ERROR
// ================================================================================================

/// Error type for invalid hash function strings.
#[derive(Debug, thiserror::Error)]
#[error(
    "invalid hash function '{hash_function}'. Valid options are: blake3-256, rpo, rpx, poseidon2, keccak"
)]
pub struct InvalidHashFunctionError {
    pub hash_function: String,
}

// TESTING UTILS
// ================================================================================================

#[cfg(any(test, feature = "testing"))]
impl ExecutionProof {
    /// Creates a dummy `ExecutionProof` for testing purposes only.
    ///
    /// A proof created in this way will not be verifiable against any verifier.
    pub fn new_dummy() -> Self {
        ExecutionProof {
            proof: Vec::new(),
            hash_fn: HashFunction::Blake3_256,
            pc_requests: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        events::EventId,
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
    fn execution_proof_from_bytes_accepts_many_minimal_precompile_requests() {
        let pc_requests = (0..64)
            .map(|event_id| PrecompileRequest::new(EventId::from_u64(event_id), Vec::new()))
            .collect();
        let proof = ExecutionProof::new(vec![1, 2, 3], HashFunction::Blake3_256, pc_requests);

        let decoded = ExecutionProof::from_bytes(&proof.to_bytes()).unwrap();

        assert_eq!(decoded, proof);
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
    fn execution_proof_rejects_over_budget_pc_requests_len() {
        let mut bytes = Vec::new();
        bytes.write_usize(0);
        bytes.write_u8(HashFunction::Blake3_256 as u8);
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
