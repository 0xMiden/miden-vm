use alloc::{string::ToString, vec::Vec};

use miden_core::{
    crypto::hash::{Blake3_192, Blake3_256, Hasher, Poseidon2, Rpo256, Rpx256},
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};
use p3_uni_stark::StarkGenericConfig;
use serde::{Deserialize, Serialize};

//use winter_air::proof::Proof;

// EXECUTION PROOF
// ================================================================================================

/// A proof of correct execution of Miden VM.
///
/// The proof encodes the proof itself as well as STARK protocol parameters used to generate the
/// proof. However, the proof does not contain public inputs needed to verify the proof.
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ExecutionProof {
    pub proof: Vec<u8>,
    pub hash_fn: HashFunction,
}

impl ExecutionProof {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Creates a new instance of [ExecutionProof] from the specified STARK proof and hash
    /// function.
    pub const fn new(proof: Vec<u8>, hash_fn: HashFunction) -> Self {
        Self { proof, hash_fn }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the underlying STARK proof.
    pub fn stark_proof(&self) -> Vec<u8> {
        self.proof.clone()
    }

    /// Returns the hash function used during proof generation process.
    pub const fn hash_fn(&self) -> HashFunction {
        self.hash_fn
    }

    /// Returns conjectured security level of this proof in bits.
    ///
    /// TODO(Al): Migrate security estimator from Winterfell to 0xMiden/Plonky3
    ///
    /// Currently returns a hardcoded 128 bits. Once the security estimator is implemented
    /// in Plonky3, this should calculate the actual conjectured security level based on:
    /// - Proof parameters (FRI folding factor, number of queries, etc.)
    /// - Hash function collision resistance
    /// - Field size and extension degree
    ///
    /// The previous Winterfell implementation (commented out above) should serve as a
    /// reference for the calculation logic.
    pub fn security_level(&self) -> u32 {
        /*
        let conjectured_security = match self.hash_fn {
            HashFunction::Blake3_192 => self.proof.conjectured_security::<Blake3_192>(),
            HashFunction::Blake3_256 => self.proof.conjectured_security::<Blake3_256>(),
            HashFunction::Rpo256 => self.proof.conjectured_security::<Rpo256>(),
            HashFunction::Rpx256 => self.proof.conjectured_security::<Rpx256>(),
            HashFunction::Poseidon2 => self.proof.conjectured_security::<Poseidon2>(),
        };
        conjectured_security.bits()
         */
        128
    }

    // SERIALIZATION / DESERIALIZATION
    // --------------------------------------------------------------------------------------------

    /// Serializes this proof into a vector of bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.proof.to_bytes();
        assert!(!bytes.is_empty(), "invalid STARK proof");
        // TODO: ideally we should write hash function into the proof first to avoid reallocations
        bytes.insert(0, self.hash_fn as u8);
        bytes
    }

    /// Reads the source bytes, parsing a new proof instance.
    ///
    /// The serialization format is: [hash_fn (1 byte)][proof bytes]
    /// where hash_fn is prepended during to_bytes() via insert(0, ...).
    pub fn from_bytes(source: &[u8]) -> Result<Self, DeserializationError> {
        if source.len() < 2 {
            return Err(DeserializationError::UnexpectedEOF);
        }
        let hash_fn = HashFunction::try_from(source[0])?;
        let proof = Vec::<u8>::read_from_bytes(&source[1..])?;
        Ok(Self::new(proof, hash_fn))
    }

    // DESTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns components of this execution proof.
    pub fn into_parts(self) -> (HashFunction, Vec<u8>) {
        (self.hash_fn, self.proof)
    }
}

// HASH FUNCTION
// ================================================================================================

/// A hash function used during STARK proof generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(bound = "")]
#[repr(u8)]
pub enum HashFunction {
    /// BLAKE3 hash function with 192-bit output.
    Blake3_192 = 0x00,
    /// BLAKE3 hash function with 256-bit output.
    Blake3_256 = 0x01,
    /// RPO hash function with 256-bit output.
    Rpo256 = 0x02,
    /// RPX hash function with 256-bit output.
    Rpx256 = 0x03,
    /// Keccak hash function with 256-bit output.
    Keccak = 0x04,
    /// Poseidon hash function with 256-bit output.
    Poseidon2 = 0x05,
}

impl Default for HashFunction {
    fn default() -> Self {
        Self::Blake3_192
    }
}

impl HashFunction {
    /// Returns the collision resistance level (in bits) of this hash function.
    pub const fn collision_resistance(&self) -> u32 {
        match self {
            HashFunction::Blake3_192 => Blake3_192::COLLISION_RESISTANCE,
            HashFunction::Blake3_256 => Blake3_256::COLLISION_RESISTANCE,
            HashFunction::Rpo256 => Rpo256::COLLISION_RESISTANCE,
            HashFunction::Rpx256 => Rpx256::COLLISION_RESISTANCE,
            HashFunction::Keccak => 128,
            HashFunction::Poseidon2 => Poseidon2::COLLISION_RESISTANCE,
        }
    }
}

impl TryFrom<u8> for HashFunction {
    type Error = DeserializationError;

    fn try_from(repr: u8) -> Result<Self, Self::Error> {
        match repr {
            0x00 => Ok(Self::Blake3_192),
            0x01 => Ok(Self::Blake3_256),
            0x02 => Ok(Self::Rpo256),
            0x03 => Ok(Self::Rpx256),
            0x04 => Ok(Self::Keccak),
            _ => Err(DeserializationError::InvalidValue(format!(
                "the hash function representation {repr} is not valid!"
            ))),
        }
    }
}

impl TryFrom<&str> for HashFunction {
    type Error = super::ExecutionOptionsError;

    fn try_from(hash_fn_str: &str) -> Result<Self, Self::Error> {
        match hash_fn_str {
            "blake3-192" => Ok(Self::Blake3_192),
            "blake3-256" => Ok(Self::Blake3_256),
            "rpo" => Ok(Self::Rpo256),
            "rpx" => Ok(Self::Rpx256),
            "keccak" => Ok(Self::Keccak),
            "poseidon2" => Ok(Self::Poseidon2),
            _ => Err(super::ExecutionOptionsError::InvalidHashFunction {
                hash_function: hash_fn_str.to_string(),
            }),
        }
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
    }
}

impl Deserializable for ExecutionProof {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let proof = Vec::<u8>::read_from(source)?;
        let hash_fn = HashFunction::read_from(source)?;

        Ok(ExecutionProof { proof, hash_fn })
    }
}

use p3_commit::Pcs;

type Com<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Commitment;
type PcsProof<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Proof;

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Proof<SC: StarkGenericConfig> {
    pub commitments: Commitments<Com<SC>>,
    pub opened_values: OpenedValues<SC::Challenge>,
    pub opening_proof: PcsProof<SC>,
    pub degree_bits: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Commitments<Com> {
    pub trace: Com,
    pub aux_trace: Com,
    pub quotient_chunks: Com,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenedValues<Challenge> {
    pub trace_local: Vec<Challenge>,
    pub trace_next: Vec<Challenge>,
    pub aux_trace_local: Vec<Challenge>,
    pub aux_trace_next: Vec<Challenge>,
    pub quotient_chunks: Vec<Vec<Challenge>>,
}

// TODO(Al): Implement Proof<SC> serialization/deserialization using miden-crypto traits
//
// Currently, proof serialization uses bincode (see prover/src/lib.rs and verifier/src/lib.rs).
// Once serialization traits are migrated from Winterfell to miden-crypto, implement these
// methods to provide a proper serialization format for Proof<SC>.
//
// This will allow:
// - Standardized proof serialization across the ecosystem
// - Better control over proof format and versioning
// - Removal of bincode dependency for proof serialization
impl<SC: StarkGenericConfig> Serializable for Proof<SC> {
    fn write_into<W: ByteWriter>(&self, _target: &mut W) {
        todo!("Implement once miden-crypto serialization traits are available")
    }

    fn get_size_hint(&self) -> usize {
        todo!("Implement once miden-crypto serialization traits are available")
    }
}

impl<SC: StarkGenericConfig> Deserializable for Proof<SC> {
    fn read_from<R: ByteReader>(_source: &mut R) -> Result<Self, DeserializationError> {
        todo!("Implement once miden-crypto serialization traits are available")
    }
}
