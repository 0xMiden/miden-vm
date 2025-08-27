use alloc::{string::ToString, vec::Vec};

use miden_core::{
    crypto::hash::{Blake3_192, Blake3_256, Hasher, Poseidon2, Rpo256, Rpx256},
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};
use winter_air::proof::Proof;

// EXECUTION PROOF
// ================================================================================================

/// A proof of correct execution of Miden VM.
///
/// The proof encodes the proof itself as well as STARK protocol parameters used to generate the
/// proof. However, the proof does not contain public inputs needed to verify the proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionProof {
    pub proof: Proof,
    pub hash_fn: HashFunction,
}

impl ExecutionProof {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Creates a new instance of [ExecutionProof] from the specified STARK proof and hash
    /// function.
    pub const fn new(proof: Proof, hash_fn: HashFunction) -> Self {
        Self { proof, hash_fn }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the underlying STARK proof.
    pub const fn stark_proof(&self) -> &Proof {
        &self.proof
    }

    /// Returns the hash function used during proof generation process.
    pub const fn hash_fn(&self) -> HashFunction {
        self.hash_fn
    }

    /// Returns conjectured security level of this proof in bits.
    pub fn security_level(&self) -> u32 {
        let conjectured_security = match self.hash_fn {
            HashFunction::Blake3_192 => self.proof.conjectured_security::<Blake3_192>(),
            HashFunction::Blake3_256 => self.proof.conjectured_security::<Blake3_256>(),
            HashFunction::Rpo256 => self.proof.conjectured_security::<Rpo256>(),
            HashFunction::Rpx256 => self.proof.conjectured_security::<Rpx256>(),
            HashFunction::Poseidon2 => self.proof.conjectured_security::<Poseidon2>(),
        };
        conjectured_security.bits()
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
    pub fn from_bytes(source: &[u8]) -> Result<Self, DeserializationError> {
        if source.len() < 2 {
            return Err(DeserializationError::UnexpectedEOF);
        }
        let hash_fn = HashFunction::try_from(source[0])?;
        let proof = Proof::from_bytes(&source[1..])?;
        Ok(Self::new(proof, hash_fn))
    }

    // DESTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns components of this execution proof.
    pub fn into_parts(self) -> (HashFunction, Proof) {
        (self.hash_fn, self.proof)
    }
}

// HASH FUNCTION
// ================================================================================================

/// A hash function used during STARK proof generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    /// Poseidon2 hash function with 256-bit output.
    Poseidon2 = 0x04,
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
            0x04 => Ok(Self::Poseidon2),
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
        let proof = Proof::read_from(source)?;
        let hash_fn = HashFunction::read_from(source)?;

        Ok(ExecutionProof { proof, hash_fn })
    }
}

// TESTING UTILS
// ================================================================================================

#[cfg(any(test, feature = "testing"))]
impl ExecutionProof {
    /// Creates a dummy `ExecutionProof` for testing purposes only.
    ///
    /// Uses a dummy `Proof` and the default `HashFunction`.
    pub fn new_dummy() -> Self {
        ExecutionProof {
            proof: Proof::new_dummy(),
            hash_fn: HashFunction::default(),
        }
    }
}
