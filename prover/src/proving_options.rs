use miden_core::{
    proof::HashFunction,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

// PROVING OPTIONS
// ================================================================================================

/// A set of parameters specifying how Miden VM execution proofs are to be generated.
///
/// This struct stores the proof-generation hash function only. The actual STARK proving parameters
/// (FRI config, security level, etc.) are determined by the hash function and hardcoded in the
/// prover's config module.
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProvingOptions {
    hash_fn: HashFunction,
}

impl ProvingOptions {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new instance of [ProvingOptions] with the specified hash function.
    ///
    /// The STARK proving parameters (security level, FRI config, etc.) are determined
    /// by the hash function and hardcoded in the prover's config module.
    pub fn new(hash_fn: HashFunction) -> Self {
        Self { hash_fn }
    }

    /// Creates a new instance of [ProvingOptions] targeting 96-bit security level.
    ///
    /// Note: The actual security parameters are hardcoded in the prover's config module.
    /// This is a convenience constructor that is equivalent to `new(hash_fn)`.
    pub fn with_96_bit_security(hash_fn: HashFunction) -> Self {
        Self::new(hash_fn)
    }

    /// Returns the hash function to be used in STARK proof generation.
    pub const fn hash_fn(&self) -> HashFunction {
        self.hash_fn
    }
}

impl Default for ProvingOptions {
    fn default() -> Self {
        Self::new(HashFunction::Blake3_256)
    }
}

impl Serializable for ProvingOptions {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.hash_fn.write_into(target);
    }
}

impl Deserializable for ProvingOptions {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self::new(HashFunction::read_from(source)?))
    }
}

#[cfg(feature = "arbitrary")]
impl proptest::prelude::Arbitrary for ProvingOptions {
    type Parameters = ();
    type Strategy = proptest::prelude::BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;
        (0u8..5)
            .prop_map(|tag| match tag {
                0 => HashFunction::Blake3_256,
                1 => HashFunction::Rpo256,
                2 => HashFunction::Rpx256,
                3 => HashFunction::Poseidon2,
                _ => HashFunction::Keccak,
            })
            .prop_map(Self::new)
            .boxed()
    }
}
