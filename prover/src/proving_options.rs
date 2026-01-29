use miden_core::HashFunction;
use miden_processor::ExecutionOptions;

// PROVING OPTIONS
// ================================================================================================

/// A set of parameters specifying how Miden VM execution proofs are to be generated.
///
/// This struct combines execution options (VM parameters) with the hash function to use
/// for proof generation. The actual STARK proving parameters (FRI config, security level, etc.)
/// are determined by the hash function and hardcoded in the prover's config module.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProvingOptions {
    exec_options: ExecutionOptions,
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
        Self {
            exec_options: ExecutionOptions::default(),
            hash_fn,
        }
    }

    /// Creates a new instance of [ProvingOptions] targeting 96-bit security level.
    ///
    /// Note: The actual security parameters are hardcoded in the prover's config module.
    /// This is a convenience constructor that is equivalent to `new(hash_fn)`.
    pub fn with_96_bit_security(hash_fn: HashFunction) -> Self {
        Self::new(hash_fn)
    }

    /// Sets [ExecutionOptions] for this [ProvingOptions].
    ///
    /// This sets the maximum number of cycles a program is allowed to execute as well as
    /// the number of cycles the program is expected to execute.
    pub fn with_execution_options(mut self, exec_options: ExecutionOptions) -> Self {
        self.exec_options = exec_options;
        self
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the hash function to be used in STARK proof generation.
    pub const fn hash_fn(&self) -> HashFunction {
        self.hash_fn
    }

    /// Returns the execution options specified for this [ProvingOptions]
    pub const fn execution_options(&self) -> &ExecutionOptions {
        &self.exec_options
    }
}

impl Default for ProvingOptions {
    fn default() -> Self {
        Self::new(HashFunction::Blake3_256)
    }
}
