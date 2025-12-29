use winter_air::BatchingMethod;

use super::{ExecutionOptionsError, FieldExtension, HashFunction, WinterProofOptions};

// PROVING OPTIONS
// ================================================================================================

/// A set of parameters specifying how Miden VM execution proofs are to be generated.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProvingOptions {
    exec_options: ExecutionOptions,
    proof_options: WinterProofOptions,
    hash_fn: HashFunction,
}

impl ProvingOptions {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Standard proof parameters for 96-bit conjectured security in non-recursive context.
    pub const REGULAR_96_BITS: WinterProofOptions = WinterProofOptions::new(
        27,
        8,
        16,
        FieldExtension::Quadratic,
        8,
        255,
        BatchingMethod::Algebraic,
        BatchingMethod::Algebraic,
    );

    /// Standard proof parameters for 128-bit conjectured security in non-recursive context.
    pub const REGULAR_128_BITS: WinterProofOptions = WinterProofOptions::new(
        27,
        16,
        21,
        FieldExtension::Cubic,
        8,
        255,
        BatchingMethod::Algebraic,
        BatchingMethod::Algebraic,
    );

    /// Standard proof parameters for 96-bit conjectured security in recursive context.
    pub const RECURSIVE_96_BITS: WinterProofOptions = WinterProofOptions::new(
        27,
        8,
        16,
        FieldExtension::Quadratic,
        4,
        127,
        BatchingMethod::Algebraic,
        BatchingMethod::Horner,
    );

    /// Standard proof parameters for 128-bit conjectured security in recursive context.
    pub const RECURSIVE_128_BITS: WinterProofOptions = WinterProofOptions::new(
        27,
        16,
        21,
        FieldExtension::Cubic,
        4,
        7,
        BatchingMethod::Horner,
        BatchingMethod::Horner,
    );

    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new instance of [ProvingOptions] from the specified parameters.
    pub fn new(
        num_queries: usize,
        blowup_factor: usize,
        grinding_factor: u32,
        field_extension: FieldExtension,
        fri_folding_factor: usize,
        fri_remainder_max_degree: usize,
        hash_fn: HashFunction,
    ) -> Self {
        let proof_options = WinterProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor,
            fri_remainder_max_degree,
            BatchingMethod::Algebraic,
            BatchingMethod::Horner,
        );
        let exec_options = ExecutionOptions::default();
        Self { exec_options, proof_options, hash_fn }
    }

    /// Creates a new preset instance of [ProvingOptions] targeting 96-bit security level, given
    /// a choice of a hash function.
    ///
    /// If the hash function is arithmetization-friendly then proofs will be generated using
    /// settings that are well-suited for recursive verification.
    pub fn with_96_bit_security(hash_fn: HashFunction) -> Self {
        let proof_options = match hash_fn {
            HashFunction::Blake3_192 | HashFunction::Blake3_256 => Self::REGULAR_96_BITS,
            HashFunction::Rpo256 | HashFunction::Rpx256 | HashFunction::Poseidon2 => {
                Self::RECURSIVE_96_BITS
            },
        };
        Self {
            exec_options: ExecutionOptions::default(),
            proof_options,
            hash_fn,
        }
    }

    /// Creates a new preset instance of [ProvingOptions] targeting 128-bit security level, given
    /// a choice of a hash function, in the non-recursive setting.
    ///
    /// If the hash function is arithmetization-friendly then proofs will be generated using
    /// settings that are well-suited for recursive verification.
    pub fn with_128_bit_security(hash_fn: HashFunction) -> Self {
        let proof_options = match hash_fn {
            HashFunction::Blake3_192 | HashFunction::Blake3_256 => Self::REGULAR_128_BITS,
            HashFunction::Rpo256 | HashFunction::Rpx256 | HashFunction::Poseidon2 => {
                Self::RECURSIVE_128_BITS
            },
        };
        Self {
            exec_options: ExecutionOptions::default(),
            proof_options,
            hash_fn,
        }
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
        Self::with_96_bit_security(HashFunction::Blake3_192)
    }
}

impl From<ProvingOptions> for WinterProofOptions {
    fn from(options: ProvingOptions) -> Self {
        options.proof_options
    }
}

// EXECUTION OPTIONS
// ================================================================================================

/// Duplicate of `miden_processor::fast::DEFAULT_CORE_TRACE_FRAGMENT_SIZE` until `ExecutionOptions`
/// is moved to `miden_air`.
const DEFAULT_CORE_TRACE_FRAGMENT_SIZE: usize = 1 << 12; // 4096

/// A set of parameters specifying execution parameters of the VM.
///
/// - `max_cycles` specifies the maximum number of cycles a program is allowed to execute.
/// - `expected_cycles` specifies the number of cycles a program is expected to execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionOptions {
    core_trace_fragment_size: usize,
    enable_tracing: bool,
    enable_debugging: bool,
}

impl Default for ExecutionOptions {
    fn default() -> Self {
        ExecutionOptions {
            core_trace_fragment_size: DEFAULT_CORE_TRACE_FRAGMENT_SIZE,
            enable_tracing: false,
            enable_debugging: false,
        }
    }
}

impl ExecutionOptions {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The maximum number of VM cycles a program is allowed to take.
    pub const MAX_CYCLES: u32 = 1 << 29;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Creates a new instance of [ExecutionOptions] from the specified parameters.
    ///
    /// If the `max_cycles` is `None` the maximum number of cycles will be set to 2^29.
    pub fn new(
        core_trace_fragment_size: usize,
        enable_tracing: bool,
        enable_debugging: bool,
    ) -> Result<Self, ExecutionOptionsError> {
        Ok(ExecutionOptions {
            core_trace_fragment_size,
            enable_tracing,
            enable_debugging,
        })
    }

    /// Sets the size of core trace fragments when generating execution traces.
    pub fn with_core_trace_fragment_size(mut self, size: usize) -> Self {
        self.core_trace_fragment_size = size;
        self
    }

    /// Enables execution of the `trace` instructions.
    pub fn with_tracing(mut self) -> Self {
        self.enable_tracing = true;
        self
    }

    /// Enables execution of programs in debug mode when the `enable_debugging` flag is set to true;
    /// otherwise, debug mode is disabled.
    ///
    /// In debug mode the VM does the following:
    /// - Executes `debug` instructions (these are ignored in regular mode).
    /// - Records additional info about program execution (e.g., keeps track of stack state at every
    ///   cycle of the VM) which enables stepping through the program forward and backward.
    pub fn with_debugging(mut self, enable_debugging: bool) -> Self {
        self.enable_debugging = enable_debugging;
        self
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the size of core trace fragments when generating execution traces.
    pub fn core_trace_fragment_size(&self) -> usize {
        self.core_trace_fragment_size
    }

    /// Returns a flag indicating whether the VM should execute `trace` instructions.
    pub fn enable_tracing(&self) -> bool {
        self.enable_tracing
    }

    /// Returns a flag indicating whether the VM should execute a program in debug mode.
    pub fn enable_debugging(&self) -> bool {
        self.enable_debugging
    }
}
