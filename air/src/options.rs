use winter_air::BatchingMethod;

use super::{
    ExecutionOptionsError, FieldExtension, HashFunction, WinterProofOptions, trace::MIN_TRACE_LEN,
};

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

/// A set of parameters specifying execution parameters of the VM.
///
/// - `max_cycles` specifies the maximum number of cycles a program is allowed to execute.
/// - `expected_cycles` specifies the number of cycles a program is expected to execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionOptions {
    max_cycles: u32,
    expected_cycles: u32,
    enable_tracing: bool,
    enable_debugging: bool,
}

impl Default for ExecutionOptions {
    fn default() -> Self {
        ExecutionOptions {
            max_cycles: Self::MAX_CYCLES,
            expected_cycles: MIN_TRACE_LEN as u32,
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
        max_cycles: Option<u32>,
        expected_cycles: u32,
        enable_tracing: bool,
        enable_debugging: bool,
    ) -> Result<Self, ExecutionOptionsError> {
        // Validate max cycles.
        let max_cycles = if let Some(max_cycles) = max_cycles {
            if max_cycles > Self::MAX_CYCLES {
                return Err(ExecutionOptionsError::MaxCycleNumTooBig {
                    max_cycles,
                    max_cycles_limit: Self::MAX_CYCLES,
                });
            }
            if max_cycles < MIN_TRACE_LEN as u32 {
                return Err(ExecutionOptionsError::MaxCycleNumTooSmall {
                    max_cycles,
                    min_cycles_limit: MIN_TRACE_LEN,
                });
            }
            max_cycles
        } else {
            Self::MAX_CYCLES
        };
        // Validate expected cycles.
        if max_cycles < expected_cycles {
            return Err(ExecutionOptionsError::ExpectedCyclesTooBig {
                max_cycles,
                expected_cycles,
            });
        }
        // Round up the expected number of cycles to the next power of two. If it is smaller than
        // MIN_TRACE_LEN -- pad expected number to it.
        let expected_cycles = expected_cycles.next_power_of_two().max(MIN_TRACE_LEN as u32);

        Ok(ExecutionOptions {
            max_cycles,
            expected_cycles,
            enable_tracing,
            enable_debugging,
        })
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

    /// Returns maximum number of cycles a program is allowed to execute for.
    pub fn max_cycles(&self) -> u32 {
        self.max_cycles
    }

    /// Returns the number of cycles a program is expected to take.
    ///
    /// This will serve as a hint to the VM for how much memory to allocate for a program's
    /// execution trace and may result in performance improvements when the number of expected
    /// cycles is equal to the number of actual cycles.
    pub fn expected_cycles(&self) -> u32 {
        self.expected_cycles
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
