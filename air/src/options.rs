use super::{ExecutionOptionsError, HashFunction};

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

    /// Creates a new instance of [ProvingOptions] targeting 128-bit security level.
    ///
    /// Note: The actual security parameters are hardcoded in the prover's config module.
    /// This is a convenience constructor that is equivalent to `new(hash_fn)`.
    pub fn with_128_bit_security(hash_fn: HashFunction) -> Self {
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
        Self::new(HashFunction::Blake3_192)
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
