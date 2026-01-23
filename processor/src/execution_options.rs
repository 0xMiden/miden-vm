use miden_air::trace::MIN_TRACE_LEN;

// CONSTANTS
// ================================================================================================

/// Default fragment size for core trace generation.
pub const DEFAULT_CORE_TRACE_FRAGMENT_SIZE: usize = 4096; // 2^12

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
    core_trace_fragment_size: usize,
    enable_tracing: bool,
    enable_debugging: bool,
}

impl Default for ExecutionOptions {
    fn default() -> Self {
        ExecutionOptions {
            max_cycles: Self::MAX_CYCLES,
            expected_cycles: MIN_TRACE_LEN as u32,
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
    ///
    /// # Errors
    /// Returns an error if:
    /// - `max_cycles` is outside the valid range
    /// - `expected_cycles` exceeds `max_cycles`
    /// - `core_trace_fragment_size` is zero
    pub fn new(
        max_cycles: Option<u32>,
        expected_cycles: u32,
        core_trace_fragment_size: usize,
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

        // Validate core trace fragment size.
        if core_trace_fragment_size == 0 {
            return Err(ExecutionOptionsError::CoreTraceFragmentSizeTooSmall);
        }

        Ok(ExecutionOptions {
            max_cycles,
            expected_cycles,
            core_trace_fragment_size,
            enable_tracing,
            enable_debugging,
        })
    }

    /// Sets the fragment size for core trace generation.
    ///
    /// Returns an error if the size is zero.
    pub fn with_core_trace_fragment_size(
        mut self,
        size: usize,
    ) -> Result<Self, ExecutionOptionsError> {
        if size == 0 {
            return Err(ExecutionOptionsError::CoreTraceFragmentSizeTooSmall);
        }
        self.core_trace_fragment_size = size;
        Ok(self)
    }

    /// Enables execution of the `trace` instructions.
    pub fn with_tracing(mut self, enable_tracing: bool) -> Self {
        self.enable_tracing = enable_tracing;
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

    /// Returns the fragment size for core trace generation.
    pub fn core_trace_fragment_size(&self) -> usize {
        self.core_trace_fragment_size
    }

    /// Returns a flag indicating whether the VM should execute `trace` instructions.
    #[inline]
    pub fn enable_tracing(&self) -> bool {
        self.enable_tracing
    }

    /// Returns a flag indicating whether the VM should execute a program in debug mode.
    #[inline]
    pub fn enable_debugging(&self) -> bool {
        self.enable_debugging
    }
}

// EXECUTION OPTIONS ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum ExecutionOptionsError {
    #[error(
        "expected number of cycles {expected_cycles} must be smaller than the maximum number of cycles {max_cycles}"
    )]
    ExpectedCyclesTooBig { max_cycles: u32, expected_cycles: u32 },
    #[error("maximum number of cycles {max_cycles} must be greater than {min_cycles_limit}")]
    MaxCycleNumTooSmall { max_cycles: u32, min_cycles_limit: usize },
    #[error("maximum number of cycles {max_cycles} must be less than {max_cycles_limit}")]
    MaxCycleNumTooBig { max_cycles: u32, max_cycles_limit: u32 },
    #[error("core trace fragment size must be greater than 0")]
    CoreTraceFragmentSizeTooSmall,
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_fragment_size() {
        // Valid power of two values should succeed
        let opts = ExecutionOptions::new(None, 64, 1024, false, false);
        assert!(opts.is_ok());
        assert_eq!(opts.unwrap().core_trace_fragment_size(), 1024);

        let opts = ExecutionOptions::new(None, 64, 4096, false, false);
        assert!(opts.is_ok());

        let opts = ExecutionOptions::new(None, 64, 1, false, false);
        assert!(opts.is_ok());
    }

    #[test]
    fn zero_fragment_size_fails() {
        let opts = ExecutionOptions::new(None, 64, 0, false, false);
        assert!(matches!(opts, Err(ExecutionOptionsError::CoreTraceFragmentSizeTooSmall)));
    }

    #[test]
    fn with_core_trace_fragment_size_validates() {
        // Valid size should succeed
        let result = ExecutionOptions::default().with_core_trace_fragment_size(2048);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().core_trace_fragment_size(), 2048);

        // Zero should fail
        let result = ExecutionOptions::default().with_core_trace_fragment_size(0);
        assert!(matches!(result, Err(ExecutionOptionsError::CoreTraceFragmentSizeTooSmall)));
    }
}
