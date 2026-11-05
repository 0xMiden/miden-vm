use miden_air_definitions::vm::trace::MIN_TRACE_LEN;
use miden_core::{
    deferred::PrecompileLimits,
    program::MIN_STACK_DEPTH,
    serde::{
        BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        SliceReader,
    },
};

// EXECUTION OPTIONS
// ================================================================================================

/// A set of parameters specifying execution parameters of the VM.
///
/// - `max_cycles` specifies the maximum number of cycles a program is allowed to execute.
/// - `expected_cycles` specifies the number of cycles a program is expected to execute.
///
/// # Binary encoding
///
/// The encoding writes fields in declaration order and has no version byte. Variable-length
/// integers must use the shortest vint64 encoding. Decoding rejects invalid booleans, invalid
/// UTF-8 class names, duplicate policy classes, truncated input, trailing input, and options that
/// violate the invariants enforced by [`Self::new`] and [`Self::with_max_stack_depth`]. Both byte
/// entrypoints require the decoded snapshot to consume the entire input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionOptions {
    max_cycles: u32,
    expected_cycles: u32,
    core_trace_fragment_size: usize,
    /// Maximum combined logical size, in bytes, of the advice stack, map, and Merkle store.
    max_advice_size_bytes: usize,
    /// Whether the synchronous prover may overlap hasher-chiplet trace building with program
    /// execution (std-only; the sequential path is used on no_std regardless).
    overlapped_trace_build: bool,
    /// Maximum number of input bytes allowed for a single hash precompile invocation.
    max_hash_len_bytes: usize,
    /// Maximum number of continuations allowed on the continuation stack at any point during
    /// execution.
    max_num_continuations: usize,
    /// Maximum number of field elements allowed on the operand stack across the active execution
    /// context and all suspended contexts.
    ///
    /// A `call`, `dyncall`, or `syscall` context switch hides the caller's operand-stack overflow
    /// (everything below the top 16 elements) until the callee returns. This limit bounds the
    /// aggregate of the active context's depth plus all such suspended overflow, so nesting
    /// context switches cannot accumulate hidden operand-stack memory beyond the configured
    /// budget.
    max_stack_depth: usize,
    /// Maximum number of field elements allowed in the processor's memory at any point during
    /// execution, rounded up to the nearest multiple of 4.
    max_memory_elements: usize,
    /// Policy limiting guest-induced deferred precompile work.
    execution_precompile_limits: PrecompileLimits,
    /// Policy limiting the final root-reachable deferred witness exported after execution.
    verification_precompile_limits: PrecompileLimits,
}

impl Default for ExecutionOptions {
    fn default() -> Self {
        ExecutionOptions {
            max_cycles: Self::MAX_CYCLES,
            expected_cycles: MIN_TRACE_LEN as u32,
            core_trace_fragment_size: Self::DEFAULT_CORE_TRACE_FRAGMENT_SIZE,
            max_advice_size_bytes: Self::DEFAULT_MAX_ADVICE_SIZE_BYTES,
            max_hash_len_bytes: Self::DEFAULT_MAX_HASH_LEN_BYTES,
            max_num_continuations: Self::DEFAULT_MAX_NUM_CONTINUATIONS,
            max_stack_depth: Self::DEFAULT_MAX_STACK_DEPTH,
            max_memory_elements: Self::DEFAULT_MAX_MEMORY_ELEMENTS,
            overlapped_trace_build: true,
            execution_precompile_limits: miden_precompiles::default_execution_precompile_limits(),
            verification_precompile_limits:
                miden_precompiles::default_verification_precompile_limits(),
        }
    }
}

impl ExecutionOptions {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// The maximum number of VM cycles a program is allowed to take.
    pub const MAX_CYCLES: u32 = 1 << 29;

    /// Default fragment size for core trace generation.
    pub const DEFAULT_CORE_TRACE_FRAGMENT_SIZE: usize = 4096; // 2^12

    /// Default maximum combined logical size of the advice provider. Set to 16 MiB.
    pub const DEFAULT_MAX_ADVICE_SIZE_BYTES: usize = 16 * 1024 * 1024;

    /// Default maximum number of input bytes for a single hash precompile invocation.
    /// Set to 2^20 (1 MB).
    pub const DEFAULT_MAX_HASH_LEN_BYTES: usize = 1 << 20;

    /// Default maximum number of continuations allowed on the continuation stack.
    /// Set to 2^16 (65536).
    pub const DEFAULT_MAX_NUM_CONTINUATIONS: usize = 1 << 16;

    /// Default maximum number of field elements allowed on the operand stack.
    ///
    /// This preserves the effective stack depth ceiling imposed by the previous fixed
    /// `FastProcessor` stack buffer.
    pub const DEFAULT_MAX_STACK_DEPTH: usize = 6615;

    /// Default maximum number of field elements allowed in the processor's memory.
    ///
    /// Memory is element-addressable, so this bounds the total number of elements live across all
    /// contexts. Internally memory is stored at word granularity (4 elements per word), so the
    /// effective limit is rounded up to a whole number of words. Set to 2^28, which lets programs
    /// use a large amount of memory while still providing a finite host-memory backstop against
    /// unbounded growth from writes to arbitrarily many unique addresses.
    pub const DEFAULT_MAX_MEMORY_ELEMENTS: usize = 1 << 28;

    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Creates a new instance of [ExecutionOptions] from the specified parameters.
    ///
    /// If the `max_cycles` is `None` the maximum number of cycles will be set to 2^29.
    ///
    /// # Errors
    /// Returns an error if:
    /// - `max_cycles` is outside the valid range
    /// - after rounding up to the next power of two, `expected_cycles` exceeds `max_cycles`
    /// - `core_trace_fragment_size` is zero
    pub fn new(
        max_cycles: Option<u32>,
        expected_cycles: u32,
        core_trace_fragment_size: usize,
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
        // Round up the expected number of cycles to the next power of two. If it is smaller than
        // MIN_TRACE_LEN -- pad expected number to it.
        let expected_cycles = expected_cycles.next_power_of_two().max(MIN_TRACE_LEN as u32);
        // Validate expected cycles (after rounding) against max_cycles.
        if max_cycles < expected_cycles {
            return Err(ExecutionOptionsError::ExpectedCyclesTooBig {
                max_cycles,
                expected_cycles,
            });
        }

        // Validate core trace fragment size.
        if core_trace_fragment_size == 0 {
            return Err(ExecutionOptionsError::CoreTraceFragmentSizeTooSmall);
        }

        Ok(ExecutionOptions {
            max_cycles,
            expected_cycles,
            core_trace_fragment_size,
            max_advice_size_bytes: Self::DEFAULT_MAX_ADVICE_SIZE_BYTES,
            max_hash_len_bytes: Self::DEFAULT_MAX_HASH_LEN_BYTES,
            max_num_continuations: Self::DEFAULT_MAX_NUM_CONTINUATIONS,
            max_stack_depth: Self::DEFAULT_MAX_STACK_DEPTH,
            max_memory_elements: Self::DEFAULT_MAX_MEMORY_ELEMENTS,
            overlapped_trace_build: true,
            execution_precompile_limits: miden_precompiles::default_execution_precompile_limits(),
            verification_precompile_limits:
                miden_precompiles::default_verification_precompile_limits(),
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

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns maximum number of cycles a program is allowed to execute for.
    #[inline(always)]
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

    /// Returns the maximum combined logical size, in bytes, of the advice provider.
    #[inline]
    pub fn max_advice_size_bytes(&self) -> usize {
        self.max_advice_size_bytes
    }

    /// Returns the maximum number of input bytes allowed for a single hash precompile invocation.
    #[inline]
    pub fn max_hash_len_bytes(&self) -> usize {
        self.max_hash_len_bytes
    }

    /// Sets whether the synchronous prover may overlap hasher-chiplet trace building with program
    /// execution (defaults to `true`; ignored on no_std, which always uses the sequential path).
    /// When enabled, overlap is opportunistic. A caller with no separate Rayon worker uses compact
    /// buffered replay.
    pub fn with_overlapped_trace_build(mut self, overlapped: bool) -> Self {
        self.overlapped_trace_build = overlapped;
        self
    }

    /// Returns whether the synchronous prover may overlap trace building with execution.
    pub fn overlapped_trace_build(&self) -> bool {
        self.overlapped_trace_build
    }

    /// Sets the maximum combined logical size, in bytes, of the advice provider.
    pub fn with_max_advice_size_bytes(mut self, size: usize) -> Self {
        self.max_advice_size_bytes = size;
        self
    }

    /// Sets the maximum number of input bytes allowed for a single hash precompile invocation.
    pub fn with_max_hash_len_bytes(mut self, size: usize) -> Self {
        self.max_hash_len_bytes = size;
        self
    }

    /// Returns the maximum number of continuations allowed on the continuation stack.
    #[inline]
    pub fn max_num_continuations(&self) -> usize {
        self.max_num_continuations
    }

    /// Returns the maximum number of field elements allowed on the operand stack across the active
    /// execution context and all suspended contexts.
    #[inline]
    pub fn max_stack_depth(&self) -> usize {
        self.max_stack_depth
    }

    /// Returns the configured maximum number of field elements allowed in the processor's memory.
    ///
    /// This is the raw value as set via [`Self::with_max_memory_elements`]; the effective cap is
    /// rounded up to a whole number of words (a multiple of 4) when memory is initialized.
    #[inline]
    pub fn max_memory_elements(&self) -> usize {
        self.max_memory_elements
    }

    /// Sets the maximum number of continuations allowed on the continuation stack.
    pub fn with_max_num_continuations(mut self, max_num_continuations: usize) -> Self {
        self.max_num_continuations = max_num_continuations;
        self
    }

    /// Sets the maximum number of field elements allowed on the operand stack across the active
    /// execution context and all suspended contexts.
    pub fn with_max_stack_depth(
        mut self,
        max_stack_depth: usize,
    ) -> Result<Self, ExecutionOptionsError> {
        if max_stack_depth < MIN_STACK_DEPTH {
            return Err(ExecutionOptionsError::MaxStackDepthTooSmall {
                max_stack_depth,
                min_stack_depth: MIN_STACK_DEPTH,
            });
        }
        self.max_stack_depth = max_stack_depth;
        Ok(self)
    }

    /// Sets the maximum number of field elements allowed in the processor's memory.
    pub fn with_max_memory_elements(mut self, max_memory_elements: usize) -> Self {
        self.max_memory_elements = max_memory_elements;
        self
    }

    /// Returns the policy limiting guest-induced deferred precompile work.
    pub const fn execution_precompile_limits(&self) -> &PrecompileLimits {
        &self.execution_precompile_limits
    }

    /// Sets the policy limiting guest-induced deferred precompile work.
    pub fn with_execution_precompile_limits(mut self, limits: PrecompileLimits) -> Self {
        self.execution_precompile_limits = limits;
        self
    }

    /// Returns the policy limiting the final root-reachable deferred witness.
    pub const fn verification_precompile_limits(&self) -> &PrecompileLimits {
        &self.verification_precompile_limits
    }

    /// Sets the policy limiting the final root-reachable deferred witness.
    pub fn with_verification_precompile_limits(mut self, limits: PrecompileLimits) -> Self {
        self.verification_precompile_limits = limits;
        self
    }
}

// SERIALIZATION
// ================================================================================================

fn read_shortest_usize<R: ByteReader>(
    source: &mut R,
    label: &str,
) -> Result<usize, DeserializationError> {
    let encoded_len = source.peek_u8()?.trailing_zeros() as usize + 1;
    let value = source.read_usize()?;
    if encoded_len != value.get_size_hint() {
        return Err(DeserializationError::InvalidValue(format!("noncanonical {label} length")));
    }
    Ok(value)
}

fn validate_decoded_options(
    max_cycles: u32,
    expected_cycles: u32,
    core_trace_fragment_size: usize,
    max_stack_depth: usize,
) -> Result<(), DeserializationError> {
    let min_cycles = MIN_TRACE_LEN as u32;
    if max_cycles < min_cycles || max_cycles > ExecutionOptions::MAX_CYCLES {
        return Err(DeserializationError::InvalidValue(format!(
            "max_cycles {max_cycles} is outside [{min_cycles}, {}]",
            ExecutionOptions::MAX_CYCLES
        )));
    }
    if !expected_cycles.is_power_of_two() || expected_cycles < min_cycles {
        return Err(DeserializationError::InvalidValue(format!(
            "expected_cycles {expected_cycles} must be a power of two at least {min_cycles}"
        )));
    }
    if expected_cycles > max_cycles {
        return Err(DeserializationError::InvalidValue(format!(
            "expected_cycles {expected_cycles} exceeds max_cycles {max_cycles}"
        )));
    }
    if core_trace_fragment_size == 0 {
        return Err(DeserializationError::InvalidValue(
            "core_trace_fragment_size must be greater than 0".into(),
        ));
    }
    if max_stack_depth < MIN_STACK_DEPTH {
        return Err(DeserializationError::InvalidValue(format!(
            "max_stack_depth {max_stack_depth} must be at least {MIN_STACK_DEPTH}"
        )));
    }
    Ok(())
}

impl Serializable for ExecutionOptions {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.max_cycles.write_into(target);
        self.expected_cycles.write_into(target);
        self.core_trace_fragment_size.write_into(target);
        self.max_advice_size_bytes.write_into(target);
        target.write_bool(self.overlapped_trace_build);
        self.max_hash_len_bytes.write_into(target);
        self.max_num_continuations.write_into(target);
        self.max_stack_depth.write_into(target);
        self.max_memory_elements.write_into(target);
        self.execution_precompile_limits.write_into(target);
        self.verification_precompile_limits.write_into(target);
    }

    fn get_size_hint(&self) -> usize {
        self.max_cycles.get_size_hint()
            + self.expected_cycles.get_size_hint()
            + self.core_trace_fragment_size.get_size_hint()
            + self.max_advice_size_bytes.get_size_hint()
            + 1
            + self.max_hash_len_bytes.get_size_hint()
            + self.max_num_continuations.get_size_hint()
            + self.max_stack_depth.get_size_hint()
            + self.max_memory_elements.get_size_hint()
            + self.execution_precompile_limits.get_size_hint()
            + self.verification_precompile_limits.get_size_hint()
    }
}

impl Deserializable for ExecutionOptions {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let max_cycles = source.read_u32()?;
        let expected_cycles = source.read_u32()?;
        let core_trace_fragment_size = read_shortest_usize(source, "core_trace_fragment_size")?;
        let max_advice_size_bytes = read_shortest_usize(source, "max_advice_size_bytes")?;
        let overlapped_trace_build = source.read_bool()?;
        let max_hash_len_bytes = read_shortest_usize(source, "max_hash_len_bytes")?;
        let max_num_continuations = read_shortest_usize(source, "max_num_continuations")?;
        let max_stack_depth = read_shortest_usize(source, "max_stack_depth")?;
        let max_memory_elements = read_shortest_usize(source, "max_memory_elements")?;
        let execution_precompile_limits = PrecompileLimits::read_from(source)?;
        let verification_precompile_limits = PrecompileLimits::read_from(source)?;

        validate_decoded_options(
            max_cycles,
            expected_cycles,
            core_trace_fragment_size,
            max_stack_depth,
        )?;

        Ok(Self {
            max_cycles,
            expected_cycles,
            core_trace_fragment_size,
            max_advice_size_bytes,
            overlapped_trace_build,
            max_hash_len_bytes,
            max_num_continuations,
            max_stack_depth,
            max_memory_elements,
            execution_precompile_limits,
            verification_precompile_limits,
        })
    }

    fn read_from_bytes(bytes: &[u8]) -> Result<Self, DeserializationError> {
        Self::read_from_bytes_with_budget(bytes, bytes.len())
    }

    fn read_from_bytes_with_budget(
        bytes: &[u8],
        budget: usize,
    ) -> Result<Self, DeserializationError> {
        let budget = budget.min(bytes.len());
        let mut reader = BudgetedReader::new(SliceReader::new(bytes), budget);
        let options = Self::read_from(&mut reader)?;
        let consumed = budget.saturating_sub(reader.remaining());
        if consumed != bytes.len() {
            return Err(DeserializationError::InvalidValue(
                "trailing bytes after execution options".into(),
            ));
        }
        Ok(options)
    }

    fn min_serialized_size() -> usize {
        2 * u32::min_serialized_size()
            + 6 * usize::min_serialized_size()
            + 1
            + 2 * PrecompileLimits::min_serialized_size()
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
    #[error("maximum stack depth {max_stack_depth} must be at least {min_stack_depth}")]
    MaxStackDepthTooSmall {
        max_stack_depth: usize,
        min_stack_depth: usize,
    },
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::{string::String, vec::Vec};

    use miden_core::{
        deferred::{WorkClass, WorkLimit},
        serde::{ByteWriter, Deserializable, Serializable},
    };

    use super::*;

    fn write_option_header(bytes: &mut Vec<u8>) {
        (MIN_TRACE_LEN as u32).write_into(bytes);
        (MIN_TRACE_LEN as u32).write_into(bytes);
        1usize.write_into(bytes);
        0usize.write_into(bytes);
        bytes.write_bool(true);
        0usize.write_into(bytes);
        0usize.write_into(bytes);
        MIN_STACK_DEPTH.write_into(bytes);
        0usize.write_into(bytes);
    }

    fn encode_options(
        max_cycles: u32,
        expected_cycles: u32,
        core_trace_fragment_size: usize,
        max_advice_size_bytes: usize,
        overlapped_trace_build: bool,
        max_hash_len_bytes: usize,
        max_num_continuations: usize,
        max_stack_depth: usize,
        max_memory_elements: usize,
        execution: &PrecompileLimits,
        verification: &PrecompileLimits,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        max_cycles.write_into(&mut bytes);
        expected_cycles.write_into(&mut bytes);
        core_trace_fragment_size.write_into(&mut bytes);
        max_advice_size_bytes.write_into(&mut bytes);
        bytes.write_bool(overlapped_trace_build);
        max_hash_len_bytes.write_into(&mut bytes);
        max_num_continuations.write_into(&mut bytes);
        max_stack_depth.write_into(&mut bytes);
        max_memory_elements.write_into(&mut bytes);
        execution.write_into(&mut bytes);
        verification.write_into(&mut bytes);
        bytes
    }

    #[test]
    fn valid_fragment_size() {
        // Valid power of two values should succeed
        let opts = ExecutionOptions::new(None, 64, 1024);
        assert!(opts.is_ok());
        assert_eq!(opts.unwrap().core_trace_fragment_size(), 1024);

        let opts = ExecutionOptions::new(None, 64, 4096);
        assert!(opts.is_ok());

        let opts = ExecutionOptions::new(None, 64, 1);
        assert!(opts.is_ok());
    }

    #[test]
    fn zero_fragment_size_fails() {
        let opts = ExecutionOptions::new(None, 64, 0);
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

    #[test]
    fn expected_cycles_validated_after_rounding() {
        // expected_cycles=65 rounds to 128; max_cycles=100 -> must fail (128 > 100).
        let opts = ExecutionOptions::new(Some(100), 65, 1024);
        assert!(matches!(
            opts,
            Err(ExecutionOptionsError::ExpectedCyclesTooBig {
                max_cycles: 100,
                expected_cycles: 128
            })
        ));

        // expected_cycles=64 rounds to 64; max_cycles=100 -> ok.
        let opts = ExecutionOptions::new(Some(100), 64, 1024);
        assert!(opts.is_ok());
        assert_eq!(opts.unwrap().expected_cycles(), 64);
    }

    #[test]
    fn max_stack_depth_validates_minimum_depth() {
        let result = ExecutionOptions::default().with_max_stack_depth(MIN_STACK_DEPTH - 1);
        assert!(matches!(
            result,
            Err(ExecutionOptionsError::MaxStackDepthTooSmall {
                max_stack_depth,
                min_stack_depth: MIN_STACK_DEPTH,
            }) if max_stack_depth == MIN_STACK_DEPTH - 1
        ));

        let result = ExecutionOptions::default().with_max_stack_depth(MIN_STACK_DEPTH);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().max_stack_depth(), MIN_STACK_DEPTH);
    }

    #[test]
    fn default_execution_options_roundtrip() {
        let options = ExecutionOptions::default();
        let bytes = options.to_bytes();
        let decoded = ExecutionOptions::read_from_bytes(&bytes).unwrap();
        assert_eq!(decoded, options);
        assert_eq!(decoded.to_bytes(), bytes);
        assert_eq!(decoded.execution_precompile_limits(), options.execution_precompile_limits());
        assert_eq!(
            decoded.verification_precompile_limits(),
            options.verification_precompile_limits()
        );
    }

    #[test]
    fn non_default_execution_options_roundtrip() {
        let execution_class = WorkClass::from_string(String::from("execution-custom"));
        let verification_class = WorkClass::from_string(String::from("verification-custom"));
        let execution_limit = WorkLimit {
            max_count: 3,
            max_total_size: 5,
            max_size: 2,
        };
        let verification_limit = WorkLimit {
            max_count: 7,
            max_total_size: 11,
            max_size: 4,
        };
        let options = ExecutionOptions::default()
            .with_core_trace_fragment_size(1)
            .unwrap()
            .with_max_advice_size_bytes(17)
            .with_overlapped_trace_build(false)
            .with_max_hash_len_bytes(19)
            .with_max_num_continuations(23)
            .with_max_stack_depth(MIN_STACK_DEPTH)
            .unwrap()
            .with_max_memory_elements(29)
            .with_execution_precompile_limits(
                PrecompileLimits::new(31).with_class(execution_class.clone(), execution_limit),
            )
            .with_verification_precompile_limits(
                PrecompileLimits::new(37)
                    .with_class(verification_class.clone(), verification_limit),
            );

        let bytes = options.to_bytes();
        let decoded = ExecutionOptions::read_from_bytes(&bytes).unwrap();
        assert_eq!(decoded, options);
        assert_eq!(decoded.to_bytes(), bytes);
        assert_eq!(decoded.execution_precompile_limits().max_elements(), 31);
        assert_eq!(decoded.verification_precompile_limits().max_elements(), 37);
        assert_eq!(
            decoded.execution_precompile_limits().class(&execution_class),
            Some(execution_limit)
        );
        assert_eq!(
            decoded.verification_precompile_limits().class(&verification_class),
            Some(verification_limit)
        );
        assert_ne!(decoded.execution_precompile_limits(), decoded.verification_precompile_limits());
    }

    #[test]
    fn execution_options_fixed_vector_roundtrip() {
        let expected = vec![
            128, 0, 0, 0, // max_cycles
            64, 0, 0, 0, // expected_cycles
            5, // core_trace_fragment_size = 2
            7, // max_advice_size_bytes = 3
            0, // overlapped_trace_build = false
            2, 2,  // max_hash_len_bytes = 128
            11, // max_num_continuations = 5
            35, // max_stack_depth = 17
            13, // max_memory_elements = 6
            7, 0, 0, 0, 0, 0, 0, 0, 1, // execution policy ceiling 7
            8, 0, 0, 0, 0, 0, 0, 0, 1, // verification policy ceiling 8
        ];
        let options = ExecutionOptions::new(Some(128), 64, 2)
            .unwrap()
            .with_max_advice_size_bytes(3)
            .with_overlapped_trace_build(false)
            .with_max_hash_len_bytes(128)
            .with_max_num_continuations(5)
            .with_max_stack_depth(17)
            .unwrap()
            .with_max_memory_elements(6)
            .with_execution_precompile_limits(PrecompileLimits::new(7))
            .with_verification_precompile_limits(PrecompileLimits::new(8));

        assert_eq!(options.to_bytes(), expected);
        let decoded = ExecutionOptions::read_from_bytes(&expected).unwrap();
        assert_eq!(decoded, options);
    }

    #[test]
    fn execution_and_verification_zero_policies_stay_distinct() {
        for execution_zero in [true, false] {
            let options = if execution_zero {
                ExecutionOptions::default()
                    .with_execution_precompile_limits(PrecompileLimits::new(0))
            } else {
                ExecutionOptions::default()
                    .with_verification_precompile_limits(PrecompileLimits::new(0))
            };
            let decoded = ExecutionOptions::read_from_bytes(&options.to_bytes()).unwrap();
            assert_eq!(decoded, options);
            if execution_zero {
                assert_eq!(decoded.execution_precompile_limits(), &PrecompileLimits::new(0));
                assert_eq!(
                    decoded.verification_precompile_limits(),
                    options.verification_precompile_limits()
                );
            } else {
                assert_eq!(decoded.verification_precompile_limits(), &PrecompileLimits::new(0));
                assert_eq!(
                    decoded.execution_precompile_limits(),
                    options.execution_precompile_limits()
                );
            }
        }
    }

    #[test]
    fn execution_options_reject_invalid_invariants() {
        let valid = encode_options(
            MIN_TRACE_LEN as u32,
            MIN_TRACE_LEN as u32,
            1,
            0,
            true,
            0,
            0,
            MIN_STACK_DEPTH,
            0,
            &PrecompileLimits::new(0),
            &PrecompileLimits::new(0),
        );
        assert!(ExecutionOptions::read_from_bytes(&valid).is_ok());

        let mut bytes = valid.clone();
        bytes[0..4].copy_from_slice(&((MIN_TRACE_LEN as u32) - 1).to_le_bytes());
        assert!(ExecutionOptions::read_from_bytes(&bytes).is_err());

        let mut bytes = valid.clone();
        bytes[0..4].copy_from_slice(&(ExecutionOptions::MAX_CYCLES + 1).to_le_bytes());
        assert!(ExecutionOptions::read_from_bytes(&bytes).is_err());

        let mut bytes = valid.clone();
        bytes[4..8].copy_from_slice(&((MIN_TRACE_LEN as u32) + 1).to_le_bytes());
        assert!(ExecutionOptions::read_from_bytes(&bytes).is_err());

        let mut bytes = valid.clone();
        bytes[4..8].copy_from_slice(&((MIN_TRACE_LEN as u32) - 1).to_le_bytes());
        assert!(ExecutionOptions::read_from_bytes(&bytes).is_err());

        let mut bytes = valid;
        bytes[4..8].copy_from_slice(&((MIN_TRACE_LEN as u32) * 2).to_le_bytes());
        assert!(ExecutionOptions::read_from_bytes(&bytes).is_err());

        let zero_fragment = encode_options(
            MIN_TRACE_LEN as u32,
            MIN_TRACE_LEN as u32,
            0,
            0,
            true,
            0,
            0,
            MIN_STACK_DEPTH,
            0,
            &PrecompileLimits::new(0),
            &PrecompileLimits::new(0),
        );
        assert!(ExecutionOptions::read_from_bytes(&zero_fragment).is_err());

        let shallow_stack = encode_options(
            MIN_TRACE_LEN as u32,
            MIN_TRACE_LEN as u32,
            1,
            0,
            true,
            0,
            0,
            MIN_STACK_DEPTH - 1,
            0,
            &PrecompileLimits::new(0),
            &PrecompileLimits::new(0),
        );
        assert!(ExecutionOptions::read_from_bytes(&shallow_stack).is_err());
    }

    #[test]
    fn execution_options_reject_invalid_bool_and_bad_bytes() {
        let valid = encode_options(
            MIN_TRACE_LEN as u32,
            MIN_TRACE_LEN as u32,
            1,
            0,
            true,
            0,
            0,
            MIN_STACK_DEPTH,
            0,
            &PrecompileLimits::new(0),
            &PrecompileLimits::new(0),
        );

        let mut invalid_bool = valid.clone();
        invalid_bool[10] = 2;
        assert!(ExecutionOptions::read_from_bytes(&invalid_bool).is_err());

        for len in 0..valid.len() {
            assert!(ExecutionOptions::read_from_bytes(&valid[..len]).is_err());
        }

        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(ExecutionOptions::read_from_bytes(&trailing).is_err());
        assert!(ExecutionOptions::read_from_bytes_with_budget(&trailing, trailing.len()).is_err());
        assert!(ExecutionOptions::read_from_bytes_with_budget(&trailing, valid.len()).is_err());
        assert!(ExecutionOptions::read_from_bytes_with_budget(&valid, valid.len()).is_ok());
        assert!(ExecutionOptions::read_from_bytes_with_budget(&valid, valid.len() + 1).is_ok());
        assert!(ExecutionOptions::read_from_bytes_with_budget(&valid, valid.len() - 1).is_err());
    }

    #[test]
    fn execution_options_reject_overlong_scalar_usize() {
        let mut bytes = Vec::new();
        (MIN_TRACE_LEN as u32).write_into(&mut bytes);
        (MIN_TRACE_LEN as u32).write_into(&mut bytes);
        bytes.extend_from_slice(&[0x06, 0x00]);
        0usize.write_into(&mut bytes);
        bytes.write_bool(true);
        0usize.write_into(&mut bytes);
        0usize.write_into(&mut bytes);
        MIN_STACK_DEPTH.write_into(&mut bytes);
        0usize.write_into(&mut bytes);
        PrecompileLimits::new(0).write_into(&mut bytes);
        PrecompileLimits::new(0).write_into(&mut bytes);
        assert!(ExecutionOptions::read_from_bytes(&bytes).is_err());
    }

    #[test]
    fn execution_options_reject_overlong_nested_policy_count() {
        let mut valid = Vec::new();
        write_option_header(&mut valid);
        PrecompileLimits::new(0).write_into(&mut valid);
        PrecompileLimits::new(0).write_into(&mut valid);
        assert!(ExecutionOptions::read_from_bytes(&valid).is_ok());

        let mut bytes = Vec::new();
        write_option_header(&mut bytes);
        0u64.write_into(&mut bytes);
        bytes.extend_from_slice(&[0x02, 0x00]);
        PrecompileLimits::new(0).write_into(&mut bytes);
        assert!(ExecutionOptions::read_from_bytes(&bytes).is_err());
    }

    #[test]
    fn execution_options_reject_duplicate_policy_keys() {
        let custom = WorkClass::from_string(String::from("custom"));
        let limit = WorkLimit {
            max_count: 1,
            max_total_size: 2,
            max_size: 1,
        };
        let mut bytes = Vec::new();
        write_option_header(&mut bytes);
        42u64.write_into(&mut bytes);
        2usize.write_into(&mut bytes);
        custom.write_into(&mut bytes);
        limit.write_into(&mut bytes);
        custom.write_into(&mut bytes);
        limit.write_into(&mut bytes);
        0u64.write_into(&mut bytes);
        0usize.write_into(&mut bytes);
        assert!(ExecutionOptions::read_from_bytes(&bytes).is_err());
    }

    #[test]
    fn execution_options_reject_oversized_policy_count() {
        let mut bytes = Vec::new();
        write_option_header(&mut bytes);
        0u64.write_into(&mut bytes);
        usize::MAX.write_into(&mut bytes);
        assert!(ExecutionOptions::read_from_bytes(&bytes).is_err());
    }

    #[test]
    fn execution_options_reject_invalid_utf8_class_name() {
        let limit = WorkLimit {
            max_count: 1,
            max_total_size: 2,
            max_size: 1,
        };

        let mut valid = Vec::new();
        write_option_header(&mut valid);
        0u64.write_into(&mut valid);
        1usize.write_into(&mut valid);
        2usize.write_into(&mut valid);
        valid.extend_from_slice(b"ab");
        limit.write_into(&mut valid);
        PrecompileLimits::new(0).write_into(&mut valid);
        assert!(ExecutionOptions::read_from_bytes(&valid).is_ok());

        let mut bytes = Vec::new();
        write_option_header(&mut bytes);
        0u64.write_into(&mut bytes);
        1usize.write_into(&mut bytes);
        2usize.write_into(&mut bytes);
        bytes.extend_from_slice(&[0xff, 0xfe]);
        limit.write_into(&mut bytes);
        PrecompileLimits::new(0).write_into(&mut bytes);
        assert!(ExecutionOptions::read_from_bytes(&bytes).is_err());
    }
}
