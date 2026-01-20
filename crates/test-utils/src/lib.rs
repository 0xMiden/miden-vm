#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};

use miden_assembly::{KernelLibrary, Library, Parse, diagnostics::reporting::PrintDiagnostic};
pub use miden_assembly::{
    Path,
    debuginfo::{DefaultSourceManager, SourceFile, SourceLanguage, SourceManager},
    diagnostics::Report,
};
pub use miden_core::{
    EMPTY_WORD, Felt, ONE, StackInputs, StackOutputs, WORD_SIZE, Word, ZERO,
    chiplets::hasher::{STATE_WIDTH, hash_elements},
    field::{Field, PrimeCharacteristicRing, PrimeField64, QuadFelt},
    stack::MIN_STACK_DEPTH,
    utils::{IntoBytes, ToElements, group_slice_elements},
};
use miden_core::{EventName, ProgramInfo, chiplets::hasher::apply_permutation};
pub use miden_processor::{
    AdviceInputs, AdviceProvider, AdviceStackBuilder, BaseHost, ContextId, ExecutionError,
    ExecutionTrace, ProcessState,
};
use miden_processor::{
    DefaultDebugHandler, DefaultHost, EventHandler, Program,
    fast::{ExecutionOutput, FastProcessor, execution_tracer::TraceGenerationContext},
    parallel::build_trace,
};
#[cfg(not(target_arch = "wasm32"))]
pub use miden_prover::prove_sync;
use miden_prover::utils::range;
pub use miden_prover::{ProvingOptions, prove};
pub use miden_verifier::verify;
pub use pretty_assertions::{assert_eq, assert_ne, assert_str_eq};
#[cfg(not(target_family = "wasm"))]
use proptest::prelude::{Arbitrary, Strategy};
pub use test_case::test_case;

pub mod math {
    pub use miden_core::{
        field::{ExtensionField, Field, PrimeField64, QuadFelt},
        utils::ToElements,
    };
}

pub mod serde {
    pub use miden_core::utils::{
        ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable, SliceReader,
    };
}

pub mod crypto;

#[cfg(not(target_family = "wasm"))]
pub mod rand;

mod test_builders;

use miden_core::sys_events::SystemEvent;
#[cfg(not(target_family = "wasm"))]
pub use proptest;
// CONSTANTS
// ================================================================================================

/// A value just over what a [u32] integer can hold.
pub const U32_BOUND: u64 = u32::MAX as u64 + 1;

/// A source code of the `truncate_stack` procedure.
pub const TRUNCATE_STACK_PROC: &str = "
@locals(4)
proc truncate_stack
     loc_storew_be.0 dropw movupw.3
    sdepth neq.16
    while.true
        dropw movupw.3
        sdepth neq.16
    end
    loc_loadw_be.0
end
";

// TEST HANDLER
// ================================================================================================

/// Asserts that running the given assembler test will result in the expected error.
#[cfg(all(feature = "std", not(target_family = "wasm")))]
#[macro_export]
macro_rules! expect_assembly_error {
    ($test:expr, $(|)? $( $pattern:pat_param )|+ $( if $guard: expr )? $(,)?) => {
        let error = $test.compile().expect_err("expected assembly to fail");
        match error.downcast::<::miden_assembly::AssemblyError>() {
            Ok(error) => {
                ::miden_core::assert_matches!(error, $( $pattern )|+ $( if $guard )?);
            }
            Err(report) => {
                panic!(r#"
assertion failed (expected assembly error, but got a different type):
    left: `{:?}`,
    right: `{}`"#, report, stringify!($($pattern)|+ $(if $guard)?));
            }
        }
    };
}

/// Asserts that running the given execution test will result in the expected error.
#[cfg(all(feature = "std", not(target_family = "wasm")))]
#[macro_export]
macro_rules! expect_exec_error_matches {
    ($test:expr, $(|)? $( $pattern:pat_param )|+ $( if $guard: expr )? $(,)?) => {
        match $test.execute() {
            Ok(_) => panic!("expected execution to fail @ {}:{}", file!(), line!()),
            Err(error) => ::miden_core::assert_matches!(error, $( $pattern )|+ $( if $guard )?),
        }
    };
}

/// Like [miden_assembly::testing::assert_diagnostic], but matches each non-empty line of the
/// rendered output to a corresponding pattern.
///
/// So if the output has 3 lines, the second of which is empty, and you provide 2 patterns, the
/// assertion passes if the first line matches the first pattern, and the third line matches the
/// second pattern - the second line is ignored because it is empty.
#[cfg(not(target_family = "wasm"))]
#[macro_export]
macro_rules! assert_diagnostic_lines {
    ($diagnostic:expr, $($expected:expr),+) => {{
        use miden_assembly::testing::Pattern;
        let actual = format!("{}", miden_assembly::diagnostics::reporting::PrintDiagnostic::new_without_color($diagnostic));
        let lines = actual.lines().filter(|l| !l.trim().is_empty()).zip([$(Pattern::from($expected)),*].into_iter());
        for (actual_line, expected) in lines {
            expected.assert_match_with_context(actual_line, &actual);
        }
    }};
}

#[cfg(not(target_family = "wasm"))]
#[macro_export]
macro_rules! assert_assembler_diagnostic {
    ($test:ident, $($expected:literal),+) => {{
        let error = $test
            .compile()
            .expect_err("expected diagnostic to be raised, but compilation succeeded");
        assert_diagnostic_lines!(error, $($expected),*);
    }};

    ($test:ident, $($expected:expr),+) => {{
        let error = $test
            .compile()
            .expect_err("expected diagnostic to be raised, but compilation succeeded");
        assert_diagnostic_lines!(error, $($expected),*);
    }};
}

/// This is a container for the data required to run tests, which allows for running several
/// different types of tests.
///
/// Types of valid result tests:
/// - Execution test: check that running a program compiled from the given source has the specified
///   results for the given (optional) inputs.
/// - Proptest: run an execution test inside a proptest.
///
/// Types of failure tests:
/// - Assembly error test: check that attempting to compile the given source causes an AssemblyError
///   which contains the specified substring.
/// - Execution error test: check that running a program compiled from the given source causes an
///   ExecutionError which contains the specified substring.
pub struct Test {
    pub source_manager: Arc<DefaultSourceManager>,
    pub source: Arc<SourceFile>,
    pub kernel_source: Option<Arc<SourceFile>>,
    pub stack_inputs: StackInputs,
    pub advice_inputs: AdviceInputs,
    pub in_debug_mode: bool,
    pub libraries: Vec<Library>,
    pub handlers: Vec<(EventName, Arc<dyn EventHandler>)>,
    pub add_modules: Vec<(Arc<Path>, String)>,
}

// BUFFER WRITER FOR TESTING
// ================================================================================================

/// A writer that buffers output in a String for testing debug output.
#[derive(Default)]
pub struct BufferWriter {
    pub buffer: String,
}

impl core::fmt::Write for BufferWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.buffer.push_str(s);
        Ok(())
    }
}

impl Test {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Creates the simplest possible new test, with only a source string and no inputs.
    pub fn new(name: &str, source: &str, in_debug_mode: bool) -> Self {
        let source_manager = Arc::new(DefaultSourceManager::default());
        let source = source_manager.load(SourceLanguage::Masm, name.into(), source.to_string());
        Self {
            source_manager,
            source,
            kernel_source: None,
            stack_inputs: StackInputs::default(),
            advice_inputs: AdviceInputs::default(),
            in_debug_mode,
            libraries: Vec::default(),
            handlers: Vec::new(),
            add_modules: Vec::default(),
        }
    }

    /// Add an extra module to link in during assembly
    pub fn add_module(&mut self, path: impl AsRef<Path>, source: impl ToString) {
        self.add_modules.push((path.as_ref().into(), source.to_string()));
    }

    /// Add a handler for a specific event when running the `Host`.
    pub fn add_event_handler(&mut self, event: EventName, handler: impl EventHandler) {
        self.add_event_handlers(vec![(event, Arc::new(handler))]);
    }

    /// Add a handler for a specific event when running the `Host`.
    pub fn add_event_handlers(&mut self, handlers: Vec<(EventName, Arc<dyn EventHandler>)>) {
        for (event, handler) in handlers {
            let event_name = event.as_str();
            if SystemEvent::from_name(event_name).is_some() {
                panic!("tried to register handler for reserved system event: {event_name}")
            }
            let event_id = event.to_event_id();
            if self.handlers.iter().any(|(e, _)| e.to_event_id() == event_id) {
                panic!("handler for event '{event_name}' was already added")
            }
            self.handlers.push((event, handler));
        }
    }

    // TEST METHODS
    // --------------------------------------------------------------------------------------------

    /// Builds a final stack from the provided stack-ordered array and asserts that executing the
    /// test will result in the expected final stack state.
    #[cfg(not(target_arch = "wasm32"))]
    #[track_caller]
    pub fn expect_stack(&self, final_stack: &[u64]) {
        let result = self.get_last_stack_state().as_int_vec();
        let expected = resize_to_min_stack_depth(final_stack);
        assert_eq!(expected, result, "Expected stack to be {:?}, found {:?}", expected, result);
    }

    /// Executes the test and validates that the process memory has the elements of `expected_mem`
    /// at address `mem_start_addr` and that the end of the stack execution trace matches the
    /// `final_stack`.
    #[cfg(not(target_arch = "wasm32"))]
    #[track_caller]
    pub fn expect_stack_and_memory(
        &self,
        final_stack: &[u64],
        mem_start_addr: u32,
        expected_mem: &[u64],
    ) {
        // compile the program
        let (program, host) = self.get_program_and_host();
        let mut host = host.with_source_manager(self.source_manager.clone());

        // execute the test
        let stack_inputs: Vec<Felt> = self.stack_inputs.into_iter().collect();
        let processor = if self.in_debug_mode {
            FastProcessor::new_debug(&stack_inputs, self.advice_inputs.clone())
        } else {
            FastProcessor::new_with_advice_inputs(&stack_inputs, self.advice_inputs.clone())
        };
        let execution_output = processor.execute_sync(&program, &mut host).unwrap();

        // validate the memory state
        for (addr, mem_value) in
            (range(mem_start_addr as usize, expected_mem.len())).zip(expected_mem.iter())
        {
            let mem_state = execution_output
                .memory
                .read_element(ContextId::root(), Felt::from_u32(addr as u32))
                .unwrap();
            assert_eq!(
                *mem_value,
                mem_state.as_canonical_u64(),
                "Expected memory [{}] => {:?}, found {:?}",
                addr,
                mem_value,
                mem_state
            );
        }

        // validate the stack states
        self.expect_stack(final_stack);
    }

    /// Asserts that executing the test inside a proptest results in the expected final stack state.
    /// The proptest will return a test failure instead of panicking if the assertion condition
    /// fails.
    #[cfg(not(target_family = "wasm"))]
    pub fn prop_expect_stack(
        &self,
        final_stack: &[u64],
    ) -> Result<(), proptest::prelude::TestCaseError> {
        let result = self.get_last_stack_state().as_int_vec();
        proptest::prop_assert_eq!(resize_to_min_stack_depth(final_stack), result);

        Ok(())
    }

    // UTILITY METHODS
    // --------------------------------------------------------------------------------------------

    /// Compiles a test's source and returns the resulting Program together with the associated
    /// kernel library (when specified).
    ///
    /// # Errors
    /// Returns an error if compilation of the program source or the kernel fails.
    pub fn compile(&self) -> Result<(Program, Option<KernelLibrary>), Report> {
        use miden_assembly::{Assembler, ParseOptions, ast::ModuleKind};

        // Enable debug tracing to stderr via the MIDEN_LOG environment variable, if present
        #[cfg(not(target_family = "wasm"))]
        {
            let _ = env_logger::Builder::from_env("MIDEN_LOG").format_timestamp(None).try_init();
        }

        let (assembler, kernel_lib) = if let Some(kernel) = self.kernel_source.clone() {
            let kernel_lib =
                Assembler::new(self.source_manager.clone()).assemble_kernel(kernel).unwrap();

            (
                Assembler::with_kernel(self.source_manager.clone(), kernel_lib.clone()),
                Some(kernel_lib),
            )
        } else {
            (Assembler::new(self.source_manager.clone()), None)
        };

        let mut assembler =
            self.add_modules.iter().fold(assembler, |mut assembler, (path, source)| {
                let module = source
                    .parse_with_options(
                        self.source_manager.clone(),
                        ParseOptions::new(ModuleKind::Library, path.clone()),
                    )
                    .expect("invalid masm source code");
                assembler.compile_and_statically_link(module).expect("failed to link module");
                assembler
            });
        // Debug mode is now always enabled
        for library in &self.libraries {
            assembler.link_dynamic_library(library).unwrap();
        }

        Ok((assembler.assemble_program(self.source.clone())?, kernel_lib))
    }

    /// Compiles the test's source to a Program and executes it with the tests inputs. Returns a
    /// resulting execution trace or error.
    ///
    /// Internally, this also checks that the slow and fast processors agree on the stack
    /// outputs.
    #[cfg(not(target_arch = "wasm32"))]
    #[track_caller]
    pub fn execute(&self) -> Result<ExecutionTrace, ExecutionError> {
        // Note: we fix a large fragment size here, as we're not testing the fragment boundaries
        // with these tests (which are tested separately), but rather only the per-fragment trace
        // generation logic - though not too big so as to over-allocate memory.
        const FRAGMENT_SIZE: usize = 1 << 16;

        let (program, host) = self.get_program_and_host();
        let mut host = host.with_source_manager(self.source_manager.clone());

        let fast_stack_result = {
            let stack_inputs: Vec<Felt> = self.stack_inputs.into_iter().collect();
            let advice_inputs: AdviceInputs = self.advice_inputs.clone();
            let fast_processor = FastProcessor::new_with_options(
                &stack_inputs,
                advice_inputs,
                miden_air::ExecutionOptions::default()
                    .with_debugging(self.in_debug_mode)
                    .with_core_trace_fragment_size(FRAGMENT_SIZE)
                    .unwrap(),
            );
            fast_processor.execute_for_trace_sync(&program, &mut host)
        };

        // compare fast and slow processors' stack outputs
        self.assert_result_with_step_execution(&fast_stack_result);

        fast_stack_result.map(|(execution_output, trace_generation_ctx)| {
            let trace = build_trace(
                execution_output,
                trace_generation_ctx,
                program.hash(),
                program.kernel().clone(),
            );

            assert_eq!(&program.hash(), trace.program_hash(), "inconsistent program hash");
            trace
        })
    }

    /// Compiles the test's source to a Program and executes it with the tests inputs.
    ///
    /// Returns the [`ExecutionOutput`] once execution is finished.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn execute_for_output(&self) -> Result<(ExecutionOutput, DefaultHost), ExecutionError> {
        let (program, host) = self.get_program_and_host();
        let mut host = host.with_source_manager(self.source_manager.clone());

        let processor = FastProcessor::new_debug(
            &self.stack_inputs.into_iter().collect::<Vec<Felt>>(),
            self.advice_inputs.clone(),
        );

        processor.execute_sync(&program, &mut host).map(|output| (output, host))
    }

    /// Compiles the test's source to a Program and executes it with the tests inputs. Returns
    /// the [`StackOutputs`] and a [`String`] containing all debug output.
    ///
    /// If the execution fails, the output is printed `stderr`.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn execute_with_debug_buffer(&self) -> Result<(StackOutputs, String), ExecutionError> {
        let debug_handler = DefaultDebugHandler::new(BufferWriter::default());

        let (program, host) = self.get_program_and_host();
        let mut host = host
            .with_source_manager(self.source_manager.clone())
            .with_debug_handler(debug_handler);

        let processor = FastProcessor::new_debug(
            &self.stack_inputs.into_iter().collect::<Vec<Felt>>(),
            self.advice_inputs.clone(),
        );

        let stack_result = processor.execute_sync(&program, &mut host);

        let debug_output = host.debug_handler().writer().buffer.clone();

        match stack_result {
            Ok(exec_output) => Ok((exec_output.stack, debug_output)),
            Err(err) => {
                // If we get an error, we print the output as an error
                #[cfg(feature = "std")]
                std::eprintln!("{}", debug_output);
                Err(err)
            },
        }
    }

    /// Compiles the test's code into a program, then generates and verifies a proof of execution
    /// using the given public inputs and the specified number of stack outputs. When `test_fail`
    /// is true, this function will force a failure by modifying the first output.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn prove_and_verify(&self, pub_inputs: Vec<u64>, test_fail: bool) {
        let (program, mut host) = self.get_program_and_host();
        let stack_inputs = StackInputs::try_from_ints(pub_inputs).unwrap();
        let (mut stack_outputs, proof) = miden_prover::prove_sync(
            &program,
            stack_inputs,
            self.advice_inputs.clone(),
            &mut host,
            ProvingOptions::default(),
        )
        .unwrap();

        let program_info = ProgramInfo::from(program);
        if test_fail {
            stack_outputs.stack_mut()[0] += ONE;
            assert!(
                miden_verifier::verify(program_info, stack_inputs, stack_outputs, proof).is_err()
            );
        } else {
            let result = miden_verifier::verify(program_info, stack_inputs, stack_outputs, proof);
            assert!(result.is_ok(), "error: {result:?}");
        }
    }

    /// Returns the last state of the stack after executing a test.
    #[cfg(not(target_arch = "wasm32"))]
    #[track_caller]
    pub fn get_last_stack_state(&self) -> StackOutputs {
        let trace = self
            .execute()
            .inspect_err(|_err| {
                #[cfg(feature = "std")]
                std::eprintln!("{}", PrintDiagnostic::new_without_color(_err))
            })
            .expect("failed to execute");

        trace.last_stack_state()
    }

    // HELPERS
    // ------------------------------------------------------------------------------------------

    /// Returns the program and host for the test.
    ///
    /// The host is initialized with the advice inputs provided in the test, as well as the kernel
    /// and library MAST forests.
    fn get_program_and_host(&self) -> (Program, DefaultHost) {
        let (program, kernel) = self.compile().expect("Failed to compile test source.");
        let mut host = DefaultHost::default();
        if let Some(kernel) = kernel {
            host.load_library(kernel.mast_forest()).unwrap();
        }
        for library in &self.libraries {
            host.load_library(library.mast_forest()).unwrap();
        }
        for (event, handler) in &self.handlers {
            host.register_handler(event.clone(), handler.clone()).unwrap();
        }

        (program, host)
    }

    fn assert_result_with_step_execution(
        &self,
        fast_result: &Result<(ExecutionOutput, TraceGenerationContext), ExecutionError>,
    ) {
        fn compare_results(
            left_result: Result<StackOutputs, &ExecutionError>,
            right_result: &Result<StackOutputs, ExecutionError>,
            left_name: &str,
            right_name: &str,
        ) {
            match (left_result, right_result) {
                (Ok(left_stack_outputs), Ok(right_stack_outputs)) => {
                    assert_eq!(
                        left_stack_outputs, *right_stack_outputs,
                        "stack outputs do not match between {left_name} and {right_name}"
                    );
                },
                (Err(left_err), Err(right_err)) => {
                    // assert that diagnostics match
                    let right_diagnostic =
                        format!("{}", PrintDiagnostic::new_without_color(right_err));
                    let left_diagnostic =
                        format!("{}", PrintDiagnostic::new_without_color(left_err));

                    assert_eq!(
                        left_diagnostic, right_diagnostic,
                        "diagnostics do not match between {left_name} and {right_name}:\n{left_name}: {}\n{right_name}: {}",
                        left_diagnostic, right_diagnostic
                    );
                },
                (Ok(_), Err(right_err)) => {
                    let right_diagnostic =
                        format!("{}", PrintDiagnostic::new_without_color(right_err));
                    panic!(
                        "expected error, but {left_name} succeeded. {right_name} error:\n{right_diagnostic}"
                    );
                },
                (Err(left_err), Ok(_)) => {
                    panic!(
                        "expected success, but {left_name} failed. {left_name} error:\n{left_err}"
                    );
                },
            }
        }

        let (program, host) = self.get_program_and_host();
        let mut host = host.with_source_manager(self.source_manager.clone());

        let fast_result_by_step = {
            let stack_inputs: Vec<Felt> = self.stack_inputs.into_iter().collect();
            let advice_inputs: AdviceInputs = self.advice_inputs.clone();
            let fast_process = if self.in_debug_mode {
                FastProcessor::new_debug(&stack_inputs, advice_inputs)
            } else {
                FastProcessor::new_with_advice_inputs(&stack_inputs, advice_inputs)
            };
            fast_process.execute_by_step_sync(&program, &mut host)
        };

        compare_results(
            fast_result.as_ref().map(|(output, _)| output.stack),
            &fast_result_by_step,
            "fast processor",
            "fast processor by step",
        );
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Appends a Word to an operand stack Vec.
pub fn append_word_to_vec(target: &mut Vec<u64>, word: Word) {
    target.extend(word.iter().map(Felt::as_canonical_u64));
}

/// Converts a slice of Felts into a vector of u64 values.
pub fn felt_slice_to_ints(values: &[Felt]) -> Vec<u64> {
    values.iter().map(|e| (*e).as_canonical_u64()).collect()
}

pub fn resize_to_min_stack_depth(values: &[u64]) -> Vec<u64> {
    let mut result: Vec<u64> = values.to_vec();
    result.resize(MIN_STACK_DEPTH, 0);
    result
}

/// A proptest strategy for generating a random word with 4 values of type T.
#[cfg(not(target_family = "wasm"))]
pub fn prop_randw<T: Arbitrary>() -> impl Strategy<Value = Vec<T>> {
    use proptest::prelude::{any, prop};
    prop::collection::vec(any::<T>(), 4)
}

/// Given a hasher state, perform one permutation.
///
/// This helper reconstructs that state, applies a permutation, and returns the resulting
/// `[RATE0',RATE1',CAP']` back in stack order.
pub fn build_expected_perm(values: &[u64]) -> [Felt; STATE_WIDTH] {
    assert!(values.len() >= STATE_WIDTH, "expected at least 12 values for hperm test");

    // Reconstruct the internal RPO state from the initial stack:
    // stack[0..12] = [v0, ..., v11]
    // => state[0..12] = stack[0..12] in [RATE0,RATE1,CAPACITY] layout.
    let mut state = [ZERO; STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        state[i] = Felt::new(values[i]);
    }

    // Apply the permutation
    apply_permutation(&mut state);

    // Map internal state back to stack layout [RATE0', RATE1', CAP']
    let mut out = [ZERO; STATE_WIDTH];
    out[..STATE_WIDTH].copy_from_slice(&state[..STATE_WIDTH]);

    out
}

pub fn build_expected_hash(values: &[u64]) -> [Felt; 4] {
    let digest = hash_elements(&values.iter().map(|&v| Felt::new(v)).collect::<Vec<_>>());
    digest.into()
}

// Generates the MASM code which pushes the input values during the execution of the program.
#[cfg(all(feature = "std", not(target_family = "wasm")))]
pub fn push_inputs(inputs: &[u64]) -> String {
    let mut result = String::new();

    inputs.iter().for_each(|v| result.push_str(&format!("push.{v}\n")));
    result
}

/// Helper function to get column name for debugging
pub fn get_column_name(col_idx: usize) -> String {
    use miden_air::trace::{
        CLK_COL_IDX, CTX_COL_IDX, DECODER_TRACE_OFFSET, FN_HASH_OFFSET, RANGE_CHECK_TRACE_OFFSET,
        STACK_TRACE_OFFSET,
        decoder::{
            ADDR_COL_IDX, GROUP_COUNT_COL_IDX, HASHER_STATE_OFFSET, IN_SPAN_COL_IDX,
            NUM_HASHER_COLUMNS, NUM_OP_BATCH_FLAGS, NUM_OP_BITS, NUM_OP_BITS_EXTRA_COLS,
            OP_BATCH_FLAGS_OFFSET, OP_BITS_EXTRA_COLS_OFFSET, OP_BITS_OFFSET, OP_INDEX_COL_IDX,
        },
        stack::{B0_COL_IDX, B1_COL_IDX, H0_COL_IDX, STACK_TOP_OFFSET},
    };

    match col_idx {
        // System columns
        CLK_COL_IDX => "clk".to_string(),
        CTX_COL_IDX => "ctx".to_string(),
        i if (FN_HASH_OFFSET..FN_HASH_OFFSET + 4).contains(&i) => {
            format!("fn_hash[{}]", i - FN_HASH_OFFSET)
        },

        // Decoder columns
        i if i == DECODER_TRACE_OFFSET + ADDR_COL_IDX => "decoder_addr".to_string(),
        i if range(DECODER_TRACE_OFFSET + OP_BITS_OFFSET, NUM_OP_BITS).contains(&i) => {
            format!("op_bits[{}]", i - (DECODER_TRACE_OFFSET + OP_BITS_OFFSET))
        },
        i if range(DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET, NUM_HASHER_COLUMNS).contains(&i) => {
            format!("hasher_state[{}]", i - (DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET))
        },
        i if i == DECODER_TRACE_OFFSET + IN_SPAN_COL_IDX => "in_span".to_string(),
        i if i == DECODER_TRACE_OFFSET + GROUP_COUNT_COL_IDX => "group_count".to_string(),
        i if i == DECODER_TRACE_OFFSET + OP_INDEX_COL_IDX => "op_index".to_string(),
        i if range(DECODER_TRACE_OFFSET + OP_BATCH_FLAGS_OFFSET, NUM_OP_BATCH_FLAGS)
            .contains(&i) =>
        {
            format!("op_batch_flag[{}]", i - (DECODER_TRACE_OFFSET + OP_BATCH_FLAGS_OFFSET))
        },
        i if range(DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET, NUM_OP_BITS_EXTRA_COLS)
            .contains(&i) =>
        {
            format!("op_bits_extra[{}]", i - (DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET))
        },
        i if range(DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET, NUM_OP_BITS_EXTRA_COLS)
            .contains(&i) =>
        {
            format!("op_bits_extra[{}]", i - (DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET))
        },

        // Stack columns
        i if range(STACK_TRACE_OFFSET + STACK_TOP_OFFSET, MIN_STACK_DEPTH).contains(&i) => {
            format!("stack[{}]", i - (STACK_TRACE_OFFSET + STACK_TOP_OFFSET))
        },
        i if i == STACK_TRACE_OFFSET + B0_COL_IDX => "stack_b0".to_string(),
        i if i == STACK_TRACE_OFFSET + B1_COL_IDX => "stack_b1".to_string(),
        i if i == STACK_TRACE_OFFSET + H0_COL_IDX => "stack_h0".to_string(),

        // Range check columns
        i if i >= RANGE_CHECK_TRACE_OFFSET => {
            format!("range_check[{}]", i - RANGE_CHECK_TRACE_OFFSET)
        },

        // Default case
        _ => format!("unknown_col[{}]", col_idx),
    }
}
