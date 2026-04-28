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
#[cfg(not(target_family = "wasm"))]
use miden_core::program::ProgramInfo;
pub use miden_core::{
    EMPTY_WORD, Felt, ONE, WORD_SIZE, Word, ZERO,
    chiplets::hasher::{STATE_WIDTH, hash_elements},
    field::{Field, PrimeCharacteristicRing, PrimeField64, QuadFelt},
    program::{MIN_STACK_DEPTH, StackInputs, StackOutputs},
    utils::{IntoBytes, ToElements, group_slice_elements},
};
use miden_core::{
    chiplets::hasher::apply_permutation,
    events::{EventName, SystemEvent},
};
pub use miden_processor::{
    ContextId, ExecutionError, ProcessorState,
    advice::{AdviceInputs, AdviceProvider, AdviceStackBuilder},
    trace::ExecutionTrace,
};
#[cfg(not(target_family = "wasm"))]
use miden_processor::{DefaultDebugHandler, trace::build_trace};
use miden_processor::{
    DefaultHost, ExecutionOutput, FastProcessor, Program, TraceBuildInputs, event::EventHandler,
};
#[cfg(not(target_family = "wasm"))]
pub use miden_prover::prove_sync;
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

pub use miden_core::serde;

pub mod crypto;

#[cfg(not(target_family = "wasm"))]
pub mod rand;

mod test_builders;

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

// COMPILE CACHE
// ================================================================================================

/// Key for the process-local compile cache, keyed by all inputs that affect compilation output.
///
/// The source manager identity is included so cached programs keep their debug/source mapping local
/// to the test context that produced them.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg(all(feature = "std", not(target_family = "wasm")))]
struct CompileCacheKey {
    source_manager: usize,
    source: SourceCacheKey,
    kernel_source: Option<SourceCacheKey>,
    add_modules: Vec<(String, String)>,
    library_digests: Vec<Word>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg(all(feature = "std", not(target_family = "wasm")))]
struct SourceCacheKey {
    uri: String,
    source: String,
}

#[cfg(all(feature = "std", not(target_family = "wasm")))]
type CompileCacheValue = (Program, Option<KernelLibrary>);

#[cfg(all(feature = "std", not(target_family = "wasm")))]
type CompileCache = std::collections::HashMap<CompileCacheKey, CompileCacheValue>;

#[cfg(all(feature = "std", not(target_family = "wasm")))]
static COMPILE_CACHE: std::sync::Mutex<Option<CompileCache>> = std::sync::Mutex::new(None);

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

    /// Adds kernel source to this test so it is assembled and linked during compilation.
    #[track_caller]
    pub fn with_kernel(self, kernel_source: impl ToString) -> Self {
        self.with_kernel_source(
            format!("kernel{}", core::panic::Location::caller().line()),
            kernel_source,
        )
    }

    /// Adds kernel source to this test so it is assembled and linked during compilation.
    pub fn with_kernel_source(
        mut self,
        kernel_name: impl Into<String>,
        kernel_source: impl ToString,
    ) -> Self {
        self.kernel_source = Some(self.source_manager.load(
            SourceLanguage::Masm,
            kernel_name.into().into(),
            kernel_source.to_string(),
        ));
        self
    }

    /// Sets the stack inputs for this test using stack-ordered values.
    #[track_caller]
    pub fn with_stack_inputs(mut self, stack_inputs: impl AsRef<[u64]>) -> Self {
        self.stack_inputs = StackInputs::try_from_ints(stack_inputs.as_ref().to_vec()).unwrap();
        self
    }

    /// Adds a library to link in during assembly.
    pub fn with_library(mut self, library: impl Into<Library>) -> Self {
        self.libraries.push(library.into());
        self
    }

    /// Adds a handler for a specific event when running the `Host`.
    pub fn with_event_handler(mut self, event: EventName, handler: impl EventHandler) -> Self {
        self.add_event_handler(event, handler);
        self
    }

    /// Adds handlers for specific events when running the `Host`.
    pub fn with_event_handlers(
        mut self,
        handlers: Vec<(EventName, Arc<dyn EventHandler>)>,
    ) -> Self {
        self.add_event_handlers(handlers);
        self
    }

    /// Adds an extra module to link in during assembly.
    pub fn with_module(mut self, path: impl AsRef<Path>, source: impl ToString) -> Self {
        self.add_module(path, source);
        self
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
    #[cfg(not(target_family = "wasm"))]
    #[track_caller]
    pub fn expect_stack(&self, final_stack: &[u64]) {
        let result = self.get_last_stack_state().as_int_vec();
        let expected = resize_to_min_stack_depth(final_stack);
        assert_eq!(expected, result, "Expected stack to be {:?}, found {:?}", expected, result);
    }

    /// Executes the test and validates that the process memory has the elements of `expected_mem`
    /// at address `mem_start_addr` and that the end of the stack execution trace matches the
    /// `final_stack`.
    #[cfg(not(target_family = "wasm"))]
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
        let processor = FastProcessor::new(self.stack_inputs)
            .with_advice(self.advice_inputs.clone())
            .with_debugging(self.in_debug_mode)
            .with_tracing(self.in_debug_mode);
        let execution_output = processor.execute_sync(&program, &mut host).unwrap();

        // validate the memory state
        for (addr, mem_value) in ((mem_start_addr as usize)
            ..(mem_start_addr as usize + expected_mem.len()))
            .zip(expected_mem.iter())
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

    /// Executes the test with the provided stack inputs and asserts the final stack state.
    ///
    /// This preserves the same execution coverage as [`expect_stack`](Self::expect_stack): traced
    /// execution, step/resume execution comparison, and trace construction are all still run.
    #[cfg(not(target_family = "wasm"))]
    #[track_caller]
    pub fn expect_stack_with_inputs(&self, stack_inputs: &[u64], final_stack: &[u64]) {
        let trace = self
            .execute_with_stack_inputs(stack_inputs)
            .inspect_err(|_err| {
                #[cfg(feature = "std")]
                std::eprintln!("{}", PrintDiagnostic::new_without_color(_err))
            })
            .expect("failed to execute");

        let result = trace.last_stack_state().as_int_vec();
        let expected = resize_to_min_stack_depth(final_stack);
        assert_eq!(expected, result, "Expected stack to be {:?}, found {:?}", expected, result);
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

        #[cfg(all(feature = "std", not(target_family = "wasm")))]
        let cache_key = self.compile_cache_key();

        #[cfg(all(feature = "std", not(target_family = "wasm")))]
        {
            let mut cache_guard = COMPILE_CACHE.lock().unwrap();
            let cache = cache_guard.get_or_insert_with(Default::default);
            if let Some(cached) = cache.get(&cache_key) {
                return Ok((cached.0.clone(), cached.1.clone()));
            }
        }

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

        let result = (assembler.assemble_program(self.source.clone())?, kernel_lib);

        #[cfg(all(feature = "std", not(target_family = "wasm")))]
        {
            let mut cache_guard = COMPILE_CACHE.lock().unwrap();
            let cache = cache_guard.get_or_insert_with(Default::default);
            cache.insert(cache_key, (result.0.clone(), result.1.clone()));
        }

        Ok(result)
    }

    /// Compiles the test's source to a Program and executes it with the tests inputs. Returns a
    /// resulting execution trace or error.
    ///
    /// Internally, this also checks that traced execution and step/resume execution agree on the
    /// stack outputs.
    #[cfg(not(target_family = "wasm"))]
    #[track_caller]
    pub fn execute(&self) -> Result<ExecutionTrace, ExecutionError> {
        self.execute_with_stack_inputs_inner(self.stack_inputs)
    }

    /// Compiles the test's source and executes it with the provided stack inputs.
    ///
    /// This uses the same traced execution, step/resume comparison, and trace construction path as
    /// [`execute`](Self::execute).
    #[cfg(not(target_family = "wasm"))]
    #[track_caller]
    pub fn execute_with_stack_inputs(
        &self,
        stack_inputs: &[u64],
    ) -> Result<ExecutionTrace, ExecutionError> {
        let stack_inputs = StackInputs::try_from_ints(stack_inputs.to_vec()).unwrap();
        self.execute_with_stack_inputs_inner(stack_inputs)
    }

    #[cfg(not(target_family = "wasm"))]
    #[track_caller]
    fn execute_with_stack_inputs_inner(
        &self,
        stack_inputs: StackInputs,
    ) -> Result<ExecutionTrace, ExecutionError> {
        // Note: we fix a large fragment size here, as we're not testing the fragment boundaries
        // with these tests (which are tested separately), but rather only the per-fragment trace
        // generation logic - though not too big so as to over-allocate memory.
        const FRAGMENT_SIZE: usize = 1 << 16;

        let (program, host) = self.get_program_and_host();
        let mut host = host.with_source_manager(self.source_manager.clone());

        let fast_stack_result = {
            let fast_processor = FastProcessor::new_with_options(
                stack_inputs,
                self.advice_inputs.clone(),
                miden_processor::ExecutionOptions::default()
                    .with_debugging(self.in_debug_mode)
                    .with_core_trace_fragment_size(FRAGMENT_SIZE)
                    .unwrap(),
            );
            fast_processor.execute_trace_inputs_sync(&program, &mut host)
        };

        // Compare traced full execution and step/resume execution stack outputs.
        self.assert_result_with_step_execution(stack_inputs, &fast_stack_result);

        fast_stack_result.and_then(|trace_inputs| {
            let trace = build_trace(trace_inputs)?;

            assert_eq!(&program.hash(), trace.program_hash(), "inconsistent program hash");
            Ok(trace)
        })
    }

    /// Compiles the test's source to a Program and executes it with the tests inputs.
    ///
    /// Returns the [`ExecutionOutput`] once execution is finished.
    #[cfg(not(target_family = "wasm"))]
    pub fn execute_for_output(&self) -> Result<(ExecutionOutput, DefaultHost), ExecutionError> {
        let (program, host) = self.get_program_and_host();
        let mut host = host.with_source_manager(self.source_manager.clone());

        let processor = FastProcessor::new(self.stack_inputs)
            .with_advice(self.advice_inputs.clone())
            .with_debugging(true)
            .with_tracing(true);

        processor.execute_sync(&program, &mut host).map(|output| (output, host))
    }

    /// Compiles the test's source to a Program and executes it with the tests inputs. Returns
    /// the [`StackOutputs`] and a [`String`] containing all debug output.
    ///
    /// If the execution fails, the output is printed `stderr`.
    #[cfg(not(target_family = "wasm"))]
    pub fn execute_with_debug_buffer(&self) -> Result<(StackOutputs, String), ExecutionError> {
        let debug_handler = DefaultDebugHandler::new(BufferWriter::default());

        let (program, host) = self.get_program_and_host();
        let mut host = host
            .with_source_manager(self.source_manager.clone())
            .with_debug_handler(debug_handler);

        let processor = FastProcessor::new(self.stack_inputs)
            .with_advice(self.advice_inputs.clone())
            .with_debugging(true)
            .with_tracing(true);

        let stack_result = processor.execute_sync(&program, &mut host);

        let debug_output = host.debug_handler().writer().buffer.clone();

        match stack_result {
            Ok(exec_output) => Ok((exec_output.stack, debug_output)),
            Err(err) => {
                // If we get an error, we print the output as an error
                #[cfg(feature = "std")]
                std::eprintln!("{debug_output}");
                Err(err)
            },
        }
    }

    /// Compiles the test's code into a program, then generates and verifies a STARK proof of
    /// execution. When `test_fail` is true, forces a failure by modifying the first output.
    ///
    /// Prefer [`check_constraints`](Self::check_constraints) for constraint validation — it is
    /// much faster and provides better error diagnostics. Use this method only when you need to
    /// exercise the full STARK prove/verify pipeline (e.g., testing proof serialization,
    /// verifier logic, or precompile request handling).
    #[cfg(not(target_family = "wasm"))]
    pub fn prove_and_verify(&self, pub_inputs: Vec<u64>, test_fail: bool) {
        let (program, mut host) = self.get_program_and_host();
        let stack_inputs = StackInputs::try_from_ints(pub_inputs).unwrap();
        let (mut stack_outputs, proof) = prove_sync(
            &program,
            stack_inputs,
            self.advice_inputs.clone(),
            &mut host,
            miden_processor::ExecutionOptions::default(),
            ProvingOptions::default(),
        )
        .unwrap();

        let program_info = ProgramInfo::from(program);
        if test_fail {
            stack_outputs.as_mut()[0] += ONE;
            assert!(verify(program_info, stack_inputs, stack_outputs, proof).is_err());
        } else {
            let result = verify(program_info, stack_inputs, stack_outputs, proof);
            assert!(result.is_ok(), "error: {result:?}");
        }
    }

    /// Executes the test program and checks all AIR constraints without generating a STARK proof.
    ///
    /// This is the recommended way to validate constraints in tests. It delegates to
    /// [`ExecutionTrace::check_constraints`], which is much faster than the
    /// full prove/verify pipeline and provides better error diagnostics. Use
    /// [`prove_and_verify`](Self::prove_and_verify) only when you need to exercise the
    /// complete STARK proof generation and verification flow.
    ///
    /// # Panics
    ///
    /// Panics if execution fails or if any AIR constraint evaluates to nonzero on any row.
    #[cfg(not(target_family = "wasm"))]
    #[track_caller]
    pub fn check_constraints(&self) {
        let trace = self
            .execute()
            .inspect_err(|_err| {
                #[cfg(feature = "std")]
                std::eprintln!("{}", PrintDiagnostic::new_without_color(_err))
            })
            .expect("failed to execute");
        trace.check_constraints();
    }

    /// Returns the last state of the stack after executing a test.
    #[cfg(not(target_family = "wasm"))]
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
    #[cfg(not(target_family = "wasm"))]
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

    #[cfg(not(target_family = "wasm"))]
    fn assert_result_with_step_execution(
        &self,
        stack_inputs: StackInputs,
        fast_result: &Result<TraceBuildInputs, ExecutionError>,
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
            let fast_process = FastProcessor::new(stack_inputs)
                .with_advice(self.advice_inputs.clone())
                .with_debugging(self.in_debug_mode)
                .with_tracing(self.in_debug_mode);
            fast_process.execute_by_step_sync(&program, &mut host)
        };

        compare_results(
            fast_result.as_ref().map(|trace_inputs| *trace_inputs.stack_outputs()),
            &fast_result_by_step,
            "traced execution",
            "step/resume execution",
        );
    }

    #[cfg(all(feature = "std", not(target_family = "wasm")))]
    fn compile_cache_key(&self) -> CompileCacheKey {
        CompileCacheKey {
            source_manager: Arc::as_ptr(&self.source_manager) as usize,
            source: SourceCacheKey::from_source_file(self.source.as_ref()),
            kernel_source: self.kernel_source.as_deref().map(SourceCacheKey::from_source_file),
            add_modules: self
                .add_modules
                .iter()
                .map(|(path, source)| (path.to_string(), source.clone()))
                .collect(),
            library_digests: self.libraries.iter().map(|library| *library.digest()).collect(),
        }
    }
}

#[cfg(all(feature = "std", not(target_family = "wasm")))]
impl SourceCacheKey {
    fn from_source_file(source_file: &SourceFile) -> Self {
        Self {
            uri: source_file.uri().as_str().to_string(),
            source: source_file.as_str().to_string(),
        }
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

    // Reconstruct the internal Poseidon2 state from the initial stack:
    // stack[0..12] = [v0, ..., v11]
    // => state[0..12] = stack[0..12] in [RATE0,RATE1,CAPACITY] layout.
    let mut state = [ZERO; STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        state[i] = Felt::new_unchecked(values[i]);
    }

    // Apply the permutation
    apply_permutation(&mut state);

    // Map internal state back to stack layout [RATE0', RATE1', CAP']
    let mut out = [ZERO; STATE_WIDTH];
    out[..STATE_WIDTH].copy_from_slice(&state[..STATE_WIDTH]);

    out
}

pub fn build_expected_hash(values: &[u64]) -> [Felt; 4] {
    let digest = hash_elements(&values.iter().map(|&v| Felt::new_unchecked(v)).collect::<Vec<_>>());
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
        i if (DECODER_TRACE_OFFSET + OP_BITS_OFFSET
            ..DECODER_TRACE_OFFSET + OP_BITS_OFFSET + NUM_OP_BITS)
            .contains(&i) =>
        {
            format!("op_bits[{}]", i - (DECODER_TRACE_OFFSET + OP_BITS_OFFSET))
        },
        i if (DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET
            ..DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET + NUM_HASHER_COLUMNS)
            .contains(&i) =>
        {
            format!("hasher_state[{}]", i - (DECODER_TRACE_OFFSET + HASHER_STATE_OFFSET))
        },
        i if i == DECODER_TRACE_OFFSET + IN_SPAN_COL_IDX => "in_span".to_string(),
        i if i == DECODER_TRACE_OFFSET + GROUP_COUNT_COL_IDX => "group_count".to_string(),
        i if i == DECODER_TRACE_OFFSET + OP_INDEX_COL_IDX => "op_index".to_string(),
        i if (DECODER_TRACE_OFFSET + OP_BATCH_FLAGS_OFFSET
            ..DECODER_TRACE_OFFSET + OP_BATCH_FLAGS_OFFSET + NUM_OP_BATCH_FLAGS)
            .contains(&i) =>
        {
            format!("op_batch_flag[{}]", i - (DECODER_TRACE_OFFSET + OP_BATCH_FLAGS_OFFSET))
        },
        i if (DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET
            ..DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET + NUM_OP_BITS_EXTRA_COLS)
            .contains(&i) =>
        {
            format!("op_bits_extra[{}]", i - (DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET))
        },
        i if (DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET
            ..DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET + NUM_OP_BITS_EXTRA_COLS)
            .contains(&i) =>
        {
            format!("op_bits_extra[{}]", i - (DECODER_TRACE_OFFSET + OP_BITS_EXTRA_COLS_OFFSET))
        },

        // Stack columns
        i if (STACK_TRACE_OFFSET + STACK_TOP_OFFSET
            ..STACK_TRACE_OFFSET + STACK_TOP_OFFSET + MIN_STACK_DEPTH)
            .contains(&i) =>
        {
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
        _ => format!("unknown_col[{col_idx}]"),
    }
}
