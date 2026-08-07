use miden_mast_package::debug_info::{DebugSourceNodeId, PackageDebugInfo};

use crate::{
    ExecutionError, ExecutionOptions, ExecutionOutput, FastProcessor, FutureMaybeSend, Host,
    Program, StackInputs, advice::AdviceInputs,
};

// PROGRAM EXECUTOR
// ================================================================================================

/// A pluggable program executor used to run a [`Program`] against a [`Host`].
///
/// Defaults to [`FastProcessor`]. Alternative implementations can wrap execution in a debugger,
/// add instrumentation, or redirect to a different backend, while leaving the surrounding
/// executor wiring untouched.
///
/// The `new` constructor is infallible from the trait's perspective: invalid advice inputs are a
/// caller bug, and the default [`FastProcessor`] implementation panics in that case, matching the
/// contract of [`FastProcessor::new_with_options`].
pub trait ProgramExecutor {
    /// Creates a new executor configured with the provided inputs and options.
    ///
    /// In generic code (`E: ProgramExecutor`) this resolves normally. For the concrete
    /// [`FastProcessor`] type, however, the inherent
    /// [`FastProcessor::new`](crate::FastProcessor::new) (which takes only stack inputs)
    /// shadows this trait method by name, so invoke the trait constructor with fully-qualified
    /// syntax: `<FastProcessor as ProgramExecutor>::new(stack_inputs, advice_inputs, options)`.
    fn new(
        stack_inputs: StackInputs,
        advice_inputs: AdviceInputs,
        options: ExecutionOptions,
    ) -> Self
    where
        Self: Sized;

    /// Executes the provided program against the given host.
    fn execute<H: Host + Send>(
        self,
        program: &Program,
        host: &mut H,
    ) -> impl FutureMaybeSend<Result<ExecutionOutput, ExecutionError>>;

    /// Executes the provided program with package-owned source/debug context.
    ///
    /// When `entrypoint_source_node` is `Some`, the debug context is rooted at that node.
    /// Executors that do not support package debug execution may fall back to [`Self::execute`].
    fn execute_with_package_debug_info<H: Host + Send>(
        self,
        program: &Program,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node: Option<DebugSourceNodeId>,
        host: &mut H,
    ) -> impl FutureMaybeSend<Result<ExecutionOutput, ExecutionError>>
    where
        Self: Sized,
    {
        let _ = (package_debug_info, entrypoint_source_node);
        self.execute(program, host)
    }
}

impl ProgramExecutor for FastProcessor {
    fn new(
        stack_inputs: StackInputs,
        advice_inputs: AdviceInputs,
        options: ExecutionOptions,
    ) -> Self {
        FastProcessor::new_with_options(stack_inputs, advice_inputs, options)
            .expect("constructing FastProcessor failed due to invalid advice inputs")
    }

    fn execute<H: Host + Send>(
        self,
        program: &Program,
        host: &mut H,
    ) -> impl FutureMaybeSend<Result<ExecutionOutput, ExecutionError>> {
        FastProcessor::execute(self, program, host)
    }

    fn execute_with_package_debug_info<H: Host + Send>(
        self,
        program: &Program,
        package_debug_info: &PackageDebugInfo,
        entrypoint_source_node: Option<DebugSourceNodeId>,
        host: &mut H,
    ) -> impl FutureMaybeSend<Result<ExecutionOutput, ExecutionError>> {
        async move {
            match entrypoint_source_node {
                Some(entrypoint_source_node) => {
                    FastProcessor::execute_with_package_debug_info_at_source_node(
                        self,
                        program,
                        package_debug_info,
                        entrypoint_source_node,
                        host,
                    )
                    .await
                },
                None => {
                    FastProcessor::execute_with_package_debug_info(
                        self,
                        program,
                        package_debug_info,
                        host,
                    )
                    .await
                },
            }
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_assembly::Assembler;

    use super::*;
    use crate::{DefaultHost, StackInputs};

    #[tokio::test(flavor = "current_thread")]
    async fn program_executor_default_impl_runs_via_trait() {
        let program = Assembler::default()
            .assemble_program("program", "begin push.3 swap drop end")
            .unwrap()
            .unwrap_program();

        // Drive execution entirely through the trait, defaulting to `FastProcessor`.
        let processor = <FastProcessor as ProgramExecutor>::new(
            StackInputs::default(),
            AdviceInputs::default(),
            ExecutionOptions::default(),
        );
        let output = <FastProcessor as ProgramExecutor>::execute(
            processor,
            &program,
            &mut DefaultHost::default(),
        )
        .await
        .unwrap();

        // push.3 leaves 3 on top; `swap drop` restores the operand stack to its
        // fixed depth of 16 so the program ends with a well-formed output stack.
        assert_eq!(output.stack.get_element(0), Some(crate::Felt::from_u32(3)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn program_executor_default_falls_back_when_no_source_node() {
        let program = Assembler::default()
            .assemble_program("program", "begin push.3 swap drop end")
            .unwrap()
            .unwrap_program();

        // `execute_with_package_debug_info` overrides only to route to the package-debug path;
        // without an entrypoint node it still executes and returns the same stack.
        let processor = <FastProcessor as ProgramExecutor>::new(
            StackInputs::default(),
            AdviceInputs::default(),
            ExecutionOptions::default(),
        );
        let output = <FastProcessor as ProgramExecutor>::execute_with_package_debug_info(
            processor,
            &program,
            &PackageDebugInfo::default(),
            None,
            &mut DefaultHost::default(),
        )
        .await
        .unwrap();

        assert_eq!(output.stack.get_element(0), Some(crate::Felt::from_u32(3)));
    }
}
