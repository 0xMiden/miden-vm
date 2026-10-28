use miden_mast_package::debug_info::{DebugSourceNodeId, PackageDebugInfo};

use crate::{
    ExecutionError, ExecutionOptions, ExecutionOutput, FastProcessor, FutureMaybeSend, Host,
    Program, StackInputs,
    advice::{AdviceError, AdviceInputs},
};

// PROGRAM EXECUTOR
// ================================================================================================

/// A pluggable program executor used to run a [`Program`] against a [`Host`].
///
/// Defaults to [`FastProcessor`]. Alternative implementations can wrap execution in a debugger,
/// add instrumentation, or redirect to a different backend, while leaving the surrounding
/// executor wiring untouched.
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
    ) -> Result<Self, AdviceError>
    where
        Self: Sized;

    /// Configures package-owned source and debug information for execution.
    fn with_debug_info(self, package_debug_info: PackageDebugInfo) -> Self;

    /// Configures the source node at which execution begins.
    fn with_entrypoint_source_node(self, entrypoint_source_node: Option<DebugSourceNodeId>)
    -> Self;

    /// Executes the provided program against the given host.
    fn execute<H: Host + Send>(
        self,
        program: &Program,
        host: &mut H,
    ) -> impl FutureMaybeSend<Result<ExecutionOutput, ExecutionError>>;
}

impl ProgramExecutor for FastProcessor {
    fn new(
        stack_inputs: StackInputs,
        advice_inputs: AdviceInputs,
        options: ExecutionOptions,
    ) -> Result<Self, AdviceError> {
        FastProcessor::new_with_options(stack_inputs, advice_inputs, options)
    }

    fn with_debug_info(mut self, package_debug_info: PackageDebugInfo) -> Self {
        self.package_debug_info = Some(package_debug_info);
        self
    }

    fn with_entrypoint_source_node(
        mut self,
        entrypoint_source_node: Option<DebugSourceNodeId>,
    ) -> Self {
        self.entrypoint_source_node = entrypoint_source_node;
        self
    }

    fn execute<H: Host + Send>(
        self,
        program: &Program,
        host: &mut H,
    ) -> impl FutureMaybeSend<Result<ExecutionOutput, ExecutionError>> {
        async move {
            match (self.package_debug_info.clone(), self.entrypoint_source_node) {
                (Some(package_debug_info), Some(entrypoint_source_node)) => {
                    FastProcessor::execute_with_package_debug_info_at_source_node(
                        self,
                        program,
                        &package_debug_info,
                        entrypoint_source_node,
                        host,
                    )
                    .await
                },
                (Some(package_debug_info), None) => {
                    FastProcessor::execute_with_package_debug_info(
                        self,
                        program,
                        &package_debug_info,
                        host,
                    )
                    .await
                },
                (None, _) => FastProcessor::execute(self, program, host).await,
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
        )
        .unwrap();
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

    #[test]
    fn program_executor_reports_invalid_advice_inputs() {
        let advice_inputs =
            AdviceInputs::default().with_map([(crate::Word::default(), vec![crate::Felt::ONE])]);
        let options = ExecutionOptions::default().with_max_advice_size_bytes(0);

        let result =
            <FastProcessor as ProgramExecutor>::new(StackInputs::default(), advice_inputs, options);

        assert!(result.is_err());
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
        )
        .unwrap();
        let processor = <FastProcessor as ProgramExecutor>::with_debug_info(
            processor,
            PackageDebugInfo::default(),
        );
        let output = <FastProcessor as ProgramExecutor>::execute(
            processor,
            &program,
            &mut DefaultHost::default(),
        )
        .await
        .unwrap();

        assert_eq!(output.stack.get_element(0), Some(crate::Felt::from_u32(3)));
    }
}
