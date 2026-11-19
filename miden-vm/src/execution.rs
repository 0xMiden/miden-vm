//! Program-bound configuration and concrete proving tasks for the shared execution pipeline.
//!
//! The processor crate owns request configuration, execution modes, outputs, and session mechanics.
//! This facade adds proving task selection without introducing a prover dependency in the engine.

use miden_processor::{
    Execute, Execution, ExecutionClaim, ExecutionError, ExecutionOptions, ExecutionRequest,
    ExecutionTask, PackageSourceDebugContext, StackInputs, Trace, TraceOutput, VmTraceBudget,
    Witness,
    advice::{AdviceInputs, AdviceProvider},
};
use miden_prover::{CompleteProof, Prover, ProverError};

use crate::{ExecutionProof, Program};

/// Program-bound inputs and context, before choosing an execution or proving task.
///
/// Setters store configuration without creating a live advice provider. Advice is validated against
/// the final execution options when the selected task runs, starts, or is initialized explicitly
/// with [`Execution::prepare`], independently of setter order.
pub struct Processor<'p> {
    request: ExecutionRequest<'p>,
}

impl<'p> Processor<'p> {
    /// Binds a program with empty inputs and default execution options.
    pub fn new(program: &'p Program) -> Self {
        Self { request: ExecutionRequest::new(program) }
    }

    pub fn with_stack_inputs(self, inputs: StackInputs) -> Self {
        Self {
            request: self.request.with_stack_inputs(inputs),
        }
    }

    pub fn with_advice(self, advice: AdviceInputs) -> Self {
        Self {
            request: self.request.with_advice(advice),
        }
    }

    pub fn with_options(self, options: ExecutionOptions) -> Self {
        Self {
            request: self.request.with_options(options),
        }
    }

    /// Couples package debug information with its optional exact entrypoint occurrence.
    ///
    /// The processor validates an explicit occurrence against this program before host callbacks.
    /// Without an occurrence, the source graph must identify at most one entrypoint root.
    pub fn with_source_context<'s>(
        self,
        source_context: Option<PackageSourceDebugContext<'s>>,
    ) -> Processor<'s>
    where
        'p: 's,
    {
        Processor {
            request: self.request.with_source_context(source_context),
        }
    }

    /// Selects ordinary execution without replay recording.
    pub fn execute(self) -> Execution<'p, Execute> {
        self.request.execute()
    }

    /// Selects compact witness recording, returning the witness and final advice.
    pub fn record_witness(self) -> Execution<'p, Witness> {
        self.request.record_witness()
    }

    /// Selects VM trace construction under the supplied relation-compatible budget.
    pub fn build_trace(self, budget: VmTraceBudget) -> Execution<'p, Trace> {
        self.request.build_trace(budget)
    }

    /// Selects proving of the VM and all authenticated precompile work.
    pub fn prove_complete<'v>(self, prover: &'v Prover) -> Execution<'p, ProveComplete<'v>> {
        self.request.select(ProveComplete { prover })
    }

    /// Selects VM proving while retaining portable precompile work for later proving.
    pub fn prove_deferred<'v>(self, prover: &'v Prover) -> Execution<'p, ProveDeferred<'v>> {
        self.request.select(ProveDeferred { prover })
    }
}

/// A completed proof with the claim and final advice from the same execution.
#[derive(Debug)]
pub struct ProvingOutput<Proof> {
    pub claim: ExecutionClaim,
    pub proof: Proof,
    pub advice: AdviceProvider,
}

/// Distinguishes execution failures from proof-generation failures.
#[derive(Debug, thiserror::Error)]
pub enum ProvingRunError {
    #[error(transparent)]
    Execution(#[from] ExecutionError),
    #[error("proof generation failed: {0}")]
    Prover(#[from] ProverError),
}

/// Execution proving the VM and all authenticated precompile work.
pub struct ProveComplete<'v> {
    prover: &'v Prover,
}

/// Execution proving the VM while retaining portable precompile work for later proving.
pub struct ProveDeferred<'v> {
    prover: &'v Prover,
}

impl ExecutionTask for ProveComplete<'_> {
    type Mode = Trace;
    type Output = ProvingOutput<CompleteProof>;
    type Error = ProvingRunError;

    fn mode(&self) -> Self::Mode {
        Trace::new(self.prover.trace_budget())
    }

    fn finish(self, output: TraceOutput) -> Result<Self::Output, Self::Error> {
        let TraceOutput { claim, trace, advice } = output;
        let proof = self.prover.prove_full_trace(trace)?;
        Ok(ProvingOutput { claim, proof, advice })
    }
}

impl ExecutionTask for ProveDeferred<'_> {
    type Mode = Trace;
    type Output = ProvingOutput<ExecutionProof>;
    type Error = ProvingRunError;

    fn mode(&self) -> Self::Mode {
        Trace::new(self.prover.trace_budget())
    }

    fn finish(self, output: TraceOutput) -> Result<Self::Output, Self::Error> {
        let TraceOutput { claim, trace, advice } = output;
        let proof = self.prover.prove_trace(trace)?;
        Ok(ProvingOutput { claim, proof, advice })
    }
}
