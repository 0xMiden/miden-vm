use miden_core::deferred::TRUE_DIGEST;

use crate::{ExecutionError, PrecompileWitness, trace::VmTrace};

/// The VM relation's trace-building memory model and caller-selected byte limit.
pub type VmTraceBudget =
    miden_stark::memory::ProvingBudget<{ miden_air_definitions::vm::MIDEN_AIR_COUNT }>;

/// The VM trace and its matching optional portable precompile witness.
#[derive(Debug)]
pub struct ExecutionTrace {
    vm: VmTrace,
    precompile: Option<PrecompileWitness>,
}

impl ExecutionTrace {
    /// Reconstructs an execution trace while checking its authenticated precompile obligation.
    ///
    /// A nonempty trace root requires a witness with the same root. An empty root must not carry
    /// a witness. This checks graph structure and the pairing. Precompile admission, semantic
    /// validity, and proof validity are checked when preparing and verifying the corresponding
    /// proofs.
    pub fn try_new(
        vm: VmTrace,
        precompile: Option<PrecompileWitness>,
    ) -> Result<Self, ExecutionError> {
        let expected = vm.precompile_root();
        match &precompile {
            None if expected != TRUE_DIGEST => {
                return Err(ExecutionError::MissingPrecompileWitness);
            },
            Some(_) if expected == TRUE_DIGEST => {
                return Err(ExecutionError::UnexpectedPrecompileWitness);
            },
            Some(witness) => {
                let actual =
                    witness.compute_root().map_err(ExecutionError::InvalidPrecompileWitness)?;
                if actual != expected {
                    return Err(ExecutionError::PrecompileRootMismatch { expected, actual });
                }
            },
            None => {},
        }
        Ok(Self { vm, precompile })
    }

    /// Borrows the VM trace.
    pub fn vm_trace(&self) -> &VmTrace {
        &self.vm
    }

    /// Borrows the witness for authenticated precompile work, when present.
    pub fn precompile_witness(&self) -> Option<&PrecompileWitness> {
        self.precompile.as_ref()
    }

    /// Extracts the VM trace and discards the precompile witness.
    pub fn into_vm_trace(self) -> VmTrace {
        self.vm
    }

    /// Separates the trace from its optional precompile witness.
    pub fn into_parts(self) -> (VmTrace, Option<PrecompileWitness>) {
        (self.vm, self.precompile)
    }
}
