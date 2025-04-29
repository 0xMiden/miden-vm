use alloc::collections::BTreeMap;

use miden_air::{RowIndex, trace::chiplets::kernel_rom::TRACE_WIDTH};
use vm_core::PrimeCharacteristicRing;

use super::{Digest, ExecutionError, Felt, Kernel, ONE, TraceFragment, Word, ZERO};

#[cfg(test)]
mod tests;

// TYPE ALIASES
// ================================================================================================

type ProcHashBytes = [u8; 32];

// KERNEL ROM
// ================================================================================================

/// Kernel ROM chiplet for the VM.
///
/// This component is responsible for validating that kernel calls requested by the executing
/// program are made against procedures which are contained within the specified kernel. It also
/// tacks all calls to kernel procedures and this info is used to construct an execution trace of
/// all kernel accesses.
///
/// # Execution trace
/// The layout of the execution trace of kernel procedure accesses is shown below:
///
///   s0   idx   h0   h1   h2   h3
/// ├────┴─────┴────┴────┴────┴────┤
///
/// In the above, the meaning of columns is as follows:
/// - `s0` is a selector column which indicates whether a procedure in a given row should count
///   toward kernel access. ONE indicates that a procedure should be counted as a single access, and
///   ZERO indicates that it shouldn't.
/// - `idx` is a procedure index in the kernel. Values in this column start at ZERO and are
///   incremented by ONE for every new procedure. Said another way, if `idx` does not change, values
///   in `h0` - `h3` must remain the same, but when `idx` is incremented values in `h0` - `h3` can
///   change.
/// - `h0` - `h3` columns contain roots of procedures in a given kernel. Together with `idx` column,
///   these form tuples (index, procedure root) for all procedures in the kernel.
#[derive(Debug)]
pub struct KernelRom {
    access_map: BTreeMap<ProcHashBytes, ProcAccessInfo>,
    kernel: Kernel,
    trace_len: usize,
}

impl KernelRom {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new [KernelRom] instantiated from the specified Kernel.
    ///
    /// The kernel ROM is populated with all procedures from the provided kernel. For each
    /// procedure the access count is set to 0.
    pub fn new(kernel: Kernel) -> Self {
        let trace_len = kernel.proc_hashes().len();
        let mut access_map = BTreeMap::new();
        for &proc_hash in kernel.proc_hashes() {
            access_map.insert(proc_hash.into(), ProcAccessInfo::new(proc_hash));
        }

        Self { access_map, kernel, trace_len }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns length of execution trace required to describe kernel ROM.
    pub const fn trace_len(&self) -> usize {
        self.trace_len
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Marks the specified procedure as accessed from the program.
    ///
    /// # Errors
    /// If the specified procedure does not exist in this kernel ROM, an error is returned.
    pub fn access_proc(&mut self, proc_hash: Digest) -> Result<(), ExecutionError> {
        let proc_hash_bytes: ProcHashBytes = proc_hash.into();
        let access_info = self
            .access_map
            .get_mut(&proc_hash_bytes)
            .ok_or(ExecutionError::SyscallTargetNotInKernel(proc_hash))?;
        // when access count is going from 0 to 1 we don't increment trace length as both 0 and 1
        // accesses require a single row in the trace
        if access_info.num_accesses > 0 {
            self.trace_len += 1;
        }
        access_info.num_accesses += 1;
        Ok(())
    }

    // EXECUTION TRACE GENERATION
    // --------------------------------------------------------------------------------------------

    /// Populates the provided execution trace fragment with execution trace of this kernel ROM.
    pub fn fill_trace(self, trace: &mut TraceFragment) {
        debug_assert_eq!(TRACE_WIDTH, trace.width(), "inconsistent trace fragment width");
        let mut row: RowIndex = 0.into();
        for (idx, access_info) in self.access_map.values().enumerate() {
            let idx = Felt::from_u16(idx as u16);

            // write at least one row into the trace for each kernel procedure
            access_info.write_into_trace(trace, row, idx);

            row += 1;

            // if the procedure was accessed more than once, we need write a row and provide the
            // procedure to the bus per additional access
            for _ in 1..access_info.num_accesses {
                access_info.write_into_trace(trace, row, idx);
                row += 1;
            }
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the underlying kernel for this ROM.
    pub const fn kernel(&self) -> &Kernel {
        &self.kernel
    }
}

// PROCEDURE ACCESS INFO
// ================================================================================================

/// Procedure access information for a given kernel procedure.
#[derive(Debug)]
struct ProcAccessInfo {
    proc_hash: Word,
    num_accesses: usize,
}

impl ProcAccessInfo {
    /// Returns a new [ProcAccessInfo] for the specified procedure with `num_accesses` set to 0.
    pub fn new(proc_hash: Digest) -> Self {
        Self {
            proc_hash: proc_hash.into(),
            num_accesses: 0,
        }
    }

    /// Writes a single row into the provided trace fragment for this procedure access entry.
    pub fn write_into_trace(&self, trace: &mut TraceFragment, row: RowIndex, idx: Felt) {
        let s0 = if self.num_accesses == 0 { ZERO } else { ONE };
        trace.set(row, 0, s0);
        trace.set(row, 1, idx);
        trace.set(row, 2, self.proc_hash[0]);
        trace.set(row, 3, self.proc_hash[1]);
        trace.set(row, 4, self.proc_hash[2]);
        trace.set(row, 5, self.proc_hash[3]);
    }
}
