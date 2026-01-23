use alloc::collections::BTreeMap;

use miden_air::trace::{RowIndex, chiplets::kernel_rom::TRACE_WIDTH};
use miden_core::field::PrimeCharacteristicRing;

use super::{Felt, Kernel, TraceFragment, Word as Digest};
use crate::errors::OperationError;

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
///   s_first   h0   h1   h2   h3
/// ├─────────┴────┴────┴────┴────┤
///
/// In the above, the meaning of columns is as follows:
/// - `s_first` indicates that this is the first occurrence of a new block of kernel procedure
///   hashes. It also acts as a flag within the block indicating whether the hash should be sent to
///   the virtual table or the bus.
/// - `h0` - `h3` columns contain roots of procedures in a given kernel.
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
    pub fn access_proc(&mut self, proc_root: Digest) -> Result<(), OperationError> {
        let proc_hash_bytes: ProcHashBytes = proc_root.into();
        let access_info = self
            .access_map
            .get_mut(&proc_hash_bytes)
            .ok_or(OperationError::SyscallTargetNotInKernel { proc_root })?;

        self.trace_len += 1;
        access_info.num_accesses += 1;
        Ok(())
    }

    // EXECUTION TRACE GENERATION
    // --------------------------------------------------------------------------------------------

    /// Populates the provided execution trace fragment with execution trace of this kernel ROM.
    pub fn fill_trace(self, trace: &mut TraceFragment) {
        debug_assert_eq!(TRACE_WIDTH, trace.width(), "inconsistent trace fragment width");
        let mut row = RowIndex::from(0);
        for access_info in self.access_map.values() {
            // Always write an entry for this procedure hash responding to the requests in the
            // requests in the virtual table. The verifier makes those requests by initializing
            // the bus with the set of procedure hashes included in the public inputs.
            access_info.write_into_trace(trace, row, true);
            row += 1_u32;

            // For every access made by the decoder/trace, include an entry in the chiplet bus
            // responding to those requests.
            for _ in 0..access_info.num_accesses {
                access_info.write_into_trace(trace, row, false);
                row += 1_u32;
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
    proc_hash: Digest,
    num_accesses: usize,
}

impl ProcAccessInfo {
    /// Returns a new [ProcAccessInfo] for the specified procedure with `num_accesses` set to 0.
    pub fn new(proc_hash: Digest) -> Self {
        Self { proc_hash, num_accesses: 0 }
    }

    /// Writes a single row into the provided trace fragment for this procedure access entry.
    pub fn write_into_trace(&self, trace: &mut TraceFragment, row: RowIndex, is_first: bool) {
        let s_first = Felt::from_bool(is_first);
        trace.set(row, 0, s_first);
        trace.set(row, 1, self.proc_hash[0]);
        trace.set(row, 2, self.proc_hash[1]);
        trace.set(row, 3, self.proc_hash[2]);
        trace.set(row, 4, self.proc_hash[3]);
    }
}
