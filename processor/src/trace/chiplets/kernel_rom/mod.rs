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
/// Validates that every SYSCALL targets a procedure declared in the kernel, and produces
/// exactly one trace row per declared procedure carrying the row's CALL-side multiplicity.
///
/// # Execution trace
///
///   m   h0   h1   h2   h3
/// ├────┴────┴────┴────┴────┤
///
/// - `m` is the number of SYSCALLs to this procedure (0 if declared but never called).
///   It gates the chiplet-side CALL add; the INIT add is always emitted with multiplicity 1.
/// - `h0..h3` is the procedure root digest.
#[derive(Debug)]
pub struct KernelRom {
    access_map: BTreeMap<ProcHashBytes, ProcAccessInfo>,
    kernel: Kernel,
}

impl KernelRom {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new [KernelRom] instantiated from the specified Kernel.
    ///
    /// The kernel ROM is populated with all procedures from the provided kernel. For each
    /// procedure the access count is set to 0.
    pub fn new(kernel: Kernel) -> Self {
        let mut access_map = BTreeMap::new();
        for &proc_hash in kernel.proc_hashes() {
            access_map.insert(proc_hash.into(), ProcAccessInfo::new(proc_hash));
        }

        Self { access_map, kernel }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns length of execution trace required to describe kernel ROM.
    ///
    /// Under the all-LogUp layout this is exactly the number of declared kernel procedures
    /// (one row per proc, regardless of access count).
    pub fn trace_len(&self) -> usize {
        self.access_map.len()
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

        access_info.num_accesses += 1;
        Ok(())
    }

    // EXECUTION TRACE GENERATION
    // --------------------------------------------------------------------------------------------

    /// Populates the provided execution trace fragment with execution trace of this kernel ROM.
    ///
    /// Emits one row per declared kernel procedure: column 0 is the CALL-label multiplicity
    /// (= number of SYSCALLs to this proc), columns 1..5 are the procedure digest.
    pub fn fill_trace(self, trace: &mut TraceFragment) {
        debug_assert_eq!(TRACE_WIDTH, trace.width(), "inconsistent trace fragment width");
        let mut row = RowIndex::from(0);
        for access_info in self.access_map.values() {
            let multiplicity = Felt::from_u64(access_info.num_accesses as u64);
            trace.set(row, 0, multiplicity);
            trace.set(row, 1, access_info.proc_hash[0]);
            trace.set(row, 2, access_info.proc_hash[1]);
            trace.set(row, 3, access_info.proc_hash[2]);
            trace.set(row, 4, access_info.proc_hash[3]);
            row += 1_u32;
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
}
