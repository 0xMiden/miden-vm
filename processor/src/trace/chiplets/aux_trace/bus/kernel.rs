use core::fmt::{Display, Formatter, Result as FmtResult};

use miden_air::trace::{
    MainTrace, RowIndex,
    chiplets::kernel_rom::{KERNEL_PROC_CALL_LABEL, KERNEL_PROC_INIT_LABEL},
};
use miden_core::{Felt, field::ExtensionField};

use crate::{
    debug::{BusDebugger, BusMessage},
    trace::chiplets::aux_trace::build_value,
};

// RESPONSES
// ================================================================================================

/// Builds the response from the kernel chiplet at `row`.
///
/// # Details
/// Each row responds to either:
/// - a kernel procedure digest that must appear in the ROM (one response per unique procedure), or
/// - a decoder request when it performs a SYSCALL.
///
/// If a kernel procedure digest is requested `n` times by the decoder, it is repeated
/// `n+1` times in the trace.
/// In the first row for a digest, the chiplet emits an init message balanced against
/// verifier-supplied kernel digests (var-len public inputs); the aux_finals boundary check
/// enforces the expected final bus value.
/// The remaining `n` rows respond to decoder requests.
pub(super) fn build_kernel_chiplet_responses<E>(
    main_trace: &MainTrace,
    row: RowIndex,
    alphas: &[E],
    _debugger: &mut BusDebugger<E>,
) -> E
where
    E: ExtensionField<Felt>,
{
    let root0 = main_trace.chiplet_kernel_root_0(row);
    let root1 = main_trace.chiplet_kernel_root_1(row);
    let root2 = main_trace.chiplet_kernel_root_2(row);
    let root3 = main_trace.chiplet_kernel_root_3(row);

    // First hash row for a digest: emit the init message used to verify kernel membership. The
    // expected final bus value is enforced via aux_finals.
    if main_trace.chiplet_kernel_is_first_hash_row(row) {
        // Emit the digest for kernel procedure membership verification (enforced via aux_finals).
        let message = KernelRomInitMessage {
            kernel_proc_digest: [root0, root1, root2, root3],
        };
        let value = message.value(alphas);

        #[cfg(any(test, feature = "bus-debugger"))]
        _debugger.add_response(alloc::boxed::Box::new(message), alphas);

        value
    } else {
        // Respond to decoder messages.
        let message = KernelRomMessage {
            kernel_proc_digest: [root0, root1, root2, root3],
        };
        let value = message.value(alphas);

        #[cfg(any(test, feature = "bus-debugger"))]
        _debugger.add_response(alloc::boxed::Box::new(message), alphas);
        value
    }
}

// MESSAGES
// ===============================================================================================

/// A message between the decoder and the kernel ROM to ensure a SYSCALL can only call procedures
/// in the kernel as specified by verifier-supplied kernel digests (var-len public inputs).
pub struct KernelRomMessage {
    pub kernel_proc_digest: [Felt; 4],
}

impl<E> BusMessage<E> for KernelRomMessage
where
    E: ExtensionField<Felt>,
{
    #[inline(always)]
    fn value(&self, alphas: &[E]) -> E {
        alphas[0]
            + build_value(
                &alphas[1..6],
                [
                    KERNEL_PROC_CALL_LABEL,
                    self.kernel_proc_digest[0],
                    self.kernel_proc_digest[1],
                    self.kernel_proc_digest[2],
                    self.kernel_proc_digest[3],
                ],
            )
    }

    fn source(&self) -> &str {
        "kernel rom"
    }
}

impl Display for KernelRomMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{{ proc digest: {:?} }}", self.kernel_proc_digest)
    }
}

/// A message linking unique kernel procedure hashes provided by the verifier (var-len public
/// inputs), with hashes contained in the kernel ROM chiplet trace.
pub struct KernelRomInitMessage {
    pub kernel_proc_digest: [Felt; 4],
}

impl<E> BusMessage<E> for KernelRomInitMessage
where
    E: ExtensionField<Felt>,
{
    #[inline(always)]
    fn value(&self, alphas: &[E]) -> E {
        alphas[0]
            + build_value(
                &alphas[1..6],
                [
                    KERNEL_PROC_INIT_LABEL,
                    self.kernel_proc_digest[0],
                    self.kernel_proc_digest[1],
                    self.kernel_proc_digest[2],
                    self.kernel_proc_digest[3],
                ],
            )
    }

    fn source(&self) -> &str {
        "kernel rom init"
    }
}

impl Display for KernelRomInitMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{{ proc digest init: {:?} }}", self.kernel_proc_digest)
    }
}
