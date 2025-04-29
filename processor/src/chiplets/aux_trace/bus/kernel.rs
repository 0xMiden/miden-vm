use core::fmt::{Display, Formatter, Result as FmtResult};

use miden_air::{RowIndex, trace::main_trace::MainTrace};
use vm_core::{ExtensionField, Felt, ONE, PrimeCharacteristicRing};

use crate::debug::{BusDebugger, BusMessage};

// REQUESTS
// ================================================================================================

// Note: all requests are handled in the `super` module, since they involve messages to multiple
// chiplets.

// RESPONSES
// ================================================================================================

/// Builds the response from the kernel chiplet at `row`.
pub(super) fn build_kernel_chiplet_responses<E>(
    main_trace: &MainTrace,
    row: RowIndex,
    alphas: &[E],
    _debugger: &mut BusDebugger<E>,
) -> E
where
    E: ExtensionField<Felt>,
{
    let kernel_chiplet_selector = main_trace.chiplet_selector_4(row);
    if kernel_chiplet_selector == ONE {
        let message = {
            let root0 = main_trace.chiplet_kernel_root_0(row);
            let root1 = main_trace.chiplet_kernel_root_1(row);
            let root2 = main_trace.chiplet_kernel_root_2(row);
            let root3 = main_trace.chiplet_kernel_root_3(row);

            KernelRomMessage {
                kernel_proc_digest: [root0, root1, root2, root3],
            }
        };

        let value = message.value(alphas);

        #[cfg(any(test, feature = "bus-debugger"))]
        _debugger.add_response(alloc::boxed::Box::new(message), alphas);

        value
    } else {
        E::ONE
    }
}

// MESSAGE
// ===============================================================================================

pub struct KernelRomMessage {
    pub kernel_proc_digest: [Felt; 4],
}

impl<E> BusMessage<E> for KernelRomMessage
where
    E: ExtensionField<Felt>,
{
    fn value(&self, alphas: &[E]) -> E {
        alphas[0]
            + alphas[1] * Felt::from_u64(0b1000)
            + alphas[2] * self.kernel_proc_digest[0]
            + alphas[3] * self.kernel_proc_digest[1]
            + alphas[4] * self.kernel_proc_digest[2]
            + alphas[5] * self.kernel_proc_digest[3]
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
