use super::Felt;

// CONSTANTS
// ================================================================================================

/// Number of columns needed to record an execution trace of the kernel ROM chiplet.
pub const TRACE_WIDTH: usize = 5;

// --- OPERATION SELECTORS ------------------------------------------------------------------------

// All kernel ROM bus labels encode the chiplet selector [1, 1, 1, 1, 0], appended with a
// per-label bit distinguishing CALL (0) from INIT (1). The label value is derived by reversing
// the bits of the full 6-bit selector and adding 1.
//
// Under the all-LogUp layout both labels are still needed: the INIT label anchors chiplet rows
// to declared-kernel public-input removes (one per procedure), while the CALL label carries
// the per-proc syscall multiplicity against decoder-emitted removes.

/// Label for a kernel-procedure call (SYSCALL decoder-side remove and chiplet-side CALL add).
///
/// The label is constructed as follows:
/// - Chiplet selector: [1, 1, 1, 1, 0]
/// - label bit: 0
/// - Combined selector: [1, 1, 1, 1, 0 | 0]
/// - Reverse bits and add 1 to get final label value: [0 | 0, 1, 1, 1, 1] + 1 = 16
pub const KERNEL_PROC_CALL_LABEL: Felt = Felt::new(0b001111 + 1);

/// Label for a kernel-procedure init (public-input boundary add and chiplet-side INIT remove).
///
/// The label is constructed as follows:
/// - Chiplet selector: [1, 1, 1, 1, 0]
/// - label bit: 1
/// - Combined selector: [1, 1, 1, 1, 0 | 1]
/// - Reverse bits and add 1 to get final label value: [1 | 0, 1, 1, 1, 1] + 1 = 48
pub const KERNEL_PROC_INIT_LABEL: Felt = Felt::new(0b101111 + 1);
