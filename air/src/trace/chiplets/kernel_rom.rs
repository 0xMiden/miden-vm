use super::Felt;

// CONSTANTS
// ================================================================================================

/// Number of columns needed to record an execution trace of the kernel ROM chiplet.
pub const TRACE_WIDTH: usize = 5;

// --- OPERATION SELECTORS ------------------------------------------------------------------------

// All kernel ROM bus labels encode the chiplet selector [1, 1, 1, 1, 0], appended with the internal
// selector `s_first` which indicates whether the chiplet should respond to an `init` or `call`
// request. The value of the flag is derived following the usual convention, i.e.,
// adding one to the big-endian representation of the full selector.

/// Specifies a kernel procedure call operation to access a procedure in the kernel ROM.
///
/// The label is constructed as follows:
/// - Chiplet selector: [1, 1, 1, 1, 0]
/// - s_first value: 0
/// - Combined selector: [1, 1, 1, 1, 0 | 0]
/// - Reverse bits and add 1 to get final label value: [0 | 0, 1, 1, 1, 1] + 1 = 16
pub const KERNEL_PROC_CALL_LABEL: Felt = Felt::new(0b001111 + 1);

/// Specified the label of the kernel ROM initialization request by the verifier.
///
/// The label is constructed as follows:
/// - Chiplet selector: [1, 1, 1, 1, 0]
/// - s_first value: 1
/// - Combined selector: [1, 1, 1, 1, 0 | 1]
/// - Reverse bits and add 1 to get final label value: [1 | 0, 1, 1, 1, 1] + 1 = 48
pub const KERNEL_PROC_INIT_LABEL: Felt = Felt::new(0b101111 + 1);
