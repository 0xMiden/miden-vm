#[cfg(test)]
use miden_core::{Felt, mast::OP_GROUP_SIZE, operations::Operation};

mod aux_trace;
pub use aux_trace::AuxTraceBuilder;
#[cfg(test)]
pub use aux_trace::BlockHashTableRow;

pub mod block_stack;

// TEST HELPERS
// ================================================================================================

/// Build an operation group from the specified list of operations.
#[cfg(test)]
pub fn build_op_group(ops: &[Operation]) -> Felt {
    let mut group = 0u64;
    let mut i = 0;
    for op in ops.iter() {
        group |= (op.op_code() as u64) << (Operation::OP_BITS * i);
        i += 1;
    }
    assert!(i <= OP_GROUP_SIZE, "too many ops");
    Felt::new(group)
}
