use miden_air::{
    RowIndex,
    trace::{chiplets::hasher::DIGEST_RANGE, main_trace::MainTrace},
};
use vm_core::{Kernel, ONE};

use super::{
    Felt, FieldElement, build_ace_memory_read_element_request, build_ace_memory_read_word_request,
};
use crate::{debug::BusDebugger, trace::AuxColumnBuilder};

/// Describes how to construct the execution trace of the chiplets virtual table auxiliary trace
/// column.
/// TODO(Al): This should probably be renamed to something more generic.
pub struct ChipletsVTableColBuilder {
    kernel: Kernel,
}

impl ChipletsVTableColBuilder {
    pub(super) fn new(kernel: Kernel) -> Self {
        Self { kernel }
    }
}

impl<E: FieldElement<BaseField = Felt>> AuxColumnBuilder<E> for ChipletsVTableColBuilder {
    fn init_requests(
        &self,
        _main_trace: &MainTrace,
        alphas: &[E],
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let mut requests = E::ONE;
        for (idx, proc_hash) in self.kernel.proc_hashes().iter().enumerate() {
            requests *= alphas[0]
                + alphas[1].mul_base((idx as u32).into())
                + alphas[2].mul_base(proc_hash[0])
                + alphas[3].mul_base(proc_hash[1])
                + alphas[4].mul_base(proc_hash[2])
                + alphas[5].mul_base(proc_hash[3]);
        }
        requests
    }

    fn get_requests_at(
        &self,
        main_trace: &MainTrace,
        alphas: &[E],
        row: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        let request_ace = if main_trace.chiplet_ace_is_read_row(row) {
            build_ace_memory_read_word_request(main_trace, alphas, row, _debugger)
        } else if main_trace.chiplet_ace_is_eval_row(row) {
            build_ace_memory_read_element_request(main_trace, alphas, row, _debugger)
        } else {
            E::ONE
        };
        chiplets_vtable_remove_sibling(main_trace, alphas, row) * request_ace
    }

    fn get_responses_at(
        &self,
        main_trace: &MainTrace,
        alphas: &[E],
        row: RowIndex,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        chiplets_vtable_add_sibling(main_trace, alphas, row)
            * build_kernel_procedure_table_inclusions(main_trace, alphas, row)
    }
}

// VIRTUAL TABLE REQUESTS
// ================================================================================================

/// Constructs the removals from the table when the hasher absorbs a new sibling node while
/// computing the new Merkle root.
fn chiplets_vtable_remove_sibling<E>(main_trace: &MainTrace, alphas: &[E], row: RowIndex) -> E
where
    E: FieldElement<BaseField = Felt>,
{
    let f_mu: bool = main_trace.f_mu(row);
    let f_mua: bool = main_trace.f_mua(row);

    if f_mu {
        let index = main_trace.chiplet_node_index(row);
        let lsb = index.as_int() & 1;
        if lsb == 0 {
            let sibling = &main_trace.chiplet_hasher_state(row)[DIGEST_RANGE.end..];
            alphas[0]
                + alphas[3].mul_base(index)
                + alphas[12].mul_base(sibling[0])
                + alphas[13].mul_base(sibling[1])
                + alphas[14].mul_base(sibling[2])
                + alphas[15].mul_base(sibling[3])
        } else {
            let sibling = &main_trace.chiplet_hasher_state(row)[DIGEST_RANGE];
            alphas[0]
                + alphas[3].mul_base(index)
                + alphas[8].mul_base(sibling[0])
                + alphas[9].mul_base(sibling[1])
                + alphas[10].mul_base(sibling[2])
                + alphas[11].mul_base(sibling[3])
        }
    } else if f_mua {
        let index = main_trace.chiplet_node_index(row);
        let lsb = index.as_int() & 1;
        if lsb == 0 {
            let sibling = &main_trace.chiplet_hasher_state(row + 1)[DIGEST_RANGE.end..];
            alphas[0]
                + alphas[3].mul_base(index)
                + alphas[12].mul_base(sibling[0])
                + alphas[13].mul_base(sibling[1])
                + alphas[14].mul_base(sibling[2])
                + alphas[15].mul_base(sibling[3])
        } else {
            let sibling = &main_trace.chiplet_hasher_state(row + 1)[DIGEST_RANGE];
            alphas[0]
                + alphas[3].mul_base(index)
                + alphas[8].mul_base(sibling[0])
                + alphas[9].mul_base(sibling[1])
                + alphas[10].mul_base(sibling[2])
                + alphas[11].mul_base(sibling[3])
        }
    } else {
        E::ONE
    }
}

// VIRTUAL TABLE RESPONSES
// ================================================================================================

/// Constructs the inclusions to the table when the hasher absorbs a new sibling node while
/// computing the old Merkle root.
fn chiplets_vtable_add_sibling<E>(main_trace: &MainTrace, alphas: &[E], row: RowIndex) -> E
where
    E: FieldElement<BaseField = Felt>,
{
    let f_mv: bool = main_trace.f_mv(row);
    let f_mva: bool = main_trace.f_mva(row);

    if f_mv {
        let index = main_trace.chiplet_node_index(row);
        let lsb = index.as_int() & 1;
        if lsb == 0 {
            let sibling = &main_trace.chiplet_hasher_state(row)[DIGEST_RANGE.end..];
            alphas[0]
                + alphas[3].mul_base(index)
                + alphas[12].mul_base(sibling[0])
                + alphas[13].mul_base(sibling[1])
                + alphas[14].mul_base(sibling[2])
                + alphas[15].mul_base(sibling[3])
        } else {
            let sibling = &main_trace.chiplet_hasher_state(row)[DIGEST_RANGE];
            alphas[0]
                + alphas[3].mul_base(index)
                + alphas[8].mul_base(sibling[0])
                + alphas[9].mul_base(sibling[1])
                + alphas[10].mul_base(sibling[2])
                + alphas[11].mul_base(sibling[3])
        }
    } else if f_mva {
        let index = main_trace.chiplet_node_index(row);
        let lsb = index.as_int() & 1;
        if lsb == 0 {
            let sibling = &main_trace.chiplet_hasher_state(row + 1)[DIGEST_RANGE.end..];
            alphas[0]
                + alphas[3].mul_base(index)
                + alphas[12].mul_base(sibling[0])
                + alphas[13].mul_base(sibling[1])
                + alphas[14].mul_base(sibling[2])
                + alphas[15].mul_base(sibling[3])
        } else {
            let sibling = &main_trace.chiplet_hasher_state(row + 1)[DIGEST_RANGE];
            alphas[0]
                + alphas[3].mul_base(index)
                + alphas[8].mul_base(sibling[0])
                + alphas[9].mul_base(sibling[1])
                + alphas[10].mul_base(sibling[2])
                + alphas[11].mul_base(sibling[3])
        }
    } else {
        E::ONE
    }
}

/// Builds the inclusions to the kernel procedure table at `row`.
fn build_kernel_procedure_table_inclusions<E>(
    main_trace: &MainTrace,
    alphas: &[E],
    row: RowIndex,
) -> E
where
    E: FieldElement<BaseField = Felt>,
{
    if main_trace.is_kernel_row(row) {
        let idx = main_trace.chiplet_kernel_idx(row);
        let idx_delta = {
            let idx_next = main_trace.chiplet_kernel_idx(row + 1);
            idx_next - idx
        };
        let next_row_is_kernel = main_trace.is_kernel_row(row + 1);

        // We want to add an entry to the table in 2 cases:
        // 1. when the next row is a kernel row and the idx changes
        //    - this adds the last row of all rows that share the same idx
        // 2. when the next row is not a kernel row
        //    - this is the edge case of (1)
        if !next_row_is_kernel || idx_delta == ONE {
            let root0 = main_trace.chiplet_kernel_root_0(row);
            let root1 = main_trace.chiplet_kernel_root_1(row);
            let root2 = main_trace.chiplet_kernel_root_2(row);
            let root3 = main_trace.chiplet_kernel_root_3(row);

            alphas[0]
                + alphas[1].mul_base(idx)
                + alphas[2].mul_base(root0)
                + alphas[3].mul_base(root1)
                + alphas[4].mul_base(root2)
                + alphas[5].mul_base(root3)
        } else {
            E::ONE
        }
    } else {
        E::ONE
    }
}
