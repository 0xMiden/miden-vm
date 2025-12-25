use alloc::vec::Vec;

use miden_air::{Felt, trace::main_trace::MainTrace};
use miden_core::FieldElement;

use crate::trace::AuxColumnBuilder;

mod block_hash_table;
use block_hash_table::BlockHashTableColumnBuilder;
#[cfg(test)]
pub use block_hash_table::BlockHashTableRow;

mod block_stack_table;
use block_stack_table::BlockStackColumnBuilder;

mod op_group_table;
use op_group_table::OpGroupTableColumnBuilder;

// AUXILIARY TRACE BUILDER
// ================================================================================================

/// Constructs the execution traces of stack-related auxiliary trace segment columns
/// (used in multiset checks).
#[derive(Debug, Default, Clone, Copy)]
pub struct AuxTraceBuilder {}

impl AuxTraceBuilder {
    /// Builds and returns decoder auxiliary trace columns p1, p2, and p3 describing states of block
    /// stack, block hash, and op group tables respectively.
    pub fn build_aux_columns<E: FieldElement<BaseField = Felt>>(
        &self,
        main_trace: &MainTrace,
        rand_elements: &[E],
    ) -> Vec<Vec<E>> {
        let block_stack_column_builder = BlockStackColumnBuilder::default();
        let block_hash_column_builder = BlockHashTableColumnBuilder::default();
        let op_group_table_column_builder = OpGroupTableColumnBuilder::default();

        let p1 = block_stack_column_builder.build_aux_column(main_trace, rand_elements);
        let p2 = block_hash_column_builder.build_aux_column(main_trace, rand_elements);
        let p3 = op_group_table_column_builder.build_aux_column(main_trace, rand_elements);

        debug_assert_eq!(
            *p1.last().unwrap(),
            E::ONE,
            "block stack table is not empty at the end of program execution"
        );
        debug_assert_eq!(
            *p2.last().unwrap(),
            E::ONE,
            "block hash table is not empty at the end of program execution"
        );
        debug_assert_eq!(
            *p3.last().unwrap(),
            E::ONE,
            "op group table is not empty at the end of program execution"
        );

        vec![p1, p2, p3]
    }
}
