//! Implementation of AuxTraceBuilder trait for processor's AuxTraceBuilders.

use miden_air::AuxTraceBuilder;
use miden_core::{ExtensionField, Felt};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use super::AuxTraceBuilders;
use crate::row_major_adapter;

impl<EF: ExtensionField<Felt>> AuxTraceBuilder<EF> for AuxTraceBuilders {
    fn build_aux_columns(
        &self,
        main_trace: &RowMajorMatrix<Felt>,
        challenges: &[EF],
    ) -> RowMajorMatrix<Felt> {
        let _span = tracing::info_span!("build_aux_columns_wrapper").entered();

        // 1. Convert row-major to column-major MainTrace
        let main_trace_col_major = {
            let _span = tracing::info_span!("row_major_to_main_trace").entered();
            row_major_adapter::row_major_to_main_trace(main_trace)
        };

        // 2. Build individual auxiliary columns using existing column-major logic
        let decoder_cols = {
            let _span = tracing::info_span!("build_decoder_aux").entered();
            self.decoder.build_aux_columns(&main_trace_col_major, challenges)
        };

        let stack_cols = {
            let _span = tracing::info_span!("build_stack_aux").entered();
            self.stack.build_aux_columns(&main_trace_col_major, challenges)
        };

        let range_cols = {
            let _span = tracing::info_span!("build_range_aux").entered();
            self.range.build_aux_columns(&main_trace_col_major, challenges)
        };

        let chiplets_cols = {
            let _span = tracing::info_span!("build_chiplets_aux").entered();
            self.chiplets.build_aux_columns(&main_trace_col_major, challenges)
        };

        // Combine all columns in order
        let aux_columns = decoder_cols
            .into_iter()
            .chain(stack_cols)
            .chain(range_cols)
            .chain(chiplets_cols)
            .collect();

        // 3. Convert column-major aux columns to row-major
        {
            let _span = tracing::info_span!("aux_columns_to_row_major").entered();
            row_major_adapter::aux_columns_to_row_major(aux_columns, main_trace.height())
        }
    }
}
