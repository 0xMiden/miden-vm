//! Typed bindings for the VM verifier MASM templates.
use askama::Template;

#[derive(Template)]
#[template(path = "vm/deep_queries.masm", escape = "none")]
pub(crate) struct VmDeepQueriesTemplate {
    pub(crate) preprocessed_lmcs_init_cv: String,
    pub(crate) quotient_lmcs_init_cv: String,
    pub(crate) aux_lmcs_init_cv: String,
    pub(crate) main_lmcs_init_cv: String,
    pub(crate) and8_lde_index_mask: u32,
    pub(crate) preprocessed_comment: String,
    pub(crate) repeat_load_preprocessed_segment: usize,
    pub(crate) main_comment: String,
    pub(crate) repeat_load_main_segment_execution_trace: usize,
    pub(crate) aux_comment: String,
    pub(crate) repeat_load_aux_segment_execution_trace: usize,
    pub(crate) repeat_load_constraints_composition_polys_trace: usize,
}

#[derive(Template)]
#[template(path = "vm/layout.masm", escape = "none")]
pub(crate) struct VmLayoutTemplate {
    pub(crate) comment_ood_scatter_table_ptr: String,
    pub(crate) proof_order_positions_ptr: usize,
    pub(crate) proof_order_ids_ptr: usize,
    pub(crate) ood_row_diagram: String,
    pub(crate) comment_ood_evaluations_ptr: String,
    pub(crate) ood_evaluations_ptr: usize,
    pub(crate) aux_bus_boundary_ptr: usize,
    pub(crate) auxiliary_ace_inputs_ptr: usize,
    pub(crate) ace_circuit_stream_ptr: usize,
    pub(crate) comment_current_trace_row_ptr: String,
    pub(crate) current_trace_row_ptr: usize,
}

#[derive(Template)]
#[template(path = "vm/mod.masm", escape = "none")]
pub(crate) struct VmModTemplate {
    pub(crate) lookup_pow_bits: usize,
    pub(crate) max_message_width: usize,
    pub(crate) num_composed_constraints: usize,
    pub(crate) max_constraint_degree: usize,
    pub(crate) num_deep_terms: usize,
    pub(crate) lookup_fractions_per_row: usize,
    pub(crate) core_boundary_lookup_terms: usize,
    pub(crate) log_height_min: usize,
    pub(crate) max_num_kernel_procedures: usize,
    pub(crate) and8_lookup_log_height: usize,
    pub(crate) relation_digest_0: u64,
    pub(crate) relation_digest_1: u64,
    pub(crate) relation_digest_2: u64,
    pub(crate) relation_digest_3: u64,
    pub(crate) and8_preprocessed_trace_com_0: u64,
    pub(crate) and8_preprocessed_trace_com_1: u64,
    pub(crate) and8_preprocessed_trace_com_2: u64,
    pub(crate) and8_preprocessed_trace_com_3: u64,
}
