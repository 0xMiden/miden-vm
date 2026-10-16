//! Typed bindings for the verifier MASM templates.
use askama::Template;

#[derive(Template)]
#[template(path = "pvm/aux_trace.masm", escape = "none")]
pub(crate) struct PvmAuxTraceTemplate {
    pub(crate) uint_val_bus_scale: usize,
    pub(crate) ec_group_bus_scale: usize,
    pub(crate) max_logup_message_width: usize,
    pub(crate) num_chiplets: usize,
    pub(crate) num_aux_value_words: usize,
    pub(crate) scatter_boundaries: String,
    pub(crate) observe_boundaries: String,
    pub(crate) buffered_aux_value_count: usize,
    pub(crate) weight_boundaries: String,
    pub(crate) fixed_uint_consumes: String,
    pub(crate) fixed_ec_consumes: String,
}

#[derive(Template)]
#[template(path = "pvm/deep_queries.masm", escape = "none")]
pub(crate) struct PvmDeepQueriesTemplate {
    pub(crate) preprocessed_tree_depth: u32,
    pub(crate) preprocessed_index_mask: u32,
    pub(crate) preprocessed_row_double_words: usize,
    pub(crate) main_row_double_words: usize,
    pub(crate) aux_row_double_words: usize,
    pub(crate) quotient_row_double_words: usize,
    pub(crate) preprocessed_lmcs_init_cv: String,
    pub(crate) main_lmcs_init_cv: String,
    pub(crate) aux_lmcs_init_cv: String,
    pub(crate) quotient_lmcs_init_cv: String,
}

#[derive(Template)]
#[template(path = "pvm/mod.masm", escape = "none")]
pub(crate) struct PvmModTemplate {
    pub(crate) lookup_pow_bits: usize,
    pub(crate) max_message_width: usize,
    pub(crate) num_composed_constraints: usize,
    pub(crate) max_constraint_degree: usize,
    pub(crate) num_deep_terms: usize,
    pub(crate) lookup_fractions_per_row: usize,
    pub(crate) fixed_boundary_lookup_terms: usize,
    pub(crate) num_chiplets: usize,
    pub(crate) height_constants: String,
    pub(crate) relation_digest_0: u64,
    pub(crate) relation_digest_1: u64,
    pub(crate) relation_digest_2: u64,
    pub(crate) relation_digest_3: u64,
    pub(crate) preprocessed_commitment_0: u64,
    pub(crate) preprocessed_commitment_1: u64,
    pub(crate) preprocessed_commitment_2: u64,
    pub(crate) preprocessed_commitment_3: u64,
    pub(crate) load_heights: String,
}

#[derive(Template)]
#[template(path = "pvm/public_inputs.masm", escape = "none")]
pub(crate) struct PvmPublicInputsTemplate {
    pub(crate) num_public_values: usize,
    pub(crate) max_aux_inputs: usize,
    pub(crate) num_aux_inputs: usize,
    pub(crate) num_chiplets: usize,
    pub(crate) buffered_shape_value_count: usize,
}

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
