//! Rendering support for the relation-local MASM ACE evaluator wrapper.

use std::{format, string::String};

use miden_core::{Felt, Word};
use miden_crypto::{
    hash::eidos::{Eidos, domains::GENERIC_FELT_SEQUENCE},
    stark::QuotientRecompositionInputs,
};

use crate::AceError;

/// Relation-specific inputs to the shared MASM constraint-evaluator renderer.
#[derive(Clone, Debug)]
pub struct MasmConstraintsEvalConfig<'a> {
    /// Command responsible for regenerating the artifact, shown in its header.
    pub generated_by: &'a str,
    /// Relation-local module exposing `auxiliary_ace_inputs_ptr` and
    /// `ace_circuit_stream_ptr`.
    pub layout_module: &'a str,
    /// Number of READ variables in the encoded ACE circuit.
    pub num_inputs: usize,
    /// Number of evaluation gates in the encoded ACE circuit.
    pub num_eval_gates: usize,
    /// Total encoded circuit-stream length, in felts.
    pub stream_len: usize,
    /// Log2 of the longest periodic-column cycle across the relation's AIRs.
    pub max_cycle_len_log: u32,
    /// Number of AIR instances in the relation.
    pub num_airs: usize,
    /// How the evaluator stages one multi-AIR fold coefficient per AIR, or `None` for a relation
    /// whose ACE READ layout reserves no coefficient slots.
    ///
    /// The staged block sits immediately after the selectors, so a relation without those slots
    /// would write past its `auxiliary_ace_inputs_ptr` region.
    pub fold_coefficients: Option<FoldCoefficientStaging<'a>>,
    /// Relation-local inputs for reconstructing the quotient from its chunks.
    pub quotient_inputs: QuotientRecompositionInputs<Felt>,
    /// Eidos digest of the circuit-stream the relation accepts.
    pub circuit_digest: Word,
}

/// Where the generated evaluator finds the proof order and the coefficient slots.
#[derive(Clone, Debug)]
pub struct FoldCoefficientStaging<'a> {
    /// MASM leaving the `id_by_pos` table base on the stack (instance index at each proof
    /// position, as materialized by the relation's proof-order pass).
    pub id_by_pos_ptr: &'a str,
    /// Felt offset of AIR 0's fold-coefficient slot from `auxiliary_ace_inputs_ptr`; AIR `k`'s
    /// slot is `2k` felts further.
    pub coefficient_offset: usize,
}

/// Renders the fold-coefficient staging procedure of a relation's evaluator. It is private to the
/// evaluator module: the only production caller is `execute_constraint_evaluation_check`.
///
/// The native verifier folds the per-AIR constraint roots as a Horner chain over proof order, so
/// the AIR opened last carries `beta^0` and the one opened first `beta^(num_airs - 1)`. Walking
/// `id_by_pos` from the last proof position to the first produces every power with one
/// multiplication between consecutive positions, each written to the slot of the AIR at that
/// position.
fn render_fold_coefficient_staging(
    staging: &FoldCoefficientStaging<'_>,
    num_airs: usize,
) -> String {
    let mut steps = Vec::with_capacity(num_airs);
    for position in (0..num_airs).rev() {
        let load = if position == 0 {
            "dup.5 mem_load".to_string()
        } else {
            format!("dup.5 add.{position} mem_load")
        };
        let advance = if position == 0 { "" } else { "\n    dup.3 dup.3 ext2mul" };
        steps.push(format!(
            "    # proof position {position}: coefficient beta^{exponent} to that AIR's slot\n    \
             {load} mul.2 dup.5 add\n    \
             # => [destination, c0, c1, beta0, beta1, coefficient_ptr, id_by_pos_ptr]\n    \
             dup.2 dup.2 dup.2 mem_store swap add.1 mem_store\n    \
             # => [c0, c1, beta0, beta1, coefficient_ptr, id_by_pos_ptr]{advance}",
            exponent = num_airs - 1 - position,
        ));
    }
    format!(
        "#! Stages AIR k's multi-AIR fold coefficient `beta^(NUM_AIRS - 1 - pos_k)` in its READ slot.\n\
         #!\n\
         #! The native verifier folds the per-AIR roots as a Horner chain over the height-sorted proof\n\
         #! order, so the AIR opened last carries `beta^0` and the one opened first\n\
         #! `beta^(NUM_AIRS - 1)`. Walking `id_by_pos` from the last proof position to the first\n\
         #! produces every power with one multiplication between consecutive positions; each is written\n\
         #! to the slot of whichever AIR sits at that position. `beta` is sampled after the auxiliary\n\
         #! trace, so this runs after `set_up_auxiliary_inputs_ace`, and the proof-order pass\n\
         #! must already have filled `id_by_pos`.\n\
         #!\n\
         #! Inputs:  []\n\
         #! Outputs: []\n\
         proc stage_air_fold_coefficients\n    \
         {ids_ptr}\n    \
         exec.layout::auxiliary_ace_inputs_ptr add.{offset}\n    \
         padw exec.constants::composition_coef_ptr mem_loadw_le drop drop\n    \
         push.0.1\n    \
         # => [c0, c1, beta0, beta1, coefficient_ptr, id_by_pos_ptr]\n    # Each step copies its coefficient and destination before storing c0 then c1.\n\
         {steps}\n    \
         drop drop drop drop drop drop\n\
         end\n",
        ids_ptr = staging.id_by_pos_ptr,
        offset = staging.coefficient_offset,
        steps = steps.join("\n"),
    )
}

/// Render the MASM wrapper that prepares ACE inputs, authenticates the circuit, and executes it.
///
/// Both the Miden VM and PVM use this renderer. Their circuit sizes, quotient inputs, and memory
/// layouts remain relation-local parameters; the authentication and evaluation control flow has
/// one source.
pub fn render_masm_constraints_eval(
    config: &MasmConstraintsEvalConfig<'_>,
) -> Result<String, AceError> {
    if !config.stream_len.is_multiple_of(8) {
        return Err(AceError::InvalidInputLayout {
            message: "ACE stream must be 8-felt aligned".into(),
        });
    }

    let stream_blocks = config.stream_len / 8;
    let stream_felts =
        u32::try_from(config.stream_len).map_err(|_| AceError::InvalidInputLayout {
            message: "ACE stream length must fit in Eidos's u32 length binding".into(),
        })?;
    let stream_init_cv = Eidos::init_chaining_word(GENERIC_FELT_SEQUENCE, stream_felts);
    let circuit_digest = config.circuit_digest;
    let quotient = config.quotient_inputs;
    let (fold_coefficient_call, fold_coefficient_proc) = match &config.fold_coefficients {
        Some(staging) => (
            "\n    exec.stage_air_fold_coefficients\n".to_string(),
            format!("\n{}", render_fold_coefficient_staging(staging, config.num_airs)),
        ),
        None => (String::new(), String::new()),
    };

    Ok(format!(
        concat!(
            "# GENERATED by `{generated_by}` — do not edit by hand.\n",
            "use miden::core::crypto::hashes::eidos\n",
            "use miden::core::stark::constants\n",
            "use miden::core::stark::constraints_eval_inputs\n",
            "use {layout_module}\n\n",
            "# CONSTANTS\n",
            "# =================================================================================================\n\n",
            "# Number of READ variables (inputs + constants) for the constraint evaluation circuit.\n",
            "const NUM_INPUTS_CIRCUIT = {num_inputs}\n\n",
            "# Number of evaluation gates in the constraint evaluation circuit\n",
            "const NUM_EVAL_GATES_CIRCUIT = {num_eval_gates}\n\n",
            "# Max cycle length for periodic columns\n",
            "const MAX_CYCLE_LEN_LOG = {max_cycle_len_log}\n\n",
            "# Number of AIR instances in the relation.\n",
            "const NUM_AIRS = {num_airs}\n\n",
            "# Number of 8-felt blocks in the authenticated ACE circuit stream.\n",
            "const ACE_STREAM_BLOCKS = {stream_blocks}\n\n",
            "# Precomputed generic Felt-sequence chaining word for the fixed-length stream.\n",
            "const ACE_STREAM_INIT_CV_0 = {stream_init_cv_0}\n",
            "const ACE_STREAM_INIT_CV_1 = {stream_init_cv_1}\n",
            "const ACE_STREAM_INIT_CV_2 = {stream_init_cv_2}\n",
            "const ACE_STREAM_INIT_CV_3 = {stream_init_cv_3}\n\n",
            "# Quotient recomposition inputs derived from the circuit's quotient arity and the\n",
            "# relation's PCS configuration. QUOTIENT_SHIFT_RATIO depends on arity;\n",
            "# QUOTIENT_FIRST_SHIFT depends on the canonical LDE shift and blowup; and\n",
            "# QUOTIENT_FIRST_WEIGHT depends on both.\n",
            "const QUOTIENT_SHIFT_RATIO = {quotient_shift_ratio}\n",
            "const QUOTIENT_FIRST_SHIFT = {quotient_first_shift}\n",
            "const QUOTIENT_FIRST_WEIGHT = {quotient_first_weight}\n\n",
            "# Eidos digest of the ACE circuit stream this relation accepts. One circuit serves\n",
            "# every proof order, so it is the advice-map key and the value the loader pins.\n",
            "const ACE_CIRCUIT_DIGEST_0 = {circuit_digest_0}\n",
            "const ACE_CIRCUIT_DIGEST_1 = {circuit_digest_1}\n",
            "const ACE_CIRCUIT_DIGEST_2 = {circuit_digest_2}\n",
            "const ACE_CIRCUIT_DIGEST_3 = {circuit_digest_3}\n\n",
            "# ERRORS\n",
            "# =================================================================================================\n\n",
            "const ERR_CIRCUIT_DIGEST_MISMATCH = \"ACE circuit stream does not match the compiled-in circuit digest\"\n\n",
            "# CONSTRAINT EVALUATION CHECKER\n",
            "# =================================================================================================\n\n",
            "#! Executes the constraints evaluation check.\n",
            "#!\n",
            "#! Inputs:  []\n",
            "#! Outputs: []\n",
            "pub proc execute_constraint_evaluation_check()\n",
            "    push.QUOTIENT_SHIFT_RATIO\n",
            "    push.QUOTIENT_FIRST_SHIFT\n",
            "    push.QUOTIENT_FIRST_WEIGHT\n",
            "    exec.layout::auxiliary_ace_inputs_ptr\n",
            "    exec.constants::air_trace_length_logs_ptr\n",
            "    push.NUM_AIRS\n",
            "    push.MAX_CYCLE_LEN_LOG\n",
            "    exec.constraints_eval_inputs::set_up_auxiliary_inputs_ace\n",
            "{fold_coefficient_call}\n",
            "    exec.load_and_authenticate_ace_circuit\n\n",
            "    push.NUM_EVAL_GATES_CIRCUIT\n",
            "    push.NUM_INPUTS_CIRCUIT\n",
            "    exec.constants::public_inputs_address_ptr mem_load\n",
            "    eval_circuit\n",
            "    drop drop drop\n",
            "end\n\n",
            "#! Loads the ACE circuit from the advice map and pins it to the compiled-in digest.\n",
            "#!\n",
            "#! The stream is one adv_pipe-aligned segment hashed in a single pass. Its digest is both\n",
            "#! the advice-map key the stream is fetched under and the value the hash must reproduce,\n",
            "#! so a stream that is not the accepted circuit fails here rather than mis-evaluating.\n",
            "proc load_and_authenticate_ace_circuit\n",
            "    push.ACE_CIRCUIT_DIGEST_3.ACE_CIRCUIT_DIGEST_2.ACE_CIRCUIT_DIGEST_1.ACE_CIRCUIT_DIGEST_0\n",
            "    # => [ACE_CIRCUIT_DIGEST]\n",
            "    adv.push_mapval\n",
            "    exec.layout::ace_circuit_stream_ptr\n",
            "    push.ACE_STREAM_INIT_CV_3.ACE_STREAM_INIT_CV_2.ACE_STREAM_INIT_CV_1.ACE_STREAM_INIT_CV_0\n",
            "    padw padw\n",
            "    # => [ZERO, ZERO, CV, ptr, ACE_CIRCUIT_DIGEST]\n",
            "    repeat.ACE_STREAM_BLOCKS\n",
            "        adv_pipe\n",
            "        exec.eidos::compress\n",
            "    end\n",
            "    exec.eidos::digest\n",
            "    # => [STREAM_DIGEST, ptr, ACE_CIRCUIT_DIGEST]\n",
            "    movup.4 drop\n",
            "    # => [STREAM_DIGEST, ACE_CIRCUIT_DIGEST]\n",
            "    assert_eqw.err=ERR_CIRCUIT_DIGEST_MISMATCH\n",
            "end\n",
            "{fold_coefficient_proc}",
        ),
        generated_by = config.generated_by,
        layout_module = config.layout_module,
        num_inputs = config.num_inputs,
        num_eval_gates = config.num_eval_gates,
        max_cycle_len_log = config.max_cycle_len_log,
        num_airs = config.num_airs,
        stream_blocks = stream_blocks,
        quotient_shift_ratio = quotient.shift_ratio.as_canonical_u64(),
        quotient_first_shift = quotient.first_shift.as_canonical_u64(),
        quotient_first_weight = quotient.first_weight.as_canonical_u64(),
        fold_coefficient_call = fold_coefficient_call,
        fold_coefficient_proc = fold_coefficient_proc,
        stream_init_cv_0 = stream_init_cv[0].as_canonical_u64(),
        stream_init_cv_1 = stream_init_cv[1].as_canonical_u64(),
        stream_init_cv_2 = stream_init_cv[2].as_canonical_u64(),
        stream_init_cv_3 = stream_init_cv[3].as_canonical_u64(),
        circuit_digest_0 = circuit_digest[0].as_canonical_u64(),
        circuit_digest_1 = circuit_digest[1].as_canonical_u64(),
        circuit_digest_2 = circuit_digest[2].as_canonical_u64(),
        circuit_digest_3 = circuit_digest[3].as_canonical_u64(),
    ))
}

#[cfg(test)]
mod tests {
    use miden_core::Felt;
    use miden_crypto::stark::QuotientRecompositionInputs;

    use super::{FoldCoefficientStaging, MasmConstraintsEvalConfig, render_masm_constraints_eval};

    const STAGING_CALL: &str = "exec.stage_air_fold_coefficients";
    const STAGING_PROC: &str = "proc stage_air_fold_coefficients";

    fn config(stages_fold_coefficients: bool) -> MasmConstraintsEvalConfig<'static> {
        MasmConstraintsEvalConfig {
            generated_by: "test",
            layout_module: "miden::core::sys::test::layout",
            num_inputs: 16,
            num_eval_gates: 8,
            stream_len: 64,
            max_cycle_len_log: 5,
            num_airs: 4,
            fold_coefficients: stages_fold_coefficients.then_some(FoldCoefficientStaging {
                id_by_pos_ptr: "exec.layout::proof_order_ids_ptr",
                coefficient_offset: 46,
            }),
            quotient_inputs: QuotientRecompositionInputs {
                shift_ratio: Felt::new_unchecked(2),
                first_shift: Felt::new_unchecked(3),
                first_weight: Felt::new_unchecked(5),
            },
            circuit_digest: [7, 11, 13, 17].map(Felt::new_unchecked).into(),
        }
    }

    /// A relation whose READ layout has no fold-coefficient slots must get no staging call.
    ///
    /// The staged block sits immediately after the selectors, so emitting it for such a relation
    /// would write past its `auxiliary_ace_inputs_ptr` region. Nothing downstream of the renderer
    /// can tell the two cases apart, which is why the flag is checked here rather than only where
    /// it is passed.
    #[test]
    fn fold_coefficient_staging_is_emitted_only_when_the_relation_asks_for_it() {
        let staged = render_masm_constraints_eval(&config(true)).expect("renders");
        assert!(staged.contains(STAGING_CALL), "the staging call is missing when requested");
        assert!(staged.contains(STAGING_PROC), "the staging procedure is missing when requested");
        assert!(
            !staged.contains(&format!("pub {STAGING_PROC}")),
            "the staging procedure is evaluator-private"
        );
        // One multiplication between consecutive positions; four AIRs, four writes.
        assert_eq!(staged.matches("ext2mul").count(), 3);
        assert_eq!(staged.matches("add.1 mem_store").count(), 4);
        assert!(staged.contains("exec.layout::auxiliary_ace_inputs_ptr add.46"));

        let bare = render_masm_constraints_eval(&config(false)).expect("renders");
        assert!(
            !bare.contains(STAGING_CALL) && !bare.contains(STAGING_PROC),
            "the staging leaked into a relation without fold-coefficient slots"
        );

        // Only the staging block may differ: both relations run the same setup, authentication,
        // and evaluation.
        for shared in [
            "exec.constraints_eval_inputs::set_up_auxiliary_inputs_ace",
            "exec.load_and_authenticate_ace_circuit",
            "assert_eqw.err=ERR_CIRCUIT_DIGEST_MISMATCH",
        ] {
            assert!(bare.contains(shared), "{shared} is missing from the unstaged evaluator");
            assert!(staged.contains(shared), "{shared} is missing from the staged evaluator");
        }
    }

    /// The single authenticated segment must be a whole number of `adv_pipe` blocks.
    #[test]
    fn a_misaligned_stream_is_refused() {
        let mut config = config(true);
        config.stream_len = 60;
        assert!(render_masm_constraints_eval(&config).is_err());
    }
}
