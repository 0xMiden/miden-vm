use std::{
    format, io,
    string::{String, ToString},
    vec::Vec,
};

use askama::Template;
use miden_ace_codegen::{
    EXT_DEGREE, InputKey, InputLayout, RecursiveAceCircuit,
    compiler::{
        CapturedAir, CompiledRelation, FoldCoefficientStaging, LayoutKind,
        MasmConstraintsEvalConfig, OodScatterPlan, ProofOrderMapsConfig, RelationGeometry,
        render_masm_constraints_eval, render_proof_order_maps,
    },
};
use miden_air::{
    MIDEN_AIR_COUNT,
    config::{self, PROTOCOL_ID, relation_digest},
};
use miden_air_definitions::{AIRS, MidenAir};
use miden_core::{Felt, WORD_SIZE, Word, program::KernelDescriptor};
use miden_lifted_stark::{QuotientRecompositionInputs, quotient_recomposition_inputs};
use p3_air::BaseAir;

use crate::templates::{VmDeepQueriesTemplate, VmLayoutTemplate, VmModTemplate};

/// Per-AIR trace regions are padded to this width before concatenation.
const LMCS_ALIGNMENT: usize = 8;

/// Felts moved by one `adv_pipe`.
///
/// This transport width governs block/segment arithmetic and destination alignment;
/// [`LMCS_ALIGNMENT`] independently governs column-padding widths.
const ADV_PIPE_BLOCK_FELTS: usize = 8;

/// Computes the relation digest used by recursive verification.
pub fn compute_relation_digest(circuit_digest: &[Felt; 4]) -> [Felt; 4] {
    relation_digest(PROTOCOL_ID, &Word::new(*circuit_digest))
}

fn check_vm_ace_stream_capacity(
    stream_start: usize,
    pvm_start: usize,
    stream_len: usize,
) -> io::Result<()> {
    let capacity = pvm_start.checked_sub(stream_start).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "PVM allocation starts before the VM ACE stream")
    })?;
    if stream_len > capacity {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "VM ACE stream requires {stream_len} felts but its fixed reservation holds \
                 {capacity}"
            ),
        ));
    }
    Ok(())
}

/// Felts reserved for the out-of-domain scatter table by `sys/vm/layout.masm`.
const OOD_SCATTER_TABLE_FELTS: usize = 64;

struct VmGeometry {
    preprocessed_widths: Vec<usize>,
    preprocessed_width: usize,
    main_widths: Vec<usize>,
    main_width: usize,
    aux_widths: Vec<usize>,
    aux_width: usize,
    quotient_width: usize,
    row_width: usize,
    ood_row_felts: usize,
    ood_frame_felts: usize,
    preprocessed_pipe_blocks: usize,
    main_pipe_blocks: usize,
    aux_pipe_blocks: usize,
    quotient_pipe_blocks: usize,
    ood_pipe_blocks: usize,
    ood_evaluations_ptr: usize,
    aux_bus_boundary_ptr: usize,
    auxiliary_ace_inputs_ptr: usize,
    ace_circuit_stream_ptr: usize,
    current_trace_row_ptr: usize,
    ood_scatter_table_ptr: usize,
    /// Felt offset of AIR 0's fold-coefficient slot from `auxiliary_ace_inputs_ptr`.
    fold_coefficient_offset: usize,
}

impl VmGeometry {
    fn from_compiled(compiled: &RelationGeometry, input_layout: &InputLayout) -> io::Result<Self> {
        let preprocessed_widths =
            compiled.airs.iter().map(|air| air.preprocessed.width).collect::<Vec<_>>();
        let main_widths = compiled.airs.iter().map(|air| air.main.width).collect::<Vec<_>>();
        let aux_widths = compiled.airs.iter().map(|air| air.aux.width).collect::<Vec<_>>();
        let preprocessed_width = compiled.preprocessed_width;
        let main_width = compiled.main_width;
        let aux_width = compiled.aux_width;
        let aux_values = compiled.airs.iter().map(|air| air.num_aux_boundary).collect::<Vec<_>>();
        if aux_values.iter().any(|&count| count != 1) {
            return Err(io::Error::other(
                "VM boundary scatter requires one auxiliary value per AIR",
            ));
        }
        let quotient_width = compiled.quotient_width;
        let row_width = preprocessed_width + main_width + aux_width + quotient_width;

        for (name, derived, actual) in [
            ("preprocessed", preprocessed_width, input_layout.counts.preprocessed_width),
            ("main", main_width, input_layout.counts.width),
            ("auxiliary-coordinate", aux_width, input_layout.counts.aux_width * EXT_DEGREE),
            (
                "auxiliary-boundary",
                aux_values.iter().sum::<usize>(),
                input_layout.counts.num_aux_boundary,
            ),
        ] {
            if derived != actual {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "AIR-derived {name} width {derived} disagrees with ACE input layout width \
                         {actual}"
                    ),
                ));
            }
        }

        for (name, width) in [
            ("preprocessed", preprocessed_width),
            ("main", main_width),
            ("auxiliary", aux_width),
            ("quotient", quotient_width),
            ("ACE row", row_width),
        ] {
            if !width.is_multiple_of(ADV_PIPE_BLOCK_FELTS) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("VM {name} width {width} is not {ADV_PIPE_BLOCK_FELTS}-felt aligned"),
                ));
            }
        }

        // Fixed memory policy: the READ section and query scratch have separate reservations.
        let aux_rand_elem_ptr = 3_225_419_776usize;
        let current_trace_row_ptr = 3_238_002_688usize;
        if !current_trace_row_ptr.is_multiple_of(ADV_PIPE_BLOCK_FELTS) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "the VM current-trace-row base {current_trace_row_ptr} is not \
                     {ADV_PIPE_BLOCK_FELTS}-felt aligned, which `adv_pipe` requires"
                ),
            ));
        }
        // The scatter table is verifier scratch that must stay clear of the ACE READ section.
        let ood_scatter_table_ptr = 3_223_323_864usize;
        if !ood_scatter_table_ptr.is_multiple_of(4) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "the VM out-of-domain scatter table base {ood_scatter_table_ptr} is not \
                     4-felt (word) aligned, which its `mem_storew_le`/`dynexec` entries require"
                ),
            ));
        }
        if ood_scatter_table_ptr + OOD_SCATTER_TABLE_FELTS > aux_rand_elem_ptr {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "the {OOD_SCATTER_TABLE_FELTS}-felt out-of-domain scatter table at \
                     {ood_scatter_table_ptr} runs into the ACE READ section at {aux_rand_elem_ptr}"
                ),
            ));
        }
        // Its lower neighbour is the kernel digest witness, one word per supported kernel
        // procedure written by `materialize_kernel_witness`; the table must start at or after its
        // end.
        let kernel_witness_ptr = 3_223_322_844usize;
        let kernel_witness_end = kernel_witness_ptr
            .checked_add(WORD_SIZE * KernelDescriptor::MAX_NUM_PROCEDURES)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "the kernel witness end overflows")
            })?;
        if ood_scatter_table_ptr < kernel_witness_end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "the out-of-domain scatter table at {ood_scatter_table_ptr} overlaps the \
                     kernel digest witness, which ends at {kernel_witness_end}"
                ),
            ));
        }

        let aux_rand_index = require_input_index(input_layout, InputKey::AuxRandBeta)?;
        let ood_index =
            require_input_index(input_layout, InputKey::Preprocessed { offset: 0, index: 0 })?;
        let next_ood_index =
            require_input_index(input_layout, InputKey::Preprocessed { offset: 1, index: 0 })?;
        let aux_bus_boundary_index =
            require_input_index(input_layout, InputKey::AuxBusBoundary(0))?;
        let auxiliary_ace_inputs_index = require_input_index(input_layout, InputKey::Alpha)?;
        let fold_coefficient_index =
            require_input_index(input_layout, InputKey::MultiAirFoldCoeff(0))?;
        let fold_coefficient_offset = input_layout_extent(
            auxiliary_ace_inputs_index,
            fold_coefficient_index,
            "fold coefficients",
        )?;

        let ood_row_felts = input_layout_extent(ood_index, next_ood_index, "current OOD row")?;
        let ood_frame_felts = input_layout_extent(ood_index, aux_bus_boundary_index, "OOD frame")?;
        if ood_row_felts != row_width * EXT_DEGREE || ood_frame_felts != 2 * ood_row_felts {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "ACE input layout has {ood_row_felts} felts per OOD row and \
                     {ood_frame_felts} per frame; AIR widths require {} and {}",
                    row_width * EXT_DEGREE,
                    2 * row_width * EXT_DEGREE,
                ),
            ));
        }

        let input_ptr =
            |index, label| input_layout_ptr(aux_rand_elem_ptr, aux_rand_index, index, label);
        let ood_evaluations_ptr = input_ptr(ood_index, "OOD evaluations")?;
        let aux_bus_boundary_ptr = input_ptr(aux_bus_boundary_index, "aux bus boundary")?;
        let auxiliary_ace_inputs_ptr =
            input_ptr(auxiliary_ace_inputs_index, "auxiliary ACE inputs")?;
        let ace_circuit_stream_ptr = input_ptr(input_layout.total_inputs, "ACE circuit stream")?;

        Ok(Self {
            preprocessed_widths,
            preprocessed_width,
            main_widths,
            main_width,
            aux_widths,
            aux_width,
            quotient_width,
            row_width,
            ood_row_felts,
            ood_frame_felts,
            preprocessed_pipe_blocks: preprocessed_width / ADV_PIPE_BLOCK_FELTS,
            main_pipe_blocks: main_width / ADV_PIPE_BLOCK_FELTS,
            aux_pipe_blocks: aux_width / ADV_PIPE_BLOCK_FELTS,
            quotient_pipe_blocks: quotient_width / ADV_PIPE_BLOCK_FELTS,
            ood_pipe_blocks: ood_row_felts / ADV_PIPE_BLOCK_FELTS,
            ood_evaluations_ptr,
            aux_bus_boundary_ptr,
            auxiliary_ace_inputs_ptr,
            ace_circuit_stream_ptr,
            current_trace_row_ptr,
            ood_scatter_table_ptr,
            fold_coefficient_offset,
        })
    }
}

fn require_input_index(input_layout: &InputLayout, key: InputKey) -> io::Result<usize> {
    input_layout.index(key).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("VM ACE input layout is missing {key:?}"),
        )
    })
}

fn input_layout_extent(start: usize, end: usize, label: &str) -> io::Result<usize> {
    end.checked_sub(start)
        .and_then(|slots| slots.checked_mul(EXT_DEGREE))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("VM ACE {label} extent is reversed or overflows"),
            )
        })
}

fn input_layout_ptr(
    base_ptr: usize,
    base_index: usize,
    index: usize,
    label: &str,
) -> io::Result<usize> {
    let offset = input_layout_extent(base_index, index, label)?;
    base_ptr.checked_add(offset).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, format!("VM ACE {label} pointer overflows"))
    })
}

fn render_vm_layout(geometry: &VmGeometry) -> io::Result<String> {
    let plan = vm_scatter_plan(geometry)?;

    let comment_ood_scatter_table_ptr = format!(
        "### Out-of-domain ingest scatter table and proof-order maps, immediately after the VM \
             control\n\
             ### frame. Reserves {OOD_SCATTER_TABLE_FELTS} felts:\n\
             ###\n\
             ###   +0            base address of the out-of-domain row being ingested\n\
             ###   +4  .. +{pairs_end}    per proof position, in stream order: (row-relative \
             destination, digest address)\n\
             ###   +{digests} .. +{digests_end}    `pipe_k` procedure digests reached by `dynexec`, \
             one word each\n\
             ###   +{positions} .. +{positions_end}    `pos_by_id`: each AIR's proof position, in \
             instance order\n\
             ###   +{ids} .. +{ids_end}    `id_by_pos`: the AIR committed at each proof position\n\
             ###\n\
             ### The internal offsets and the reserve's sufficiency are owned by \
             `miden-verifier-codegen`, which\n\
             ### derives them from the AIR widths and fills `sys/vm/ood_frames.masm` accordingly.",
        pairs_end = plan.pipe_digests().start - 1,
        digests = plan.pipe_digests().start,
        digests_end = plan.table_felts() - 1,
        positions = plan.table_felts(),
        positions_end = plan.table_felts() + MIDEN_AIR_COUNT - 1,
        ids = plan.table_felts() + MIDEN_AIR_COUNT,
        ids_end = plan.table_felts() + 2 * MIDEN_AIR_COUNT - 1,
    );

    let positions_ptr =
        geometry.ood_scatter_table_ptr.checked_add(plan.table_felts()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "VM proof-order map overflows")
        })?;
    let ids_ptr = positions_ptr.checked_add(MIDEN_AIR_COUNT).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "VM proof-order map overflows")
    })?;

    let ood_row_diagram = format!(
        "##   OOD_EVALUATIONS_PTR --> [ OOD evaluations          ]  {} felts",
        geometry.ood_frame_felts
    );
    let comment_ood_evaluations_ptr = format!(
        "### OOD evaluations in the VM ACE READ section. Each aligned current/next row has\n\
             ### {} scalar evaluations: {} preprocessed, {} main, {} auxiliary-coordinate, and \
             {}\n\
             ### quotient. Each evaluation is quadratic-extension valued, so advice supplies {} \
             base felts\n\
             ### per row.",
        geometry.row_width,
        geometry.preprocessed_width,
        geometry.main_width,
        geometry.aux_width,
        geometry.quotient_width,
        geometry.ood_row_felts,
    );
    let comment_current_trace_row_ptr = format!(
        "### Scratch row for DEEP query openings: {} preprocessed, {} main, {}\n\
             ### auxiliary-coordinate, and {} quotient felts ({} total).",
        geometry.preprocessed_width,
        geometry.main_width,
        geometry.aux_width,
        geometry.quotient_width,
        geometry.row_width,
    );
    VmLayoutTemplate {
        ood_evaluations_ptr: geometry.ood_evaluations_ptr,
        aux_bus_boundary_ptr: geometry.aux_bus_boundary_ptr,
        auxiliary_ace_inputs_ptr: geometry.auxiliary_ace_inputs_ptr,
        ace_circuit_stream_ptr: geometry.ace_circuit_stream_ptr,
        current_trace_row_ptr: geometry.current_trace_row_ptr,
        proof_order_positions_ptr: positions_ptr,
        proof_order_ids_ptr: ids_ptr,
        comment_ood_scatter_table_ptr,
        ood_row_diagram,
        comment_ood_evaluations_ptr,
        comment_current_trace_row_ptr,
    }
    .render()
    .map_err(io::Error::other)
}

const WORD_FELTS: usize = 4;

fn vm_scatter_plan(geometry: &VmGeometry) -> io::Result<OodScatterPlan> {
    let plan = OodScatterPlan::new(
        &geometry.preprocessed_widths,
        &geometry.main_widths,
        &geometry.aux_widths,
        geometry.quotient_width,
    )
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    let required = plan.table_felts() + 2 * MIDEN_AIR_COUNT;
    if required > OOD_SCATTER_TABLE_FELTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "the scatter table and proof-order maps need {required} felts but reserve {OOD_SCATTER_TABLE_FELTS}"
            ),
        ));
    }
    Ok(plan)
}

fn render_vm_ood_frames(geometry: &VmGeometry) -> io::Result<String> {
    let plan = vm_scatter_plan(geometry)?;
    // Word reads and writes need word-aligned bases; the pass falls back to single-cell accesses
    // otherwise, so alignment is a layout fact checked here, not an assumption.
    // The generic height array is word aligned under the verifier memory policy.
    let heights_ptr = 3_223_322_744usize;
    let ids_ptr = geometry
        .ood_scatter_table_ptr
        .checked_add(plan.table_felts())
        .and_then(|ptr| ptr.checked_add(MIDEN_AIR_COUNT))
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "VM proof-order map overflows")
        })?;
    let proof_order_maps = render_proof_order_maps(&ProofOrderMapsConfig {
        num_airs: MIDEN_AIR_COUNT,
        heights_ptr: "push.LOG_AIR_TRACE_LENGTHS_PTR",
        pos_by_id_ptr: "exec.layout::proof_order_positions_ptr",
        id_by_pos_ptr: "exec.layout::proof_order_ids_ptr",
        word_load_heights: heights_ptr.is_multiple_of(WORD_FELTS),
        word_store_ids: ids_ptr.is_multiple_of(WORD_FELTS),
    })
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;

    let procedures = plan.render(&proof_order_maps);

    Ok(format!(
        r#"# GENERATED by `{generated_by}` — do not edit by hand.
use {{LOG_AIR_TRACE_LENGTHS_PTR}} from miden::core::stark::constants
use miden::core::stark::types
use miden::core::sys::vm::layout

# Number of AIR instances in the relation.
# NUM_AIRS = {num_airs}

# Per-row OOD layout uses LMCS alignment {LMCS_ALIGNMENT}:
#   preprocessed: {preprocessed_parts} = {preprocessed} scalar evaluations
#   main:         {main_parts} = {main} scalar evaluations
#   aux:          {aux_parts} = {aux} scalar evaluations
#   quotient:     {quotient} scalar evaluations
# The advice stream supplies {ood_felts} base felts, read as {pipe_blocks} `adv_pipe` blocks.

{procedures}"#,
        generated_by = crate::GENERATED_BY,
        num_airs = MIDEN_AIR_COUNT,
        preprocessed_parts = format_sum(&geometry.preprocessed_widths),
        preprocessed = geometry.preprocessed_width,
        main_parts = format_sum(&geometry.main_widths),
        main = geometry.main_width,
        aux_parts = format_sum(&geometry.aux_widths),
        aux = geometry.aux_width,
        quotient = geometry.quotient_width,
        ood_felts = geometry.ood_row_felts,
        pipe_blocks = geometry.ood_pipe_blocks,
    ))
}

fn render_vm_deep_queries(geometry: &VmGeometry) -> io::Result<String> {
    let chaining_word = |width| -> io::Result<String> {
        let encoded_len = u32::try_from(width).map_err(io::Error::other)?;
        let cv = miden_core::crypto::hash::Eidos::init_chaining_word(
            miden_crypto::hash::eidos::domains::LMCS_LEAF,
            encoded_len,
        );
        Ok(format!("{:?}", word_to_array(cv).map(|f| f.as_canonical_u64())))
    };
    let depth = u32::from(miden_air::and8_lookup::columns::LOG_AND8_LOOKUP_TRACE_HEIGHT)
        + u32::from(config::LOG_BLOWUP);
    let mask = 1u32
        .checked_shl(depth)
        .and_then(|n| n.checked_sub(1))
        .ok_or_else(|| io::Error::other("AND8 setup depth exceeds u32 query indices"))?;
    VmDeepQueriesTemplate {
        and8_lde_index_mask: mask,
        preprocessed_lmcs_init_cv: chaining_word(geometry.preprocessed_width)?,
        main_lmcs_init_cv: chaining_word(geometry.main_width)?,
        aux_lmcs_init_cv: chaining_word(geometry.aux_width)?,
        quotient_lmcs_init_cv: chaining_word(geometry.quotient_width)?,
        preprocessed_comment: format!(
            "    # AND8 preprocessed matrix: {} columns, padded to {} base felts by LMCS.",
            BaseAir::<Felt>::preprocessed_width(&MidenAir::And8Lookup),
            geometry.preprocessed_width
        ),
        main_comment: format!(
            "    # Load the aligned main leaf: {} = {} base felts.",
            format_sum(&geometry.main_widths),
            geometry.main_width
        ),
        aux_comment: format!(
            "    # Load the aligned aux leaf: {} = {} base felts.",
            format_sum(&geometry.aux_widths),
            geometry.aux_width
        ),
        repeat_load_preprocessed_segment: geometry.preprocessed_pipe_blocks,
        repeat_load_main_segment_execution_trace: geometry.main_pipe_blocks,
        repeat_load_aux_segment_execution_trace: geometry.aux_pipe_blocks,
        repeat_load_constraints_composition_polys_trace: geometry.quotient_pipe_blocks,
    }
    .render()
    .map_err(io::Error::other)
}

fn format_sum(parts: &[usize]) -> String {
    parts.iter().map(usize::to_string).collect::<Vec<_>>().join(" + ")
}

fn word_to_array(word: Word) -> [Felt; 4] {
    [word[0], word[1], word[2], word[3]]
}

fn render_constraints_eval_file(
    circuit: &RecursiveAceCircuit,
    quotient_inputs: QuotientRecompositionInputs<Felt>,
    geometry: &VmGeometry,
    max_cycle_len_log: u32,
) -> io::Result<String> {
    render_masm_constraints_eval(&MasmConstraintsEvalConfig {
        generated_by: crate::GENERATED_BY,
        layout_module: "miden::core::sys::vm::layout",
        num_inputs: circuit.num_inputs,
        num_eval_gates: circuit.num_eval_gates,
        stream_len: circuit.stream_len,
        max_cycle_len_log,
        num_airs: MIDEN_AIR_COUNT,
        // The VM's canonical READ layout reserves one fold-coefficient slot per AIR, so its
        // evaluator stages them from the proof-order maps; that block is what makes the circuit
        // order-invariant.
        fold_coefficients: FoldCoefficientStaging {
            id_by_pos_ptr: "exec.layout::proof_order_ids_ptr",
            coefficient_offset: geometry.fold_coefficient_offset,
        },
        quotient_inputs,
        circuit_digest: circuit.commitment,
    })
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
}

pub(crate) fn render(modules: &mut Vec<crate::RenderedModule>) -> Result<(), String> {
    let captured = AIRS
        .iter()
        .map(CapturedAir::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let airs = captured.iter().collect::<Vec<_>>();
    let compiled =
        CompiledRelation::from_captured(&airs, LMCS_ALIGNMENT).map_err(|e| e.to_string())?;
    let source = compiled.build_circuit(LayoutKind::Masm).map_err(|e| e.to_string())?;
    let circuit = RecursiveAceCircuit::try_from(source.to_ace().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let geometry = VmGeometry::from_compiled(compiled.geometry(), source.layout())
        .map_err(|e| e.to_string())?;
    check_vm_ace_stream_capacity(
        geometry.ace_circuit_stream_ptr,
        super::pvm::PVM_READ_START as usize,
        circuit.stream_len,
    )
    .map_err(|e| e.to_string())?;
    let quotient = quotient_recomposition_inputs::<Felt>(
        source.layout().counts.num_quotient_chunks.ilog2() as u8,
        config::pcs_params().log_blowup(),
    )
    .map_err(|e| e.to_string())?;
    let digest = compute_relation_digest(&word_to_array(circuit.commitment));
    let setup = config::EIDOS_PREPROCESSED_COMMITMENT;
    use miden_air::security;
    let min_trace_len = miden_air::trace::MIN_TRACE_LEN;
    if !min_trace_len.is_power_of_two() {
        return Err("VM minimum trace length must be a power of two".into());
    }
    let wrapper = VmModTemplate {
        relation_digest_0: digest[0].as_canonical_u64(),
        relation_digest_1: digest[1].as_canonical_u64(),
        relation_digest_2: digest[2].as_canonical_u64(),
        relation_digest_3: digest[3].as_canonical_u64(),
        and8_preprocessed_trace_com_0: setup[0],
        and8_preprocessed_trace_com_1: setup[1],
        and8_preprocessed_trace_com_2: setup[2],
        and8_preprocessed_trace_com_3: setup[3],
        log_height_min: min_trace_len.ilog2() as usize,
        lookup_pow_bits: security::LOOKUP_POW_BITS as usize,
        max_message_width: security::LOOKUP_SHAPE.max_message_width as usize,
        num_composed_constraints: security::AIR_SHAPE.num_composed_constraints as usize,
        max_constraint_degree: security::AIR_SHAPE.max_constraint_degree as usize,
        num_deep_terms: security::AIR_SHAPE.num_deep_terms.expect("DEEP composition") as usize,
        lookup_fractions_per_row: security::LOOKUP_SHAPE.fractions_per_row as usize,
        core_boundary_lookup_terms: security::CORE_BOUNDARY_LOOKUP_TERMS as usize,
        max_num_kernel_procedures: KernelDescriptor::MAX_NUM_PROCEDURES,
        and8_lookup_log_height: miden_air::trace::and8_lookup::AND8_LOOKUP_TRACE_HEIGHT.ilog2()
            as usize,
    }
    .render()
    .map_err(|e| e.to_string())?;
    for (name, content) in [
        ("mod", wrapper),
        ("layout", render_vm_layout(&geometry).map_err(|e| e.to_string())?),
        ("ood_frames", render_vm_ood_frames(&geometry).map_err(|e| e.to_string())?),
        ("deep_queries", render_vm_deep_queries(&geometry).map_err(|e| e.to_string())?),
        (
            "constraints_eval",
            render_constraints_eval_file(
                &circuit,
                quotient,
                &geometry,
                compiled.geometry().shared_period.ilog2(),
            )
            .map_err(|e| e.to_string())?,
        ),
    ] {
        super::push_module(modules, "vm", name, &content)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use miden_air_definitions::compiler::vm::{
        build_canonical_multi_air_ace_circuit, recursive_verifier_ace_config,
    };

    use super::*;
    /// A group every AIR occupies is indexed correctly by proof-order position, and one with a
    /// single occupant needs no table at all. Anything between the two would address past the
    /// group's slots, so the renderer must refuse it instead of emitting it.
    #[test]
    fn scatter_plan_rejects_partially_occupied_commitment_groups() {
        // The VM preprocessed commitment group is occupied only by `MidenAir::And8Lookup`.
        assert!(vm_scatter_plan(&scatter_test_geometry(&[0, 0, 0, 16])).is_ok());
        // Every AIR occupies the group.
        assert!(vm_scatter_plan(&scatter_test_geometry(&[16, 16, 16, 16])).is_ok());
        // Two of four: the proof-order position no longer indexes the group's slots.
        let Err(partial) = vm_scatter_plan(&scatter_test_geometry(&[16, 0, 0, 16])) else {
            panic!("a partially occupied group must be refused");
        };
        assert!(
            partial
                .to_string()
                .contains("preprocessed commitment group is occupied by 2 of 4"),
            "unexpected refusal: {partial}"
        );
    }

    /// A geometry whose only meaningful axis is the preprocessed occupancy under test.
    fn scatter_test_geometry(preprocessed_widths: &[usize]) -> VmGeometry {
        let preprocessed_widths = preprocessed_widths.to_vec();
        let main_widths = vec![8; preprocessed_widths.len()];
        let aux_widths = vec![8; preprocessed_widths.len()];
        let preprocessed_width: usize = preprocessed_widths.iter().sum();
        let main_width: usize = main_widths.iter().sum();
        let aux_width: usize = aux_widths.iter().sum();
        let quotient_width = 8;
        let row_width = preprocessed_width + main_width + aux_width + quotient_width;
        VmGeometry {
            preprocessed_widths,
            preprocessed_width,
            main_widths,
            main_width,
            aux_widths,
            aux_width,
            quotient_width,
            row_width,
            ood_row_felts: row_width * EXT_DEGREE,
            ood_frame_felts: 2 * row_width * EXT_DEGREE,
            preprocessed_pipe_blocks: preprocessed_width / ADV_PIPE_BLOCK_FELTS,
            main_pipe_blocks: main_width / ADV_PIPE_BLOCK_FELTS,
            aux_pipe_blocks: aux_width / ADV_PIPE_BLOCK_FELTS,
            quotient_pipe_blocks: quotient_width / ADV_PIPE_BLOCK_FELTS,
            ood_pipe_blocks: row_width * EXT_DEGREE / ADV_PIPE_BLOCK_FELTS,
            ood_evaluations_ptr: 0,
            aux_bus_boundary_ptr: 0,
            auxiliary_ace_inputs_ptr: 0,
            ace_circuit_stream_ptr: 0,
            current_trace_row_ptr: 0,
            ood_scatter_table_ptr: 0,
            fold_coefficient_offset: 0,
        }
    }

    #[test]
    fn vm_ace_stream_capacity_accepts_exact_fit_and_rejects_overflow() {
        let stream_start = 1_000;
        let pvm_start = 1_100;

        check_vm_ace_stream_capacity(stream_start, pvm_start, 100).expect("exact fit");
        let error = check_vm_ace_stream_capacity(stream_start, pvm_start, 101)
            .expect_err("one felt beyond the reservation must fail");
        assert!(error.to_string().contains("requires 101 felts"));
    }

    #[test]
    fn vm_ace_stream_capacity_rejects_reversed_anchors() {
        let error = check_vm_ace_stream_capacity(1_100, 1_000, 0)
            .expect_err("the PVM allocation must follow the VM stream");
        assert!(error.to_string().contains("PVM allocation starts before"));
    }

    #[test]
    fn deep_query_loader_repeats_follow_air_geometry() {
        let circuit = build_canonical_multi_air_ace_circuit(recursive_verifier_ace_config())
            .expect("recursive ACE circuit");
        let captured = AIRS.iter().map(CapturedAir::new).collect::<Result<Vec<_>, _>>().unwrap();
        let refs = captured.iter().collect::<Vec<_>>();
        let compiled = CompiledRelation::from_captured(&refs, LMCS_ALIGNMENT).unwrap();
        let geometry =
            VmGeometry::from_compiled(compiled.geometry(), circuit.layout()).expect("VM geometry");
        let deep_queries = render_vm_deep_queries(&geometry).expect("render DEEP-query loaders");

        for (proc_name, expected) in [
            ("load_preprocessed_segment", geometry.preprocessed_pipe_blocks),
            ("load_main_segment_execution_trace", geometry.main_pipe_blocks),
            ("load_aux_segment_execution_trace", geometry.aux_pipe_blocks),
            ("load_constraints_composition_polys_trace", geometry.quotient_pipe_blocks),
        ] {
            let proc_marker = format!("proc {proc_name}");
            let proc_body = deep_queries
                .split_once(&proc_marker)
                .unwrap_or_else(|| panic!("missing {proc_name}"))
                .1
                .split_once("\nend")
                .unwrap_or_else(|| panic!("missing end of {proc_name}"))
                .0;
            let actual = proc_body
                .lines()
                .find_map(|line| line.trim().strip_prefix("repeat.")?.parse::<usize>().ok())
                .unwrap_or_else(|| panic!("missing repeat in {proc_name}"));
            assert_eq!(actual, expected, "stale query loader geometry in {proc_name}");
        }
    }
}
