use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use std::{fs, io, println};

use miden_ace_codegen::{EXT_DEGREE, InputKey, InputLayout};
use miden_air::{
    AIRS, MIDEN_AIR_COUNT, MidenAir, MidenMultiAir, NUM_PUBLIC_VALUES, PROOF_ORDER_COUNT,
    ProofOrder, Statement,
    ace::RecursiveAceCircuitFactory,
    config::{ACE_CIRCUIT_REGISTRY_DEPTH, relation_digest},
};
use miden_core::{Felt, Word, field::QuadFelt, program::KernelDescriptor};
use miden_crypto::{
    hash::eidos::Eidos,
    merkle::MerkleTree,
    stark::{
        Preprocessed, QuotientRecompositionInputs,
        air::{BaseAir, LiftedAir},
        quotient_recomposition_inputs,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Check,
    Write,
}

const PROTOCOL_ID: u64 = 1;
const ACE_REGISTRY_PADDING_DOMAIN: u64 = 0xace;
const ACE_REGISTRY_LEAF_COUNT: usize = 1 << ACE_CIRCUIT_REGISTRY_DEPTH;
const AIR_CONFIG_PATH: &str = "../../../air/src/config.rs";
const CONSTRAINTS_EVAL_PATH: &str = "asm/sys/vm/constraints_eval.masm";
const RELATION_DIGEST_PATH: &str = "asm/sys/vm/mod.masm";
const VERIFIER_LIB_PATH: &str = "../../../verifier/src/lib.rs";
const VM_AUX_TRACE_PATH: &str = "asm/sys/vm/aux_trace.masm";
const VM_LAYOUT_PATH: &str = "asm/sys/vm/layout.masm";
const VM_OOD_FRAMES_PATH: &str = "asm/sys/vm/ood_frames.masm";
const VM_DEEP_QUERIES_PATH: &str = "asm/sys/vm/deep_queries.masm";
const VM_PUBLIC_INPUTS_PATH: &str = "asm/sys/vm/public_inputs.masm";
const PVM_LAYOUT_PATH: &str = "asm/sys/pvm/layout.masm";
const SECURITY_ESTIMATOR_PATH: &str = "asm/stark/security.masm";
const GENERIC_UTILS_PATH: &str = "asm/stark/utils.masm";
const LMCS_ALIGNMENT: usize = 8;

/// Computes the relation digest used by recursive verification.
pub fn compute_relation_digest(registry_root: &[Felt; 4]) -> [Felt; 4] {
    relation_digest(PROTOCOL_ID, &Word::new(*registry_root))
}

fn native_padding_leaf() -> Word {
    Eidos::hash_elements(&[Felt::new_unchecked(ACE_REGISTRY_PADDING_DOMAIN)])
}

/// Runs write (`--write`) or staleness-check (`--check`) mode.
pub fn run(mode: Mode) -> Result<(), String> {
    match mode {
        Mode::Check => check(),
        Mode::Write => write().map_err(|e| format!("{e}")),
    }
}

/// Runs the full regeneration flow.
fn write() -> io::Result<()> {
    let artifact = compute_artifacts()?;
    write_artifacts(&artifact)
}

/// Checks generated artifacts against current AIR-derived values.
fn check() -> Result<(), String> {
    let artifact = compute_artifacts().map_err(|err| err.to_string())?;
    constraints_eval_masm_matches_artifact(&artifact)?;
    relation_digest_matches_artifact(&artifact)?;
    public_inputs_masm_matches_air()?;
    vm_geometry_matches_artifact(&artifact)?;
    security_masm_matches_air()?;
    Ok(())
}

/// Generate a full computed snapshot from the current AIR.
fn compute_artifacts() -> io::Result<ComputedArtifacts> {
    let mut order_artifacts = Vec::new();
    // One factored build serves every proof order. Each order still assembles and encodes the
    // full stream, but the factory avoids rebuilding the composition and rehashing the common
    // section.
    let factory = RecursiveAceCircuitFactory::new()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    let num_quotient_chunks = factory.num_quotient_chunks();
    if !num_quotient_chunks.is_power_of_two() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("quotient chunk count {num_quotient_chunks} is not a power of two"),
        ));
    }
    let quotient_inputs = quotient_recomposition_inputs::<Felt>(
        num_quotient_chunks.ilog2() as u8,
        miden_air::config::pcs_params().log_blowup(),
    )
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    // Retain the first order's common-section bytes and require exact equality for later orders.
    // Comparing cached digests alone would not establish that the emitted sections are equal.
    let mut common_section: Option<Vec<Felt>> = None;
    let mut leaf_buffer = miden_ace_codegen::ShuffleEncodeBuffer::new();
    for order in ProofOrder::variants() {
        let circuit = factory
            .circuit_for_order(&order)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;

        // Recompute the registry leaf through the registry-builder API and require it to agree
        // with the assembled circuit before deriving the root.
        let registry_leaf = factory
            .leaf_for_order(&order, &mut leaf_buffer)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        if registry_leaf != circuit.commitment {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "encode-only registry leaf diverges from the assembled circuit for {}",
                    order.file_stem()
                ),
            ));
        }

        let common = &circuit.instructions[circuit.shuffle_prefix_len..];
        match &common_section {
            None => {
                if Eidos::hash_elements(common) != circuit.common_commitment {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "ACE common-section digest does not match the emitted common section",
                    ));
                }
                common_section = Some(common.to_vec());
            },
            Some(reference) => {
                if common != reference.as_slice() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "ACE common section is not order-invariant: differs for {}",
                            order.file_stem()
                        ),
                    ));
                }
            },
        }

        order_artifacts.push(OrderArtifact {
            order,
            num_inputs: circuit.num_inputs,
            num_eval_gates: circuit.num_eval_gates,
            stream_len: circuit.stream_len,
            shuffle_prefix_len: circuit.shuffle_prefix_len,
            common_commitment: word_to_array(circuit.common_commitment),
            circuit_commitment: word_to_array(circuit.commitment),
        });
    }
    if order_artifacts.len() != PROOF_ORDER_COUNT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proof-order variant count does not match PROOF_ORDER_COUNT",
        ));
    }

    ensure_uniform_circuit_metadata(&order_artifacts)?;
    let registry = AceCircuitRegistry::from_order_artifacts(&order_artifacts)?;
    let registry_root = registry.root;
    let relation_digest = compute_relation_digest(&registry_root);
    let preprocessed_commitment = compute_eidos_preprocessed_commitment()?;
    let constraints_eval = render_constraints_eval_file(&order_artifacts, quotient_inputs)?;
    let vm_geometry = VmGeometry::from_input_layout(factory.input_layout())?;
    let vm_layout = render_vm_layout(&vm_geometry)?;
    let vm_ood_frames = render_vm_ood_frames(&vm_geometry);
    let vm_deep_queries = render_vm_deep_queries(&vm_geometry)?;

    let mut relation_mod = read_file(RELATION_DIGEST_PATH)?;
    for (i, elem) in relation_digest.iter().enumerate() {
        replace_masm_const(
            &mut relation_mod,
            &format!("RELATION_DIGEST_{i}"),
            &elem.as_canonical_u64().to_string(),
        )?;
    }
    for (i, elem) in registry_root.iter().enumerate() {
        replace_masm_const(
            &mut relation_mod,
            &format!("ACE_REGISTRY_ROOT_{i}"),
            &elem.as_canonical_u64().to_string(),
        )?;
    }
    for (i, elem) in preprocessed_commitment.iter().enumerate() {
        replace_masm_const(
            &mut relation_mod,
            &format!("AND8_PREPROCESSED_TRACE_COM_{i}"),
            &elem.as_canonical_u64().to_string(),
        )?;
    }
    let mut air_config = read_file(AIR_CONFIG_PATH)?;
    replace_felt_array_const(&mut air_config, "RELATION_DIGEST", &relation_digest)?;
    replace_felt_array_const(&mut air_config, "ACE_CIRCUIT_REGISTRY_ROOT", &registry_root)?;

    let mut verifier_lib = read_file(VERIFIER_LIB_PATH)?;
    replace_u64_array_const(
        &mut verifier_lib,
        "EIDOS_PREPROCESSED_COMMITMENT",
        &preprocessed_commitment,
    )?;

    let first = order_artifacts.first().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "at least one ACE circuit is required")
    })?;
    ensure_vm_ace_stream_fits(first.stream_len, &vm_layout)?;

    Ok(ComputedArtifacts {
        num_inputs: first.num_inputs,
        num_eval_gates: first.num_eval_gates,
        prefix_rows: first.shuffle_prefix_len / 8,
        common_rows: (first.stream_len - first.shuffle_prefix_len) / 8,
        registry_root,
        relation_digest,
        preprocessed_commitment,
        constraints_eval,
        relation_mod,
        air_config,
        verifier_lib,
        vm_layout,
        vm_ood_frames,
        vm_deep_queries,
    })
}

fn compute_eidos_preprocessed_commitment() -> io::Result<[Felt; 4]> {
    let config = miden_air::config::eidos_config(
        miden_air::config::pcs_params(),
        miden_air::config::RELATION_DIGEST,
    );
    let statement = Statement::<Felt, QuadFelt, MidenMultiAir>::new(
        MidenMultiAir::new(),
        vec![Felt::ZERO; NUM_PUBLIC_VALUES],
        vec![],
    )
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    let preprocessed = Preprocessed::build(&statement, &config).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "canonical verifier statement has no preprocessed trace",
        )
    })?;
    let commitment: [u64; 4] = preprocessed.commitment().into();

    Ok(commitment.map(Felt::new_unchecked))
}

fn ensure_vm_ace_stream_fits(stream_len: usize, vm_layout: &str) -> io::Result<()> {
    let pvm_layout = read_file(PVM_LAYOUT_PATH)?;
    let stream_start =
        parse_masm_const::<usize>(vm_layout, "ACE_CIRCUIT_STREAM_PTR", VM_LAYOUT_PATH)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    let pvm_start = parse_masm_const::<usize>(&pvm_layout, "PUBLIC_INPUTS_PTR", PVM_LAYOUT_PATH)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

    check_vm_ace_stream_capacity(stream_start, pvm_start, stream_len)
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

struct VmGeometry {
    preprocessed_width: usize,
    main_widths: Vec<usize>,
    main_width: usize,
    aux_widths: Vec<usize>,
    aux_width: usize,
    quotient_width: usize,
    row_width: usize,
    ood_row_felts: usize,
    ood_frame_felts: usize,
    main_pipe_blocks: usize,
    aux_pipe_blocks: usize,
    ood_pipe_blocks: usize,
    ood_evaluations_ptr: usize,
    aux_bus_boundary_ptr: usize,
    auxiliary_ace_inputs_ptr: usize,
    ace_circuit_stream_ptr: usize,
    current_trace_row_ptr: usize,
}

impl VmGeometry {
    fn from_input_layout(input_layout: &InputLayout) -> io::Result<Self> {
        let preprocessed_width: usize = AIRS
            .iter()
            .map(|air| BaseAir::<Felt>::preprocessed_width(air).next_multiple_of(LMCS_ALIGNMENT))
            .sum();
        let main_widths: Vec<_> = AIRS
            .iter()
            .map(|air| BaseAir::<Felt>::width(air).next_multiple_of(LMCS_ALIGNMENT))
            .collect();
        let main_width: usize = main_widths.iter().sum();
        let aux_widths: Vec<_> = AIRS
            .iter()
            .map(|air| {
                (LiftedAir::<Felt, QuadFelt>::aux_width(air) * EXT_DEGREE)
                    .next_multiple_of(LMCS_ALIGNMENT)
            })
            .collect();
        let aux_width: usize = aux_widths.iter().sum();
        let quotient_width = input_layout.counts.num_quotient_chunks * EXT_DEGREE;
        let row_width = preprocessed_width + main_width + aux_width + quotient_width;

        for (name, derived, actual) in [
            ("preprocessed", preprocessed_width, input_layout.counts.preprocessed_width),
            ("main", main_width, input_layout.counts.width),
            ("auxiliary-coordinate", aux_width, input_layout.counts.aux_width * EXT_DEGREE),
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

        for (name, width) in
            [("main", main_width), ("auxiliary", aux_width), ("ACE row", row_width)]
        {
            if !width.is_multiple_of(LMCS_ALIGNMENT) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("VM {name} width {width} is not {LMCS_ALIGNMENT}-felt aligned"),
                ));
            }
        }

        let layout = read_file(VM_LAYOUT_PATH)?;
        let aux_rand_elem_ptr =
            parse_masm_const::<usize>(&layout, "AUX_RAND_ELEM_PTR", VM_LAYOUT_PATH)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let current_trace_row_ptr =
            parse_masm_const::<usize>(&layout, "CURRENT_TRACE_ROW_PTR", VM_LAYOUT_PATH)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

        let aux_rand_index = require_input_index(input_layout, InputKey::AuxRandBeta)?;
        let ood_index =
            require_input_index(input_layout, InputKey::Preprocessed { offset: 0, index: 0 })?;
        let next_ood_index =
            require_input_index(input_layout, InputKey::Preprocessed { offset: 1, index: 0 })?;
        let aux_bus_boundary_index =
            require_input_index(input_layout, InputKey::AuxBusBoundary(0))?;
        let auxiliary_ace_inputs_index = require_input_index(input_layout, InputKey::Alpha)?;

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
            preprocessed_width,
            main_widths,
            main_width,
            aux_widths,
            aux_width,
            quotient_width,
            row_width,
            ood_row_felts,
            ood_frame_felts,
            main_pipe_blocks: main_width / LMCS_ALIGNMENT,
            aux_pipe_blocks: aux_width / LMCS_ALIGNMENT,
            ood_pipe_blocks: ood_row_felts / LMCS_ALIGNMENT,
            ood_evaluations_ptr,
            aux_bus_boundary_ptr,
            auxiliary_ace_inputs_ptr,
            ace_circuit_stream_ptr,
            current_trace_row_ptr,
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
    let mut layout = read_file(VM_LAYOUT_PATH)?;
    for (name, value) in [
        ("OOD_EVALUATIONS_PTR", geometry.ood_evaluations_ptr),
        ("AUX_BUS_BOUNDARY_PTR", geometry.aux_bus_boundary_ptr),
        ("AUXILIARY_ACE_INPUTS_PTR", geometry.auxiliary_ace_inputs_ptr),
        ("ACE_CIRCUIT_STREAM_PTR", geometry.ace_circuit_stream_ptr),
        ("CURRENT_TRACE_ROW_PTR", geometry.current_trace_row_ptr),
    ] {
        replace_masm_const(&mut layout, name, &value.to_string())?;
    }

    replace_line_with_prefix(
        &mut layout,
        "##   OOD_EVALUATIONS_PTR -->",
        &format!(
            "##   OOD_EVALUATIONS_PTR --> [ OOD evaluations          ]  {} felts",
            geometry.ood_frame_felts
        ),
    )?;
    replace_comment_before_const(
        &mut layout,
        "OOD_EVALUATIONS_PTR",
        &format!(
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
        ),
    )?;
    replace_comment_before_const(
        &mut layout,
        "CURRENT_TRACE_ROW_PTR",
        &format!(
            "### Scratch row for DEEP query openings: {} preprocessed, {} main, {}\n\
             ### auxiliary-coordinate, and {} quotient felts ({} total).",
            geometry.preprocessed_width,
            geometry.main_width,
            geometry.aux_width,
            geometry.quotient_width,
            geometry.row_width,
        ),
    )?;
    Ok(layout)
}

fn render_vm_ood_frames(geometry: &VmGeometry) -> String {
    format!(
        r#"#! Processes the out-of-domain (OOD) evaluations of all committed polynomials.
#!
#! Loads one OOD row from advice, absorbs it into the Eidos transcript, and updates the
#! Horner accumulator used by the DEEP fixed terms.
#!
#! Inputs:  [scratch0, scratch1, cv, ptr, alpha_ptr, acc0, acc1]
#! Outputs: [scratch0, scratch1, cv', ptr, alpha_ptr, acc0', acc1']
pub proc process_row_ood_evaluations
    # Per-row OOD layout uses LMCS alignment {LMCS_ALIGNMENT}:
    #   preprocessed: {preprocessed} scalar evaluations
    #   main:         {main_parts} = {main} scalar evaluations
    #   aux:          {aux_parts} = {aux} scalar evaluations
    #   quotient:     {quotient} scalar evaluations
    # The advice stream supplies {ood_felts} base felts, read as {pipe_blocks} `adv_pipe` blocks.
    repeat.{pipe_blocks}
        adv_pipe
        horner_eval_ext
        compress
    end
end
"#,
        preprocessed = geometry.preprocessed_width,
        main_parts = format_sum(&geometry.main_widths),
        main = geometry.main_width,
        aux_parts = format_sum(&geometry.aux_widths),
        aux = geometry.aux_width,
        quotient = geometry.quotient_width,
        ood_felts = geometry.ood_row_felts,
        pipe_blocks = geometry.ood_pipe_blocks,
    )
}

fn render_vm_deep_queries(geometry: &VmGeometry) -> io::Result<String> {
    let mut deep_queries = read_file(VM_DEEP_QUERIES_PATH)?;
    replace_line_with_prefix(
        &mut deep_queries,
        "# Load the aligned main leaf:",
        &format!(
            "    # Load the aligned main leaf: {} = {} base felts.",
            format_sum(&geometry.main_widths),
            geometry.main_width,
        ),
    )?;
    replace_repeat_in_proc(
        &mut deep_queries,
        "load_main_segment_execution_trace",
        geometry.main_pipe_blocks,
    )?;
    replace_line_with_prefix(
        &mut deep_queries,
        "# Load the aligned aux leaf:",
        &format!(
            "    # Load the aligned aux leaf: {} = {} base felts.",
            format_sum(&geometry.aux_widths),
            geometry.aux_width,
        ),
    )?;
    replace_repeat_in_proc(
        &mut deep_queries,
        "load_aux_segment_execution_trace",
        geometry.aux_pipe_blocks,
    )?;
    Ok(deep_queries)
}

fn format_sum(parts: &[usize]) -> String {
    parts.iter().map(usize::to_string).collect::<Vec<_>>().join(" + ")
}

fn replace_line_with_prefix(
    content: &mut String,
    prefix: &str,
    replacement: &str,
) -> io::Result<()> {
    let start = content
        .lines()
        .scan(0usize, |offset, line| {
            let start = *offset;
            *offset += line.len() + 1;
            Some((start, line))
        })
        .find_map(|(start, line)| line.trim_start().starts_with(prefix).then_some(start))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{prefix} not found")))?;
    let end = content[start..].find('\n').map(|idx| start + idx).unwrap_or(content.len());
    content.replace_range(start..end, replacement);
    Ok(())
}

fn replace_comment_before_const(
    content: &mut String,
    name: &str,
    replacement: &str,
) -> io::Result<()> {
    let const_marker = format!("const {name} = ");
    let const_start = content.find(&const_marker).ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, format!("{const_marker} not found"))
    })?;
    let mut block_start = const_start;
    while block_start > 0 {
        let previous_end = block_start.saturating_sub(1);
        let previous_start = content[..previous_end].rfind('\n').map(|idx| idx + 1).unwrap_or(0);
        if !content[previous_start..previous_end].trim_start().starts_with("###") {
            break;
        }
        block_start = previous_start;
    }
    if block_start == const_start {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("comment before {name} not found"),
        ));
    }
    content.replace_range(block_start..const_start, &format!("{replacement}\n"));
    Ok(())
}

fn replace_repeat_in_proc(content: &mut String, proc_name: &str, count: usize) -> io::Result<()> {
    let proc_marker = format!("proc {proc_name}");
    let proc_start = content.find(&proc_marker).ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, format!("{proc_marker} not found"))
    })?;
    let proc_end = content[proc_start..]
        .find("\nend")
        .map(|idx| proc_start + idx)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("end of {proc_name}")))?;
    let repeat_start = content[proc_start..proc_end]
        .find("repeat.")
        .map(|idx| proc_start + idx)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("repeat in {proc_name}")))?;
    let repeat_end = content[repeat_start..proc_end]
        .find('\n')
        .map(|idx| repeat_start + idx)
        .unwrap_or(proc_end);
    content.replace_range(repeat_start..repeat_end, &format!("repeat.{count}"));
    Ok(())
}

fn write_artifacts(artifact: &ComputedArtifacts) -> io::Result<()> {
    write_file(CONSTRAINTS_EVAL_PATH, &artifact.constraints_eval)?;
    write_file(RELATION_DIGEST_PATH, &artifact.relation_mod)?;
    write_file(AIR_CONFIG_PATH, &artifact.air_config)?;
    write_file(VERIFIER_LIB_PATH, &artifact.verifier_lib)?;
    write_file(VM_LAYOUT_PATH, &artifact.vm_layout)?;
    write_file(VM_OOD_FRAMES_PATH, &artifact.vm_ood_frames)?;
    write_file(VM_DEEP_QUERIES_PATH, &artifact.vm_deep_queries)?;
    println!(
        "wrote asm/sys/vm/constraints_eval.masm ({} inputs, {} eval gates, repeat.{}+{})",
        artifact.num_inputs, artifact.num_eval_gates, artifact.prefix_rows, artifact.common_rows
    );
    println!(
        "wrote asm/sys/vm/mod.masm (relation digest, ACE registry root, and preprocessed commitment)"
    );
    println!("wrote air/src/config.rs (relation digest and ACE registry)");
    println!("wrote verifier/src/lib.rs (preprocessed commitment)");
    println!("wrote VM recursive-verifier layout, OOD-frame, and DEEP-query geometry");
    println!("done - run `cargo test -p miden-air --lib` to update the insta snapshot");
    Ok(())
}

fn ensure_uniform_circuit_metadata(order_artifacts: &[OrderArtifact]) -> io::Result<()> {
    let Some(first) = order_artifacts.first() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "at least one ACE circuit is required",
        ));
    };

    for artifact in &order_artifacts[1..] {
        if artifact.num_inputs != first.num_inputs
            || artifact.num_eval_gates != first.num_eval_gates
            || artifact.stream_len != first.stream_len
            || artifact.shuffle_prefix_len != first.shuffle_prefix_len
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("ACE circuit metadata differs for {}", artifact.order.file_stem()),
            ));
        }
        if artifact.common_commitment != first.common_commitment {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("ACE common-section digest differs for {}", artifact.order.file_stem()),
            ));
        }
    }

    Ok(())
}

fn word_from_array(elements: [Felt; 4]) -> Word {
    Word::new(elements)
}

fn word_to_array(word: Word) -> [Felt; 4] {
    [word[0], word[1], word[2], word[3]]
}

struct AceCircuitRegistry {
    root: [Felt; 4],
    #[cfg_attr(not(test), allow(dead_code))]
    leaves: Vec<Word>,
}

impl AceCircuitRegistry {
    fn from_order_artifacts(order_artifacts: &[OrderArtifact]) -> io::Result<Self> {
        let active_leaf_count = PROOF_ORDER_COUNT;
        if active_leaf_count > ACE_REGISTRY_LEAF_COUNT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ACE circuit registry is too small for the supported proof orders",
            ));
        }

        let mut leaves = alloc::vec![native_padding_leaf(); ACE_REGISTRY_LEAF_COUNT];
        let mut seen = vec![false; active_leaf_count];

        for artifact in order_artifacts {
            let tag = artifact.order.tag() as usize;
            if tag >= active_leaf_count {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("proof-order tag {tag} is outside the active registry range"),
                ));
            }
            if seen[tag] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("duplicate proof-order tag {tag}"),
                ));
            }

            seen[tag] = true;
            leaves[tag] = word_from_array(artifact.circuit_commitment);
        }

        if let Some(missing_tag) = seen.iter().position(|&is_seen| !is_seen) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("missing ACE circuit commitment for proof-order tag {missing_tag}"),
            ));
        }

        let tree = MerkleTree::new(&leaves).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to build ACE circuit registry: {err}"),
            )
        })?;

        Ok(Self { root: word_to_array(tree.root()), leaves })
    }
}

fn render_constraints_eval_file(
    order_artifacts: &[OrderArtifact],
    quotient_inputs: QuotientRecompositionInputs<Felt>,
) -> io::Result<String> {
    let Some(first) = order_artifacts.first() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "at least one ACE circuit is required",
        ));
    };
    let max_cycle_len_log = max_periodic_cycle_len_log();
    let h_common = first.common_commitment;

    miden_ace_codegen::render_masm_constraints_eval(&miden_ace_codegen::MasmConstraintsEvalConfig {
        generated_by: "cargo run -p miden-core-lib --features constraints-tools --bin \
                           regenerate-constraints -- --write",
        layout_module: "miden::core::sys::vm::layout",
        num_inputs: first.num_inputs,
        num_eval_gates: first.num_eval_gates,
        stream_len: first.stream_len,
        shuffle_prefix_len: first.shuffle_prefix_len,
        max_cycle_len_log,
        registry_depth: ACE_CIRCUIT_REGISTRY_DEPTH,
        order_tag_count: PROOF_ORDER_COUNT,
        num_airs: MIDEN_AIR_COUNT,
        quotient_inputs,
        common_commitment: Word::new(h_common),
    })
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
}

fn max_periodic_cycle_len_log() -> u32 {
    let max_len = AIRS
        .iter()
        .flat_map(<MidenAir as BaseAir<Felt>>::periodic_columns)
        .map(|column| column.len())
        .max()
        .unwrap_or(1);

    assert!(
        max_len.is_power_of_two(),
        "maximum AIR periodic cycle length must be a power of two"
    );
    max_len.ilog2()
}

/// Verify that the ACE circuit constants in `constraints_eval.masm` match the current AIR.
pub fn constraints_eval_masm_matches_air() -> Result<(), String> {
    let artifact = compute_artifacts().map_err(|e| e.to_string())?;
    constraints_eval_masm_matches_artifact(&artifact)
}

fn constraints_eval_masm_matches_artifact(artifact: &ComputedArtifacts) -> Result<(), String> {
    let masm = read_file(CONSTRAINTS_EVAL_PATH).map_err(|e| e.to_string())?;
    if masm != artifact.constraints_eval {
        return Err(format!("{CONSTRAINTS_EVAL_PATH} is stale"));
    }
    Ok(())
}

/// Verify that RELATION_DIGEST in `air/src/config.rs` and `sys/vm/mod.masm` matches current AIR.
pub fn relation_digest_matches_air() -> Result<(), String> {
    let artifact = compute_artifacts().map_err(|e| e.to_string())?;
    relation_digest_matches_artifact(&artifact)
}

fn relation_digest_matches_artifact(artifact: &ComputedArtifacts) -> Result<(), String> {
    let expected = artifact.relation_digest;

    if miden_air::config::RELATION_DIGEST != expected {
        return Err("RELATION_DIGEST in air/src/config.rs is stale".into());
    }
    if miden_air::config::ACE_CIRCUIT_REGISTRY_ROOT != artifact.registry_root {
        return Err(
            "ACE_CIRCUIT_REGISTRY_ROOT in air/src/config.rs is stale (the root binds every \
             registry leaf; leaves are recomputed at runtime and are not checked in)"
                .into(),
        );
    }

    let masm = read_file(RELATION_DIGEST_PATH).map_err(|e| e.to_string())?;
    let mut masm_digest: [Felt; 4] = [Felt::ZERO; 4];
    for (i, slot) in masm_digest.iter_mut().enumerate() {
        let name = format!("RELATION_DIGEST_{i}");
        *slot =
            parse_masm_const::<u64>(&masm, &name, "sys/vm/mod.masm").map(Felt::new_unchecked)?;
    }

    if masm_digest != expected {
        return Err("RELATION_DIGEST in sys/vm/mod.masm is stale".into());
    }

    let mut masm_registry_root: [Felt; 4] = [Felt::ZERO; 4];
    for (i, slot) in masm_registry_root.iter_mut().enumerate() {
        let name = format!("ACE_REGISTRY_ROOT_{i}");
        *slot =
            parse_masm_const::<u64>(&masm, &name, "sys/vm/mod.masm").map(Felt::new_unchecked)?;
    }

    if masm_registry_root != artifact.registry_root {
        return Err("ACE registry root in sys/vm/mod.masm is stale".into());
    }

    let mut masm_preprocessed_commitment = [Felt::ZERO; 4];
    for (i, slot) in masm_preprocessed_commitment.iter_mut().enumerate() {
        let name = format!("AND8_PREPROCESSED_TRACE_COM_{i}");
        *slot =
            parse_masm_const::<u64>(&masm, &name, "sys/vm/mod.masm").map(Felt::new_unchecked)?;
    }
    if masm_preprocessed_commitment != artifact.preprocessed_commitment {
        return Err("And8 preprocessed commitment in sys/vm/mod.masm is stale".into());
    }

    let verifier_lib = read_file(VERIFIER_LIB_PATH).map_err(|e| e.to_string())?;
    if verifier_lib != artifact.verifier_lib {
        return Err("EIDOS_PREPROCESSED_COMMITMENT in verifier/src/lib.rs is stale".into());
    }

    // `derive_order_tag` sweeps this many AIRs and weights each inversion by
    // `(NUM_MIDEN_AIRS - 1 - pos)!`, so a stale value silently mis-ranks proof orders.
    let num_miden_airs = parse_masm_const::<usize>(&masm, "NUM_MIDEN_AIRS", "sys/vm/mod.masm")?;
    if num_miden_airs != MIDEN_AIR_COUNT {
        return Err("NUM_MIDEN_AIRS in sys/vm/mod.masm is stale".into());
    }

    // The VM aux hook dispatches the three weighted boundary sums by proof-order tag. Keep its
    // active-tag bound tied to the same AIR-derived order count as the generated evaluator.
    let aux_trace = read_file(VM_AUX_TRACE_PATH).map_err(|e| e.to_string())?;
    let order_tag_count =
        parse_masm_const::<usize>(&aux_trace, "ORDER_TAG_COUNT", VM_AUX_TRACE_PATH)?;
    if order_tag_count != PROOF_ORDER_COUNT {
        return Err("ORDER_TAG_COUNT in sys/vm/aux_trace.masm is stale".into());
    }

    Ok(())
}

/// Verify that Miden VM public-input constants match the current AIR set.
pub fn public_inputs_masm_matches_air() -> Result<(), String> {
    let public_inputs = read_file(VM_PUBLIC_INPUTS_PATH).map_err(|e| e.to_string())?;
    let num_miden_airs =
        parse_masm_const::<usize>(&public_inputs, "NUM_MIDEN_AIRS", VM_PUBLIC_INPUTS_PATH)?;
    if num_miden_airs != MIDEN_AIR_COUNT {
        return Err("NUM_MIDEN_AIRS in sys/vm/public_inputs.masm is stale".into());
    }

    Ok(())
}

/// Verify that recursive-verifier memory, OOD, and DEEP-query geometry matches the AIR widths.
pub fn vm_geometry_matches_air() -> Result<(), String> {
    let artifact = compute_artifacts().map_err(|e| e.to_string())?;
    vm_geometry_matches_artifact(&artifact)
}

fn vm_geometry_matches_artifact(artifact: &ComputedArtifacts) -> Result<(), String> {
    for (path, expected) in [
        (VM_LAYOUT_PATH, artifact.vm_layout.as_str()),
        (VM_OOD_FRAMES_PATH, artifact.vm_ood_frames.as_str()),
        (VM_DEEP_QUERIES_PATH, artifact.vm_deep_queries.as_str()),
    ] {
        let actual = read_file(path).map_err(|e| e.to_string())?;
        if actual != expected {
            return Err(format!("{path} has stale AIR-width geometry"));
        }
    }

    Ok(())
}

/// Checks the common estimator constants and the MVM descriptor against the shared PCS and current
/// AIRs.
///
/// The parity tests compare final native and MASM levels. This check covers the constants and
/// bounds independently, including values from rounds that do not determine the final level for
/// the current MVM configuration.
pub fn security_masm_matches_air() -> Result<(), String> {
    let estimator = read_file(SECURITY_ESTIMATOR_PATH).map_err(|e| e.to_string())?;
    // These literals define the shared fixed-point format and the PCS values used to bound the
    // terms omitted by the MASM estimator. The remaining limits are checked below against the MVM
    // relation and the generic verifier.
    let fractional_bits = miden_air::security::FIXED_POINT_FRACTIONAL_BITS;
    let fixed_point_one = miden_air::security::FIXED_POINT_ONE;
    let field_bits = miden_air::security::CHALLENGE_FIELD_BITS;
    let field_ceiling = field_bits.div_ceil(fixed_point_one) * fixed_point_one;
    let shared_literals: [(&str, u64); 10] = [
        ("FP_SHIFT", u64::from(fractional_bits)),
        ("FP_ONE", fixed_point_one),
        ("MAX_Q16_FRACTION", fixed_point_one - 1),
        ("BITS_PER_QUERY_FP", miden_air::security::BITS_PER_QUERY),
        ("CHALLENGE_FIELD_WHOLE_BITS", field_bits >> fractional_bits),
        ("CHALLENGE_FIELD_OFFSET_FP", field_ceiling - field_bits),
        ("SECURITY_CAP_BITS", miden_air::security::SECURITY_CAP >> fractional_bits),
        ("FRI_FOLDING_BASE_BITS", miden_air::security::FOLDING_BASE >> fractional_bits),
        ("LOG2_E_FP", miden_air::security::LOG2_E),
        (
            "MAX_CONSTRAINT_DEGREE",
            (1u64 << miden_air::config::pcs_params().log_blowup()) + 1,
        ),
    ];

    for (name, expected) in shared_literals {
        let actual = parse_masm_const::<u64>(&estimator, name, SECURITY_ESTIMATOR_PATH)?;
        if actual != expected {
            return Err(format!("{name} in {SECURITY_ESTIMATOR_PATH} is stale"));
        }
    }

    // The estimator omits five native security terms only while the MVM shape and the generic
    // verifier's parameter ranges satisfy its documented bounds. `air_shape_matches_symbolic`
    // checks the stored shape against the AIRs; the checks below fail if that shape leaves the
    // estimator envelope. This function also pins the generic verifier bounds directly.
    let wrapper = read_file(RELATION_DIGEST_PATH).map_err(|e| e.to_string())?;
    let utils = read_file(GENERIC_UTILS_PATH).map_err(|e| e.to_string())?;
    let air_shape = miden_air::security::AIR_SHAPE;
    let parsed = |name: &str| parse_masm_const::<u64>(&estimator, name, SECURITY_ESTIMATOR_PATH);
    let lookup_coefficient = (u64::from(air_shape.lookup.max_message_width) + 2)
        * u64::from(air_shape.lookup.fractions_per_row);
    let max_boundary_terms = u64::from(miden_air::security::CORE_BOUNDARY_LOOKUP_TERMS)
        + KernelDescriptor::MAX_NUM_PROCEDURES as u64;
    if u64::from(air_shape.num_composed_constraints) > parsed("MAX_COMPOSED_CONSTRAINTS")? {
        return Err("the MVM composed-constraint count exceeds the estimator envelope".into());
    }
    if u64::from(air_shape.max_constraint_degree) > parsed("MAX_CONSTRAINT_DEGREE")? {
        return Err("the MVM constraint degree exceeds the estimator envelope".into());
    }
    if u64::from(air_shape.num_deep_terms.expect("the MVM uses DEEP composition"))
        > parsed("MAX_DEEP_TERMS")?
    {
        return Err("the MVM DEEP term count exceeds the estimator envelope".into());
    }
    if lookup_coefficient < parsed("MIN_LOOKUP_COEFFICIENT")? {
        return Err("the MVM lookup coefficient falls below the estimator envelope".into());
    }
    if lookup_coefficient > parsed("MAX_LOOKUP_COEFFICIENT")? {
        return Err("the MVM lookup coefficient exceeds the estimator envelope".into());
    }
    if max_boundary_terms > parsed("MAX_BOUNDARY_TERMS")? {
        return Err("the MVM boundary-term maximum exceeds the estimator envelope".into());
    }
    if parsed("MIN_LOG_HEIGHT")?
        != parse_masm_const::<u64>(&wrapper, "LOG_HEIGHT_MIN", RELATION_DIGEST_PATH)?
    {
        return Err(format!("MIN_LOG_HEIGHT in {SECURITY_ESTIMATOR_PATH} is stale"));
    }
    let estimator_heights = parsed("MAX_LOG_HEIGHT")?;
    if parsed("MAX_NUM_QUERIES")?
        != parse_masm_const::<u64>(&utils, "NUM_QUERIES_MAX", GENERIC_UTILS_PATH)?
    {
        return Err(format!("MAX_NUM_QUERIES in {SECURITY_ESTIMATOR_PATH} is stale"));
    }
    if parsed("MAX_POW_BITS")?
        != parse_masm_const::<u64>(&utils, "POW_BITS_MAX", GENERIC_UTILS_PATH)?
    {
        return Err(format!("MAX_POW_BITS in {SECURITY_ESTIMATOR_PATH} is stale"));
    }

    let descriptor_literals: [(&str, u64); 9] = [
        ("LOOKUP_POW_BITS", miden_air::security::LOOKUP_POW_BITS as u64),
        (
            "MAX_MESSAGE_WIDTH",
            miden_air::security::AIR_SHAPE.lookup.max_message_width as u64,
        ),
        (
            "NUM_COMPOSED_CONSTRAINTS",
            miden_air::security::AIR_SHAPE.num_composed_constraints as u64,
        ),
        (
            "MAX_CONSTRAINT_DEGREE",
            miden_air::security::AIR_SHAPE.max_constraint_degree as u64,
        ),
        (
            "NUM_DEEP_TERMS",
            miden_air::security::AIR_SHAPE
                .num_deep_terms
                .expect("the MVM uses DEEP composition") as u64,
        ),
        (
            "CORE_BOUNDARY_LOOKUP_TERMS",
            miden_air::security::CORE_BOUNDARY_LOOKUP_TERMS as u64,
        ),
        (
            "LOOKUP_FRACTIONS_PER_ROW",
            miden_air::security::AIR_SHAPE.lookup.fractions_per_row as u64,
        ),
        ("MAX_NUM_KERNEL_PROCEDURES", KernelDescriptor::MAX_NUM_PROCEDURES as u64),
        ("LOG_HEIGHT_MAX", estimator_heights),
    ];

    for (name, expected) in descriptor_literals {
        let actual = parse_masm_const::<u64>(&wrapper, name, RELATION_DIGEST_PATH)?;
        if actual != expected {
            return Err(format!("{name} in {RELATION_DIGEST_PATH} is stale"));
        }
    }

    Ok(())
}

fn parse_masm_const<T: core::str::FromStr>(
    masm: &str,
    name: &str,
    file_label: &str,
) -> Result<T, String>
where
    T::Err: core::fmt::Debug,
{
    let prefix = format!("const {name} = ");
    masm.lines()
        .find_map(|line| {
            let value = line.trim().strip_prefix(&prefix)?;
            let value = value.split('#').next().unwrap_or(value).trim();
            value.parse::<T>().ok()
        })
        .ok_or_else(|| format!("constant {name} not found in {file_label}"))
}

fn replace_masm_const(content: &mut String, name: &str, new_value: &str) -> io::Result<()> {
    let prefix = format!("const {name} = ");
    let line_start = content
        .find(&prefix)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{name} not found")))?;
    let line_end = content[line_start..]
        .find('\n')
        .map(|i| line_start + i)
        .unwrap_or(content.len());
    let line = &content[line_start..line_end];
    let suffix = line.find('#').map_or("", |comment_start| {
        let whitespace_start = line[..comment_start].trim_end().len();
        &line[whitespace_start..]
    });
    content.replace_range(line_start..line_end, &format!("{prefix}{new_value}{suffix}"));
    Ok(())
}

fn replace_felt_array_const(
    content: &mut String,
    name: &str,
    values: &[Felt; 4],
) -> io::Result<()> {
    let marker = format!("pub const {name}:");
    let start = content
        .find(&marker)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{name} not found")))?;
    let init_marker = " = [";
    let init_start =
        content[start..].find(init_marker).map(|idx| start + idx).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("{name} initializer not found"))
        })?;
    let block_start = init_start + init_marker.len();
    let block_end =
        content[block_start..].find("];").map(|idx| idx + block_start).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("{name} terminator not found"))
        })?;
    let mut new_block: String = values
        .iter()
        .map(|f| format!("\n    Felt::new_unchecked({}),", f.as_canonical_u64()))
        .collect();
    new_block.push('\n');
    content.replace_range(block_start..block_end, &new_block);
    Ok(())
}

fn replace_u64_array_const(content: &mut String, name: &str, values: &[Felt; 4]) -> io::Result<()> {
    let marker = format!("const {name}:");
    let start = content
        .find(&marker)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{name} not found")))?;
    let init_marker = " = [";
    let init_start =
        content[start..].find(init_marker).map(|idx| start + idx).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("{name} initializer not found"))
        })?;
    let block_start = init_start + init_marker.len();
    let block_end =
        content[block_start..].find("];").map(|idx| idx + block_start).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("{name} terminator not found"))
        })?;
    let mut new_block: String = values
        .iter()
        .map(|value| format!("\n    {},", value.as_canonical_u64()))
        .collect();
    new_block.push('\n');
    content.replace_range(block_start..block_end, &new_block);
    Ok(())
}

fn read_file(rel_path: &str) -> io::Result<String> {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel_path);
    fs::read_to_string(&path)
        .map_err(|e| io::Error::new(e.kind(), format!("failed to read {path}: {e}")))
}

fn write_file(rel_path: &str, contents: &str) -> io::Result<()> {
    let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel_path);
    fs::write(&path, contents)
        .map_err(|e| io::Error::new(e.kind(), format!("failed to write {path}: {e}")))
}

struct ComputedArtifacts {
    num_inputs: usize,
    num_eval_gates: usize,
    prefix_rows: usize,
    common_rows: usize,
    registry_root: [Felt; 4],
    relation_digest: [Felt; 4],
    preprocessed_commitment: [Felt; 4],
    constraints_eval: String,
    relation_mod: String,
    air_config: String,
    verifier_lib: String,
    vm_layout: String,
    vm_ood_frames: String,
    vm_deep_queries: String,
}

struct OrderArtifact {
    order: ProofOrder,
    num_inputs: usize,
    num_eval_gates: usize,
    stream_len: usize,
    shuffle_prefix_len: usize,
    common_commitment: [Felt; 4],
    circuit_commitment: [Felt; 4],
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn ace_registry_places_commitments_by_order_tag() {
        let artifacts = dummy_artifacts();
        let registry = AceCircuitRegistry::from_order_artifacts(&artifacts).unwrap();

        for artifact in artifacts {
            assert_eq!(
                registry.leaves[artifact.order.tag() as usize],
                word_from_array(artifact.circuit_commitment)
            );
        }
    }

    #[test]
    fn ace_registry_uses_padding_leaves_outside_supported_orders() {
        let registry = AceCircuitRegistry::from_order_artifacts(&dummy_artifacts()).unwrap();

        for index in PROOF_ORDER_COUNT..ACE_REGISTRY_LEAF_COUNT {
            assert_eq!(registry.leaves[index], native_padding_leaf());
        }
    }

    #[test]
    fn ace_registry_rejects_missing_and_duplicate_tags() {
        let mut missing = dummy_artifacts();
        missing.pop();
        assert!(AceCircuitRegistry::from_order_artifacts(&missing).is_err());

        let mut duplicate = dummy_artifacts();
        duplicate[1].order = duplicate[0].order.clone();
        assert!(AceCircuitRegistry::from_order_artifacts(&duplicate).is_err());
    }

    fn dummy_artifacts() -> Vec<OrderArtifact> {
        ProofOrder::variants()
            .into_iter()
            .map(|order| {
                let tag = order.tag() as u64;
                OrderArtifact {
                    order,
                    num_inputs: 1,
                    num_eval_gates: 1,
                    stream_len: 16,
                    shuffle_prefix_len: 8,
                    common_commitment: [Felt::ZERO; 4],
                    circuit_commitment: [
                        Felt::new_unchecked(tag + 1),
                        Felt::new_unchecked(tag + 2),
                        Felt::new_unchecked(tag + 3),
                        Felt::new_unchecked(tag + 4),
                    ],
                }
            })
            .collect()
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
}
