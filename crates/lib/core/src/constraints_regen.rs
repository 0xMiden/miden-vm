use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use std::{fs, io, println};

use miden_ace_codegen::{EXT_DEGREE, InputKey, InputLayout};
use miden_air::{
    AIRS, MIDEN_AIR_COUNT, MidenAir, MidenMultiAir, NUM_PUBLIC_VALUES, Statement,
    ace::{build_recursive_verifier_ace_circuit, recursive_verifier_input_layout},
    config::relation_digest,
};
use miden_core::{Felt, Word, field::QuadFelt, program::KernelDescriptor};
use miden_crypto::stark::{
    Preprocessed, QuotientRecompositionInputs,
    air::{BaseAir, LiftedAir},
    quotient_recomposition_inputs,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Check,
    Write,
}

const PROTOCOL_ID: u64 = 1;
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

/// Felts moved by one `adv_pipe`. Numerically equal to [`LMCS_ALIGNMENT`] today, but a distinct
/// quantity: this bounds block/segment arithmetic and `adv_pipe` destination alignment, while
/// `LMCS_ALIGNMENT` bounds column-padding widths. If the two ever diverge, block arithmetic must
/// keep using this constant, not the padding width.
const ADV_PIPE_BLOCK_FELTS: usize = 8;

/// Computes the relation digest used by recursive verification.
pub fn compute_relation_digest(circuit_digest: &[Felt; 4]) -> [Felt; 4] {
    relation_digest(PROTOCOL_ID, &Word::new(*circuit_digest))
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
    // One circuit serves every proof order, so there is nothing to build per order and nothing
    // to cross-check between orders: the proof-order dependence lives in the MASM verifier's
    // ingest scatter and fold-coefficient staging instead.
    let circuit = build_recursive_verifier_ace_circuit()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    let input_layout = recursive_verifier_input_layout()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;

    let num_quotient_chunks = input_layout.counts.num_quotient_chunks;
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

    let circuit_digest = word_to_array(circuit.commitment);
    let relation_digest = compute_relation_digest(&circuit_digest);
    let constraints_eval = render_constraints_eval_file(&circuit, quotient_inputs)?;
    let vm_geometry = VmGeometry::from_input_layout(&input_layout)?;
    let vm_layout = render_vm_layout(&vm_geometry)?;
    let vm_ood_frames = render_vm_ood_frames(&vm_geometry)?;
    let vm_deep_queries = render_vm_deep_queries(&vm_geometry)?;

    let preprocessed_commitment = compute_eidos_preprocessed_commitment()?;

    let mut relation_mod = read_file(RELATION_DIGEST_PATH)?;
    for (i, elem) in relation_digest.iter().enumerate() {
        replace_masm_const(
            &mut relation_mod,
            &format!("RELATION_DIGEST_{i}"),
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
    replace_felt_array_const(&mut air_config, "ACE_CIRCUIT_DIGEST", &circuit_digest)?;

    let mut verifier_lib = read_file(VERIFIER_LIB_PATH)?;
    replace_u64_array_const(
        &mut verifier_lib,
        "EIDOS_PREPROCESSED_COMMITMENT",
        &preprocessed_commitment,
    )?;

    ensure_vm_ace_stream_fits(circuit.stream_len, &vm_layout)?;

    Ok(ComputedArtifacts {
        num_inputs: circuit.num_inputs,
        num_eval_gates: circuit.num_eval_gates,
        stream_blocks: circuit.stream_len / 8,
        circuit_digest,
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

/// Felts reserved for the out-of-domain scatter table by `sys/vm/layout.masm`.
const OOD_SCATTER_TABLE_FELTS: usize = 64;
/// Offset, in felts from the table base, of the first `(destination, digest address)` pair.
const OOD_SCATTER_SLOTS_OFFSET: usize = 4;

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
}

impl VmGeometry {
    fn from_input_layout(input_layout: &InputLayout) -> io::Result<Self> {
        let preprocessed_widths: Vec<_> = AIRS
            .iter()
            .map(|air| BaseAir::<Felt>::preprocessed_width(air).next_multiple_of(LMCS_ALIGNMENT))
            .collect();
        let preprocessed_width: usize = preprocessed_widths.iter().sum();
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

        let layout = read_file(VM_LAYOUT_PATH)?;
        let aux_rand_elem_ptr =
            parse_masm_const::<usize>(&layout, "AUX_RAND_ELEM_PTR", VM_LAYOUT_PATH)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let current_trace_row_ptr =
            parse_masm_const::<usize>(&layout, "CURRENT_TRACE_ROW_PTR", VM_LAYOUT_PATH)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
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
        let ood_scatter_table_ptr =
            parse_masm_const::<usize>(&layout, "OOD_SCATTER_TABLE_PTR", VM_LAYOUT_PATH)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
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

/// One per-AIR segment of one commitment group, together with how the hook reaches it.
struct ScatterDispatch {
    /// Commitment group this segment belongs to.
    group: &'static str,
    /// Canonical destination, in felts from the row base.
    dst: usize,
    /// Segment length in `adv_pipe` blocks.
    blocks: usize,
    /// Position of this segment within its commitment group on the wire.
    position: usize,
    /// Stream position in the runtime table, or `None` when the geometry fixes the segment's
    /// place on the wire regardless of the proof order.
    slot: Option<usize>,
}

/// Where AIR `air`'s segment of one commitment group must land, and which table slot names it.
struct ScatterSource {
    group: &'static str,
    air: usize,
    dst: usize,
    blocks: usize,
    slot_offset: usize,
}

/// Compile-time shape of the out-of-domain ingest scatter.
struct ScatterPlan {
    /// Stream-order dispatches for one row.
    dispatches: Vec<ScatterDispatch>,
    /// Per-AIR sources the order pass routes into the runtime table.
    sources: Vec<ScatterSource>,
    /// Distinct segment lengths, ascending; one `pipe_k` procedure each.
    lengths: Vec<usize>,
    /// Offset, in felts from the table base, of the first `pipe_k` digest word.
    digest_offset: usize,
}

impl ScatterPlan {
    /// Felt offset from the table base of the `pipe_k` digest covering `blocks`.
    fn digest_offset_for(&self, blocks: usize) -> usize {
        let index = self
            .lengths
            .iter()
            .position(|length| *length == blocks)
            .expect("every segment length has a pipe procedure");
        self.digest_offset + WORD_FELTS * index
    }
}

const WORD_FELTS: usize = 4;

/// Derives the scatter's compile-time shape from the AIR widths.
///
/// A commitment group holding at most one non-empty segment carries no proof-order freedom: its
/// occupant is always alone on the wire and always lands at the same canonical address, so it is
/// dispatched directly rather than through the table. The quotient matrix is relation-wide, not
/// per-AIR, and is likewise fixed.
fn vm_scatter_plan(geometry: &VmGeometry) -> io::Result<ScatterPlan> {
    let groups = [
        ("preprocessed", &geometry.preprocessed_widths),
        ("main", &geometry.main_widths),
        ("aux", &geometry.aux_widths),
    ];
    let mut dispatches = Vec::new();
    let mut sources = Vec::new();
    let mut group_base = 0usize;
    let mut slot = 0usize;

    for (group, widths) in groups {
        let occupied = widths.iter().filter(|width| **width > 0).count();
        // Slots of one group are contiguous and indexed by proof position, so every source in
        // the group shares this base and adds `2 * pos` at run time. `pos` ranks the AIR among
        // *all* AIRs, which indexes the group's slots only when every AIR occupies the group. A
        // partially occupied group would need the rank among occupants instead, which the proof
        // order does not directly give; refuse to emit rather than silently address past the
        // group's slots.
        if occupied > 1 && occupied != widths.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "the {group} commitment group is occupied by {occupied} of {} AIRs; the \
                     out-of-domain scatter indexes its table by proof-order position, which \
                     requires every AIR to occupy the group",
                    widths.len()
                ),
            ));
        }
        let group_slot_offset = OOD_SCATTER_SLOTS_OFFSET + 2 * slot;
        let mut canonical = group_base;
        let mut position = 0usize;
        for (air, width) in widths.iter().enumerate() {
            if *width == 0 {
                continue;
            }
            let blocks = width * EXT_DEGREE / ADV_PIPE_BLOCK_FELTS;
            if occupied > 1 {
                sources.push(ScatterSource {
                    group,
                    air,
                    dst: canonical,
                    blocks,
                    slot_offset: group_slot_offset,
                });
                dispatches.push(ScatterDispatch {
                    group,
                    dst: canonical,
                    blocks,
                    position,
                    slot: Some(slot),
                });
                slot += 1;
            } else {
                dispatches.push(ScatterDispatch {
                    group,
                    dst: canonical,
                    blocks,
                    position,
                    slot: None,
                });
            }
            position += 1;
            canonical += width * EXT_DEGREE;
        }
        group_base += widths.iter().sum::<usize>() * EXT_DEGREE;
    }
    dispatches.push(ScatterDispatch {
        group: "quotient",
        dst: group_base,
        position: 0,
        blocks: geometry.quotient_width * EXT_DEGREE / ADV_PIPE_BLOCK_FELTS,
        slot: None,
    });

    let mut lengths: Vec<_> = dispatches.iter().map(|dispatch| dispatch.blocks).collect();
    lengths.sort_unstable();
    lengths.dedup();

    // Digest words must be word-aligned, so they follow the pair table at the next word boundary.
    let digest_offset = (OOD_SCATTER_SLOTS_OFFSET + 2 * slot).next_multiple_of(WORD_FELTS);
    let required = digest_offset + WORD_FELTS * lengths.len();
    if required > OOD_SCATTER_TABLE_FELTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "the out-of-domain scatter table needs {required} felts but OOD_SCATTER_TABLE_PTR \
                 reserves {OOD_SCATTER_TABLE_FELTS}"
            ),
        ));
    }
    if dispatches.iter().map(|dispatch| dispatch.blocks).sum::<usize>() != geometry.ood_pipe_blocks
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the scatter dispatch table does not cover exactly one out-of-domain row",
        ));
    }

    Ok(ScatterPlan {
        dispatches,
        sources,
        lengths,
        digest_offset,
    })
}

/// Emits `push.OFFSET`-free addressing of one table cell, leaving its value on the stack.
fn scatter_cell_load(offset: usize) -> String {
    if offset == 0 {
        "exec.layout::ood_scatter_table_ptr mem_load".into()
    } else {
        format!("exec.layout::ood_scatter_table_ptr add.{offset} mem_load")
    }
}

fn render_vm_ood_frames(geometry: &VmGeometry) -> io::Result<String> {
    let plan = vm_scatter_plan(geometry)?;

    let pipes = plan
        .lengths
        .iter()
        .map(|blocks| {
            format!(
                "#! Absorbs {blocks} advice blocks into the row already targeted by the caller.\n\
                 #!\n\
                 #! Inputs:  [scratch0, scratch1, cv, ptr, alpha_ptr, acc0, acc1]\n\
                 #! Outputs: [scratch0, scratch1, cv', ptr + {felts}, alpha_ptr, acc0', acc1']\n\
                 proc pipe_{blocks}\n    \
                 repeat.{blocks}\n        \
                 adv_pipe\n        \
                 horner_eval_ext\n        \
                 compress\n    \
                 end\nend\n",
                felts = blocks * ADV_PIPE_BLOCK_FELTS,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let digest_staging = plan
        .lengths
        .iter()
        .map(|blocks| {
            format!(
                "    procref.pipe_{blocks} exec.layout::ood_scatter_table_ptr add.{offset} \
                 mem_storew_le dropw",
                offset = plan.digest_offset_for(*blocks),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let mut order_pass = Vec::new();
    for air in 0..MIDEN_AIR_COUNT {
        let sources: Vec<_> = plan.sources.iter().filter(|source| source.air == air).collect();
        if sources.is_empty() {
            continue;
        }
        let mut block = format!(
            "\n    exec.constants::air_trace_length_logs_ptr push.NUM_AIRS push.{air}\n    \
             exec.utils::proof_order_position_from_heights\n    \
             # => [pos]\n"
        );
        for source in sources {
            block += &format!(
                "    # {group}: {blocks} blocks at row offset {dst}\n    \
                 push.{dst} dup.1 mul.2 exec.layout::ood_scatter_table_ptr add add.{slot} \
                 mem_store\n    \
                 exec.layout::ood_scatter_table_ptr add.{digest} dup.1 mul.2 \
                 exec.layout::ood_scatter_table_ptr add add.{next} mem_store\n",
                group = source.group,
                blocks = source.blocks,
                dst = source.dst,
                slot = source.slot_offset,
                digest = plan.digest_offset_for(source.blocks),
                next = source.slot_offset + 1,
            );
        }
        block += "    drop\n";
        order_pass.push(block);
    }

    let ingest = plan
        .dispatches
        .iter()
        .map(|dispatch| match dispatch.slot {
            // The proof order decides which AIR sits here, so both the destination and the
            // segment length come from the table the order pass filled.
            Some(slot) => format!(
                "    # {group} group, proof position {position}\n    \
                 exec.layout::ood_scatter_table_ptr dup add.{pair} mem_load swap mem_load \
                 add\n    swap.13 drop\n    {digest}\n    dynexec",
                group = dispatch.group,
                position = dispatch.position,
                pair = OOD_SCATTER_SLOTS_OFFSET + 2 * slot,
                digest = scatter_cell_load(OOD_SCATTER_SLOTS_OFFSET + 2 * slot + 1),
            ),
            None => format!(
                "    # {group} group, sole occupant: {blocks} blocks at row offset {dst}\n    \
                 exec.layout::ood_scatter_table_ptr mem_load{offset}\n    swap.13 drop\n    \
                 exec.pipe_{blocks}",
                group = dispatch.group,
                dst = dispatch.dst,
                offset = if dispatch.dst == 0 {
                    String::new()
                } else {
                    format!(" add.{}", dispatch.dst)
                },
                blocks = dispatch.blocks,
            ),
        })
        .collect::<Vec<_>>()
        .join("\n");

    Ok(format!(
        r#"# GENERATED by `cargo run -p miden-core-lib --features constraints-tools --bin regenerate-constraints -- --write` — do not edit by hand.
use miden::core::stark::constants
use miden::core::stark::utils
use miden::core::sys::vm::layout

# Number of AIR instances in the relation.
const NUM_AIRS = {num_airs}

# Per-row OOD layout uses LMCS alignment {LMCS_ALIGNMENT}:
#   preprocessed: {preprocessed_parts} = {preprocessed} scalar evaluations
#   main:         {main_parts} = {main} scalar evaluations
#   aux:          {aux_parts} = {aux} scalar evaluations
#   quotient:     {quotient} scalar evaluations
# The advice stream supplies {ood_felts} base felts, read as {pipe_blocks} `adv_pipe` blocks.

{pipes}
#! Stages the proof-order-dependent half of the out-of-domain scatter table.
#!
#! The proof commits each AIR's trace at its position in the height-sorted proof order, while the
#! constraint circuit reads it at the AIR's canonical instance offset. Both the canonical
#! destination and the segment length are compile-time per AIR; this procedure only routes them to
#! the stream position the absorbed trace heights put that AIR in.
#!
#! Must run after the AIR heights are stored and before the first out-of-domain row is ingested.
#!
#! Inputs:  []
#! Outputs: []
pub proc stage_ood_scatter_table
{digest_staging}
{order_pass}end

#! Processes the out-of-domain (OOD) evaluations of all committed polynomials.
#!
#! Loads one OOD row from advice, absorbs it into the Eidos transcript, and updates the Horner
#! accumulator used by the DEEP fixed terms. Both stay positional over the advice stream; the only
#! thing the proof order moves is where each segment is stored, which the table staged by
#! `stage_ood_scatter_table` supplies.
#!
#! Inputs:  [scratch0, scratch1, cv, ptr, alpha_ptr, acc0, acc1]
#! Outputs: [scratch0, scratch1, cv', ptr + {ood_felts}, alpha_ptr, acc0', acc1']
pub proc process_row_ood_evaluations
    dup.12 exec.layout::ood_scatter_table_ptr mem_store
{ingest}
    exec.layout::ood_scatter_table_ptr mem_load add.{ood_felts}
    swap.13 drop
end
"#,
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
        order_pass = order_pass.join(""),
    ))
}

fn render_vm_deep_queries(geometry: &VmGeometry) -> io::Result<String> {
    let mut deep_queries = read_file(VM_DEEP_QUERIES_PATH)?;
    replace_line_with_prefix(
        &mut deep_queries,
        "# Load the aligned preprocessed leaf:",
        &format!(
            "    # Load the aligned preprocessed leaf: {} base felts.",
            geometry.preprocessed_width,
        ),
    )?;
    replace_repeat_in_proc(
        &mut deep_queries,
        "load_preprocessed_segment",
        geometry.preprocessed_pipe_blocks,
    )?;
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
    replace_repeat_in_proc(
        &mut deep_queries,
        "load_constraints_composition_polys_trace",
        geometry.quotient_pipe_blocks,
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
        "wrote asm/sys/vm/constraints_eval.masm ({} inputs, {} eval gates, repeat.{})",
        artifact.num_inputs, artifact.num_eval_gates, artifact.stream_blocks
    );
    println!("wrote asm/sys/vm/mod.masm (relation digest and preprocessed commitment)");
    println!("wrote air/src/config.rs (relation digest and ACE circuit digest)");
    println!("wrote verifier/src/lib.rs (preprocessed commitment)");
    println!("wrote VM recursive-verifier layout, OOD-frame, and DEEP-query geometry");
    println!("done - run `cargo test -p miden-air --lib` to update the insta snapshot");
    Ok(())
}

fn word_to_array(word: Word) -> [Felt; 4] {
    [word[0], word[1], word[2], word[3]]
}

fn render_constraints_eval_file(
    circuit: &miden_air::ace::RecursiveAceCircuit,
    quotient_inputs: QuotientRecompositionInputs<Felt>,
) -> io::Result<String> {
    miden_ace_codegen::render_masm_constraints_eval(&miden_ace_codegen::MasmConstraintsEvalConfig {
        generated_by: "cargo run -p miden-core-lib --features constraints-tools --bin \
                           regenerate-constraints -- --write",
        layout_module: "miden::core::sys::vm::layout",
        num_inputs: circuit.num_inputs,
        num_eval_gates: circuit.num_eval_gates,
        stream_len: circuit.stream_len,
        max_cycle_len_log: max_periodic_cycle_len_log(),
        num_airs: MIDEN_AIR_COUNT,
        // The VM's canonical READ layout reserves one fold-coefficient slot per AIR, so its
        // evaluator stages them; that block is what makes the circuit order-invariant.
        stages_fold_coefficients: true,
        quotient_inputs,
        circuit_digest: circuit.commitment,
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
    if miden_air::config::ACE_CIRCUIT_DIGEST != artifact.circuit_digest {
        return Err(
            "ACE_CIRCUIT_DIGEST in air/src/config.rs is stale (it binds the transcript to the \
             one circuit the recursive verifier evaluates)"
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

    // Both the boundary weighting and `scatter_aux_bus_boundary` unroll one block per AIR against
    // this bound; a stale value would drop the extra AIR from the weighted sum and leave its
    // boundary value at its proof-order address.
    let aux_trace = read_file(VM_AUX_TRACE_PATH).map_err(|e| e.to_string())?;
    let scatter_airs = parse_masm_const::<usize>(&aux_trace, "NUM_AIRS", VM_AUX_TRACE_PATH)?;
    if scatter_airs != MIDEN_AIR_COUNT {
        return Err("NUM_AIRS in sys/vm/aux_trace.masm is stale".into());
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
    stream_blocks: usize,
    circuit_digest: [Felt; 4],
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

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec};

    use super::*;

    /// A group every AIR occupies is indexed correctly by proof-order position, and one with a
    /// single occupant needs no table at all. Anything between the two would address past the
    /// group's slots, so the renderer must refuse it instead of emitting it.
    #[test]
    fn scatter_plan_rejects_partially_occupied_commitment_groups() {
        // Today's shape: only the last AIR has preprocessed columns.
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
            main_pipe_blocks: main_width / ADV_PIPE_BLOCK_FELTS,
            aux_pipe_blocks: aux_width / ADV_PIPE_BLOCK_FELTS,
            ood_pipe_blocks: row_width * EXT_DEGREE / ADV_PIPE_BLOCK_FELTS,
            ood_evaluations_ptr: 0,
            aux_bus_boundary_ptr: 0,
            auxiliary_ace_inputs_ptr: 0,
            ace_circuit_stream_ptr: 0,
            current_trace_row_ptr: 0,
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
        let layout = recursive_verifier_input_layout().expect("recursive ACE input layout");
        let geometry = VmGeometry::from_input_layout(&layout).expect("VM geometry");
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
