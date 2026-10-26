use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use std::{fmt::Write as _, fs, io, println};

use miden_ace_codegen::{
    EXT_DEGREE, FoldCoefficientStaging, InputKey, InputLayout, OodScatterPlan,
    ProofOrderMapsConfig, render_proof_order_maps,
};
use miden_air::{
    AIRS, MIDEN_AIR_COUNT, MidenAir, MidenMultiAir, Statement,
    ace::{
        RecursiveAceCircuit, build_canonical_multi_air_ace_circuit, recursive_verifier_ace_config,
    },
    config::{self, relation_digest},
};
use miden_core::{
    Felt, WORD_SIZE, Word, crypto::hash::Eidos, field::QuadFelt, program::KernelDescriptor,
};
use miden_crypto::{
    hash::eidos::{BLOCK_LEN as EIDOS_BLOCK_WIDTH, domains::LMCS_LEAF},
    stark::{
        Preprocessed, QuotientRecompositionInputs, StarkConfig,
        air::{BaseAir, LiftedAir},
        lmcs::Lmcs,
        quotient_recomposition_inputs,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Check,
    Write,
}

const PROTOCOL_ID: u64 = 1;
const AIR_CONFIG_PATH: &str = "../../../air/src/config.rs";
const CONSTRAINTS_EVAL_PATH: &str = "asm/sys/vm/constraints_eval.masm";
const VM_WRAPPER_PATH: &str = "asm/sys/vm/mod.masm";
const VM_LAYOUT_PATH: &str = "asm/sys/vm/layout.masm";
const STARK_CONSTANTS_PATH: &str = "asm/stark/constants.masm";
const VM_OOD_FRAMES_PATH: &str = "asm/sys/vm/ood_frames.masm";
const VM_PARAMETERS_PATH: &str = "asm/sys/vm/parameters.masm";
const VM_PUBLIC_INPUTS_PATH: &str = "asm/sys/vm/public_inputs.masm";
const PVM_LAYOUT_PATH: &str = "asm/sys/pvm/layout.masm";
const SECURITY_ESTIMATOR_PATH: &str = "asm/stark/security.masm";
const GENERIC_UTILS_PATH: &str = "asm/stark/utils.masm";
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
    // The circuit topology is fixed across proof orders; MASM applies proof-order-specific ingest
    // scatter and fold-coefficient staging.
    let source = build_canonical_multi_air_ace_circuit(recursive_verifier_ace_config())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    let input_layout = source.layout();
    let circuit = RecursiveAceCircuit::try_from(
        source
            .to_ace()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?,
    )
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
        config::pcs_params().log_blowup(),
    )
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;

    let circuit_digest = word_to_array(circuit.commitment);
    let relation_digest = compute_relation_digest(&circuit_digest);
    let vm_geometry = VmGeometry::from_input_layout(input_layout)?;
    let constraints_eval = render_constraints_eval_file(&circuit, quotient_inputs, &vm_geometry)?;
    let vm_ood_frames = render_vm_ood_frames(&vm_geometry)?;

    let preprocessed_commitments = compute_preprocessed_commitments(relation_digest)?;

    let vm_parameters =
        render_vm_parameters(&vm_geometry, &relation_digest, &preprocessed_commitments.eidos)?;
    let mut air_config = read_file(AIR_CONFIG_PATH)?;
    replace_felt_array_const(&mut air_config, "RELATION_DIGEST", &relation_digest)?;
    replace_felt_array_const(&mut air_config, "ACE_CIRCUIT_DIGEST", &circuit_digest)?;
    replace_u8_array_const(
        &mut air_config,
        "BLAKE3_PREPROCESSED_COMMITMENT",
        &preprocessed_commitments.blake3,
    )?;
    replace_u64_array_const(
        &mut air_config,
        "EIDOS_PREPROCESSED_COMMITMENT",
        &preprocessed_commitments.eidos,
    )?;
    replace_u64_array_const(
        &mut air_config,
        "KECCAK_PREPROCESSED_COMMITMENT",
        &preprocessed_commitments.keccak,
    )?;

    ensure_vm_ace_stream_fits(circuit.stream_len, vm_geometry.ace_circuit_stream_ptr)?;

    Ok(ComputedArtifacts {
        num_inputs: circuit.num_inputs,
        num_eval_gates: circuit.num_eval_gates,
        stream_blocks: circuit.stream_len / 8,
        circuit_digest,
        relation_digest,
        preprocessed_commitments,
        constraints_eval,
        air_config,
        vm_ood_frames,
        vm_parameters,
    })
}

struct PreprocessedCommitments {
    blake3: [u8; 32],
    eidos: [u64; 4],
    keccak: [u64; 4],
}

type Commitment<SC> = <<SC as StarkConfig<Felt, QuadFelt>>::Lmcs as Lmcs>::Commitment;

fn compute_preprocessed_commitments(digest: [Felt; 4]) -> io::Result<PreprocessedCommitments> {
    let statement = Statement::<Felt, QuadFelt, MidenMultiAir>::new(
        MidenMultiAir::new(),
        vec![(0, vec![Felt::ZERO; miden_air::NUM_PUBLIC_VALUES])],
        vec![],
    )
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
    let params = config::pcs_params();
    Ok(PreprocessedCommitments {
        blake3: compute_preprocessed_commitment(
            &statement,
            &config::blake3_256_config(params, digest),
        )?
        .into(),
        eidos: compute_preprocessed_commitment(&statement, &config::eidos_config(params, digest))?
            .into(),
        keccak: compute_preprocessed_commitment(
            &statement,
            &config::keccak_config(params, digest),
        )?
        .into(),
    })
}

fn compute_preprocessed_commitment<SC>(
    statement: &Statement<Felt, QuadFelt, MidenMultiAir>,
    config: &SC,
) -> io::Result<Commitment<SC>>
where
    SC: StarkConfig<Felt, QuadFelt>,
{
    Preprocessed::build(statement, config)
        .map(|preprocessed| preprocessed.commitment())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "canonical verifier statement has no preprocessed trace",
            )
        })
}

fn ensure_vm_ace_stream_fits(stream_len: usize, stream_start: usize) -> io::Result<()> {
    let pvm_layout = read_file(PVM_LAYOUT_PATH)?;
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
    ood_pipe_blocks: usize,
    ood_evaluations_ptr: usize,
    aux_bus_boundary_ptr: usize,
    auxiliary_ace_inputs_ptr: usize,
    ace_circuit_stream_ptr: usize,
    ood_scatter_table_ptr: usize,
    /// Felt offset of AIR 0's first selector from `auxiliary_ace_inputs_ptr`.
    air_selector_offset: usize,
    /// Felt offset of AIR 0's fold-coefficient slot from `auxiliary_ace_inputs_ptr`.
    fold_coefficient_offset: usize,
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
        let aux_values: Vec<_> =
            AIRS.iter().map(LiftedAir::<Felt, QuadFelt>::num_aux_values).collect();
        if aux_values.as_slice() != [1usize; MIDEN_AIR_COUNT].as_slice() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "the VM proof-order boundary scatter requires exactly one auxiliary value per \
                     AIR, got {aux_values:?}"
                ),
            ));
        }
        let quotient_width = input_layout.counts.num_quotient_chunks * EXT_DEGREE;
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
        // Its lower neighbour is the kernel digest witness, one word per supported kernel
        // procedure written by `materialize_kernel_witness`; the table must start at or after its
        // end.
        let kernel_witness_ptr =
            parse_masm_const::<usize>(&layout, "KERNEL_WITNESS_PTR", VM_LAYOUT_PATH)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
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
        let air_selector_offset = input_layout_extent(
            auxiliary_ace_inputs_index,
            require_input_index(input_layout, InputKey::IsFirstAir(0))?,
            "per-AIR selectors",
        )?;
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
            ood_pipe_blocks: ood_row_felts / ADV_PIPE_BLOCK_FELTS,
            ood_evaluations_ptr,
            aux_bus_boundary_ptr,
            auxiliary_ace_inputs_ptr,
            ace_circuit_stream_ptr,
            ood_scatter_table_ptr,
            air_selector_offset,
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

/// Renders protocol and geometry constants for the VM MASM verifier.
fn render_vm_parameters(
    geometry: &VmGeometry,
    relation_digest: &[Felt; 4],
    preprocessed_commitment: &[u64; 4],
) -> io::Result<String> {
    let plan = vm_scatter_plan(geometry)?;
    let positions_ptr =
        geometry.ood_scatter_table_ptr.checked_add(plan.table_felts()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "VM proof-order map overflows")
        })?;
    let ids_ptr = positions_ptr.checked_add(MIDEN_AIR_COUNT).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "VM proof-order map overflows")
    })?;
    for (name, ptr) in
        [("PROOF_ORDER_POSITIONS_PTR", positions_ptr), ("PROOF_ORDER_IDS_PTR", ids_ptr)]
    {
        u32::try_from(ptr).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, format!("VM {name} exceeds u32 memory"))
        })?;
    }
    let mut output = String::from(
        "# Generated by `make regenerate-constraints`. Do not edit.\n\n\
         # Protocol commitments under the native Eidos configuration.\n",
    );
    for (prefix, word) in [
        ("RELATION_DIGEST", relation_digest.map(|felt| felt.as_canonical_u64())),
        ("AND8_PREPROCESSED_TRACE_COM", *preprocessed_commitment),
    ] {
        for (index, value) in word.into_iter().enumerate() {
            writeln!(output, "pub const {prefix}_{index} = {value}").unwrap();
        }
    }
    output.push_str("\n# Security descriptor from miden_air::security.\n");
    for (name, value) in [
        ("MAX_MESSAGE_WIDTH", miden_air::security::LOOKUP_SHAPE.max_message_width),
        (
            "NUM_COMPOSED_CONSTRAINTS",
            miden_air::security::AIR_SHAPE.num_composed_constraints,
        ),
        ("MAX_CONSTRAINT_DEGREE", miden_air::security::AIR_SHAPE.max_constraint_degree),
        (
            "NUM_DEEP_TERMS",
            miden_air::security::AIR_SHAPE
                .num_deep_terms
                .expect("the VM uses DEEP composition"),
        ),
        ("LOOKUP_FRACTIONS_PER_ROW", miden_air::security::LOOKUP_SHAPE.fractions_per_row),
    ] {
        writeln!(output, "pub const {name} = {value}").unwrap();
    }

    let and8_log_height = miden_air::and8_lookup::columns::LOG_AND8_LOOKUP_TRACE_HEIGHT;
    let tree_depth = u32::from(and8_log_height) + u32::from(config::pcs_params().log_blowup());
    let index_mask = 1u64
        .checked_shl(tree_depth)
        .and_then(|size| u32::try_from(size - 1).ok())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "AND8 LDE depth exceeds u32 indices")
        })?;
    writeln!(output, "\n# Fixed And8 setup height and its PCS-expanded query-index mask.").unwrap();
    writeln!(output, "pub const AND8_LOOKUP_LOG_HEIGHT = {and8_log_height}").unwrap();
    writeln!(output, "pub const AND8_LDE_INDEX_MASK = {index_mask}").unwrap();

    let raw_preprocessed: Vec<_> = AIRS.iter().map(BaseAir::<Felt>::preprocessed_width).collect();
    let air_names = AIRS.iter().map(|air| air.name()).collect::<Vec<_>>().join(", ");
    writeln!(output, "\n# Per-AIR widths in canonical order: {air_names}.").unwrap();
    writeln!(
        output,
        "# Preprocessed: {} raw columns -> {} aligned base felts = {}.",
        format_sum(&raw_preprocessed),
        format_sum(&geometry.preprocessed_widths),
        geometry.preprocessed_width,
    )
    .unwrap();
    writeln!(
        output,
        "# Main: {} = {} aligned base felts.",
        format_sum(&geometry.main_widths),
        geometry.main_width,
    )
    .unwrap();
    writeln!(
        output,
        "# Auxiliary coordinates: {} = {} aligned base felts.",
        format_sum(&geometry.aux_widths),
        geometry.aux_width,
    )
    .unwrap();

    output.push_str(
        "\n# Query-row blocks and LMCS leaf frames, in commitment-group order.\n\
                     # Each block contains eight base felts.\n",
    );
    for (group, width) in [
        ("PREPROCESSED", geometry.preprocessed_width),
        ("MAIN", geometry.main_width),
        ("AUX", geometry.aux_width),
        ("QUOTIENT", geometry.quotient_width),
    ] {
        if width == 0 || !width.is_multiple_of(EIDOS_BLOCK_WIDTH) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "VM {group} query width {width} must be a positive multiple of {EIDOS_BLOCK_WIDTH}"
                ),
            ));
        }
        let encoded_len = u32::try_from(width).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("VM {group} LMCS encoded length exceeds u32"),
            )
        })?;
        let cv = Eidos::init_chaining_word(LMCS_LEAF, encoded_len);
        writeln!(output, "pub const {group}_ROW_DOUBLE_WORDS = {}", width / EIDOS_BLOCK_WIDTH)
            .unwrap();
        writeln!(
            output,
            "pub const {group}_LMCS_INIT_CV = [{}, {}, {}, {}]",
            cv[0], cv[1], cv[2], cv[3]
        )
        .unwrap();
    }

    writeln!(output, "\n# VM ACE READ addresses derived from InputLayout.").unwrap();
    writeln!(
        output,
        "# Stack I/O: {} public values in {} base-field cells immediately before AUX_RAND_ELEM_PTR.",
        miden_air::NUM_PUBLIC_VALUES,
        miden_air::NUM_PUBLIC_VALUES * EXT_DEGREE,
    )
    .unwrap();
    writeln!(
        output,
        "# OOD frame: {} base felts; each current/next row has {} scalar evaluations.",
        geometry.ood_frame_felts, geometry.row_width
    )
    .unwrap();
    writeln!(
        output,
        "# Query scratch row: {} preprocessed + {} main + {} auxiliary + {} quotient felts.",
        geometry.preprocessed_width,
        geometry.main_width,
        geometry.aux_width,
        geometry.quotient_width
    )
    .unwrap();
    let shared_stark_slots = geometry.air_selector_offset / EXT_DEGREE;
    let selector_slots = geometry
        .fold_coefficient_offset
        .checked_sub(geometry.air_selector_offset)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "VM ACE fold coefficients precede per-AIR selectors",
            )
        })?
        / EXT_DEGREE;
    let auxiliary_felts = geometry
        .ace_circuit_stream_ptr
        .checked_sub(geometry.auxiliary_ace_inputs_ptr)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "VM ACE circuit stream precedes auxiliary inputs",
            )
        })?;
    let auxiliary_slots = auxiliary_felts / EXT_DEGREE;
    let padding_slots = auxiliary_slots
        .checked_sub(shared_stark_slots)
        .and_then(|slots| slots.checked_sub(selector_slots))
        .and_then(|slots| slots.checked_sub(MIDEN_AIR_COUNT))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "VM ACE auxiliary allocation cannot fit STARK variables, selectors, and \
                 fold coefficients",
            )
        })?;
    writeln!(
        output,
        "# Auxiliary ACE inputs, in memory order (one slot = {EXT_DEGREE} base felts):\n\
         #   {shared_stark_slots} shared STARK slots; {selector_slots} selectors for {MIDEN_AIR_COUNT} AIRs;\n\
         #   {MIDEN_AIR_COUNT} fold coefficients; {padding_slots} alignment slots.\n\
         #   Total: {auxiliary_slots} slots ({auxiliary_felts} base felts)."
    )
    .unwrap();
    for (name, value) in [
        ("OOD_EVALUATIONS_PTR", geometry.ood_evaluations_ptr),
        ("AUX_BUS_BOUNDARY_PTR", geometry.aux_bus_boundary_ptr),
        ("AUXILIARY_ACE_INPUTS_PTR", geometry.auxiliary_ace_inputs_ptr),
        ("ACE_CIRCUIT_STREAM_PTR", geometry.ace_circuit_stream_ptr),
    ] {
        u32::try_from(value).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, format!("VM {name} exceeds u32 memory"))
        })?;
        writeln!(output, "pub const {name} = {value}").unwrap();
    }
    writeln!(
        output,
        "\n# Scatter reserve: {OOD_SCATTER_TABLE_FELTS} felts at {}.",
        geometry.ood_scatter_table_ptr
    )
    .unwrap();
    writeln!(
        output,
        "# +0: row base; +4..{}: destination/digest pairs; +{}..{}: pipe procedure digests.",
        plan.pipe_digests().start - 1,
        plan.pipe_digests().start,
        plan.table_felts() - 1
    )
    .unwrap();
    writeln!(output, "# The two following maps contain {MIDEN_AIR_COUNT} felts each.").unwrap();
    writeln!(output, "pub const PROOF_ORDER_POSITIONS_PTR = {positions_ptr}").unwrap();
    writeln!(output, "pub const PROOF_ORDER_IDS_PTR = {ids_ptr}").unwrap();
    Ok(output)
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
    let stark_constants = read_file(STARK_CONSTANTS_PATH)?;
    let heights_ptr = parse_masm_const::<usize>(
        &stark_constants,
        "LOG_AIR_TRACE_LENGTHS_PTR",
        STARK_CONSTANTS_PATH,
    )
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
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
        r#"# GENERATED by `cargo run -p miden-core-lib --features constraints-tools --bin regenerate-constraints -- --write` — do not edit by hand.
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

fn format_sum(parts: &[usize]) -> String {
    parts.iter().map(usize::to_string).collect::<Vec<_>>().join(" + ")
}

fn write_artifacts(artifact: &ComputedArtifacts) -> io::Result<()> {
    write_file(CONSTRAINTS_EVAL_PATH, &artifact.constraints_eval)?;
    write_file(AIR_CONFIG_PATH, &artifact.air_config)?;
    write_file(VM_OOD_FRAMES_PATH, &artifact.vm_ood_frames)?;
    write_file(VM_PARAMETERS_PATH, &artifact.vm_parameters)?;
    println!(
        "wrote asm/sys/vm/constraints_eval.masm ({} inputs, {} eval gates, repeat.{})",
        artifact.num_inputs, artifact.num_eval_gates, artifact.stream_blocks
    );
    println!("wrote air/src/config.rs (relation and ACE digests, preprocessed commitments)");
    println!("wrote VM recursive-verifier parameters and OOD-frame geometry");
    println!("done - run `cargo test -p miden-air --lib` to update the insta snapshot");
    Ok(())
}

fn word_to_array(word: Word) -> [Felt; 4] {
    [word[0], word[1], word[2], word[3]]
}

fn render_constraints_eval_file(
    circuit: &RecursiveAceCircuit,
    quotient_inputs: QuotientRecompositionInputs<Felt>,
    geometry: &VmGeometry,
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

fn max_periodic_cycle_len_log() -> u32 {
    let max_len = AIRS
        .iter()
        .flat_map(|air| <MidenAir as BaseAir<Felt>>::periodic_columns(air).into_owned())
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

/// Verify that RELATION_DIGEST in `air/src/config.rs` and `sys/vm/parameters.masm` matches current
/// AIR.
pub fn relation_digest_matches_air() -> Result<(), String> {
    let artifact = compute_artifacts().map_err(|e| e.to_string())?;
    relation_digest_matches_artifact(&artifact)
}

fn relation_digest_matches_artifact(artifact: &ComputedArtifacts) -> Result<(), String> {
    let expected = artifact.relation_digest;

    if config::RELATION_DIGEST != expected {
        return Err("RELATION_DIGEST in air/src/config.rs is stale".into());
    }
    if config::ACE_CIRCUIT_DIGEST != artifact.circuit_digest {
        return Err(
            "ACE_CIRCUIT_DIGEST in air/src/config.rs is stale (it binds the transcript to the \
             one circuit the recursive verifier evaluates)"
                .into(),
        );
    }

    if read_file(VM_PARAMETERS_PATH).map_err(|err| err.to_string())? != artifact.vm_parameters {
        return Err(format!("{VM_PARAMETERS_PATH} is stale"));
    }

    let commitments = &artifact.preprocessed_commitments;
    if config::BLAKE3_PREPROCESSED_COMMITMENT != commitments.blake3
        || config::EIDOS_PREPROCESSED_COMMITMENT != commitments.eidos
        || config::KECCAK_PREPROCESSED_COMMITMENT != commitments.keccak
    {
        return Err("preprocessed commitments in air/src/config.rs are stale".into());
    }

    // The generated map/scatter hook is specialized to one block per AIR. A stale value would
    // leave an AIR without a routed out-of-domain segment.
    let ood_frames = read_file(VM_OOD_FRAMES_PATH).map_err(|e| e.to_string())?;
    let scatter_airs = parse_masm_const::<usize>(&ood_frames, "NUM_AIRS", VM_OOD_FRAMES_PATH)?;
    if scatter_airs != MIDEN_AIR_COUNT {
        return Err("NUM_AIRS in sys/vm/ood_frames.masm is stale".into());
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
        (VM_OOD_FRAMES_PATH, artifact.vm_ood_frames.as_str()),
        (VM_PARAMETERS_PATH, artifact.vm_parameters.as_str()),
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
    let sample_bits = miden_air::security::EIDOS_CHALLENGE_SAMPLE_BITS;
    let shared_literals: [(&str, u64); 9] = [
        ("FP_SHIFT", u64::from(fractional_bits)),
        ("FP_ONE", fixed_point_one),
        ("BITS_PER_QUERY_FP", miden_air::security::BITS_PER_QUERY),
        ("CHALLENGE_SAMPLE_BITS", sample_bits >> fractional_bits),
        ("SECURITY_CAP_BITS", miden_air::security::SECURITY_CAP >> fractional_bits),
        (
            "DEEP_FIELD_BASE_BITS",
            (sample_bits >> fractional_bits) - u64::from(config::pcs_params().log_blowup()),
        ),
        ("FRI_FOLDING_BASE_BITS", miden_air::security::FOLDING_BASE >> fractional_bits),
        ("LOG2_E_FP", miden_air::security::LOG2_E),
        ("MAX_CONSTRAINT_DEGREE", (1u64 << config::pcs_params().log_blowup()) + 1),
    ];

    for (name, expected) in shared_literals {
        let actual = parse_masm_const::<u64>(&estimator, name, SECURITY_ESTIMATOR_PATH)?;
        if actual != expected {
            return Err(format!("{name} in {SECURITY_ESTIMATOR_PATH} is stale"));
        }
    }

    // The estimator omits four native security terms only while the MVM shape and the generic
    // verifier's parameter ranges satisfy its documented bounds. `air_shape_matches_symbolic`
    // checks the stored shape against the AIRs; the checks below fail if that shape leaves the
    // estimator envelope. This function also pins the generic verifier bounds directly.
    let wrapper = read_file(VM_WRAPPER_PATH).map_err(|e| e.to_string())?;
    let utils = read_file(GENERIC_UTILS_PATH).map_err(|e| e.to_string())?;
    let air_shape = miden_air::security::AIR_SHAPE;
    let parsed = |name: &str| parse_masm_const::<u64>(&estimator, name, SECURITY_ESTIMATOR_PATH);
    let lookup = air_shape.lookup.expect("the MVM uses a lookup argument");
    let lookup_coefficient =
        (u64::from(lookup.max_message_width) + 2) * u64::from(lookup.fractions_per_row);
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
        != parse_masm_const::<u64>(&wrapper, "LOG_HEIGHT_MIN", VM_WRAPPER_PATH)?
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

    let parameters = read_file(VM_PARAMETERS_PATH).map_err(|err| err.to_string())?;
    let wrapper_source = (&wrapper, VM_WRAPPER_PATH);
    let parameters_source = (&parameters, VM_PARAMETERS_PATH);
    for (name, (source, path), expected) in [
        ("LOOKUP_POW_BITS", wrapper_source, miden_air::security::LOOKUP_POW_BITS as u64),
        (
            "MAX_MESSAGE_WIDTH",
            parameters_source,
            miden_air::security::LOOKUP_SHAPE.max_message_width as u64,
        ),
        (
            "NUM_COMPOSED_CONSTRAINTS",
            parameters_source,
            miden_air::security::AIR_SHAPE.num_composed_constraints as u64,
        ),
        (
            "MAX_CONSTRAINT_DEGREE",
            parameters_source,
            miden_air::security::AIR_SHAPE.max_constraint_degree as u64,
        ),
        (
            "NUM_DEEP_TERMS",
            parameters_source,
            miden_air::security::AIR_SHAPE
                .num_deep_terms
                .expect("the MVM uses DEEP composition") as u64,
        ),
        (
            "CORE_BOUNDARY_LOOKUP_TERMS",
            wrapper_source,
            miden_air::security::CORE_BOUNDARY_LOOKUP_TERMS as u64,
        ),
        (
            "LOOKUP_FRACTIONS_PER_ROW",
            parameters_source,
            miden_air::security::LOOKUP_SHAPE.fractions_per_row as u64,
        ),
        (
            "MAX_NUM_KERNEL_PROCEDURES",
            wrapper_source,
            KernelDescriptor::MAX_NUM_PROCEDURES as u64,
        ),
        ("LOG_HEIGHT_MAX", wrapper_source, estimator_heights),
    ] {
        let actual = parse_masm_const::<u64>(source, name, path)?;
        if actual != expected {
            return Err(format!("{name} in {path} is stale"));
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
    let metadata_prefix = format!("# {name} = ");
    masm.lines()
        .find_map(|line| {
            let line = line.trim();
            let value = line
                .strip_prefix("pub ")
                .unwrap_or(line)
                .strip_prefix(&prefix)
                .or_else(|| line.strip_prefix(&metadata_prefix))?;
            let value = value.split('#').next().unwrap_or(value).trim();
            value.parse::<T>().ok()
        })
        .ok_or_else(|| format!("constant {name} not found in {file_label}"))
}

fn replace_felt_array_const(
    content: &mut String,
    name: &str,
    values: &[Felt; 4],
) -> io::Result<()> {
    let mut body: String = values
        .iter()
        .map(|f| format!("\n    Felt::new_unchecked({}),", f.as_canonical_u64()))
        .collect();
    body.push('\n');
    replace_rust_array_const(content, "pub const", name, &body)
}

fn replace_u64_array_const(content: &mut String, name: &str, values: &[u64; 4]) -> io::Result<()> {
    let mut body: String = values.iter().map(|value| format!("\n    {value},")).collect();
    body.push('\n');
    replace_rust_array_const(content, "pub const", name, &body)
}

fn replace_u8_array_const(content: &mut String, name: &str, values: &[u8; 32]) -> io::Result<()> {
    let mut body: String = values.iter().map(|value| format!("\n    {value},")).collect();
    body.push('\n');
    replace_rust_array_const(content, "pub const", name, &body)
}

fn replace_rust_array_const(
    content: &mut String,
    declaration_prefix: &str,
    name: &str,
    body: &str,
) -> io::Result<()> {
    let marker = format!("{declaration_prefix} {name}:");
    let start = content
        .find(&marker)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("{name} not found")))?;
    if content[start + marker.len()..].contains(&marker) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{name} is declared more than once"),
        ));
    }

    // These generated declarations keep `=` on the declaration line, while rustfmt may put the
    // opening bracket on the next line. Anchoring the assignment to that line prevents a malformed
    // declaration from borrowing an initializer from a later item.
    let declaration_end = content[start..]
        .find('\n')
        .map(|offset| start + offset)
        .unwrap_or(content.len());
    let assign = content[start + marker.len()..declaration_end]
        .find('=')
        .map(|offset| start + marker.len() + offset)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("{name} initializer not found"))
        })?;

    let init_start = content[assign + 1..]
        .find(|character: char| !character.is_whitespace())
        .map(|offset| assign + 1 + offset)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("{name} initializer not found"))
        })?;
    if content.as_bytes()[init_start] != b'[' {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{name} initializer not found"),
        ));
    }

    // rustfmt either closes a short array on the opening line or places the top-level `];` at
    // column zero. Array body lines are indented. Stop at the first other unindented line so a
    // malformed target cannot consume syntax (including brackets in strings or comments) from a
    // later item.
    let first_line_end = content[init_start..]
        .find('\n')
        .map(|offset| init_start + offset)
        .unwrap_or(content.len());
    let mut terminator_end = content[init_start..first_line_end]
        .find("];")
        .map(|offset| init_start + offset + 2);
    let mut line_start = first_line_end.saturating_add(1);
    while terminator_end.is_none() && line_start < content.len() {
        let line_end = content[line_start..]
            .find('\n')
            .map(|offset| line_start + offset)
            .unwrap_or(content.len());
        let line = &content[line_start..line_end];
        if line.starts_with("];") {
            terminator_end = Some(line_start + 2);
        } else if !line.is_empty() && !line.as_bytes().first().is_some_and(u8::is_ascii_whitespace)
        {
            break;
        }
        line_start = line_end.saturating_add(1);
    }
    let terminator_end = terminator_end.ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, format!("{name} terminator not found"))
    })?;
    content.replace_range(assign..terminator_end, &format!("= [{body}];"));
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
    preprocessed_commitments: PreprocessedCommitments,
    constraints_eval: String,
    air_config: String,
    vm_ood_frames: String,
    vm_parameters: String,
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec};

    use super::*;

    #[test]
    fn generated_felt_array_replacement_is_rustfmt_safe_and_fails_closed() {
        let values = [1, 2, 3, 4].map(Felt::new_unchecked);
        let name = "RELATION_DIGEST";
        let declaration = "pub const RELATION_DIGEST: [Felt; 4]";
        let body = "\n    Felt::new_unchecked(1),\n    Felt::new_unchecked(2),\n    \
                    Felt::new_unchecked(3),\n    Felt::new_unchecked(4),\n";
        let following = "pub(crate) const UNTOUCHED: &str = \"];\";\n";

        let mut wrapped = format!("{declaration} =\n    [0, 0, 0, 0];\n\n{following}");
        replace_felt_array_const(&mut wrapped, name, &values).unwrap();
        assert_eq!(wrapped, format!("{declaration} = [{body}];\n\n{following}"));

        let mut malformed = format!("{declaration} = [0, 0, 0, 0;\n\n{following}");
        let original = malformed.clone();
        let error = replace_felt_array_const(&mut malformed, name, &values).unwrap_err();
        assert!(error.to_string().contains("terminator not found"));
        assert_eq!(malformed, original);

        let mut duplicate =
            format!("{declaration} = [0, 0, 0, 0];\n{declaration} = [0, 0, 0, 0];\n");
        let original = duplicate.clone();
        let error = replace_felt_array_const(&mut duplicate, name, &values).unwrap_err();
        assert!(error.to_string().contains("declared more than once"));
        assert_eq!(duplicate, original);
    }

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

    /// Synthetic row widths with configurable preprocessed occupancy and the VM auxiliary layout.
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
            ood_pipe_blocks: row_width * EXT_DEGREE / ADV_PIPE_BLOCK_FELTS,
            ood_evaluations_ptr: 0,
            aux_bus_boundary_ptr: 0,
            auxiliary_ace_inputs_ptr: 0,
            // Auxiliary slots: 10 shared, 12 selectors, 4 fold coefficients, 2 padding.
            ace_circuit_stream_ptr: 28 * EXT_DEGREE,
            ood_scatter_table_ptr: 0,
            air_selector_offset: 10 * EXT_DEGREE,
            fold_coefficient_offset: 22 * EXT_DEGREE,
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
    fn deep_query_parameters_reject_empty_or_unaligned_rows() {
        let mut geometry = scatter_test_geometry(&[0, 0, 0, 8]);
        for invalid_width in [0, EIDOS_BLOCK_WIDTH - 1] {
            geometry.main_width = invalid_width;
            let error = render_vm_parameters(&geometry, &[Felt::ZERO; 4], &[0; 4]).unwrap_err();
            assert!(error.to_string().contains("MAIN query width"), "{error}");
        }
    }

    #[test]
    fn auxiliary_input_layout_rejects_reversed_or_truncated_regions() {
        let assert_rejected = |geometry: &VmGeometry, expected: &str| {
            let error = render_vm_parameters(geometry, &[Felt::ZERO; 4], &[0; 4]).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(error.to_string(), expected);
        };

        let mut geometry = scatter_test_geometry(&[0, 0, 0, 8]);
        geometry.air_selector_offset = geometry.fold_coefficient_offset + EXT_DEGREE;
        assert_rejected(&geometry, "VM ACE fold coefficients precede per-AIR selectors");

        let mut geometry = scatter_test_geometry(&[0, 0, 0, 8]);
        geometry.auxiliary_ace_inputs_ptr = geometry.ace_circuit_stream_ptr + EXT_DEGREE;
        assert_rejected(&geometry, "VM ACE circuit stream precedes auxiliary inputs");

        let mut geometry = scatter_test_geometry(&[0, 0, 0, 8]);
        geometry.ace_circuit_stream_ptr = geometry.fold_coefficient_offset;
        assert_rejected(
            &geometry,
            "VM ACE auxiliary allocation cannot fit STARK variables, selectors, and \
             fold coefficients",
        );
    }

    #[test]
    fn proof_order_map_pointers_must_fit_u32_memory() {
        let mut geometry = scatter_test_geometry(&[0, 0, 0, 8]);
        let table_felts = vm_scatter_plan(&geometry).unwrap().table_felts();
        // Exercise the first pointer exceeding u32, then only the second. On a 32-bit host,
        // checked usize addition rejects these cases before the encoded-address range check.
        for (offset, name) in [
            (table_felts - 1, "PROOF_ORDER_POSITIONS_PTR"),
            (table_felts + MIDEN_AIR_COUNT - 1, "PROOF_ORDER_IDS_PTR"),
        ] {
            geometry.ood_scatter_table_ptr = u32::MAX as usize - offset;
            let error = render_vm_parameters(&geometry, &[Felt::ZERO; 4], &[0; 4]).unwrap_err();
            let expected = if usize::BITS == 32 {
                "VM proof-order map overflows".into()
            } else {
                format!("VM {name} exceeds u32 memory")
            };
            assert_eq!(error.to_string(), expected);
        }
    }
}
