//! Regeneration tool for the PVM recursive-verifier MASM artifacts.
//!
//! One order-invariant circuit serves every proof ordering, so the tool compiles that circuit from
//! the captured chiplet AIRs and emits the memory layout, the out-of-domain ingest hook, and the
//! constraint evaluator from the same relation geometry. Both modes first compare the circuit
//! digest, relation digest, and circuit shape against the identity pinned in
//! `miden_air::precompiles::protocol`; generation never accepts a new identity. `--check` then
//! byte-compares every rendered file against its checked-in copy. The relation wrapper and query
//! loaders import generated parameters; their procedure bodies are not regeneration inputs.

use std::{
    fmt::Write as _,
    format, io, println,
    string::{String, ToString},
    vec::Vec,
};

use miden_ace::{
    EXT_DEGREE, FoldCoefficientStaging, InputKey, InputLayout, LayoutKind,
    MasmConstraintsEvalConfig, render_masm_constraints_eval,
};
use miden_air::precompiles::{NUM_CHIPLETS, security as pvm_security};
use miden_air_definitions::precompiles::relation::{self, CapturedPvmRelation, HeightRule};
use miden_core::{Felt, Word, crypto::hash::Eidos};
use miden_crypto::hash::eidos::{BLOCK_LEN as EIDOS_BLOCK_WIDTH, domains::LMCS_LEAF};
use miden_stark::{QuotientRecompositionInputs, quotient_recomposition_inputs};

use super::{
    ace::PvmRecursiveAceCircuit,
    ace_constants::{
        GENERATED_BY, PVM_ACE_CIRCUIT_DIGEST, PVM_CIRCUIT_SHAPE, PVM_PREPROCESSED_COMMITMENT,
        PVM_RELATION_DIGEST, relation_digest_for_circuit,
    },
    pvm_ood_frames::{
        OOD_SCATTER_TABLE_FELTS, PvmOodGeometry, PvmScatterTableLayout, pvm_scatter_table_layout,
        render_pvm_ood_frames,
    },
};

const PVM_CONSTRAINTS_EVAL_PATH: &str = "../../lib/core/asm/sys/pvm/constraints_eval.masm";
const PVM_PARAMETERS_PATH: &str = "../../lib/core/asm/sys/pvm/parameters.masm";
const PVM_FIXED_BOUNDARY_PATH: &str = "../../lib/core/asm/sys/pvm/fixed_boundary.masm";
const PVM_LAYOUT_PATH: &str = "../../lib/core/asm/sys/pvm/layout.masm";
const PVM_OOD_FRAMES_PATH: &str = "../../lib/core/asm/sys/pvm/ood_frames.masm";

/// Fixed 4-Ki-felt boundary after the VM relation's reserved ACE stream region. The PVM's complete
/// READ section starts here; its aux-randomness anchor is later because four public EF inputs
/// precede it.
const PVM_READ_START: u32 = 3_225_432_064;
/// Start of the VM relation's next scratch region; the PVM allocation must end before it.
const NEXT_VM_REGION_START: u32 = 3_238_002_688;
/// `pos_by_id` is padded to a whole word so the following `id_by_pos` table is word-aligned.
const PROOF_ORDER_POSITIONS_FELTS: u32 = (NUM_CHIPLETS as u32).next_multiple_of(4);

/// Whether [`run`] rewrites the committed artifacts (`Write`) or byte-compares a freshly
/// built set against them (`Check`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Check,
    Write,
}

/// Runs write (`--write`) or staleness-check (`--check`) mode.
pub fn run(mode: Mode) -> Result<(), String> {
    let artifacts = compute()?;
    pinned_identity_matches(&artifacts)?;
    match mode {
        Mode::Check => check(&artifacts),
        Mode::Write => write(&artifacts).map_err(|e| format!("{e}")),
    }
}

struct GeneratedArtifacts {
    /// Eidos digest of the accepted ACE circuit's instruction stream.
    circuit_digest: Word,
    /// Relation digest binding that circuit into the Fiat-Shamir transcript.
    relation_digest: [Felt; 4],
    /// Shape of the encoded circuit stream.
    shape: CircuitShape,
    /// Generated PVM relation layout, derived from the ACE `InputLayout`.
    layout_masm: String,
    /// Generated PVM out-of-domain ingest hook, derived from the chiplet widths.
    ood_frames_masm: String,
    /// Protocol constants and query geometry for the PVM MASM verifier.
    parameters_masm: String,
    /// Fixed-environment catalogue expanded into the assembly reduction templates.
    fixed_boundary_masm: String,
    /// Generated PVM constraint evaluator, rendered from the same circuit metadata.
    constraints_eval_masm: String,
}

#[derive(Clone, Debug)]
struct PvmReadLayout {
    regions: Vec<PvmReadRegion>,
    stream_ptr: u32,
    query_row_felts: u32,
    /// Felt offset of chiplet 0's fold-coefficient slot from `AUXILIARY_ACE_INPUTS_PTR`.
    fold_coefficient_offset: usize,
}

#[derive(Clone, Debug)]
struct PvmReadRegion {
    constant: &'static str,
    ptr: u32,
    extent: u32,
}

/// The encoded ACE stream's shape, which an in-VM verifier needs as compile-time constants: how
/// much to read and the digest the loaded stream must reproduce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CircuitShape {
    num_inputs: usize,
    num_eval_gates: usize,
    stream_len: usize,
}

impl PvmReadLayout {
    /// Derive every READ-region boundary from the circuit's own `InputLayout`.
    fn from_input_layout(layout: &InputLayout) -> Result<Self, String> {
        let boundary_specs = [
            ("PUBLIC_INPUTS_PTR", InputKey::Public(0)),
            ("AUX_RAND_ELEM_PTR", InputKey::AuxRandBeta),
            ("PREPROCESSED_CURRENT_PTR", InputKey::Preprocessed { offset: 0, index: 0 }),
            ("MAIN_CURRENT_PTR", InputKey::Main { offset: 0, index: 0 }),
            ("AUX_CURRENT_PTR", InputKey::AuxCoord { offset: 0, index: 0, coord: 0 }),
            (
                "QUOTIENT_CURRENT_PTR",
                InputKey::QuotientChunkCoord { offset: 0, chunk: 0, coord: 0 },
            ),
            ("PREPROCESSED_NEXT_PTR", InputKey::Preprocessed { offset: 1, index: 0 }),
            ("MAIN_NEXT_PTR", InputKey::Main { offset: 1, index: 0 }),
            ("AUX_NEXT_PTR", InputKey::AuxCoord { offset: 1, index: 0, coord: 0 }),
            (
                "QUOTIENT_NEXT_PTR",
                InputKey::QuotientChunkCoord { offset: 1, chunk: 0, coord: 0 },
            ),
            ("AUX_BUS_BOUNDARY_PTR", InputKey::AuxBusBoundary(0)),
            ("AUXILIARY_ACE_INPUTS_PTR", InputKey::Alpha),
        ];

        let mut boundaries = Vec::with_capacity(boundary_specs.len() + 1);
        for &(constant, key) in &boundary_specs {
            let index = layout.index(key).ok_or_else(|| {
                format!("PVM ACE layout is missing boundary {constant} ({key:?})")
            })?;
            let felt_offset = u32::try_from(index.checked_mul(2).ok_or_else(|| {
                format!("PVM ACE layout boundary {constant} overflows its felt offset")
            })?)
            .map_err(|_| format!("PVM ACE layout boundary {constant} exceeds u32 memory"))?;
            let ptr = PVM_READ_START
                .checked_add(felt_offset)
                .ok_or_else(|| format!("PVM ACE layout boundary {constant} overflows u32"))?;
            boundaries.push((constant, ptr));
        }

        if boundaries.first().map(|(_, ptr)| *ptr) != Some(PVM_READ_START) {
            return Err("PVM public inputs must begin at the complete READ-section anchor".into());
        }
        if boundaries.windows(2).any(|pair| pair[0].1 >= pair[1].1) {
            return Err("PVM ACE READ-region boundaries are not strictly increasing".into());
        }

        let read_extent = u32::try_from(
            layout
                .total_inputs
                .checked_mul(2)
                .ok_or_else(|| "PVM ACE READ extent overflows usize".to_string())?,
        )
        .map_err(|_| "PVM ACE READ extent exceeds u32 memory".to_string())?;
        let stream_ptr = PVM_READ_START
            .checked_add(read_extent)
            .ok_or_else(|| "PVM ACE stream pointer overflows u32".to_string())?;
        boundaries.push(("ACE_CIRCUIT_STREAM_PTR", stream_ptr));

        // The staged fold coefficients live at the end of the auxiliary-input region; a region
        // that ended before them would silently overwrite the ACE stream reservation.
        let fold_coefficients_end =
            layout.index(InputKey::MultiAirFoldCoeff(NUM_CHIPLETS - 1)).ok_or_else(|| {
                "PVM ACE layout is missing its last fold-coefficient slot".to_string()
            })? + 1;
        if fold_coefficients_end > layout.total_inputs {
            return Err("PVM fold coefficients fall outside the declared READ section".into());
        }
        let alpha_index = layout
            .index(InputKey::Alpha)
            .ok_or_else(|| "PVM ACE layout is missing its stark-vars base".to_string())?;
        let first_fold_coefficient =
            layout.index(InputKey::MultiAirFoldCoeff(0)).ok_or_else(|| {
                "PVM ACE layout is missing its first fold-coefficient slot".to_string()
            })?;
        let fold_coefficient_offset = first_fold_coefficient
            .checked_sub(alpha_index)
            .ok_or_else(|| "PVM fold coefficients precede the stark-vars base".to_string())?
            .checked_mul(EXT_DEGREE)
            .ok_or_else(|| "PVM fold-coefficient felt offset overflows usize".to_string())?;

        let regions = boundaries
            .windows(2)
            .map(|pair| PvmReadRegion {
                constant: pair[0].0,
                ptr: pair[0].1,
                extent: pair[1].1 - pair[0].1,
            })
            .collect();

        let current_row_start = layout
            .index(InputKey::Preprocessed { offset: 0, index: 0 })
            .ok_or_else(|| "PVM ACE layout is missing the current-row start".to_string())?;
        let next_row_start = layout
            .index(InputKey::Preprocessed { offset: 1, index: 0 })
            .ok_or_else(|| "PVM ACE layout is missing the next-row start".to_string())?;
        let query_row_felts = u32::try_from(
            next_row_start
                .checked_sub(current_row_start)
                .ok_or_else(|| "PVM next-row boundary precedes the current row".to_string())?,
        )
        .map_err(|_| "PVM query row exceeds u32 memory".to_string())?;

        Ok(Self {
            regions,
            stream_ptr,
            query_row_felts,
            fold_coefficient_offset,
        })
    }
}

/// Compile the canonical circuit from the captured chiplet AIRs and derive every generated
/// artifact from it.
fn compute() -> Result<GeneratedArtifacts, String> {
    let captured = CapturedPvmRelation::new().map_err(|e| format!("{e}"))?;
    let compiled = captured.compile().map_err(|e| format!("{e}"))?;
    let source = compiled.build_circuit(LayoutKind::Masm).map_err(|e| format!("{e}"))?;
    let input_layout = source.layout();
    let circuit = PvmRecursiveAceCircuit::try_from(source.to_ace().map_err(|e| format!("{e}"))?)
        .map_err(|e| format!("{e}"))?;
    let read_layout = PvmReadLayout::from_input_layout(input_layout)?;
    let num_quotient_chunks = input_layout.counts.num_quotient_chunks;
    if !num_quotient_chunks.is_power_of_two() {
        return Err(format!(
            "PVM quotient chunk count {num_quotient_chunks} is not a power of two"
        ));
    }
    let quotient_inputs = quotient_recomposition_inputs::<Felt>(
        num_quotient_chunks.ilog2() as u8,
        miden_air::precompiles::stark_config::precompile_pcs_params().log_blowup(),
    )
    .map_err(|err| err.to_string())?;

    let shape = CircuitShape {
        num_inputs: circuit.num_inputs,
        num_eval_gates: circuit.num_eval_gates,
        stream_len: circuit.stream_len,
    };
    let circuit_digest = circuit.commitment;
    let relation_digest = relation_digest_for_circuit(&circuit_digest);
    // The setup commitment is a trusted verifier input pinned in `miden_air::precompiles`, whose
    // tests rebuild it from the authored setup trace.
    let preprocessed_commitment = Word::new(PVM_PREPROCESSED_COMMITMENT.map(Felt::new_unchecked));
    let protocol = relation::protocol();

    let geometry = PvmOodGeometry::from_compiled(compiled.geometry(), input_layout)?;
    let scatter_table_layout = pvm_scatter_table_layout(&geometry)?;
    let layout_masm = render_pvm_layout(&read_layout, shape.stream_len, &scatter_table_layout)?;
    let stream_len = u32::try_from(shape.stream_len)
        .map_err(|_| "PVM ACE stream length exceeds u32 memory".to_string())?;
    let scratch = pvm_scratch_allocation(&read_layout, stream_len)?;
    let ood_frames_masm =
        render_pvm_ood_frames(&geometry, scratch.proof_order_ids_ptr.is_multiple_of(4))?;
    let parameters_masm =
        render_pvm_parameters(&geometry, &protocol, relation_digest, preprocessed_commitment)?;
    let constraints_eval_masm = render_pvm_constraints_eval(
        shape,
        circuit_digest,
        quotient_inputs,
        read_layout.fold_coefficient_offset,
        protocol.max_periodic_log,
    )?;

    Ok(GeneratedArtifacts {
        circuit_digest,
        relation_digest,
        shape,
        layout_masm,
        ood_frames_masm,
        parameters_masm,
        fixed_boundary_masm: crate::recursive::fixed_boundary_codegen::render_fixed_boundary()?,
        constraints_eval_masm,
    })
}

/// Relation-local scratch that follows the ACE READ section, in allocation order.
struct PvmScratchAllocation {
    stream_end: u32,
    bus_gamma_ptr: u32,
    c_total_ptr: u32,
    current_trace_row_ptr: u32,
    preprocessed_com_ptr: u32,
    ood_scatter_table_ptr: u32,
    proof_order_positions_ptr: u32,
    proof_order_ids_ptr: u32,
    allocation_end: u32,
}

/// Lays out the scratch regions after a `stream_len`-felt circuit stream, checking every
/// alignment their MASM consumers rely on.
fn pvm_scratch_allocation(
    layout: &PvmReadLayout,
    stream_len: u32,
) -> Result<PvmScratchAllocation, String> {
    let stream_end = layout
        .stream_ptr
        .checked_add(stream_len)
        .ok_or_else(|| "PVM ACE stream allocation overflows u32".to_string())?;
    let bus_gamma_ptr = stream_end;
    let c_total_ptr = bus_gamma_ptr
        .checked_add(4)
        .ok_or_else(|| "PVM bus-gamma allocation overflows u32".to_string())?;
    let current_trace_row_ptr = c_total_ptr
        .checked_add(4)
        .ok_or_else(|| "PVM boundary-correction allocation overflows u32".to_string())?;
    if !current_trace_row_ptr.is_multiple_of(8) {
        return Err(format!(
            "PVM current-trace-row base {current_trace_row_ptr} is not 8-felt aligned, which \
             `adv_pipe` requires"
        ));
    }
    let preprocessed_com_ptr = current_trace_row_ptr
        .checked_add(layout.query_row_felts)
        .ok_or_else(|| "PVM current-row allocation overflows u32".to_string())?;
    let ood_scatter_table_ptr = preprocessed_com_ptr
        .checked_add(4)
        .ok_or_else(|| "PVM preprocessed-commitment allocation overflows u32".to_string())?;
    if !ood_scatter_table_ptr.is_multiple_of(4) {
        return Err(format!(
            "PVM out-of-domain scatter table base {ood_scatter_table_ptr} is not 4-felt \
             (word) aligned, which its `mem_storew_le`/`dynexec` entries require"
        ));
    }
    let proof_order_positions_ptr = ood_scatter_table_ptr
        .checked_add(OOD_SCATTER_TABLE_FELTS)
        .ok_or_else(|| "PVM out-of-domain scatter table overflows u32".to_string())?;
    // The ten live `pos_by_id` cells are padded to a whole word so that `id_by_pos`, which the
    // proof-order pass writes with word stores, starts word-aligned.
    let proof_order_ids_ptr = proof_order_positions_ptr
        .checked_add(PROOF_ORDER_POSITIONS_FELTS)
        .ok_or_else(|| "PVM proof-order position table overflows u32".to_string())?;
    let allocation_end = proof_order_ids_ptr
        .checked_add(NUM_CHIPLETS as u32)
        .ok_or_else(|| "PVM proof-order id table overflows u32".to_string())?;
    if allocation_end > NEXT_VM_REGION_START {
        return Err(format!(
            "PVM ACE allocation {PVM_READ_START}..{allocation_end} reaches the VM scratch region starting at {NEXT_VM_REGION_START}"
        ));
    }

    Ok(PvmScratchAllocation {
        stream_end,
        bus_gamma_ptr,
        c_total_ptr,
        current_trace_row_ptr,
        preprocessed_com_ptr,
        ood_scatter_table_ptr,
        proof_order_positions_ptr,
        proof_order_ids_ptr,
        allocation_end,
    })
}

fn render_pvm_layout(
    layout: &PvmReadLayout,
    stream_len: usize,
    scatter_table: &PvmScatterTableLayout,
) -> Result<String, String> {
    let stream_len = u32::try_from(stream_len)
        .map_err(|_| "PVM ACE stream length exceeds u32 memory".to_string())?;
    let PvmScratchAllocation {
        stream_end,
        bus_gamma_ptr,
        c_total_ptr,
        current_trace_row_ptr,
        preprocessed_com_ptr,
        ood_scatter_table_ptr,
        proof_order_positions_ptr,
        proof_order_ids_ptr,
        allocation_end,
    } = pvm_scratch_allocation(layout, stream_len)?;
    let proof_order_padding = PROOF_ORDER_POSITIONS_FELTS - NUM_CHIPLETS as u32;
    let proof_order_liveness = if proof_order_padding == 0 {
        format!("All {NUM_CHIPLETS} cells are live.")
    } else {
        format!(
            "The first {NUM_CHIPLETS} cells are live and the final {proof_order_padding} pad the\n\
             ### following table to a word boundary."
        )
    };
    let pair_end = scatter_table
        .proof_order_pairs
        .end
        .checked_sub(1)
        .filter(|end| *end >= scatter_table.proof_order_pairs.start)
        .ok_or_else(|| "PVM scatter-table pair range is empty".to_string())?;
    let digest_end = scatter_table
        .pipe_digests
        .end
        .checked_sub(1)
        .filter(|end| *end >= scatter_table.pipe_digests.start)
        .ok_or_else(|| "PVM scatter-table digest range is empty".to_string())?;

    let mut out = format!(
        r#"# GENERATED by `{GENERATED_BY}` — do not edit by hand.
### PVM relation memory layout.
###
### The ACE READ section is one dense vector of quadratic-extension inputs.
### Every boundary below is derived from the PVM circuit's InputLayout; each
### input occupies two base-field felts. The complete allocation, including relation-local
### scratch after the stream, is the half-open range {PVM_READ_START}..{allocation_end}.
### Per-AIR heights remain in the generic 16-cell array, in ChipletAir::all()
### order; the PVM wrapper supplies the relation count and that shared base.

use miden::core::stark::types

"#
    );

    for region in &layout.regions {
        writeln!(
            out,
            "### {}: {} felts at {}..{}.",
            region.constant,
            region.extent,
            region.ptr,
            region.ptr + region.extent
        )
        .expect("writing to String cannot fail");
        if matches!(
            region.constant,
            "PUBLIC_INPUTS_PTR"
                | "AUX_RAND_ELEM_PTR"
                | "PREPROCESSED_CURRENT_PTR"
                | "AUX_BUS_BOUNDARY_PTR"
                | "AUXILIARY_ACE_INPUTS_PTR"
        ) {
            writeln!(out, "const {} = {}\n", region.constant, region.ptr)
                .expect("writing to String cannot fail");
        } else {
            out.push('\n');
        }
    }
    write!(
        out,
        r#"### {stream_len} felts: {stream_ptr}..{stream_end}.
const ACE_CIRCUIT_STREAM_PTR = {stream_ptr}

### 4 felts: {bus_gamma_ptr}..{c_total_ptr}. Stores gamma = beta^18.
const BUS_GAMMA_PTR = {bus_gamma_ptr}

### 4 felts: {c_total_ptr}..{current_trace_row_ptr}. Stores the two-felt fixed-boundary correction; the remaining two felts are reserved.
const C_TOTAL_PTR = {c_total_ptr}

### {query_row_felts} felts: {current_trace_row_ptr}..{preprocessed_com_ptr}. Stores one opened query row in commitment-group order.
const CURRENT_TRACE_ROW_PTR = {current_trace_row_ptr}

### 4 felts: {preprocessed_com_ptr}..{ood_scatter_table_ptr}. Stores the trusted preprocessed-tree commitment for DEEP openings.
const PREPROCESSED_COM_PTR = {preprocessed_com_ptr}

### {OOD_SCATTER_TABLE_FELTS} felts: {ood_scatter_table_ptr}..{proof_order_positions_ptr}. Out-of-domain ingest scatter table:
###
###   +0            base address of the out-of-domain row being ingested
###   +{pair_start:<3}.. +{pair_end:<6}per proof position, in stream order: (row-relative destination, digest address)
###   +{digest_start:<3}.. +{digest_end:<6}`pipe_k` procedure digests reached by `dynexec`, one word each
###
### The internal offsets and the reserve's sufficiency are owned by the regeneration tool,
### which derives them from the chiplet widths and fills `sys/pvm/ood_frames.masm`
### accordingly.
const OOD_SCATTER_TABLE_PTR = {ood_scatter_table_ptr}

### {PROOF_ORDER_POSITIONS_FELTS} felts: {proof_order_positions_ptr}..{proof_order_ids_ptr}. `pos_by_id`: the position of each
### chiplet, in ChipletAir::all() order, within the height-sorted proof order.
### {proof_order_liveness}
### Staged once per proof by `sys/pvm/ood_frames.masm::stage_proof_order_maps`; read by both
### ingest scatters.
const PROOF_ORDER_POSITIONS_PTR = {proof_order_positions_ptr}

### {NUM_CHIPLETS} felts: {proof_order_ids_ptr}..{allocation_end}. `id_by_pos`: the
### ChipletAir::all() index committed at each proof position. Staged with `pos_by_id`;
### read by the reverse fold-coefficient walk in `sys/pvm/constraints_eval.masm`.
const PROOF_ORDER_IDS_PTR = {proof_order_ids_ptr}
"#,
        stream_ptr = layout.stream_ptr,
        query_row_felts = layout.query_row_felts,
        pair_start = scatter_table.proof_order_pairs.start,
        digest_start = scatter_table.pipe_digests.start,
    )
    .expect("writing to String cannot fail");

    for (accessor, constant) in [
        ("public_inputs_ptr", "PUBLIC_INPUTS_PTR"),
        ("aux_rand_elem_ptr", "AUX_RAND_ELEM_PTR"),
        ("preprocessed_current_ptr", "PREPROCESSED_CURRENT_PTR"),
        ("aux_bus_boundary_ptr", "AUX_BUS_BOUNDARY_PTR"),
        ("auxiliary_ace_inputs_ptr", "AUXILIARY_ACE_INPUTS_PTR"),
        ("ace_circuit_stream_ptr", "ACE_CIRCUIT_STREAM_PTR"),
        ("bus_gamma_ptr", "BUS_GAMMA_PTR"),
        ("c_total_ptr", "C_TOTAL_PTR"),
        ("current_trace_row_ptr", "CURRENT_TRACE_ROW_PTR"),
        ("preprocessed_com_ptr", "PREPROCESSED_COM_PTR"),
        ("ood_scatter_table_ptr", "OOD_SCATTER_TABLE_PTR"),
        ("proof_order_positions_ptr", "PROOF_ORDER_POSITIONS_PTR"),
        ("proof_order_ids_ptr", "PROOF_ORDER_IDS_PTR"),
    ] {
        writeln!(out, "\npub proc {accessor}() -> types::Address\n    push.{constant}\nend")
            .expect("writing to String cannot fail");
    }

    Ok(out)
}

fn render_pvm_constraints_eval(
    shape: CircuitShape,
    circuit_digest: Word,
    quotient_inputs: QuotientRecompositionInputs<Felt>,
    fold_coefficient_offset: usize,
    max_cycle_len_log: u32,
) -> Result<String, String> {
    render_masm_constraints_eval(&MasmConstraintsEvalConfig {
        generated_by: GENERATED_BY,
        layout_module: "miden::core::sys::pvm::layout",
        num_inputs: shape.num_inputs,
        num_eval_gates: shape.num_eval_gates,
        stream_len: shape.stream_len,
        max_cycle_len_log,
        num_airs: NUM_CHIPLETS,
        fold_coefficients: FoldCoefficientStaging {
            id_by_pos_ptr: "exec.layout::proof_order_ids_ptr",
            coefficient_offset: fold_coefficient_offset,
        },
        quotient_inputs,
        circuit_digest,
    })
    .map_err(|err| err.to_string())
}

fn render_pvm_parameters(
    geometry: &PvmOodGeometry,
    protocol: &relation::RelationProtocol,
    relation_digest: [Felt; 4],
    preprocessed_commitment: Word,
) -> Result<String, String> {
    let mut output = String::from(
        "# Generated by `make regenerate-pvm-constants`. Do not edit.\n\n\
         # Protocol commitments under the native Eidos configuration.\n",
    );
    for (prefix, word) in [
        ("RELATION_DIGEST", Word::new(relation_digest)),
        ("PREPROCESSED_COMMITMENT", preprocessed_commitment),
    ] {
        for (index, felt) in word.iter().enumerate() {
            writeln!(output, "pub const {prefix}_{index} = {}", felt.as_canonical_u64()).unwrap();
        }
    }
    output.push_str("\n# Security descriptor from miden_air::precompiles::security.\n");
    for (name, value) in [
        ("MAX_MESSAGE_WIDTH", u64::from(pvm_security::LOOKUP_SHAPE.max_message_width)),
        (
            "NUM_COMPOSED_CONSTRAINTS",
            u64::from(pvm_security::AIR_SHAPE.num_composed_constraints),
        ),
        (
            "MAX_CONSTRAINT_DEGREE",
            u64::from(pvm_security::AIR_SHAPE.max_constraint_degree),
        ),
        (
            "NUM_DEEP_TERMS",
            u64::from(
                pvm_security::AIR_SHAPE.num_deep_terms.expect("the PVM uses DEEP composition"),
            ),
        ),
        (
            "LOOKUP_FRACTIONS_PER_ROW",
            u64::from(pvm_security::LOOKUP_SHAPE.fractions_per_row),
        ),
        (
            "FIXED_BOUNDARY_LOOKUP_TERMS",
            u64::from(pvm_security::FIXED_BOUNDARY_LOOKUP_TERMS),
        ),
    ] {
        writeln!(output, "pub const {name} = {value}").unwrap();
    }

    output.push_str("\n# Bus-domain scale factors: BusId + 1 from the native relation registry.\n");
    for (name, bus) in [
        ("UINT_VAL_BUS_SCALE", miden_air::precompiles::relations::BusId::UintVal),
        ("EC_GROUP_BUS_SCALE", miden_air::precompiles::relations::BusId::EcGroup),
    ] {
        writeln!(output, "pub const {name} = {}", bus as usize + 1).unwrap();
    }

    let setup_height = miden_air::precompiles::primitives::byte_pair_lut::TRACE_HEIGHT;
    if !setup_height.is_power_of_two() {
        return Err("BytePairLut setup height must be a power of two".into());
    }
    let log_height = setup_height.ilog2();
    let depth = log_height
        + u32::from(miden_air::precompiles::stark_config::precompile_pcs_params().log_blowup());
    let index_mask = 1u64
        .checked_shl(depth)
        .and_then(|size| u32::try_from(size - 1).ok())
        .ok_or_else(|| "PVM preprocessed LDE depth exceeds u32 indices".to_string())?;
    output.push_str("\n# BytePairLut setup height and PCS-expanded Merkle tree.\n");
    writeln!(output, "pub const PREPROCESSED_TRACE_LOG_HEIGHT = {log_height}").unwrap();
    writeln!(output, "pub const PREPROCESSED_TREE_DEPTH = {depth}").unwrap();
    writeln!(output, "pub const PREPROCESSED_INDEX_MASK = {index_mask}").unwrap();

    output.push_str(
        "\n# Minimum log2 heights for non-fixed AIRs, indexed in ChipletAir::all() order.\n\
         # The row bound is max(2, longest periodic cycle, preprocessed trace height).\n",
    );
    for (index, height) in protocol.heights.iter().enumerate() {
        if let HeightRule::Minimum(log_height) = height {
            writeln!(output, "pub const MIN_LOG_HEIGHT_{index} = {log_height}").unwrap();
        }
    }

    output.push_str(
        "\n# Query-row blocks and LMCS leaf frames, in commitment-group order.\n\
                     # Each block contains eight base felts.\n",
    );
    for (blocks_name, init_cv_name, width) in geometry.deep_query_groups() {
        if width == 0 || !width.is_multiple_of(EIDOS_BLOCK_WIDTH) {
            return Err(format!(
                "PVM {blocks_name} width {width} must be a positive multiple of {EIDOS_BLOCK_WIDTH}"
            ));
        }
        let encoded_len = u32::try_from(width)
            .map_err(|_| format!("PVM {init_cv_name} LMCS encoded length exceeds u32"))?;
        let init_cv = Eidos::init_chaining_word(LMCS_LEAF, encoded_len);
        writeln!(output, "pub const {blocks_name} = {}", width / EIDOS_BLOCK_WIDTH).unwrap();
        writeln!(output, "pub const {init_cv_name} = {}", masm_word_literal(init_cv)).unwrap();
    }
    Ok(output)
}

/// Compares the compiled circuit with the relation identity pinned in `miden-air`.
fn pinned_identity_matches(artifacts: &GeneratedArtifacts) -> Result<(), String> {
    const PINS_PATH: &str = "crates/air/generated/src/precompiles/protocol.rs";
    for (name, actual, expected) in [
        ("relation_digest", PVM_RELATION_DIGEST, artifacts.relation_digest),
        ("ace_circuit_digest", PVM_ACE_CIRCUIT_DIGEST, *artifacts.circuit_digest),
    ] {
        if actual.map(Felt::new_unchecked) != expected {
            return Err(format!(
                "pinned {name} in {PINS_PATH} is stale: expected {:?}; an intentional relation \
                 change must update the pins before regenerating",
                expected.map(|felt| felt.as_canonical_u64())
            ));
        }
    }
    let shape = (
        artifacts.shape.num_inputs,
        artifacts.shape.num_eval_gates,
        artifacts.shape.stream_len,
    );
    if PVM_CIRCUIT_SHAPE != shape {
        return Err(format!(
            "the build-compiled PVM circuit shape {PVM_CIRCUIT_SHAPE:?} differs from the \
             regenerated shape {shape:?}"
        ));
    }
    Ok(())
}

fn check(artifacts: &GeneratedArtifacts) -> Result<(), String> {
    for (path, rendered) in [
        (PVM_LAYOUT_PATH, &artifacts.layout_masm),
        (PVM_PARAMETERS_PATH, &artifacts.parameters_masm),
        (PVM_FIXED_BOUNDARY_PATH, &artifacts.fixed_boundary_masm),
        (PVM_OOD_FRAMES_PATH, &artifacts.ood_frames_masm),
        (PVM_CONSTRAINTS_EVAL_PATH, &artifacts.constraints_eval_masm),
    ] {
        if read_generated_file(path)? != *rendered {
            return Err(format!("{path} is stale; run `make regenerate-pvm-constants`"));
        }
    }
    println!("PVM MASM artifacts are up to date");
    Ok(())
}

fn write(artifacts: &GeneratedArtifacts) -> io::Result<()> {
    write_generated_file(PVM_LAYOUT_PATH, &artifacts.layout_masm)?;
    write_generated_file(PVM_PARAMETERS_PATH, &artifacts.parameters_masm)?;
    write_generated_file(PVM_FIXED_BOUNDARY_PATH, &artifacts.fixed_boundary_masm)?;
    write_generated_file(PVM_OOD_FRAMES_PATH, &artifacts.ood_frames_masm)?;
    write_generated_file(PVM_CONSTRAINTS_EVAL_PATH, &artifacts.constraints_eval_masm)?;
    Ok(())
}

fn generated_path(relative: &str) -> String {
    format!("{}/{}", env!("CARGO_MANIFEST_DIR"), relative)
}

fn read_generated_file(relative: &str) -> Result<String, String> {
    let path = generated_path(relative);
    std::fs::read_to_string(&path).map_err(|err| format!("failed to read {path}: {err}"))
}

fn write_generated_file(relative: &str, contents: &str) -> io::Result<()> {
    let path = generated_path(relative);
    std::fs::write(&path, contents)
        .map_err(|err| io::Error::new(err.kind(), format!("failed to write {path}: {err}")))?;
    println!("wrote {path}");
    Ok(())
}

fn masm_word_literal(word: Word) -> String {
    let elements = word.as_elements();
    format!(
        "[{}, {}, {}, {}]",
        elements[0].as_canonical_u64(),
        elements[1].as_canonical_u64(),
        elements[2].as_canonical_u64(),
        elements[3].as_canonical_u64(),
    )
}

#[cfg(test)]
mod tests {
    use miden_ace::LayoutKind;
    use miden_air_definitions::precompiles::relation::CapturedPvmRelation;

    use super::{
        NEXT_VM_REGION_START, PROOF_ORDER_POSITIONS_FELTS, PvmReadLayout, pvm_scratch_allocation,
    };

    #[test]
    fn pvm_proof_order_tables_are_disjoint_and_word_aligned() {
        let captured = CapturedPvmRelation::new().unwrap();
        let compiled = captured.compile().unwrap();
        let canonical = compiled.build_circuit(LayoutKind::Masm).unwrap();
        let read_layout = PvmReadLayout::from_input_layout(canonical.layout()).unwrap();
        let circuit = miden_air::precompiles::protocol::recursive_circuit();
        let stream_len = u32::try_from(circuit.stream_len).unwrap();
        let scratch = pvm_scratch_allocation(&read_layout, stream_len).unwrap();

        assert!(scratch.proof_order_positions_ptr.is_multiple_of(4));
        assert!(scratch.proof_order_ids_ptr.is_multiple_of(4));
        assert_eq!(
            scratch.proof_order_ids_ptr - scratch.proof_order_positions_ptr,
            PROOF_ORDER_POSITIONS_FELTS,
            "pos_by_id must reserve its word-aligned extent before id_by_pos"
        );
        assert_eq!(
            scratch.allocation_end - scratch.proof_order_ids_ptr,
            miden_air::precompiles::NUM_CHIPLETS as u32,
            "id_by_pos must reserve exactly one cell per chiplet"
        );
        assert!(scratch.allocation_end <= NEXT_VM_REGION_START);
    }
}
