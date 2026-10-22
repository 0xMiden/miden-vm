use std::{
    fmt::Write as _,
    format,
    string::{String, ToString},
    vec::Vec,
};

use askama::Template;
use miden_ace::{
    EXT_DEGREE, FoldCoefficientStaging, InputKey, InputLayout, LayoutKind,
    MasmConstraintsEvalConfig, RecursiveAceCircuit as PvmRecursiveAceCircuit,
    render_masm_constraints_eval,
};
use miden_air_source::precompile::relation::{self, CapturedPvmRelation};
use miden_core::{Felt, Word, crypto::hash::Eidos};
use miden_crypto::hash::eidos::{BLOCK_LEN as EIDOS_BLOCK_WIDTH, domains::LMCS_LEAF};
use miden_stark::{
    QuotientRecompositionInputs, quotient_recomposition_inputs, security as pvm_security,
};

pub(crate) use crate::GENERATED_BY;
use crate::{
    pvm_ood_frames::{
        OOD_SCATTER_TABLE_FELTS, PvmOodGeometry, PvmScatterTableLayout, pvm_scatter_table_layout,
        render_pvm_ood_frames,
    },
    templates::{PvmDeepQueriesTemplate, PvmModTemplate},
};
/// Fixed 4-Ki-felt boundary after the VM relation's reserved ACE stream region. The PVM's complete
/// READ section starts here; its aux-randomness anchor is later because four public EF inputs
/// precede it.
pub(crate) const PVM_READ_START: u32 = 3_225_432_064;
/// Start of the VM relation's next scratch region; the PVM allocation must end before it.
const NEXT_VM_REGION_START: u32 = 3_238_002_688;
#[derive(Clone, Debug)]
struct PvmReadLayout {
    num_airs: usize,
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
    fn from_input_layout(layout: &InputLayout, num_airs: usize) -> Result<Self, String> {
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
            layout.index(InputKey::MultiAirFoldCoeff(num_airs - 1)).ok_or_else(|| {
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
            num_airs,
            regions,
            stream_ptr,
            query_row_felts,
            fold_coefficient_offset,
        })
    }
}

/// Render the complete production PVM relation.
pub(crate) fn render(modules: &mut Vec<crate::RenderedModule>) -> Result<(), String> {
    let captured = CapturedPvmRelation::new().map_err(|e| e.to_string())?;
    let compiled = captured.compile().map_err(|e| e.to_string())?;
    let source = compiled.build_circuit(LayoutKind::Masm).map_err(|e| e.to_string())?;
    let num_airs = compiled.geometry().airs.len();
    let protocol = relation::protocol();
    let air_shape = miden_air_source::precompile::geometry::air_shape(&compiled);
    let lookup_shape = air_shape.lookup.ok_or("PVM relation requires lookup security data")?;
    let input_layout = source.layout();
    let circuit = PvmRecursiveAceCircuit::try_from(source.to_ace().map_err(|e| format!("{e}"))?)
        .map_err(|e| format!("{e}"))?;
    let read_layout = PvmReadLayout::from_input_layout(input_layout, num_airs)?;
    let num_quotient_chunks = input_layout.counts.num_quotient_chunks;
    if !num_quotient_chunks.is_power_of_two() {
        return Err(format!(
            "PVM quotient chunk count {num_quotient_chunks} is not a power of two"
        ));
    }
    let quotient_inputs = quotient_recomposition_inputs::<Felt>(
        num_quotient_chunks.ilog2() as u8,
        miden_air::precompile::policy::precompile_pcs_params().log_blowup(),
    )
    .map_err(|err| err.to_string())?;

    let shape = CircuitShape {
        num_inputs: circuit.num_inputs,
        num_eval_gates: circuit.num_eval_gates,
        stream_len: circuit.stream_len,
    };
    let circuit_digest = circuit.commitment;
    let relation_digest = miden_air::vm::config::relation_digest(
        miden_air::precompile::policy::PROTOCOL_ID,
        &circuit_digest,
    );
    let preprocessed_commitment = preprocessed_commitment();

    let geometry = PvmOodGeometry::from_compiled(compiled.geometry(), input_layout)?;
    let scatter_table_layout = pvm_scatter_table_layout(&geometry)?;
    let layout_masm = render_pvm_layout(&read_layout, shape.stream_len, &scatter_table_layout)?;
    let stream_len = u32::try_from(shape.stream_len)
        .map_err(|_| "PVM ACE stream length exceeds u32 memory".to_string())?;
    let scratch = pvm_scratch_allocation(&read_layout, stream_len)?;
    let ood_frames_masm =
        render_pvm_ood_frames(&geometry, scratch.proof_order_ids_ptr.is_multiple_of(4))?;
    let deep_queries_masm = render_pvm_deep_queries(&geometry)?;
    let constraints_eval_masm = render_pvm_constraints_eval(
        shape,
        circuit_digest,
        quotient_inputs,
        read_layout.fold_coefficient_offset,
        num_airs,
        protocol.max_periodic_log,
    )?;

    let mut heights = String::new();
    let mut loads = String::new();
    for (i, height) in protocol.heights.iter().enumerate() {
        use miden_air_source::precompile::relation::HeightRule;
        let (prefix, loader, log_height) = match height {
            HeightRule::Fixed(log_height) => ("FIXED", "load_fixed_air_height", log_height),
            HeightRule::Minimum(log_height) => ("MIN", "load_air_height", log_height),
        };
        if i > 0 {
            heights.push('\n');
            loads.push('\n');
        }
        write!(heights, "const {prefix}_LOG_HEIGHT_{i} = {log_height}").unwrap();
        write!(loads, "    push.{prefix}_LOG_HEIGHT_{i} exec.{loader}").unwrap();
    }
    let digest = relation_digest.map(|felt| felt.as_canonical_u64());
    let setup = core::array::from_fn::<_, 4, _>(|i| preprocessed_commitment[i].as_canonical_u64());
    let relation_mod_masm = PvmModTemplate {
        relation_digest_0: digest[0],
        relation_digest_1: digest[1],
        relation_digest_2: digest[2],
        relation_digest_3: digest[3],
        preprocessed_commitment_0: setup[0],
        preprocessed_commitment_1: setup[1],
        preprocessed_commitment_2: setup[2],
        preprocessed_commitment_3: setup[3],
        max_message_width: lookup_shape.max_message_width as usize,
        num_composed_constraints: air_shape.num_composed_constraints as usize,
        max_constraint_degree: air_shape.max_constraint_degree as usize,
        num_deep_terms: air_shape.num_deep_terms.expect("the PVM uses DEEP composition") as usize,
        lookup_fractions_per_row: lookup_shape.fractions_per_row as usize,
        fixed_boundary_lookup_terms: protocol.boundary.fixed_boundary_terms,
        lookup_pow_bits: pvm_security::LOOKUP_POW_BITS as usize,
        num_chiplets: num_airs,
        height_constants: heights,
        load_heights: loads,
    }
    .render()
    .map_err(|e| e.to_string())?;
    let protocol = crate::protocol::PvmProtocolPlan::from_relation(num_airs, &protocol)?;
    for (name, content) in [
        ("aux_trace", protocol.render_aux_trace()?),
        ("public_inputs", protocol.render_public_inputs()?),
        ("mod", relation_mod_masm),
        ("layout", layout_masm),
        ("ood_frames", ood_frames_masm),
        ("deep_queries", deep_queries_masm),
        ("constraints_eval", constraints_eval_masm),
    ] {
        super::push_module(modules, "pvm", name, &content)?;
    }
    Ok(())
}
/// The setup commitment pinned in `miden-air`, whose tests rebuild it from the AIRs.
fn preprocessed_commitment() -> Word {
    Word::new(
        miden_air::precompile::protocol::pins()
            .preprocessed_commitment
            .map(Felt::new_unchecked),
    )
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
    let bus_gamma_ptr = stream_end
        .checked_next_multiple_of(8)
        .ok_or("PVM scratch alignment overflows u32")?;
    let c_total_ptr = bus_gamma_ptr
        .checked_add(4)
        .ok_or_else(|| "PVM bus-gamma allocation overflows u32".to_string())?;
    let current_trace_row_ptr = c_total_ptr
        .checked_add(4)
        .ok_or_else(|| "PVM boundary-correction allocation overflows u32".to_string())?
        .checked_next_multiple_of(8)
        .ok_or("PVM current-row alignment overflows u32")?;
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
        .checked_add((layout.num_airs as u32).next_multiple_of(4))
        .ok_or_else(|| "PVM proof-order position table overflows u32".to_string())?;
    let allocation_end = proof_order_ids_ptr
        .checked_add(layout.num_airs as u32)
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
    let num_airs = layout.num_airs;
    let proof_order_positions_felts = (num_airs as u32).next_multiple_of(4);
    let proof_order_padding = proof_order_positions_felts - num_airs as u32;
    let proof_order_liveness = if proof_order_padding == 0 {
        format!("All {num_airs} cells are live.")
    } else {
        format!(
            "The first {num_airs} cells are live and the final {proof_order_padding} pad the\n\
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

    let mut out = String::new();
    writeln!(out, "# GENERATED by `{GENERATED_BY}` — do not edit by hand.")
        .expect("writing to String cannot fail");
    out.push_str("### PVM relation memory layout.\n");
    out.push_str("###\n");
    out.push_str("### The ACE READ section is one dense vector of quadratic-extension inputs.\n");
    out.push_str("### Every boundary below is derived from the PVM circuit's InputLayout; each\n");
    writeln!(
        out,
        "### input occupies two base-field felts. The complete allocation, including relation-local\n### scratch after the stream, is the half-open range {PVM_READ_START}..{allocation_end}."
    )
    .expect("writing to String cannot fail");
    out.push_str("### Per-AIR heights remain in the generic 16-cell array, in ChipletAir::all()\n");
    out.push_str(
        "### order; the PVM wrapper supplies the relation count and that shared base.\n\n",
    );
    out.push_str("use miden::core::stark::types\n\n");

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
    writeln!(
        out,
        "### {stream_len} felts: {}..{stream_end}.\nconst ACE_CIRCUIT_STREAM_PTR = {}\n",
        layout.stream_ptr, layout.stream_ptr
    )
    .expect("writing to String cannot fail");
    writeln!(
        out,
        "### 4 felts: {bus_gamma_ptr}..{c_total_ptr}. Stores gamma = beta^18.\nconst BUS_GAMMA_PTR = {bus_gamma_ptr}\n"
    )
    .expect("writing to String cannot fail");
    writeln!(
        out,
        "### 4 felts: {c_total_ptr}..{current_trace_row_ptr}. Stores the two-felt fixed-boundary correction; the remaining two felts are reserved.\nconst C_TOTAL_PTR = {c_total_ptr}\n"
    )
    .expect("writing to String cannot fail");
    writeln!(
        out,
        "### {} felts: {current_trace_row_ptr}..{preprocessed_com_ptr}. Stores one opened query row in commitment-group order.\nconst CURRENT_TRACE_ROW_PTR = {current_trace_row_ptr}\n",
        layout.query_row_felts
    )
    .expect("writing to String cannot fail");
    writeln!(
        out,
        "### 4 felts: {preprocessed_com_ptr}..{ood_scatter_table_ptr}. Stores the trusted preprocessed-tree commitment for DEEP openings.\nconst PREPROCESSED_COM_PTR = {preprocessed_com_ptr}\n"
    )
    .expect("writing to String cannot fail");
    writeln!(
        out,
        "### {OOD_SCATTER_TABLE_FELTS} felts: {ood_scatter_table_ptr}..{proof_order_positions_ptr}. Out-of-domain ingest scatter table:\n\
         ###\n\
         ###   +0            base address of the out-of-domain row being ingested\n\
         ###   +{pair_start:<3}.. +{pair_end:<6}per proof position, in stream order: (row-relative destination, digest address)\n\
         ###   +{digest_start:<3}.. +{digest_end:<6}`pipe_k` procedure digests reached by `dynexec`, one word each\n\
         ###\n\
         ### The internal offsets and the reserve's sufficiency are owned by `miden-verifier-codegen`,\n\
         ### which derives them from the chiplet widths and fills `sys/pvm/ood_frames.masm`\n\
         ### accordingly.\nconst OOD_SCATTER_TABLE_PTR = {ood_scatter_table_ptr}\n",
        pair_start = scatter_table.proof_order_pairs.start,
        digest_start = scatter_table.pipe_digests.start,
    )
    .expect("writing to String cannot fail");
    writeln!(
        out,
        "### {proof_order_positions_felts} felts: {proof_order_positions_ptr}..{proof_order_ids_ptr}. `pos_by_id`: the position of each\n\
         ### chiplet, in ChipletAir::all() order, within the height-sorted proof order.\n\
         ### {proof_order_liveness}\n\
         ### Staged once per proof by `sys/pvm/ood_frames.masm::stage_proof_order_maps`; read by both\n\
         ### ingest scatters.\nconst PROOF_ORDER_POSITIONS_PTR = {proof_order_positions_ptr}\n"
    )
    .expect("writing to String cannot fail");
    writeln!(
        out,
        "### {num_airs} felts: {proof_order_ids_ptr}..{allocation_end}. `id_by_pos`: the\n\
         ### ChipletAir::all() index committed at each proof position. Staged with `pos_by_id`;\n\
         ### read by the reverse fold-coefficient walk in `sys/pvm/constraints_eval.masm`.\n\
         const PROOF_ORDER_IDS_PTR = {proof_order_ids_ptr}\n"
    )
    .expect("writing to String cannot fail");

    for (accessor, constant) in [
        ("public_inputs_ptr", "PUBLIC_INPUTS_PTR"),
        ("aux_rand_elem_ptr", "AUX_RAND_ELEM_PTR"),
        ("preprocessed_current_ptr", "PREPROCESSED_CURRENT_PTR"),
        ("aux_bus_boundary_ptr", "AUX_BUS_BOUNDARY_PTR"),
        ("auxiliary_ace_inputs_ptr", "AUXILIARY_ACE_INPUTS_PTR"),
    ] {
        writeln!(out, "pub proc {accessor}() -> types::Address\n    push.{constant}\nend\n")
            .expect("writing to String cannot fail");
    }
    out.push_str("pub proc ace_circuit_stream_ptr() -> types::Address\n    push.ACE_CIRCUIT_STREAM_PTR\nend\n");
    out.push_str("\npub proc bus_gamma_ptr() -> types::Address\n    push.BUS_GAMMA_PTR\nend\n");
    out.push_str("\npub proc c_total_ptr() -> types::Address\n    push.C_TOTAL_PTR\nend\n");
    out.push_str("\npub proc current_trace_row_ptr() -> types::Address\n    push.CURRENT_TRACE_ROW_PTR\nend\n");
    out.push_str(
        "\npub proc preprocessed_com_ptr() -> types::Address\n    push.PREPROCESSED_COM_PTR\nend\n",
    );
    out.push_str("\npub proc ood_scatter_table_ptr() -> types::Address\n    push.OOD_SCATTER_TABLE_PTR\nend\n");
    out.push_str("\npub proc proof_order_positions_ptr() -> types::Address\n    push.PROOF_ORDER_POSITIONS_PTR\nend\n");
    out.push_str(
        "\npub proc proof_order_ids_ptr() -> types::Address\n    push.PROOF_ORDER_IDS_PTR\nend\n",
    );

    Ok(out)
}

fn render_pvm_constraints_eval(
    shape: CircuitShape,
    circuit_digest: Word,
    quotient_inputs: QuotientRecompositionInputs<Felt>,
    fold_coefficient_offset: usize,
    num_airs: usize,
    max_cycle_len_log: u32,
) -> Result<String, String> {
    render_masm_constraints_eval(&MasmConstraintsEvalConfig {
        generated_by: GENERATED_BY,
        layout_module: "miden::core::sys::pvm::layout",
        num_inputs: shape.num_inputs,
        num_eval_gates: shape.num_eval_gates,
        stream_len: shape.stream_len,
        max_cycle_len_log,
        num_airs,
        fold_coefficients: FoldCoefficientStaging {
            id_by_pos_ptr: "exec.layout::proof_order_ids_ptr",
            coefficient_offset: fold_coefficient_offset,
        },
        quotient_inputs,
        circuit_digest,
    })
    .map_err(|err| err.to_string())
}

fn render_pvm_deep_queries(geometry: &PvmOodGeometry) -> Result<String, String> {
    let groups = geometry.deep_query_groups();
    let mut blocks = [0; 4];
    let mut cvs: [String; 4] = core::array::from_fn(|_| String::new());
    for (i, (blocks_name, init_cv_name, width)) in groups.into_iter().enumerate() {
        if !width.is_multiple_of(EIDOS_BLOCK_WIDTH) {
            return Err(format!(
                "PVM {blocks_name} width {width} is not {EIDOS_BLOCK_WIDTH}-felt aligned"
            ));
        }
        blocks[i] = width / EIDOS_BLOCK_WIDTH;
        let encoded_len = u32::try_from(width)
            .map_err(|_| format!("PVM {init_cv_name} LMCS encoded length exceeds u32"))?;
        cvs[i] = masm_word_literal(Eidos::init_chaining_word(LMCS_LEAF, encoded_len));
    }
    let depth = miden_air::precompile::primitives::byte_pair_lut::TRACE_HEIGHT.ilog2()
        + u32::from(miden_air::precompile::policy::LOG_BLOWUP);
    let mask = 1u32
        .checked_shl(depth)
        .and_then(|n| n.checked_sub(1))
        .ok_or("PVM setup depth exceeds u32 query indices")?;
    let [
        preprocessed_lmcs_init_cv,
        main_lmcs_init_cv,
        aux_lmcs_init_cv,
        quotient_lmcs_init_cv,
    ] = cvs;
    PvmDeepQueriesTemplate {
        preprocessed_tree_depth: depth,
        preprocessed_index_mask: mask,
        preprocessed_row_double_words: blocks[0],
        main_row_double_words: blocks[1],
        aux_row_double_words: blocks[2],
        quotient_row_double_words: blocks[3],
        preprocessed_lmcs_init_cv,
        main_lmcs_init_cv,
        aux_lmcs_init_cv,
        quotient_lmcs_init_cv,
    }
    .render()
    .map_err(|e| e.to_string())
}

fn masm_word_literal(word: Word) -> String {
    let elements = word.as_elements();
    format!(
        "[{}, {}, {}, {}]",
        elements[0].as_canonical_u64(),
        elements[1].as_canonical_u64(),
        elements[2].as_canonical_u64(),
        elements[3].as_canonical_u64()
    )
}
