//! Regeneration tool for the PVM ACE circuit constants and generated MASM artifacts.
//!
//! One order-invariant circuit serves every proof ordering, so `--write` builds that circuit,
//! mints its digest and the relation digest derived from it, and emits the memory layout, the
//! out-of-domain ingest hook, and the constraint evaluator from the same circuit metadata.
//! `--check` recomputes the same artifacts, compares the digests and circuit shape against the
//! constants compiled into `ace_constants.rs`, then byte-compares every rendered file against its
//! checked-in copy. For `ace_constants.rs` and `sys/pvm/mod.masm` themselves the byte comparison
//! is close to tautological, since their rendering substitutes those already-checked values into
//! the checked-in file's own template; the real coverage for those two paths is the value
//! comparison above, not the byte comparison.

use std::{
    fmt::Write as _,
    format, io, println,
    string::{String, ToString},
    vec::Vec,
};

use miden_ace_codegen::{
    InputKey, InputLayout, MasmConstraintsEvalConfig, render_masm_constraints_eval,
};
use miden_core::{Felt, Word};
use miden_lifted_air::BaseAir;
use miden_lifted_stark::{QuotientRecompositionInputs, quotient_recomposition_inputs};
use miden_precompiles_air::{ChipletAir, NUM_CHIPLETS};

use crate::{
    ace::build_pvm_recursive_verifier_ace_circuit,
    ace_constants::{
        GENERATED_BY, PVM_ACE_CIRCUIT_DIGEST, PVM_CIRCUIT_SHAPE, PVM_PREPROCESSED_COMMITMENT,
        PVM_RELATION_DIGEST, relation_digest_for_circuit,
    },
    pvm_ood_frames::{OOD_SCATTER_TABLE_FELTS, PvmOodGeometry, render_pvm_ood_frames},
};

const CONSTANTS_PATH: &str = "src/ace_constants.rs";
const PVM_CONSTRAINTS_EVAL_PATH: &str = "../lib/core/asm/sys/pvm/constraints_eval.masm";
const PVM_LAYOUT_PATH: &str = "../lib/core/asm/sys/pvm/layout.masm";
const PVM_OOD_FRAMES_PATH: &str = "../lib/core/asm/sys/pvm/ood_frames.masm";
const PVM_RELATION_MOD_PATH: &str = "../lib/core/asm/sys/pvm/mod.masm";

/// First felt after the VM relation's fixed ACE stream reservation. The PVM's complete READ
/// section starts here; its aux-randomness anchor is later because four public EF inputs precede
/// it.
// The narrowed four-AIR VM evaluator occupies 8,520 felts; place the PVM frame at the next
// 4-Ki-felt boundary after that stream so the two relation-owned allocations cannot overlap.
const PVM_READ_START: u32 = 3_225_432_064;
/// Start of the VM relation's next scratch region; the PVM allocation must end before it.
const NEXT_VM_REGION_START: u32 = 3_238_002_688;

/// Whether [`run`] re-mints the committed artifacts (`Write`) or byte-compares a freshly
/// built set against them (`Check`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Check,
    Write,
}

/// Runs write (`--write`) or staleness-check (`--check`) mode.
pub fn run(mode: Mode) -> Result<(), String> {
    let artifacts = compute()?;
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
    /// Commitment to the preprocessed (setup) LDE tree under the Eidos config —
    /// the configuration an in-VM verifier targets.
    ///
    /// This is a trusted verifier input rather than proof data: the Rust verifier
    /// rebuilds the bundle locally, but a MASM verifier has no way to, so it must be
    /// pinned as a protocol constant and observed into the transcript.
    preprocessed_commitment: Word,
    /// Shape of the encoded circuit stream.
    shape: CircuitShape,
    /// Generated PVM relation layout, derived from the ACE `InputLayout`.
    layout_masm: String,
    /// Generated PVM out-of-domain ingest hook, derived from the chiplet widths.
    ood_frames_masm: String,
    /// Generated PVM constraint evaluator, rendered from the same circuit metadata.
    constraints_eval_masm: String,
    /// Hand-written relation wrapper with its generated protocol constants updated.
    relation_mod_masm: String,
    /// Hand-written constants module with its generated values updated.
    constants_rs: String,
}

#[derive(Clone, Debug)]
struct PvmReadLayout {
    regions: Vec<PvmReadRegion>,
    stream_ptr: u32,
    query_row_felts: u32,
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

        Ok(Self { regions, stream_ptr, query_row_felts })
    }
}

/// Build the canonical circuit and derive every generated artifact from it.
fn compute() -> Result<GeneratedArtifacts, String> {
    let circuit = build_pvm_recursive_verifier_ace_circuit().map_err(|e| format!("{e}"))?;
    let input_layout = crate::ace::build_canonical_precompile_ace_circuit()
        .map_err(|e| format!("{e}"))?
        .layout()
        .clone();
    let read_layout = PvmReadLayout::from_input_layout(&input_layout)?;
    let num_quotient_chunks = input_layout.counts.num_quotient_chunks;
    if !num_quotient_chunks.is_power_of_two() {
        return Err(format!(
            "PVM quotient chunk count {num_quotient_chunks} is not a power of two"
        ));
    }
    let quotient_inputs = quotient_recomposition_inputs::<Felt>(
        num_quotient_chunks.ilog2() as u8,
        miden_precompiles_air::stark_config::precompile_pcs_params().log_blowup(),
    )
    .map_err(|err| err.to_string())?;

    let shape = CircuitShape {
        num_inputs: circuit.num_inputs,
        num_eval_gates: circuit.num_eval_gates,
        stream_len: circuit.stream_len,
    };
    let circuit_digest = circuit.commitment;
    let relation_digest = relation_digest_for_circuit(&circuit_digest);
    let preprocessed_commitment = preprocessed_commitment(relation_digest);

    let layout_masm = render_pvm_layout(&read_layout, shape.stream_len)?;
    let ood_frames_masm =
        render_pvm_ood_frames(&PvmOodGeometry::from_input_layout(&input_layout)?)?;
    let constraints_eval_masm =
        render_pvm_constraints_eval(shape, circuit_digest, quotient_inputs)?;

    let mut relation_mod_masm = read_generated_file(PVM_RELATION_MOD_PATH)?;
    for (prefix, word) in [
        ("RELATION_DIGEST", Word::new(relation_digest)),
        ("PREPROCESSED_COMMITMENT", preprocessed_commitment),
    ] {
        for (index, felt) in word.iter().enumerate() {
            replace_masm_const(
                &mut relation_mod_masm,
                &format!("{prefix}_{index}"),
                felt.as_canonical_u64(),
            )?;
        }
    }

    let mut constants_rs = read_generated_file(CONSTANTS_PATH)?;
    for (name, word) in [
        ("PVM_RELATION_DIGEST", Word::new(relation_digest)),
        ("PVM_ACE_CIRCUIT_DIGEST", circuit_digest),
        ("PVM_PREPROCESSED_COMMITMENT", preprocessed_commitment),
    ] {
        replace_limb_array_const(&mut constants_rs, name, &word)?;
    }
    replace_shape_const(&mut constants_rs, shape)?;

    Ok(GeneratedArtifacts {
        circuit_digest,
        relation_digest,
        preprocessed_commitment,
        shape,
        layout_masm,
        ood_frames_masm,
        constraints_eval_masm,
        relation_mod_masm,
        constants_rs,
    })
}

/// Commitment to the setup (preprocessed) trace tree under the Eidos config.
///
/// Built through the same cache the prover and Rust verifier use, seeded with the freshly
/// minted relation digest, so the config matches production exactly and the minted constant
/// is by construction the value they observe into the transcript. (The commitment itself
/// is digest-independent; threading the digest avoids relying on that property here.)
fn preprocessed_commitment(digest: [Felt; 4]) -> Word {
    let params = miden_precompiles_air::stark_config::precompile_pcs_params();
    let config = miden_precompiles_air::stark_config::eidos_config(params, digest);
    // The LMCS commitment is a 4-felt hash; Word is the MASM-facing representation.
    let commitment: [u64; 4] =
        miden_precompiles_air::preprocessed::build_uncached(&config).commitment().into();
    Word::new(commitment.map(Felt::new_unchecked))
}

fn render_pvm_layout(layout: &PvmReadLayout, stream_len: usize) -> Result<String, String> {
    let stream_len = u32::try_from(stream_len)
        .map_err(|_| "PVM ACE stream length exceeds u32 memory".to_string())?;
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
    let allocation_end = proof_order_positions_ptr
        .checked_add(NUM_CHIPLETS as u32)
        .ok_or_else(|| "PVM proof-order position table overflows u32".to_string())?;
    if allocation_end > NEXT_VM_REGION_START {
        return Err(format!(
            "PVM ACE allocation {PVM_READ_START}..{allocation_end} reaches the VM scratch region starting at {NEXT_VM_REGION_START}"
        ));
    }

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

    for region in &layout.regions {
        writeln!(
            out,
            "### {} felts: {}..{}.\nconst {} = {}\n",
            region.extent,
            region.ptr,
            region.ptr + region.extent,
            region.constant,
            region.ptr
        )
        .expect("writing to String cannot fail");
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
         ###   +4  .. +43    per proof position, in stream order: (row-relative destination, digest address)\n\
         ###   +44 .. +83    `pipe_k` procedure digests reached by `dynexec`, one word each\n\
         ###\n\
         ### The internal offsets and the reserve's sufficiency are owned by the regeneration tool,\n\
         ### which derives them from the chiplet widths and fills `sys/pvm/ood_frames.masm`\n\
         ### accordingly.\nconst OOD_SCATTER_TABLE_PTR = {ood_scatter_table_ptr}\n"
    )
    .expect("writing to String cannot fail");
    writeln!(
        out,
        "### {NUM_CHIPLETS} felts: {proof_order_positions_ptr}..{allocation_end}. Position of each chiplet, in\n\
         ### ChipletAir::all() order, within the height-sorted proof order. Staged once per proof by\n\
         ### `sys/pvm/mod.masm`; read by both ingest scatters.\nconst PROOF_ORDER_POSITIONS_PTR = {proof_order_positions_ptr}\n"
    )
    .expect("writing to String cannot fail");

    for (accessor, constant) in [
        ("public_inputs_ptr", "PUBLIC_INPUTS_PTR"),
        ("aux_rand_elem_ptr", "AUX_RAND_ELEM_PTR"),
        ("preprocessed_current_ptr", "PREPROCESSED_CURRENT_PTR"),
        ("aux_bus_boundary_ptr", "AUX_BUS_BOUNDARY_PTR"),
        ("auxiliary_ace_inputs_ptr", "AUXILIARY_ACE_INPUTS_PTR"),
    ] {
        writeln!(out, "pub proc {accessor}\n    push.{constant}\nend\n")
            .expect("writing to String cannot fail");
    }
    out.push_str("pub proc ace_circuit_stream_ptr\n    push.ACE_CIRCUIT_STREAM_PTR\nend\n");
    out.push_str("\npub proc bus_gamma_ptr\n    push.BUS_GAMMA_PTR\nend\n");
    out.push_str("\npub proc c_total_ptr\n    push.C_TOTAL_PTR\nend\n");
    out.push_str("\npub proc current_trace_row_ptr\n    push.CURRENT_TRACE_ROW_PTR\nend\n");
    out.push_str("\npub proc preprocessed_com_ptr\n    push.PREPROCESSED_COM_PTR\nend\n");
    out.push_str("\npub proc ood_scatter_table_ptr\n    push.OOD_SCATTER_TABLE_PTR\nend\n");
    out.push_str("\npub proc proof_order_positions_ptr\n    push.PROOF_ORDER_POSITIONS_PTR\nend\n");

    Ok(out)
}

fn render_pvm_constraints_eval(
    shape: CircuitShape,
    circuit_digest: Word,
    quotient_inputs: QuotientRecompositionInputs<Felt>,
) -> Result<String, String> {
    let max_cycle_len_log = max_periodic_cycle_len_log()?;
    render_masm_constraints_eval(&MasmConstraintsEvalConfig {
        generated_by: GENERATED_BY,
        layout_module: "miden::core::sys::pvm::layout",
        num_inputs: shape.num_inputs,
        num_eval_gates: shape.num_eval_gates,
        stream_len: shape.stream_len,
        max_cycle_len_log,
        num_airs: NUM_CHIPLETS,
        stages_fold_coefficients: true,
        quotient_inputs,
        circuit_digest,
    })
    .map_err(|err| err.to_string())
}

fn max_periodic_cycle_len_log() -> Result<u32, String> {
    let max_len = ChipletAir::all()
        .iter()
        .flat_map(<ChipletAir as BaseAir<Felt>>::periodic_columns)
        .map(|column| column.len())
        .max()
        .unwrap_or(1);
    if !max_len.is_power_of_two() {
        return Err("maximum PVM AIR periodic cycle length is not a power of two".into());
    }
    Ok(max_len.ilog2())
}

fn check(artifacts: &GeneratedArtifacts) -> Result<(), String> {
    for (name, actual, expected) in [
        ("PVM_RELATION_DIGEST", PVM_RELATION_DIGEST, artifacts.relation_digest),
        ("PVM_ACE_CIRCUIT_DIGEST", PVM_ACE_CIRCUIT_DIGEST, *artifacts.circuit_digest),
        (
            "PVM_PREPROCESSED_COMMITMENT",
            PVM_PREPROCESSED_COMMITMENT,
            *artifacts.preprocessed_commitment,
        ),
    ] {
        if actual.map(Felt::new_unchecked) != expected {
            return Err(format!("{name} in {CONSTANTS_PATH} is stale"));
        }
    }
    if PVM_CIRCUIT_SHAPE
        != (
            artifacts.shape.num_inputs,
            artifacts.shape.num_eval_gates,
            artifacts.shape.stream_len,
        )
    {
        return Err(format!("PVM_CIRCUIT_SHAPE in {CONSTANTS_PATH} is stale"));
    }

    for (path, rendered) in [
        (CONSTANTS_PATH, &artifacts.constants_rs),
        (PVM_LAYOUT_PATH, &artifacts.layout_masm),
        (PVM_OOD_FRAMES_PATH, &artifacts.ood_frames_masm),
        (PVM_CONSTRAINTS_EVAL_PATH, &artifacts.constraints_eval_masm),
        (PVM_RELATION_MOD_PATH, &artifacts.relation_mod_masm),
    ] {
        if read_generated_file(path)? != *rendered {
            return Err(format!("{path} is stale; run `make regenerate-pvm-constants`"));
        }
    }
    println!("PVM ACE constants and MASM artifacts are up to date");
    Ok(())
}

fn write(artifacts: &GeneratedArtifacts) -> io::Result<()> {
    write_generated_file(CONSTANTS_PATH, &artifacts.constants_rs)?;
    write_generated_file(PVM_LAYOUT_PATH, &artifacts.layout_masm)?;
    write_generated_file(PVM_OOD_FRAMES_PATH, &artifacts.ood_frames_masm)?;
    write_generated_file(PVM_CONSTRAINTS_EVAL_PATH, &artifacts.constraints_eval_masm)?;
    write_generated_file(PVM_RELATION_MOD_PATH, &artifacts.relation_mod_masm)?;
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

fn replace_masm_const(content: &mut String, name: &str, value: u64) -> Result<(), String> {
    let prefix = format!("const {name} = ");
    let mut declarations = content
        .match_indices(&prefix)
        .filter(|(start, _)| *start == 0 || content.as_bytes()[start - 1] == b'\n');
    let line_start = declarations
        .next()
        .map(|(start, _)| start)
        .ok_or_else(|| format!("{name} not found in {PVM_RELATION_MOD_PATH}"))?;
    if declarations.next().is_some() {
        return Err(format!("{name} is declared more than once in {PVM_RELATION_MOD_PATH}"));
    }
    let line_end = content[line_start..]
        .find('\n')
        .map(|offset| line_start + offset)
        .unwrap_or(content.len());
    content.replace_range(line_start..line_end, &format!("{prefix}{value}"));
    Ok(())
}

/// Rewrite the initializer of a `pub const NAME: [u64; 4]` declaration.
fn replace_limb_array_const(content: &mut String, name: &str, word: &Word) -> Result<(), String> {
    let body: String =
        word.iter().map(|felt| format!("\n    {},", felt.as_canonical_u64())).collect();
    replace_const_initializer(content, name, " = [", "];", &format!("{body}\n"))
}

/// Rewrite the initializer of the `pub const PVM_CIRCUIT_SHAPE: (usize, usize, usize)`
/// declaration.
fn replace_shape_const(content: &mut String, shape: CircuitShape) -> Result<(), String> {
    let body = format!("{}, {}, {}", shape.num_inputs, shape.num_eval_gates, shape.stream_len);
    replace_const_initializer(content, "PVM_CIRCUIT_SHAPE", " = (", ");", &body)
}

fn replace_const_initializer(
    content: &mut String,
    name: &str,
    open: &str,
    close: &str,
    body: &str,
) -> Result<(), String> {
    let marker = format!("pub const {name}:");
    let start = content
        .find(&marker)
        .ok_or_else(|| format!("{name} not found in {CONSTANTS_PATH}"))?;
    if content[start + marker.len()..].contains(&marker) {
        return Err(format!("{name} is declared more than once in {CONSTANTS_PATH}"));
    }
    let open_start = content[start..]
        .find(open)
        .map(|offset| start + offset)
        .ok_or_else(|| format!("{name} initializer not found in {CONSTANTS_PATH}"))?;
    let body_start = open_start + open.len();
    let body_end = content[body_start..]
        .find(close)
        .map(|offset| body_start + offset)
        .ok_or_else(|| format!("{name} terminator not found in {CONSTANTS_PATH}"))?;
    content.replace_range(body_start..body_end, body);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::string::String;

    use miden_core::{Felt, Word};

    use super::{CircuitShape, replace_limb_array_const, replace_masm_const, replace_shape_const};

    #[test]
    fn relation_constants_are_replaced_without_touching_the_wrapper() {
        let mut source = String::from(
            "before\nconst RELATION_DIGEST_0 = 1\nconst PREPROCESSED_COMMITMENT_3 = 2\nafter\n",
        );
        replace_masm_const(&mut source, "RELATION_DIGEST_0", 42).unwrap();
        replace_masm_const(&mut source, "PREPROCESSED_COMMITMENT_3", 99).unwrap();
        assert_eq!(
            source,
            "before\nconst RELATION_DIGEST_0 = 42\nconst PREPROCESSED_COMMITMENT_3 = 99\nafter\n"
        );
    }

    #[test]
    fn relation_constant_replacement_fails_closed_when_a_constant_is_missing() {
        let mut source = String::from("const RELATION_DIGEST_0 = 1\n");
        let error = replace_masm_const(&mut source, "PREPROCESSED_COMMITMENT_0", 42).unwrap_err();
        assert!(error.contains("PREPROCESSED_COMMITMENT_0 not found"));
    }

    #[test]
    fn relation_constant_replacement_rejects_duplicate_declarations() {
        let mut source = String::from("const RELATION_DIGEST_0 = 1\nconst RELATION_DIGEST_0 = 2\n");
        let error = replace_masm_const(&mut source, "RELATION_DIGEST_0", 42).unwrap_err();
        assert!(error.contains("RELATION_DIGEST_0 is declared more than once"));
    }

    #[test]
    fn generated_rust_constants_are_rewritten_in_place() {
        let mut source = String::from(
            "/// doc\npub const PVM_ACE_CIRCUIT_DIGEST: [u64; 4] = [0, 0, 0, 0];\n\npub const \
             PVM_CIRCUIT_SHAPE: (usize, usize, usize) = (0, 0, 0);\n",
        );
        let word = Word::new([1u64, 2, 3, 4].map(Felt::new_unchecked));
        replace_limb_array_const(&mut source, "PVM_ACE_CIRCUIT_DIGEST", &word).unwrap();
        replace_shape_const(
            &mut source,
            CircuitShape {
                num_inputs: 5,
                num_eval_gates: 6,
                stream_len: 8,
            },
        )
        .unwrap();
        assert_eq!(
            source,
            "/// doc\npub const PVM_ACE_CIRCUIT_DIGEST: [u64; 4] = [\n    1,\n    2,\n    3,\n    \
             4,\n];\n\npub const PVM_CIRCUIT_SHAPE: (usize, usize, usize) = (5, 6, 8);\n"
        );
    }

    #[test]
    fn generated_rust_constant_replacement_fails_closed_when_absent() {
        let mut source = String::from("pub const OTHER: [u64; 4] = [0, 0, 0, 0];\n");
        let word = Word::new([1u64, 2, 3, 4].map(Felt::new_unchecked));
        let error =
            replace_limb_array_const(&mut source, "PVM_ACE_CIRCUIT_DIGEST", &word).unwrap_err();
        assert!(error.contains("PVM_ACE_CIRCUIT_DIGEST not found"));
    }
}
