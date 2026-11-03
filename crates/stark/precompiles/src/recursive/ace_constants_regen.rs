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
    EXT_DEGREE, InputKey, InputLayout,
    compiler::{
        LayoutKind, MasmConstraintsEvalConfig, MasmMemoryExtents, MasmMemoryLayout,
        render_masm_constraints_eval,
    },
};
use miden_air::precompiles::NUM_CHIPLETS;
use miden_air_definitions::{
    compiler::precompiles::CapturedPvmRelation,
    precompiles::relation::{self, HeightRule},
};
use miden_core::{Felt, WORD_SIZE, Word, crypto::hash::Eidos};
use miden_crypto::hash::eidos::{BLOCK_LEN as EIDOS_BLOCK_WIDTH, domains::LMCS_LEAF};
use miden_stark::{QuotientRecompositionInputs, quotient_recomposition_inputs};

use super::{
    ace::PvmRecursiveAceCircuit,
    ace_constants::{
        GENERATED_BY, PVM_ACE_CIRCUIT_DIGEST, PVM_CIRCUIT_SHAPE, PVM_PREPROCESSED_COMMITMENT,
        PVM_RELATION_DIGEST, relation_digest_for_circuit,
    },
    pvm_ood_frames::{PvmOodGeometry, pvm_scatter_plan, render_pvm_ood_frames},
};

const PVM_CONSTRAINTS_EVAL_PATH: &str = "../../lib/core/asm/sys/pvm/constraints_eval.masm";
const PVM_PARAMETERS_PATH: &str = "../../lib/core/asm/sys/pvm/parameters.masm";
const PVM_FIXED_BOUNDARY_PATH: &str = "../../lib/core/asm/sys/pvm/fixed_boundary.masm";
const PVM_LAYOUT_PATH: &str = "../../lib/core/asm/sys/pvm/layout.masm";
const PVM_OOD_FRAMES_PATH: &str = "../../lib/core/asm/sys/pvm/ood_frames.masm";

const STARK_CONSTANTS_PATH: &str = "../../lib/core/asm/stark/constants.masm";

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
    /// Generated PVM memory layout, including offsets from the ACE `InputLayout`.
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
    memory: MasmMemoryLayout,
    /// Felt offset of chiplet 0's fold-coefficient slot from `AUXILIARY_ACE_INPUTS_PTR`.
    fold_coefficient_offset: usize,
}

#[derive(Clone, Debug)]
struct PvmReadRegion {
    constant: &'static str,
    ptr: usize,
    extent: usize,
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
    fn from_input_layout(layout: &InputLayout, memory: MasmMemoryLayout) -> Result<Self, String> {
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
            let ptr = memory.input_ptr(index).map_err(|err| err.to_string())?;
            boundaries.push((constant, ptr));
        }

        if boundaries.first().map(|(_, ptr)| *ptr) != Some(memory.ace_inputs_start()) {
            return Err("PVM public inputs must begin at the first ACE READ slot".into());
        }
        if boundaries.windows(2).any(|pair| pair[0].1 >= pair[1].1) {
            return Err("PVM ACE READ-region boundaries are not strictly increasing".into());
        }

        boundaries.push(("ACE_CIRCUIT_STREAM_PTR", memory.stream_start()));

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

        Ok(Self { regions, memory, fold_coefficient_offset })
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
    let geometry = PvmOodGeometry::from_compiled(compiled.geometry(), input_layout)?;
    let memory = MasmMemoryLayout::new(
        &read_masm_file(STARK_CONSTANTS_PATH)?,
        input_layout,
        MasmMemoryExtents {
            // One word each for the LogUp separator and fixed-environment correction.
            state_felts: 2 * WORD_SIZE,
            stream_felts: circuit.stream_len,
            query_row_felts: geometry.query_row_felts(),
            scatter_felts: pvm_scatter_plan(&geometry)?.table_felts(),
        },
    )
    .map_err(|err| err.to_string())?;
    let read_layout = PvmReadLayout::from_input_layout(input_layout, memory)?;
    let num_quotient_chunks = input_layout.counts.num_quotient_chunks;
    if !num_quotient_chunks.is_power_of_two() {
        return Err(format!(
            "PVM quotient chunk count {num_quotient_chunks} is not a power of two"
        ));
    }
    let quotient_inputs = quotient_recomposition_inputs::<Felt>(
        num_quotient_chunks.ilog2() as u8,
        miden_air::precompiles::policy::precompile_pcs_params().log_blowup(),
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
    if input_layout.counts.num_public
        != miden_air_definitions::precompiles::logup::NUM_PUBLIC_VALUES
    {
        return Err("PVM ACE public values disagree with the statement schema".into());
    }

    let layout_masm = render_pvm_layout(&read_layout, shape.stream_len);
    let ood_frames_masm = render_pvm_ood_frames(&geometry)?;
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

fn render_pvm_layout(layout: &PvmReadLayout, stream_len: usize) -> String {
    let memory = &layout.memory;
    let stream_end = memory.stream_start() + stream_len;

    let mut out = format!(
        r#"# GENERATED by `{GENERATED_BY}` — do not edit by hand.
### PVM statement fields and variable ACE input boundaries.
###
### The ACE READ section is one dense vector of quadratic-extension inputs.
### Its internal boundaries follow the PVM circuit's InputLayout; each input occupies two
### base-field felts. The major memory anchors are defined in `stark/constants.masm`.

use miden::core::stark::types

### LogUp bus separator [gamma0, gamma1, 0, 0], where gamma = beta^18.
pub const BUS_GAMMA_PTR = {state_start}
pub const BUS_GAMMA_C1_PTR = BUS_GAMMA_PTR + 1

### Fixed-environment LogUp correction [c0, c1, 0, 0].
pub const C_TOTAL_PTR = {correction_ptr}
pub const C_TOTAL_C1_PTR = C_TOTAL_PTR + 1

"#,
        state_start = memory.relation_state_start(),
        correction_ptr = memory.relation_state_start() + WORD_SIZE,
    );

    for region in layout.regions.iter().filter(|region| region.constant != "AUX_RAND_ELEM_PTR") {
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
            "PUBLIC_INPUTS_PTR" | "AUX_BUS_BOUNDARY_PTR" | "AUXILIARY_ACE_INPUTS_PTR"
        ) {
            let visibility =
                if matches!(region.constant, "PUBLIC_INPUTS_PTR" | "AUX_BUS_BOUNDARY_PTR") {
                    "pub "
                } else {
                    ""
                };
            writeln!(out, "{visibility}const {} = {}\n", region.constant, region.ptr)
                .expect("writing to String cannot fail");
        } else {
            out.push('\n');
        }
    }
    write!(
        out,
        r#"### {stream_len} felts: {stream_ptr}..{stream_end}.
const ACE_CIRCUIT_STREAM_PTR = {stream_ptr}

"#,
        stream_ptr = memory.stream_start(),
    )
    .expect("writing to String cannot fail");

    out.push_str("### Public values occupy consecutive quadratic-extension slots.\n");
    let public_felts = layout.regions[0].extent;
    for offset in 1..public_felts {
        writeln!(
            out,
            "pub const PUBLIC_INPUT_{}_C{}_PTR = PUBLIC_INPUTS_PTR + {offset}",
            offset / 2,
            offset % 2,
        )
        .expect("writing to String cannot fail");
    }
    out.push_str("\n### Words of the normalized boundary array, two extension values per word.\n");
    for word in 1..NUM_CHIPLETS / 2 {
        writeln!(
            out,
            "pub const AUX_BOUNDARY_WORD_{word}_PTR = AUX_BUS_BOUNDARY_PTR + {}",
            word * 4
        )
        .expect("writing to String cannot fail");
    }

    for (accessor, constant) in [
        ("public_inputs_ptr", "PUBLIC_INPUTS_PTR"),
        ("aux_bus_boundary_ptr", "AUX_BUS_BOUNDARY_PTR"),
        ("auxiliary_ace_inputs_ptr", "AUXILIARY_ACE_INPUTS_PTR"),
        ("ace_circuit_stream_ptr", "ACE_CIRCUIT_STREAM_PTR"),
    ] {
        writeln!(out, "\npub proc {accessor}() -> types::Address\n    push.{constant}\nend")
            .expect("writing to String cannot fail");
    }

    out
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
        fold_coefficient_offset,
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
    let metadata = &miden_air::precompiles::protocol::PROTOCOL;
    let air_shape = metadata.air_shape;
    let lookup_shape = air_shape.lookup.ok_or("PVM security metadata requires lookup arguments")?;
    output.push_str("\n# Security descriptor from miden_air::precompiles::protocol.\n");
    for (name, value) in [
        ("MAX_MESSAGE_WIDTH", u64::from(lookup_shape.max_message_width)),
        ("NUM_COMPOSED_CONSTRAINTS", u64::from(air_shape.num_composed_constraints)),
        ("MAX_CONSTRAINT_DEGREE", u64::from(air_shape.max_constraint_degree)),
        (
            "NUM_DEEP_TERMS",
            u64::from(air_shape.num_deep_terms.expect("the PVM uses DEEP composition")),
        ),
        ("LOOKUP_FRACTIONS_PER_ROW", u64::from(lookup_shape.fractions_per_row)),
        ("FIXED_BOUNDARY_LOOKUP_TERMS", u64::from(metadata.fixed_boundary_lookup_terms)),
    ] {
        writeln!(output, "pub const {name} = {value}").unwrap();
    }

    output.push_str("\n# Bus-domain scale factors: BusId + 1 from the native relation registry.\n");
    for (name, bus) in [
        (
            "UINT_VAL_BUS_SCALE",
            miden_air_definitions::precompiles::relations::BusId::UintVal,
        ),
        (
            "EC_GROUP_BUS_SCALE",
            miden_air_definitions::precompiles::relations::BusId::EcGroup,
        ),
    ] {
        writeln!(output, "pub const {name} = {}", bus as usize + 1).unwrap();
    }

    let setup_height = miden_air_definitions::precompiles::primitives::byte_pair_lut::TRACE_HEIGHT;
    if !setup_height.is_power_of_two() {
        return Err("BytePairLut setup height must be a power of two".into());
    }
    let log_height = setup_height.ilog2();
    let depth = log_height
        + u32::from(miden_air::precompiles::policy::precompile_pcs_params().log_blowup());
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
        if read_masm_file(path)? != *rendered {
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

fn masm_path(relative: &str) -> String {
    format!("{}/{}", env!("CARGO_MANIFEST_DIR"), relative)
}

fn read_masm_file(relative: &str) -> Result<String, String> {
    let path = masm_path(relative);
    std::fs::read_to_string(&path).map_err(|err| format!("failed to read {path}: {err}"))
}

fn write_generated_file(relative: &str, contents: &str) -> io::Result<()> {
    let path = masm_path(relative);
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
