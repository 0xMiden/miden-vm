use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use std::{fs, io, path::Path};

use miden_ace::{CompiledCircuit, InputKey, InputLayout};
use miden_core::{Felt, Word, field::QuadFelt, program::KernelDescriptor};
use miden_crypto::hash::eidos::{
    Eidos,
    domains::{GENERIC_FELT_SEQUENCE, LMCS_LEAF},
};
use miden_stark::{
    Preprocessed, QuotientRecompositionInputs, StarkConfig, air::BaseAir, lmcs::Lmcs,
    quotient_recomposition_inputs,
};

use super::masm_renderer::{
    self, AirGeometry, ArtifactOwnership, CircuitMetadata, QuotientReconstruction, ReadLayout,
    RelationInput, RenderedArtifact, SecurityParameters, SharedAbi, V1RenderInput, VmAbiAnchors,
};
use crate::vm::{
    AIRS, Air as MidenAir, MIDEN_AIR_COUNT, MultiAir as MidenMultiAir, NUM_PUBLIC_VALUES,
    Statement,
    ace::{build_canonical_multi_air_ace_circuit, recursive_verifier_ace_config},
    config::{self, relation_digest},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Check,
    Write,
}

mod accepted {
    include!("../../templates/vm-pins.rs");
}

const PROTOCOL_ID: u64 = 1;
const AIR_CONFIG_PATH: &str = "crates/air/generated/src/config.rs";
#[cfg(test)]
const CONSTRAINTS_EVAL_PATH: &str = "crates/lib/core/asm/sys/vm/constraints_eval.masm";
const RELATION_DIGEST_PATH: &str = "crates/lib/core/asm/sys/vm/mod.masm";
#[cfg(test)]
const VM_LAYOUT_PATH: &str = "crates/lib/core/asm/sys/vm/layout.masm";
const STARK_CONSTANTS_PATH: &str = "crates/lib/core/asm/stark/constants.masm";
#[cfg(test)]
const VM_OOD_FRAMES_PATH: &str = "crates/lib/core/asm/sys/vm/ood_frames.masm";
#[cfg(test)]
const VM_DEEP_QUERIES_PATH: &str = "crates/lib/core/asm/sys/vm/deep_queries.masm";
const VM_PUBLIC_INPUTS_PATH: &str = "crates/lib/core/asm/sys/vm/public_inputs.masm";
const SECURITY_ESTIMATOR_PATH: &str = "crates/lib/core/asm/stark/security.masm";
const GENERIC_UTILS_PATH: &str = "crates/lib/core/asm/stark/utils.masm";
/// Felts moved by one `adv_pipe`.
///
/// This transport width governs block/segment arithmetic and destination alignment;
/// Commitment padding independently governs column widths.
#[cfg(test)]
const ADV_PIPE_BLOCK_FELTS: usize = 8;

/// Computes the relation digest used by recursive verification.
pub fn compute_relation_digest(circuit_digest: &[Felt; 4]) -> [Felt; 4] {
    relation_digest(PROTOCOL_ID, &Word::new(*circuit_digest))
}

/// Runs write (`--write`) or staleness-check (`--check`) mode.
pub fn run(root: &Path, mode: Mode) -> Result<(), String> {
    // Validate both current relations before delivering any managed projection.
    super::run(root, mode)
}

/// Captured and compiled inputs, including layout metadata absent from canonical ACE bytes.
#[derive(Clone, Debug)]
pub struct CompiledVerifierInputs {
    pub masm: V1RenderInput,
    pub preprocessed_commitments: PreprocessedCommitments,
}

/// Capture and compile authored AIR, then adapt its layout and explicit setup inputs.
pub fn compile(commitments: PreprocessedCommitments) -> CompiledVerifierInputs {
    compile_inputs(Some(commitments))
}

/// Compatibility orchestration over explicit compilation and pure rendering.
pub fn compile_and_render(commitments: PreprocessedCommitments) -> ComputedArtifacts {
    render(&compile(commitments))
}

/// Shared verifier memory ABI expected by both source render adapters.
///
/// Core-lib independently compares these values with its live generic MASM constants.
pub const SHARED_ABI: SharedAbi = SharedAbi {
    heights_ptr: 3_223_322_744,
    heights_capacity: 16,
    composition_coefficients_ptr: 3_223_322_704,
    public_inputs_address_ptr: 3_223_322_638,
};

pub(super) const VM_ABI: VmAbiAnchors = VmAbiAnchors {
    num_kernel_procedures_ptr: 3_223_322_776,
    control_alignment_padding_ptr: 3_223_322_777,
    bus_gamma_ptr: 3_223_322_780,
    c_total_ptr: 3_223_322_784,
    claim_commitment_ptr: 3_223_322_788,
    claim_ptr: 3_223_322_792,
    boundary_anchor_padding_ptr: 3_223_322_832,
    boundary_inputs_ptr: 3_223_322_836,
    kernel_witness_ptr: 3_223_322_844,
    scatter_ptr: 3_223_323_864,
    scatter_reserve_felts: 64,
    read_beta_anchor: 3_225_419_776,
    current_trace_row_ptr: 3_238_002_688,
    next_region_start: super::precompile::PVM_READ_START,
};

/// Accepted setup inputs for the current protocol. This is not a claim of fresh setup derivation.
pub fn accepted_setup_commitments() -> PreprocessedCommitments {
    PreprocessedCommitments {
        blake3: accepted::BLAKE3_PREPROCESSED_COMMITMENT,
        rpo: accepted::RPO_PREPROCESSED_COMMITMENT,
        rpx: accepted::RPX_PREPROCESSED_COMMITMENT,
        eidos: accepted::EIDOS_PREPROCESSED_COMMITMENT,
        poseidon2: accepted::POSEIDON2_PREPROCESSED_COMMITMENT,
        keccak: accepted::KECCAK_PREPROCESSED_COMMITMENT,
    }
}

/// Independently derive all fixed-table commitments and compare every generated output/pin.
pub fn check_setup(root: &Path) -> Result<(), String> {
    let artifact = compute_artifacts(None);
    check_artifacts(root, &artifact)
}

/// Compare rendered outputs against the explicit destination checkout.
pub fn check_artifacts(root: &Path, artifact: &ComputedArtifacts) -> Result<(), String> {
    validate_delivery(root, artifact)?;
    super::delivery::deliver(root, &artifact.files, Mode::Check)?;
    public_inputs_masm_matches_air(root)?;
    security_masm_matches_air(root)?;
    Ok(())
}

/// Generate a full computed snapshot from the current AIR.
fn compute_artifacts(supplied: Option<PreprocessedCommitments>) -> ComputedArtifacts {
    render(&compile_inputs(supplied))
}

fn compile_inputs(supplied: Option<PreprocessedCommitments>) -> CompiledVerifierInputs {
    let circuit = CompiledCircuit::from_circuit(build_canonical_multi_air_ace_circuit(
        recursive_verifier_ace_config(),
    ));
    let layout = circuit.layout();
    let quotient_chunks = layout.counts.num_quotient_chunks;
    assert!(
        quotient_chunks.is_power_of_two(),
        "quotient chunk count {quotient_chunks} is not a power of two"
    );
    let quotient = quotient_recomposition_inputs::<Felt>(
        quotient_chunks.ilog2() as u8,
        config::pcs_params().log_blowup(),
    )
    .expect("compile_inputs requires valid authored compiler inputs");
    let geometry = AirGeometry::from_airs(&AIRS, quotient_chunks);
    let circuit_digest = word_to_array(circuit.commitment());
    let relation_digest = compute_relation_digest(&circuit_digest);
    let commitments = match supplied {
        Some(commitments) => commitments,
        None => derive_setup_commitments(relation_digest),
    };
    let air_shape = crate::vm::security::derive_air_shape();
    let lookup = air_shape.lookup.expect("the relation uses lookup");
    CompiledVerifierInputs {
        masm: V1RenderInput {
            relation: RelationInput::Vm(VM_ABI),
            circuit: render_circuit_metadata(&circuit, max_periodic_cycle_len_log()),
            query_leaf_initial_cvs: query_leaf_initial_cvs(&geometry),
            geometry,
            counts: layout.counts,
            read_layout: render_read_layout(layout),
            quotient: render_quotient_inputs(quotient),
            relation_digest: relation_digest.map(|felt| felt.as_canonical_u64()),
            preprocessed_commitment: commitments.eidos,
            security: SecurityParameters {
                lookup_pow_bits: crate::vm::security::LOOKUP_POW_BITS,
                max_message_width: lookup.max_message_width,
                num_composed_constraints: air_shape.num_composed_constraints,
                max_constraint_degree: air_shape.max_constraint_degree,
                num_deep_terms: air_shape.num_deep_terms
                    .expect("VM AIR must use DEEP composition"),
                lookup_fractions_per_row: lookup.fractions_per_row,
                boundary_lookup_terms: crate::vm::security::CORE_BOUNDARY_LOOKUP_TERMS,
            },
            shared_abi: SHARED_ABI,
            regeneration_command: "cargo run -p miden-air-source --features tooling --bin air-codegen -- <workspace-root> --write".into(),
        },
        preprocessed_commitments: commitments,
    }
}

/// Render complete candidate projections without capture, compilation, setup or destination I/O.
pub fn render(compiled: &CompiledVerifierInputs) -> ComputedArtifacts {
    render_prepared(
        &masm_renderer::prepare_v1(compiled.masm.clone()),
        compiled.preprocessed_commitments,
    )
}

pub(super) fn render_prepared(
    plan: &masm_renderer::V1RenderPlan,
    preprocessed_commitments: PreprocessedCommitments,
) -> ComputedArtifacts {
    let input = &plan.input;
    let mut files = masm_renderer::render_v1(plan);
    let circuit_digest = input.circuit.digest.map(Felt::new_unchecked);
    let relation_digest = input.relation_digest.map(Felt::new_unchecked);
    let mut air_config = include_str!("../../templates/vm-config.rs").to_string();
    replace_felt_array_const(&mut air_config, "RELATION_DIGEST", &relation_digest);
    replace_felt_array_const(&mut air_config, "ACE_CIRCUIT_DIGEST", &circuit_digest);
    replace_u8_array_const(
        &mut air_config,
        "BLAKE3_PREPROCESSED_COMMITMENT",
        &preprocessed_commitments.blake3,
    );
    replace_felt_array_const(
        &mut air_config,
        "RPO_PREPROCESSED_COMMITMENT",
        &preprocessed_commitments.rpo,
    );
    replace_felt_array_const(
        &mut air_config,
        "RPX_PREPROCESSED_COMMITMENT",
        &preprocessed_commitments.rpx,
    );
    replace_u64_array_const(
        &mut air_config,
        "EIDOS_PREPROCESSED_COMMITMENT",
        &preprocessed_commitments.eidos,
    );
    replace_felt_array_const(
        &mut air_config,
        "POSEIDON2_PREPROCESSED_COMMITMENT",
        &preprocessed_commitments.poseidon2,
    );
    replace_u64_array_const(
        &mut air_config,
        "KECCAK_PREPROCESSED_COMMITMENT",
        &preprocessed_commitments.keccak,
    );

    files.push(RenderedArtifact {
        relative_path: AIR_CONFIG_PATH.into(),
        body: air_config,
        ownership: ArtifactOwnership::ProtectedCheckOnly,
    });
    ComputedArtifacts {
        circuit_digest,
        relation_digest,
        preprocessed_commitments,
        files,
    }
}

pub(super) fn canonical_word(word: Word) -> [u64; 4] {
    word_to_array(word).map(|felt| felt.as_canonical_u64())
}

pub(super) fn render_circuit_metadata(
    circuit: &CompiledCircuit,
    max_cycle_log: u32,
) -> CircuitMetadata {
    let stream_felts = u32::try_from(circuit.encoded().size_in_felt())
        .expect("render_circuit_metadata requires valid authored compiler inputs");
    CircuitMetadata {
        encoded_read_count: u32::try_from(circuit.encoded().num_vars())
            .expect("render_circuit_metadata requires valid authored compiler inputs"),
        eval_gate_count: u32::try_from(circuit.encoded().num_eval_rows())
            .expect("render_circuit_metadata requires valid authored compiler inputs"),
        stream_felts,
        max_cycle_log: u8::try_from(max_cycle_log)
            .expect("render_circuit_metadata requires valid authored compiler inputs"),
        digest: canonical_word(circuit.commitment()),
        stream_initial_cv: canonical_word(Eidos::init_chaining_word(
            GENERIC_FELT_SEQUENCE,
            stream_felts,
        )),
    }
}

pub(super) fn render_read_layout(layout: &InputLayout) -> ReadLayout {
    let index = |key| require_input_index(layout, key);
    ReadLayout {
        total_slots: layout.total_inputs,
        public_0: index(InputKey::Public(0)),
        aux_rand_beta: index(InputKey::AuxRandBeta),
        aux_rand_alpha: index(InputKey::AuxRandAlpha),
        preprocessed_current: index(InputKey::Preprocessed { offset: 0, index: 0 }),
        main_current: index(InputKey::Main { offset: 0, index: 0 }),
        aux_current: index(InputKey::AuxCoord { offset: 0, index: 0, coord: 0 }),
        quotient_current: index(InputKey::QuotientChunkCoord { offset: 0, chunk: 0, coord: 0 }),
        preprocessed_next: index(InputKey::Preprocessed { offset: 1, index: 0 }),
        main_next: index(InputKey::Main { offset: 1, index: 0 }),
        aux_next: index(InputKey::AuxCoord { offset: 1, index: 0, coord: 0 }),
        quotient_next: index(InputKey::QuotientChunkCoord { offset: 1, chunk: 0, coord: 0 }),
        aux_bus_boundary: index(InputKey::AuxBusBoundary(0)),
        alpha: index(InputKey::Alpha),
        multi_air_fold_coefficient_0: index(InputKey::MultiAirFoldCoeff(0)),
    }
}

pub(super) fn render_quotient_inputs(
    q: QuotientRecompositionInputs<Felt>,
) -> QuotientReconstruction {
    QuotientReconstruction {
        shift_ratio: q.shift_ratio.as_canonical_u64(),
        first_shift: q.first_shift.as_canonical_u64(),
        first_weight: q.first_weight.as_canonical_u64(),
    }
}

pub(super) fn query_leaf_initial_cvs(geometry: &AirGeometry) -> [[u64; 4]; 4] {
    let widths = [
        geometry.preprocessed.iter().sum::<usize>(),
        geometry.main.iter().sum(),
        geometry.aux_coordinates.iter().sum(),
        geometry.quotient_coordinates,
    ];
    let mut cvs = [[0; 4]; 4];
    for (slot, width) in cvs.iter_mut().zip(widths) {
        let width = u32::try_from(width)
            .expect("query_leaf_initial_cvs requires valid authored compiler inputs");
        *slot = canonical_word(Eidos::init_chaining_word(LMCS_LEAF, width));
    }
    cvs
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PreprocessedCommitments {
    pub blake3: [u8; 32],
    pub rpo: [Felt; 4],
    pub rpx: [Felt; 4],
    pub eidos: [u64; 4],
    pub poseidon2: [Felt; 4],
    pub keccak: [u64; 4],
}

type Commitment<SC> = <<SC as StarkConfig<Felt, QuadFelt>>::Lmcs as Lmcs>::Commitment;

pub fn derive_setup_commitments(digest: [Felt; 4]) -> PreprocessedCommitments {
    let statement = Statement::<Felt, QuadFelt, MidenMultiAir>::new(
        MidenMultiAir::new(),
        vec![Felt::ZERO; NUM_PUBLIC_VALUES],
        vec![],
    )
    .expect("canonical VM public input shape");
    let params = config::pcs_params();
    PreprocessedCommitments {
        blake3: compute_preprocessed_commitment(
            &statement,
            &config::blake3_256_config(params, digest),
        )
        .into(),
        rpo: compute_preprocessed_commitment(&statement, &config::rpo_config(params, digest))
            .into(),
        rpx: compute_preprocessed_commitment(&statement, &config::rpx_config(params, digest))
            .into(),
        eidos: compute_preprocessed_commitment(&statement, &config::eidos_config(params, digest))
            .into(),
        poseidon2: compute_preprocessed_commitment(
            &statement,
            &config::poseidon2_config(params, digest),
        )
        .into(),
        keccak: compute_preprocessed_commitment(&statement, &config::keccak_config(params, digest))
            .into(),
    }
}

fn compute_preprocessed_commitment<SC>(
    statement: &Statement<Felt, QuadFelt, MidenMultiAir>,
    config: &SC,
) -> Commitment<SC>
where
    SC: StarkConfig<Felt, QuadFelt>,
{
    Preprocessed::build(statement, config)
        .map(|preprocessed| preprocessed.commitment())
        .expect("canonical verifier statement has no preprocessed trace")
}

fn require_input_index(input_layout: &InputLayout, key: InputKey) -> usize {
    input_layout
        .index(key)
        .unwrap_or_else(|| panic!("ACE READ input layout is missing {key:?}"))
}

fn word_to_array(word: Word) -> [Felt; 4] {
    [word[0], word[1], word[2], word[3]]
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

fn relation_digest_matches_artifact(
    root: &Path,
    artifact: &ComputedArtifacts,
) -> Result<(), String> {
    let expected = artifact.relation_digest;

    let pin_source = read_file(root, AIR_CONFIG_PATH).map_err(|e| e.to_string())?;
    let commitments = &artifact.preprocessed_commitments;
    let felt_values =
        |values: &[Felt; 4]| values.iter().map(Felt::as_canonical_u64).collect::<Vec<_>>();
    for (name, expected) in [
        ("RELATION_DIGEST", felt_values(&artifact.relation_digest)),
        ("ACE_CIRCUIT_DIGEST", felt_values(&artifact.circuit_digest)),
        ("BLAKE3_PREPROCESSED_COMMITMENT", commitments.blake3.map(u64::from).to_vec()),
        ("RPO_PREPROCESSED_COMMITMENT", felt_values(&commitments.rpo)),
        ("RPX_PREPROCESSED_COMMITMENT", felt_values(&commitments.rpx)),
        ("EIDOS_PREPROCESSED_COMMITMENT", commitments.eidos.to_vec()),
        ("POSEIDON2_PREPROCESSED_COMMITMENT", felt_values(&commitments.poseidon2)),
        ("KECCAK_PREPROCESSED_COMMITMENT", commitments.keccak.to_vec()),
    ] {
        if parse_rust_pin_array(&pin_source, name)? != expected {
            return Err(format!(
                "{name} in {AIR_CONFIG_PATH} differs from derived/explicit pin input"
            ));
        }
    }

    if accepted::RELATION_DIGEST != expected {
        return Err("RELATION_DIGEST in air/src/config.rs is stale".into());
    }
    if accepted::ACE_CIRCUIT_DIGEST != artifact.circuit_digest {
        return Err(
            "ACE_CIRCUIT_DIGEST in air/src/config.rs is stale (it binds the transcript to the \
             one circuit the recursive verifier evaluates)"
                .into(),
        );
    }

    let masm = read_file(root, RELATION_DIGEST_PATH).map_err(|e| e.to_string())?;
    let mut masm_digest: [Felt; 4] = [Felt::ZERO; 4];
    for (i, slot) in masm_digest.iter_mut().enumerate() {
        let name = format!("RELATION_DIGEST_{i}");
        *slot =
            parse_masm_const::<u64>(&masm, &name, "sys/vm/mod.masm").map(Felt::new_unchecked)?;
    }

    if masm_digest != expected {
        return Err("RELATION_DIGEST in sys/vm/mod.masm is stale".into());
    }

    let mut masm_preprocessed_commitment = [0u64; 4];
    for (i, slot) in masm_preprocessed_commitment.iter_mut().enumerate() {
        let name = format!("AND8_PREPROCESSED_TRACE_COM_{i}");
        *slot = parse_masm_const::<u64>(&masm, &name, "sys/vm/mod.masm")?;
    }
    if masm_preprocessed_commitment != artifact.preprocessed_commitments.eidos {
        return Err("And8 preprocessed commitment in sys/vm/mod.masm is stale".into());
    }

    super::delivery::validate_protected(root, &artifact.files)?;

    let commitments = &artifact.preprocessed_commitments;
    if accepted::BLAKE3_PREPROCESSED_COMMITMENT != commitments.blake3
        || accepted::RPO_PREPROCESSED_COMMITMENT != commitments.rpo
        || accepted::RPX_PREPROCESSED_COMMITMENT != commitments.rpx
        || accepted::EIDOS_PREPROCESSED_COMMITMENT != commitments.eidos
        || accepted::POSEIDON2_PREPROCESSED_COMMITMENT != commitments.poseidon2
        || accepted::KECCAK_PREPROCESSED_COMMITMENT != commitments.keccak
    {
        return Err("preprocessed commitments in air/src/config.rs are stale".into());
    }

    Ok(())
}

/// Validate protected inputs and source ABI before any output delivery.
pub(super) fn validate_delivery(root: &Path, artifact: &ComputedArtifacts) -> Result<(), String> {
    super::accepted::load(root)?.check(
        "vm",
        artifact.circuit_digest.map(|felt| felt.as_canonical_u64()),
        artifact.relation_digest.map(|felt| felt.as_canonical_u64()),
    )?;
    relation_digest_matches_artifact(root, artifact)?;
    validate_shared_abi(root)
}

pub(super) fn validate_shared_abi(root: &Path) -> Result<(), String> {
    let constants = read_file(root, STARK_CONSTANTS_PATH).map_err(|error| error.to_string())?;
    for (name, expected) in [
        ("LOG_AIR_TRACE_LENGTHS_PTR", SHARED_ABI.heights_ptr),
        ("LOG_AIR_TRACE_LENGTHS_CAPACITY", SHARED_ABI.heights_capacity),
        ("CONSTRAINT_COMPOSITION_COEFS_PTR", SHARED_ABI.composition_coefficients_ptr),
        ("PUBLIC_INPUTS_ADDRESS_PTR", SHARED_ABI.public_inputs_address_ptr),
    ] {
        if parse_masm_const::<u32>(&constants, name, STARK_CONSTANTS_PATH)? != expected {
            return Err(format!(
                "{name} in live generic MASM differs from the source-owned verifier ABI"
            ));
        }
    }
    Ok(())
}

/// Verify that Miden VM public-input constants match the current AIR set.
pub fn public_inputs_masm_matches_air(root: &Path) -> Result<(), String> {
    let public_inputs = read_file(root, VM_PUBLIC_INPUTS_PATH).map_err(|e| e.to_string())?;
    let num_miden_airs =
        parse_masm_const::<usize>(&public_inputs, "NUM_MIDEN_AIRS", VM_PUBLIC_INPUTS_PATH)?;
    if num_miden_airs != MIDEN_AIR_COUNT {
        return Err("NUM_MIDEN_AIRS in sys/vm/public_inputs.masm is stale".into());
    }

    Ok(())
}

/// Checks the common estimator constants and the MVM descriptor against the shared PCS and current
/// AIRs.
///
/// The parity tests compare final native and MASM levels. This check covers the constants and
/// bounds independently, including values from rounds that do not determine the final level for
/// the current MVM configuration.
pub fn security_masm_matches_air(root: &Path) -> Result<(), String> {
    let estimator = read_file(root, SECURITY_ESTIMATOR_PATH).map_err(|e| e.to_string())?;
    // These literals define the shared fixed-point format and the PCS values used to bound the
    // terms omitted by the MASM estimator. The remaining limits are checked below against the MVM
    // relation and the generic verifier.
    let fractional_bits = crate::vm::security::FIXED_POINT_FRACTIONAL_BITS;
    let fixed_point_one = crate::vm::security::FIXED_POINT_ONE;
    let sample_bits = crate::vm::security::EIDOS_CHALLENGE_SAMPLE_BITS;
    let shared_literals: [(&str, u64); 9] = [
        ("FP_SHIFT", u64::from(fractional_bits)),
        ("FP_ONE", fixed_point_one),
        ("BITS_PER_QUERY_FP", crate::vm::security::BITS_PER_QUERY),
        ("CHALLENGE_SAMPLE_BITS", sample_bits >> fractional_bits),
        ("SECURITY_CAP_BITS", crate::vm::security::SECURITY_CAP >> fractional_bits),
        (
            "DEEP_FIELD_BASE_BITS",
            (sample_bits >> fractional_bits) - u64::from(config::pcs_params().log_blowup()),
        ),
        ("FRI_FOLDING_BASE_BITS", crate::vm::security::FOLDING_BASE >> fractional_bits),
        ("LOG2_E_FP", crate::vm::security::LOG2_E),
        ("MAX_CONSTRAINT_DEGREE", (1u64 << config::pcs_params().log_blowup()) + 1),
    ];

    for (name, expected) in shared_literals {
        let actual = parse_masm_const::<u64>(&estimator, name, SECURITY_ESTIMATOR_PATH)?;
        if actual != expected {
            return Err(format!("{name} in {SECURITY_ESTIMATOR_PATH} is stale"));
        }
    }

    // The estimator omits four native security terms only while the MVM shape and the generic
    // verifier's parameter ranges satisfy its documented bounds. Independent metadata tests check
    // production shape against symbolic AIRs; these checks fail if it leaves the estimator
    // envelope. This function also pins the generic verifier bounds directly.
    let wrapper = read_file(root, RELATION_DIGEST_PATH).map_err(|e| e.to_string())?;
    let utils = read_file(root, GENERIC_UTILS_PATH).map_err(|e| e.to_string())?;
    let air_shape = crate::vm::security::derive_air_shape();
    let parsed = |name: &str| parse_masm_const::<u64>(&estimator, name, SECURITY_ESTIMATOR_PATH);
    let lookup = air_shape.lookup.expect("the MVM uses a lookup argument");
    let lookup_coefficient =
        (u64::from(lookup.max_message_width) + 2) * u64::from(lookup.fractions_per_row);
    let max_boundary_terms = u64::from(crate::vm::security::CORE_BOUNDARY_LOOKUP_TERMS)
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
        ("LOOKUP_POW_BITS", crate::vm::security::LOOKUP_POW_BITS as u64),
        ("MAX_MESSAGE_WIDTH", lookup.max_message_width as u64),
        ("NUM_COMPOSED_CONSTRAINTS", air_shape.num_composed_constraints as u64),
        ("MAX_CONSTRAINT_DEGREE", air_shape.max_constraint_degree as u64),
        (
            "NUM_DEEP_TERMS",
            air_shape.num_deep_terms.expect("the MVM uses DEEP composition") as u64,
        ),
        (
            "CORE_BOUNDARY_LOOKUP_TERMS",
            crate::vm::security::CORE_BOUNDARY_LOOKUP_TERMS as u64,
        ),
        ("LOOKUP_FRACTIONS_PER_ROW", lookup.fractions_per_row as u64),
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
            let line = line.trim();
            let value = line.strip_prefix("pub ").unwrap_or(line).strip_prefix(&prefix)?;
            let value = value.split('#').next().unwrap_or(value).trim();
            value.parse::<T>().ok()
        })
        .ok_or_else(|| format!("constant {name} not found in {file_label}"))
}

fn replace_felt_array_const(content: &mut String, name: &str, values: &[Felt; 4]) {
    // Preserve authored formatting when accepted values are already current.
    if parse_rust_pin_array(content, name)
        .is_ok_and(|actual| actual == values.iter().map(Felt::as_canonical_u64).collect::<Vec<_>>())
    {
        return;
    }
    let mut body: String = values
        .iter()
        .map(|f| format!("\n    Felt::new_unchecked({}),", f.as_canonical_u64()))
        .collect();
    body.push('\n');
    replace_rust_array_const(content, "pub const", name, &body)
}

fn replace_u64_array_const(content: &mut String, name: &str, values: &[u64; 4]) {
    // Preserve authored formatting when accepted values are already current.
    if parse_rust_pin_array(content, name).is_ok_and(|actual| actual == values.to_vec()) {
        return;
    }
    let mut body: String = values.iter().map(|value| format!("\n    {value},")).collect();
    body.push('\n');
    replace_rust_array_const(content, "pub const", name, &body)
}

fn replace_u8_array_const(content: &mut String, name: &str, values: &[u8; 32]) {
    // Preserve authored formatting when accepted values are already current.
    if parse_rust_pin_array(content, name)
        .is_ok_and(|actual| actual == values.iter().copied().map(u64::from).collect::<Vec<_>>())
    {
        return;
    }
    let mut body: String = values.iter().map(|value| format!("\n    {value},")).collect();
    body.push('\n');
    replace_rust_array_const(content, "pub const", name, &body)
}

fn replace_rust_array_const(
    content: &mut String,
    declaration_prefix: &str,
    name: &str,
    body: &str,
) {
    let marker = format!("{declaration_prefix} {name}:");
    let start = content.find(&marker).unwrap_or_else(|| panic!("{name} not found"));
    assert!(
        !content[start + marker.len()..].contains(&marker),
        "{name} is declared more than once"
    );

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
        .unwrap_or_else(|| panic!("{name} initializer not found"));

    let init_start = content[assign + 1..]
        .find(|character: char| !character.is_whitespace())
        .map(|offset| assign + 1 + offset)
        .unwrap_or_else(|| panic!("{name} initializer not found"));
    assert!(content.as_bytes()[init_start] == b'[', "{name} initializer not found");

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
    let terminator_end = terminator_end.unwrap_or_else(|| panic!("{name} terminator not found"));
    content.replace_range(assign..terminator_end, &format!("= [{body}];"));
}

/// Read canonical integer pin arrays while tolerating rustfmt's array line wrapping.
fn parse_rust_pin_array(content: &str, name: &str) -> Result<Vec<u64>, String> {
    let marker = format!("pub const {name}:");
    let mut declarations = content
        .match_indices(&marker)
        .filter(|(start, _)| *start == 0 || content.as_bytes()[start - 1] == b'\n');
    let start = declarations
        .next()
        .map(|(start, _)| start)
        .ok_or_else(|| format!("{name} declaration not found"))?;
    if declarations.next().is_some() {
        return Err(format!("{name} declared more than once"));
    }
    let declaration = &content[start..];
    let line_end = declaration.find('\n').unwrap_or(declaration.len());
    let assign = declaration[..line_end]
        .find('=')
        .ok_or_else(|| format!("{name} initializer not found"))?;
    let initializer = declaration[assign + 1..]
        .trim_start()
        .strip_prefix('[')
        .ok_or_else(|| format!("{name} is not an array"))?;
    let end = initializer
        .find("];")
        .ok_or_else(|| format!("{name} array terminator not found"))?;
    initializer[..end]
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            let value = value
                .strip_prefix("Felt::new_unchecked(")
                .and_then(|value| value.strip_suffix(')'))
                .unwrap_or(value);
            value.parse::<u64>().map_err(|e| format!("{name} invalid canonical limb: {e}"))
        })
        .collect()
}

fn read_file(root: &Path, rel_path: &str) -> io::Result<String> {
    let path = root.join(rel_path);
    fs::read_to_string(&path)
        .map_err(|e| io::Error::new(e.kind(), format!("failed to read {}: {e}", path.display())))
}

pub struct ComputedArtifacts {
    pub circuit_digest: [Felt; 4],
    pub relation_digest: [Felt; 4],
    pub preprocessed_commitments: PreprocessedCommitments,
    pub files: Vec<RenderedArtifact>,
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::{super::expect_panic, *};

    const PVM_PROTECTED_WRAPPER: &str = "crates/lib/core/asm/sys/pvm/mod.masm";
    const DELIVERY_MANAGED_PATHS: [&str; 15] = [
        CONSTRAINTS_EVAL_PATH,
        VM_LAYOUT_PATH,
        VM_OOD_FRAMES_PATH,
        VM_DEEP_QUERIES_PATH,
        "crates/lib/core/asm/sys/pvm/constraints_eval.masm",
        "crates/lib/core/asm/sys/pvm/layout.masm",
        "crates/lib/core/asm/sys/pvm/ood_frames.masm",
        "crates/lib/core/asm/sys/pvm/deep_queries.masm",
        "crates/lib/core/asm/sys/pvm/aux_trace.masm",
        "crates/lib/core/asm/sys/pvm/public_inputs.masm",
        "crates/air/generated/artifacts/vm-evaluator.rs.zlib",
        "crates/air/generated/artifacts/vm-degrees.rs",
        "crates/air/generated/artifacts/precompile-degrees.rs",
        "crates/air/generated/artifacts/vm-metadata.rs",
        "crates/air/generated/artifacts/precompile-metadata.rs",
    ];

    struct DeliveryFixture {
        root: std::path::PathBuf,
    }

    impl DeliveryFixture {
        fn new(vm: &ComputedArtifacts, pvm: &super::super::precompile::GeneratedArtifacts) -> Self {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let unique = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let fixture = Self {
                root: std::env::temp_dir().join(format!(
                    "miden-masm-delivery-{}-{timestamp}-{unique}",
                    std::process::id(),
                )),
            };
            // This fixture exercises delivery behavior, not accepted-identity derivation.
            // Independent pin/golden and live-library tests retain that separate obligation.
            let accepted = serde_json::json!({
                "accepted_schema": 1,
                "relations": {
                    "vm": {
                        "protocol_id": 1,
                        "accepted_circuit_digest": vm.circuit_digest.map(|felt| felt.as_canonical_u64()),
                        "accepted_relation_digest": vm.relation_digest.map(|felt| felt.as_canonical_u64()),
                    },
                    "precompile": {
                        "protocol_id": 4,
                        "accepted_circuit_digest": canonical_word(pvm.circuit_digest),
                        "accepted_relation_digest": pvm.relation_digest.map(|felt| felt.as_canonical_u64()),
                    },
                },
            });
            assert_eq!((vm.files.len(), pvm.files.len()), (6, 9));
            for relative in &DELIVERY_MANAGED_PATHS[..10] {
                let file = vm
                    .files
                    .iter()
                    .chain(&pvm.files)
                    .find(|file| file.relative_path == *relative)
                    .unwrap();
                assert_eq!(file.ownership, ArtifactOwnership::Managed);
            }
            fixture.write(
                "crates/air/generated/protocol/accepted.json",
                &serde_json::to_string_pretty(&accepted).unwrap(),
            );
            let shared = format!(
                "pub const LOG_AIR_TRACE_LENGTHS_PTR = {}\n\
                 pub const LOG_AIR_TRACE_LENGTHS_CAPACITY = {}\n\
                 pub const CONSTRAINT_COMPOSITION_COEFS_PTR = {}\n\
                 pub const PUBLIC_INPUTS_ADDRESS_PTR = {}\n",
                SHARED_ABI.heights_ptr,
                SHARED_ABI.heights_capacity,
                SHARED_ABI.composition_coefficients_ptr,
                SHARED_ABI.public_inputs_address_ptr,
            );
            fixture.write(STARK_CONSTANTS_PATH, &shared);
            for relative in [
                AIR_CONFIG_PATH,
                RELATION_DIGEST_PATH,
                "crates/air/generated/src/precompile/ace_constants.rs",
                "crates/air/generated/src/precompile/protocol.rs",
                PVM_PROTECTED_WRAPPER,
            ] {
                let file = vm
                    .files
                    .iter()
                    .chain(&pvm.files)
                    .find(|file| file.relative_path == relative)
                    .unwrap();
                assert_eq!(file.ownership, ArtifactOwnership::ProtectedCheckOnly);
                fixture.write(relative, &file.body);
            }
            for relative in DELIVERY_MANAGED_PATHS {
                fixture.write(relative, &format!("unchanged managed sentinel: {relative}\n"));
            }
            validate_delivery(&fixture.root, vm).expect("valid VM delivery fixture");
            super::super::precompile::validate_delivery(&fixture.root, pvm)
                .expect("valid PVM delivery fixture");
            fixture
        }

        fn write(&self, relative: &str, body: &str) {
            let path = self.root.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, body).unwrap();
        }

        fn managed_contents(&self) -> Vec<Vec<u8>> {
            DELIVERY_MANAGED_PATHS
                .iter()
                .map(|relative| fs::read(self.root.join(relative)).unwrap())
                .collect()
        }
    }

    impl Drop for DeliveryFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn delivery_artifacts() -> (ComputedArtifacts, super::super::precompile::GeneratedArtifacts) {
        let vm = compile_and_render(accepted_setup_commitments());
        let pvm = super::super::precompile::compile_and_render(
            super::super::precompile::accepted_setup_commitment(),
        );
        (vm, pvm)
    }

    #[test]
    fn typed_render_rejects_a_misaligned_ace_stream() {
        let mut compiled = compile(accepted_setup_commitments());
        compiled.masm.circuit.stream_felts -= 1;
        let error = expect_panic(|| render(&compiled));
        assert!(error.to_string().contains("circuit metadata"), "unexpected error: {error}");
    }

    #[test]
    fn compiler_panic_prevents_managed_output_writes() {
        let (vm, pvm) = delivery_artifacts();
        let fixture = DeliveryFixture::new(&vm, &pvm);
        let before = fixture.managed_contents();
        let mut compiled = compile(accepted_setup_commitments());
        compiled.masm.circuit.stream_felts -= 1;
        expect_panic(|| {
            let artifact = render(&compiled);
            super::super::delivery::deliver(&fixture.root, &artifact.files, Mode::Write).unwrap();
        });
        assert_eq!(fixture.managed_contents(), before);
    }

    #[test]
    fn protected_full_body_drift_is_detected_with_unchanged_numeric_pins() {
        let (vm, pvm) = delivery_artifacts();
        let fixture = DeliveryFixture::new(&vm, &pvm);
        for (relative, suffix) in [
            (AIR_CONFIG_PATH, "// protected body drift\n"),
            (RELATION_DIGEST_PATH, "# protected body drift\n"),
        ] {
            let original = read_file(&fixture.root, relative).unwrap();
            let drifted = format!("{original}\n{suffix}");
            if relative == AIR_CONFIG_PATH {
                assert_eq!(
                    parse_rust_pin_array(&original, "RELATION_DIGEST").unwrap(),
                    parse_rust_pin_array(&drifted, "RELATION_DIGEST").unwrap()
                );
            } else {
                assert_eq!(
                    parse_masm_const::<u64>(&original, "RELATION_DIGEST_0", relative).unwrap(),
                    parse_masm_const::<u64>(&drifted, "RELATION_DIGEST_0", relative).unwrap()
                );
            }
            fixture.write(relative, &drifted);
            let error = validate_delivery(&fixture.root, &vm).unwrap_err();
            assert!(
                error.contains(relative) && error.contains("protected template-body drift"),
                "unexpected error: {error}"
            );
            fixture.write(relative, &original);
        }
    }

    #[test]
    fn rejected_write_delivery_preserves_every_managed_output() {
        let (vm, pvm) = delivery_artifacts();
        for rejected_input in ["accepted identity", "VM protected body", "PVM protected body"] {
            let fixture = DeliveryFixture::new(&vm, &pvm);
            let before = fixture.managed_contents();
            let expected = match rejected_input {
                "accepted identity" => {
                    let relative = "crates/air/generated/protocol/accepted.json";
                    let mut accepted: serde_json::Value =
                        serde_json::from_str(&read_file(&fixture.root, relative).unwrap()).unwrap();
                    let limb = &mut accepted["relations"]["vm"]["accepted_circuit_digest"][0];
                    *limb = serde_json::Value::from(limb.as_u64().unwrap() + 1);
                    fixture.write(relative, &serde_json::to_string_pretty(&accepted).unwrap());
                    "candidate identity differs"
                },
                "VM protected body" => {
                    fixture.write(
                        RELATION_DIGEST_PATH,
                        &format!(
                            "{}\n# rejected body drift\n",
                            read_file(&fixture.root, RELATION_DIGEST_PATH).unwrap()
                        ),
                    );
                    RELATION_DIGEST_PATH
                },
                "PVM protected body" => {
                    fixture.write(
                        PVM_PROTECTED_WRAPPER,
                        &format!(
                            "{}\n# rejected body drift\n",
                            read_file(&fixture.root, PVM_PROTECTED_WRAPPER).unwrap()
                        ),
                    );
                    PVM_PROTECTED_WRAPPER
                },
                _ => unreachable!(),
            };
            let error = super::super::run(&fixture.root, Mode::Write)
                .expect_err("rejected input must prevent delivery");
            assert!(error.contains(expected), "unexpected {rejected_input} error: {error}");
            assert_eq!(
                fixture.managed_contents(),
                before,
                "rejected {rejected_input} changed a managed output"
            );
        }
    }

    #[test]
    fn accepted_pin_reader_supports_wrapping_and_rejects_malformed_values() {
        for input in [
            "pub const PIN: [u64; 4] = [1, 2, 3, 4];\n",
            "pub const PIN: [Felt; 4] =\n[\n Felt::new_unchecked(1), Felt::new_unchecked(2),\n Felt::new_unchecked(3), Felt::new_unchecked(4),\n];\n",
        ] {
            assert_eq!(parse_rust_pin_array(input, "PIN").unwrap(), [1, 2, 3, 4]);
        }
        for input in [
            "pub const OTHER: [u64; 1] = [1];",
            "pub const PIN: [u64; 1] = [1];\npub const PIN: [u64; 1] = [2];",
            "pub const PIN: [u64; 1] = [invalid];",
            "pub const PIN: [u64; 1] = [1]",
        ] {
            assert!(parse_rust_pin_array(input, "PIN").is_err());
        }
    }

    #[test]
    fn generated_felt_array_replacement_is_rustfmt_safe_and_fails_closed() {
        let values = [1, 2, 3, 4].map(Felt::new_unchecked);
        let name = "RELATION_DIGEST";
        let declaration = "pub const RELATION_DIGEST: [Felt; 4]";
        let body = "\n    Felt::new_unchecked(1),\n    Felt::new_unchecked(2),\n    \
                    Felt::new_unchecked(3),\n    Felt::new_unchecked(4),\n";
        let following = "pub(crate) const UNTOUCHED: &str = \"];\";\n";

        let mut wrapped = format!("{declaration} =\n    [0, 0, 0, 0];\n\n{following}");
        replace_felt_array_const(&mut wrapped, name, &values);
        assert_eq!(wrapped, format!("{declaration} = [{body}];\n\n{following}"));

        let mut malformed = format!("{declaration} = [0, 0, 0, 0;\n\n{following}");
        let original = malformed.clone();
        let error = expect_panic(|| replace_felt_array_const(&mut malformed, name, &values));
        assert!(error.to_string().contains("terminator not found"));
        assert_eq!(malformed, original);

        let mut duplicate =
            format!("{declaration} = [0, 0, 0, 0];\n{declaration} = [0, 0, 0, 0];\n");
        let original = duplicate.clone();
        let error = expect_panic(|| replace_felt_array_const(&mut duplicate, name, &values));
        assert!(error.to_string().contains("declared more than once"));
        assert_eq!(duplicate, original);
    }

    #[test]
    fn unchanged_pin_arrays_keep_authored_formatting() {
        let mut felt = String::from(
            "pub const PIN: [Felt; 4] =\n    [Felt::new_unchecked(1), Felt::new_unchecked(2),\n     Felt::new_unchecked(3), Felt::new_unchecked(4)];\n",
        );
        let original = felt.clone();
        replace_felt_array_const(&mut felt, "PIN", &[1, 2, 3, 4].map(Felt::new_unchecked));
        assert_eq!(felt, original);

        let mut limbs = String::from("pub const PIN: [u64; 4] = [1, 2,\n 3, 4];\n");
        let original = limbs.clone();
        replace_u64_array_const(&mut limbs, "PIN", &[1, 2, 3, 4]);
        assert_eq!(limbs, original);

        let body = ["7"; 32].join(", ");
        let mut bytes = format!("pub const PIN: [u8; 32] =\n    [{body}];\n");
        let original = bytes.clone();
        replace_u8_array_const(&mut bytes, "PIN", &[7; 32]);
        assert_eq!(bytes, original);
    }

    #[test]
    fn deep_query_loader_repeats_follow_air_geometry() {
        let compiled = compile(accepted_setup_commitments());
        let artifact = render(&compiled);
        let deep_queries = &artifact
            .files
            .iter()
            .find(|file| file.relative_path == VM_DEEP_QUERIES_PATH)
            .unwrap()
            .body;
        let geometry = &compiled.masm.geometry;
        for (proc_name, expected) in [
            (
                "load_preprocessed_segment",
                geometry.preprocessed.iter().sum::<usize>() / ADV_PIPE_BLOCK_FELTS,
            ),
            (
                "load_main_segment_execution_trace",
                geometry.main.iter().sum::<usize>() / ADV_PIPE_BLOCK_FELTS,
            ),
            (
                "load_aux_segment_execution_trace",
                geometry.aux_coordinates.iter().sum::<usize>() / ADV_PIPE_BLOCK_FELTS,
            ),
            (
                "load_constraints_composition_polys_trace",
                geometry.quotient_coordinates / ADV_PIPE_BLOCK_FELTS,
            ),
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
