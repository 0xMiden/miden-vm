//! Source-owned PVM ACE constants, layout, and MASM generation.
//!
//! Compilation adapts authored AIR and explicit setup inputs; pure rendering consumes compiled
//! metadata plus packaged engine templates.
//! `run` defaults to checking the caller's checkout; ordinary writes update generated projections
//! while retaining accepted pins. Fresh setup derivation and deliberate pin acceptance are separate
//! operations. Byte comparisons complement independent numeric pin/shape checks and downstream
//! native/MASM layout and protocol oracles.

use std::{
    format,
    path::Path,
    string::{String, ToString},
};

use miden_ace::{CompiledCircuit, InputKey, InputLayout};
use miden_core::{Felt, Word, utils::Matrix};
use miden_stark::{
    air::{BaseAir, LiftedAir, MultiAir},
    quotient_recomposition_inputs,
};

pub use super::Mode;
use super::{
    constraints::{
        self, canonical_word, query_leaf_initial_cvs, render_circuit_metadata,
        render_quotient_inputs, render_read_layout,
    },
    masm_renderer::{
        self, AirGeometry, ArtifactOwnership, FixedUintInput, HeightRule, PvmAbiAnchors,
        PvmAirInput, PvmGlueInput, RelationInput, RenderedArtifact, SecurityParameters,
        V1RenderInput,
    },
};
use crate::precompile::{Air as ChipletAir, security as pvm_security};

mod accepted {
    include!("../../templates/pvm-pins.rs");
}
use accepted::{
    GENERATED_BY, PVM_ACE_CIRCUIT_DIGEST, PVM_CIRCUIT_SHAPE, PVM_PREPROCESSED_COMMITMENT,
    PVM_RELATION_DIGEST, relation_digest_for_circuit,
};

const CONSTANTS_PATH: &str = "crates/air/generated/src/precompile/ace_constants.rs";
const PROTOCOL_PATH: &str = "crates/air/generated/src/precompile/protocol.rs";
#[cfg(test)]
const PVM_DEEP_QUERIES_PATH: &str = "crates/lib/core/asm/sys/pvm/deep_queries.masm";

/// Fixed 4-Ki-felt boundary after the VM relation's reserved ACE stream region. The PVM's complete
/// READ section starts here; its aux-randomness anchor is later because four public EF inputs
/// precede it.
pub(super) const PVM_READ_START: u32 = 3_225_432_064;
/// Start of the VM relation's next scratch region; the PVM allocation must end before it.
const NEXT_VM_REGION_START: u32 = constraints::VM_ABI.current_trace_row_ptr;
/// Runs write (`--write`) or staleness-check (`--check`) mode.
pub fn run(root: &Path, mode: Mode) -> Result<(), String> {
    // Validate both current relations before delivering any managed projection.
    super::run(root, mode)
}

/// Explicit accepted setup value; supplying it does not derive setup afresh.
pub fn accepted_setup_commitment() -> Word {
    Word::new(PVM_PREPROCESSED_COMMITMENT.map(Felt::new_unchecked))
}

/// Captured circuit and layout inputs needed by pure MASM rendering.
#[derive(Clone, Debug)]
pub struct CompiledVerifierInputs {
    pub masm: V1RenderInput,
}

/// Capture authored PVM AIR and adapt its compiled layout with explicit setup input.
pub fn compile(commitment: Word) -> CompiledVerifierInputs {
    compile_inputs(Some(commitment))
}

/// Compatibility orchestration over explicit compilation and pure rendering.
pub fn compile_and_render(commitment: Word) -> GeneratedArtifacts {
    render(&compile(commitment))
}

/// Independently derive source fixed setup and compare the accepted outputs.
pub fn check_setup(root: &Path) -> Result<(), String> {
    let artifacts = compute(None);
    validate_delivery(root, &artifacts)?;
    super::delivery::deliver(root, &artifacts.files, Mode::Check)
}

pub struct GeneratedArtifacts {
    /// Eidos digest of the accepted ACE circuit's instruction stream.
    pub circuit_digest: Word,
    /// Relation digest binding that circuit into the Fiat-Shamir transcript.
    pub relation_digest: [Felt; 4],
    /// Commitment to the preprocessed (setup) LDE tree under the Eidos config —
    /// the configuration an in-VM verifier targets.
    ///
    /// This is a trusted verifier input rather than proof data: the Rust verifier
    /// rebuilds the bundle locally, but a MASM verifier has no way to, so it must be
    /// pinned as a protocol constant and observed into the transcript.
    pub preprocessed_commitment: Word,
    /// Shape of the encoded circuit stream.
    pub shape: CircuitShape,
    pub files: std::vec::Vec<RenderedArtifact>,
}

/// The encoded ACE stream's shape, which an in-VM verifier needs as compile-time constants: how
/// much to read and the digest the loaded stream must reproduce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitShape {
    pub num_inputs: usize,
    pub num_eval_gates: usize,
    pub stream_len: usize,
}

/// Build candidates and render them without accepting new protocol values.
fn compute(supplied_commitment: Option<Word>) -> GeneratedArtifacts {
    render(&compile_inputs(supplied_commitment))
}

fn compile_inputs(supplied_commitment: Option<Word>) -> CompiledVerifierInputs {
    let circuit = CompiledCircuit::from_circuit(
        crate::precompile::ace::build_canonical_precompile_ace_circuit(),
    );
    let layout = circuit.layout();
    let quotient_chunks = layout.counts.num_quotient_chunks;
    assert!(
        quotient_chunks.is_power_of_two(),
        "PVM quotient chunk count {quotient_chunks} is not a power of two"
    );
    let quotient = quotient_recomposition_inputs::<Felt>(
        quotient_chunks.ilog2() as u8,
        crate::precompile::stark_config::precompile_pcs_params().log_blowup(),
    )
    .expect("compile_inputs requires valid authored compiler inputs");
    let relation_digest = relation_digest_for_circuit(&circuit.commitment());
    let preprocessed_commitment =
        supplied_commitment.unwrap_or_else(|| derive_setup_commitment(relation_digest));
    let geometry =
        AirGeometry::from_airs(crate::precompile::MultiAir::new().airs(), quotient_chunks);
    let air_shape = pvm_security::derive_air_shape();
    let lookup = air_shape.lookup.expect("the relation uses lookup");
    CompiledVerifierInputs {
        masm: V1RenderInput {
            relation: RelationInput::Pvm {
                abi: PvmAbiAnchors {
                    read_base: PVM_READ_START,
                    scatter_reserve_felts: 96,
                    next_region_start: NEXT_VM_REGION_START,
                },
                glue: compile_glue(layout),
            },
            circuit: render_circuit_metadata(&circuit, max_periodic_cycle_len_log()),
            query_leaf_initial_cvs: query_leaf_initial_cvs(&geometry),
            geometry,
            counts: layout.counts,
            read_layout: render_read_layout(layout),
            quotient: render_quotient_inputs(quotient),
            relation_digest: relation_digest.map(|felt| felt.as_canonical_u64()),
            preprocessed_commitment: canonical_word(preprocessed_commitment),
            security: SecurityParameters {
                lookup_pow_bits: pvm_security::LOOKUP_POW_BITS,
                max_message_width: lookup.max_message_width,
                num_composed_constraints: air_shape.num_composed_constraints,
                max_constraint_degree: air_shape.max_constraint_degree,
                num_deep_terms: air_shape
                    .num_deep_terms
                    .expect("PVM AIR must use DEEP composition"),
                lookup_fractions_per_row: lookup.fractions_per_row,
                boundary_lookup_terms: pvm_security::FIXED_BOUNDARY_LOOKUP_TERMS,
            },
            shared_abi: constraints::SHARED_ABI,
            regeneration_command: GENERATED_BY.into(),
        },
    }
}

/// Adapt authored declarations and the originating ACE layout, never production metadata tables.
fn compile_glue(layout: &InputLayout) -> PvmGlueInput {
    use crate::precompile::{
        fixed,
        relations::{BusId, MAX_MESSAGE_WIDTH},
    };
    let relation = crate::precompile::MultiAir::new();
    let airs = relation
        .airs()
        .iter()
        .enumerate()
        .map(|(id, air)| {
            let rows = air
                .max_periodic_length()
                .max(2)
                .max(air.preprocessed_trace().map(|trace| trace.height()).unwrap_or(0));
            assert!(rows.is_power_of_two(), "PVM minimum height must be a power of two");
            let height = match air.fixed_log_height() {
                Some(log) => {
                    assert_eq!(log, rows.ilog2(), "fixed height must match authored trace");
                    HeightRule::Fixed(log)
                },
                None => HeightRule::Minimum(rows.ilog2()),
            };
            assert_eq!(air.num_aux_values(), 1, "PVM glue requires one boundary value per AIR");
            PvmAirInput {
                height,
                boundary_slot: layout
                    .index(InputKey::AuxBusBoundary(id))
                    .expect("PVM ACE must contain each boundary slot"),
            }
        })
        .collect();
    let uints = fixed::fixed_uintval_msgs()
        .map(|msg| FixedUintInput {
            ptr: u32::try_from(msg.ptr.as_canonical_u64()).expect("fixed pointer fits u32"),
            bound_ptr: u32::try_from(msg.bound_ptr.as_canonical_u64())
                .expect("fixed pointer fits u32"),
            limbs: msg
                .limbs
                .map(|limb| u32::try_from(limb.as_canonical_u64()).expect("32-bit limb")),
        })
        .collect();
    let groups = fixed::fixed_ecgroup_msgs()
        .map(|msg| {
            [
                msg.group_ptr,
                msg.a_ptr,
                msg.b_ptr,
                msg.bound_ptr,
                msg.scalar_bound_ptr,
                msg.beta_ptr,
                msg.lambda_ptr,
            ]
            .map(|felt| u32::try_from(felt.as_canonical_u64()).expect("fixed pointer fits u32"))
        })
        .collect();
    PvmGlueInput {
        airs,
        num_public_values: relation.num_air_inputs(),
        max_aux_inputs: relation.max_aux_inputs(),
        num_aux_inputs: 0,
        uints,
        groups,
        uint_bus_scale: BusId::UintVal as u32 + 1,
        ec_bus_scale: BusId::EcGroup as u32 + 1,
        max_message_width: MAX_MESSAGE_WIDTH,
    }
}

/// Pure rendering of compiled metadata; no AIR capture, setup, acceptance or destination I/O.
pub fn render(compiled: &CompiledVerifierInputs) -> GeneratedArtifacts {
    render_prepared(&masm_renderer::prepare_v1(compiled.masm.clone()))
}

pub(super) fn render_prepared(plan: &masm_renderer::V1RenderPlan) -> GeneratedArtifacts {
    let input = &plan.input;
    let mut files = masm_renderer::render_v1(plan);
    let circuit_digest = Word::new(input.circuit.digest.map(Felt::new_unchecked));
    let relation_digest = input.relation_digest.map(Felt::new_unchecked);
    let preprocessed_commitment = Word::new(input.preprocessed_commitment.map(Felt::new_unchecked));
    let shape = CircuitShape {
        num_inputs: input.circuit.encoded_read_count as usize,
        num_eval_gates: input.circuit.eval_gate_count as usize,
        stream_len: input.circuit.stream_felts as usize,
    };
    let mut constants_rs = include_str!("../../templates/pvm-constants.rs").to_string();
    for (name, word) in [
        ("PVM_RELATION_DIGEST", Word::new(relation_digest)),
        ("PVM_ACE_CIRCUIT_DIGEST", circuit_digest),
        ("PVM_PREPROCESSED_COMMITMENT", preprocessed_commitment),
    ] {
        replace_limb_array_const(&mut constants_rs, name, &word);
    }
    replace_shape_const(&mut constants_rs, shape);
    for (path, body) in [
        (CONSTANTS_PATH, constants_rs),
        (PROTOCOL_PATH, render_protocol(&relation_digest)),
    ] {
        files.push(RenderedArtifact {
            relative_path: path.into(),
            body,
            ownership: ArtifactOwnership::ProtectedCheckOnly,
        });
    }
    GeneratedArtifacts {
        circuit_digest,
        relation_digest,
        preprocessed_commitment,
        shape,
        files,
    }
}

/// Commitment to the setup (preprocessed) trace tree under the Eidos config.
///
/// Built directly by the lower STARK setup implementation from source MultiAir fixed data and
/// explicit relation/configuration input, independently of product caches. The commitment itself
/// is digest-independent; threading the digest avoids relying on that property here.
pub fn derive_setup_commitment(digest: [Felt; 4]) -> Word {
    let params = crate::precompile::stark_config::precompile_pcs_params();
    let config = crate::precompile::stark_config::eidos_config(params, digest);
    // The LMCS commitment is a 4-felt hash; Word is the MASM-facing representation.
    let statement = miden_stark::air::Statement::<
        Felt,
        miden_core::field::QuadFelt,
        crate::precompile::MultiAir,
    >::new(
        crate::precompile::MultiAir::new(),
        vec![Felt::ZERO; crate::precompile::logup::NUM_PUBLIC_VALUES],
        vec![],
    )
    .expect("canonical PVM public input shape");
    let commitment: [u64; 4] = miden_stark::Preprocessed::build(&statement, &config)
        .expect("PVM source declares a fixed preprocessed table")
        .commitment()
        .into();
    Word::new(commitment.map(Felt::new_unchecked))
}

fn max_periodic_cycle_len_log() -> u32 {
    let max_len = ChipletAir::all()
        .iter()
        .flat_map(|air| <ChipletAir as BaseAir<Felt>>::periodic_columns(air).into_owned())
        .map(|column| column.len())
        .max()
        .unwrap_or(1);
    assert!(
        max_len.is_power_of_two(),
        "maximum PVM AIR periodic cycle length is not a power of two"
    );
    max_len.ilog2()
}

/// Validate accepted inputs and protected projections before any managed output write.
pub(super) fn validate_delivery(root: &Path, artifacts: &GeneratedArtifacts) -> Result<(), String> {
    super::accepted::load(root)?.check(
        "precompile",
        canonical_word(artifacts.circuit_digest),
        artifacts.relation_digest.map(|felt| felt.as_canonical_u64()),
    )?;
    constraints::validate_shared_abi(root)?;
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
            return Err(format!("{name} differs from explicit accepted source inputs"));
        }
    }
    if PVM_CIRCUIT_SHAPE
        != (
            artifacts.shape.num_inputs,
            artifacts.shape.num_eval_gates,
            artifacts.shape.stream_len,
        )
    {
        return Err("PVM_CIRCUIT_SHAPE differs from accepted source inputs".into());
    }
    super::delivery::validate_protected(root, &artifacts.files)
}

fn render_protocol(relation_digest: &[Felt; 4]) -> String {
    let body: String = relation_digest
        .iter()
        .map(|felt| format!("    {},\n", felt.as_canonical_u64()))
        .collect();
    format!(
        "/// Relation digest binding the canonical PVM ACE circuit into the Fiat-Shamir transcript.\n\
         ///\n\
         /// Checked by `air-codegen`; must match `PVM_RELATION_DIGEST` in\n\
         /// `miden-air::precompile::ace_constants`.\n\
         #[rustfmt::skip]\n\
         pub const PVM_RELATION_DIGEST: [u64; 4] = [\n{body}];\n"
    ) + "\ninclude!(\"../../artifacts/precompile-variants.rs\");\n\n/// Returns the identity of the exact selected canonical relation.\npub fn relation_digest(variant: super::PvmAirVariant) -> super::stark_config::RelationDigest {\n    PVM_VARIANT_RELATION_DIGESTS[variant.as_u8() as usize].map(miden_core::Felt::new_unchecked)\n}\n"
}

/// Rewrite the initializer of a `pub const NAME: [u64; 4]` declaration.
fn replace_limb_array_const(content: &mut String, name: &str, word: &Word) {
    let body: String =
        word.iter().map(|felt| format!("\n    {},", felt.as_canonical_u64())).collect();
    replace_const_initializer(content, name, "[", "];", &format!("{body}\n"))
}

/// Rewrite the initializer of the `pub const PVM_CIRCUIT_SHAPE: (usize, usize, usize)`
/// declaration.
fn replace_shape_const(content: &mut String, shape: CircuitShape) {
    let body = format!("{}, {}, {}", shape.num_inputs, shape.num_eval_gates, shape.stream_len);
    replace_const_initializer(content, "PVM_CIRCUIT_SHAPE", "(", ");", &body)
}

fn replace_const_initializer(
    content: &mut String,
    name: &str,
    open: &str,
    close: &str,
    body: &str,
) {
    let marker = format!("pub const {name}:");
    let start = content
        .find(&marker)
        .unwrap_or_else(|| panic!("{name} not found in {CONSTANTS_PATH}"));
    assert!(
        !content[start + marker.len()..].contains(&marker),
        "{name} is declared more than once in {CONSTANTS_PATH}"
    );
    let declaration_start = start + marker.len();
    let declaration_end = content[declaration_start..]
        .find("pub const ")
        .map(|offset| declaration_start + offset)
        .unwrap_or(content.len());
    let declaration = &content[declaration_start..declaration_end];
    // The initializer follows the first `=` after the declaration's type. rustfmt may wrap it
    // onto its own line, so the search for the opening delimiter starts at that `=` (never inside
    // the `[u64; 4]` type) and the whole `= <open>...<close>` span is rewritten in one canonical
    // shape rather than patched in place. Every search is bounded by the next public constant so a
    // malformed declaration cannot consume its neighbor's initializer.
    let assign = declaration
        .find('=')
        .map(|offset| declaration_start + offset)
        .unwrap_or_else(|| panic!("{name} initializer not found in {CONSTANTS_PATH}"));
    let after_assign = &content[assign..declaration_end];
    let open_start = after_assign
        .find(open)
        .map(|offset| assign + offset)
        .unwrap_or_else(|| panic!("{name} initializer not found in {CONSTANTS_PATH}"));
    let body_start = open_start + open.len();
    let body_end = content[body_start..declaration_end]
        .find(close)
        .map(|offset| body_start + offset)
        .unwrap_or_else(|| panic!("{name} terminator not found in {CONSTANTS_PATH}"));
    content.replace_range(assign..body_end + close.len(), &format!("= {open}{body}{close}"));
}

#[cfg(test)]
mod tests {
    use std::string::String;

    use miden_core::{Felt, Word};

    use super::{
        super::expect_panic, CircuitShape, NEXT_VM_REGION_START, PVM_DEEP_QUERIES_PATH,
        PVM_READ_START, accepted_setup_commitment, compile, masm_renderer, render,
        replace_limb_array_const, replace_shape_const,
    };

    #[test]
    fn pvm_read_and_scratch_regions_match_the_rendered_layout() {
        {
            let plan = masm_renderer::prepare_v1(compile(accepted_setup_commitment()).masm);
            let input = &plan.input;
            let layout = &plan.layout;
            let num_airs = input.geometry.main.len() as u32;
            let row_felts = (input.geometry.preprocessed.iter().sum::<usize>()
                + input.geometry.main.iter().sum::<usize>()
                + input.geometry.aux_coordinates.iter().sum::<usize>()
                + input.geometry.quotient_coordinates) as u32;
            let stream = PVM_READ_START + 2 * input.read_layout.total_slots as u32;
            let gamma = stream + input.circuit.stream_felts;
            let row = gamma + 8;
            let setup = row + row_felts;
            let scatter = setup + 4;
            let positions = scatter + 96;
            let ids = positions + num_airs.next_multiple_of(4);

            assert_eq!(layout.public_inputs_ptr, PVM_READ_START);
            assert_eq!(layout.ace_circuit_stream_ptr, stream);
            assert_eq!(layout.bus_gamma_ptr, gamma);
            assert_eq!(layout.c_total_ptr, gamma + 4);
            assert_eq!(layout.current_trace_row_ptr, row);
            assert_eq!(layout.query_row_felts, row_felts);
            assert_eq!(layout.preprocessed_com_ptr, setup);
            assert_eq!(layout.ood_scatter_table_ptr, scatter);
            assert_eq!(layout.proof_order_positions_ptr, positions);
            assert_eq!(layout.proof_order_ids_ptr, ids);
            assert_eq!(layout.fold_coefficient_felt_offset, 2 * (10 + 3 * num_airs));
            assert!(row.is_multiple_of(8));
            assert!([scatter, positions, ids].iter().all(|ptr| ptr.is_multiple_of(4)));
            assert!(ids + num_airs <= NEXT_VM_REGION_START);
        }
    }

    #[test]
    fn renderer_rejects_geometry_that_disagrees_with_compiled_counts() {
        let mut compiled = compile(accepted_setup_commitment());
        compiled.masm.geometry.main[0] += 8;
        expect_panic(|| render(&compiled));
    }

    #[test]
    fn renderer_rejects_missing_read_slot_extent() {
        let mut compiled = compile(accepted_setup_commitment());
        compiled.masm.read_layout.total_slots = compiled.masm.read_layout.alpha;
        expect_panic(|| render(&compiled));
    }

    #[test]
    fn generated_rust_constants_are_rewritten_in_place() {
        let mut source = String::from(
            "/// doc\npub const PVM_ACE_CIRCUIT_DIGEST: [u64; 4] = [0, 0, 0, 0];\n\npub const \
             PVM_CIRCUIT_SHAPE: (usize, usize, usize) = (0, 0, 0);\n",
        );
        let word = Word::new([1u64, 2, 3, 4].map(Felt::new_unchecked));
        replace_limb_array_const(&mut source, "PVM_ACE_CIRCUIT_DIGEST", &word);
        replace_shape_const(
            &mut source,
            CircuitShape {
                num_inputs: 5,
                num_eval_gates: 6,
                stream_len: 8,
            },
        );
        assert_eq!(
            source,
            "/// doc\npub const PVM_ACE_CIRCUIT_DIGEST: [u64; 4] = [\n    1,\n    2,\n    3,\n    \
             4,\n];\n\npub const PVM_CIRCUIT_SHAPE: (usize, usize, usize) = (5, 6, 8);\n"
        );
    }

    /// rustfmt wraps a long limb array onto the line after the `=`; the initializer must still be
    /// found (not the `[` of the `[u64; 4]` type) and rewritten in the canonical shape.
    #[test]
    fn generated_rust_constants_are_rewritten_when_rustfmt_wraps_the_initializer() {
        let mut source = String::from(
            "pub const PVM_RELATION_DIGEST: [u64; 4] =\n    [1, 2, 3, 4];\n\npub const \
             PVM_ACE_CIRCUIT_DIGEST: [u64; 4] = [\n    0,\n    0,\n    0,\n    0,\n];\n",
        );
        let word = Word::new([5u64, 6, 7, 8].map(Felt::new_unchecked));
        replace_limb_array_const(&mut source, "PVM_RELATION_DIGEST", &word);
        assert_eq!(
            source,
            "pub const PVM_RELATION_DIGEST: [u64; 4] = [\n    5,\n    6,\n    7,\n    8,\n];\n\n\
             pub const PVM_ACE_CIRCUIT_DIGEST: [u64; 4] = [\n    0,\n    0,\n    0,\n    0,\n];\n"
        );
    }

    #[test]
    fn generated_rust_constant_replacement_fails_closed_when_absent_or_malformed() {
        let word = Word::new([1u64, 2, 3, 4].map(Felt::new_unchecked));
        let following = "pub const OTHER: [u64; 4] = [9, 8, 7, 6];\n";
        for (malformed, expected_error) in [
            (String::new(), "not found"),
            ("pub const PVM_ACE_CIRCUIT_DIGEST: [u64; 4]\n".into(), "initializer not found"),
            (
                "pub const PVM_ACE_CIRCUIT_DIGEST: [u64; 4] = 0;\n".into(),
                "initializer not found",
            ),
            (
                "pub const PVM_ACE_CIRCUIT_DIGEST: [u64; 4] = [0, 0, 0, 0;\n".into(),
                "terminator not found",
            ),
        ] {
            let mut source = malformed;
            source.push_str(following);
            let original = source.clone();

            let error = expect_panic(|| {
                replace_limb_array_const(&mut source, "PVM_ACE_CIRCUIT_DIGEST", &word)
            });

            assert!(error.contains(expected_error), "unexpected error: {error}");
            assert_eq!(source, original);
            assert!(source.ends_with(following));
        }
    }

    #[test]
    fn pvm_deep_query_rendering_is_deterministic() {
        let compiled = compile(accepted_setup_commitment());
        let first = render(&compiled);
        let second = render(&compiled);
        assert_eq!(
            first
                .files
                .iter()
                .find(|file| file.relative_path == PVM_DEEP_QUERIES_PATH)
                .unwrap()
                .body,
            second
                .files
                .iter()
                .find(|file| file.relative_path == PVM_DEEP_QUERIES_PATH)
                .unwrap()
                .body
        );
    }

    #[test]
    fn pvm_deep_query_block_counts_and_frames_follow_source_widths() {
        let compiled = compile(accepted_setup_commitment());
        let artifact = render(&compiled);
        let deep_queries_masm = &artifact
            .files
            .iter()
            .find(|file| file.relative_path == PVM_DEEP_QUERIES_PATH)
            .unwrap()
            .body;
        let geometry = &compiled.masm.geometry;
        let widths = [
            geometry.preprocessed.iter().sum::<usize>(),
            geometry.main.iter().sum(),
            geometry.aux_coordinates.iter().sum(),
            geometry.quotient_coordinates,
        ];
        for ((prefix, width), expected_cv) in ["PREPROCESSED", "MAIN", "AUX", "QUOTIENT"]
            .into_iter()
            .zip(widths)
            .zip(compiled.masm.query_leaf_initial_cvs)
        {
            assert!(
                deep_queries_masm
                    .contains(&format!("const {prefix}_ROW_DOUBLE_WORDS = {}", width / 8))
            );
            let expected_cv = format!(
                "[{}, {}, {}, {}]",
                expected_cv[0], expected_cv[1], expected_cv[2], expected_cv[3]
            );
            assert!(
                deep_queries_masm.contains(&format!("const {prefix}_LMCS_INIT_CV = {expected_cv}"))
            );
        }
    }

    #[test]
    fn pvm_row_geometry_and_scatter_match_canonical_numeric_pins() {
        let input = compile(accepted_setup_commitment()).masm;
        let g = &input.geometry;
        assert_eq!(g.preprocessed, [0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(g.main, [96, 112, 64, 8, 40, 48, 32, 24, 24, 40, 56, 40]);
        assert_eq!(g.aux_coordinates, [40, 40, 24, 8, 24, 56, 8, 8, 24, 24, 32, 24]);
        assert_eq!(g.quotient_coordinates, 8);
        let scatter = miden_ace::OodScatterPlan::new(
            &g.preprocessed,
            &g.main,
            &g.aux_coordinates,
            g.quotient_coordinates,
        );
        assert_eq!(scatter.row_felts(), 1_824);
        assert_eq!(scatter.row_felts() / 8, 228);
        assert_eq!(
            scatter.row_felts() / 2,
            input.counts.preprocessed_width
                + input.counts.width
                + 2 * input.counts.aux_width
                + 2 * input.counts.num_quotient_chunks
        );
        assert_eq!(scatter.segment_count(), 26);
        assert_eq!(scatter.dispatched_slots(), 24);
        assert_eq!((scatter.proof_order_pairs(), scatter.pipe_digests()), (4..52, 52..88));
    }
}
