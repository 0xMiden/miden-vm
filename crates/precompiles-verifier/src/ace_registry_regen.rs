//! Regeneration tool for the PVM ACE registry and generated MASM artifacts.
//!
//! `--check` hashes every ordering through the packed encode-only path and pins the resulting
//! registry row, root, and generated artifacts against the checked-in files. `--write` additionally
//! compares every packed leaf with the scalar encode-only path before minting those artifacts. A
//! structured order sample cross-checks both encode-only paths against fully assembled streams and
//! from-scratch `hash_elements` commitments.
//!
//! Full circuit assembly is deliberately sampled: its order-invariant common section would
//! otherwise be cloned and encoded 10! times even though assembly and encode-only generation share
//! their shuffle emitter and operation encoder. Packed-versus-scalar hash validation remains
//! exhaustive when minting; leaf generation, tag inversion, and root construction are exhaustive
//! in both modes.

use std::{
    fmt::Write as _,
    format, io, println,
    string::{String, ToString},
    vec::Vec,
};

use miden_ace_codegen::{
    EXT_DEGREE, FactoredCircuitFactory, InputKey, InputLayout, MasmConstraintsEvalConfig,
    PackedLeafScratch, ShuffleEncodeBuffer, fold_row_to_root, order_from_tag, order_tag,
    render_masm_constraints_eval, subtree_leaves,
};
use miden_core::{Felt, Word, crypto::hash::Eidos};
use miden_crypto::{hash::eidos::BLOCK_LEN as EIDOS_BLOCK_WIDTH, merkle::MerkleTree};
use miden_lifted_air::BaseAir;
use miden_lifted_stark::{QuotientRecompositionInputs, quotient_recomposition_inputs};
use miden_precompiles_air::{
    ChipletAir, NUM_CHIPLETS, preprocessed,
    stark_config::{eidos_config, precompile_pcs_params},
};
use rayon::prelude::*;

use crate::{
    ace::{
        PVM_ACE_REGISTRY_DEPTH, PVM_ORDER_COUNT, PVM_REGISTRY_LAYOUT,
        build_precompile_factored_ace_circuit, structured_orders,
    },
    ace_registry::{
        PVM_ACE_REGISTRY_LEVEL12_ROW, PVM_ACE_REGISTRY_ROOT, PVM_RELATION_DIGEST,
        relation_digest_for_root,
    },
};

const DATA_PATH: &str = "src/ace_registry/data.rs";
const PROTOCOL_PATH: &str = "../precompiles-air/src/protocol.rs";
const PVM_CONSTRAINTS_EVAL_PATH: &str = "../lib/core/asm/sys/pvm/constraints_eval.masm";
const PVM_DEEP_QUERIES_PATH: &str = "../lib/core/asm/sys/pvm/deep_queries.masm";
const PVM_LAYOUT_PATH: &str = "../lib/core/asm/sys/pvm/layout.masm";
const PVM_OOD_FRAMES_PATH: &str = "../lib/core/asm/sys/pvm/ood_frames.masm";
const PVM_RELATION_MOD_PATH: &str = "../lib/core/asm/sys/pvm/mod.masm";

/// First felt after the VM relation's fixed ACE stream reservation. The PVM's complete READ
/// section starts here; its aux-randomness anchor is later because four public EF inputs precede
/// it.
// Place the PVM frame at the fixed 4-Ki-felt boundary after the VM relation's reserved READ
// section so the two relation-owned allocations cannot overlap.
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
    if cfg!(debug_assertions) {
        println!(
            "warning: debug builds are much slower; use `make check-pvm-registry` or \
             `make regenerate-pvm-registry` for the release-mode registry tools"
        );
    }
    let artifacts = compute(mode)?;
    match mode {
        Mode::Check => check(&artifacts),
        Mode::Write => write(&artifacts).map_err(|e| format!("{e}")),
    }
}

struct GeneratedArtifacts {
    row: Vec<Word>,
    root: Word,
    digest: [Felt; 4],
    /// Commitment to the preprocessed (setup) LDE tree under the Eidos config —
    /// the configuration an in-VM verifier targets.
    ///
    /// This is a trusted verifier input rather than proof data: the Rust verifier
    /// rebuilds the bundle locally, but a MASM verifier has no way to, so it must be
    /// pinned as a protocol constant and observed into the transcript.
    preprocessed_commitment: Word,
    /// Shape of the encoded circuit stream, identical for every proof order.
    shape: CircuitShape,
    /// Generated PVM relation layout, derived from the ACE `InputLayout`.
    layout_masm: String,
    /// Generated PVM constraint evaluator, rendered from the same circuit metadata as the
    /// registry constants.
    constraints_eval_masm: String,
    /// Hand-written DEEP-query implementation with its row-block constants updated.
    deep_queries_masm: String,
    /// Hand-written OOD-frame implementation with its row-block constant and geometry prose
    /// updated.
    ood_frames_masm: String,
    /// Hand-written relation wrapper with its generated registry root and relation digest updated.
    relation_mod_masm: String,
}

/// Committed base-coordinate widths for one PVM trace row.
///
/// Auxiliary and quotient extension-field values each occupy [`EXT_DEGREE`] committed base
/// coordinates. OOD advice then supplies an extension-field evaluation for every one of these
/// committed coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PvmRowWidths {
    preprocessed: usize,
    main: usize,
    auxiliary: usize,
    quotient: usize,
}

impl PvmRowWidths {
    fn total(self) -> Result<usize, String> {
        [self.preprocessed, self.main, self.auxiliary, self.quotient]
            .into_iter()
            .try_fold(0usize, |total, width| {
                total
                    .checked_add(width)
                    .ok_or_else(|| "PVM trace row width overflows".to_string())
            })
    }

    fn named(self) -> [(&'static str, usize); 4] {
        [
            ("preprocessed", self.preprocessed),
            ("main", self.main),
            ("auxiliary-coordinate", self.auxiliary),
            ("quotient-coordinate", self.quotient),
        ]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PvmTraceGeometry {
    row_widths: PvmRowWidths,
    ood_row_felts: usize,
    ood_row_blocks: usize,
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

impl PvmTraceGeometry {
    fn from_input_layout(layout: &InputLayout) -> Result<Self, String> {
        let expected = PvmRowWidths {
            preprocessed: layout.counts.preprocessed_width,
            main: layout.counts.width,
            auxiliary: layout
                .counts
                .aux_width
                .checked_mul(EXT_DEGREE)
                .ok_or_else(|| "PVM auxiliary-coordinate width overflows".to_string())?,
            quotient: layout
                .counts
                .num_quotient_chunks
                .checked_mul(EXT_DEGREE)
                .ok_or_else(|| "PVM quotient-coordinate width overflows".to_string())?,
        };
        let current = trace_row_widths(layout, 0, InputKey::Preprocessed { offset: 1, index: 0 })?;
        let next = trace_row_widths(layout, 1, InputKey::AuxBusBoundary(0))?;

        if current != next {
            return Err(format!(
                "PVM current/next trace-row widths differ: {current:?} versus {next:?}"
            ));
        }
        if current != expected {
            return Err(format!(
                "PVM trace-row boundaries {current:?} disagree with InputLayout counts {expected:?}"
            ));
        }
        for (name, width) in current.named() {
            if !width.is_multiple_of(EIDOS_BLOCK_WIDTH) {
                return Err(format!(
                    "PVM {name} row width {width} is not {EIDOS_BLOCK_WIDTH}-felt aligned"
                ));
            }
        }

        let row_width = current.total()?;
        let ood_row_felts = row_width
            .checked_mul(EXT_DEGREE)
            .ok_or_else(|| "PVM OOD row felt width overflows".to_string())?;
        if !ood_row_felts.is_multiple_of(EIDOS_BLOCK_WIDTH) {
            return Err(format!(
                "PVM OOD row width {ood_row_felts} is not {EIDOS_BLOCK_WIDTH}-felt aligned"
            ));
        }

        Ok(Self {
            row_widths: current,
            ood_row_felts,
            ood_row_blocks: ood_row_felts / EIDOS_BLOCK_WIDTH,
        })
    }

    fn row_width(self) -> Result<usize, String> {
        self.row_widths.total()
    }

    fn deep_query_blocks(self) -> [(&'static str, usize); 4] {
        [
            (
                "PREPROCESSED_ROW_DOUBLE_WORDS",
                self.row_widths.preprocessed / EIDOS_BLOCK_WIDTH,
            ),
            ("MAIN_ROW_DOUBLE_WORDS", self.row_widths.main / EIDOS_BLOCK_WIDTH),
            ("AUX_ROW_DOUBLE_WORDS", self.row_widths.auxiliary / EIDOS_BLOCK_WIDTH),
            ("QUOTIENT_ROW_DOUBLE_WORDS", self.row_widths.quotient / EIDOS_BLOCK_WIDTH),
        ]
    }
}

fn trace_row_widths(
    layout: &InputLayout,
    offset: usize,
    row_end: InputKey,
) -> Result<PvmRowWidths, String> {
    let [preprocessed, main, auxiliary, quotient, end] = [
        InputKey::Preprocessed { offset, index: 0 },
        InputKey::Main { offset, index: 0 },
        InputKey::AuxCoord { offset, index: 0, coord: 0 },
        InputKey::QuotientChunkCoord { offset, chunk: 0, coord: 0 },
        row_end,
    ]
    .map(|key| {
        layout
            .index(key)
            .ok_or_else(|| format!("PVM ACE layout is missing trace-row boundary {key:?}"))
    });
    let (preprocessed, main, auxiliary, quotient, end) =
        (preprocessed?, main?, auxiliary?, quotient?, end?);
    let extent = |start: usize, end: usize, name: &str| {
        end.checked_sub(start)
            .ok_or_else(|| format!("PVM {name} trace-row boundary is reversed"))
    };

    Ok(PvmRowWidths {
        preprocessed: extent(preprocessed, main, "preprocessed")?,
        main: extent(main, auxiliary, "main")?,
        auxiliary: extent(auxiliary, quotient, "auxiliary")?,
        quotient: extent(quotient, end, "quotient")?,
    })
}

/// The encoded ACE stream's shape, which an in-VM verifier needs as compile-time
/// constants: how much to read, where the order-invariant segment begins, and its digest.
///
/// Uniform across proof orders by construction: only the factored shuffle routing changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CircuitShape {
    num_inputs: usize,
    num_eval_gates: usize,
    stream_len: usize,
    shuffle_prefix_len: usize,
    common_commitment: Word,
}

impl CircuitShape {
    fn of(circuit: &miden_ace_codegen::FactoredEncodedCircuit) -> Result<Self, String> {
        let stream_len = circuit.encoded.size_in_felt();
        if !stream_len.is_multiple_of(EIDOS_BLOCK_WIDTH)
            || !circuit.shuffle_prefix_len.is_multiple_of(EIDOS_BLOCK_WIDTH)
        {
            return Err(format!(
                "ACE stream segments must be adv_pipe-block aligned; got {stream_len} felts \
                 with a {}-felt prefix",
                circuit.shuffle_prefix_len
            ));
        }
        Ok(Self {
            num_inputs: circuit.encoded.num_vars(),
            num_eval_gates: circuit.encoded.num_eval_rows(),
            stream_len,
            shuffle_prefix_len: circuit.shuffle_prefix_len,
            common_commitment: circuit.common_commitment,
        })
    }
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
            let felt_offset = u32::try_from(index.checked_mul(EXT_DEGREE).ok_or_else(|| {
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
                .checked_mul(EXT_DEGREE)
                .ok_or_else(|| "PVM ACE READ extent overflows usize".to_string())?,
        )
        .map_err(|_| "PVM ACE READ extent exceeds u32 memory".to_string())?;
        let stream_ptr = PVM_READ_START
            .checked_add(read_extent)
            .ok_or_else(|| "PVM ACE stream pointer overflows u32".to_string())?;
        boundaries.push(("ACE_CIRCUIT_STREAM_PTR", stream_ptr));

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

/// Enumerate every ordering and compute the registry row, root, and relation digest.
fn compute(mode: Mode) -> Result<GeneratedArtifacts, String> {
    let factored = build_precompile_factored_ace_circuit().map_err(|e| format!("{e}"))?;
    let factory = FactoredCircuitFactory::new(factored).map_err(|e| format!("{e}"))?;
    let input_layout = factory.factored().layout();
    let trace_geometry = PvmTraceGeometry::from_input_layout(input_layout)?;
    let read_layout = PvmReadLayout::from_input_layout(input_layout)?;
    if usize::try_from(read_layout.query_row_felts)
        .map_err(|_| "PVM query-row scratch width does not fit the host usize".to_string())?
        != trace_geometry.row_width()?
    {
        return Err(format!(
            "PVM query-row scratch width {} disagrees with trace-row width {}",
            read_layout.query_row_felts,
            trace_geometry.row_width()?,
        ));
    }
    let num_quotient_chunks = input_layout.counts.num_quotient_chunks;
    if !num_quotient_chunks.is_power_of_two() {
        return Err(format!(
            "PVM quotient chunk count {num_quotient_chunks} is not a power of two"
        ));
    }
    let quotient_inputs = quotient_recomposition_inputs::<Felt>(
        num_quotient_chunks.ilog2() as u8,
        precompile_pcs_params().log_blowup(),
    )
    .map_err(|err| err.to_string())?;
    let canonical_order: Vec<usize> = (0..NUM_CHIPLETS).collect();
    let canonical = factory.circuit_for_order(&canonical_order).map_err(|err| err.to_string())?;
    let shape = CircuitShape::of(&canonical)?;

    // From-scratch hash cross-check on the structured sample: the resumed compression chain must
    // reproduce full-stream `hash_elements` digests. Full assembly shares the shuffle emitter and
    // operation encoder with the encode-only path, so sampling it retains the useful structural
    // cross-check without cloning the invariant common section for every order. The mint path below
    // separately compares packed and scalar hashes for every realizable order.
    let mut sample_orders = structured_orders();
    sample_orders.sort_unstable();
    sample_orders.dedup();
    let sample_order_slices: Vec<&[usize]> =
        sample_orders.iter().map(<[usize; NUM_CHIPLETS]>::as_slice).collect();
    let mut packed_scratch = PackedLeafScratch::new();
    let mut packed_leaves = Vec::with_capacity(sample_orders.len());
    factory
        .leaves_for_orders(&sample_order_slices, &mut packed_scratch, &mut packed_leaves)
        .map_err(|e| format!("{e}"))?;
    if packed_leaves.len() != sample_orders.len() {
        return Err("packed registry leaf sample has the wrong length".into());
    }

    let mut scalar_buffer = ShuffleEncodeBuffer::new();
    for (order, packed_leaf) in sample_orders.iter().zip(&packed_leaves) {
        let circuit = factory.circuit_for_order(order.as_slice()).map_err(|e| format!("{e}"))?;
        let instructions = circuit.encoded.instructions();
        let scalar_leaf = factory
            .leaf_for_order(order.as_slice(), &mut scalar_buffer)
            .map_err(|e| format!("{e}"))?;
        if Eidos::hash_elements(&instructions[..circuit.shuffle_prefix_len])
            != circuit.shuffle_commitment
            || Eidos::hash_elements(&instructions[circuit.shuffle_prefix_len..])
                != circuit.common_commitment
            || scalar_leaf != circuit.commitment
            || packed_leaf != &scalar_leaf
        {
            return Err(format!(
                "packed or resumed-chain commitments diverge from the assembled circuit for \
                 {order:?}"
            ));
        }
    }

    // One subtree per checked-in row node. Never materialises the full tree; the fan-out
    // is here because the generic subtree unit is deliberately serial.
    let completed = std::sync::atomic::AtomicUsize::new(0);
    let total = PVM_REGISTRY_LAYOUT.row_len();
    match mode {
        Mode::Check => println!(
            "computing {} packed leaves over {total} subtrees",
            PVM_REGISTRY_LAYOUT.order_count(),
        ),
        Mode::Write => println!(
            "computing {} packed leaves over {total} subtrees with exhaustive scalar validation",
            PVM_REGISTRY_LAYOUT.order_count(),
        ),
    }
    let row: Vec<Word> = (0..PVM_REGISTRY_LAYOUT.row_len())
        .into_par_iter()
        .map_init(
            || (PackedLeafScratch::new(), ShuffleEncodeBuffer::new()),
            |(packed_scratch, scalar_buffer), subtree_index| -> Result<Word, String> {
                let leaves =
                    subtree_leaves(&factory, &PVM_REGISTRY_LAYOUT, subtree_index, packed_scratch)
                        .map_err(|e| format!("{e}"))?;

                let start = subtree_index * PVM_REGISTRY_LAYOUT.leaves_per_subtree();
                let realizable = PVM_REGISTRY_LAYOUT
                    .order_count()
                    .saturating_sub(start)
                    .min(PVM_REGISTRY_LAYOUT.leaves_per_subtree());
                for (offset, packed_leaf) in leaves.iter().take(realizable).enumerate() {
                    let tag = (start + offset) as u32;
                    let order =
                        order_from_tag(tag, PVM_REGISTRY_LAYOUT.num_airs()).ok_or_else(|| {
                            format!("proof-order decoder rejected realizable tag {tag}")
                        })?;
                    if order_tag(&order) != tag {
                        return Err(format!(
                            "proof-order encoder does not invert the decoder at tag {tag}; \
                             refusing to mint"
                        ));
                    }
                    if mode == Mode::Write {
                        let scalar_leaf = factory
                            .leaf_for_order(&order, scalar_buffer)
                            .map_err(|e| format!("{e}"))?;
                        if *packed_leaf != scalar_leaf {
                            return Err(format!(
                                "packed registry leaf diverges from the scalar encode-only leaf at \
                                 tag {tag}; refusing to mint"
                            ));
                        }
                    }
                }
                let finished = completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                if finished.is_multiple_of(512) || finished == total {
                    println!("  {finished}/{total} subtrees");
                }

                MerkleTree::new(&leaves)
                    .map(|subtree| subtree.root())
                    .map_err(|e| format!("subtree {subtree_index}: {e}"))
            },
        )
        .collect::<Result<Vec<_>, _>>()?;

    let root = fold_row_to_root(&row);
    let digest = relation_digest_for_root(&root);
    let preprocessed_commitment = preprocessed_commitment(digest);
    let layout_masm = render_pvm_layout(&read_layout, shape.stream_len)?;
    let constraints_eval_masm = render_pvm_constraints_eval(shape, quotient_inputs)?;
    let deep_queries_masm = render_pvm_deep_queries(trace_geometry)?;
    let ood_frames_masm = render_pvm_ood_frames(trace_geometry)?;
    let mut relation_mod_masm = read_generated_file(PVM_RELATION_MOD_PATH)?;
    for (index, felt) in digest.iter().enumerate() {
        replace_masm_const(
            &mut relation_mod_masm,
            &format!("RELATION_DIGEST_{index}"),
            felt.as_canonical_u64(),
            PVM_RELATION_MOD_PATH,
        )?;
    }
    for (index, felt) in root.iter().enumerate() {
        replace_masm_const(
            &mut relation_mod_masm,
            &format!("ACE_REGISTRY_ROOT_{index}"),
            felt.as_canonical_u64(),
            PVM_RELATION_MOD_PATH,
        )?;
    }
    for (index, felt) in preprocessed_commitment.iter().enumerate() {
        replace_masm_const(
            &mut relation_mod_masm,
            &format!("PREPROCESSED_COMMITMENT_{index}"),
            felt.as_canonical_u64(),
            PVM_RELATION_MOD_PATH,
        )?;
    }

    Ok(GeneratedArtifacts {
        row,
        root,
        digest,
        preprocessed_commitment,
        shape,
        layout_masm,
        constraints_eval_masm,
        deep_queries_masm,
        ood_frames_masm,
        relation_mod_masm,
    })
}

/// Commitment to the setup (preprocessed) trace tree under the Eidos config.
///
/// Built through the same preprocessing code as the prover and Rust verifier, seeded with the
/// freshly minted relation digest, so the config matches production exactly and the minted
/// constant is by construction the value they observe into the transcript. (The commitment
/// itself is digest-independent; threading the digest avoids relying on that property here.)
fn preprocessed_commitment(digest: [Felt; 4]) -> Word {
    let params = precompile_pcs_params();
    let config = eidos_config(params, digest);
    // The LMCS commitment is a 4-felt hash; Word is the MASM-facing representation.
    let commitment: [u64; 4] = preprocessed::build_uncached(&config).commitment().into();
    Word::new(commitment.map(Felt::new_unchecked))
}

fn render_pvm_layout(layout: &PvmReadLayout, stream_len: usize) -> Result<String, String> {
    let stream_len = u32::try_from(stream_len)
        .map_err(|_| "PVM ACE stream length exceeds u32 memory".to_string())?;
    let num_chiplets =
        u32::try_from(NUM_CHIPLETS).map_err(|_| "PVM AIR count exceeds u32 memory".to_string())?;
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
    let preprocessed_com_ptr = current_trace_row_ptr
        .checked_add(layout.query_row_felts)
        .ok_or_else(|| "PVM current-row allocation overflows u32".to_string())?;
    let aux_value_ptrs_ptr = preprocessed_com_ptr
        .checked_add(4)
        .ok_or_else(|| "PVM preprocessed-commitment allocation overflows u32".to_string())?;
    let allocation_end = aux_value_ptrs_ptr
        .checked_add(num_chiplets)
        .ok_or_else(|| "PVM auxiliary-value pointer allocation overflows u32".to_string())?;
    if allocation_end > NEXT_VM_REGION_START {
        return Err(format!(
            "PVM ACE allocation {PVM_READ_START}..{allocation_end} reaches the VM scratch region starting at {NEXT_VM_REGION_START}"
        ));
    }

    let mut out = String::new();
    writeln!(out, "# GENERATED by `make regenerate-pvm-registry` — do not edit by hand.")
        .expect("writing to String cannot fail");
    out.push_str("### PVM relation memory layout.\n");
    out.push_str("###\n");
    out.push_str("### The ACE READ section is one dense vector of quadratic-extension inputs.\n");
    out.push_str("### Every boundary below is derived from the PVM circuit's InputLayout; each\n");
    let extension_degree = small_number_label(EXT_DEGREE);
    writeln!(
        out,
        "### input occupies {extension_degree} base-field felts. The complete allocation, including relation-local\n### scratch after the stream, is the half-open range {PVM_READ_START}..{allocation_end}."
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
        "### 4 felts: {preprocessed_com_ptr}..{aux_value_ptrs_ptr}. Stores the trusted preprocessed-tree commitment for DEEP openings.\nconst PREPROCESSED_COM_PTR = {preprocessed_com_ptr}\n"
    )
    .expect("writing to String cannot fail");
    writeln!(
        out,
        "### {NUM_CHIPLETS} felts: {aux_value_ptrs_ptr}..{allocation_end}. Stores, by stable AIR index, the absolute address of its first auxiliary boundary value in the proof-ordered buffer.\nconst AUX_VALUE_PTRS_PTR = {aux_value_ptrs_ptr}\n"
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
    out.push_str("\npub proc aux_value_ptrs_ptr\n    push.AUX_VALUE_PTRS_PTR\nend\n");

    Ok(out)
}

fn render_pvm_constraints_eval(
    shape: CircuitShape,
    quotient_inputs: QuotientRecompositionInputs<Felt>,
) -> Result<String, String> {
    let max_cycle_len_log = max_periodic_cycle_len_log()?;
    render_masm_constraints_eval(&MasmConstraintsEvalConfig {
        generated_by: "cargo run -p miden-precompiles-verifier --release --features registry-tools \
                       --bin pvm-registry-regen -- --write",
        layout_module: "miden::core::sys::pvm::layout",
        num_inputs: shape.num_inputs,
        num_eval_gates: shape.num_eval_gates,
        stream_len: shape.stream_len,
        shuffle_prefix_len: shape.shuffle_prefix_len,
        max_cycle_len_log,
        registry_depth: PVM_ACE_REGISTRY_DEPTH,
        order_tag_count: PVM_ORDER_COUNT,
        num_airs: NUM_CHIPLETS,
        quotient_inputs,
        common_commitment: shape.common_commitment,
    })
    .map_err(|err| err.to_string())
}

fn render_pvm_deep_queries(geometry: PvmTraceGeometry) -> Result<String, String> {
    let mut deep_queries = read_generated_file(PVM_DEEP_QUERIES_PATH)?;
    for (name, blocks) in geometry.deep_query_blocks() {
        replace_masm_const(&mut deep_queries, name, blocks, PVM_DEEP_QUERIES_PATH)?;
    }
    Ok(deep_queries)
}

fn render_pvm_ood_frames(geometry: PvmTraceGeometry) -> Result<String, String> {
    const GEOMETRY_START: &str = "#! The row is the LMCS-aligned wire sequence used by the lifted PCS, in commitment-group order:";
    const GEOMETRY_END: &str = "pub proc process_row_ood_evaluations";

    let mut ood_frames = read_generated_file(PVM_OOD_FRAMES_PATH)?;
    replace_masm_const(
        &mut ood_frames,
        "OOD_ROW_DOUBLE_WORDS",
        geometry.ood_row_blocks,
        PVM_OOD_FRAMES_PATH,
    )?;

    let quotient_chunks = geometry.row_widths.quotient / EXT_DEGREE;
    let air_count = small_number_label(NUM_CHIPLETS);
    let quotient_chunk_count = small_number_label(quotient_chunks);
    let row_width = geometry.row_width()?;
    let geometry_docs = format!(
        "#! The row is the LMCS-aligned wire sequence used by the lifted PCS, in commitment-group order:\n\
#!\n\
#! - {} preprocessed extension-field slots;\n\
#! - {} main extension-field slots across {air_count} AIRs in proof order;\n\
#! - {} auxiliary-coordinate extension-field slots across {air_count} AIRs in proof order;\n\
#! - {} quotient extension-field slots ({quotient_chunk_count} quadratic-extension chunks).\n\
#!\n\
#! This is {} extension-field values = {} felts = {} `adv_pipe` blocks. Each block is stored,\n\
#! folded into the DEEP fixed term with `horner_eval_ext`, and compressed into the Eidos\n\
#! transcript.\n\
#!\n\
#! Inputs:  [scratch0, scratch1, cv, ptr, alpha_ptr, acc0, acc1]\n\
#! Outputs: [scratch0, scratch1, cv', ptr, alpha_ptr, acc0', acc1']\n",
        geometry.row_widths.preprocessed,
        geometry.row_widths.main,
        geometry.row_widths.auxiliary,
        geometry.row_widths.quotient,
        format_with_commas(row_width),
        format_with_commas(geometry.ood_row_felts),
        format_with_commas(geometry.ood_row_blocks),
    );
    replace_unique_block(
        &mut ood_frames,
        GEOMETRY_START,
        GEOMETRY_END,
        &geometry_docs,
        PVM_OOD_FRAMES_PATH,
    )?;
    Ok(ood_frames)
}

fn small_number_label(value: usize) -> String {
    match value {
        0 => "zero".into(),
        1 => "one".into(),
        2 => "two".into(),
        3 => "three".into(),
        4 => "four".into(),
        5 => "five".into(),
        6 => "six".into(),
        7 => "seven".into(),
        8 => "eight".into(),
        9 => "nine".into(),
        10 => "ten".into(),
        _ => value.to_string(),
    }
}

fn format_with_commas(value: usize) -> String {
    let digits = value.to_string();
    let mut output = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.bytes().enumerate() {
        if index != 0 && (digits.len() - index).is_multiple_of(3) {
            output.push(',');
        }
        output.push(char::from(digit));
    }
    output
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
    if artifacts.root != Word::new(PVM_ACE_REGISTRY_ROOT.map(Felt::new_unchecked)) {
        return Err("PVM_ACE_REGISTRY_ROOT in ace_registry/data.rs is stale (the root binds \
                    every registry leaf; leaves are recomputed and are not checked in)"
            .into());
    }
    if artifacts.digest != PVM_RELATION_DIGEST.map(Felt::new_unchecked) {
        return Err("PVM_RELATION_DIGEST in precompiles-air/src/protocol.rs is stale".into());
    }
    let checked_in = PVM_ACE_REGISTRY_LEVEL12_ROW
        .iter()
        .map(|node| Word::new(node.map(Felt::new_unchecked)));
    if !artifacts.row.iter().copied().eq(checked_in) {
        return Err("PVM_ACE_REGISTRY_LEVEL12_ROW in ace_registry/data.rs is stale".into());
    }
    let path = data_path();
    let checked_in = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read generated registry data at {path}: {e}"))?;
    if checked_in != render_registry_data(artifacts) {
        return Err(format!(
            "{DATA_PATH} was not produced by the current generator; run \
             `make regenerate-pvm-registry`"
        ));
    }
    if read_generated_file(PROTOCOL_PATH)? != render_protocol(artifacts) {
        return Err(format!("{PROTOCOL_PATH} is stale; run `make regenerate-pvm-registry`"));
    }
    if read_generated_file(PVM_LAYOUT_PATH)? != artifacts.layout_masm {
        return Err(format!("{PVM_LAYOUT_PATH} is stale; run `make regenerate-pvm-registry`"));
    }
    if read_generated_file(PVM_CONSTRAINTS_EVAL_PATH)? != artifacts.constraints_eval_masm {
        return Err(format!(
            "{PVM_CONSTRAINTS_EVAL_PATH} is stale; run `make regenerate-pvm-registry`"
        ));
    }
    if read_generated_file(PVM_DEEP_QUERIES_PATH)? != artifacts.deep_queries_masm {
        return Err(format!(
            "{PVM_DEEP_QUERIES_PATH} is stale; run `make regenerate-pvm-registry`"
        ));
    }
    if read_generated_file(PVM_OOD_FRAMES_PATH)? != artifacts.ood_frames_masm {
        return Err(format!("{PVM_OOD_FRAMES_PATH} is stale; run `make regenerate-pvm-registry`"));
    }
    if read_generated_file(PVM_RELATION_MOD_PATH)? != artifacts.relation_mod_masm {
        return Err(format!(
            "{PVM_RELATION_MOD_PATH} has stale registry constants; run \
             `make regenerate-pvm-registry`"
        ));
    }
    println!("PVM registry and MASM artifacts are up to date");
    Ok(())
}

fn format_word(word: &Word) -> String {
    word.iter().fold(String::new(), |mut output, felt| {
        output.push_str(&format!("    {},\n", felt.as_canonical_u64()));
        output
    })
}

fn render_registry_data(artifacts: &GeneratedArtifacts) -> String {
    let mut rows = String::new();
    for node in &artifacts.row {
        let limbs: Vec<String> =
            node.iter().map(|felt| felt.as_canonical_u64().to_string()).collect();
        rows.push_str(&format!("    [{}],\n", limbs.join(", ")));
    }
    let root = format_word(&artifacts.root);
    let preprocessed = format_word(&artifacts.preprocessed_commitment);
    let num_inputs = artifacts.shape.num_inputs;
    let num_eval_gates = artifacts.shape.num_eval_gates;
    let stream_len = artifacts.shape.stream_len;

    format!(
        "//! GENERATED by `make regenerate-pvm-registry` — do not edit by hand.\n//!\n//! \
         Protocol constants of the PVM ACE circuit registry. The row is authenticated\n//! \
         against the root at first use (`verified_pyramid`), so it carries no trust; the\n//! \
         root is protocol-visible.\n\n/// Root of the PVM ACE circuit registry (raw canonical \
         u64 limbs).\npub const PVM_ACE_REGISTRY_ROOT: [u64; 4] = [\n{root}];\n\n/// \
         Commitment to the preprocessed (setup) trace tree under the Eidos config (raw \
         canonical\n/// u64 limbs). A trusted verifier input, not proof data: an in-VM verifier \
         cannot\n/// rebuild the bundle, so it observes this pinned value into the transcript.\n#[cfg(test)]\npub \
         const PVM_PREPROCESSED_COMMITMENT: [u64; 4] = [\n{preprocessed}];\n\n/// Encoded \
         circuit shape, identical for every proof order: (READ variables, evaluation\n/// gates, \
         stream length in felts). An in-VM verifier needs these as compile-time\n/// constants to \
         size its reads and its ACE evaluation.\n#[cfg(test)]\npub const PVM_CIRCUIT_SHAPE: \
         (usize, usize, usize) = ({num_inputs}, {num_eval_gates}, {stream_len});\n\n/// The \
         registry tree's 4096 nodes at depth 12 (raw canonical u64 limbs).\n#[rustfmt::skip]\npub \
         static PVM_ACE_REGISTRY_LEVEL12_ROW: [[u64; 4]; 4096] = [\n{rows}];\n"
    )
}

fn render_protocol(artifacts: &GeneratedArtifacts) -> String {
    let digest = artifacts.digest.iter().fold(String::new(), |mut output, felt| {
        writeln!(output, "    {},", felt.as_canonical_u64())
            .expect("writing to String cannot fail");
        output
    });
    format!(
        "/// Relation digest binding the PVM ACE registry root into the Fiat-Shamir transcript.\n\
         pub const PVM_RELATION_DIGEST: [u64; 4] = [\n{digest}];\n"
    )
}

fn data_path() -> String {
    format!("{}/{}", env!("CARGO_MANIFEST_DIR"), DATA_PATH)
}

fn write(artifacts: &GeneratedArtifacts) -> io::Result<()> {
    let path = data_path();
    std::fs::write(&path, render_registry_data(artifacts))
        .map_err(|e| io::Error::new(e.kind(), format!("failed to write {path}: {e}")))?;
    println!("wrote {path}");
    write_generated_file(PROTOCOL_PATH, &render_protocol(artifacts))?;
    write_generated_file(PVM_LAYOUT_PATH, &artifacts.layout_masm)?;
    write_generated_file(PVM_CONSTRAINTS_EVAL_PATH, &artifacts.constraints_eval_masm)?;
    write_generated_file(PVM_DEEP_QUERIES_PATH, &artifacts.deep_queries_masm)?;
    write_generated_file(PVM_OOD_FRAMES_PATH, &artifacts.ood_frames_masm)?;
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

fn replace_masm_const(
    content: &mut String,
    name: &str,
    value: impl core::fmt::Display,
    path: &str,
) -> Result<(), String> {
    let prefix = format!("const {name} = ");
    let mut declarations = content
        .match_indices(&prefix)
        .filter(|(start, _)| *start == 0 || content.as_bytes()[start - 1] == b'\n');
    let line_start = declarations
        .next()
        .map(|(start, _)| start)
        .ok_or_else(|| format!("{name} not found in {path}"))?;
    if declarations.next().is_some() {
        return Err(format!("{name} is declared more than once in {path}"));
    }
    let line_end = content[line_start..]
        .find('\n')
        .map(|offset| line_start + offset)
        .unwrap_or(content.len());
    content.replace_range(line_start..line_end, &format!("{prefix}{value}"));
    Ok(())
}

fn replace_unique_block(
    content: &mut String,
    start_marker: &str,
    end_marker: &str,
    replacement: &str,
    path: &str,
) -> Result<(), String> {
    let find_unique_line = |marker: &str| {
        let mut matches = content.match_indices(marker).filter(|(start, _)| {
            let end = *start + marker.len();
            (*start == 0 || content.as_bytes()[start - 1] == b'\n')
                && (end == content.len() || content.as_bytes()[end] == b'\n')
        });
        let start = matches
            .next()
            .map(|(start, _)| start)
            .ok_or_else(|| format!("marker {marker:?} not found in {path}"))?;
        if matches.next().is_some() {
            return Err(format!("marker {marker:?} occurs more than once in {path}"));
        }
        Ok(start)
    };

    let start = find_unique_line(start_marker)?;
    let end = find_unique_line(end_marker)?;
    if start >= end {
        return Err(format!("marker {end_marker:?} does not follow {start_marker:?} in {path}"));
    }
    if replacement.lines().next() != Some(start_marker) || !replacement.ends_with('\n') {
        return Err(format!(
            "replacement for the block beginning {start_marker:?} in {path} has invalid boundaries"
        ));
    }
    content.replace_range(start..end, replacement);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::string::String;

    use miden_core::{Felt, Word};

    use super::{
        PVM_DEEP_QUERIES_PATH, PVM_OOD_FRAMES_PATH, PvmTraceGeometry, format_word,
        read_generated_file, render_pvm_deep_queries, render_pvm_ood_frames, replace_masm_const,
        replace_unique_block,
    };

    #[test]
    fn generated_words_put_one_limb_on_each_line() {
        let word =
            Word::new([Felt::from(1u32), Felt::from(2u32), Felt::from(3u32), Felt::from(4u32)]);
        assert_eq!(format_word(&word), "    1,\n    2,\n    3,\n    4,\n");
    }

    #[test]
    fn masm_constants_are_replaced_without_touching_surrounding_source() {
        let mut source = String::from(
            "before\nconst RELATION_DIGEST_0 = 1\nconst ACE_REGISTRY_ROOT_3 = 2\nafter\n",
        );
        replace_masm_const(&mut source, "RELATION_DIGEST_0", 42, "test.masm").unwrap();
        replace_masm_const(&mut source, "ACE_REGISTRY_ROOT_3", 99, "test.masm").unwrap();
        assert_eq!(
            source,
            "before\nconst RELATION_DIGEST_0 = 42\nconst ACE_REGISTRY_ROOT_3 = 99\nafter\n"
        );
    }

    #[test]
    fn masm_constant_replacement_fails_closed_when_a_constant_is_missing() {
        let mut source = String::from("const RELATION_DIGEST_0 = 1\n");
        let error =
            replace_masm_const(&mut source, "ACE_REGISTRY_ROOT_0", 42, "test.masm").unwrap_err();
        assert!(error.contains("ACE_REGISTRY_ROOT_0 not found"));
        assert!(error.contains("test.masm"));
    }

    #[test]
    fn masm_constant_replacement_rejects_duplicate_declarations() {
        let mut source = String::from("const RELATION_DIGEST_0 = 1\nconst RELATION_DIGEST_0 = 2\n");
        let error =
            replace_masm_const(&mut source, "RELATION_DIGEST_0", 42, "test.masm").unwrap_err();
        assert!(error.contains("RELATION_DIGEST_0 is declared more than once"));
    }

    #[test]
    fn masm_block_replacement_fails_closed_on_duplicate_body_markers() {
        let mut source = String::from("# start\nold\nproc body\nproc body\n");
        let error = replace_unique_block(
            &mut source,
            "# start",
            "proc body",
            "# start\nnew\n",
            "test.masm",
        )
        .unwrap_err();
        assert!(error.contains("occurs more than once"));
    }

    #[test]
    fn masm_geometry_block_replacement_preserves_procedure_suffix() {
        const START: &str = "#! generated geometry";
        const PROCEDURE: &str = "pub proc process_row_ood_evaluations\n    push.42\nend\n";

        let mut source = String::from(
            "#! module docs\n#! generated geometry\n#! old values\npub proc process_row_ood_evaluations\n    push.42\nend\n",
        );
        replace_unique_block(
            &mut source,
            START,
            "pub proc process_row_ood_evaluations",
            "#! generated geometry\n#! new values\n",
            "test.masm",
        )
        .unwrap();

        assert_eq!(
            source,
            "#! module docs\n#! generated geometry\n#! new values\npub proc process_row_ood_evaluations\n    push.42\nend\n"
        );
        assert!(source.ends_with(PROCEDURE));
    }

    #[test]
    fn masm_block_replacement_rejects_marker_prefixes() {
        let mut source = String::from("# start\nold\nproc body_v2\n");
        let error = replace_unique_block(
            &mut source,
            "# start",
            "proc body",
            "# start\nnew\n",
            "test.masm",
        )
        .unwrap_err();
        assert!(error.contains("not found"));
    }

    #[test]
    fn checked_in_pvm_geometry_masm_is_idempotent_under_rendering() {
        let factored = crate::ace::build_precompile_factored_ace_circuit().unwrap();
        let geometry = PvmTraceGeometry::from_input_layout(factored.layout()).unwrap();

        let checked_in_deep_queries = read_generated_file(PVM_DEEP_QUERIES_PATH).unwrap();
        assert_eq!(
            render_pvm_deep_queries(geometry).unwrap().as_bytes(),
            checked_in_deep_queries.as_bytes(),
        );

        let checked_in_ood_frames = read_generated_file(PVM_OOD_FRAMES_PATH).unwrap();
        assert_eq!(
            render_pvm_ood_frames(geometry).unwrap().as_bytes(),
            checked_in_ood_frames.as_bytes(),
        );
    }
}
