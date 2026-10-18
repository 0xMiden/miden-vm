//! Host-only, pure MASM rendering from explicit source-derived inputs.
//!
//! Authored templates contain the algorithms' assembly presentation. Rust
//! derives and validates addresses, schedules, groups, and template contexts.
//! Invalid authored inputs panic; external artifact decoding and delivery remain fallible.

mod artifact;
mod deep;
mod input;
mod layout;
mod ood;
mod proof_order;
mod pvm_glue;
mod runtime;
pub mod shared;
mod templates;
pub use runtime::{PARAMETERS_FELTS, PARAMETERS_PTR};
#[cfg(test)]
mod tests;

use std::{string::String, vec::Vec};

pub use artifact::{ArtifactOwnership, RenderedArtifact};
pub use input::*;
use miden_ace::OodScatterPlan;
pub use proof_order::{LayoutAccessor, PointerRef, ProofOrderConfig};

use self::{
    layout::LayoutPlan,
    ood::{MemoryRegion, OodPlan},
    proof_order::ProofOrderPlan,
};

/// Only `prepare_v1` constructs a complete, validated template context.
#[derive(Clone, Debug)]
pub struct V1RenderPlan {
    pub(crate) input: V1RenderInput,
    pub(crate) relation_name: String,
    pub(crate) num_airs: usize,
    pub(crate) stream_blocks: u32,
    pub(crate) layout: LayoutPlan,
    pub(crate) deep: deep::DeepPlan,
    pub(crate) ood: OodPlan,
    pub(crate) pvm_glue: Option<pvm_glue::PvmGluePlan>,
    pub(crate) fold_positions: Vec<usize>,
    pub(crate) runtime: runtime::RuntimePlan,
}

pub fn prepare_v1(input: V1RenderInput) -> V1RenderPlan {
    let num_airs = input.geometry.main.len();
    let (relation_name, expected_airs) = match &input.relation {
        RelationInput::Vm(_) => ("vm".into(), 4),
        RelationInput::Pvm { glue, .. } => {
            let variant = glue.variant;
            let count = crate::precompile::MultiAir::with_variant(variant);
            use miden_stark::air::MultiAir as _;
            let namespace = if variant == miden_core::deferred::PvmAirVariant::ALL {
                "pvm".into()
            } else {
                std::format!("pvm::v{}", variant.as_u8())
            };
            (namespace, count.airs().len())
        },
    };
    assert!(num_airs == expected_airs, "v1 relation: canonical relation AIR count differs");
    assert!(
        !input.regeneration_command.contains(['\n', '\r']),
        "header: regeneration command must occupy one line"
    );
    let encoded_reads = usize::try_from(input.circuit.encoded_read_count)
        .unwrap_or_else(|_| panic!("circuit metadata: READ count exceeds usize"));
    let eval_gates = usize::try_from(input.circuit.eval_gate_count)
        .unwrap_or_else(|_| panic!("circuit metadata: EVAL count exceeds usize"));
    let stream_felts = usize::try_from(input.circuit.stream_felts)
        .unwrap_or_else(|_| panic!("circuit metadata: stream length exceeds usize"));
    miden_ace::EncodedCircuit::validate_shape(encoded_reads, eval_gates, stream_felts)
        .expect("compiler circuit metadata must satisfy encoded shape");
    let constant_slots = stream_felts
        .checked_sub(eval_gates)
        .map(|felts| felts / 2)
        .expect("circuit metadata: stream is shorter than EVAL gates");
    assert!(
        input.read_layout.total_slots.checked_add(constant_slots) == Some(encoded_reads),
        "circuit metadata: encoded READs must match external layout slots plus constants"
    );
    assert!(
        input.shared_abi.heights_capacity >= num_airs as u32
            && input.shared_abi.heights_ptr.is_multiple_of(4)
            && input.shared_abi.composition_coefficients_ptr.is_multiple_of(4),
        "shared ABI: height capacity or word alignment is invalid"
    );
    let scatter = OodScatterPlan::new(
        &input.geometry.preprocessed,
        &input.geometry.main,
        &input.geometry.aux_coordinates,
        input.geometry.quotient_coordinates,
    );
    let layout = LayoutPlan::new(&input, &scatter);
    let pvm_glue = match &input.relation {
        RelationInput::Pvm { glue, .. } => Some(pvm_glue::PvmGluePlan::new(&input, glue)),
        RelationInput::Vm(_) => None,
    };
    let deep = deep::DeepPlan::new(&input);
    let runtime = runtime::RuntimePlan::new(&input, &layout, &deep, pvm_glue.as_ref());
    let proof_order = ProofOrderPlan::new(&ProofOrderConfig {
        num_airs,
        heights: PointerRef::SharedHeights { address: input.shared_abi.heights_ptr },
        positions: PointerRef::Layout {
            accessor: LayoutAccessor::ProofOrderPositions,
            address: layout.proof_order_positions_ptr,
        },
        ids: PointerRef::Layout {
            accessor: LayoutAccessor::ProofOrderIds,
            address: layout.proof_order_ids_ptr,
        },
        word_load_heights: input.relation.is_vm(),
        word_store_ids: true,
        procedure_name: "stage_proof_order_maps".into(),
        public: true,
    });
    let ood = OodPlan::new(
        &scatter,
        layout.table_region(),
        MemoryRegion {
            base: layout.proof_order_positions_ptr,
            len_felts: num_airs as u32,
        },
        MemoryRegion {
            base: layout.proof_order_ids_ptr,
            len_felts: num_airs as u32,
        },
        proof_order,
    );
    let stream_blocks = input.circuit.stream_felts / 8;
    V1RenderPlan {
        input,
        relation_name,
        num_airs,
        stream_blocks,
        layout,
        deep,
        ood,
        pvm_glue,
        runtime,
        fold_positions: (0..num_airs).rev().collect(),
    }
}

/// Preserve supplied candidate values. Delivery acceptance and all I/O belong
/// to the host adapter, independently of this pure rendering operation.
pub fn render(input: &V1RenderInput) -> Vec<RenderedArtifact> {
    render_v1(&prepare_v1(input.clone()))
}

pub fn render_v1(plan: &V1RenderPlan) -> Vec<RenderedArtifact> {
    templates::render(plan)
}

pub fn render_proof_order(config: &ProofOrderConfig) -> String {
    templates::render_proof_order(&ProofOrderPlan::new(config))
}
