//! Typed inputs supplied by the source host adapter.
//!
//! These values are explicit supplied metadata, including candidate identities.
//! Delivery must match candidates against the existing accepted authorities
//! before writing outputs. Pure rendering preserves supplied values and does
//! not capture AIR, compile ACE, derive cryptographic words, or accept pins.

use std::{string::String, vec::Vec};

pub use miden_ace::InputCounts;

#[derive(Clone, Debug)]
pub enum RelationInput {
    Vm(VmAbiAnchors),
    Pvm { abi: PvmAbiAnchors, glue: PvmGlueInput },
}

impl RelationInput {
    pub fn is_vm(&self) -> bool {
        matches!(self, Self::Vm(_))
    }
}

#[derive(Clone, Debug)]
pub struct CircuitMetadata {
    /// Encoded READ variables, including constant reads; not layout slots.
    pub encoded_read_count: u32,
    pub eval_gate_count: u32,
    pub stream_felts: u32,
    pub max_cycle_log: u8,
    pub digest: [u64; 4],
    /// Existing crypto adapter's fixed-length ACE stream initial word.
    pub stream_initial_cv: [u64; 4],
}

#[derive(Clone, Debug)]
pub struct AirGeometry {
    /// Scalar committed coordinates in canonical AIR identity order.
    pub preprocessed: Vec<usize>,
    pub main: Vec<usize>,
    /// Auxiliary extension columns are already expanded into coordinates.
    pub aux_coordinates: Vec<usize>,
    pub quotient_coordinates: usize,
}

impl AirGeometry {
    pub(crate) fn from_airs<
        A: miden_stark::air::LiftedAir<miden_core::Felt, miden_core::field::QuadFelt>,
    >(
        airs: &[A],
        quotient_chunks: usize,
    ) -> Self {
        let mut geometry = Self {
            preprocessed: Vec::with_capacity(airs.len()),
            main: Vec::with_capacity(airs.len()),
            aux_coordinates: Vec::with_capacity(airs.len()),
            quotient_coordinates: quotient_chunks
                .checked_mul(miden_ace::EXT_DEGREE)
                .expect("quotient coordinate width overflows")
                .next_multiple_of(8),
        };
        for air in airs {
            assert_eq!(
                air.num_aux_values(),
                1,
                "boundary scatter requires one auxiliary value per AIR"
            );
            let widths = crate::metadata::ColumnWidths {
                preprocessed: air.preprocessed_width(),
                main: air.width(),
                aux: air.aux_width(),
            }
            .committed(8);
            geometry.preprocessed.push(widths.preprocessed);
            geometry.main.push(widths.main);
            geometry.aux_coordinates.push(widths.aux);
        }
        geometry
    }
}

/// All indices count quadratic-extension input slots, each occupying two felts.
#[derive(Clone, Debug)]
pub struct ReadLayout {
    pub total_slots: usize,
    pub public_0: usize,
    pub aux_rand_beta: usize,
    pub aux_rand_alpha: usize,
    pub preprocessed_current: usize,
    pub main_current: usize,
    pub aux_current: usize,
    pub quotient_current: usize,
    pub preprocessed_next: usize,
    pub main_next: usize,
    pub aux_next: usize,
    pub quotient_next: usize,
    pub aux_bus_boundary: usize,
    pub alpha: usize,
    pub multi_air_fold_coefficient_0: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct QuotientReconstruction {
    pub shift_ratio: u64,
    pub first_shift: u64,
    pub first_weight: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct SecurityParameters {
    pub lookup_pow_bits: u32,
    pub max_message_width: u32,
    pub num_composed_constraints: u32,
    pub max_constraint_degree: u32,
    pub num_deep_terms: u32,
    pub lookup_fractions_per_row: u32,
    pub boundary_lookup_terms: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct SharedAbi {
    pub heights_ptr: u32,
    pub heights_capacity: u32,
    pub composition_coefficients_ptr: u32,
    pub public_inputs_address_ptr: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct VmAbiAnchors {
    pub num_kernel_procedures_ptr: u32,
    pub control_alignment_padding_ptr: u32,
    pub bus_gamma_ptr: u32,
    pub c_total_ptr: u32,
    pub claim_commitment_ptr: u32,
    pub claim_ptr: u32,
    pub boundary_anchor_padding_ptr: u32,
    pub boundary_inputs_ptr: u32,
    pub kernel_witness_ptr: u32,
    pub scatter_ptr: u32,
    pub scatter_reserve_felts: u32,
    pub read_beta_anchor: u32,
    pub current_trace_row_ptr: u32,
    pub next_region_start: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct PvmAbiAnchors {
    pub read_base: u32,
    pub scatter_reserve_felts: u32,
    pub next_region_start: u32,
}

/// Shape rules in canonical instance order. Fixed heights retain their equality-only check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeightRule {
    Minimum(u32),
    Fixed(u32),
}

#[derive(Clone, Debug)]
pub struct PvmAirInput {
    pub height: HeightRule,
    /// Absolute EF READ slot for this AIR's single normalized boundary value.
    pub boundary_slot: usize,
}

#[derive(Clone, Debug)]
pub struct FixedUintInput {
    pub ptr: u32,
    pub bound_ptr: u32,
    /// Little-endian 32-bit limbs, as in the authored UintVal message.
    pub limbs: [u32; 8],
}

#[derive(Clone, Debug)]
pub struct PvmGlueInput {
    pub variant: miden_core::deferred::PvmAirVariant,
    pub airs: Vec<PvmAirInput>,
    pub num_public_values: usize,
    pub max_aux_inputs: usize,
    pub num_aux_inputs: usize,
    pub uints: Vec<FixedUintInput>,
    /// EcGroup payloads in authored group order.
    pub groups: Vec<[u32; 7]>,
    pub uint_bus_scale: u32,
    pub ec_bus_scale: u32,
    pub max_message_width: usize,
}

#[derive(Clone, Debug)]
pub struct V1RenderInput {
    pub relation: RelationInput,
    pub circuit: CircuitMetadata,
    pub geometry: AirGeometry,
    pub counts: InputCounts,
    pub read_layout: ReadLayout,
    pub quotient: QuotientReconstruction,
    /// Preprocessed, main, auxiliary, quotient LMCS_LEAF initial words.
    pub query_leaf_initial_cvs: [[u64; 4]; 4],
    pub relation_digest: [u64; 4],
    pub preprocessed_commitment: [u64; 4],
    pub security: SecurityParameters,
    pub shared_abi: SharedAbi,
    /// A single-line human-readable regeneration command used only in comments.
    pub regeneration_command: String,
}
