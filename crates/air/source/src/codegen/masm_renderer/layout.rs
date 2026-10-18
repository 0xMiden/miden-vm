//! Source-owned READ-slot to felt-address derivation.

use miden_ace::OodScatterPlan;

use super::{input::*, ood::MemoryRegion};

#[derive(Clone, Debug, Default)]
pub(crate) struct LayoutPlan {
    pub public_inputs_ptr: u32,
    pub aux_rand_elem_ptr: u32,
    pub preprocessed_current_ptr: u32,
    pub main_current_ptr: u32,
    pub aux_current_ptr: u32,
    pub quotient_current_ptr: u32,
    pub preprocessed_next_ptr: u32,
    pub main_next_ptr: u32,
    pub aux_next_ptr: u32,
    pub quotient_next_ptr: u32,
    pub aux_bus_boundary_ptr: u32,
    pub auxiliary_ace_inputs_ptr: u32,
    pub ace_circuit_stream_ptr: u32,
    pub bus_gamma_ptr: u32,
    pub c_total_ptr: u32,
    pub current_trace_row_ptr: u32,
    pub preprocessed_com_ptr: u32,
    pub ood_scatter_table_ptr: u32,
    pub proof_order_positions_ptr: u32,
    pub proof_order_ids_ptr: u32,
    pub num_kernel_procedures_ptr: u32,
    pub control_alignment_padding_ptr: u32,
    pub claim_commitment_ptr: u32,
    pub claim_ptr: u32,
    pub boundary_anchor_padding_ptr: u32,
    pub boundary_inputs_ptr: u32,
    pub kernel_witness_ptr: u32,
    pub ood_evaluations_ptr: u32,
    pub fold_coefficient_felt_offset: u32,
    pub query_row_felts: u32,
    pub scatter_table_felts: u32,
    pub scatter_reserve_felts: u32,
}

impl LayoutPlan {
    pub fn new(input: &V1RenderInput, scatter: &OodScatterPlan) -> Self {
        let n = input.geometry.main.len();
        let r = &input.read_layout;
        let c = &input.counts;
        let widths = [
            sum(&input.geometry.preprocessed),
            sum(&input.geometry.main),
            sum(&input.geometry.aux_coordinates),
            input.geometry.quotient_coordinates,
        ];
        assert!(
            c.preprocessed_width == widths[0]
                && c.width == widths[1]
                && c.aux_width.checked_mul(2) == Some(widths[2])
                && c.num_quotient_chunks.checked_mul(2).map(|width| width.next_multiple_of(8))
                    == Some(widths[3])
                && c.num_aux_boundary == n
                && c.num_randomness == 2,
            "READ layout: input counts contradict canonical AIR geometry"
        );
        assert!(
            r.public_0 == 0
                && r.aux_rand_beta == c.num_public
                && r.aux_rand_beta.checked_add(1) == Some(r.aux_rand_alpha)
                && r.preprocessed_current > r.aux_rand_alpha
                && r.aux_bus_boundary.checked_add(n).map(|end| end.next_multiple_of(2))
                    == Some(r.alpha),
            "READ layout: missing or inconsistent logical key slots"
        );
        // Auxiliary slots relative to Alpha are ten fixed values, followed by
        // three boundary values per AIR, then one fold coefficient per AIR.
        // Alignment tail slots are reserved; they are not additional inputs.
        let fold_start = n
            .checked_mul(3)
            .and_then(|slots| slots.checked_add(10))
            .and_then(|slots| r.alpha.checked_add(slots))
            .expect("READ layout: auxiliary slot interval overflow");
        let fold_end = fold_start.checked_add(n).expect("READ layout: fold slot interval overflow");
        let aligned_end = fold_end
            .checked_add(3)
            .map(|end| end / 4 * 4)
            .expect("READ layout: READ alignment tail overflow");
        assert!(
            r.multi_air_fold_coefficient_0 == fold_start && r.total_slots == aligned_end,
            "READ layout: fold slots must follow all auxiliary inputs and end within the exact aligned layout"
        );
        let current = [
            r.preprocessed_current,
            r.main_current,
            r.aux_current,
            r.quotient_current,
            r.preprocessed_next,
        ];
        let next = [
            r.preprocessed_next,
            r.main_next,
            r.aux_next,
            r.quotient_next,
            r.aux_bus_boundary,
        ];
        for (boundaries, frame) in [(&current, "current"), (&next, "next")] {
            for i in 0..4 {
                assert!(
                    boundaries[i + 1].checked_sub(boundaries[i]) == Some(widths[i]),
                    "READ layout: {frame} frame contradicts coordinate widths"
                );
            }
        }
        let query_row = r
            .preprocessed_next
            .checked_sub(r.preprocessed_current)
            .expect("READ layout: row boundary underflow");
        assert!(
            query_row.checked_mul(2) == Some(scatter.row_felts()),
            "READ layout: query and OOD row lengths differ"
        );
        let mut p = Self {
            fold_coefficient_felt_offset: u32_count(r.multi_air_fold_coefficient_0 - r.alpha, 2),
            query_row_felts: u32_count(query_row, 1),
            scatter_table_felts: u32_count(scatter.table_felts(), 1),
            ..Self::default()
        };
        match &input.relation {
            RelationInput::Vm(a) => {
                let pointer = |key: usize| {
                    let offset = key
                        .checked_sub(r.aux_rand_beta)
                        .expect("VM layout: key precedes randomness anchor");
                    add(a.read_beta_anchor, u32_count(offset, 2))
                };
                p.aux_rand_elem_ptr = a.read_beta_anchor;
                p.ood_evaluations_ptr = pointer(r.preprocessed_current);
                p.aux_bus_boundary_ptr = pointer(r.aux_bus_boundary);
                p.auxiliary_ace_inputs_ptr = pointer(r.alpha);
                p.ace_circuit_stream_ptr = pointer(r.total_slots);
                p.current_trace_row_ptr = a.current_trace_row_ptr;
                p.ood_scatter_table_ptr = a.scatter_ptr;
                p.scatter_reserve_felts = a.scatter_reserve_felts;
                p.proof_order_positions_ptr =
                    add(a.scatter_ptr, u32_count(scatter.pipe_digests().end, 1));
                p.proof_order_ids_ptr = add(p.proof_order_positions_ptr, u32_count(n, 1));
                let reserve_end = add(a.scatter_ptr, a.scatter_reserve_felts);
                let map_end = add(p.proof_order_ids_ptr, u32_count(n, 1));
                assert!(
                    map_end <= reserve_end
                        && reserve_end <= a.read_beta_anchor
                        && a.scatter_ptr >= add(a.kernel_witness_ptr, 4 * 255)
                        && add(p.ace_circuit_stream_ptr, input.circuit.stream_felts)
                            <= a.next_region_start,
                    "VM layout: fixed ABI reservation is exceeded"
                );
                p.num_kernel_procedures_ptr = a.num_kernel_procedures_ptr;
                p.control_alignment_padding_ptr = a.control_alignment_padding_ptr;
                p.bus_gamma_ptr = a.bus_gamma_ptr;
                p.c_total_ptr = a.c_total_ptr;
                p.claim_commitment_ptr = a.claim_commitment_ptr;
                p.claim_ptr = a.claim_ptr;
                p.boundary_anchor_padding_ptr = a.boundary_anchor_padding_ptr;
                p.boundary_inputs_ptr = a.boundary_inputs_ptr;
                p.kernel_witness_ptr = a.kernel_witness_ptr;
                let control = [
                    a.num_kernel_procedures_ptr,
                    a.control_alignment_padding_ptr,
                    a.bus_gamma_ptr,
                    a.c_total_ptr,
                    a.claim_commitment_ptr,
                    a.claim_ptr,
                    a.boundary_anchor_padding_ptr,
                    a.boundary_inputs_ptr,
                    a.kernel_witness_ptr,
                    a.scatter_ptr,
                ];
                assert!(
                    control.windows(2).all(|w| w[0] < w[1]),
                    "VM layout: control pointers must increase strictly"
                );
            },
            RelationInput::Pvm { abi: a, .. } => {
                let pointer = |key: usize| add(a.read_base, u32_count(key, 2));
                p.public_inputs_ptr = pointer(r.public_0);
                p.aux_rand_elem_ptr = pointer(r.aux_rand_beta);
                p.preprocessed_current_ptr = pointer(r.preprocessed_current);
                p.main_current_ptr = pointer(r.main_current);
                p.aux_current_ptr = pointer(r.aux_current);
                p.quotient_current_ptr = pointer(r.quotient_current);
                p.preprocessed_next_ptr = pointer(r.preprocessed_next);
                p.main_next_ptr = pointer(r.main_next);
                p.aux_next_ptr = pointer(r.aux_next);
                p.quotient_next_ptr = pointer(r.quotient_next);
                p.aux_bus_boundary_ptr = pointer(r.aux_bus_boundary);
                p.auxiliary_ace_inputs_ptr = pointer(r.alpha);
                p.ace_circuit_stream_ptr = pointer(r.total_slots);
                let boundaries = [
                    p.public_inputs_ptr,
                    p.aux_rand_elem_ptr,
                    p.preprocessed_current_ptr,
                    p.main_current_ptr,
                    p.aux_current_ptr,
                    p.quotient_current_ptr,
                    p.preprocessed_next_ptr,
                    p.main_next_ptr,
                    p.aux_next_ptr,
                    p.quotient_next_ptr,
                    p.aux_bus_boundary_ptr,
                    p.auxiliary_ace_inputs_ptr,
                    p.ace_circuit_stream_ptr,
                ];
                assert!(
                    boundaries.windows(2).all(|w| w[0] < w[1]),
                    "PVM layout: READ boundaries must increase strictly"
                );
                p.bus_gamma_ptr = add(p.ace_circuit_stream_ptr, input.circuit.stream_felts);
                p.c_total_ptr = add(p.bus_gamma_ptr, 4);
                p.current_trace_row_ptr = add(p.c_total_ptr, 4);
                p.preprocessed_com_ptr = add(p.current_trace_row_ptr, p.query_row_felts);
                p.ood_scatter_table_ptr = add(p.preprocessed_com_ptr, 4);
                p.scatter_reserve_felts = a.scatter_reserve_felts;
                p.proof_order_positions_ptr = add(p.ood_scatter_table_ptr, a.scatter_reserve_felts);
                let map_reserve =
                    n.checked_add(3).map(|n| n / 4 * 4).expect("PVM layout: map reserve overflow");
                p.proof_order_ids_ptr = add(p.proof_order_positions_ptr, u32_count(map_reserve, 1));
                assert!(
                    add(p.proof_order_ids_ptr, u32_count(n, 1)) <= a.next_region_start,
                    "PVM layout: allocation crosses the next scratch anchor"
                );
            },
        }
        assert!(
            p.current_trace_row_ptr.is_multiple_of(8)
                && p.ood_scatter_table_ptr.is_multiple_of(4)
                && p.proof_order_ids_ptr.is_multiple_of(4)
                && p.aux_rand_elem_ptr.is_multiple_of(8),
            "layout: required ABI alignment is missing"
        );
        p
    }

    pub fn table_region(&self) -> MemoryRegion {
        MemoryRegion {
            base: self.ood_scatter_table_ptr,
            len_felts: self.scatter_table_felts,
        }
    }
}

pub(crate) fn add(base: u32, offset: u32) -> u32 {
    base.checked_add(offset).expect("layout: felt address overflow")
}

pub(crate) fn u32_count(value: usize, factor: usize) -> u32 {
    value
        .checked_mul(factor)
        .and_then(|n| u32::try_from(n).ok())
        .expect("layout: count or felt offset exceeds u32")
}

pub(crate) fn sum(values: &[usize]) -> usize {
    values
        .iter()
        .try_fold(0usize, |total, &n| total.checked_add(n))
        .expect("layout: coordinate width overflow")
}
