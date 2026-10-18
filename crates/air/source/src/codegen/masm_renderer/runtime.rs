//! Fixed trusted runtime parameter ABI. No proof/advice value selects these fields.
use std::{vec, vec::Vec};

use super::{LayoutPlan, RelationInput, V1RenderInput, deep::DeepPlan, ood::MemoryRegion};
pub const PARAMETERS_PTR: u32 = 3_223_324_000;
pub const PARAMETERS_FELTS: u32 = 80;
/// One fixed ABI field, shared by Rust staging and MASM consumers.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ParameterField {
    pub offset: usize,
    pub width: usize,
    pub name: &'static str,
    pub accessor: &'static str,
}
impl ParameterField {
    pub fn address(self) -> u32 {
        PARAMETERS_PTR
            .checked_add(self.offset as u32)
            .expect("parameter address overflow")
    }
    fn write(self, values: &mut [u64; PARAMETERS_FELTS as usize], data: &[u64]) {
        assert_eq!(self.width, data.len());
        values[self.offset..self.offset + self.width].copy_from_slice(data);
    }
}
macro_rules! fields {
    ($( $name:ident = $offset:literal, $width:literal, $accessor:literal; )*) => {
        $(pub(crate) const $name: ParameterField = ParameterField {offset:$offset,width:$width,name:stringify!($name),accessor:$accessor};)*
        pub(crate) const FIELDS: &[ParameterField] = &[$($name),*];
    }
}
fields! {
    AUX_RAND_ELEM_PTR = 0, 1, "aux_rand_elem_ptr";
    AUX_BUS_BOUNDARY_PTR = 1, 1, "aux_bus_boundary_ptr";
    AUXILIARY_ACE_INPUTS_PTR = 2, 1, "auxiliary_ace_inputs_ptr";
    ACE_CIRCUIT_STREAM_PTR = 3, 1, "ace_circuit_stream_ptr";
    STREAM_BLOCKS = 4, 1, "stream_blocks";
    NUM_INPUTS = 5, 1, "num_inputs";
    NUM_GATES = 6, 1, "num_gates";
    CYCLE_LOG = 7, 1, "cycle_log";
    NUM_AIRS = 8, 1, "num_airs";
    FOLD_OFFSET = 9, 1, "fold_offset";
    OOD_SCATTER_TABLE_PTR = 10, 1, "ood_scatter_table_ptr";
    PROOF_ORDER_POSITIONS_PTR = 11, 1, "proof_order_positions_ptr";
    PROOF_ORDER_IDS_PTR = 12, 1, "proof_order_ids_ptr";
    ROW_FELTS = 13, 1, "row_felts";
    BUS_GAMMA_PTR = 14, 1, "bus_gamma_ptr";
    C_TOTAL_PTR = 15, 1, "c_total_ptr";
    PUBLIC_INPUTS_PTR = 16, 1, "public_inputs_ptr";
    PREPROCESSED_COM_PTR = 17, 1, "preprocessed_com_ptr";
    PREPROCESSED_DEPTH = 18, 1, "preprocessed_depth";
    SHAPE_BUFFERED = 19, 1, "shape_buffered";
    ACE_INITIAL_CV = 20, 4, "";
    ACE_DIGEST = 24, 4, "";
    QUOTIENT_SHIFT_RATIO = 28, 1, "";
    QUOTIENT_FIRST_SHIFT = 29, 1, "";
    QUOTIENT_FIRST_WEIGHT = 30, 1, "";
    RESERVED_31 = 31, 1, "";
    PREPROCESSED_LEAF_CV = 32, 4, "";
    MAIN_LEAF_CV = 36, 4, "";
    AUX_LEAF_CV = 40, 4, "";
    QUOTIENT_LEAF_CV = 44, 4, "";
    PREPROCESSED_BASE_PIPE = 48, 4, "";
    MAIN_BASE_PIPE = 52, 4, "";
    AUX_BASE_PIPE = 56, 4, "";
    QUOTIENT_BASE_PIPE = 60, 4, "";
    PREPROCESSED_EXT_PIPE = 64, 4, "";
    QUOTIENT_EXT_PIPE = 68, 4, "";
    QUOTIENT_DESTINATION = 72, 1, "";
    FOLD_COEFFICIENTS_PTR = 73, 1, "";
    RESERVED_74 = 74, 1, "";
    RESERVED_75 = 75, 1, "";
    ACE_PIPE = 76, 4, "";
}
#[derive(Clone, Debug)]
pub(crate) struct PipeBinding {
    pub field: ParameterField,
    pub kind: &'static str,
    pub blocks: u32,
}
#[derive(Clone, Debug)]
pub(crate) struct ParameterWord {
    pub address: u32,
    pub values: [u64; 4],
}
impl ParameterWord {
    pub(crate) fn fields(&self) -> impl Iterator<Item = &'static ParameterField> {
        let start = (self.address - PARAMETERS_PTR) as usize;
        let end = start + self.values.len();
        FIELDS.iter().filter(move |field| (start..end).contains(&field.offset))
    }
}
#[derive(Clone, Debug)]
pub(crate) struct RuntimePlan {
    pub words: Vec<ParameterWord>,
    pub bindings: Vec<PipeBinding>,
    pub preprocessed_depth_address: u32,
}
impl RuntimePlan {
    pub fn new(
        i: &V1RenderInput,
        l: &LayoutPlan,
        d: &DeepPlan,
        glue: Option<&super::pvm_glue::PvmGluePlan>,
    ) -> Self {
        let mut end = 0;
        for field in FIELDS {
            assert_eq!(field.offset, end, "parameter fields must partition the entire ABI");
            end = end.checked_add(field.width).expect("parameter field extent overflow");
            if field.width == 4 {
                assert!(field.address().is_multiple_of(4));
            }
        }
        assert_eq!(end, PARAMETERS_FELTS as usize);
        let region = MemoryRegion {
            base: PARAMETERS_PTR,
            len_felts: PARAMETERS_FELTS,
        };
        let checked_region = |base: u32, end: u32| {
            let len_felts = end.checked_sub(base).expect("runtime interval reversed");
            MemoryRegion { base, len_felts }
        };
        // The generic frame, all VM control/kernel witnesses and the FULL scatter reservation.
        // Both relations exclude this region, even when PVM is the only rendered input.
        let mut excluded = vec![
            checked_region(3_223_322_624, 3_223_323_928),
            MemoryRegion {
                base: i.shared_abi.heights_ptr,
                len_felts: i.shared_abi.heights_capacity,
            },
            MemoryRegion {
                base: i.shared_abi.composition_coefficients_ptr,
                len_felts: 4,
            },
            MemoryRegion {
                base: i.shared_abi.public_inputs_address_ptr,
                len_felts: 1,
            },
        ];
        let (read_start, read_end, scratch_end, preprocessed_depth) = match &i.relation {
            RelationInput::Vm(a) => {
                let prefix = super::layout::u32_count(i.counts.num_public, 2);
                let start =
                    a.read_beta_anchor.checked_sub(prefix).expect("public READ prefix underflow");
                excluded.push(checked_region(
                    a.num_kernel_procedures_ptr,
                    a.scatter_ptr
                        .checked_add(a.scatter_reserve_felts)
                        .expect("VM reserve overflow"),
                ));
                (
                    start,
                    l.ace_circuit_stream_ptr
                        .checked_add(i.circuit.stream_felts)
                        .expect("ACE interval overflow"),
                    a.current_trace_row_ptr
                        .checked_add(l.query_row_felts)
                        .expect("VM row overflow"),
                    19,
                )
            },
            RelationInput::Pvm { abi: a, .. } => (
                a.read_base,
                l.ace_circuit_stream_ptr
                    .checked_add(i.circuit.stream_felts)
                    .expect("ACE interval overflow"),
                l.proof_order_ids_ptr
                    .checked_add(i.geometry.main.len() as u32)
                    .expect("PVM maps overflow"),
                19,
            ),
        };
        excluded.push(checked_region(read_start, read_end));
        if i.relation.is_vm() {
            excluded.push(MemoryRegion {
                base: l.current_trace_row_ptr,
                len_felts: l.query_row_felts,
            });
        } else {
            excluded.push(checked_region(read_end, scratch_end));
        }
        assert!(region.base.is_multiple_of(8) && region.len_felts.is_multiple_of(8));
        for other in excluded {
            assert!(
                !region.overlaps(other),
                "trusted runtime parameters overlap a reserved interval"
            );
        }
        let n = i.geometry.main.len();
        let mut values = [0u64; PARAMETERS_FELTS as usize];
        AUX_RAND_ELEM_PTR.write(&mut values, &[l.aux_rand_elem_ptr as u64]);
        AUX_BUS_BOUNDARY_PTR.write(&mut values, &[l.aux_bus_boundary_ptr as u64]);
        AUXILIARY_ACE_INPUTS_PTR.write(&mut values, &[l.auxiliary_ace_inputs_ptr as u64]);
        ACE_CIRCUIT_STREAM_PTR.write(&mut values, &[l.ace_circuit_stream_ptr as u64]);
        STREAM_BLOCKS.write(&mut values, &[(i.circuit.stream_felts / 8) as u64]);
        NUM_INPUTS.write(&mut values, &[i.circuit.encoded_read_count as u64]);
        NUM_GATES.write(&mut values, &[i.circuit.eval_gate_count as u64]);
        CYCLE_LOG.write(&mut values, &[i.circuit.max_cycle_log as u64]);
        NUM_AIRS.write(&mut values, &[n as u64]);
        FOLD_OFFSET.write(&mut values, &[l.fold_coefficient_felt_offset as u64]);
        OOD_SCATTER_TABLE_PTR.write(&mut values, &[l.ood_scatter_table_ptr as u64]);
        PROOF_ORDER_POSITIONS_PTR.write(&mut values, &[l.proof_order_positions_ptr as u64]);
        PROOF_ORDER_IDS_PTR.write(&mut values, &[l.proof_order_ids_ptr as u64]);
        ROW_FELTS.write(
            &mut values,
            &[l.query_row_felts.checked_mul(2).expect("OOD row overflow") as u64],
        );
        BUS_GAMMA_PTR.write(&mut values, &[l.bus_gamma_ptr as u64]);
        C_TOTAL_PTR.write(&mut values, &[l.c_total_ptr as u64]);
        PUBLIC_INPUTS_PTR.write(&mut values, &[l.public_inputs_ptr as u64]);
        PREPROCESSED_COM_PTR.write(
            &mut values,
            &[if i.relation.is_vm() {
                3_223_322_740
            } else {
                l.preprocessed_com_ptr as u64
            }],
        );
        PREPROCESSED_DEPTH.write(&mut values, &[preprocessed_depth as u64]);
        SHAPE_BUFFERED.write(&mut values, &[glue.map_or(0, |g| g.shape_buffered as u64)]);
        ACE_INITIAL_CV.write(&mut values, &i.circuit.stream_initial_cv);
        ACE_DIGEST.write(&mut values, &i.circuit.digest);
        QUOTIENT_SHIFT_RATIO.write(&mut values, &[i.quotient.shift_ratio]);
        QUOTIENT_FIRST_SHIFT.write(&mut values, &[i.quotient.first_shift]);
        QUOTIENT_FIRST_WEIGHT.write(&mut values, &[i.quotient.first_weight]);
        let leaf_fields = [PREPROCESSED_LEAF_CV, MAIN_LEAF_CV, AUX_LEAF_CV, QUOTIENT_LEAF_CV];
        let pipe_fields =
            [PREPROCESSED_BASE_PIPE, MAIN_BASE_PIPE, AUX_BASE_PIPE, QUOTIENT_BASE_PIPE];
        let mut bindings = Vec::new();
        for (g, group) in d.groups.iter().enumerate() {
            leaf_fields[g].write(&mut values, &group.cv);
            bindings.push(PipeBinding {
                field: pipe_fields[g],
                kind: "base",
                blocks: group.blocks,
            });
        }
        bindings.push(PipeBinding {
            field: PREPROCESSED_EXT_PIPE,
            kind: "ext",
            blocks: d.groups[0].blocks.checked_mul(2).expect("pipe block overflow"),
        });
        bindings.push(PipeBinding {
            field: QUOTIENT_EXT_PIPE,
            kind: "ext",
            blocks: d.groups[3].blocks.checked_mul(2).expect("pipe block overflow"),
        });
        bindings.push(PipeBinding {
            field: ACE_PIPE,
            kind: "ace",
            blocks: i.circuit.stream_felts / 8,
        });
        // All digest slots and reserved fields initially zero; each digest is then staged by
        // procref.
        QUOTIENT_DESTINATION.write(
            &mut values,
            &[l.query_row_felts
                .checked_sub(d.groups[3].width)
                .and_then(|n| n.checked_mul(2))
                .expect("quotient destination overflow") as u64],
        );
        FOLD_COEFFICIENTS_PTR.write(
            &mut values,
            &[l.auxiliary_ace_inputs_ptr
                .checked_add(l.fold_coefficient_felt_offset)
                .expect("fold address overflow") as u64],
        );
        let words = values
            .as_chunks::<4>()
            .0
            .iter()
            .enumerate()
            .map(|(k, w)| ParameterWord {
                address: PARAMETERS_PTR + 4 * k as u32,
                values: *w,
            })
            .collect();
        Self {
            words,
            bindings,
            preprocessed_depth_address: PREPROCESSED_DEPTH.address(),
        }
    }
}
