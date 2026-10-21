//! Static lowering of relation protocol operations into MASM kernels.
//!
//! Heights are proof data; the number of instances, boundary coordinates, and transcript framing
//! are compiler data. Keeping this lowering separate from the optimized field kernels lets the
//! relation use direct calls and immediate addresses without a runtime metadata table.
use std::fmt::Write;

use askama::Template;
use miden_lifted_air::StatementEncoding;

use crate::templates::{PvmAuxTraceTemplate, PvmPublicInputsTemplate};

/// The PVM statement schema and its one-boundary-value-per-instance protocol.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PvmProtocolPlan {
    pub(crate) num_airs: usize,
    pub(crate) num_public_values: usize,
    pub(crate) max_aux_inputs: usize,
    pub(crate) num_aux_inputs: usize,
}

impl PvmProtocolPlan {
    pub(crate) fn from_relation(
        num_airs: usize,
        protocol: &miden_air_definitions::precompiles::relation::RelationProtocol,
    ) -> Result<Self, String> {
        use miden_air_definitions::precompiles::relation::AuxBoundaryReduction;
        match protocol.boundary.reduction {
            AuxBoundaryReduction::TraceLengthWeightedSum => {},
        }
        if protocol.boundary.values_per_air.len() != num_airs
            || protocol.boundary.values_per_air.iter().any(|&n| n != 1)
        {
            return Err("PVM boundary kernel requires one value per AIR".into());
        }
        Self {
            num_airs,
            num_public_values: protocol.num_public_values,
            max_aux_inputs: protocol.max_aux_inputs,
            num_aux_inputs: protocol.num_aux_inputs,
        }
        .validate()
    }

    pub(crate) fn validate(self) -> Result<Self, String> {
        if !(1..=16).contains(&self.num_airs) {
            return Err("PVM protocol requires between one and sixteen AIR instances".into());
        }
        if self.num_public_values != 4 || self.max_aux_inputs != 0 || self.num_aux_inputs != 0 {
            return Err(
                "PVM public-root kernel requires the four-value, zero-aux statement schema".into(),
            );
        }
        Ok(self)
    }

    pub(crate) fn render_public_inputs(self) -> Result<String, String> {
        PvmPublicInputsTemplate {
            num_chiplets: self.num_airs,
            num_public_values: self.num_public_values,
            max_aux_inputs: self.max_aux_inputs,
            num_aux_inputs: self.num_aux_inputs,
            buffered_shape_value_count: (4 + StatementEncoding {
                num_public_values: self.num_public_values,
                max_aux_inputs: self.max_aux_inputs,
                num_aux_inputs: self.num_aux_inputs,
                num_airs: self.num_airs,
            }
            .shape_len())
                % 8,
        }
        .render()
        .map_err(|e| e.to_string())
    }

    pub(crate) fn render_aux_trace(self) -> Result<String, String> {
        let coordinates = self.num_airs * 2;
        use miden_air::precompiles::relations::{BusId, MAX_MESSAGE_WIDTH};
        if MAX_MESSAGE_WIDTH != 18 {
            return Err("PVM beta-power kernel requires message width eighteen".into());
        }
        let mut scatter = String::new();
        for id in (0..self.num_airs).rev() {
            write!(scatter, "    exec.layout::proof_order_positions_ptr").unwrap();
            offset(&mut scatter, id);
            scatter.push_str(" mem_load\n    exec.load_boundary_pair\n\n");
        }
        for start in (0..coordinates / 4 * 4).step_by(4) {
            scatter.push_str("    exec.layout::aux_bus_boundary_ptr");
            offset(&mut scatter, start);
            scatter.push_str(" mem_storew_le dropw\n");
        }
        for start in coordinates / 4 * 4..coordinates {
            scatter.push_str("    exec.layout::aux_bus_boundary_ptr");
            offset(&mut scatter, start);
            scatter.push_str(" mem_store\n");
        }

        let mut observe = String::new();
        for start in (0..coordinates / 4 * 4).step_by(4) {
            observe.push_str("    padw adv_loadw\n    exec.layout::aux_bus_boundary_ptr");
            offset(&mut observe, start);
            observe.push_str(" mem_storew_le\n    exec.random_coin::eidos_observe_word\n");
        }
        // Odd instance counts leave two real coordinates. Reading a padded word would consume
        // the next protocol field and change the native transcript, so lower each scalar exactly.
        for start in coordinates / 4 * 4..coordinates {
            observe.push_str("    adv_push dup exec.layout::aux_bus_boundary_ptr");
            offset(&mut observe, start);
            observe.push_str(" mem_store exec.random_coin::observe_felt\n");
        }

        let mut weighted = String::new();
        for id in 0..self.num_airs {
            if id == 0 {
                weighted.push_str("    mem_load.LOG_AIR_TRACE_LENGTHS_PTR");
            } else {
                weighted.push_str("    push.LOG_AIR_TRACE_LENGTHS_PTR");
                offset(&mut weighted, id);
                weighted.push_str(" mem_load");
            }
            writeln!(weighted, " push.{} exec.load_weighted_aux_sum", id * 2).unwrap();
            if id > 0 {
                weighted.push_str("    ext2add\n");
            }
            weighted.push('\n');
        }
        PvmAuxTraceTemplate {
            uint_val_bus_scale: BusId::UintVal as usize + 1,
            ec_group_bus_scale: BusId::EcGroup as usize + 1,
            max_logup_message_width: MAX_MESSAGE_WIDTH,
            fixed_uint_consumes: fixed_uint_consumes(),
            fixed_ec_consumes: fixed_ec_consumes(),
            num_chiplets: self.num_airs,
            num_aux_value_words: coordinates / 4,
            buffered_aux_value_count: (4 + coordinates) % 8,
            scatter_boundaries: scatter.trim_end().into(),
            observe_boundaries: observe.trim_end().into(),
            weight_boundaries: weighted.trim_end().into(),
        }
        .render()
        .map_err(|e| e.to_string())
    }
}

fn offset(out: &mut String, offset: usize) {
    if offset != 0 {
        write!(out, " add.{offset}").unwrap();
    }
}

/// Lower the fixed `UintVal` consumes: self-pins in declaration order, then dependent values by
/// environment pointer. The arithmetic reduction is commutative, so this order only fixes the
/// kernel's instruction stream; every literal is derived from native data.
fn fixed_uint_consumes() -> String {
    let mut messages = miden_air::precompiles::fixed::fixed_uintval_msgs().collect::<Vec<_>>();
    messages.sort_by_key(|message| {
        (
            message.ptr != message.bound_ptr,
            if message.ptr == message.bound_ptr {
                0
            } else {
                message.ptr.as_canonical_u64()
            },
        )
    });
    let mut out = String::new();
    for message in messages {
        writeln!(
            out,
            "    # UintVal(ptr={}, bound={}).",
            message.ptr.as_canonical_u64(),
            message.bound_ptr.as_canonical_u64()
        )
        .unwrap();
        let limbs = message.limbs.map(|felt| felt.as_canonical_u64());
        let reversed = limbs.into_iter().rev().collect::<Vec<_>>();
        let leading = reversed.iter().take_while(|&&limb| limb == reversed[0]).count();
        let hexadecimal = reversed.iter().any(|&value| value > 255);
        let literal = |value| {
            if hexadecimal {
                format!("0x{value:08X}")
            } else {
                format!("{value}")
            }
        };
        // Zero literals already use the VM's compact padding encoding. Reusing a nonzero u32
        // prefix with dup has the same instruction count and avoids repeated immediate data.
        let rest = if reversed[0] != 0 && leading >= 3 {
            writeln!(
                out,
                "    # The top {leading} limbs are equal; push the value once and duplicate it."
            )
            .unwrap();
            write!(out, "    push.{}", literal(reversed[0])).unwrap();
            for _ in 1..leading {
                out.push_str(" dup");
            }
            out.push('\n');
            &reversed[leading..]
        } else {
            reversed.as_slice()
        };
        out.push_str("    push");
        for &value in rest {
            write!(out, ".{}", literal(value)).unwrap();
        }
        writeln!(
            out,
            ".{}.{}",
            message.bound_ptr.as_canonical_u64(),
            message.ptr.as_canonical_u64()
        )
        .unwrap();
        out.push_str("    movup.13 movup.13\n    exec.fold_uint_val_payload\n    exec.add_cached_prefix_inverse_to_sum\n\n");
    }
    out.trim_end().into()
}

fn fixed_ec_consumes() -> String {
    let mut out = String::new();
    for message in miden_air::precompiles::fixed::fixed_ecgroup_msgs() {
        writeln!(
            out,
            "    # EcGroup(group={}, A={}, B={}, base-bound={}, scalar-bound={}, beta={}, \
             lambda={}).",
            message.group_ptr.as_canonical_u64(),
            message.a_ptr.as_canonical_u64(),
            message.b_ptr.as_canonical_u64(),
            message.bound_ptr.as_canonical_u64(),
            message.scalar_bound_ptr.as_canonical_u64(),
            message.beta_ptr.as_canonical_u64(),
            message.lambda_ptr.as_canonical_u64()
        )
        .unwrap();
        let values = [
            message.lambda_ptr,
            message.beta_ptr,
            message.scalar_bound_ptr,
            message.bound_ptr,
            message.b_ptr,
            message.a_ptr,
            message.group_ptr,
        ];
        out.push_str("    push");
        for value in values {
            write!(out, ".{}", value.as_canonical_u64()).unwrap();
        }
        out.push_str("\n    movup.10 movup.10\n    exec.fold_ec_group_payload\n    push.EC_GROUP_BUS_SCALE exec.compute_bus_prefix ext2add ext2inv\n    movup.5 movup.5 ext2add\n\n");
    }
    out.trim_end().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(num_airs: usize) -> PvmProtocolPlan {
        PvmProtocolPlan {
            num_airs,
            num_public_values: 4,
            max_aux_inputs: 0,
            num_aux_inputs: 0,
        }
        .validate()
        .unwrap()
    }

    #[test]
    fn full_relation_consumes_exact_boundary_coordinates() {
        for n in [miden_air::precompiles::NUM_CHIPLETS] {
            let aux = plan(n).render_aux_trace().unwrap();
            let observe = aux
                .split_once("pub proc observe_aux_trace()")
                .unwrap()
                .1
                .split_once("\nend")
                .unwrap()
                .0;
            assert_eq!(observe.matches("padw adv_loadw").count(), 1 + n / 2);
            assert_eq!(
                observe.matches("adv_push dup exec.layout::aux_bus_boundary_ptr").count(),
                2 * (n % 2)
            );
            assert_eq!(observe.matches("exec.load_weighted_aux_sum").count(), n);
            assert!(aux.contains(&format!("push.{} assert_eq.err=\"PVM observe_aux_trace: boundary transcript framing drifted\"", (4 + 2 * n) % 8)));
            assert!(
                plan(n)
                    .render_public_inputs()
                    .unwrap()
                    .contains(&format!("const BUFFERED_SHAPE_VALUE_COUNT = {}", (12 + n) % 8))
            );
        }
    }
}
