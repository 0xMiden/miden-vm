//! Canonical placement of the auxiliary-bus boundary values.
//!
//! The proof submits one normalized LogUp boundary value per AIR, ordered by the height-sorted
//! proof order, and `observe_aux_trace` absorbs them in exactly that order. The order-invariant
//! constraint circuit instead reads AIR `k`'s value at `AUX_BUS_BOUNDARY_PTR + 2k` — the address
//! `InputKey::AuxBusBoundary(k)` names, with `k` the canonical instance index.
//!
//! `scatter_aux_bus_boundary` closes that gap after the values are absorbed: the transcript still
//! sees the wire order, and only the resting place of each pair moves. This file pins that the
//! move happens, that it is the right permutation for every proof order the four VM AIRs admit,
//! and that it disturbs neither the operand stack nor the wire order the transcript saw.

use miden_air::MIDEN_AIR_COUNT;
use miden_core::Felt;

use super::vm_layout_const;
use crate::helpers::read_memory_felt;

/// Each AIR contributes one extension-field boundary value, so two base felts.
const SIGMA_FELTS: u32 = 2;

/// Values parked under the absorb so the scatter's stack-neutrality is observable.
const SENTINELS: [u64; 4] = [7_001, 7_002, 7_003, 7_004];
/// Word-aligned harness cell the sentinels are written back to.
const SENTINEL_PTR: u32 = 1_000;
/// Word-aligned harness cell the pushed log heights are written back to.
const HEIGHTS_PTR: u32 = 1_004;

// ORACLES
// ================================================================================================

/// The canonical AIR occupying each proof position.
///
/// The proof order sorts ascending by log height with the canonical instance index breaking ties,
/// which is what `stark::utils::proof_order_position_from_heights` computes one AIR at a time.
fn proof_order(heights: &[u64]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..heights.len()).collect();
    order.sort_by_key(|&air| (heights[air], air));
    order
}

/// Log heights that place canonical AIR `order[p]` at proof position `p`.
pub(super) fn heights_for_order(order: &[usize]) -> Vec<u64> {
    let mut heights = vec![0u64; order.len()];
    for (position, &air) in order.iter().enumerate() {
        heights[air] = 10 + position as u64;
    }
    heights
}

/// Every permutation of `0..n`, in lexicographic order.
pub(super) fn permutations(n: usize) -> Vec<Vec<usize>> {
    let mut current: Vec<usize> = (0..n).collect();
    let mut all = vec![current.clone()];
    loop {
        let Some(pivot) = (0..n.saturating_sub(1)).rev().find(|&i| current[i] < current[i + 1])
        else {
            return all;
        };
        let successor = (pivot + 1..n).rev().find(|&j| current[j] > current[pivot]).expect("pivot");
        current.swap(pivot, successor);
        current[pivot + 1..].reverse();
        all.push(current.clone());
    }
}

/// One distinguishable felt per boundary coordinate, indexed by proof position.
///
/// These are the values as they arrive on the wire: entry `2p + c` is coordinate `c` of the
/// boundary value the proof submits at position `p`.
fn wire_values() -> Vec<u64> {
    (0..(MIDEN_AIR_COUNT as u32 * SIGMA_FELTS))
        .map(|i| 101 + 13 * u64::from(i))
        .collect()
}

// MASM GENERATION
// ================================================================================================

/// Absorbs the boundary values the way `observe_aux_trace` does, optionally scattering afterwards.
///
/// The two `padw adv_loadw` / `mem_storew_le` pairs are the production absorb verbatim; only the
/// transcript observation is replaced by a `dropw`, since the transcript is not what this file
/// measures. The sentinels sit under the whole sequence and are written back at the end.
fn source(heights: &[u64], scatter: bool) -> String {
    let stores = heights
        .iter()
        .enumerate()
        .map(|(air, height)| {
            let offset = if air == 0 { String::new() } else { format!(" add.{air}") };
            format!("    push.{height} exec.constants::air_trace_length_logs_ptr{offset} mem_store")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let scatter = if scatter {
        "    exec.aux_trace::scatter_aux_bus_boundary"
    } else {
        "    # control: absorb only"
    };
    format!(
        "use miden::core::stark::constants
use miden::core::sys::vm::aux_trace
use miden::core::sys::vm::layout

begin
{stores}

    push.{s3}.{s2}.{s1}.{s0}

    padw adv_loadw
    exec.layout::aux_bus_boundary_ptr mem_storew_le
    dropw

    padw adv_loadw
    exec.layout::aux_bus_boundary_ptr add.4 mem_storew_le
    dropw

{scatter}

    push.{SENTINEL_PTR} mem_storew_le dropw
end",
        s0 = SENTINELS[0],
        s1 = SENTINELS[1],
        s2 = SENTINELS[2],
        s3 = SENTINELS[3],
    )
}

/// Runs one fixture and returns the eight boundary felts, in address order.
fn run(heights: &[u64], scatter: bool) -> Vec<u64> {
    let advice = wire_values();
    let source = source(heights, scatter);
    let (output, _) = build_test!(source.as_str(), &[], &advice)
        .execute_for_output()
        .unwrap_or_else(|err| {
            panic!("boundary absorb must execute for heights {heights:?}: {err}")
        });

    for (i, sentinel) in SENTINELS.iter().enumerate() {
        assert_eq!(
            read_memory_felt(&output, SENTINEL_PTR + i as u32),
            Felt::new_unchecked(*sentinel),
            "the absorb/scatter sequence disturbed operand-stack slot {i} for heights {heights:?}"
        );
    }

    let base = vm_layout_const("AUX_BUS_BOUNDARY_PTR");
    (0..MIDEN_AIR_COUNT as u32 * SIGMA_FELTS)
        .map(|i| read_memory_felt(&output, base + i).as_canonical_u64())
        .collect()
}

// TESTS
// ================================================================================================

/// The scatter resolves one proof position per AIR and addresses the boundary region as
/// `MIDEN_AIR_COUNT` consecutive pairs. `constraints_regen` pins the `NUM_AIRS` bound itself; what
/// is pinned here is that the unrolled body and the region it permutes agree with that bound.
#[test]
fn the_scatter_covers_every_air_of_the_relation() {
    let aux_trace = include_str!("../../asm/sys/vm/aux_trace.masm");
    let blocks = aux_trace.matches("exec.utils::proof_order_position_from_heights").count();
    assert_eq!(
        blocks, MIDEN_AIR_COUNT,
        "the scatter does not resolve every AIR's proof position"
    );

    let region =
        vm_layout_const("AUXILIARY_ACE_INPUTS_PTR") - vm_layout_const("AUX_BUS_BOUNDARY_PTR");
    assert_eq!(
        region,
        MIDEN_AIR_COUNT as u32 * SIGMA_FELTS,
        "the boundary region no longer holds exactly one extension value per AIR"
    );
}

/// The absorb alone must leave the wire order in memory: proof position `p` at felt `2p`.
///
/// This is the premise the scatter is defined against; without it the permutation asserted below
/// would be measured from the wrong baseline.
#[test]
fn the_absorb_alone_stores_the_boundary_values_in_wire_order() {
    for order in permutations(MIDEN_AIR_COUNT) {
        let heights = heights_for_order(&order);
        assert_eq!(
            run(&heights, false),
            wire_values(),
            "the control absorb reordered the wire for heights {heights:?}"
        );
    }
}

/// For every proof order the four VM AIRs admit, the value submitted at proof position `p` must
/// come to rest at the canonical address of the AIR that position belongs to.
#[test]
fn the_scatter_moves_every_boundary_value_to_its_canonical_air() {
    let wire = wire_values();
    for order in permutations(MIDEN_AIR_COUNT) {
        let heights = heights_for_order(&order);
        assert_eq!(proof_order(&heights), order, "the fixture does not induce the target order");

        let scattered = run(&heights, true);

        let mut expected = vec![u64::MAX; wire.len()];
        for (position, &air) in order.iter().enumerate() {
            for coordinate in 0..SIGMA_FELTS as usize {
                expected[air * SIGMA_FELTS as usize + coordinate] =
                    wire[position * SIGMA_FELTS as usize + coordinate];
            }
        }

        // Guards against a vacuous fixture: only the identity order may leave the wire in place.
        if order == (0..MIDEN_AIR_COUNT).collect::<Vec<_>>() {
            assert_eq!(expected, wire, "the identity order must not move any boundary value");
        } else {
            assert_ne!(expected, wire, "fixture {heights:?} does not move any boundary value");
        }

        assert_eq!(
            scattered, expected,
            "boundary values landed wrong for heights {heights:?} (proof order {order:?})"
        );
    }
}

/// The weighted outer-LogUp sum must multiply each AIR's boundary value by *that AIR's* row
/// count.
///
/// `observe_aux_trace` forms `sum_k n_k * sigma_k` by pairing the height pushed at stack slot `k`
/// with the boundary pair at region offset `2k`. Both sides are therefore indexed by canonical
/// instance index — but the values arrive in proof order, so the pairing is only correct because
/// the scatter runs first. This runs the production sequence (absorb, scatter, push heights) for
/// every proof order and checks the two halves meet: slot `k` carries AIR `k`'s height, and
/// offset `2k` carries the value AIR `k` submitted from wherever it sat on the wire.
///
/// Reordering the scatter after the sum would leave offset `2k` holding proof position `k`'s
/// value while slot `k` still carried AIR `k`'s height — a silent mispairing for every
/// non-identity order, which is what this pins.
#[test]
fn the_weighted_sum_pairs_each_height_with_its_own_airs_boundary_value() {
    let wire = wire_values();
    for order in permutations(MIDEN_AIR_COUNT) {
        let heights = heights_for_order(&order);
        // The production absorb-and-scatter, then the very push the weighted sum consumes,
        // captured in memory instead of folded into a sum.
        let body = source(&heights, true);
        let body = body.strip_suffix("end").expect("the harness source ends with `end`");
        let source = format!(
            "{body}\n    exec.aux_trace::push_canonical_log_heights\n    \
             push.{HEIGHTS_PTR} mem_storew_le dropw\nend"
        );

        let advice = wire_values();
        let (output, _) = build_test!(source.as_str(), &[], &advice)
            .execute_for_output()
            .unwrap_or_else(|err| panic!("weighted-sum staging must execute: {err}"));

        for air in 0..MIDEN_AIR_COUNT {
            let position = order.iter().position(|&a| a == air).expect("every AIR is placed");

            assert_eq!(
                read_memory_felt(&output, HEIGHTS_PTR + air as u32).as_canonical_u64(),
                heights[air],
                "stack slot {air} does not carry AIR {air}'s log height for {heights:?}"
            );
            for coordinate in 0..SIGMA_FELTS as usize {
                assert_eq!(
                    read_memory_felt(
                        &output,
                        vm_layout_const("AUX_BUS_BOUNDARY_PTR")
                            + (air * SIGMA_FELTS as usize + coordinate) as u32
                    )
                    .as_canonical_u64(),
                    wire[position * SIGMA_FELTS as usize + coordinate],
                    "offset {} does not carry AIR {air}'s boundary value for {heights:?}",
                    air * SIGMA_FELTS as usize + coordinate
                );
            }
        }
    }
}

/// Equal heights carry no proof-order freedom: the canonical instance index breaks every tie, so
/// the scatter must be the identity even though the height comparison never separates two AIRs.
#[test]
fn tied_heights_scatter_to_the_instance_order() {
    let wire = wire_values();
    for heights in [vec![18u64; MIDEN_AIR_COUNT], vec![9u64, 9, 21, 9]] {
        let order = proof_order(&heights);
        let mut expected = vec![u64::MAX; wire.len()];
        for (position, &air) in order.iter().enumerate() {
            for coordinate in 0..SIGMA_FELTS as usize {
                expected[air * SIGMA_FELTS as usize + coordinate] =
                    wire[position * SIGMA_FELTS as usize + coordinate];
            }
        }
        assert_eq!(
            run(&heights, true),
            expected,
            "tied heights {heights:?} did not resolve to the instance order"
        );
    }
}
