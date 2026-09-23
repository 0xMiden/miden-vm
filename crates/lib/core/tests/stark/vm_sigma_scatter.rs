//! Checks canonical placement of VM auxiliary-bus boundary values.
//!
//! Each AIR contributes one extension-field value in height-sorted proof order.
//! The harness stages these pairs, calls `scatter_aux_bus_boundary`, and checks canonical
//! memory placement and stack preservation. Transcript observation is outside this harness.

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
/// which is what `sys::vm::ood_frames::stage_proof_order_maps` derives once from the heights.
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

/// Stages proof-ordered boundary values and calls the production scatter with stack sentinels.
fn source(heights: &[u64]) -> String {
    let stores = heights
        .iter()
        .enumerate()
        .map(|(air, height)| {
            let offset = if air == 0 { String::new() } else { format!(" add.{air}") };
            format!("    push.{height} exec.constants::air_trace_length_logs_ptr{offset} mem_store")
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "use miden::core::stark::constants
use miden::core::sys::vm::aux_trace
use miden::core::sys::vm::layout
use miden::core::sys::vm::ood_frames

begin
{stores}
    exec.ood_frames::stage_proof_order_maps

    push.{s3}.{s2}.{s1}.{s0}

    padw adv_loadw
    exec.layout::aux_bus_boundary_ptr mem_storew_le
    dropw

    padw adv_loadw
    exec.layout::aux_bus_boundary_ptr add.4 mem_storew_le
    dropw

    exec.aux_trace::scatter_aux_bus_boundary

    push.{SENTINEL_PTR} mem_storew_le dropw
    exec.aux_trace::push_canonical_log_heights
    push.{HEIGHTS_PTR} mem_storew_le dropw
end",
        s0 = SENTINELS[0],
        s1 = SENTINELS[1],
        s2 = SENTINELS[2],
        s3 = SENTINELS[3],
    )
}

/// Runs one fixture and returns the eight boundary felts, in address order.
fn run(heights: &[u64]) -> Vec<u64> {
    let advice = wire_values();
    let source = source(heights);
    let (output, _) = build_test!(source.as_str(), &[], &advice)
        .execute_for_output()
        .unwrap_or_else(|err| {
            panic!("boundary scatter must execute for heights {heights:?}: {err}")
        });

    for (i, sentinel) in SENTINELS.iter().enumerate() {
        assert_eq!(
            read_memory_felt(&output, SENTINEL_PTR + i as u32),
            Felt::new_unchecked(*sentinel),
            "the absorb/scatter sequence disturbed operand-stack slot {i} for heights {heights:?}"
        );
    }

    for (air, &height) in heights.iter().enumerate() {
        assert_eq!(
            read_memory_felt(&output, HEIGHTS_PTR + air as u32).as_canonical_u64(),
            height,
            "canonical height for AIR {air}"
        );
    }

    let base = vm_layout_const("AUX_BUS_BOUNDARY_PTR");
    (0..MIDEN_AIR_COUNT as u32 * SIGMA_FELTS)
        .map(|i| read_memory_felt(&output, base + i).as_canonical_u64())
        .collect()
}

// TESTS
// ================================================================================================

/// The boundary region holds one extension-field value per AIR.
#[test]
fn the_scatter_covers_every_air_of_the_relation() {
    let region =
        vm_layout_const("AUXILIARY_ACE_INPUTS_PTR") - vm_layout_const("AUX_BUS_BOUNDARY_PTR");
    assert_eq!(
        region,
        MIDEN_AIR_COUNT as u32 * SIGMA_FELTS,
        "the boundary region no longer holds exactly one extension value per AIR"
    );
}

/// For every proof order the four VM AIRs admit, the value submitted at proof position `p` must
/// come to rest at the canonical address of the AIR that position belongs to.
#[test]
fn the_scatter_moves_every_boundary_value_to_its_canonical_air() {
    let wire = wire_values();
    for order in permutations(MIDEN_AIR_COUNT) {
        let heights = heights_for_order(&order);
        assert_eq!(proof_order(&heights), order, "the fixture does not induce the target order");

        let scattered = run(&heights);

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
            run(&heights),
            expected,
            "tied heights {heights:?} did not resolve to the instance order"
        );
    }
}
