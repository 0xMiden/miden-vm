//! Canonical placement of the PVM auxiliary-bus boundary values.
//!
//! The proof submits every chiplet's exposed LogUp boundary value consecutively, the chiplets
//! ordered by trace height, and `observe_aux_trace` absorbs them in exactly that order. The
//! order-invariant constraint circuit instead reads chiplet `j`'s value at
//! `AUX_BUS_BOUNDARY_PTR + 2j` — the address `InputKey::AuxBusBoundary(j)` names, with `j` the
//! canonical instance index.
//!
//! Every chiplet exposes exactly one value, so the flat proof-ordered stream is a simple
//! `2 * position` map. This file pins that `scatter_aux_bus_boundary` inverts exactly that map,
//! for every proof order the fixtures induce, and that it disturbs neither the operand stack nor
//! the wire order the transcript saw.

use miden_core::Felt;

use super::pvm_layout_const;
use crate::helpers::read_memory_felt;

/// Chiplet instances in `ChipletAir::all()` order.
const NUM_CHIPLETS: usize = 10;

/// Boundary values each chiplet exposes, in canonical instance order.
///
/// `pvm_aux_hook_matches_every_chiplets_boundary_shape` (in `miden-precompiles-verifier`) pins
/// this shape against `LiftedAir::num_aux_values`, so a chiplet that started exposing a second
/// value fails there rather than silently reshaping the fixtures here.
const BOUNDARY_WIDTHS: [usize; NUM_CHIPLETS] = [1; NUM_CHIPLETS];

/// Every boundary value is one extension-field element, so two base felts.
const SIGMA_FELTS: usize = 2;

/// Values parked under the absorb so the scatter's stack-neutrality is observable.
const SENTINELS: [u64; 4] = [7_001, 7_002, 7_003, 7_004];
/// Word-aligned harness cell the sentinels are written back to.
const SENTINEL_PTR: u32 = 1_000;

fn total_values() -> usize {
    BOUNDARY_WIDTHS.iter().sum()
}

// ORACLES
// ================================================================================================

/// The canonical chiplet occupying each proof position.
///
/// The proof order sorts ascending by log height with the canonical instance index breaking ties,
/// which is what `stark::utils::proof_order_position_from_heights` computes one chiplet at a time.
fn proof_order(heights: &[u64]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..heights.len()).collect();
    order.sort_by_key(|&air| (heights[air], air));
    order
}

/// Log heights that place canonical chiplet `order[p]` at proof position `p`.
pub(super) fn heights_for_order(order: &[usize]) -> Vec<u64> {
    let mut heights = vec![0u64; order.len()];
    for (position, &air) in order.iter().enumerate() {
        heights[air] = 10 + position as u64;
    }
    heights
}

/// Flat index of each chiplet's first boundary value when the blocks are laid out in `order`.
fn starts_in(order: &[usize]) -> Vec<usize> {
    let mut starts = vec![0usize; NUM_CHIPLETS];
    let mut next = 0usize;
    for &air in order {
        starts[air] = next;
        next += BOUNDARY_WIDTHS[air];
    }
    starts
}

/// Canonical flat index of each chiplet's first boundary value.
fn canonical_starts() -> Vec<usize> {
    starts_in(&(0..NUM_CHIPLETS).collect::<Vec<_>>())
}

/// One distinguishable felt per boundary coordinate, indexed by flat proof-order slot.
fn wire_values() -> Vec<u64> {
    (0..(total_values() * SIGMA_FELTS) as u64).map(|i| 101 + 13 * i).collect()
}

/// The boundary region as it must read after the scatter.
fn expected_after_scatter(order: &[usize], wire: &[u64]) -> Vec<u64> {
    let proof = starts_in(order);
    let canonical = canonical_starts();
    let mut expected = vec![u64::MAX; wire.len()];
    for air in 0..NUM_CHIPLETS {
        for value in 0..BOUNDARY_WIDTHS[air] {
            for coordinate in 0..SIGMA_FELTS {
                expected[(canonical[air] + value) * SIGMA_FELTS + coordinate] =
                    wire[(proof[air] + value) * SIGMA_FELTS + coordinate];
            }
        }
    }
    assert!(
        !expected.contains(&u64::MAX),
        "the canonical numbering does not cover every value"
    );
    expected
}

/// Structured proof orders: identity, reversal, every adjacent swap, each chiplet moved to either
/// end, and a deterministic scramble. Ten chiplets admit 3,628,800 orders, so the sweep is a
/// sample; it is chosen to separate every pair of adjacent positions.
pub(super) fn structured_orders() -> Vec<Vec<usize>> {
    let identity: Vec<usize> = (0..NUM_CHIPLETS).collect();
    let mut orders = vec![identity.clone()];
    let mut reversed = identity.clone();
    reversed.reverse();
    orders.push(reversed);
    for i in 0..NUM_CHIPLETS - 1 {
        let mut order = identity.clone();
        order.swap(i, i + 1);
        orders.push(order);
    }
    for air in 0..NUM_CHIPLETS {
        let mut front = identity.clone();
        front.remove(air);
        front.insert(0, air);
        orders.push(front);
        let mut back = identity.clone();
        back.remove(air);
        back.push(air);
        orders.push(back);
    }
    // A deterministic scramble.
    orders.push(vec![4, 9, 1, 7, 0, 6, 3, 8, 2, 5]);
    orders.push(vec![3, 0, 2, 4, 5, 6, 7, 8, 9, 1]);
    orders.push(vec![1, 9, 8, 7, 6, 5, 4, 2, 0, 3]);
    orders.sort();
    orders.dedup();
    orders
}

// MASM GENERATION
// ================================================================================================

/// Absorbs the boundary values the way `observe_aux_trace` does, optionally scattering afterwards.
///
/// The six `padw adv_loadw` / `mem_storew_le` pairs are the production absorb verbatim; only the
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
    let absorbs = (0..total_values() * SIGMA_FELTS / 4)
        .map(|word| {
            let offset = if word == 0 {
                String::new()
            } else {
                format!(" add.{}", 4 * word)
            };
            format!(
                "    padw adv_loadw\n    exec.layout::aux_bus_boundary_ptr{offset} \
                 mem_storew_le\n    dropw"
            )
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
use miden::core::sys::pvm
use miden::core::sys::pvm::aux_trace
use miden::core::sys::pvm::layout

begin
{stores}
    exec.pvm::stage_proof_order_positions

    push.{s3}.{s2}.{s1}.{s0}

{absorbs}

{scatter}

    push.{SENTINEL_PTR} mem_storew_le dropw
end",
        s0 = SENTINELS[0],
        s1 = SENTINELS[1],
        s2 = SENTINELS[2],
        s3 = SENTINELS[3],
    )
}

/// Runs one fixture and returns the boundary region, in address order.
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

    let base = pvm_layout_const("AUX_BUS_BOUNDARY_PTR");
    (0..(total_values() * SIGMA_FELTS) as u32)
        .map(|i| read_memory_felt(&output, base + i).as_canonical_u64())
        .collect()
}

// TESTS
// ================================================================================================

/// The scatter resolves one proof position per chiplet and addresses exactly the boundary region
/// the circuit reads.
#[test]
fn the_scatter_covers_every_chiplet_of_the_relation() {
    let aux_trace = include_str!("../../asm/sys/pvm/aux_trace.masm");
    assert_eq!(
        aux_trace.matches("exec.layout::proof_order_positions_ptr").count(),
        NUM_CHIPLETS,
        "the scatter does not resolve every chiplet's proof position"
    );
    assert_eq!(
        aux_trace.matches("exec.load_boundary_pair").count(),
        total_values(),
        "the scatter does not read every exposed boundary value"
    );

    let region =
        pvm_layout_const("AUXILIARY_ACE_INPUTS_PTR") - pvm_layout_const("AUX_BUS_BOUNDARY_PTR");
    assert_eq!(
        region as usize,
        total_values() * SIGMA_FELTS,
        "the boundary region no longer holds exactly the exposed values"
    );
}

/// The absorb alone must leave the wire order in memory: flat slot `j` at felt `2j`.
///
/// This is the premise the scatter is defined against; without it the permutation asserted below
/// would be measured from the wrong baseline.
#[test]
fn the_absorb_alone_stores_the_boundary_values_in_wire_order() {
    for order in structured_orders() {
        let heights = heights_for_order(&order);
        assert_eq!(
            run(&heights, false),
            wire_values(),
            "the control absorb reordered the wire for heights {heights:?}"
        );
    }
}

/// Every value submitted at a flat proof-order slot must come to rest at the canonical address of
/// the chiplet, and the value within that chiplet, that the slot belongs to.
#[test]
fn the_scatter_moves_every_boundary_value_to_its_canonical_slot() {
    let wire = wire_values();
    let identity: Vec<usize> = (0..NUM_CHIPLETS).collect();
    for order in structured_orders() {
        let heights = heights_for_order(&order);
        assert_eq!(proof_order(&heights), order, "the fixture does not induce the target order");

        let expected = expected_after_scatter(&order, &wire);
        // Guards against a vacuous fixture: only the identity order may leave the wire in place.
        if order == identity {
            assert_eq!(expected, wire, "the identity order must not move any boundary value");
        } else {
            assert_ne!(expected, wire, "fixture {heights:?} does not move any boundary value");
        }

        assert_eq!(
            run(&heights, true),
            expected,
            "boundary values landed wrong for heights {heights:?} (proof order {order:?})"
        );
    }
}

/// Equal heights carry no proof-order freedom: the canonical instance index breaks every tie, so
/// the scatter must be the identity even though the height comparison never separates two
/// chiplets.
#[test]
fn tied_heights_scatter_to_the_instance_order() {
    let wire = wire_values();
    for heights in [
        vec![18u64; NUM_CHIPLETS],
        vec![9u64, 9, 9, 9, 21, 21, 21, 9, 9, 21],
        // A pair of chiplets tied against each other, everything else split around them.
        vec![14u64, 12, 14, 12, 11, 11, 16, 16, 12, 14],
    ] {
        let order = proof_order(&heights);
        assert_eq!(
            run(&heights, true),
            expected_after_scatter(&order, &wire),
            "tied heights {heights:?} did not resolve to the instance order"
        );
    }
}
