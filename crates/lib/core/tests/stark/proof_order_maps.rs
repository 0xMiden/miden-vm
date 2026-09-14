//! Behavioral oracles for the generated proof-order pass of both relations.
//!
//! `stage_proof_order_maps` derives the height-sorted proof order once from the AIR heights and
//! materializes `pos_by_id` and `id_by_pos`. The out-of-domain scatter, the boundary placement,
//! and the fold-coefficient staging all read these maps, so this file pins them directly: against
//! the Rust stable sort by `(height, instance index)` and against each other as inverses, for every
//! VM order, the PVM structured sample, seeded random heights, and tied heights.

use miden_ace_codegen::{MAX_ORDER_AIRS, ProofOrderMapsConfig, render_proof_order_maps};
use miden_core::Felt;

use super::{
    pvm_layout_const,
    pvm_sigma_scatter::{heights_for_order as pvm_heights_for_order, structured_orders},
    vm_layout_const,
    vm_sigma_scatter::{heights_for_order, permutations},
};
use crate::helpers::read_memory_felt;

/// Values parked under the pass so its stack-neutrality is observable.
const SENTINELS: [u64; 4] = [7_001, 7_002, 7_003, 7_004];
/// Word-aligned harness cell the sentinels are written back to.
const SENTINEL_PTR: u32 = 1_000;
/// Written immediately around the two maps and into any alignment padding between them.
const MAP_MEMORY_SENTINEL: u64 = 0xcafe_f00d;

/// Literal, word-aligned regions used to execute non-production renderer configurations.
const GENERIC_HEIGHTS_PTR: u32 = 2_000;
const GENERIC_POSITIONS_PTR: u32 = 2_100;
const GENERIC_IDS_PTR: u32 = 2_120;

/// Mixed heights with frequent ties; each generic configuration uses the required prefix.
const GENERIC_HEIGHTS: [u64; MAX_ORDER_AIRS] = [12, 8, 12, 6, 9, 6, 10, 9, 11, 7, 11, 8];

struct Relation {
    module: &'static str,
    num_airs: usize,
    layout_const: fn(&str) -> u32,
}

impl Relation {
    fn vm() -> Self {
        Self {
            module: "vm",
            num_airs: 4,
            layout_const: vm_layout_const,
        }
    }

    fn pvm() -> Self {
        Self {
            module: "pvm",
            num_airs: 10,
            layout_const: pvm_layout_const,
        }
    }

    /// Every non-map cell directly bordering the allocation. PVM's ten-entry `pos_by_id` table
    /// has two padding cells before the word-aligned `id_by_pos` table; VM's four-entry tables are
    /// adjacent and therefore have no internal padding.
    fn map_guard_addresses(&self) -> Vec<u32> {
        let positions = (self.layout_const)("PROOF_ORDER_POSITIONS_PTR");
        let ids = (self.layout_const)("PROOF_ORDER_IDS_PTR");
        let positions_end = positions + self.num_airs as u32;
        assert!(positions > 0, "{}: positions table cannot be guarded below zero", self.module);
        assert!(positions_end <= ids, "{}: pos_by_id overlaps id_by_pos", self.module);

        let mut guards = vec![positions - 1];
        guards.extend(positions_end..ids);
        guards.push(ids + self.num_airs as u32);
        guards
    }

    /// Stores the heights and runs the pass under the sentinels.
    fn source(&self, heights: &[u64]) -> String {
        let module = self.module;
        let stores = heights
            .iter()
            .enumerate()
            .map(|(air, height)| {
                let offset = if air == 0 { String::new() } else { format!(" add.{air}") };
                format!(
                    "    push.{height} exec.constants::air_trace_length_logs_ptr{offset} mem_store"
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let memory_guards = self
            .map_guard_addresses()
            .into_iter()
            .map(|addr| format!("    push.{MAP_MEMORY_SENTINEL} push.{addr} mem_store"))
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "use miden::core::stark::constants
use miden::core::sys::{module}::ood_frames

begin
{stores}
{memory_guards}
    push.{s3}.{s2}.{s1}.{s0}
    exec.ood_frames::stage_proof_order_maps
    push.{SENTINEL_PTR} mem_storew_le dropw
end",
            s0 = SENTINELS[0],
            s1 = SENTINELS[1],
            s2 = SENTINELS[2],
            s3 = SENTINELS[3],
        )
    }

    fn check(&self, heights: &[u64]) {
        let source = self.source(heights);
        let test = build_test!(source.as_str(), &[]);
        let (output, _) = test.execute_for_output().unwrap_or_else(|err| {
            panic!("{}: the proof-order pass must execute for {heights:?}: {err}", self.module)
        });

        for (i, sentinel) in SENTINELS.iter().enumerate() {
            assert_eq!(
                read_memory_felt(&output, SENTINEL_PTR + i as u32),
                Felt::new_unchecked(*sentinel),
                "{}: the pass disturbed operand-stack slot {i} for heights {heights:?}",
                self.module
            );
        }

        for addr in self.map_guard_addresses() {
            assert_eq!(
                read_memory_felt(&output, addr),
                Felt::new_unchecked(MAP_MEMORY_SENTINEL),
                "{}: the pass wrote outside its maps at address {addr} for heights {heights:?}",
                self.module
            );
        }

        let mut order: Vec<usize> = (0..self.num_airs).collect();
        order.sort_by_key(|&air| (heights[air], air));

        let positions = (self.layout_const)("PROOF_ORDER_POSITIONS_PTR");
        let ids = (self.layout_const)("PROOF_ORDER_IDS_PTR");
        for (position, &air) in order.iter().enumerate() {
            assert_eq!(
                read_memory_felt(&output, positions + air as u32).as_canonical_u64(),
                position as u64,
                "{}: pos_by_id[{air}] is wrong for heights {heights:?}",
                self.module
            );
            assert_eq!(
                read_memory_felt(&output, ids + position as u32).as_canonical_u64(),
                air as u64,
                "{}: id_by_pos[{position}] is wrong for heights {heights:?}",
                self.module
            );
        }
    }
}

/// Executes one renderer configuration as a local MASM procedure and checks its complete contract.
fn check_generic_renderer_config(num_airs: usize, word_load_heights: bool, word_store_ids: bool) {
    let heights = &GENERIC_HEIGHTS[..num_airs];
    let heights_ptr = format!("push.{GENERIC_HEIGHTS_PTR}");
    let pos_by_id_ptr = format!("push.{GENERIC_POSITIONS_PTR}");
    let id_by_pos_ptr = format!("push.{GENERIC_IDS_PTR}");
    let procedure = render_proof_order_maps(&ProofOrderMapsConfig {
        num_airs,
        heights_ptr: &heights_ptr,
        pos_by_id_ptr: &pos_by_id_ptr,
        id_by_pos_ptr: &id_by_pos_ptr,
        word_load_heights,
        word_store_ids,
    })
    .expect("every supported generic configuration must render")
    .replacen("pub proc stage_proof_order_maps", "proc stage_proof_order_maps", 1);

    let height_stores = heights
        .iter()
        .enumerate()
        .map(|(air, height)| {
            format!("    push.{height} push.{} mem_store", GENERIC_HEIGHTS_PTR + air as u32)
        })
        .collect::<Vec<_>>()
        .join("\n");
    let positions_end = GENERIC_POSITIONS_PTR + num_airs as u32;
    let guard_addresses = core::iter::once(GENERIC_POSITIONS_PTR - 1)
        .chain(positions_end..GENERIC_IDS_PTR)
        .chain(core::iter::once(GENERIC_IDS_PTR + num_airs as u32))
        .collect::<Vec<_>>();
    let memory_guards = guard_addresses
        .iter()
        .map(|addr| format!("    push.{MAP_MEMORY_SENTINEL} push.{addr} mem_store"))
        .collect::<Vec<_>>()
        .join("\n");
    let source = format!(
        "{procedure}\n\
         begin\n\
         {height_stores}\n\
         {memory_guards}\n    \
         push.{s3}.{s2}.{s1}.{s0}\n    \
         exec.stage_proof_order_maps\n    \
         push.{SENTINEL_PTR} mem_storew_le dropw\n\
         end",
        s0 = SENTINELS[0],
        s1 = SENTINELS[1],
        s2 = SENTINELS[2],
        s3 = SENTINELS[3],
    );
    let test = build_test!(source.as_str(), &[]);
    let (output, _) = test.execute_for_output().unwrap_or_else(|err| {
        panic!(
            "generic {num_airs}-AIR pass (word load {word_load_heights}, word store \
             {word_store_ids}) must execute: {err}"
        )
    });

    for (i, sentinel) in SENTINELS.iter().enumerate() {
        assert_eq!(
            read_memory_felt(&output, SENTINEL_PTR + i as u32),
            Felt::new_unchecked(*sentinel),
            "generic {num_airs}-AIR pass disturbed operand-stack slot {i}"
        );
    }
    for addr in guard_addresses {
        assert_eq!(
            read_memory_felt(&output, addr),
            Felt::new_unchecked(MAP_MEMORY_SENTINEL),
            "generic {num_airs}-AIR pass wrote outside its maps at address {addr}"
        );
    }

    let mut order: Vec<usize> = (0..num_airs).collect();
    order.sort_by_key(|&air| (heights[air], air));
    for (position, &air) in order.iter().enumerate() {
        assert_eq!(
            read_memory_felt(&output, GENERIC_POSITIONS_PTR + air as u32).as_canonical_u64(),
            position as u64,
            "generic {num_airs}-AIR pos_by_id[{air}] is wrong"
        );
        assert_eq!(
            read_memory_felt(&output, GENERIC_IDS_PTR + position as u32).as_canonical_u64(),
            air as u64,
            "generic {num_airs}-AIR id_by_pos[{position}] is wrong"
        );
    }
}

/// The renderer supports every AIR count from two through twelve. This test executes every
/// supported count and each load/store mode.
#[test]
fn generic_renderer_executes_every_supported_count_and_access_mode() {
    for num_airs in 2..=MAX_ORDER_AIRS {
        for word_store_ids in [false, true] {
            check_generic_renderer_config(num_airs, false, word_store_ids);
        }
    }
    for word_store_ids in [false, true] {
        check_generic_renderer_config(4, true, word_store_ids);
    }
}

/// Every one of the 24 VM orders, induced by distinct heights.
#[test]
fn vm_maps_match_the_stable_sort_for_every_order() {
    let relation = Relation::vm();
    for order in permutations(relation.num_airs) {
        relation.check(&heights_for_order(&order));
    }
}

/// Equal heights carry no proof-order freedom: the instance index breaks every tie, so the pass
/// must resolve ties to instance order and never treat two equal keys as swappable.
#[test]
fn vm_maps_resolve_ties_to_instance_order() {
    let relation = Relation::vm();
    for heights in [
        vec![18u64; 4],
        vec![9u64, 9, 21, 9],
        vec![12u64, 12, 10, 12],
        vec![6u64, 29, 6, 29],
    ] {
        relation.check(&heights);
    }
}

/// The PVM structured sample: identity, reversal, adjacent swaps, each chiplet at either end, and
/// scrambles that move the two composite chiplets past each other.
#[test]
fn pvm_maps_match_the_stable_sort_for_structured_orders() {
    let relation = Relation::pvm();
    for order in structured_orders() {
        relation.check(&pvm_heights_for_order(&order));
    }
}

#[test]
fn pvm_maps_resolve_ties_to_instance_order() {
    let relation = Relation::pvm();
    for heights in [
        vec![18u64; 10],
        vec![9u64, 9, 9, 9, 21, 21, 21, 9, 9, 21],
        vec![14u64, 12, 14, 12, 11, 11, 16, 16, 12, 14],
        vec![1u64, 29, 1, 29, 1, 29, 1, 29, 1, 29],
    ] {
        relation.check(&heights);
    }
}

/// Deterministic pseudo-random height vectors, ties included, so the generated PVM stack
/// choreography is driven by more than the structured sample. The Rust network itself is
/// validated exhaustively in `miden-ace-codegen`; this exercises the rendered MASM with the same
/// class of inputs.
#[test]
fn pvm_maps_match_the_stable_sort_for_seeded_random_heights() {
    let relation = Relation::pvm();
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        6 + state % 24
    };
    for _ in 0..32 {
        let heights: Vec<u64> = (0..relation.num_airs).map(|_| next()).collect();
        relation.check(&heights);
    }
}

/// The generated pass must be branch-free: a fixed comparator network of `cswap`s, no loops and
/// no conditionals, so its cost and its control flow are independent of the proof order. The
/// four-input network is Batcher's merge exchange; the PVM uses the smaller 29-comparator network
/// pinned in `miden-ace-codegen`. Both counts are pinned again on the Rust side by
/// `network_sizes_are_pinned`.
#[test]
fn the_pass_is_a_fixed_comparator_network() {
    for (hook, comparators) in [
        (include_str!("../../asm/sys/vm/ood_frames.masm"), 5),
        (include_str!("../../asm/sys/pvm/ood_frames.masm"), 29),
    ] {
        let start = hook.find("pub proc stage_proof_order_maps").expect("the pass is generated");
        let body = &hook[start..];
        let body = &body[..body.find("\nend").expect("the pass ends")];
        let ops: Vec<_> = body
            .lines()
            .flat_map(|line| line.split('#').next().unwrap_or_default().split_whitespace())
            .collect();
        assert_eq!(
            ops.windows(2).filter(|pair| pair[0] == "u32lt" && pair[1] == "cswap").count(),
            comparators,
            "the pass must apply exactly the generated comparator network"
        );
        assert_eq!(
            ops.iter().filter(|&&op| op == "cswap").count(),
            comparators,
            "every cswap must belong to a generated compare-exchange"
        );
        for forbidden in ["while", "if.", "repeat", "adv_push"] {
            assert!(
                !ops.iter().any(|op| op.starts_with(forbidden)),
                "the pass must not contain an operation starting with `{forbidden}`"
            );
        }
    }
}
