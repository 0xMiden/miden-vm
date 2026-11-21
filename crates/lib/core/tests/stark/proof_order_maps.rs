//! Behavioral oracles for the generated proof-order pass of both relations.
//!
//! `stage_proof_order_maps` derives the height-sorted proof order once from the AIR heights and
//! materializes `pos_by_id` and `id_by_pos`. The out-of-domain scatter, the boundary placement,
//! and the fold-coefficient staging all read these maps, so this file pins them directly: against
//! the Rust stable sort by `(height, instance index)` and against each other as inverses, for every
//! VM order, the PVM structured sample, seeded random heights, and tied heights.

use miden_ace::{MAX_ORDER_AIRS, compiler::render_proof_order_maps};
use miden_core::Felt;

use super::{
    pvm_sigma_scatter::{heights_for_order as pvm_heights_for_order, structured_orders},
    vm_sigma_scatter::{heights_for_order, permutations},
};
use crate::helpers::{read_memory_felt, stark_constant};

/// Values parked under the pass so its stack-neutrality is observable.
const SENTINELS: [u64; 4] = [7_001, 7_002, 7_003, 7_004];
/// Word-aligned harness cell the sentinels are written back to.
const SENTINEL_PTR: u32 = 1_000;
/// Written immediately around the two maps and into any alignment padding between them.
const MAP_MEMORY_SENTINEL: u64 = 0xcafe_f00d;

/// Mixed heights with frequent ties; each generic configuration uses the required prefix.
const GENERIC_HEIGHTS: [u64; MAX_ORDER_AIRS] = [12, 8, 12, 6, 9, 6, 10, 9, 11, 7, 11, 8];

struct Relation {
    module: &'static str,
    num_airs: usize,
}

impl Relation {
    fn vm() -> Self {
        Self { module: "vm", num_airs: 4 }
    }

    fn pvm() -> Self {
        Self {
            module: "pvm",
            num_airs: miden_air::precompiles::NUM_CHIPLETS,
        }
    }

    /// Guards the live map extents and the unused cells between them.
    fn map_guard_addresses(&self) -> Vec<u32> {
        let positions = stark_constant("PROOF_ORDER_POSITIONS_PTR");
        let ids = stark_constant("PROOF_ORDER_IDS_PTR");
        let positions_end = positions + self.num_airs as u32;
        assert!(positions > 0, "{}: positions table cannot be guarded below zero", self.module);
        assert!(positions_end <= ids, "{}: pos_by_id overlaps id_by_pos", self.module);

        let mut guards = vec![positions - 1];
        guards.extend(positions_end..ids);
        guards.push(ids + self.num_airs as u32);
        guards
    }

    /// Stores the heights and runs the pass under the sentinels.
    fn source(&self, heights: &[u64], prelude: &str, call: &str) -> String {
        let stores = heights
            .iter()
            .enumerate()
            .map(|(air, height)| {
                let offset = if air == 0 { String::new() } else { format!(" add.{air}") };
                format!("    push.{height} push.LOG_AIR_TRACE_LENGTHS_PTR{offset} mem_store")
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
            "use {{LOG_AIR_TRACE_LENGTHS_PTR}} from miden::core::stark::constants
{prelude}

begin
{stores}
{memory_guards}
    push.{s3}.{s2}.{s1}.{s0}
    {call}
    push.{SENTINEL_PTR} mem_storew_le dropw
end",
            s0 = SENTINELS[0],
            s1 = SENTINELS[1],
            s2 = SENTINELS[2],
            s3 = SENTINELS[3],
        )
    }

    fn check(&self, heights: &[u64]) {
        let prelude = format!("use miden::core::sys::{}::ood_frames", self.module);
        let source = self.source(heights, &prelude, "exec.ood_frames::stage_proof_order_maps");
        self.check_source(heights, source);
    }

    fn check_source(&self, heights: &[u64], source: String) {
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

        let positions = stark_constant("PROOF_ORDER_POSITIONS_PTR");
        let ids = stark_constant("PROOF_ORDER_IDS_PTR");
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

/// Covers scalar tails as well as complete word loads and stores for every supported AIR count.
#[test]
fn generic_renderer_executes_every_supported_count() {
    for num_airs in 2..=MAX_ORDER_AIRS {
        let relation = Relation { module: "generated", num_airs };
        let heights = &GENERIC_HEIGHTS[..num_airs];
        let procedure = render_proof_order_maps(num_airs).expect("supported AIR count").replacen(
            "pub proc ",
            "proc ",
            1,
        );
        let prelude = format!(
            "use {{PROOF_ORDER_POSITIONS_PTR, PROOF_ORDER_IDS_PTR}} from miden::core::stark::constants\n{procedure}"
        );
        let source = relation.source(heights, &prelude, "exec.stage_proof_order_maps");
        relation.check_source(heights, source);
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
        vec![18u64; 12],
        vec![9u64, 9, 9, 9, 21, 21, 21, 9, 9, 21, 9, 21],
        vec![14u64, 12, 14, 12, 11, 11, 16, 16, 12, 14, 11, 16],
        vec![1u64, 29, 1, 29, 1, 29, 1, 29, 1, 29, 1, 29],
    ] {
        relation.check(&heights);
    }
}

/// Deterministic pseudo-random height vectors, ties included, so the generated PVM stack
/// choreography is driven by more than the structured sample. The Rust network itself is
/// validated exhaustively in `miden-ace`; this exercises the rendered MASM with the same
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
/// no conditionals, so its cost and its control flow are independent of the proof order. Both the
/// four-input VM network and the twelve-input PVM network are Batcher's merge exchange, generated
/// by `miden-ace`.
#[test]
fn the_pass_is_a_fixed_comparator_network() {
    for (hook, comparators) in [
        (include_str!("../../asm/sys/vm/ood_frames.masm"), 5),
        (include_str!("../../asm/sys/pvm/ood_frames.masm"), 41),
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
