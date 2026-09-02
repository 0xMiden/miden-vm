//! Ingest-time scatter for the PVM out-of-domain row: correctness and mechanism-cost guard.
//!
//! The proof commits each chiplet's trace in *proof order* (ascending log height, instance index
//! breaking ties), while the order-invariant ACE circuit reads every chiplet's trace at its
//! *canonical* (instance-order) address. `process_row_ood_evaluations` closes that gap at ingest:
//! the transcript absorb and the DEEP Horner accumulation stay positional over the advice stream,
//! and only the `adv_pipe` destination is retargeted at segment boundaries.
//!
//! This file pins both halves of that mechanism at PVM scale — ten chiplets, 230 blocks, 22
//! segments — against the checked-in generated hook:
//!
//! - the scatter is *transparent*: the full 16-slot working frame (sponge, pointer, alpha pointer,
//!   Horner accumulator) after a scattered row is bit-identical to the flat row's, and every
//!   eight-felt block lands verbatim at its canonical destination;
//! - the scatter is *dispatched*, not looped: retargeting per segment through `dynexec` costs a
//!   fraction of the obvious per-block `while` loop over the destination pointer. The cycle
//!   assertions below exist so that "simplification" is caught here rather than in a proof-cost
//!   regression.
#![allow(clippy::chunks_exact_to_as_chunks)]

use miden_core::{
    Felt, Word,
    advice::AdviceStack,
    crypto::hash::Eidos,
    field::{BasedVectorSpace, QuadFelt},
};

use super::{
    pvm_layout_const,
    pvm_sigma_scatter::{heights_for_order, structured_orders},
};
use crate::helpers::read_memory_felt;

/// Felts moved by one `adv_pipe`.
const BLOCK_FELTS: u32 = 8;
/// Chiplet instances in `ChipletAir::all()` order.
const NUM_CHIPLETS: usize = 10;

// HARNESS MEMORY MAP
// ================================================================================================

const ALPHA_PTR: u32 = 1_000;
const RESULT_PTR: u32 = 2_000;
const CLK0_PTR: u32 = 2_100;
const CLK1_PTR: u32 = 2_101;
const CLK2_PTR: u32 = 2_102;
const ROW_BASE_PTR: u32 = 2_103;
/// Per-stream-position dispatch table.
const TABLE_PTR: u32 = 2_200;
/// Word-aligned procedure digests reached by `dynexec`.
const DIGEST_PTR: u32 = 2_400;
/// Double-word aligned, as `adv_pipe` requires.
const OOD_BASE: u32 = 16_384;

/// Cycle ceiling for the checked-in hook's two-row ingest.
///
/// Absorbing the row costs three cycles per block, so both rows are 2 x 230 x 3 = 1,380 cycles of
/// unavoidable work; per-segment dispatch adds about 30 cycles to each of the 22 segments, twice
/// (measured: 2,724). Guarding the destination pointer once per block instead would add at least
/// ten cycles to every one of the 460 blocks — the per-block loop measures 3,765 cycles for a
/// single row — landing far above this ceiling. That is the point: this bound is what makes the
/// mechanism, not merely the addresses, a tested property of the generated file.
const MAX_TWO_ROW_INGEST_CYCLES: u64 = 3_200;

const INITIAL_SPONGE: [u64; 12] = [11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22];
const ALPHA: [u64; 2] = [3, 5];
const INITIAL_ACC: [u64; 2] = [7, 9];

// ROW GEOMETRY
// ================================================================================================

/// Aligned per-chiplet widths of one PVM out-of-domain row, in canonical instance order.
///
/// Widths are counted in evaluation slots (one per committed base column, or per auxiliary
/// coordinate); each slot is one extension-field value, hence two felts on the wire.
///
/// `ChipletAir` is not exported from `miden-precompiles-prover`, so these are read back out of the
/// generated hook's own header rather than re-derived here; `pvm_row_geometry_is_the_one_the_hook
/// _was_rendered_from` (in that crate) is what ties the header to the chiplet declarations.
#[derive(Clone, Debug)]
struct RowGeometry {
    preprocessed: Vec<usize>,
    main: Vec<usize>,
    aux: Vec<usize>,
    /// Shared across chiplets: the quotient is one recomposed matrix, not a per-chiplet one.
    quotient: usize,
}

/// One per-chiplet segment of one commitment group, as it appears on the wire.
#[derive(Clone, Copy, Debug)]
struct Segment {
    /// Canonical destination, in felts from the row base.
    dst: u32,
    /// Length in `adv_pipe` blocks.
    blocks: u32,
}

/// One segment plus how the hook reaches it.
#[derive(Clone, Copy, Debug)]
struct Dispatch {
    dst: u32,
    blocks: u32,
    /// Stream position in the runtime dispatch table, or `None` when the segment's place in the
    /// stream is fixed by the geometry rather than by the proof order.
    slot: Option<u32>,
}

const HOOK: &str = include_str!("../../asm/sys/pvm/ood_frames.masm");

/// Reads a rendered `label: a + b + ... = total scalar evaluations` line as its parts.
fn rendered_parts(label: &str) -> Vec<usize> {
    let line = HOOK
        .lines()
        .map(|line| line.trim().trim_start_matches('#').trim())
        .find(|line| line.starts_with(label))
        .unwrap_or_else(|| panic!("the generated hook declares no {label} widths"));
    let rest = line.strip_prefix(label).expect("prefix matched above");
    let parts = rest.split('=').next().expect("split yields at least one part");
    parts
        .split('+')
        .map(|part| {
            part.split_whitespace()
                .next()
                .and_then(|value| value.parse().ok())
                .unwrap_or_else(|| panic!("could not read {label} widths from {line:?}"))
        })
        .collect()
}

impl RowGeometry {
    fn pvm() -> Self {
        Self {
            preprocessed: rendered_parts("preprocessed:"),
            main: rendered_parts("main:"),
            aux: rendered_parts("aux:"),
            quotient: rendered_parts("quotient:")[0],
        }
    }

    fn groups(&self) -> [&Vec<usize>; 3] {
        [&self.preprocessed, &self.main, &self.aux]
    }

    fn row_felts(&self) -> u32 {
        let slots: usize =
            self.groups().iter().map(|g| g.iter().sum::<usize>()).sum::<usize>() + self.quotient;
        (slots * 2) as u32
    }

    /// Felt offset of each commitment group from the row base, in emission order.
    fn group_bases(&self) -> [u32; 4] {
        let mut bases = [0u32; 4];
        let mut acc = 0usize;
        for (i, group) in self.groups().iter().enumerate() {
            bases[i] = (acc * 2) as u32;
            acc += group.iter().sum::<usize>();
        }
        bases[3] = (acc * 2) as u32;
        bases
    }

    /// Canonical felt offsets of each chiplet inside one group, relative to the group base.
    fn canonical_offsets(widths: &[usize]) -> Vec<u32> {
        let mut offsets = Vec::with_capacity(widths.len());
        let mut acc = 0usize;
        for width in widths {
            offsets.push((acc * 2) as u32);
            acc += width;
        }
        offsets
    }

    /// The segment table for one proof order, in wire order, each carrying its canonical
    /// destination.
    ///
    /// `order[p]` is the canonical instance index committed at proof position `p`. Zero-width
    /// segments never reach the wire and are dropped.
    fn segments(&self, order: &[usize]) -> Vec<Segment> {
        let bases = self.group_bases();
        let mut segments = Vec::new();
        for (group_index, widths) in self.groups().iter().enumerate() {
            let offsets = Self::canonical_offsets(widths);
            for &air in order {
                if widths[air] == 0 {
                    continue;
                }
                segments.push(Segment {
                    dst: bases[group_index] + offsets[air],
                    blocks: (widths[air] * 2) as u32 / BLOCK_FELTS,
                });
            }
        }
        segments.push(Segment {
            dst: bases[3],
            blocks: (self.quotient * 2) as u32 / BLOCK_FELTS,
        });
        segments
    }

    /// The same table, annotated with which segments the proof order can move.
    ///
    /// A group holding at most one non-empty segment has no proof-order freedom: whichever chiplet
    /// owns it is always alone on the wire and always lands at the same canonical address.
    fn scatter_plan(&self, order: &[usize]) -> Vec<Dispatch> {
        let bases = self.group_bases();
        let mut plan = Vec::new();
        let mut slot = 0u32;
        for (group_index, widths) in self.groups().iter().enumerate() {
            let offsets = Self::canonical_offsets(widths);
            let occupied = widths.iter().filter(|width| **width > 0).count();
            for &air in order {
                if widths[air] == 0 {
                    continue;
                }
                let dispatch_slot = if occupied > 1 {
                    slot += 1;
                    Some(slot - 1)
                } else {
                    None
                };
                plan.push(Dispatch {
                    dst: bases[group_index] + offsets[air],
                    blocks: (widths[air] * 2) as u32 / BLOCK_FELTS,
                    slot: dispatch_slot,
                });
            }
        }
        plan.push(Dispatch {
            dst: bases[3],
            blocks: (self.quotient * 2) as u32 / BLOCK_FELTS,
            slot: None,
        });
        plan
    }
}

/// Chiplet indices ordered by ascending `(log height, instance index)`, i.e. the proof order.
fn proof_order(heights: &[u64]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..heights.len()).collect();
    order.sort_by_key(|&i| (heights[i], i));
    order
}

/// Height fixtures: the structured proof orders `pvm_sigma_scatter` already sweeps for the sigma
/// scatter, plus a tie the instance order breaks.
fn height_fixtures() -> Vec<Vec<u64>> {
    let mut fixtures: Vec<Vec<u64>> =
        structured_orders().iter().map(|order| heights_for_order(order)).collect();
    fixtures.push(vec![18, 18, 16, 18, 18, 16, 18, 18, 18, 16]);
    fixtures
}

// MASM GENERATION
// ================================================================================================

/// The one absorb the scatter must leave untouched: store, DEEP-fold, transcript-compress.
const ABSORB: &str = "adv_pipe horner_eval_ext compress";

/// Seeds the 16-slot working frame the out-of-domain hook operates on.
fn prologue() -> String {
    let s = INITIAL_SPONGE;
    format!(
        "        push.0.0.{a1}.{a0} push.{ALPHA_PTR} mem_storew_le dropw
        push.{OOD_BASE} mem_store.{ROW_BASE_PTR}
        push.{acc1}.{acc0}.{ALPHA_PTR}.{OOD_BASE}
        push.{c3}.{c2}.{c1}.{c0}
        push.{r1_3}.{r1_2}.{r1_1}.{r1_0}
        push.{r0_3}.{r0_2}.{r0_1}.{r0_0}
",
        a0 = ALPHA[0],
        a1 = ALPHA[1],
        acc0 = INITIAL_ACC[0],
        acc1 = INITIAL_ACC[1],
        r0_0 = s[0],
        r0_1 = s[1],
        r0_2 = s[2],
        r0_3 = s[3],
        r1_0 = s[4],
        r1_1 = s[5],
        r1_2 = s[6],
        r1_3 = s[7],
        c0 = s[8],
        c1 = s[9],
        c2 = s[10],
        c3 = s[11],
    )
}

/// Persists the whole working frame so the flat and scattered runs can be compared slot by slot.
fn epilogue() -> String {
    format!(
        "        push.{r0} mem_storew_le dropw
        push.{r4} mem_storew_le dropw
        push.{r8} mem_storew_le dropw
        push.{r12} mem_store push.{r13} mem_store push.{r14} mem_store push.{r15} mem_store
",
        r0 = RESULT_PTR,
        r4 = RESULT_PTR + 4,
        r8 = RESULT_PTR + 8,
        r12 = RESULT_PTR + 12,
        r13 = RESULT_PTR + 13,
        r14 = RESULT_PTR + 14,
        r15 = RESULT_PTR + 15,
    )
}

/// Restores the monotone row pointer the hook's caller expects in slot 12.
fn pointer_epilogue(row_felts: u32) -> String {
    format!("        mem_load.{ROW_BASE_PTR} add.{row_felts} swap.13 drop\n")
}

fn program(procedures: &str, setup: &str, measured: &str, row_felts: u32) -> String {
    format!(
        "{procedures}
begin
{prologue}{setup}
        clk mem_store.{CLK0_PTR}
{measured}
        clk mem_store.{CLK1_PTR}
{pointer}{epilogue}end",
        prologue = prologue(),
        pointer = pointer_epilogue(row_felts),
        epilogue = epilogue(),
    )
}

/// Baseline: the wire-order ingest, which stores the row exactly as it arrives.
fn flat_source(row_felts: u32) -> String {
    let blocks = row_felts / BLOCK_FELTS;
    program("", "", &format!("        repeat.{blocks} {ABSORB} end"), row_felts)
}

/// The obvious scatter: retarget per segment, then walk each segment block by block, testing the
/// destination pointer against the segment end.
fn while_source(segments: &[Segment], row_felts: u32) -> String {
    let setup = segments
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let dst = OOD_BASE + s.dst;
            let end = dst + BLOCK_FELTS * s.blocks;
            let a = TABLE_PTR + 2 * i as u32;
            format!("        push.{dst} mem_store.{a} push.{end} mem_store.{b}", b = a + 1)
        })
        .collect::<Vec<_>>()
        .join("\n");
    let measured = segments
        .iter()
        .enumerate()
        .map(|(i, _)| {
            let a = TABLE_PTR + 2 * i as u32;
            format!(
                "        mem_load.{a} swap.13 drop
        dup.12 mem_load.{b} neq
        while.true
            {ABSORB}
            dup.12 mem_load.{b} neq
        end",
                b = a + 1
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    program("", &setup, &measured, row_felts)
}

/// The deployed mechanism, exactly as the PVM renderer emits it.
///
/// One `pipe_k` procedure per distinct segment length, dispatched per stream position through a
/// `(row-relative destination, digest address)` table. Groups holding at most one non-empty
/// segment carry no proof-order freedom, so they are emitted with a compile-time destination and
/// a direct `exec` instead of a table entry.
fn production_source(geometry: &RowGeometry, order: &[usize], row_felts: u32) -> String {
    let plan = geometry.scatter_plan(order);
    let mut lengths: Vec<u32> = plan.iter().map(|d| d.blocks).collect();
    lengths.sort_unstable();
    lengths.dedup();
    let digest_address = |blocks: u32| {
        DIGEST_PTR
            + 4 * lengths.iter().position(|k| *k == blocks).expect("length is tabulated") as u32
    };

    let procedures = lengths
        .iter()
        .map(|k| format!("proc pipe_{k}\n    repeat.{k} {ABSORB} end\nend"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut setup = lengths
        .iter()
        .map(|k| {
            format!("        procref.pipe_{k} push.{a} mem_storew_le dropw", a = digest_address(*k))
        })
        .collect::<Vec<_>>();
    // Stands in for the MASM order pass, which derives these two cells per position from the
    // absorbed chiplet heights. The real pass is exercised through the generated hook itself.
    for dispatch in &plan {
        if let Some(slot) = dispatch.slot {
            setup.push(format!(
                "        push.{dst} mem_store.{a} push.{digest} mem_store.{b}",
                dst = dispatch.dst,
                digest = digest_address(dispatch.blocks),
                a = TABLE_PTR + 2 * slot,
                b = TABLE_PTR + 2 * slot + 1,
            ));
        }
    }

    let measured = plan
        .iter()
        .map(|dispatch| match dispatch.slot {
            Some(slot) => format!(
                "        mem_load.{a} mem_load.{ROW_BASE_PTR} add swap.13 drop mem_load.{b} \
                 dynexec",
                a = TABLE_PTR + 2 * slot,
                b = TABLE_PTR + 2 * slot + 1,
            ),
            None => format!(
                "        mem_load.{ROW_BASE_PTR}{offset} swap.13 drop exec.pipe_{k}",
                offset = if dispatch.dst == 0 {
                    String::new()
                } else {
                    format!(" add.{}", dispatch.dst)
                },
                k = dispatch.blocks,
            ),
        })
        .collect::<Vec<_>>()
        .join("\n");

    program(&procedures, &setup.join("\n"), &measured, row_felts)
}

// EXECUTION
// ================================================================================================

struct Run {
    cycles: u64,
    frame: Vec<u64>,
    row: Vec<u64>,
}

fn run(source: &str, wire: &[Felt], row_felts: u32) -> Run {
    let mut advice = AdviceStack::new();
    advice.append_for_adv_pipe(wire);
    let (output, _) = build_test!(source, &[], &advice)
        .execute_for_output()
        .unwrap_or_else(|err| panic!("scatter program must execute: {err}\n{source}"));

    let cycles = read_memory_felt(&output, CLK1_PTR).as_canonical_u64()
        - read_memory_felt(&output, CLK0_PTR).as_canonical_u64();
    let frame = (0..16)
        .map(|i| read_memory_felt(&output, RESULT_PTR + i).as_canonical_u64())
        .collect();
    let row = (0..row_felts)
        .map(|i| read_memory_felt(&output, OOD_BASE + i).as_canonical_u64())
        .collect();
    Run { cycles, frame, row }
}

fn synthetic_row(row_felts: u32) -> Vec<Felt> {
    (0..row_felts).map(|i| Felt::from_u32(17 * i + 23)).collect()
}

/// Every block of the wire stream must appear verbatim at its canonical destination.
fn assert_scattered(flat: &Run, scattered: &Run, segments: &[Segment], label: &str) {
    let mut stream_block = 0u32;
    for segment in segments {
        for b in 0..segment.blocks {
            let src = (BLOCK_FELTS * (stream_block + b)) as usize;
            let dst = (segment.dst + BLOCK_FELTS * b) as usize;
            assert_eq!(
                flat.row[src..src + BLOCK_FELTS as usize],
                scattered.row[dst..dst + BLOCK_FELTS as usize],
                "{label}: wire block {} did not land at felt {dst}",
                stream_block + b
            );
        }
        stream_block += segment.blocks;
    }
    assert_eq!(
        stream_block * BLOCK_FELTS,
        flat.row.len() as u32,
        "{label}: the segment table does not cover the row"
    );
}

// TESTS
// ================================================================================================

/// The header the segment table is read from must agree with the row the hook actually pipes.
///
/// A stale header would give every oracle below the wrong destinations while the hook itself was
/// still self-consistent, so the sweep would compare two different geometries and pass.
#[test]
fn pvm_row_geometry_matches_the_generated_hook() {
    let geometry = RowGeometry::pvm();
    assert_eq!(geometry.main.len(), NUM_CHIPLETS);
    assert_eq!(geometry.aux.len(), NUM_CHIPLETS);
    assert_eq!(geometry.preprocessed.len(), NUM_CHIPLETS);

    let blocks: u32 = HOOK
        .lines()
        .find_map(|line| line.split_once("read as ")?.1.split_whitespace().next()?.parse().ok())
        .expect("the generated hook declares a block count");
    assert_eq!(blocks, geometry.row_felts() / BLOCK_FELTS, "the declared block count is stale");

    let plan = geometry.scatter_plan(&(0..NUM_CHIPLETS).collect::<Vec<_>>());
    assert_eq!(plan.len(), 22, "the PVM row is 22 segments");
    assert_eq!(
        plan.iter().filter(|d| d.slot.is_some()).count(),
        20,
        "main and aux are the order-dependent groups"
    );
    assert_eq!(
        HOOK.matches("\n    dynexec").count(),
        20,
        "the generated hook does not dispatch every order-dependent segment"
    );
}

/// The scatter must be transparent to the transcript, the DEEP accumulator and the row pointer,
/// and must place every wire block at its canonical address, for any proof order.
#[test]
fn scatter_preserves_the_working_frame_and_lands_blocks_canonically() {
    let geometry = RowGeometry::pvm();
    let row_felts = geometry.row_felts();
    let row = synthetic_row(row_felts);
    let flat = run(&flat_source(row_felts), &row, row_felts);

    for heights in height_fixtures() {
        let order = proof_order(&heights);
        let segments = geometry.segments(&order);

        for (label, source) in [
            ("per-block while", while_source(&segments, row_felts)),
            ("dispatched", production_source(&geometry, &order, row_felts)),
        ] {
            let scattered = run(&source, &row, row_felts);
            assert_eq!(
                flat.frame, scattered.frame,
                "{label} scatter perturbed the working frame for order {order:?}"
            );
            assert_scattered(&flat, &scattered, &segments, label);
        }
    }
}

/// The scatter must dispatch per segment, not loop per block.
///
/// `dynexec` on a per-length `pipe_k` procedure keeps the retarget off the hot path; testing the
/// destination pointer once per block does not. Under the Eidos transcript one absorbed block
/// costs three cycles, so a per-block guard is not a small constant on top — it is the dominant
/// term. This test exists so that "simplifying" the dispatch back into a loop fails here.
#[test]
fn dispatched_scatter_stays_far_cheaper_than_a_per_block_loop() {
    let geometry = RowGeometry::pvm();
    let row_felts = geometry.row_felts();
    let row = synthetic_row(row_felts);
    let order = proof_order(&[20, 17, 14, 16, 11, 21, 13, 18, 12, 15]);
    let segments = geometry.segments(&order);
    let plan = geometry.scatter_plan(&order);
    let mut lengths: Vec<u32> = plan.iter().map(|dispatch| dispatch.blocks).collect();
    lengths.sort_unstable();
    lengths.dedup();

    let flat = run(&flat_source(row_felts), &row, row_felts).cycles;
    let looped = run(&while_source(&segments, row_felts), &row, row_felts).cycles;
    let dispatched = run(&production_source(&geometry, &order, row_felts), &row, row_felts).cycles;

    let dispatched_slots = plan.iter().filter(|dispatch| dispatch.slot.is_some()).count();
    println!(
        "PVM out-of-domain row: {NUM_CHIPLETS} chiplets, {} blocks, {} segments \
         ({dispatched_slots} order-dependent), {} distinct segment lengths {lengths:?}",
        row_felts / BLOCK_FELTS,
        plan.len(),
        lengths.len(),
    );
    for (label, cycles) in [
        ("flat, no scatter ", flat),
        ("per-block while  ", looped),
        ("dispatched       ", dispatched),
    ] {
        println!(
            "  {label}: {cycles:6} cycles ({:+.1}% vs flat, {:+} per segment)",
            100.0 * (cycles as f64 - flat as f64) / flat as f64,
            (cycles as i64 - flat as i64) / plan.len() as i64,
        );
    }

    assert!(
        looped - flat >= 3 * (dispatched - flat),
        "the per-block loop ({looped}) is no longer materially worse than dispatch \
         ({dispatched}); if the scatter has been rewritten as a loop, revert it"
    );
    assert!(
        (dispatched - flat) / plan.len() as u64 <= 30,
        "the scatter costs {} cycles per segment, well past the dispatch mechanism's \
         ~20 (flat {flat}, dispatched {dispatched})",
        (dispatched - flat) / plan.len() as u64
    );
}

// GENERATED HOOK
// ================================================================================================

/// Drives the checked-in `sys/pvm/ood_frames.masm` end to end: stage the table from the chiplet
/// heights, then ingest both out-of-domain rows exactly as the generic verifier does.
fn generated_hook_source(heights: &[u64], ood_ptr: u32) -> String {
    let s = INITIAL_SPONGE;
    let stores = heights
        .iter()
        .enumerate()
        .map(|(air, height)| {
            let offset = if air == 0 { String::new() } else { format!(" add.{air}") };
            format!(
                "        push.{height} exec.constants::air_trace_length_logs_ptr{offset} mem_store"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "use miden::core::stark::constants
use miden::core::sys::pvm
use miden::core::sys::pvm::ood_frames

begin
{stores}
        clk mem_store.{CLK0_PTR}
        exec.pvm::stage_proof_order_positions
        exec.ood_frames::stage_ood_scatter_table
        clk mem_store.{CLK2_PTR}

        push.0.0.{a1}.{a0} push.{ALPHA_PTR} mem_storew_le dropw
        push.{acc1}.{acc0}.{ALPHA_PTR}.{ood_ptr}
        push.{c3}.{c2}.{c1}.{c0}
        push.{r1_3}.{r1_2}.{r1_1}.{r1_0}
        push.{r0_3}.{r0_2}.{r0_1}.{r0_0}
        exec.ood_frames::process_row_ood_evaluations
        exec.ood_frames::process_row_ood_evaluations
        clk mem_store.{CLK1_PTR}
{epilogue}end",
        a0 = ALPHA[0],
        a1 = ALPHA[1],
        acc0 = INITIAL_ACC[0],
        acc1 = INITIAL_ACC[1],
        r0_0 = s[0],
        r0_1 = s[1],
        r0_2 = s[2],
        r0_3 = s[3],
        r1_0 = s[4],
        r1_1 = s[5],
        r1_2 = s[6],
        r1_3 = s[7],
        c0 = s[8],
        c1 = s[9],
        c2 = s[10],
        c3 = s[11],
        epilogue = epilogue(),
    )
}

/// The out-of-domain frame the wire stream must produce, laid out canonically.
fn expected_frame_memory(geometry: &RowGeometry, order: &[usize], wire: &[Felt]) -> Vec<u64> {
    let row_felts = geometry.row_felts() as usize;
    let mut expected = vec![u64::MAX; 2 * row_felts];
    let mut consumed = 0usize;
    for row in 0..2 {
        for segment in geometry.segments(order) {
            let len = (segment.blocks * BLOCK_FELTS) as usize;
            let dst = row * row_felts + segment.dst as usize;
            for i in 0..len {
                expected[dst + i] = wire[consumed + i].as_canonical_u64();
            }
            consumed += len;
        }
    }
    assert_eq!(consumed, wire.len(), "the segment table does not cover both rows");
    expected
}

/// The checked-in hook must land every chiplet's segment at its canonical address for both rows,
/// while leaving the transcript, the DEEP accumulator and the monotone row pointer exactly where a
/// flat wire-order ingest would.
///
/// The oracles are computed in Rust from the wire stream, so this does not merely compare the hook
/// against another MASM rendering of the same idea.
#[test]
fn generated_hook_scatters_both_rows_to_canonical_addresses() {
    let geometry = RowGeometry::pvm();
    let row_felts = geometry.row_felts();
    let wire = synthetic_row(2 * row_felts);
    let ood_ptr = pvm_layout_const("PREPROCESSED_CURRENT_PTR");

    let alpha = QuadFelt::new(ALPHA.map(Felt::new_unchecked));
    let expected_acc = wire
        .as_chunks::<2>()
        .0
        .iter()
        .map(|coordinates| QuadFelt::new([coordinates[0], coordinates[1]]))
        .fold(QuadFelt::new(INITIAL_ACC.map(Felt::new_unchecked)), |acc, coefficient| {
            coefficient + alpha * acc
        });
    let expected_acc: &[Felt] = expected_acc.as_basis_coefficients_slice();
    let initial_cv: [u64; 4] = INITIAL_SPONGE[8..].try_into().expect("four-felt chaining word");
    let expected_cv = wire
        .as_chunks::<8>()
        .0
        .iter()
        .fold(Word::new(initial_cv.map(Felt::new_unchecked)), |cv, block| {
            Eidos::compress(cv, *block)
        });

    let identity: Vec<usize> = (0..NUM_CHIPLETS).collect();
    for heights in height_fixtures() {
        let order = proof_order(&heights);
        let mut advice = AdviceStack::new();
        advice.append_for_adv_pipe(&wire);
        let (output, _) = build_test!(generated_hook_source(&heights, ood_ptr), &[], &advice)
            .execute_for_output()
            .expect("the generated out-of-domain hook must execute");

        let expected = expected_frame_memory(&geometry, &order, &wire);
        // Guards against a vacuous fixture: a proof order that moves nothing would pass every
        // assertion below even if the hook ignored the table entirely.
        let wire_order: Vec<u64> = wire.iter().map(Felt::as_canonical_u64).collect();
        if order == identity {
            assert_eq!(expected, wire_order, "the identity order must store the row flat");
        } else {
            assert_ne!(expected, wire_order, "fixture {heights:?} does not move any segment");
        }

        for (i, expected) in expected.iter().enumerate() {
            assert_eq!(
                read_memory_felt(&output, ood_ptr + i as u32).as_canonical_u64(),
                *expected,
                "felt {i} of the out-of-domain frame is wrong for heights {heights:?} \
                 (proof order {order:?})"
            );
        }

        assert_eq!(
            read_memory_felt(&output, RESULT_PTR + 12),
            Felt::from_u32(ood_ptr + 2 * row_felts),
            "the row pointer did not advance by exactly two rows"
        );
        assert_eq!(
            read_memory_felt(&output, RESULT_PTR + 13),
            Felt::from_u32(ALPHA_PTR),
            "the DEEP alpha pointer was disturbed"
        );
        for (i, expected) in expected_acc.iter().enumerate() {
            assert_eq!(
                read_memory_felt(&output, RESULT_PTR + 14 + i as u32),
                *expected,
                "the DEEP Horner accumulator diverged at coordinate {i}"
            );
        }
        for (i, expected) in expected_cv.iter().enumerate() {
            assert_eq!(
                read_memory_felt(&output, RESULT_PTR + 8 + i as u32),
                *expected,
                "the Eidos transcript chaining word diverged at limb {i}"
            );
        }

        let staged = read_memory_felt(&output, CLK2_PTR).as_canonical_u64()
            - read_memory_felt(&output, CLK0_PTR).as_canonical_u64();
        let ingested = read_memory_felt(&output, CLK1_PTR).as_canonical_u64()
            - read_memory_felt(&output, CLK2_PTR).as_canonical_u64();
        assert!(
            ingested <= MAX_TWO_ROW_INGEST_CYCLES,
            "the generated hook took {ingested} cycles to ingest both rows, past the \
             {MAX_TWO_ROW_INGEST_CYCLES} a per-segment dispatch can cost"
        );
        println!(
            "heights {heights:?} -> proof order {order:?}: {staged} cycles staging the table, \
             {ingested} ingesting both rows"
        );
    }
}
