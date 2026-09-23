//! Checks the generated OOD ingest hook's canonical memory layout, transcript state,
//! DEEP accumulator, pointer updates, and two-row ingest cycle budget.

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
const NUM_CHIPLETS: usize = miden_precompiles_air::NUM_CHIPLETS;

// HARNESS MEMORY MAP
// ================================================================================================

const ALPHA_PTR: u32 = 1_000;
const RESULT_PTR: u32 = 2_000;
const CLK0_PTR: u32 = 2_100;
const CLK1_PTR: u32 = 2_101;
const CLK2_PTR: u32 = 2_102;

/// Upper bound for ingesting both OOD rows, excluding proof-order and scatter-table staging.
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
/// This benchmark reads the widths from the checked-in generated hook's header. The verifier-side
/// `pvm_row_geometry_is_the_one_the_hook_was_rendered_from` test ties that header to the
/// [`miden_precompiles_air::ChipletAir`] declarations.
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
    fixtures.push(vec![18, 18, 16, 18, 18, 16, 18, 18, 18, 16, 18, 16]);
    fixtures
}

// MASM GENERATION
// ================================================================================================

/// Persists the whole working frame for comparison with the Rust reference.
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

fn synthetic_row(row_felts: u32) -> Vec<Felt> {
    (0..row_felts).map(|i| Felt::from_u32(17 * i + 23)).collect()
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
}

// GENERATED HOOK
// ================================================================================================

/// Stages the proof-order maps and scatter table, then calls the generated hook for both rows.
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
use miden::core::sys::pvm::ood_frames

begin
{stores}
        clk mem_store.{CLK0_PTR}
        exec.ood_frames::stage_proof_order_maps
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

/// Checks both scattered rows and the working frame against Rust wire-order references.
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
        // Every non-identity fixture must distinguish scattering from a flat wire-order write.
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

        // Compression updates the chaining word and preserves the last absorbed rate block.
        for (i, expected) in wire[wire.len() - 8..].iter().enumerate() {
            assert_eq!(
                read_memory_felt(&output, RESULT_PTR + i as u32),
                *expected,
                "the last absorbed rate block changed at limb {i}"
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
