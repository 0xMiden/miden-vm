//! Test support for inspecting and directly materializing Eidos transcript traces.

use miden_core::{Felt, utils::RowMajorMatrix};

use super::{AbsorptionId, EidosRequires, generate_trace_with_byte_lookups};
use crate::primitives::byte_pair_lut::BytePairLutRequires;

/// Constructs a physical absorption ID without allocating it through [`EidosRequires`].
pub(crate) fn forged_absorption_id(absorption_id: u32) -> AbsorptionId {
    AbsorptionId(absorption_id)
}

/// Returns the number of physical compressions allocated by `requires`.
pub(crate) fn total_cycles(requires: &EidosRequires) -> u32 {
    requires.next_seq
}

/// Materializes an Eidos trace while discarding its byte-pair lookup requirements.
pub(crate) fn generate_trace(requires: EidosRequires) -> RowMajorMatrix<Felt> {
    generate_trace_with_byte_lookups(requires, &mut BytePairLutRequires::new())
}

/// Deterministic compression cycles with distinct blocks, chaining values, and metadata.
fn synthetic_cycles(count: usize) -> alloc::vec::Vec<super::CompressionCycle> {
    use miden_core::{Word, field::PrimeCharacteristicRing};

    (0..count)
        .map(|cycle| super::CompressionCycle {
            in_mult: (cycle as u32 % 5) + 1,
            out_mult: cycle as u32 % 3,
            is_continuation: cycle % 2 == 1,
            chain_head_id: (cycle / 3) as u32,
            block: core::array::from_fn(|idx| {
                Felt::from_u32((cycle as u32) ^ (idx as u32).wrapping_mul(0x0102_0304))
            }),
            cv_in: Word::new(core::array::from_fn(|idx| {
                Felt::from_u32((cycle as u32).rotate_left(idx as u32))
            })),
        })
        .collect()
}

#[test]
fn compression_trace_matches_regenerated_cycles() {
    use alloc::vec;

    use miden_core::field::PrimeCharacteristicRing;

    use super::{
        EIDOS_COMPRESSION_CYCLE_LEN, NUM_EIDOS_COMPRESSION_COLS, build_eidos_compression_trace,
        fill_compression_cycles_sequential,
    };
    use crate::primitives::byte_pair_lut::{
        BytePairOp, generate_trace as generate_byte_pair_trace,
    };

    // Cover empty input, no padding, one padding cycle, both sides of the template threshold
    // (127 and 128 padding cycles), and parallel real-cycle filling when multiple threads exist.
    for real_cycles in [0usize, 1, 3, 129, 384, 513] {
        let cycles = synthetic_cycles(real_cycles);
        let physical_cycles = (real_cycles * EIDOS_COMPRESSION_CYCLE_LEN)
            .next_power_of_two()
            .max(EIDOS_COMPRESSION_CYCLE_LEN)
            / EIDOS_COMPRESSION_CYCLE_LEN;
        let height = physical_cycles * EIDOS_COMPRESSION_CYCLE_LEN;
        let mut expected_rows = vec![[Felt::ZERO; NUM_EIDOS_COMPRESSION_COLS]; height];
        let mut expected_lookups = BytePairLutRequires::new();
        let mut actual_lookups = BytePairLutRequires::new();
        for lookups in [&mut expected_lookups, &mut actual_lookups] {
            lookups.require(BytePairOp::Xor, 0x12, 0x34);
            lookups.require_range16(0x5678);
        }

        fill_compression_cycles_sequential(&cycles, &mut expected_rows, &mut expected_lookups);
        let trace = build_eidos_compression_trace(&cycles, height, &mut actual_lookups);

        assert_eq!(trace.values, expected_rows.as_flattened(), "{real_cycles} real cycles");
        assert_eq!(
            generate_byte_pair_trace(actual_lookups).values,
            generate_byte_pair_trace(expected_lookups).values,
            "{real_cycles} real cycles"
        );
    }
}

#[test]
fn padding_copies_match_regenerated_cycles() {
    use alloc::vec;

    use miden_core::field::PrimeCharacteristicRing;

    use super::{
        EIDOS_COMPRESSION_CYCLE_LEN, NUM_EIDOS_COMPRESSION_COLS, fill_padding_cycles,
        write_compression_cycle,
    };
    use crate::primitives::byte_pair_lut::{
        BytePairOp, generate_trace as generate_byte_pair_trace,
    };

    // One template plus 1024 copies allows two parallel splits of at least 512 cycles each.
    // Starting after real cycles checks that retagging preserves the physical cycle numbering.
    const REAL_CYCLES: usize = 3071;
    const PADDING_CYCLES: usize = 1025;
    let mut expected_rows = vec![
        [Felt::ZERO; NUM_EIDOS_COMPRESSION_COLS];
        PADDING_CYCLES * EIDOS_COMPRESSION_CYCLE_LEN
    ];
    let mut actual_rows = expected_rows.clone();
    let mut expected_lookups = BytePairLutRequires::new();
    let mut actual_lookups = BytePairLutRequires::new();
    for lookups in [&mut expected_lookups, &mut actual_lookups] {
        lookups.require(BytePairOp::Xor, 0, 0);
        lookups.require_range16(0);
    }

    for (offset, rows) in expected_rows.chunks_mut(EIDOS_COMPRESSION_CYCLE_LEN).enumerate() {
        write_compression_cycle(None, REAL_CYCLES + offset, rows, &mut expected_lookups);
    }
    fill_padding_cycles(REAL_CYCLES, &mut actual_rows, &mut actual_lookups);

    assert_eq!(actual_rows, expected_rows);
    assert_eq!(
        generate_byte_pair_trace(actual_lookups).values,
        generate_byte_pair_trace(expected_lookups).values,
    );
}

#[cfg(feature = "concurrent")]
#[test]
fn parallel_cycle_fill_matches_sequential_trace_and_lookups() {
    use alloc::vec;

    use miden_core::field::PrimeCharacteristicRing;

    use super::{
        EIDOS_COMPRESSION_CYCLE_LEN, NUM_EIDOS_COMPRESSION_COLS, fill_compression_cycles_parallel,
        fill_compression_cycles_sequential,
    };
    use crate::primitives::byte_pair_lut::{
        BytePairOp, generate_trace as generate_byte_pair_trace,
    };

    // Exercise both the final partial parallel chunk and zero-filled padding cycles.
    const PHYSICAL_CYCLES: usize = 513;
    const REAL_CYCLES: usize = 509;
    let cycles = synthetic_cycles(REAL_CYCLES);
    let row_count = PHYSICAL_CYCLES * EIDOS_COMPRESSION_CYCLE_LEN;
    let mut sequential_rows = vec![[Felt::ZERO; NUM_EIDOS_COMPRESSION_COLS]; row_count];
    let mut parallel_rows = sequential_rows.clone();
    let mut sequential_lookups = BytePairLutRequires::new();
    let mut parallel_lookups = BytePairLutRequires::new();
    for lookups in [&mut sequential_lookups, &mut parallel_lookups] {
        lookups.require(BytePairOp::Xor, 0x12, 0x34);
        lookups.require_range16(0x5678);
    }

    fill_compression_cycles_sequential(&cycles, &mut sequential_rows, &mut sequential_lookups);
    fill_compression_cycles_parallel(&cycles, &mut parallel_rows, &mut parallel_lookups);

    assert_eq!(parallel_rows, sequential_rows);
    assert_eq!(
        generate_byte_pair_trace(parallel_lookups).values,
        generate_byte_pair_trace(sequential_lookups).values,
    );
}
