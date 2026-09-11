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

#[cfg(feature = "concurrent")]
#[test]
fn parallel_cycle_fill_matches_sequential_trace_and_lookups() {
    use alloc::{vec, vec::Vec};

    use miden_core::Word;

    use super::{
        CompressionCycle, EIDOS_COMPRESSION_CYCLE_LEN, NUM_EIDOS_COMPRESSION_COLS,
        fill_compression_cycles_parallel, fill_compression_cycles_sequential,
    };
    use crate::primitives::byte_pair_lut::{
        BytePairOp, generate_trace as generate_byte_pair_trace,
    };

    // Exercise both the final partial parallel chunk and zero-filled padding cycles.
    const PHYSICAL_CYCLES: usize = 513;
    const REAL_CYCLES: usize = 509;
    let cycles: Vec<_> = (0..REAL_CYCLES)
        .map(|cycle| CompressionCycle {
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
        .collect();
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
