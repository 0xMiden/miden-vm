use alloc::vec::Vec;

use miden_core::{WORD_SIZE, field::PrimeCharacteristicRing};

use super::{ChipletTraceFragment, Felt, KERNEL_ROM_TRACE_WIDTH, KernelDescriptor, KernelRom};
use crate::{ONE, ZERO};

// CONSTANTS
// ================================================================================================

const PROC1_HASH: [Felt; WORD_SIZE] = [ONE, ZERO, ONE, ZERO];
const PROC2_HASH: [Felt; WORD_SIZE] = [ONE, ONE, ONE, ONE];

// TESTS
// ================================================================================================

#[test]
fn kernel_rom_invalid_access() {
    let kernel = build_kernel();
    let mut rom = KernelRom::new(kernel);

    // accessing procedure which is in the kernel should be fine
    assert!(rom.access_proc(PROC1_HASH.into()).is_ok());

    // accessing procedure which is not in the kernel should return an error
    assert!(rom.access_proc([ZERO, ONE, ZERO, ONE].into()).is_err());
}

#[test]
fn kernel_rom_no_access() {
    let rom = KernelRom::new(build_kernel());
    assert_eq!(rom.trace_len(), 0);
}

#[test]
fn kernel_rom_with_access() {
    // 5 accesses: 3 for proc1, 2 for proc2 -> multiplicities (3, 2).
    let kernel = build_kernel();
    let mut rom = KernelRom::new(kernel);

    rom.access_proc(PROC1_HASH.into()).unwrap();
    rom.access_proc(PROC2_HASH.into()).unwrap();
    rom.access_proc(PROC1_HASH.into()).unwrap();
    rom.access_proc(PROC1_HASH.into()).unwrap();
    rom.access_proc(PROC2_HASH.into()).unwrap();

    let expected_trace_len = 2;
    assert_eq!(expected_trace_len, rom.trace_len());

    let trace = build_trace(rom, expected_trace_len);

    assert_row(&trace, 0, Felt::from_u64(3), PROC1_HASH);
    assert_row(&trace, 1, Felt::from_u64(2), PROC2_HASH);
}

#[test]
fn kernel_rom_with_single_access() {
    // Mixed: proc1 accessed twice, proc2 never -> multiplicities (2, 0).
    let kernel = build_kernel();
    let mut rom = KernelRom::new(kernel);

    rom.access_proc(PROC1_HASH.into()).unwrap();
    rom.access_proc(PROC1_HASH.into()).unwrap();

    let expected_trace_len = 1;
    assert_eq!(expected_trace_len, rom.trace_len());

    let trace = build_trace(rom, expected_trace_len);

    assert_row(&trace, 0, Felt::from_u64(2), PROC1_HASH);
}

#[test]
fn unused_exports_keep_canonical_leaf_indices() {
    let mut rom = KernelRom::new(build_kernel());
    rom.access_proc(PROC2_HASH.into()).unwrap();
    let trace = build_trace(rom, 1);
    assert_row(&trace, 0, ONE, PROC2_HASH);
    assert_eq!(trace[6][0], ONE);
    assert_eq!(trace[7][0], ONE);
}

#[test]
fn kernel_membership_rows_count_toward_both_hasher_limits() {
    let tree = build_kernel().to_merkle_tree();
    let mut baseline = KernelRom::new(build_kernel());
    baseline.access_proc(PROC1_HASH.into()).unwrap();
    let mut hasher = super::super::Hasher::default();
    baseline.authenticate(&mut hasher, &tree, usize::MAX, usize::MAX).unwrap();
    let controller_rows = hasher.trace_len();
    let compression_rows = hasher.eidos_compression_trace_len();
    for (controller_limit, compression_limit) in
        [(controller_rows - 1, compression_rows), (controller_rows, compression_rows - 1)]
    {
        let mut rom = KernelRom::new(build_kernel());
        rom.access_proc(PROC1_HASH.into()).unwrap();
        let mut hasher = super::super::Hasher::default();
        assert!(
            rom.authenticate(&mut hasher, &tree, controller_limit, compression_limit)
                .is_err()
        );
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Creates a kernel with two dummy procedures
fn build_kernel() -> KernelDescriptor {
    KernelDescriptor::new(&[PROC1_HASH.into(), PROC2_HASH.into()]).unwrap()
}

/// Builds a trace of the specified length and fills it with data from the provided KernelRom
/// instance.
fn build_trace(mut kernel_rom: KernelRom, num_rows: usize) -> Vec<Vec<Felt>> {
    let tree = kernel_rom.kernel().to_merkle_tree();
    let mut hasher = super::super::Hasher::default();
    kernel_rom.authenticate(&mut hasher, &tree, usize::MAX, usize::MAX).unwrap();
    let mut band = Felt::zero_vec(KERNEL_ROM_TRACE_WIDTH * num_rows);
    let mut fragment = ChipletTraceFragment::row_major(
        &mut band,
        KERNEL_ROM_TRACE_WIDTH,
        0,
        KERNEL_ROM_TRACE_WIDTH,
    );
    kernel_rom.fill_trace(&mut fragment);

    (0..KERNEL_ROM_TRACE_WIDTH)
        .map(|c| (0..num_rows).map(|r| band[r * KERNEL_ROM_TRACE_WIDTH + c]).collect())
        .collect()
}

/// Asserts that row `row` carries the given multiplicity and procedure digest.
fn assert_row(trace: &[Vec<Felt>], row: usize, multiplicity: Felt, digest: [Felt; WORD_SIZE]) {
    assert_eq!(trace[0][row], multiplicity, "multiplicity mismatch at row {row}");
    assert_eq!(trace[1][row], digest[0], "digest[0] mismatch at row {row}");
    assert_eq!(trace[2][row], digest[1], "digest[1] mismatch at row {row}");
    assert_eq!(trace[3][row], digest[2], "digest[2] mismatch at row {row}");
    assert_eq!(trace[4][row], digest[3], "digest[3] mismatch at row {row}");
}
