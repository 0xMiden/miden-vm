use alloc::vec::Vec;

use miden_core::{WORD_SIZE, field::PrimeCharacteristicRing};

use super::{Felt, Kernel, KernelRom, TRACE_WIDTH, TraceFragment};
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
    // Each declared procedure gets one row with multiplicity 0 when never called; the INIT
    // side of the chiplets bus still matches the public-input-injected remove.
    let kernel = build_kernel();
    let rom = KernelRom::new(kernel);

    let expected_trace_len = 2;
    assert_eq!(expected_trace_len, rom.trace_len());

    let trace = build_trace(rom, expected_trace_len);

    assert_row(&trace, 0, ZERO, PROC1_HASH);
    assert_row(&trace, 1, ZERO, PROC2_HASH);
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

    let expected_trace_len = 2;
    assert_eq!(expected_trace_len, rom.trace_len());

    let trace = build_trace(rom, expected_trace_len);

    assert_row(&trace, 0, Felt::from_u64(2), PROC1_HASH);
    assert_row(&trace, 1, ZERO, PROC2_HASH);
}

// HELPER FUNCTIONS
// ================================================================================================

/// Creates a kernel with two dummy procedures
fn build_kernel() -> Kernel {
    Kernel::new(&[PROC1_HASH.into(), PROC2_HASH.into()]).unwrap()
}

/// Builds a trace of the specified length and fills it with data from the provided KernelRom
/// instance.
fn build_trace(kernel_rom: KernelRom, num_rows: usize) -> Vec<Vec<Felt>> {
    let mut trace = (0..TRACE_WIDTH).map(|_| vec![ZERO; num_rows]).collect::<Vec<_>>();
    let mut fragment = TraceFragment::trace_to_fragment(&mut trace);
    kernel_rom.fill_trace(&mut fragment);

    trace
}

/// Asserts that row `row` carries the given multiplicity and procedure digest.
fn assert_row(trace: &[Vec<Felt>], row: usize, multiplicity: Felt, digest: [Felt; WORD_SIZE]) {
    assert_eq!(trace[0][row], multiplicity, "multiplicity mismatch at row {row}");
    assert_eq!(trace[1][row], digest[0], "digest[0] mismatch at row {row}");
    assert_eq!(trace[2][row], digest[1], "digest[1] mismatch at row {row}");
    assert_eq!(trace[3][row], digest[2], "digest[2] mismatch at row {row}");
    assert_eq!(trace[4][row], digest[3], "digest[3] mismatch at row {row}");
}
