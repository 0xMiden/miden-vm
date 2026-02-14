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
    let kernel = build_kernel();
    let rom = KernelRom::new(kernel);

    let expected_trace_len = 2;
    assert_eq!(expected_trace_len, rom.trace_len());

    // generate trace
    let trace = build_trace(rom, expected_trace_len);

    // the first row of the trace should correspond to the first procedure
    let row = 0;

    assert_eq!(trace[0][row], ONE); // s0
    assert_eq!(trace[1][row], PROC1_HASH[0]);
    assert_eq!(trace[2][row], PROC1_HASH[1]);
    assert_eq!(trace[3][row], PROC1_HASH[2]);
    assert_eq!(trace[4][row], PROC1_HASH[3]);

    // the second row of the trace should correspond to the second procedure
    let row = 1;

    assert_eq!(trace[0][row], ONE); // s0
    assert_eq!(trace[1][row], PROC2_HASH[0]);
    assert_eq!(trace[2][row], PROC2_HASH[1]);
    assert_eq!(trace[3][row], PROC2_HASH[2]);
    assert_eq!(trace[4][row], PROC2_HASH[3]);
}

#[test]
#[expect(clippy::needless_range_loop)]
fn kernel_rom_with_access() {
    let kernel = build_kernel();
    let mut rom = KernelRom::new(kernel);

    // generate 5 access: 3 for proc1 and 2 for proc2
    rom.access_proc(PROC1_HASH.into()).unwrap();
    rom.access_proc(PROC2_HASH.into()).unwrap();
    rom.access_proc(PROC1_HASH.into()).unwrap();
    rom.access_proc(PROC1_HASH.into()).unwrap();
    rom.access_proc(PROC2_HASH.into()).unwrap();

    let expected_trace_len = 7;
    assert_eq!(expected_trace_len, rom.trace_len());

    // generate trace
    let trace = build_trace(rom, expected_trace_len);

    // the first 5 rows of the trace should correspond to the first procedure
    for row in 0..4 {
        let s_first = row == 0;

        assert_eq!(trace[0][row], Felt::from_bool(s_first)); // s_first
        assert_eq!(trace[1][row], PROC1_HASH[0]);
        assert_eq!(trace[2][row], PROC1_HASH[1]);
        assert_eq!(trace[3][row], PROC1_HASH[2]);
        assert_eq!(trace[4][row], PROC1_HASH[3]);
    }

    // the remaining 2 rows of the trace should correspond to the second procedure
    for row in 4..7 {
        let s_first = row == 4;

        assert_eq!(trace[0][row], Felt::from_bool(s_first)); // s_first
        assert_eq!(trace[1][row], PROC2_HASH[0]);
        assert_eq!(trace[2][row], PROC2_HASH[1]);
        assert_eq!(trace[3][row], PROC2_HASH[2]);
        assert_eq!(trace[4][row], PROC2_HASH[3]);
    }
}

#[test]
#[expect(clippy::needless_range_loop)]
fn kernel_rom_with_single_access() {
    let kernel = build_kernel();
    let mut rom = KernelRom::new(kernel);

    // generate 2 access for proc1
    rom.access_proc(PROC1_HASH.into()).unwrap();
    rom.access_proc(PROC1_HASH.into()).unwrap();

    let expected_trace_len = 4;
    assert_eq!(expected_trace_len, rom.trace_len());

    // generate trace
    let trace = build_trace(rom, expected_trace_len);

    // the first 3 rows of the trace should correspond to the first procedure
    for row in 0..3 {
        let s_first = row == 0;

        assert_eq!(trace[0][row], Felt::from_bool(s_first)); // s_first
        assert_eq!(trace[1][row], PROC1_HASH[0]);
        assert_eq!(trace[2][row], PROC1_HASH[1]);
        assert_eq!(trace[3][row], PROC1_HASH[2]);
        assert_eq!(trace[4][row], PROC1_HASH[3]);
    }

    // the last row of the trace should correspond to the second procedure
    let row = 3;
    assert_eq!(trace[0][row], Felt::from_bool(true)); // s_first
    assert_eq!(trace[1][row], PROC2_HASH[0]);
    assert_eq!(trace[2][row], PROC2_HASH[1]);
    assert_eq!(trace[3][row], PROC2_HASH[2]);
    assert_eq!(trace[4][row], PROC2_HASH[3]);
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
