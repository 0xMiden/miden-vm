//! Fixed eight-row schedule for one SHA-256 block's IO.

use alloc::vec::Vec;

use miden_core::Felt;

pub const IO_PERIOD: usize = 8;
pub const NUM_PERIODIC_COLS: usize = 11;
pub const P_IDX: usize = 0;
pub const P_FIRST: usize = 1;
pub const P_LAST: usize = 2;
pub const P_CHUNK_FIRST: usize = 3;
pub const P_CHUNK_LAST: usize = 4;
/// Third row of a four-row chunk, which emits the chunk's Eidos block.
pub const P_CHUNK_EMIT: usize = 5;
/// Second row of a four-row chunk, which forwards the chunk's first row.
pub const P_CHUNK_SECOND: usize = 6;
pub const P_STATE: usize = 7;
/// `IV[2i + 1]` on state row `i`.
pub const P_IV_LO: usize = 8;
/// `IV[2i]` on state row `i`.
pub const P_IV_HI: usize = 9;
pub const P_DIGEST_NEXT: usize = 10;

/// SHA-256 initial state, in FIPS 180-4 word order.
pub const IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

pub fn io_program() -> [Vec<Felt>; NUM_PERIODIC_COLS] {
    let mut columns = core::array::from_fn(|_| Vec::with_capacity(IO_PERIOD));
    for i in 0..IO_PERIOD {
        let [iv_hi, iv_lo] = if i < 4 { [IV[2 * i], IV[2 * i + 1]] } else { [0, 0] };
        let row = [
            i as u32,
            (i == 0) as u32,
            (i == 7) as u32,
            (i % 4 == 0) as u32,
            (i % 4 == 3) as u32,
            (i % 4 == 2) as u32,
            (i % 4 == 1) as u32,
            (i < 4) as u32,
            iv_lo,
            iv_hi,
            (i < 3) as u32,
        ];
        for (column, value) in columns.iter_mut().zip(row) {
            column.push(Felt::from_u32(value));
        }
    }
    columns
}
