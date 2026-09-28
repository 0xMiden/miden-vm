//! Fixed sixteen-word schedule for one SHA-512 block's IO.
//!
//! Each row represents eight bytes. Rows 0..8 also carry the eight state words, and rows
//! 14 and 15 hold the final block's 128-bit length suffix. Every four rows form an Eidos chunk;
//! its lookup is emitted on the third row so the AIR can read the fourth row through `next`.

use alloc::vec::Vec;

use miden_core::Felt;

pub const IO_PERIOD: usize = 16;
pub const NUM_PERIODIC_COLS: usize = 13;
pub const P_IDX: usize = 0;
pub const P_FIRST: usize = 1;
pub const P_LAST: usize = 2;
pub const P_AT14: usize = 3;
pub const P_CHUNK_FIRST: usize = 4;
pub const P_CHUNK_LAST: usize = 5;
/// Third row of a four-row chunk, which emits the chunk's Eidos block.
pub const P_CHUNK_EMIT: usize = 6;
/// Second row of a four-row chunk, which forwards the chunk's first row.
pub const P_CHUNK_SECOND: usize = 7;
pub const P_STATE: usize = 8;
/// Selects the first or second 32-byte digest chunk; used only on digest rows 0..8.
pub const P_DIGEST_CYCLE_OFFSET: usize = 9;
pub const P_IV_LO: usize = 10;
pub const P_IV_HI: usize = 11;
pub const P_DIGEST_NEXT: usize = 12;

/// SHA-512 initial state, in FIPS 180-4 word order.
pub const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// Build row selectors and IV halves shared by the standalone and multiplexed IO layouts.
/// These columns repeat every sixteen rows; invocation-specific flags remain witness columns.
pub fn io_program() -> [Vec<Felt>; NUM_PERIODIC_COLS] {
    let mut columns = core::array::from_fn(|_| Vec::with_capacity(IO_PERIOD));
    for i in 0..IO_PERIOD {
        let iv = IV.get(i).copied().unwrap_or(0);
        let row = [
            i as u32,
            (i == 0) as u32,
            (i == 15) as u32,
            (i == 14) as u32,
            (i % 4 == 0) as u32,
            (i % 4 == 3) as u32,
            (i % 4 == 2) as u32,
            (i % 4 == 1) as u32,
            (i < 8) as u32,
            (i >= 4) as u32,
            iv as u32,
            (iv >> 32) as u32,
            (i < 7) as u32,
        ];
        for (column, value) in columns.iter_mut().zip(row) {
            column.push(Felt::from_u32(value));
        }
    }
    columns
}
