//! Sixty-four-row schedule for one SHA-512 block's IO.
//!
//! Rows 0..16 carry raw input, 16..24 carry chaining state, 24..32 carry the final digest,
//! and row 32 binds the assertion. Raw and digest chunks emit on their third row so the AIR
//! can read the fourth row through `next`. Rows 33..64 carry invocation metadata only.

use alloc::vec::Vec;

use miden_core::Felt;

pub const IO_PERIOD: usize = 64;
pub const NUM_PERIODIC_COLS: usize = 23;
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
/// Selects the first or second 32-byte digest chunk; used only on digest rows 24..32.
pub const P_DIGEST_CYCLE_OFFSET: usize = 9;
pub const P_IV_LO: usize = 10;
pub const P_IV_HI: usize = 11;
pub const P_DIGEST_NEXT: usize = 12;
pub const P_RAW: usize = 13;
pub const P_RAW_NEXT: usize = 14;
pub const P_RAW_LAST: usize = 15;
pub const P_CHUNK_ADVANCE: usize = 16;
pub const P_STATE_IDX: usize = 17;
pub const P_DIGEST: usize = 18;
pub const P_DIGEST_IDX: usize = 19;
pub const P_DIGEST_SECOND: usize = 20;
pub const P_DIGEST_EMIT: usize = 21;
pub const P_BIND: usize = 22;

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
/// These columns repeat every sixty-four rows; invocation-specific flags remain witness columns.
pub fn io_program() -> [Vec<Felt>; NUM_PERIODIC_COLS] {
    let mut columns = core::array::from_fn(|_| Vec::with_capacity(IO_PERIOD));
    for i in 0..IO_PERIOD {
        let raw = i < 16;
        let state = (16..24).contains(&i);
        let digest = (24..32).contains(&i);
        let iv = if state { IV[i - 16] } else { 0 };
        let row = [
            i.min(15) as u32,
            (i == 0) as u32,
            (i == 63) as u32,
            (i == 14) as u32,
            (raw && i % 4 == 0) as u32,
            (raw && i % 4 == 3) as u32,
            (raw && i % 4 == 2) as u32,
            (raw && i % 4 == 1) as u32,
            state as u32,
            (digest && i >= 28) as u32,
            iv as u32,
            (iv >> 32) as u32,
            (24..31).contains(&i) as u32,
            raw as u32,
            (i < 15) as u32,
            (i == 15) as u32,
            (raw && i < 15 && i % 4 == 3) as u32,
            if state { (i - 16) as u32 } else { 0 },
            digest as u32,
            if digest { (i - 24) as u32 } else { 0 },
            (digest && i % 4 == 1) as u32,
            (digest && i % 4 == 2) as u32,
            (i == 32) as u32,
        ];
        for (column, value) in columns.iter_mut().zip(row) {
            column.push(Felt::from_u32(value));
        }
    }
    columns
}
