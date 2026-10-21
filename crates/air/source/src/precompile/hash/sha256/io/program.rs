//! Serialized 32-row schedule for one SHA-256 block: raw bytes, state, digest, binding.

use alloc::vec::Vec;

use miden_core::Felt;

pub const IO_PERIOD: usize = 32;
pub const NUM_PERIODIC_COLS: usize = 23;
pub const P_IDX: usize = 0;
pub const P_FIRST: usize = 1;
pub const P_LAST: usize = 2;
pub const P_RAW: usize = 3;
pub const P_RAW_NEXT: usize = 4;
pub const P_RAW_LAST: usize = 5;
pub const P_CHUNK_FIRST: usize = 6;
pub const P_CHUNK_END: usize = 7;
pub const P_CHUNK_ADVANCE: usize = 8;
pub const P_STATE: usize = 9;
pub const P_STATE_IDX: usize = 10;
pub const P_IV_LO: usize = 11;
pub const P_IV_HI: usize = 12;
pub const P_DIGEST: usize = 13;
pub const P_DIGEST_IDX: usize = 14;
pub const P_DIGEST_NEXT: usize = 15;
pub const P_DIGEST_SECOND: usize = 16;
pub const P_DIGEST_EMIT: usize = 17;
pub const P_DIGEST_CARRY: usize = 18;
pub const P_BIND: usize = 19;
pub const P_SUFFIX: usize = 20;
pub const P_LENGTH: usize = 21;
pub const P_RAW_EMIT: usize = 22;

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
        let state = (16..20).contains(&i);
        let digest = (20..24).contains(&i);
        let [iv_hi, iv_lo] = if state {
            [IV[2 * (i - 16)], IV[2 * (i - 16) + 1]]
        } else {
            [0, 0]
        };
        let row = [
            i.min(15) as u32,
            (i == 0) as u32,
            (i == 31) as u32,
            (i < 16) as u32,
            (i < 15) as u32,
            (i == 15) as u32,
            (i == 0 || i == 8) as u32,
            (i == 7 || i == 15) as u32,
            (i == 7) as u32,
            state as u32,
            if state { (i - 16) as u32 } else { 0 },
            iv_lo,
            iv_hi,
            digest as u32,
            if digest { (i - 20) as u32 } else { 0 },
            (20..23).contains(&i) as u32,
            (i == 21) as u32,
            (i == 22) as u32,
            (20..24).contains(&i) as u32,
            (i == 24) as u32,
            (i == 14 || i == 15) as u32,
            (i == 14) as u32,
            (i == 7 || i == 15) as u32,
        ];
        for (column, value) in columns.iter_mut().zip(row) {
            column.push(Felt::from_u32(value));
        }
    }
    columns
}
