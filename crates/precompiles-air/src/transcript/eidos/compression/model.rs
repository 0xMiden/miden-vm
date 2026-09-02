//! Execution helpers for the 32-row Eidos compression schedule.

use super::schedule::EIDOS_COMPRESSION_IV;

pub fn low_output(v: [u32; 16]) -> [u32; 8] {
    core::array::from_fn(|i| v[i] ^ v[i + 8])
}

pub fn initial_working_state(h: [u32; 8]) -> [u32; 16] {
    let mut v = [0; 16];
    v[..8].copy_from_slice(&h);
    v[8..].copy_from_slice(&EIDOS_COMPRESSION_IV);
    v
}
