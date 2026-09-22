//! State helpers for materializing the 32-row Eidos compression trace.

use super::schedule::EIDOS_COMPRESSION_IV;

/// Returns the sixteen raw XOF words for final working state `v` and input chaining value `h`:
/// the chaining-value fold followed by the XOF feed-forward.
pub fn raw_xof_output(v: [u32; 16], h: [u32; 8]) -> [u32; 16] {
    core::array::from_fn(|i| if i < 8 { v[i] ^ v[i + 8] } else { v[i] ^ h[i - 8] })
}

pub fn initial_working_state(h: [u32; 8]) -> [u32; 16] {
    let mut v = [0; 16];
    v[..8].copy_from_slice(&h);
    v[8..].copy_from_slice(&EIDOS_COMPRESSION_IV);
    v
}
