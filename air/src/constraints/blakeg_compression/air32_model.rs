//! Execution helpers for the 32-row BlakeG schedule.

#[cfg(test)]
use super::air32_layout::FUSED_G_ROWS;
#[cfg(test)]
use super::air32_schedule::{G_IDX_COL, G_IDX_DIAG, SIGMA, fused_step_at};

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[cfg(test)]
pub fn execute_fused_rounds(block: [u32; 16], h: [u32; 8]) -> [u32; 16] {
    let mut v = initial_working_state(h);

    for row in 0..FUSED_G_ROWS {
        let step = fused_step_at(row).expect("row is a fused G row");
        for g in 0..4 {
            let [ai, bi, ci, di] = step.lane_map[g];
            let msg = block[step.message_indices[g]];
            apply_half_g(&mut v, [ai, bi, ci, di], msg, step.first_rotation, step.second_rotation);
        }
    }

    v
}

#[cfg(test)]
pub fn execute_unfused_rounds(block: [u32; 16], h: [u32; 8]) -> [u32; 16] {
    let mut v = initial_working_state(h);

    for round in 0..SIGMA.len() {
        let s = &SIGMA[round];
        for g in 0..4 {
            apply_full_g(&mut v, G_IDX_COL[g], block[s[2 * g]], block[s[2 * g + 1]]);
        }
        for g in 0..4 {
            apply_full_g(&mut v, G_IDX_DIAG[g], block[s[8 + 2 * g]], block[s[8 + 2 * g + 1]]);
        }
    }

    v
}

pub fn low_output(v: [u32; 16]) -> [u32; 8] {
    core::array::from_fn(|i| v[i] ^ v[i + 8])
}

#[cfg(test)]
pub fn xof_lanes(v: [u32; 16], h: [u32; 8]) -> [u32; 16] {
    core::array::from_fn(|i| if i < 8 { v[i] ^ v[i + 8] } else { v[i] ^ h[i - 8] })
}

pub fn initial_working_state(h: [u32; 8]) -> [u32; 16] {
    let mut v = [0; 16];
    v[..8].copy_from_slice(&h);
    v[8..].copy_from_slice(&IV);
    v
}

#[cfg(test)]
fn apply_full_g(v: &mut [u32; 16], lane: [usize; 4], msg0: u32, msg1: u32) {
    apply_half_g(v, lane, msg0, 16, 12);
    apply_half_g(v, lane, msg1, 8, 7);
}

#[cfg(test)]
fn apply_half_g(
    v: &mut [u32; 16],
    [ai, bi, ci, di]: [usize; 4],
    msg: u32,
    first_rotation: u32,
    second_rotation: u32,
) {
    v[ai] = v[ai].wrapping_add(v[bi]).wrapping_add(msg);
    v[di] = (v[di] ^ v[ai]).rotate_right(first_rotation);
    v[ci] = v[ci].wrapping_add(v[di]);
    v[bi] = (v[bi] ^ v[ci]).rotate_right(second_rotation);
}
