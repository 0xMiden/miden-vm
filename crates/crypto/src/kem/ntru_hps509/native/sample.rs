use super::{COIN_BYTES, N, WEIGHT, poly::Poly};
use crate::utils::zeroize::Zeroizing;

/// HPS uses the same samplers for (f, g) and (r, m).
pub(super) fn pair(coins: &[u8; COIN_BYTES]) -> (Poly, Poly) {
    let mut iid = Poly::zero();
    for (c, &byte) in iid.0[..N - 1].iter_mut().zip(&coins[..N - 1]) {
        *c = byte as u16 % 3;
    }
    (iid, fixed_type(coins[N - 1..].try_into().unwrap()))
}

fn fixed_type(coins: &[u8; COIN_BYTES - (N - 1)]) -> Poly {
    let mut keys = Zeroizing::new([i32::MAX; 512]);
    let mut block = Zeroizing::new([0; 16]);
    let outputs = keys[..N - 1].as_chunks_mut::<4>().0;
    for (out, bytes) in outputs.iter_mut().zip(coins.as_chunks::<15>().0) {
        // Four 30-bit little-endian draws. The low two bits carry the trit through sorting.
        block[..15].copy_from_slice(bytes);
        let packed = Zeroizing::new(u128::from_le_bytes(*block));
        for (i, key) in out.iter_mut().enumerate() {
            *key = (((*packed >> (30 * i)) as u32) << 2) as i32;
        }
    }
    let half = WEIGHT as usize / 2;
    for key in &mut keys[..half] {
        *key |= 1;
    }
    for key in &mut keys[half..2 * half] {
        *key |= 2;
    }
    sort(&mut keys);
    let mut result = Poly::zero();
    for (c, &key) in result.0[..N - 1].iter_mut().zip(keys.iter()) {
        *c = key as u16 & 3;
    }
    result
}

/// Bitonic sorting with public indices and branch-free signed comparisons.
///
/// Padding keys are larger than every sampled key (whose low bits are 0, 1, or 2).
/// After sorting they occupy the four discarded positions. Equal sampled keys carry
/// equal trits, so their ordering does not affect the reference sampler's result.
fn sort(keys: &mut [i32; 512]) {
    let mut width = 2;
    while width <= keys.len() {
        let mut distance = width / 2;
        while distance != 0 {
            for i in 0..keys.len() {
                let j = i ^ distance;
                if j > i {
                    let a = keys[i];
                    let b = keys[j];
                    let descending = (i & width != 0) as i64;
                    let exchange = (((b as i64 - a as i64) >> 63) ^ -descending) as i32;
                    let difference = (a ^ b) & exchange;
                    keys[i] ^= difference;
                    keys[j] ^= difference;
                }
            }
            distance /= 2;
        }
        width *= 2;
    }
}
