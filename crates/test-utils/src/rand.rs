use alloc::vec::Vec;
use core::{
    array,
    sync::atomic::{AtomicU64, Ordering},
};

use super::{Felt, QuadFelt, WORD_SIZE, Word};

pub trait Randomizable {
    fn random() -> Self;
}

pub fn rand_value<T: Randomizable>() -> T {
    T::random()
}

pub fn rand_array<T: Randomizable, const N: usize>() -> [T; N] {
    array::from_fn(|_| T::random())
}

pub fn rand_vector<T: Randomizable>(len: usize) -> Vec<T> {
    (0..len).map(|_| T::random()).collect()
}

pub fn seeded_word(seed: &mut u64) -> Word {
    let elements = [
        seeded_element(seed),
        seeded_element(seed),
        seeded_element(seed),
        seeded_element(seed),
    ];
    elements.into()
}

pub fn seeded_element(seed: &mut u64) -> Felt {
    *seed = (*seed).wrapping_add(0x9e37_79b9_7f4a_7c15);
    Felt::new(splitmix64(*seed))
}

impl Randomizable for u64 {
    fn random() -> Self {
        next_u64()
    }
}

impl Randomizable for u32 {
    fn random() -> Self {
        next_u64() as u32
    }
}

impl Randomizable for u16 {
    fn random() -> Self {
        next_u64() as u16
    }
}

impl Randomizable for u8 {
    fn random() -> Self {
        next_u64() as u8
    }
}

impl Randomizable for Felt {
    fn random() -> Self {
        Felt::new(next_u64())
    }
}

impl Randomizable for QuadFelt {
    fn random() -> Self {
        QuadFelt::new_complex(Felt::random(), Felt::random())
    }
}

impl Randomizable for Word {
    fn random() -> Self {
        let elements = rand_array::<Felt, WORD_SIZE>();
        Word::new(elements)
    }
}

fn next_u64() -> u64 {
    static STATE: AtomicU64 = AtomicU64::new(0x4d595df4d0f33173);

    let mut current = STATE.load(Ordering::Relaxed);
    loop {
        let next = current.wrapping_add(0x9e37_79b9_7f4a_7c15);
        match STATE.compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return splitmix64(next),
            Err(observed) => current = observed,
        }
    }
}

/// SplitMix64 hash function for mixing RNG state into high-quality random output.
fn splitmix64(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}
