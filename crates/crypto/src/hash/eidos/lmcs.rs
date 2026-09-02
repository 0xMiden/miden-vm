//! Eidos LMCS configuration.
//!
//! LMCS leaf hashing uses zero padding to the eight-Felt block width and deliberately does not bind
//! a variable input length. Matrix metadata fixes every committed row width, so this construction
//! is only suitable for those fixed-width rows and is not interchangeable with
//! [`Eidos::hash_elements`](super::Eidos::hash_elements). Internal nodes use the distinct
//! eight-felt Eidos chaining value and therefore remain separated from leaves.

use core::array;

use p3_symmetric::PseudoCompressionFunction;

use super::{
    PACKED_LANES, compression, encoding,
    framing::{self, FELT_BLOCK_INIT_CV, FELT_INIT_CV_U64},
};
use crate::{
    Felt,
    stark::{
        hasher::{Alignable, StatefulHasher},
        lmcs::config::LmcsConfig,
    },
};

const DIGEST_WIDTH: usize = super::DIGEST_WIDTH;
const BLOCK_LEN: usize = super::BLOCK_LEN;

const COMPRESSION_INPUTS: usize = 2;

// LMCS creates hasher states with `Default`. Eidos starts from a non-zero
// chaining value, so the state carries one extra flag to mark initialization.
const INIT_FLAG_IDX: usize = DIGEST_WIDTH;
const STATE_WIDTH: usize = DIGEST_WIDTH + 1;

type PackedFelt = [Felt; PACKED_LANES];
type PackedU64 = [u64; PACKED_LANES];
type Digest = [u64; DIGEST_WIDTH];
type PackedDigest = [PackedU64; DIGEST_WIDTH];
type State = [u64; STATE_WIDTH];
type PackedState = [PackedU64; STATE_WIDTH];

/// Eidos LMCS configuration.
pub type EidosLmcs = LmcsConfig<
    PackedFelt,
    PackedU64,
    EidosLmcsHasher,
    EidosLmcsCompressor,
    STATE_WIDTH,
    DIGEST_WIDTH,
>;

/// Stateful hasher used by the Eidos LMCS configuration.
#[derive(Clone, Copy, Debug)]
pub struct EidosLmcsHasher;

/// Compression function used for LMCS internal tree nodes.
#[derive(Clone, Copy, Debug)]
pub struct EidosLmcsCompressor;

impl PseudoCompressionFunction<Digest, COMPRESSION_INPUTS> for EidosLmcsCompressor {
    #[inline]
    fn compress(&self, input: [Digest; COMPRESSION_INPUTS]) -> Digest {
        let block = [
            input[0][0],
            input[0][1],
            input[0][2],
            input[0][3],
            input[1][0],
            input[1][1],
            input[1][2],
            input[1][3],
        ];
        encoding::pack_cv_to_u64s(compression::compress_u64_cv(FELT_BLOCK_INIT_CV, block))
    }
}

impl PseudoCompressionFunction<PackedDigest, COMPRESSION_INPUTS> for EidosLmcsCompressor {
    #[inline]
    fn compress(&self, input: [PackedDigest; COMPRESSION_INPUTS]) -> PackedDigest {
        let block = [
            input[0][0],
            input[0][1],
            input[0][2],
            input[0][3],
            input[1][0],
            input[1][1],
            input[1][2],
            input[1][3],
        ];
        compression::compress_packed_u64_cv(
            framing::init_packed_u64_cv(0, [BLOCK_LEN as u32, 0, 0]),
            block,
        )
    }
}

impl StatefulHasher<Felt, Digest> for EidosLmcsHasher {
    type State = State;

    fn absorb_into(&self, state: &mut Self::State, input: impl IntoIterator<Item = Felt>) {
        ensure_initialized(state);

        let cv = absorb_blocks(
            encoding::unpack_u64_cv(read_digest(state)),
            input,
            Felt::ZERO,
            |cv, block| compression::compress_cv(cv, encoding::encode_felt_block(&block)),
        );
        pack_lmcs_cv_into(cv, state);
    }

    fn squeeze(&self, state: &Self::State) -> Digest {
        if state[INIT_FLAG_IDX] == 0 {
            FELT_INIT_CV_U64
        } else {
            read_digest(state)
        }
    }
}

impl StatefulHasher<PackedFelt, PackedDigest> for EidosLmcsHasher {
    type State = PackedState;

    fn absorb_into(&self, state: &mut Self::State, input: impl IntoIterator<Item = PackedFelt>) {
        ensure_packed_initialized(state);

        let cv = absorb_blocks(
            encoding::unpack_packed_u64_cv(read_digest(state)),
            input,
            [Felt::ZERO; PACKED_LANES],
            |cv, block| {
                compression::compress_cv_packed(cv, encoding::encode_packed_felt_block(block))
            },
        );
        pack_lmcs_cv_packed_into(cv, state);
    }

    fn squeeze(&self, state: &Self::State) -> PackedDigest {
        let initialized = packed_initialization_state(state);
        if initialized {
            read_digest(state)
        } else {
            array::from_fn(|word| [FELT_INIT_CV_U64[word]; PACKED_LANES])
        }
    }
}

impl<Input, Target> Alignable<Input, Target> for EidosLmcsHasher {
    // LMCS rows are absorbed in Eidos block-sized groups; this is independent of
    // the host SIMD lane count.
    const ALIGNMENT: usize = BLOCK_LEN;
}

/// Creates the Eidos LMCS configuration used by the STARK proof config.
pub const fn config() -> EidosLmcs {
    LmcsConfig::new(EidosLmcsHasher, EidosLmcsCompressor)
}

fn absorb_blocks<T, D>(
    mut digest: D,
    input: impl IntoIterator<Item = T>,
    zero: T,
    mut compress: impl FnMut(D, [T; BLOCK_LEN]) -> D,
) -> D
where
    T: Copy,
{
    let mut block = [zero; BLOCK_LEN];
    let mut filled = 0usize;

    for value in input {
        block[filled] = value;
        filled += 1;

        if filled == BLOCK_LEN {
            digest = compress(digest, block);
            filled = 0;
        }
    }

    if filled != 0 {
        block[filled..].fill(zero);
        digest = compress(digest, block);
    }

    digest
}

fn ensure_initialized(state: &mut State) {
    if state[INIT_FLAG_IDX] != 0 {
        return;
    }

    write_digest(state, FELT_INIT_CV_U64);
    state[INIT_FLAG_IDX] = 1;
}

fn ensure_packed_initialized(state: &mut PackedState) {
    let initialized = packed_initialization_state(state);

    if initialized {
        return;
    }

    for (word, value) in state[..DIGEST_WIDTH].iter_mut().zip(FELT_INIT_CV_U64) {
        *word = [value; PACKED_LANES];
    }
    state[INIT_FLAG_IDX] = [1; PACKED_LANES];
}

fn packed_initialization_state(state: &PackedState) -> bool {
    let initialized = state[INIT_FLAG_IDX][0] != 0;
    assert!(
        state[INIT_FLAG_IDX].iter().all(|&flag| (flag != 0) == initialized),
        "packed LMCS state contains mixed initialization flags"
    );
    initialized
}

fn read_digest<T: Copy, const WIDTH: usize>(state: &[T; WIDTH]) -> [T; DIGEST_WIDTH] {
    array::from_fn(|idx| state[idx])
}

fn write_digest<T: Copy, const WIDTH: usize>(state: &mut [T; WIDTH], digest: [T; DIGEST_WIDTH]) {
    state[..DIGEST_WIDTH].copy_from_slice(&digest);
}

fn pack_lmcs_cv_into(cv: [u32; 8], state: &mut State) {
    write_digest(state, encoding::pack_cv_to_u64s(cv));
}

fn pack_lmcs_cv_packed_into(cv: [[u32; PACKED_LANES]; 8], state: &mut PackedState) {
    write_digest(state, encoding::pack_cv_to_packed_u64s(cv));
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use p3_symmetric::PseudoCompressionFunction;

    use super::*;
    use crate::{
        hash::eidos::{Eidos, compression::compress_felt_block_for_test},
        stark::hasher::{Alignable, StatefulHasher},
    };

    const INPUT_LENGTHS: [usize; 7] = [0, 1, 7, 8, 9, 16, 17];

    #[test]
    fn lmcs_alignment_is_one_eidos_block() {
        assert_eq!(<EidosLmcsHasher as Alignable<Felt, Digest>>::ALIGNMENT, BLOCK_LEN);
    }

    #[test]
    fn empty_row_sequence_squeezes_initialized_digest() {
        let hasher = EidosLmcsHasher;

        let scalar =
            <EidosLmcsHasher as StatefulHasher<Felt, Digest>>::squeeze(&hasher, &[0; STATE_WIDTH]);
        assert_eq!(scalar, FELT_INIT_CV_U64);

        let packed = <EidosLmcsHasher as StatefulHasher<PackedFelt, PackedDigest>>::squeeze(
            &hasher,
            &[[0; PACKED_LANES]; STATE_WIDTH],
        );
        for lane in 0..PACKED_LANES {
            assert_eq!(unpack_digest_lane(packed, lane), FELT_INIT_CV_U64);
        }
    }

    #[test]
    #[should_panic(expected = "packed LMCS state contains mixed initialization flags")]
    fn mixed_packed_initialization_flags_are_rejected() {
        let hasher = EidosLmcsHasher;
        let mut state = [[0; PACKED_LANES]; STATE_WIDTH];
        state[INIT_FLAG_IDX][0] = 1;

        let _ =
            <EidosLmcsHasher as StatefulHasher<PackedFelt, PackedDigest>>::squeeze(&hasher, &state);
    }

    #[test]
    fn partial_tail_uses_zero_padding_independently_of_previous_block() {
        let hasher = EidosLmcsHasher;
        let input = (1..=9).map(Felt::new_unchecked).collect::<Vec<_>>();
        let mut explicitly_padded = input.clone();
        explicitly_padded.resize(16, Felt::ZERO);

        let mut partial_state = [0; STATE_WIDTH];
        <EidosLmcsHasher as StatefulHasher<Felt, Digest>>::absorb_into(
            &hasher,
            &mut partial_state,
            input,
        );

        let mut padded_state = [0; STATE_WIDTH];
        <EidosLmcsHasher as StatefulHasher<Felt, Digest>>::absorb_into(
            &hasher,
            &mut padded_state,
            explicitly_padded,
        );

        assert_eq!(partial_state, padded_state);
    }

    #[test]
    fn frozen_lmcs_tree_vector() {
        let hasher = EidosLmcsHasher;
        let mut left_state = [0; STATE_WIDTH];
        let mut right_state = [0; STATE_WIDTH];
        <EidosLmcsHasher as StatefulHasher<Felt, Digest>>::absorb_into(
            &hasher,
            &mut left_state,
            (1..=9).map(Felt::new_unchecked),
        );
        <EidosLmcsHasher as StatefulHasher<Felt, Digest>>::absorb_into(
            &hasher,
            &mut right_state,
            (101..=109).map(Felt::new_unchecked),
        );
        let left = read_digest(&left_state);
        let right = read_digest(&right_state);
        let root = EidosLmcsCompressor.compress([left, right]);

        assert_eq!(
            left,
            [6361241547698535781, 8537111288558577663, 851413926585467786, 31821888461167226,],
        );
        assert_eq!(
            right,
            [
                5928680795072819257,
                9046658530231547486,
                1678833814049704111,
                7048430306948613652,
            ],
        );
        assert_eq!(
            root,
            [
                4698205327658179430,
                1657025491673246698,
                418554804512439445,
                8258405545248521438
            ],
        );
    }

    #[test]
    fn packed_absorb_matches_scalar_lanes() {
        let hasher = EidosLmcsHasher;

        for len in INPUT_LENGTHS {
            let lanes = scalar_lane_inputs(len);
            let packed_input = pack_lanes(&lanes);

            let mut packed_state = [[0; PACKED_LANES]; STATE_WIDTH];
            <EidosLmcsHasher as StatefulHasher<PackedFelt, PackedDigest>>::absorb_into(
                &hasher,
                &mut packed_state,
                packed_input,
            );

            for lane in 0..PACKED_LANES {
                let mut scalar_state = [0; STATE_WIDTH];
                <EidosLmcsHasher as StatefulHasher<Felt, Digest>>::absorb_into(
                    &hasher,
                    &mut scalar_state,
                    lanes[lane].iter().copied(),
                );

                for word in 0..STATE_WIDTH {
                    assert_eq!(
                        packed_state[word][lane], scalar_state[word],
                        "packed lane {lane} diverged from scalar at input length {len}, word {word}",
                    );
                }
            }
        }
    }

    #[test]
    fn scalar_absorb_matches_felt_digest_reference() {
        let hasher = EidosLmcsHasher;

        for len in INPUT_LENGTHS {
            let input = scalar_lane_inputs(len)[0].clone();

            let mut state = [0; STATE_WIDTH];
            <EidosLmcsHasher as StatefulHasher<Felt, Digest>>::absorb_into(
                &hasher,
                &mut state,
                input.iter().copied(),
            );

            let mut expected = Eidos::init_chaining_word(0, 0).into();
            expected = absorb_blocks(expected, input, Felt::ZERO, compress_felt_block_for_test);

            let actual = read_digest(&state).map(Felt::new_unchecked);
            assert_eq!(
                actual, expected,
                "LMCS digest changed field semantics at input length {len}",
            );
        }
    }

    #[test]
    fn lmcs_compressor_matches_eidos_merge_semantics() {
        let left = digest_from_seed(10);
        let right = digest_from_seed(20);
        let compressor = EidosLmcsCompressor;

        let actual = compressor.compress([left, right]);
        let expected = eidos_hash_two_digests(left, right);
        assert_eq!(actual, expected);

        let left_packed = pack_digest_lanes(array::from_fn(|lane| digest_from_seed(100 + lane)));
        let right_packed = pack_digest_lanes(array::from_fn(|lane| digest_from_seed(200 + lane)));
        let actual_packed = compressor.compress([left_packed, right_packed]);

        for (lane, _) in left_packed[0].iter().enumerate() {
            let left_lane = unpack_digest_lane(left_packed, lane);
            let right_lane = unpack_digest_lane(right_packed, lane);
            let expected_lane = eidos_hash_two_digests(left_lane, right_lane);

            for word in 0..DIGEST_WIDTH {
                assert_eq!(
                    actual_packed[word][lane], expected_lane[word],
                    "packed compressor lane {lane} diverged at word {word}",
                );
            }
        }
    }

    fn scalar_lane_inputs(len: usize) -> [Vec<Felt>; PACKED_LANES] {
        array::from_fn(|lane| {
            (0..len)
                .map(|idx| Felt::new_unchecked(1 + lane as u64 * 1_000 + idx as u64))
                .collect()
        })
    }

    fn pack_lanes(lanes: &[Vec<Felt>; PACKED_LANES]) -> Vec<PackedFelt> {
        (0..lanes[0].len()).map(|idx| array::from_fn(|lane| lanes[lane][idx])).collect()
    }

    fn digest_from_seed(seed: usize) -> Digest {
        array::from_fn(|idx| Felt::new_unchecked((seed + idx) as u64).as_canonical_u64())
    }

    fn eidos_hash_two_digests(left: Digest, right: Digest) -> Digest {
        let elements: [Felt; BLOCK_LEN] = array::from_fn(|idx| {
            let value = if idx < DIGEST_WIDTH {
                left[idx]
            } else {
                right[idx - DIGEST_WIDTH]
            };
            Felt::new_unchecked(value)
        });
        let expected: [Felt; DIGEST_WIDTH] = Eidos::hash_elements(&elements).into();
        expected.map(|value| value.as_canonical_u64())
    }

    fn pack_digest_lanes(lanes: [Digest; PACKED_LANES]) -> PackedDigest {
        array::from_fn(|word| array::from_fn(|lane| lanes[lane][word]))
    }

    fn unpack_digest_lane(digest: PackedDigest, lane: usize) -> Digest {
        array::from_fn(|word| digest[word][lane])
    }
}
