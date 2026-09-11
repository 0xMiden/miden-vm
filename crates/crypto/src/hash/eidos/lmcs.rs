//! Eidos LMCS configuration.
//!
//! LMCS leaf hashing has a registered custom domain. Each matrix row is padded independently to
//! the eight-Felt block width, and the total padded length is bound in the initial chaining value.
//! Matrix metadata fixes the row boundaries and widths. Internal nodes use the reserved Merkle
//! inner-node construction and remain separated from leaves.

use alloc::vec::Vec;

use p3_symmetric::PseudoCompressionFunction;

use super::{
    PACKED_LANES, compression,
    domain::EidosDomain,
    domains::LmcsLeafDomain,
    encoding,
    framing::{self, MERKLE_NODE_INIT_CV},
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

type PackedFelt = [Felt; PACKED_LANES];
type PackedU64 = [u64; PACKED_LANES];
type Digest = [u64; DIGEST_WIDTH];
type PackedDigest = [PackedU64; DIGEST_WIDTH];
type State = Digest;
type PackedState = PackedDigest;

/// Eidos LMCS configuration.
pub type EidosLmcs = LmcsConfig<
    PackedFelt,
    PackedU64,
    EidosLmcsHasher,
    EidosLmcsCompressor,
    DIGEST_WIDTH,
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
        encoding::pack_cv_to_u64s(compression::compress_u64_cv(MERKLE_NODE_INIT_CV, block))
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
        compression::compress_packed_u64_cv(&framing::init_packed_u64_cv(0, [0; 3]), &block)
    }
}

impl StatefulHasher<Felt, Digest> for EidosLmcsHasher {
    type State = State;

    fn initialize_state(&self, state: &mut Self::State, encoded_len: usize) {
        *state = new_state(encoded_len);
    }

    fn absorb_into(&self, state: &mut Self::State, input: impl IntoIterator<Item = Felt>) {
        let cv = absorb_blocks(encoding::unpack_u64_cv(*state), input, Felt::ZERO, |cv, block| {
            compression::compress_cv(cv, encoding::encode_felt_block(&block))
        });
        *state = encoding::pack_cv_to_u64s(cv);
    }

    fn squeeze(&self, state: &Self::State) -> Digest {
        *state
    }

    fn hash_rows<'a>(&self, rows: impl IntoIterator<Item = &'a [Felt]>) -> Digest
    where
        Felt: 'a,
    {
        let rows = rows.into_iter().collect::<Vec<_>>();
        let mut state = new_state(encoded_len(rows.iter().map(|row| row.len())));
        for row in rows {
            self.absorb_into(&mut state, row.iter().copied());
        }
        self.squeeze(&state)
    }
}

impl StatefulHasher<PackedFelt, PackedDigest> for EidosLmcsHasher {
    type State = PackedState;

    fn initialize_state(&self, state: &mut Self::State, encoded_len: usize) {
        *state = new_packed_state(encoded_len);
    }

    fn absorb_into(&self, state: &mut Self::State, input: impl IntoIterator<Item = PackedFelt>) {
        let cv = absorb_blocks(
            encoding::unpack_packed_u64_cv(*state),
            input,
            [Felt::ZERO; PACKED_LANES],
            |cv, block| {
                compression::compress_cv_packed(&cv, &encoding::encode_packed_felt_block(block))
            },
        );
        *state = encoding::pack_cv_to_packed_u64s(cv);
    }

    fn squeeze(&self, state: &Self::State) -> PackedDigest {
        *state
    }

    fn hash_rows<'a>(&self, rows: impl IntoIterator<Item = &'a [PackedFelt]>) -> PackedDigest
    where
        PackedFelt: 'a,
    {
        let rows = rows.into_iter().collect::<Vec<_>>();
        let mut state = new_packed_state(encoded_len(rows.iter().map(|row| row.len())));
        for row in rows {
            self.absorb_into(&mut state, row.iter().copied());
        }
        self.squeeze(&state)
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

fn new_state(encoded_len: usize) -> State {
    let encoded_len = u32::try_from(encoded_len).expect("LMCS encoded length exceeds u32");
    let cv = framing::init_cv(LmcsLeafDomain::TAG.as_u32(), [encoded_len, 0, 0]);
    encoding::pack_cv_to_u64s(cv)
}

fn new_packed_state(encoded_len: usize) -> PackedState {
    let encoded_len = u32::try_from(encoded_len).expect("LMCS encoded length exceeds u32");
    framing::init_packed_u64_cv(LmcsLeafDomain::TAG.as_u32(), [encoded_len, 0, 0])
}

fn encoded_len(row_lengths: impl IntoIterator<Item = usize>) -> usize {
    row_lengths.into_iter().fold(0usize, |total, len| {
        let padded = len
            .checked_add(BLOCK_LEN - 1)
            .map(|len| len / BLOCK_LEN * BLOCK_LEN)
            .expect("LMCS row length exceeds usize");
        total.checked_add(padded).expect("LMCS encoded length exceeds usize")
    })
}

#[cfg(test)]
mod tests {
    use core::array;

    use p3_symmetric::PseudoCompressionFunction;

    use super::*;
    use crate::{
        Word,
        hash::eidos::{Eidos, compression::compress_felt_block_for_test},
        stark::{
            hasher::{Alignable, StatefulHasher},
            lmcs::{Lmcs, LmcsTree},
            matrix::RowMajorMatrix,
        },
    };

    const INPUT_LENGTHS: [usize; 7] = [0, 1, 7, 8, 9, 16, 17];

    #[test]
    fn lmcs_alignment_is_one_eidos_block() {
        assert_eq!(<EidosLmcsHasher as Alignable<Felt, Digest>>::ALIGNMENT, BLOCK_LEN);
    }

    #[test]
    fn empty_row_sequence_squeezes_length_bound_digest() {
        let hasher = EidosLmcsHasher;
        let scalar_state = new_state(0);

        let scalar =
            <EidosLmcsHasher as StatefulHasher<Felt, Digest>>::squeeze(&hasher, &scalar_state);
        let expected: Digest = Eidos::init_chaining_word_with_params(LmcsLeafDomain, [0; 3])
            .into_elements()
            .map(|value| value.as_canonical_u64());
        assert_eq!(scalar, expected);

        let packed_state = new_packed_state(0);
        let packed = <EidosLmcsHasher as StatefulHasher<PackedFelt, PackedDigest>>::squeeze(
            &hasher,
            &packed_state,
        );
        for lane in 0..PACKED_LANES {
            assert_eq!(unpack_digest_lane(&packed, lane), expected);
        }
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    #[should_panic(expected = "LMCS encoded length exceeds u32")]
    fn encoded_length_must_fit_the_framing_lane() {
        let _ = new_state(u32::MAX as usize + 1);
    }

    #[test]
    fn partial_tail_uses_zero_padding_independently_of_previous_block() {
        let hasher = EidosLmcsHasher;
        let input = (1..=9).map(Felt::new_unchecked).collect::<Vec<_>>();
        let mut explicitly_padded = input.clone();
        explicitly_padded.resize(16, Felt::ZERO);

        let mut partial_state = new_state(16);
        <EidosLmcsHasher as StatefulHasher<Felt, Digest>>::absorb_into(
            &hasher,
            &mut partial_state,
            input,
        );

        let mut padded_state = new_state(16);
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
        let mut left_state = new_state(16);
        let mut right_state = new_state(16);
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
        let left = left_state;
        let right = right_state;
        let root = EidosLmcsCompressor.compress([left, right]);

        assert_eq!(
            left,
            [7975491762537237790, 210725808216452534, 809262867721008121, 4612689512912990922,],
        );
        assert_eq!(
            right,
            [
                3235890721826482854,
                5501488662693794106,
                7516676704806885018,
                6369515668133163107,
            ],
        );
        assert_eq!(
            root,
            [
                2202331962719226590,
                2302273434923287409,
                7081266703261990827,
                2694702893234644687,
            ],
        );
    }

    #[test]
    fn packed_absorb_matches_scalar_lanes() {
        let hasher = EidosLmcsHasher;

        for len in INPUT_LENGTHS {
            let lanes = scalar_lane_inputs(len);
            let packed_input = pack_lanes(&lanes);

            let encoded_len = encoded_len([len]);
            let mut packed_state = new_packed_state(encoded_len);
            <EidosLmcsHasher as StatefulHasher<PackedFelt, PackedDigest>>::absorb_into(
                &hasher,
                &mut packed_state,
                packed_input,
            );

            for lane in 0..PACKED_LANES {
                let mut scalar_state = new_state(encoded_len);
                <EidosLmcsHasher as StatefulHasher<Felt, Digest>>::absorb_into(
                    &hasher,
                    &mut scalar_state,
                    lanes[lane].iter().copied(),
                );

                for word in 0..DIGEST_WIDTH {
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
            let encoded_len = encoded_len([len]);

            let mut state = new_state(encoded_len);
            <EidosLmcsHasher as StatefulHasher<Felt, Digest>>::absorb_into(
                &hasher,
                &mut state,
                input.iter().copied(),
            );

            let mut expected =
                Eidos::init_chaining_word_with_params(LmcsLeafDomain, [encoded_len as u32, 0, 0])
                    .into();
            expected = absorb_blocks(expected, input, Felt::ZERO, compress_felt_block_for_test);

            let actual = state.map(Felt::new_unchecked);
            assert_eq!(
                actual, expected,
                "LMCS digest changed field semantics at input length {len}",
            );
        }
    }

    #[test]
    fn lmcs_paths_bind_the_sum_of_independently_padded_rows() {
        let first = (1..=3).map(Felt::new_unchecked).collect::<Vec<_>>();
        let second = (4..=12).map(Felt::new_unchecked).collect::<Vec<_>>();
        let matrices = vec![
            RowMajorMatrix::new(first.clone(), first.len()),
            RowMajorMatrix::new(second.clone(), second.len()),
        ];
        let lmcs = config();

        let hasher = EidosLmcsHasher;
        let mut expected_state = new_state(24);
        <EidosLmcsHasher as StatefulHasher<Felt, Digest>>::absorb_into(
            &hasher,
            &mut expected_state,
            first.iter().copied(),
        );
        <EidosLmcsHasher as StatefulHasher<Felt, Digest>>::absorb_into(
            &hasher,
            &mut expected_state,
            second.iter().copied(),
        );

        let leaf = lmcs.hash([first.as_slice(), second.as_slice()]);
        assert_eq!(*leaf.as_ref(), expected_state);
        let tree = lmcs.build_tree(matrices.clone());
        let aligned_tree = lmcs.build_aligned_tree(matrices);
        assert_eq!(tree.root(), leaf);
        assert_eq!(aligned_tree.root(), leaf);
    }

    #[test]
    fn length_binding_prevents_extending_a_leaf_digest() {
        let hasher = EidosLmcsHasher;
        let first = (1..=8).map(Felt::new_unchecked).collect::<Vec<_>>();
        let second = (9..=16).map(Felt::new_unchecked).collect::<Vec<_>>();

        let mut prefix_state = new_state(8);
        <EidosLmcsHasher as StatefulHasher<Felt, Digest>>::absorb_into(
            &hasher,
            &mut prefix_state,
            first.iter().copied(),
        );
        <EidosLmcsHasher as StatefulHasher<Felt, Digest>>::absorb_into(
            &hasher,
            &mut prefix_state,
            second.iter().copied(),
        );

        let mut full_state = new_state(16);
        <EidosLmcsHasher as StatefulHasher<Felt, Digest>>::absorb_into(
            &hasher,
            &mut full_state,
            first.into_iter().chain(second),
        );

        assert_ne!(prefix_state, full_state);
    }

    #[test]
    fn lmcs_compressor_matches_eidos_merge_semantics() {
        let left = digest_from_seed(10);
        let right = digest_from_seed(20);
        let compressor = EidosLmcsCompressor;

        let actual = compressor.compress([left, right]);
        let expected = eidos_hash_two_digests(left, right);
        assert_eq!(actual, expected);

        let left_packed = pack_digest_lanes(&array::from_fn(|lane| digest_from_seed(100 + lane)));
        let right_packed = pack_digest_lanes(&array::from_fn(|lane| digest_from_seed(200 + lane)));
        let actual_packed = compressor.compress([left_packed, right_packed]);

        for (lane, _) in left_packed[0].iter().enumerate() {
            let left_lane = unpack_digest_lane(&left_packed, lane);
            let right_lane = unpack_digest_lane(&right_packed, lane);
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
        let left = Word::new(elements[..DIGEST_WIDTH].try_into().unwrap());
        let right = Word::new(elements[DIGEST_WIDTH..].try_into().unwrap());
        Eidos::merge(&[left, right])
            .into_elements()
            .map(|value| value.as_canonical_u64())
    }

    fn pack_digest_lanes(lanes: &[Digest; PACKED_LANES]) -> PackedDigest {
        array::from_fn(|word| array::from_fn(|lane| lanes[lane][word]))
    }

    fn unpack_digest_lane(digest: &PackedDigest, lane: usize) -> Digest {
        array::from_fn(|word| digest[word][lane])
    }
}
