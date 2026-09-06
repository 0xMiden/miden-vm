//! The framed Eidos hash construction.

use alloc::vec::Vec;
use core::array;

use p3_symmetric::CryptographicHasher;

use super::{
    BLOCK_LEN, DIGEST_WIDTH, PACKED_LANES, PackedBlock, PackedChainingValue, PackedDigest,
    PackedFelt, compression, encoding,
    framing::{self, BYTE_STRING_SELECTOR, FELT_BLOCK_INIT_CV},
};
use crate::{Felt, Word, field::BasedVectorSpace};

const FELT_BLOCK_INIT_PACKED_CV: PackedChainingValue = [
    [Felt::new_unchecked(encoding::pack_output_pair_u64(
        FELT_BLOCK_INIT_CV[0],
        FELT_BLOCK_INIT_CV[1],
    )); PACKED_LANES],
    [Felt::new_unchecked(encoding::pack_output_pair_u64(
        FELT_BLOCK_INIT_CV[2],
        FELT_BLOCK_INIT_CV[3],
    )); PACKED_LANES],
    [Felt::new_unchecked(encoding::pack_output_pair_u64(
        FELT_BLOCK_INIT_CV[4],
        FELT_BLOCK_INIT_CV[5],
    )); PACKED_LANES],
    [Felt::new_unchecked(encoding::pack_output_pair_u64(
        FELT_BLOCK_INIT_CV[6],
        FELT_BLOCK_INIT_CV[7],
    )); PACKED_LANES],
];

/// Eidos hash construction.
///
/// Byte strings and field-element strings use distinct registered selectors. Field hashing
/// additionally accepts a u32 selector, and both constructions bind the exact input length into
/// the initial chaining value.
/// The `CryptographicHasher<u64, _>` implementation hashes exact 64-bit words; it does not reduce
/// them modulo the Goldilocks field order.
///
/// Digests occupy a 252-bit packed subspace and therefore provide at most 126 bits of generic
/// collision resistance.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Eidos;

impl Eidos {
    /// Compress one complete block under a caller-supplied chaining value.
    ///
    /// This is the raw compression layer underlying the Eidos hash construction. It does not add
    /// domain separation, length binding, padding, or any other message framing. The input CV may
    /// contain arbitrary canonical field elements; only the output CV is restricted to Eidos's
    /// 252-bit packed subspace.
    #[inline]
    pub fn compress(cv: Word, block: [Felt; BLOCK_LEN]) -> Word {
        compression::compress_felt_block(cv, block)
    }

    /// Compress one complete block in each native packed lane.
    ///
    /// Each lane is independent. Like [`Self::compress`], this adds no message framing.
    #[inline]
    pub fn compress_packed(cv: PackedChainingValue, block: PackedBlock) -> PackedChainingValue {
        compression::compress_packed_felt_cv(&cv, &block)
    }

    /// Return all sixteen raw XOF output lanes for one complete block.
    ///
    /// Each `u32` lane is embedded as one field element. This is raw XOF material for a
    /// caller-supplied CV, not an Eidos digest, and no message framing is added.
    #[inline]
    pub fn compress_xof(cv: Word, block: [Felt; BLOCK_LEN]) -> [Felt; 16] {
        Self::compress_xof_lanes(cv, block).map(Felt::from_u32)
    }

    #[inline]
    pub(crate) fn compress_xof_lanes(cv: Word, block: [Felt; BLOCK_LEN]) -> [u32; 16] {
        compression::compress_xof_cv(encoding::word_to_cv(cv), encoding::encode_felt_block(&block))
    }

    /// Construct the seed CV used by the Fiat-Shamir challenger.
    ///
    /// This is one raw compression from the zero CV. The first u32 block lane contains the
    /// registered transcript selector and the remaining fifteen lanes are zero. It is a dedicated
    /// challenger seed construction, not a framed message hash.
    #[inline]
    pub fn transcript_init_cv(selector: u32) -> Word {
        let mut block = [0u32; 16];
        block[0] = selector;
        encoding::output_cv_to_word(compression::compress_cv([0u32; 8], block))
    }

    /// Construct the felt-sequence initial chaining value as a packed word.
    ///
    /// `n` is the total number of felts in the complete message, not the size of the next block.
    #[inline]
    pub fn init_chaining_word(selector: u32, n: u32) -> Word {
        Self::init_chaining_word_with_params(selector, [n, 0, 0])
    }

    /// Construct an initial chaining value from a registered selector and three parameters.
    ///
    /// The selector defines the construction and the meaning of its parameters. Every supplied
    /// value occupies one complete low u32 lane; the corresponding high lane is a fixed masked IV
    /// word.
    #[inline]
    pub fn init_chaining_word_with_params(selector: u32, params: [u32; 3]) -> Word {
        encoding::output_cv_to_word(framing::init_cv(selector, params))
    }

    /// Construct the same felt-sequence initial chaining word in every native packed lane.
    ///
    /// `n` is the total number of felts in each complete message, not the size of the next block.
    #[inline]
    pub fn init_packed_chaining_word(selector: u32, n: u32) -> PackedChainingValue {
        framing::init_packed_cv(selector, [n, 0, 0])
    }

    /// Hash a byte string with the registered byte-string selector.
    pub fn hash(bytes: &[u8]) -> Word {
        let len = u32::try_from(bytes.len()).expect("input too long: byte count must fit in u32");
        let mut cv = framing::init_cv(BYTE_STRING_SELECTOR, [len, 0, 0]);

        if bytes.is_empty() {
            cv = compression::compress_cv(cv, [0; 16]);
        } else {
            #[cfg(target_arch = "aarch64")]
            {
                cv = compress_encoded_blocks(cv, bytes.chunks(64).map(encoding::encode_byte_block));
            }
            #[cfg(not(target_arch = "aarch64"))]
            for chunk in bytes.chunks(64) {
                cv = compression::compress_cv(cv, encoding::encode_byte_block(chunk));
            }
        }

        encoding::output_cv_to_word(cv)
    }

    /// Hash a field-element sequence under selector zero.
    #[inline]
    pub fn hash_elements<E: BasedVectorSpace<Felt>>(elements: &[E]) -> Word {
        Self::hash_elements_in_domain(elements, Felt::ZERO)
    }

    /// Hash a field-element sequence under a caller-supplied selector.
    pub fn hash_elements_in_domain<E: BasedVectorSpace<Felt>>(
        elements: &[E],
        domain: Felt,
    ) -> Word {
        let domain = framing::selector_to_u32(domain);
        let len = elements
            .len()
            .checked_mul(E::DIMENSION)
            .expect("input too long: felt count overflowed usize");
        let iter = elements
            .iter()
            .flat_map(|element| E::as_basis_coefficients_slice(element).iter().copied());
        Word::new(hash_felt_iter_in_domain_with_len(iter, len, domain))
    }

    /// Hash two digest words under selector zero.
    #[inline]
    pub fn merge(values: &[Word; 2]) -> Word {
        compress_digest_pair(values, FELT_BLOCK_INIT_CV)
    }

    /// Hash two packed digest words under selector zero in every native packed lane.
    ///
    /// This is the packed equivalent of [`Self::merge`].
    #[inline]
    pub fn merge_packed(values: &[PackedDigest; 2]) -> PackedDigest {
        let block = array::from_fn(|i| {
            if i < DIGEST_WIDTH {
                values[0][i]
            } else {
                values[1][i - DIGEST_WIDTH]
            }
        });
        Self::compress_packed(FELT_BLOCK_INIT_PACKED_CV, block)
    }

    /// Hash two digest words under a caller-supplied selector.
    #[inline]
    pub fn merge_in_domain(values: &[Word; 2], domain: Felt) -> Word {
        let domain = framing::selector_to_u32(domain);
        let cv = if domain == 0 {
            FELT_BLOCK_INIT_CV
        } else {
            framing::init_cv(domain, [BLOCK_LEN as u32, 0, 0])
        };
        compress_digest_pair(values, cv)
    }

    /// Hash a sequence of digest words under selector zero.
    #[inline]
    pub fn merge_many(values: &[Word]) -> Word {
        Self::hash_elements(Word::words_as_elements(values))
    }
}

#[inline]
fn compress_digest_pair(values: &[Word; 2], cv: [u32; 8]) -> Word {
    encoding::output_cv_to_word(compression::compress_cv(cv, digest_pair_block(values)))
}

#[inline]
fn digest_pair_block(values: &[Word; 2]) -> [u32; 16] {
    array::from_fn(|lane| {
        let felt = values[lane / (2 * DIGEST_WIDTH)][(lane / 2) % DIGEST_WIDTH].as_canonical_u64();
        if lane % 2 == 0 {
            felt as u32
        } else {
            (felt >> 32) as u32
        }
    })
}

#[inline]
fn exact_size_hint<I: Iterator>(iter: &I) -> Option<usize> {
    let (lower, upper) = iter.size_hint();
    upper.filter(|&upper| upper == lower)
}

/// Keep sequential batches bounded independently of the message length.
#[cfg(target_arch = "aarch64")]
fn compress_encoded_blocks(mut cv: [u32; 8], blocks: impl Iterator<Item = [u32; 16]>) -> [u32; 8] {
    let mut batch = [[0; 16]; 8];
    let mut count = 0;
    for block in blocks {
        batch[count] = block;
        count += 1;
        if count == batch.len() {
            cv = compression::compress_blocks(cv, &batch);
            count = 0;
        }
    }
    if count != 0 {
        cv = compression::compress_blocks(cv, &batch[..count]);
    }
    cv
}

/// Batch encoded field blocks while leaving padding and length checks to the scheduler.
#[cfg(target_arch = "aarch64")]
fn fold_encoded_field_blocks<I>(
    iter: I,
    len: usize,
    cv: [u32; 8],
    zero: I::Item,
    encode: impl Fn([I::Item; BLOCK_LEN]) -> [u32; 16],
) -> [u32; 8]
where
    I: Iterator,
    I::Item: Copy,
{
    let mut batch = [[0; 16]; 8];
    let mut count = 0;
    let mut cv = framing::fold_blocks::<BLOCK_LEN, _, _>(iter, len, cv, zero, |mut cv, block| {
        batch[count] = encode(block);
        count += 1;
        if count == batch.len() {
            cv = compression::compress_blocks(cv, &batch);
            count = 0;
        }
        cv
    });
    if count != 0 {
        cv = compression::compress_blocks(cv, &batch[..count]);
    }
    cv
}

fn hash_felt_iter_in_domain_with_len<I>(iter: I, len: usize, domain: u32) -> [Felt; DIGEST_WIDTH]
where
    I: Iterator<Item = Felt>,
{
    let len_u32 = u32::try_from(len).expect("input too long: felt count must fit in u32");
    #[cfg(target_arch = "aarch64")]
    let cv = fold_encoded_field_blocks(
        iter,
        len,
        framing::init_cv(domain, [len_u32, 0, 0]),
        Felt::ZERO,
        |block| encoding::encode_felt_block(&block),
    );
    #[cfg(not(target_arch = "aarch64"))]
    let cv = framing::fold_blocks::<BLOCK_LEN, _, _>(
        iter,
        len,
        framing::init_cv(domain, [len_u32, 0, 0]),
        Felt::ZERO,
        |cv, block| compression::compress_cv(cv, encoding::encode_felt_block(&block)),
    );
    encoding::output_cv_to_word(cv).into()
}

fn hash_u64_iter_with_len<I>(iter: I, len: usize) -> [u64; DIGEST_WIDTH]
where
    I: Iterator<Item = u64>,
{
    let len_u32 = u32::try_from(len).expect("input too long: felt count must fit in u32");
    #[cfg(target_arch = "aarch64")]
    let cv =
        fold_encoded_field_blocks(iter, len, framing::init_cv(0, [len_u32, 0, 0]), 0, |block| {
            encoding::encode_u64_block(&block)
        });
    #[cfg(not(target_arch = "aarch64"))]
    let cv = framing::fold_blocks::<BLOCK_LEN, _, _>(
        iter,
        len,
        framing::init_cv(0, [len_u32, 0, 0]),
        0,
        compression::compress_u64_cv,
    );
    encoding::pack_cv_to_u64s(cv)
}

fn hash_packed_felt_iter_with_len<I>(iter: I, len: usize) -> PackedDigest
where
    I: Iterator<Item = PackedFelt>,
{
    let len_u32 = u32::try_from(len).expect("input too long: felt count must fit in u32");
    framing::fold_blocks::<BLOCK_LEN, _, _>(
        iter,
        len,
        framing::init_packed_cv(0, [len_u32, 0, 0]),
        [Felt::ZERO; PACKED_LANES],
        |cv, block| compression::compress_packed_felt_cv(&cv, &block),
    )
}

fn hash_packed_u64_iter_with_len<I>(iter: I, len: usize) -> [[u64; PACKED_LANES]; DIGEST_WIDTH]
where
    I: Iterator<Item = [u64; PACKED_LANES]>,
{
    let len_u32 = u32::try_from(len).expect("input too long: felt count must fit in u32");
    framing::fold_blocks::<BLOCK_LEN, _, _>(
        iter,
        len,
        framing::init_packed_u64_cv(0, [len_u32, 0, 0]),
        [0; PACKED_LANES],
        |cv, block| compression::compress_packed_u64_cv(&cv, &block),
    )
}

impl CryptographicHasher<Felt, [Felt; DIGEST_WIDTH]> for Eidos {
    fn hash_iter<I>(&self, input: I) -> [Felt; DIGEST_WIDTH]
    where
        I: IntoIterator<Item = Felt>,
    {
        let iter = input.into_iter();
        if let Some(len) = exact_size_hint(&iter) {
            hash_felt_iter_in_domain_with_len(iter, len, 0)
        } else {
            let elements: Vec<Felt> = iter.collect();
            let len = elements.len();
            hash_felt_iter_in_domain_with_len(elements.into_iter(), len, 0)
        }
    }
}

impl CryptographicHasher<u64, [u64; DIGEST_WIDTH]> for Eidos {
    fn hash_iter<I>(&self, input: I) -> [u64; DIGEST_WIDTH]
    where
        I: IntoIterator<Item = u64>,
    {
        let iter = input.into_iter();
        if let Some(len) = exact_size_hint(&iter) {
            hash_u64_iter_with_len(iter, len)
        } else {
            let elements: Vec<u64> = iter.collect();
            let len = elements.len();
            hash_u64_iter_with_len(elements.into_iter(), len)
        }
    }
}

impl CryptographicHasher<PackedFelt, PackedDigest> for Eidos {
    fn hash_iter<I>(&self, input: I) -> PackedDigest
    where
        I: IntoIterator<Item = PackedFelt>,
    {
        let iter = input.into_iter();
        if let Some(len) = exact_size_hint(&iter) {
            hash_packed_felt_iter_with_len(iter, len)
        } else {
            let elements: Vec<PackedFelt> = iter.collect();
            let len = elements.len();
            hash_packed_felt_iter_with_len(elements.into_iter(), len)
        }
    }
}

impl CryptographicHasher<[u64; PACKED_LANES], [[u64; PACKED_LANES]; DIGEST_WIDTH]> for Eidos {
    fn hash_iter<I>(&self, input: I) -> [[u64; PACKED_LANES]; DIGEST_WIDTH]
    where
        I: IntoIterator<Item = [u64; PACKED_LANES]>,
    {
        let iter = input.into_iter();
        if let Some(len) = exact_size_hint(&iter) {
            hash_packed_u64_iter_with_len(iter, len)
        } else {
            let elements: Vec<[u64; PACKED_LANES]> = iter.collect();
            let len = elements.len();
            hash_packed_u64_iter_with_len(elements.into_iter(), len)
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::vec;

    use super::*;
    use crate::hash::eidos::PackedBlock;

    #[test]
    fn digest_pair_block_preserves_word_order_and_input_high_bits() {
        let values = [
            Word::new([
                Felt::new_unchecked(0x8000_0001_0000_0001),
                Felt::new_unchecked(0x4000_0002_0000_0003),
                Felt::new_unchecked(0x2000_0003_0000_0005),
                Felt::new_unchecked(0x1000_0004_0000_0007),
            ]),
            Word::new([
                Felt::new_unchecked(0x0800_0005_0000_000b),
                Felt::new_unchecked(0x0400_0006_0000_000d),
                Felt::new_unchecked(0x0200_0007_0000_0011),
                Felt::new_unchecked(0x0100_0008_0000_0013),
            ]),
        ];

        assert_eq!(
            digest_pair_block(&values),
            [
                1,
                0x8000_0001,
                3,
                0x4000_0002,
                5,
                0x2000_0003,
                7,
                0x1000_0004,
                11,
                0x0800_0005,
                13,
                0x0400_0006,
                17,
                0x0200_0007,
                19,
                0x0100_0008,
            ]
        );
    }

    #[test]
    fn digest_merges_preserve_framing_and_packed_lane_equivalence() {
        let values = [
            Word::new([
                Felt::new_unchecked(0x8000_0001_0000_0001),
                Felt::new_unchecked(0x4000_0002_0000_0003),
                Felt::new_unchecked(0x2000_0003_0000_0005),
                Felt::new_unchecked(0x1000_0004_0000_0007),
            ]),
            Word::new([
                Felt::new_unchecked(0x0800_0005_0000_000b),
                Felt::new_unchecked(0x0400_0006_0000_000d),
                Felt::new_unchecked(0x0200_0007_0000_0011),
                Felt::new_unchecked(0x0100_0008_0000_0013),
            ]),
        ];
        let elements = values.into_iter().flat_map(Word::into_iter).collect::<Vec<_>>();
        let domain = Felt::from_u32(17);
        let expected_merge = Word::new([
            Felt::new_unchecked(7066677778366688579),
            Felt::new_unchecked(2670184074332039235),
            Felt::new_unchecked(8367120510803267708),
            Felt::new_unchecked(4671844698153676469),
        ]);
        let expected_domain_merge = Word::new([
            Felt::new_unchecked(6280005452210828352),
            Felt::new_unchecked(7305477876879022688),
            Felt::new_unchecked(6501408626928269720),
            Felt::new_unchecked(8345300191011544472),
        ]);

        assert_eq!(Eidos::merge(&values), expected_merge);
        assert_eq!(Eidos::merge(&values), Eidos::hash_elements(&elements));
        assert_eq!(Eidos::merge_in_domain(&values, domain), expected_domain_merge);
        assert_eq!(
            Eidos::merge_in_domain(&values, domain),
            Eidos::hash_elements_in_domain(&elements, domain)
        );

        let packed = values.map(|word| array::from_fn(|i| [word[i]; PACKED_LANES]));
        let merged = Eidos::merge_packed(&packed);
        assert_eq!(merged, array::from_fn(|i| [expected_merge[i]; PACKED_LANES]));
    }

    #[test]
    fn sequential_field_batches_preserve_framing_and_exact_iterators() {
        for blocks in [0, 1, 7, 8, 9, 63, 64, 65, 72] {
            for tail in [0, 1, 7] {
                let len = blocks * BLOCK_LEN + tail;
                let values: Vec<u64> =
                    (0..len).map(|i| u64::MAX.wrapping_sub(i as u64 * 0x0101_0101)).collect();
                let felts: Vec<Felt> = values.iter().map(|v| Felt::new_unchecked(v >> 1)).collect();
                for domain in [0, 17] {
                    let initial = framing::init_cv(domain, [len as u32, 0, 0]);
                    let expected = framing::fold_blocks::<BLOCK_LEN, _, _>(
                        felts.iter().copied(),
                        len,
                        initial,
                        Felt::ZERO,
                        |cv, block| {
                            compression::compress_cv(cv, encoding::encode_felt_block(&block))
                        },
                    );
                    assert_eq!(
                        Eidos::hash_elements_in_domain(&felts, Felt::from_u32(domain)),
                        encoding::output_cv_to_word(expected),
                    );
                    if domain == 0 {
                        let actual: [Felt; DIGEST_WIDTH] = Eidos.hash_iter(felts.iter().copied());
                        assert_eq!(Word::new(actual), encoding::output_cv_to_word(expected));
                    }
                }
                let initial = framing::init_cv(0, [len as u32, 0, 0]);
                let expected = framing::fold_blocks::<BLOCK_LEN, _, _>(
                    values.iter().copied(),
                    len,
                    initial,
                    0,
                    compression::compress_u64_cv,
                );
                let actual: [u64; DIGEST_WIDTH] = Eidos.hash_iter(values.iter().copied());
                assert_eq!(actual, encoding::pack_cv_to_u64s(expected));
                #[cfg(target_arch = "aarch64")]
                assert_eq!(
                    fold_encoded_field_blocks(
                        values.iter().copied(),
                        len,
                        initial,
                        0,
                        |block: [u64; BLOCK_LEN]| encoding::encode_u64_block(&block)
                    ),
                    expected,
                );

                // Both over- and underreported exact hints must still be rejected,
                // including when the actual input ends at a batch boundary.
                for claimed in [len.checked_sub(1), Some(len + 1)].into_iter().flatten() {
                    assert!(
                        std::panic::catch_unwind(|| {
                            let _: [Felt; DIGEST_WIDTH] = Eidos.hash_iter(DishonestSizeHint {
                                inner: felts.iter().copied(),
                                claimed,
                            });
                        })
                        .is_err()
                    );
                    assert!(
                        std::panic::catch_unwind(|| {
                            let _: [u64; DIGEST_WIDTH] = Eidos.hash_iter(DishonestSizeHint {
                                inner: values.iter().copied(),
                                claimed,
                            });
                        })
                        .is_err()
                    );
                }
            }
        }
    }

    #[test]
    fn sequential_byte_vectors() {
        for (n, expected) in [
            (
                0,
                [
                    2910656516858685338,
                    4269926152153106528,
                    576084148240214716,
                    4236080967700832008,
                ],
            ),
            (
                64,
                [
                    3569322132172867237,
                    4505987984688213795,
                    501544810337014917,
                    6644984086372658326,
                ],
            ),
            (
                128,
                [
                    5954243955803425906,
                    4571021742501296852,
                    1158949400215543998,
                    5828945230432344913,
                ],
            ),
            (
                512,
                [
                    610729722130186455,
                    2047615770893706848,
                    8180501629483829075,
                    8830705694241315303,
                ],
            ),
            (
                576,
                [
                    5629405759424591611,
                    1670145300985505392,
                    3946491887450433446,
                    2226282959157556185,
                ],
            ),
            (
                577,
                [
                    7993109494051924800,
                    1250336225736444400,
                    7555335408522046248,
                    6545331745750935460,
                ],
            ),
        ] {
            let bytes: Vec<u8> = (0..n).map(|i| i as u8).collect();
            assert_eq!(
                Eidos::hash(&bytes)
                    .as_elements()
                    .iter()
                    .map(|v| v.as_canonical_u64())
                    .collect::<Vec<_>>(),
                expected
            );
        }
    }

    struct LooseSizeHint<I>(I);

    impl<I: Iterator> Iterator for LooseSizeHint<I> {
        type Item = I::Item;

        fn next(&mut self) -> Option<Self::Item> {
            self.0.next()
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (0, None)
        }
    }

    struct DishonestSizeHint<I> {
        inner: I,
        claimed: usize,
    }

    impl<I: Iterator> Iterator for DishonestSizeHint<I> {
        type Item = I::Item;

        fn next(&mut self) -> Option<Self::Item> {
            self.inner.next()
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (self.claimed, Some(self.claimed))
        }
    }

    #[test]
    fn empty_constructions_each_compress_one_zero_block() {
        let byte_cv = framing::init_cv(BYTE_STRING_SELECTOR, [0; 3]);
        let felt_cv = framing::init_cv(0, [0; 3]);
        assert_eq!(
            Eidos::hash(&[]),
            encoding::output_cv_to_word(compression::compress_cv(byte_cv, [0; 16]))
        );
        assert_eq!(
            Eidos::hash_elements::<Felt>(&[]),
            encoding::output_cv_to_word(compression::compress_cv(felt_cv, [0; 16]))
        );
        assert_ne!(Eidos::hash(&[]), Eidos::hash_elements::<Felt>(&[]));
    }

    #[test]
    fn transcript_init_cv_matches_one_raw_compression() {
        let selector = 0x0201u32;
        let mut block = [Felt::ZERO; BLOCK_LEN];
        block[0] = Felt::from_u32(selector);
        assert_eq!(Eidos::transcript_init_cv(selector), Eidos::compress(Word::default(), block));
    }

    #[test]
    fn framed_full_block_matches_manual_init_then_compress() {
        let domain = 17u32;
        let block: [Felt; BLOCK_LEN] =
            array::from_fn(|i| Felt::new_unchecked((i as u64 + 1) * 0x0101_0101));
        let cv = Eidos::init_chaining_word(domain, BLOCK_LEN as u32);

        let framed = Eidos::hash_elements_in_domain(&block, Felt::from_u32(domain));
        assert_eq!(Eidos::compress(cv, block), framed);
        assert_ne!(Eidos::compress(Word::default(), block), framed);
    }

    #[test]
    fn packed_compression_and_merge_match_scalar_lanes() {
        let domain = 17;
        let input_len = (2 * BLOCK_LEN) as u32;
        let packed_cv = Eidos::init_packed_chaining_word(domain, input_len);
        let packed_block: PackedBlock = array::from_fn(|element| {
            array::from_fn(|lane| Felt::new_unchecked((element * 101 + lane * 17 + 3) as u64))
        });
        let packed = Eidos::compress_packed(packed_cv, packed_block);
        let packed_values: [PackedDigest; 2] = [
            array::from_fn(|word| packed_block[word]),
            array::from_fn(|word| packed_block[DIGEST_WIDTH + word]),
        ];
        let packed_merged = Eidos::merge_packed(&packed_values);

        for lane in 0..PACKED_LANES {
            let scalar_cv = Eidos::init_chaining_word(domain, input_len);
            let scalar_block = array::from_fn(|element| packed_block[element][lane]);
            let scalar = Eidos::compress(scalar_cv, scalar_block);
            let actual = Word::new(array::from_fn(|word| packed[word][lane]));
            assert_eq!(actual, scalar, "packed lane {lane} diverged");

            let scalar_values = [
                Word::new(array::from_fn(|word| packed_values[0][word][lane])),
                Word::new(array::from_fn(|word| packed_values[1][word][lane])),
            ];
            let actual = Word::new(array::from_fn(|word| packed_merged[word][lane]));
            assert_eq!(actual, Eidos::merge(&scalar_values), "packed merge lane {lane} diverged");
        }
    }

    #[test]
    fn all_hasher_representations_match_at_block_boundaries() {
        for len in [0, 1, 7, 8, 9, 15, 16, 17] {
            let felts: Vec<Felt> =
                (0..len).map(|i| Felt::new_unchecked((i as u64 + 1) * 17)).collect();
            let u64s: Vec<u64> = felts.iter().map(Felt::as_canonical_u64).collect();
            let felt_digest = <Eidos as CryptographicHasher<Felt, [Felt; DIGEST_WIDTH]>>::hash_iter(
                &Eidos,
                felts.iter().copied(),
            );
            let u64_digest = <Eidos as CryptographicHasher<u64, [u64; DIGEST_WIDTH]>>::hash_iter(
                &Eidos,
                u64s.iter().copied(),
            );
            assert_eq!(felt_digest, u64_digest.map(Felt::new_unchecked));

            let packed_felts: Vec<PackedFelt> =
                felts.iter().map(|felt| [*felt; PACKED_LANES]).collect();
            let packed_u64s: Vec<[u64; PACKED_LANES]> =
                u64s.iter().map(|value| [*value; PACKED_LANES]).collect();
            let packed_felt_digest =
                <Eidos as CryptographicHasher<PackedFelt, PackedDigest>>::hash_iter(
                    &Eidos,
                    packed_felts,
                );
            let packed_u64_digest = <Eidos as CryptographicHasher<
                [u64; PACKED_LANES],
                [[u64; PACKED_LANES]; DIGEST_WIDTH],
            >>::hash_iter(&Eidos, packed_u64s);

            for lane in 0..PACKED_LANES {
                assert_eq!(
                    array::from_fn::<_, DIGEST_WIDTH, _>(|word| packed_felt_digest[word][lane]),
                    felt_digest,
                );
                assert_eq!(
                    array::from_fn::<_, DIGEST_WIDTH, _>(|word| packed_u64_digest[word][lane]),
                    u64_digest,
                );
            }
        }
    }

    #[test]
    fn loose_size_hints_match_exact_iterators_for_all_representations() {
        let felts: Vec<Felt> = (0..17).map(|i| Felt::new_unchecked((i as u64 + 1) * 17)).collect();
        let u64s: Vec<u64> = felts.iter().map(Felt::as_canonical_u64).collect();
        let packed_felts: Vec<PackedFelt> =
            felts.iter().map(|felt| [*felt; PACKED_LANES]).collect();
        let packed_u64s: Vec<[u64; PACKED_LANES]> =
            u64s.iter().map(|value| [*value; PACKED_LANES]).collect();

        assert_eq!(
            Eidos.hash_iter(felts.iter().copied()),
            Eidos.hash_iter(LooseSizeHint(felts.into_iter())),
        );
        assert_eq!(
            <Eidos as CryptographicHasher<u64, [u64; DIGEST_WIDTH]>>::hash_iter(
                &Eidos,
                u64s.iter().copied(),
            ),
            <Eidos as CryptographicHasher<u64, [u64; DIGEST_WIDTH]>>::hash_iter(
                &Eidos,
                LooseSizeHint(u64s.into_iter()),
            ),
        );
        assert_eq!(
            <Eidos as CryptographicHasher<PackedFelt, PackedDigest>>::hash_iter(
                &Eidos,
                packed_felts.iter().copied(),
            ),
            <Eidos as CryptographicHasher<PackedFelt, PackedDigest>>::hash_iter(
                &Eidos,
                LooseSizeHint(packed_felts.into_iter()),
            ),
        );
        assert_eq!(
            <Eidos as CryptographicHasher<
                [u64; PACKED_LANES],
                [[u64; PACKED_LANES]; DIGEST_WIDTH],
            >>::hash_iter(&Eidos, packed_u64s.iter().copied()),
            <Eidos as CryptographicHasher<
                [u64; PACKED_LANES],
                [[u64; PACKED_LANES]; DIGEST_WIDTH],
            >>::hash_iter(&Eidos, LooseSizeHint(packed_u64s.into_iter())),
        );
    }

    #[test]
    #[should_panic(expected = "iterator yielded a different length than its size_hint")]
    fn dishonest_exact_size_hint_is_rejected() {
        let iter = DishonestSizeHint {
            inner: [Felt::ONE, Felt::ONE].into_iter(),
            claimed: 3,
        };
        let _: [Felt; DIGEST_WIDTH] = Eidos.hash_iter(iter);
    }

    #[test]
    fn hash_elements_is_deterministic() {
        let elements = vec![Felt::new_unchecked(1), Felt::new_unchecked(2), Felt::new_unchecked(3)];
        assert_eq!(Eidos::hash_elements(&elements), Eidos::hash_elements(&elements));
    }
}
