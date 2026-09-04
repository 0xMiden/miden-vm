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
        Self::compress_packed(framing::init_packed_cv(0, [BLOCK_LEN as u32, 0, 0]), block)
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
    let block: [Felt; BLOCK_LEN] = array::from_fn(|i| {
        if i < DIGEST_WIDTH {
            values[0][i]
        } else {
            values[1][i - DIGEST_WIDTH]
        }
    });
    encoding::output_cv_to_word(compression::compress_cv(cv, encoding::encode_felt_block(&block)))
}

#[inline]
fn exact_size_hint<I: Iterator>(iter: &I) -> Option<usize> {
    let (lower, upper) = iter.size_hint();
    upper.filter(|&upper| upper == lower)
}

fn hash_felt_iter_in_domain_with_len<I>(iter: I, len: usize, domain: u32) -> [Felt; DIGEST_WIDTH]
where
    I: Iterator<Item = Felt>,
{
    let len_u32 = u32::try_from(len).expect("input too long: felt count must fit in u32");
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
    use alloc::vec;

    use super::*;
    use crate::hash::eidos::PackedBlock;

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
