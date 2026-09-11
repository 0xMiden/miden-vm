//! The framed Eidos hash construction.

use alloc::vec::Vec;
use core::array;

use p3_symmetric::CryptographicHasher;

use super::{
    BLOCK_LEN, DIGEST_WIDTH, PACKED_LANES, PackedBlock, PackedChainingValue, PackedDigest,
    PackedFelt, compression,
    domain::{ByteString, EidosDomain, FeltSequence, Transcript},
    domains::{GENERIC_BYTE_STRING, GENERIC_FELT_SEQUENCE},
    encoding,
    framing::{self, GENERIC_FELT_TAG, MERKLE_NODE_INIT_CV},
};
use crate::{Felt, Word, field::BasedVectorSpace};

/// Eidos hash construction.
///
/// Byte strings and field-element strings use distinct typed, registered domains. Both
/// constructions bind the exact input length into the initial chaining value. The fixed
/// two-to-one Merkle compression exposed by [`Self::merge`] is the sole reserved zero-tag
/// construction and is deliberately distinct from ordinary Felt-sequence hashing.
/// The `CryptographicHasher<u64, _>` implementations are bit-level adapters for the generic
/// Felt-sequence construction. Canonical Goldilocks encodings produce exactly the same digest as
/// their `Felt` counterparts. Other `u64` values are split into their two limbs without reduction;
/// this deterministic extension is not a separate registered message domain.
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

    /// Compress one complete block in each packed lane.
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

    /// Construct the framed initial CV used by a Fiat-Shamir challenger.
    ///
    /// The registered transcript tag occupies the domain lane and all three parameter lanes are
    /// zero. The transcript's subsequent absorb and squeeze schedule is defined by its domain.
    #[inline]
    pub fn transcript_init_cv<D>(domain: D) -> Word
    where
        D: EidosDomain<Encoding = Transcript>,
    {
        Self::init_chaining_word_with_params(domain, [0; 3])
    }

    /// Construct an initial chaining word with `param0` in the first parameter lane.
    ///
    /// The remaining two parameter lanes are zero. Standard Felt- and byte-sequence domains use
    /// `param0` for the complete logical input length; custom domains define it in their registry
    /// schema.
    #[inline]
    pub fn init_chaining_word<D: EidosDomain>(domain: D, param0: u32) -> Word {
        Self::init_chaining_word_with_params(domain, [param0, 0, 0])
    }

    /// Construct an initial chaining value from a registered domain tag and three parameters.
    ///
    /// The domain defines the construction and the meaning of its parameters. Every supplied
    /// value occupies one complete low u32 lane; the corresponding high lane is a fixed masked IV
    /// word.
    #[inline]
    pub fn init_chaining_word_with_params<D: EidosDomain>(_: D, params: [u32; 3]) -> Word {
        Self::init_chaining_word_with_tag(D::TAG, params)
    }

    /// Construct an initial chaining value from a structurally valid runtime tag and three
    /// parameters.
    ///
    /// This is the dynamic counterpart of [`Self::init_chaining_word_with_params`] for registries
    /// such as deferred precompiles, where the concrete domain is selected at runtime. Constructing
    /// a [`super::DomainTag`] establishes only its structural and namespace rules; the caller
    /// remains responsible for checking membership in the relevant owner registry and enforcing
    /// that domain's parameter and payload schema.
    #[inline]
    pub fn init_chaining_word_with_tag(tag: super::DomainTag, params: [u32; 3]) -> Word {
        encoding::output_cv_to_word(framing::init_cv(tag.as_u32(), params))
    }

    /// Construct the same one-parameter initial chaining word in every packed lane.
    ///
    /// The interpretation of `param0` is defined by the registered domain.
    #[inline]
    pub fn init_packed_chaining_word<D: EidosDomain>(_: D, param0: u32) -> PackedChainingValue {
        framing::init_packed_cv(D::TAG.as_u32(), [param0, 0, 0])
    }

    /// Hash a byte string with the registered generic byte-string domain.
    ///
    /// # Panics
    ///
    /// Panics if the byte length does not fit in `u32`.
    #[inline]
    pub fn hash(bytes: &[u8]) -> Word {
        Self::hash_in_domain(bytes, GENERIC_BYTE_STRING)
    }

    /// Hash a byte string under a typed byte-string domain.
    ///
    /// A Felt-sequence or custom-schedule domain cannot be passed to this function.
    ///
    /// # Panics
    ///
    /// Panics if the byte length does not fit in `u32`.
    pub fn hash_in_domain<D>(bytes: &[u8], _: D) -> Word
    where
        D: EidosDomain<Encoding = ByteString>,
    {
        let len = u32::try_from(bytes.len()).expect("input too long: byte count must fit in u32");
        let mut cv = framing::init_cv(D::TAG.as_u32(), [len, 0, 0]);

        if bytes.is_empty() {
            cv = compression::compress_cv(cv, [0; 16]);
        } else {
            for chunk in bytes.chunks(64) {
                cv = compression::compress_cv(cv, encoding::encode_byte_block(chunk));
            }
        }

        encoding::output_cv_to_word(cv)
    }

    /// Hash a field-element sequence under the registered generic Felt-sequence domain.
    ///
    /// # Panics
    ///
    /// Panics if the flattened Felt length overflows `usize` or does not fit in `u32`.
    #[inline]
    pub fn hash_elements<E: BasedVectorSpace<Felt>>(elements: &[E]) -> Word {
        Self::hash_elements_in_domain(elements, GENERIC_FELT_SEQUENCE)
    }

    /// Hash a field-element sequence under a typed Felt-sequence domain.
    ///
    /// A byte-string or custom-schedule domain cannot be passed to this function.
    ///
    /// # Panics
    ///
    /// Panics if the flattened Felt length overflows `usize` or does not fit in `u32`.
    ///
    /// ```compile_fail
    /// use miden_crypto::{Felt, hash::eidos::{Eidos, domains::GENERIC_BYTE_STRING}};
    ///
    /// let values = [Felt::ZERO];
    /// let _ = Eidos::hash_elements_in_domain(&values, GENERIC_BYTE_STRING);
    /// ```
    ///
    /// Raw field elements are not domain declarations either:
    ///
    /// ```compile_fail
    /// use miden_crypto::{Felt, hash::eidos::Eidos};
    ///
    /// let values = [Felt::ZERO];
    /// let byte_tag = Felt::new_unchecked(0x0000_0301);
    /// let _ = Eidos::hash_elements_in_domain(&values, byte_tag);
    /// ```
    pub fn hash_elements_in_domain<E, D>(elements: &[E], _: D) -> Word
    where
        E: BasedVectorSpace<Felt>,
        D: EidosDomain<Encoding = FeltSequence>,
    {
        let len = elements
            .len()
            .checked_mul(E::DIMENSION)
            .expect("input too long: felt count overflowed usize");
        let iter = elements
            .iter()
            .flat_map(|element| E::as_basis_coefficients_slice(element).iter().copied());
        Word::new(hash_felt_iter_in_domain_with_len(iter, len, D::TAG.as_u32()))
    }

    /// Compress two digest words as one reserved Merkle inner node.
    ///
    /// This fixed, one-block construction uses the all-zero domain tuple and is intentionally not
    /// equivalent to [`Self::hash_elements`] over the same eight Felts.
    #[inline]
    pub fn merge(values: &[Word; 2]) -> Word {
        compress_digest_pair(values, MERKLE_NODE_INIT_CV)
    }

    /// Return the initial chaining word reserved for Merkle inner-node compression.
    ///
    /// Its four injected framing lanes are all zero. It is exposed for implementations which
    /// schedule [`Self::merge`] through a separate compression engine; ordinary callers should
    /// use [`Self::merge`] directly.
    #[inline]
    pub fn merkle_node_init_chaining_word() -> Word {
        encoding::output_cv_to_word(MERKLE_NODE_INIT_CV)
    }

    /// Compress two packed digest words as reserved Merkle inner nodes in every packed lane.
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
        Self::compress_packed(framing::init_packed_cv(0, [0; 3]), block)
    }

    /// Hash two digest words under a typed Felt-sequence domain.
    #[inline]
    pub fn merge_in_domain<D>(values: &[Word; 2], _: D) -> Word
    where
        D: EidosDomain<Encoding = FeltSequence>,
    {
        let cv = framing::init_cv(D::TAG.as_u32(), [BLOCK_LEN as u32, 0, 0]);
        compress_digest_pair(values, cv)
    }

    /// Hash a sequence of digest words under the generic Felt-sequence domain.
    ///
    /// # Panics
    ///
    /// Panics if the flattened Felt length does not fit in `u32`.
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
        framing::init_cv(GENERIC_FELT_TAG, [len_u32, 0, 0]),
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
    let cv = framing::fold_blocks::<BLOCK_LEN, _, _>(
        iter,
        len,
        framing::init_packed_u32_cv(GENERIC_FELT_TAG, [len_u32, 0, 0]),
        [Felt::ZERO; PACKED_LANES],
        |cv, block| compression::compress_packed_felt_block(&cv, &block),
    );
    encoding::pack_cv_to_felts(cv)
}

fn hash_packed_u64_iter_with_len<I>(iter: I, len: usize) -> [[u64; PACKED_LANES]; DIGEST_WIDTH]
where
    I: Iterator<Item = [u64; PACKED_LANES]>,
{
    let len_u32 = u32::try_from(len).expect("input too long: felt count must fit in u32");
    let cv = framing::fold_blocks::<BLOCK_LEN, _, _>(
        iter,
        len,
        framing::init_packed_u32_cv(GENERIC_FELT_TAG, [len_u32, 0, 0]),
        [0; PACKED_LANES],
        |cv, block| compression::compress_packed_u64_block(&cv, &block),
    );
    compression::pack_packed_u64_cv(&cv)
}

impl CryptographicHasher<Felt, [Felt; DIGEST_WIDTH]> for Eidos {
    fn hash_iter<I>(&self, input: I) -> [Felt; DIGEST_WIDTH]
    where
        I: IntoIterator<Item = Felt>,
    {
        let iter = input.into_iter();
        if let Some(len) = exact_size_hint(&iter) {
            hash_felt_iter_in_domain_with_len(iter, len, GENERIC_FELT_TAG)
        } else {
            let elements: Vec<Felt> = iter.collect();
            let len = elements.len();
            hash_felt_iter_in_domain_with_len(elements.into_iter(), len, GENERIC_FELT_TAG)
        }
    }

    #[inline]
    fn hash_slice(&self, input: &[Felt]) -> [Felt; DIGEST_WIDTH] {
        hash_felt_iter_in_domain_with_len(input.iter().copied(), input.len(), GENERIC_FELT_TAG)
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

    #[inline]
    fn hash_slice(&self, input: &[u64]) -> [u64; DIGEST_WIDTH] {
        hash_u64_iter_with_len(input.iter().copied(), input.len())
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

    #[inline]
    fn hash_slice(&self, input: &[PackedFelt]) -> PackedDigest {
        hash_packed_felt_iter_with_len(input.iter().copied(), input.len())
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

    #[inline]
    fn hash_slice(&self, input: &[[u64; PACKED_LANES]]) -> [[u64; PACKED_LANES]; DIGEST_WIDTH] {
        hash_packed_u64_iter_with_len(input.iter().copied(), input.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::eidos::{
        DomainTag, DomainVersion, PackedBlock,
        domain::namespace,
        domains::{GenericByteStringDomain, GenericFeltSequenceDomain},
    };

    #[derive(Debug, Copy, Clone)]
    struct TestTranscriptDomain;

    impl EidosDomain for TestTranscriptDomain {
        type Encoding = Transcript;

        const NAME: &'static str = "TEST_TRANSCRIPT";
        const TAG: DomainTag =
            DomainTag::new(namespace::MIDEN_VM, 0xffff, DomainVersion::numbered(1));
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
        let byte_cv = framing::init_cv(GenericByteStringDomain::TAG.as_u32(), [0; 3]);
        let felt_cv = framing::init_cv(GenericFeltSequenceDomain::TAG.as_u32(), [0; 3]);
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
    fn transcript_init_cv_uses_registered_framing() {
        assert_eq!(
            Eidos::transcript_init_cv(TestTranscriptDomain),
            Eidos::init_chaining_word_with_params(TestTranscriptDomain, [0; 3]),
        );
    }

    #[test]
    fn runtime_tag_initializer_matches_the_typed_initializer() {
        let params = [1, 2, 3];
        assert_eq!(
            Eidos::init_chaining_word_with_tag(TestTranscriptDomain::TAG, params),
            Eidos::init_chaining_word_with_params(TestTranscriptDomain, params),
        );
    }

    #[test]
    fn framed_full_block_matches_manual_init_then_compress() {
        let block: [Felt; BLOCK_LEN] =
            array::from_fn(|i| Felt::new_unchecked((i as u64 + 1) * 0x0101_0101));
        let cv = Eidos::init_chaining_word(GENERIC_FELT_SEQUENCE, BLOCK_LEN as u32);

        let framed = Eidos::hash_elements_in_domain(&block, GENERIC_FELT_SEQUENCE);
        assert_eq!(Eidos::compress(cv, block), framed);
        assert_ne!(Eidos::compress(Word::default(), block), framed);
    }

    #[test]
    fn packed_compression_and_merge_match_scalar_lanes() {
        let input_len = (2 * BLOCK_LEN) as u32;
        let packed_cv = Eidos::init_packed_chaining_word(GENERIC_FELT_SEQUENCE, input_len);
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
            let scalar_cv = Eidos::init_chaining_word(GENERIC_FELT_SEQUENCE, input_len);
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
            assert_eq!(felt_digest, Eidos.hash_slice(&felts));
            let u64_digest = <Eidos as CryptographicHasher<u64, [u64; DIGEST_WIDTH]>>::hash_iter(
                &Eidos,
                u64s.iter().copied(),
            );
            assert_eq!(u64_digest, Eidos.hash_slice(&u64s));
            assert_eq!(felt_digest, u64_digest.map(Felt::new_unchecked));

            let packed_felts: Vec<PackedFelt> =
                felts.iter().map(|felt| [*felt; PACKED_LANES]).collect();
            let packed_u64s: Vec<[u64; PACKED_LANES]> =
                u64s.iter().map(|value| [*value; PACKED_LANES]).collect();
            let packed_felt_digest =
                <Eidos as CryptographicHasher<PackedFelt, PackedDigest>>::hash_iter(
                    &Eidos,
                    packed_felts.iter().copied(),
                );
            let packed_u64_digest = <Eidos as CryptographicHasher<
                [u64; PACKED_LANES],
                [[u64; PACKED_LANES]; DIGEST_WIDTH],
            >>::hash_iter(&Eidos, packed_u64s.iter().copied());
            assert_eq!(packed_felt_digest, Eidos.hash_slice(&packed_felts));
            assert_eq!(packed_u64_digest, Eidos.hash_slice(&packed_u64s));

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
}
