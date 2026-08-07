//! Factory for per-order encodings and registry leaves over one factored composition.
//!
//! Registry construction visits every proof ordering of a multi-AIR composition. This
//! factory builds the order-invariant work exactly once — the factored circuit, the
//! sponge state after absorbing the constants section, and the common-section digest —
//! so that each ordering costs only its shuffle bytes plus a short resumed hash
//! ([`FactoredCircuitFactory::leaf_for_order`]), or one assembly plus that same resumed
//! hash when the full instruction stream is needed
//! ([`FactoredCircuitFactory::circuit_for_order`]).
//!
//! The registry leaf of an ordering is `merge(H(constants | shuffle), H(common))` over
//! the two `adv_pipe`-aligned stream segments.

use miden_core::{Felt, Word, crypto::hash::Poseidon2};
use miden_crypto::{
    field::{ExtensionField, Field},
    hash::poseidon2::Poseidon2Permutation256,
    stark::symmetric::Permutation,
};
use miden_field::{PackedValue, PrimeCharacteristicRing};

use crate::{
    AceError, EXT_DEGREE, encode::EncodedCircuit, factored::ShuffleEncodeBuffer,
    pipeline::FactoredMultiAirCircuit,
};

/// Poseidon2 sponge rate in base-field elements.
const RATE_WIDTH: usize = Poseidon2::RATE_RANGE.end - Poseidon2::RATE_RANGE.start;

/// Packed base-field element of the platform's SIMD backend.
type PackedFelt = <Felt as Field>::Packing;

/// Number of proof orders [`FactoredCircuitFactory::leaves_for_orders`] hashes per
/// packed Poseidon2 permutation (1 on backends without a packed implementation).
pub const LEAF_LANES: usize = <PackedFelt as PackedValue>::WIDTH;

/// Reusable scratch for [`FactoredCircuitFactory::leaves_for_orders`].
#[derive(Default)]
pub struct PackedLeafScratch {
    buffer: ShuffleEncodeBuffer,
    streams: Vec<Vec<Felt>>,
}

impl PackedLeafScratch {
    /// Create an empty scratch.
    pub fn new() -> Self {
        Self::default()
    }
}

/// One proof order's encoded circuit plus its stream-segment commitments.
#[derive(Clone, Debug)]
pub struct FactoredEncodedCircuit {
    /// The encoded instruction stream and its node counts.
    pub encoded: EncodedCircuit,
    /// Length in felts of the per-order stream prefix (constants + shuffle section).
    pub shuffle_prefix_len: usize,
    /// Poseidon2 digest of the per-order prefix.
    pub shuffle_commitment: Word,
    /// Poseidon2 digest of the order-invariant common section.
    pub common_commitment: Word,
    /// Registry leaf and advice-map key: `merge(shuffle_commitment, common_commitment)`.
    pub commitment: Word,
}

/// Factory caching the order-invariant parts of a factored multi-AIR composition.
pub struct FactoredCircuitFactory<EF> {
    factored: FactoredMultiAirCircuit<EF>,
    /// Sponge state after absorbing the constants section.
    ///
    /// The constants section is byte-identical for every proof order and a whole number
    /// of rate blocks, and the sponge's length binding depends only on `total_len %
    /// RATE_WIDTH` (identical across orders because all stream sections are
    /// rate-aligned), so hashing a per-order prefix may resume from this state and
    /// absorb only the shuffle section.
    constants_state: [Felt; Poseidon2::STATE_WIDTH],
    /// Felt length of the constants section absorbed into `constants_state`.
    const_felts: usize,
    /// Digest of the order-invariant common section, computed once.
    common_commitment: Word,
}

impl<EF> FactoredCircuitFactory<EF>
where
    EF: ExtensionField<Felt>,
{
    /// Build the factory, fixing the order-invariant stream sections.
    ///
    /// Encodes the canonical (identity) order once to fix the constants and common
    /// sections, then proves the encode-only leaf path against that assembled stream on
    /// the deployed composition: the canonical order's shuffle window must match byte
    /// for byte, and the resumed sponge must reproduce the digest of the full prefix.
    /// Divergence between the two paths is configuration-dependent (it hides in the
    /// padding arithmetic), so a fixture test elsewhere cannot stand in for this check.
    pub fn new(factored: FactoredMultiAirCircuit<EF>) -> Result<Self, AceError> {
        let canonical: Vec<usize> = (0..factored.num_airs()).collect();
        let circuit = factored.circuit_for_order(&canonical)?;
        let encoded = circuit.to_ace()?;
        let instructions = encoded.instructions();
        let const_felts = encoded.num_constants() * EXT_DEGREE;
        let prefix_len = const_felts + factored.num_shuffle_ops();
        if !const_felts.is_multiple_of(RATE_WIDTH)
            || !prefix_len.is_multiple_of(RATE_WIDTH)
            || prefix_len >= instructions.len()
        {
            return Err(AceError::InvalidInputLayout {
                message: "ACE stream sections must be rate-aligned for prefix resumption".into(),
            });
        }

        let mut constants_state = [<Felt as PrimeCharacteristicRing>::ZERO; Poseidon2::STATE_WIDTH];
        absorb_rate_blocks(&mut constants_state, &instructions[..const_felts]);
        let common_commitment = Poseidon2::hash_elements(&instructions[prefix_len..]);

        let mut buffer = ShuffleEncodeBuffer::new();
        let fast = factored.encode_shuffle_section_for_order(&canonical, &mut buffer)?;
        if fast != &instructions[const_felts..prefix_len] {
            return Err(AceError::InvalidInputLayout {
                message: "encode-only shuffle section diverges from the assembled stream".into(),
            });
        }
        let mut resumed = constants_state;
        absorb_rate_blocks(&mut resumed, fast);
        let resumed_prefix =
            Word::new(resumed[Poseidon2::RATE0_RANGE].try_into().expect("digest is one word"));
        if resumed_prefix != Poseidon2::hash_elements(&instructions[..prefix_len]) {
            return Err(AceError::InvalidInputLayout {
                message: "resumed prefix hash diverges from hashing the full prefix".into(),
            });
        }

        Ok(Self {
            factored,
            constants_state,
            const_felts,
            common_commitment,
        })
    }

    /// The factored composition this factory serves.
    pub fn factored(&self) -> &FactoredMultiAirCircuit<EF> {
        &self.factored
    }

    /// Felt length of the order-invariant constants section.
    pub fn const_felts(&self) -> usize {
        self.const_felts
    }

    /// Compute the registry leaf for one proof order without assembling its circuit.
    ///
    /// Encodes only the shuffle section into `buffer` and resumes the cached
    /// post-constants sponge state, so a caller enumerating every ordering pays per
    /// leaf only the per-order bytes and their hash — this is what makes an `n!`-leaf
    /// registry build feasible. Equality with [`Self::circuit_for_order`]'s
    /// `commitment` is pinned at construction (canonical order) and must be re-pinned
    /// per order wherever a registry is minted.
    pub fn leaf_for_order(
        &self,
        proof_order: &[usize],
        buffer: &mut ShuffleEncodeBuffer,
    ) -> Result<Word, AceError> {
        let shuffle = self.factored.encode_shuffle_section_for_order(proof_order, buffer)?;
        let mut state = self.constants_state;
        absorb_rate_blocks(&mut state, shuffle);
        let shuffle_commitment =
            Word::new(state[Poseidon2::RATE0_RANGE].try_into().expect("digest is one word"));
        Ok(Poseidon2::merge(&[shuffle_commitment, self.common_commitment]))
    }

    /// Compute registry leaves for a batch of proof orders, hashing `LEAF_LANES`
    /// orders per packed Poseidon2 permutation.
    ///
    /// Produces exactly the leaves [`Self::leaf_for_order`] produces, in order — the
    /// shuffle sections of every proof order have identical length, which is what makes
    /// lane-lockstep absorption sound. Chunks shorter than `LEAF_LANES` (the batch
    /// tail) pad unused lanes with the last order and discard the duplicates, so the
    /// packed path is the only code path. Equality with the scalar path is pinned by
    /// `packed_leaves_match_the_scalar_path` and, wherever a registry is minted, by the
    /// per-order dual-path check (whose assembled side hashes scalar).
    pub fn leaves_for_orders(
        &self,
        orders: &[&[usize]],
        scratch: &mut PackedLeafScratch,
        out: &mut Vec<Word>,
    ) -> Result<(), AceError> {
        scratch.streams.resize_with(LEAF_LANES, Vec::new);
        for chunk in orders.chunks(LEAF_LANES) {
            for lane in 0..LEAF_LANES {
                // Tail lanes repeat the last real order; their outputs are discarded.
                let order = chunk.get(lane).copied().unwrap_or(chunk[chunk.len() - 1]);
                let shuffle =
                    self.factored.encode_shuffle_section_for_order(order, &mut scratch.buffer)?;
                scratch.streams[lane].clear();
                scratch.streams[lane].extend_from_slice(shuffle);
            }

            // Resume the (order-invariant) post-constants sponge state in every lane and
            // absorb the per-lane shuffle sections in lockstep.
            let mut state: [PackedFelt; Poseidon2::STATE_WIDTH] = core::array::from_fn(|e| {
                let mut packed = <PackedFelt as PrimeCharacteristicRing>::ZERO;
                packed.as_slice_mut().fill(self.constants_state[e]);
                packed
            });
            // Rate alignment is established at construction; assert rather than debug_assert
            // so a miscount cannot silently truncate a hashed block in a release build.
            assert!(
                scratch.streams[0].len().is_multiple_of(RATE_WIDTH),
                "shuffle streams must be rate-aligned"
            );
            let blocks = scratch.streams[0].len() / RATE_WIDTH;
            for block in 0..blocks {
                for i in 0..RATE_WIDTH {
                    let elem = &mut state[Poseidon2::RATE_RANGE.start + i];
                    for lane in 0..LEAF_LANES {
                        elem.as_slice_mut()[lane] = scratch.streams[lane][block * RATE_WIDTH + i];
                    }
                }
                Poseidon2Permutation256.permute_mut(&mut state);
            }

            // Batched `Poseidon2::merge(shuffle_commitment, common_commitment)`: rate =
            // the two digests, capacity zero, one permutation, digest = first rate word.
            let mut merge_state: [PackedFelt; Poseidon2::STATE_WIDTH] =
                core::array::from_fn(|_| <PackedFelt as PrimeCharacteristicRing>::ZERO);
            for i in 0..4 {
                merge_state[i] = state[Poseidon2::RATE0_RANGE.start + i];
                let mut common = <PackedFelt as PrimeCharacteristicRing>::ZERO;
                common.as_slice_mut().fill(self.common_commitment[i]);
                merge_state[4 + i] = common;
            }
            Poseidon2Permutation256.permute_mut(&mut merge_state);

            for lane in 0..chunk.len() {
                let leaf: [Felt; 4] = core::array::from_fn(|i| merge_state[i].as_slice()[lane]);
                out.push(Word::new(leaf));
            }
        }
        Ok(())
    }

    /// Assemble, encode, and hash the circuit for one proof order.
    ///
    /// Only the shuffle section is hashed live (resuming from the cached post-constants
    /// sponge state); the common-section digest is reused. The resulting commitments
    /// are definitionally equal to hashing the full stream segments, which the caller's
    /// segment tests pin per order.
    pub fn circuit_for_order(
        &self,
        proof_order: &[usize],
    ) -> Result<FactoredEncodedCircuit, AceError> {
        let circuit = self.factored.circuit_for_order(proof_order)?;
        let encoded = circuit.to_ace()?;
        let instructions = encoded.instructions();
        let stream_len = encoded.size_in_felt();
        if stream_len != instructions.len() {
            return Err(AceError::InvalidInputLayout {
                message: format!(
                    "ACE circuit stream length ({stream_len}) does not match instruction count \
                     ({})",
                    instructions.len()
                ),
            });
        }
        let shuffle_prefix_len = self.const_felts + self.factored.num_shuffle_ops();
        if encoded.num_constants() * EXT_DEGREE != self.const_felts
            || !stream_len.is_multiple_of(RATE_WIDTH)
            || shuffle_prefix_len >= stream_len
        {
            return Err(AceError::InvalidInputLayout {
                message: "assembled ACE stream does not match the factored section layout".into(),
            });
        }

        let mut state = self.constants_state;
        absorb_rate_blocks(&mut state, &instructions[self.const_felts..shuffle_prefix_len]);
        let shuffle_commitment =
            Word::new(state[Poseidon2::RATE0_RANGE].try_into().expect("digest is one word"));
        let common_commitment = self.common_commitment;
        let commitment = Poseidon2::merge(&[shuffle_commitment, common_commitment]);

        Ok(FactoredEncodedCircuit {
            encoded,
            shuffle_prefix_len,
            shuffle_commitment,
            common_commitment,
            commitment,
        })
    }
}

/// Absorb whole rate blocks into a Poseidon2 sponge state.
fn absorb_rate_blocks(state: &mut [Felt; Poseidon2::STATE_WIDTH], elements: &[Felt]) {
    // `chunks_exact` would silently drop a trailing partial block, yielding a wrong digest;
    // assert rather than debug_assert so a miscount cannot survive a release build.
    assert!(
        elements.len().is_multiple_of(RATE_WIDTH),
        "sponge absorption requires whole rate blocks"
    );
    for block in elements.chunks_exact(RATE_WIDTH) {
        state[Poseidon2::RATE_RANGE].copy_from_slice(block);
        Poseidon2::apply_permutation(state);
    }
}
