//! Factory for per-order encodings and registry leaves over one factored composition.
//!
//! Registry construction visits every proof ordering of a multi-AIR composition. This
//! factory builds the order-invariant work exactly once — the factored circuit, the
//! chaining state after absorbing the constants section, and the common-section digest —
//! so that each ordering costs only its shuffle bytes plus a short resumed hash
//! ([`FactoredCircuitFactory::leaf_for_order`]), or one assembly plus that same resumed
//! hash when the full instruction stream is needed
//! ([`FactoredCircuitFactory::circuit_for_order`]).
//!
//! The registry leaf of an ordering is `merge(H(constants | shuffle), H(common))` over
//! the two `adv_pipe`-aligned stream segments.

use miden_core::{Felt, Word, crypto::hash::Eidos};
use miden_crypto::{
    field::ExtensionField,
    hash::eidos::{BLOCK_LEN, PACKED_LANES, PackedBlock, PackedDigest},
};

use crate::{
    AceError, EXT_DEGREE, encode::EncodedCircuit, factored::ShuffleEncodeBuffer,
    pipeline::FactoredMultiAirCircuit,
};

/// Number of proof orders [`FactoredCircuitFactory::leaves_for_orders`] hashes per
/// packed Eidos compression.
pub const LEAF_LANES: usize = PACKED_LANES;

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
    /// Eidos digest of the per-order prefix.
    pub shuffle_commitment: Word,
    /// Eidos digest of the order-invariant common section.
    pub common_commitment: Word,
    /// Registry leaf and advice-map key: `merge(shuffle_commitment, common_commitment)`.
    pub commitment: Word,
}

/// Factory caching the order-invariant parts of a factored multi-AIR composition.
pub struct FactoredCircuitFactory<EF> {
    factored: FactoredMultiAirCircuit<EF>,
    /// Chaining state after absorbing the constants section.
    ///
    /// The constants section is byte-identical for every proof order and a whole number
    /// of Eidos blocks. Every order has the same prefix length, so the length-bound Eidos
    /// chaining word is initialized for that complete prefix before the constants are
    /// absorbed. Hashing a per-order prefix can therefore resume from this state and
    /// absorb only the shuffle section.
    constants_state: Word,
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
    /// sections, then checks the encode-only shuffle window byte for byte against that
    /// assembled stream and checks the resumed prefix digest against hashing the full prefix.
    /// This establishes the cached state and canonical-order consistency; it does not
    /// assemble or cross-check every other proof order.
    pub fn new(factored: FactoredMultiAirCircuit<EF>) -> Result<Self, AceError> {
        let canonical: Vec<usize> = (0..factored.num_airs()).collect();
        let circuit = factored.circuit_for_order(&canonical)?;
        let encoded = circuit.to_ace()?;
        let instructions = encoded.instructions();
        let const_felts = encoded.num_constants() * EXT_DEGREE;
        let prefix_len = const_felts + factored.num_shuffle_ops();
        if !const_felts.is_multiple_of(BLOCK_LEN)
            || !prefix_len.is_multiple_of(BLOCK_LEN)
            || prefix_len >= instructions.len()
        {
            return Err(AceError::InvalidInputLayout {
                message: "ACE stream sections must be block-aligned for prefix resumption".into(),
            });
        }

        let prefix_len_u32 =
            u32::try_from(prefix_len).map_err(|_| AceError::InvalidInputLayout {
                message: "ACE stream prefix length must fit in Eidos's u32 length binding".into(),
            })?;
        let mut constants_state = Eidos::init_chaining_word(0, prefix_len_u32);
        compress_blocks(&mut constants_state, &instructions[..const_felts]);
        let common_commitment = Eidos::hash_elements(&instructions[prefix_len..]);

        let mut buffer = ShuffleEncodeBuffer::new();
        let fast = factored.encode_shuffle_section_for_order(&canonical, &mut buffer)?;
        if fast != &instructions[const_felts..prefix_len] {
            return Err(AceError::InvalidInputLayout {
                message: "encode-only shuffle section diverges from the assembled stream".into(),
            });
        }
        let mut resumed = constants_state;
        compress_blocks(&mut resumed, fast);
        if resumed != Eidos::hash_elements(&instructions[..prefix_len]) {
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
    /// post-constants chaining state, so a caller enumerating every ordering pays per
    /// leaf only the per-order bytes and their hash — this is what makes an `n!`-leaf
    /// registry build feasible. Construction pins equality with
    /// [`Self::circuit_for_order`]'s `commitment` for the canonical order only. A caller
    /// persisting a registry commitment is responsible for any broader differential
    /// validation its trust boundary requires.
    pub fn leaf_for_order(
        &self,
        proof_order: &[usize],
        buffer: &mut ShuffleEncodeBuffer,
    ) -> Result<Word, AceError> {
        let shuffle = self.factored.encode_shuffle_section_for_order(proof_order, buffer)?;
        let mut state = self.constants_state;
        compress_blocks(&mut state, shuffle);
        let shuffle_commitment = state;
        Ok(Eidos::merge(&[shuffle_commitment, self.common_commitment]))
    }

    /// Compute registry leaves for a batch of proof orders, hashing `LEAF_LANES`
    /// orders per packed Eidos compression.
    ///
    /// Produces exactly the leaves [`Self::leaf_for_order`] produces, in order — the
    /// shuffle sections of every proof order have identical length, which is what makes
    /// lane-lockstep absorption sound. Chunks shorter than `LEAF_LANES` (the batch
    /// tail) pad unused lanes with the last order and discard the duplicates, so the
    /// packed path is the only code path. This method does not perform its own scalar or
    /// assembled differential check; callers persisting its output are responsible for
    /// validating those paths over the scope their trust boundary requires.
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

            // Resume the order-invariant post-constants chaining state in every lane and
            // absorb the per-lane shuffle sections in lockstep.
            let mut state: PackedDigest =
                core::array::from_fn(|element| [self.constants_state[element]; LEAF_LANES]);
            // Block alignment is established at construction; assert rather than debug_assert
            // so a miscount cannot silently truncate a hashed block in a release build.
            assert!(
                scratch.streams[0].len().is_multiple_of(BLOCK_LEN),
                "shuffle streams must be block-aligned"
            );
            let blocks = scratch.streams[0].len() / BLOCK_LEN;
            for block in 0..blocks {
                let mut packed_block: PackedBlock = [[Felt::ZERO; LEAF_LANES]; BLOCK_LEN];
                for (i, packed_elements) in packed_block.iter_mut().enumerate() {
                    for (packed_element, stream) in packed_elements.iter_mut().zip(&scratch.streams)
                    {
                        *packed_element = stream[block * BLOCK_LEN + i];
                    }
                }
                state = Eidos::compress_packed(state, packed_block);
            }

            let common: PackedDigest =
                core::array::from_fn(|element| [self.common_commitment[element]; LEAF_LANES]);
            let leaves = Eidos::merge_packed(&[state, common]);

            out.extend((0..chunk.len()).map(|lane| {
                let leaf: [Felt; 4] = core::array::from_fn(|i| leaves[i][lane]);
                Word::new(leaf)
            }));
        }
        Ok(())
    }

    /// Assemble, encode, and hash the circuit for one proof order.
    ///
    /// Only the shuffle section is hashed live (resuming from the cached post-constants
    /// chaining state); the common-section digest is reused. The returned encoded stream
    /// lets callers independently recompute either segment digest when they need to
    /// validate the cached commitments.
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
            || !stream_len.is_multiple_of(BLOCK_LEN)
            || shuffle_prefix_len >= stream_len
        {
            return Err(AceError::InvalidInputLayout {
                message: "assembled ACE stream does not match the factored section layout".into(),
            });
        }

        let mut state = self.constants_state;
        compress_blocks(&mut state, &instructions[self.const_felts..shuffle_prefix_len]);
        let shuffle_commitment = state;
        let common_commitment = self.common_commitment;
        let commitment = Eidos::merge(&[shuffle_commitment, common_commitment]);

        Ok(FactoredEncodedCircuit {
            encoded,
            shuffle_prefix_len,
            shuffle_commitment,
            common_commitment,
            commitment,
        })
    }
}

/// Compress complete Eidos blocks under an initialized chaining word.
fn compress_blocks(state: &mut Word, elements: &[Felt]) {
    // Ignoring a trailing partial block would yield a wrong digest; assert rather than
    // debug_assert so a miscount cannot survive a release build.
    assert!(
        elements.len().is_multiple_of(BLOCK_LEN),
        "Eidos compression requires complete blocks"
    );
    for &block in elements.as_chunks::<BLOCK_LEN>().0 {
        *state = Eidos::compress(*state, block);
    }
}
