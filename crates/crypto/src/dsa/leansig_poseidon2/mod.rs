//! Miden-native LeanSig signatures using the Poseidon2 hash function.
//!
//! This is a fixed-parameter generalized XMSS construction designed to match the
//! `miden::core::crypto::dsa::leansig_poseidon2::verify` MASM procedure. It has a `2^32` epoch
//! space, 46 base-8 Winternitz chains, target sum 200, and a 32-level Merkle authentication path.
//! As in the LeanSig Ethereum instantiation, SHAKE128 is the secret-key PRF used to derive
//! one-time chain starts and deterministic encoding randomness; Poseidon is used for the public
//! message, chain, leaf, and tree hashes. This version substitutes Goldilocks Poseidon2 for the
//! reference KoalaBear Poseidon1 hash.
//!
//! The key generator commits only to the requested contiguous activation interval. Nodes outside
//! that interval are opaque, deterministically generated subtree roots. This lets applications
//! create short-lived keys without materializing all `2^32` one-time public keys.
//!
//! An epoch is the one-time nonce and leaf identifier. The secret key maintains a monotonic
//! `next_epoch` cursor: after signing an epoch, that epoch and every earlier epoch are permanently
//! rejected. Persist the updated secret key before publishing a signature so this protection also
//! survives process restarts.

use alloc::vec::Vec;

use miden_crypto_derive::{SilentDebug, SilentDisplay};
use rand::{Rng, RngExt};
use shake::{
    Shake128,
    digest::{ExtendableOutput, Update, XofReader},
};
use thiserror::Error;

use crate::utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
    zeroize::{Zeroize, ZeroizeOnDrop},
};
use crate::{EMPTY_WORD, Felt, Map, Word, field::PrimeField64, hash::poseidon2::Poseidon2};

// PARAMETERS
// ================================================================================================

/// Number of Winternitz chains in this LeanSig instantiation.
pub const DIMENSION: usize = 46;

/// Number of nodes in a signature's Merkle authentication path.
pub const TREE_DEPTH: usize = 32;

/// Number of elements in each Winternitz chain.
pub const BASE: u8 = 8;

/// Required sum of the incomparable encoding digits.
pub const TARGET_SUM: u32 = 200;

const HYPERCUBE_Q: u64 = 17_179_869_180;
const GOLDILOCKS_P_MINUS_ONE: u64 = 18_446_744_069_414_584_320;
const MAX_ENCODING_ATTEMPTS: u32 = 1 << 16;

const DOMAIN_PUBLIC_KEY: u32 = 1;
const DOMAIN_MESSAGE: u32 = 2;
const DOMAIN_CHAIN: u32 = 3;
const DOMAIN_LEAF: u32 = 4;
const DOMAIN_TREE: u32 = 5;
const SECRET_KEY_VERSION: u8 = 1;

const PRF_KEY_LENGTH: usize = 32;
const PRF_BYTES_PER_FELT: usize = 16;
const PRF_DOMAIN_SEPARATOR: [u8; 16] = [
    0xae, 0xae, 0x22, 0xff, 0x00, 0x01, 0xfa, 0xff, 0x21, 0xaf, 0x12, 0x00, 0x01, 0x11, 0xff, 0x00,
];
const PRF_CHAIN_START: u8 = 0;
const PRF_RHO: u8 = 1;
const PRF_INACTIVE_NODE: u8 = 2;

// PUBLIC TYPES
// ================================================================================================

/// A LeanSig public key consisting of a Merkle root and public hash parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    root: Word,
    parameter: Word,
}

impl PublicKey {
    /// Creates a public key from its constituent words.
    pub const fn new(root: Word, parameter: Word) -> Self {
        Self { root, parameter }
    }

    /// Returns the root of the one-time-key Merkle tree.
    pub const fn root(&self) -> Word {
        self.root
    }

    /// Returns the public hash parameter.
    pub const fn parameter(&self) -> Word {
        self.parameter
    }

    /// Returns the commitment consumed by the MASM verifier.
    pub fn to_commitment(&self) -> Word {
        Poseidon2::merge_in_domain(&[self.root, self.parameter], Felt::from_u32(DOMAIN_PUBLIC_KEY))
    }

    /// Verifies a signature for `message` at `epoch`.
    pub fn verify(&self, epoch: u32, message: Word, signature: &Signature) -> bool {
        let Some(codeword) = encode_message(message, self.parameter, epoch, signature.rho) else {
            return false;
        };

        let chain_ends = core::array::from_fn(|chain_index| {
            chain(
                signature.hashes[chain_index],
                self.parameter,
                epoch,
                chain_index as u8,
                codeword[chain_index],
                BASE - 1,
            )
        });
        let mut current = hash_leaf(&chain_ends, epoch);
        let mut position = epoch;
        for (level, sibling) in signature.authentication_path.iter().enumerate() {
            let (left, right) = if position & 1 == 0 {
                (current, *sibling)
            } else {
                (*sibling, current)
            };
            position >>= 1;
            current = hash_parent(left, right, (level + 1) as u8, position);
        }

        current == self.root
    }
}

/// A Poseidon2 LeanSig signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    rho: Word,
    hashes: [Word; DIMENSION],
    authentication_path: [Word; TREE_DEPTH],
}

impl Signature {
    /// Creates a signature from its wire-format components.
    pub const fn new(
        rho: Word,
        hashes: [Word; DIMENSION],
        authentication_path: [Word; TREE_DEPTH],
    ) -> Self {
        Self { rho, hashes, authentication_path }
    }

    /// Returns the encoding randomness.
    pub const fn rho(&self) -> Word {
        self.rho
    }

    /// Returns the disclosed Winternitz chain nodes.
    pub const fn hashes(&self) -> &[Word; DIMENSION] {
        &self.hashes
    }

    /// Returns the Merkle authentication path.
    pub const fn authentication_path(&self) -> &[Word; TREE_DEPTH] {
        &self.authentication_path
    }

    /// Encodes the public key and signature in the order consumed by the MASM advice stack.
    pub fn to_advice(&self, public_key: &PublicKey) -> Vec<Felt> {
        let mut advice = Vec::with_capacity((3 + DIMENSION + TREE_DEPTH) * Word::NUM_ELEMENTS);
        advice.extend(public_key.root);
        advice.extend(public_key.parameter);
        advice.extend(self.rho);
        advice.extend(self.hashes.iter().flat_map(|word| word.iter()).copied());
        advice.extend(self.authentication_path.iter().flat_map(|word| word.iter()).copied());
        advice
    }
}

/// A LeanSig secret key for a contiguous activation interval.
#[derive(SilentDebug, SilentDisplay)]
pub struct SecretKey {
    prf_key: [u8; PRF_KEY_LENGTH],
    public_key: PublicKey,
    activation_epoch: u32,
    num_active_epochs: u32,
    next_epoch: u64,
    authentication_paths: Vec<[Word; TREE_DEPTH]>,
}

impl SecretKey {
    /// Generates a key from OS-provided randomness.
    #[cfg(feature = "std")]
    pub fn new(activation_epoch: u32, num_active_epochs: u32) -> Result<Self, KeyGenerationError> {
        Self::with_rng(&mut rand::rng(), activation_epoch, num_active_epochs)
    }

    /// Generates a key for a contiguous range of epochs.
    ///
    /// Key-generation work and secret-key storage scale linearly with `num_active_epochs`.
    pub fn with_rng<R: Rng>(
        rng: &mut R,
        activation_epoch: u32,
        num_active_epochs: u32,
    ) -> Result<Self, KeyGenerationError> {
        let activation_end = u64::from(activation_epoch) + u64::from(num_active_epochs);
        if num_active_epochs == 0 {
            return Err(KeyGenerationError::EmptyActivationInterval);
        }
        if activation_end > (1u64 << TREE_DEPTH) {
            return Err(KeyGenerationError::ActivationIntervalOverflow {
                activation_epoch,
                num_active_epochs,
            });
        }

        Ok(Self::from_material(
            rng.random(),
            random_word(rng),
            activation_epoch,
            num_active_epochs,
            u64::from(activation_epoch),
        ))
    }

    fn from_material(
        prf_key: [u8; PRF_KEY_LENGTH],
        parameter: Word,
        activation_epoch: u32,
        num_active_epochs: u32,
        next_epoch: u64,
    ) -> Self {
        let activation_end = u64::from(activation_epoch) + u64::from(num_active_epochs);
        let mut builder = TreeBuilder {
            prf_key,
            parameter,
            activation_start: u64::from(activation_epoch),
            activation_end,
            nodes: Map::new(),
        };
        let root = builder.build_node(TREE_DEPTH as u8, 0);

        let mut authentication_paths = Vec::with_capacity(num_active_epochs as usize);
        for offset in 0..num_active_epochs {
            let epoch = activation_epoch.wrapping_add(offset);
            authentication_paths.push(builder.authentication_path(epoch));
        }

        Self {
            prf_key,
            public_key: PublicKey::new(root, parameter),
            activation_epoch,
            num_active_epochs,
            next_epoch,
            authentication_paths,
        }
    }

    /// Returns the public key corresponding to this secret key.
    pub const fn public_key(&self) -> PublicKey {
        self.public_key
    }

    /// Returns the first active epoch.
    pub const fn activation_epoch(&self) -> u32 {
        self.activation_epoch
    }

    /// Returns the number of active epochs.
    pub const fn num_active_epochs(&self) -> u32 {
        self.num_active_epochs
    }

    /// Returns the next unused epoch, or `None` if the activation interval is exhausted.
    pub fn next_epoch(&self) -> Option<u32> {
        (self.next_epoch < self.activation_end()).then_some(self.next_epoch as u32)
    }

    /// Signs `message` at the next unused epoch and returns that epoch with the signature.
    pub fn sign_next(&mut self, message: Word) -> Result<(u32, Signature), SigningError> {
        let epoch = self.next_epoch().ok_or(SigningError::KeyExhausted)?;
        self.sign(epoch, message).map(|signature| (epoch, signature))
    }

    /// Signs `message` using the one-time key identified by `epoch`.
    ///
    /// On success, this advances the key's nonce cursor to `epoch + 1`. Any skipped epochs become
    /// unusable, which ensures the signer can never move its one-time nonce backwards.
    pub fn sign(&mut self, epoch: u32, message: Word) -> Result<Signature, SigningError> {
        let path_index = u64::from(epoch).checked_sub(u64::from(self.activation_epoch));
        let Some(path_index) =
            path_index.filter(|index| *index < u64::from(self.num_active_epochs))
        else {
            return Err(SigningError::EpochNotActive {
                epoch,
                activation_epoch: self.activation_epoch,
                num_active_epochs: self.num_active_epochs,
            });
        };
        if u64::from(epoch) < self.next_epoch {
            return Err(SigningError::EpochAlreadyUsed { epoch, next_epoch: self.next_epoch });
        }

        let (rho, codeword) = (0..MAX_ENCODING_ATTEMPTS)
            .find_map(|attempt| {
                let rho = derive_rho(&self.prf_key, message, epoch, attempt);
                encode_message(message, self.public_key.parameter, epoch, rho)
                    .map(|codeword| (rho, codeword))
            })
            .ok_or(SigningError::EncodingAttemptsExceeded { attempts: MAX_ENCODING_ATTEMPTS })?;

        let hashes = core::array::from_fn(|chain_index| {
            let start = derive_chain_start(&self.prf_key, epoch, chain_index as u8);
            chain(
                start,
                self.public_key.parameter,
                epoch,
                chain_index as u8,
                0,
                codeword[chain_index],
            )
        });

        let signature = Signature::new(rho, hashes, self.authentication_paths[path_index as usize]);
        self.next_epoch = u64::from(epoch) + 1;
        Ok(signature)
    }

    fn activation_end(&self) -> u64 {
        u64::from(self.activation_epoch) + u64::from(self.num_active_epochs)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.prf_key.zeroize();
    }
}

impl ZeroizeOnDrop for SecretKey {}

// SERIALIZATION
// ================================================================================================

impl Serializable for PublicKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.root);
        target.write(self.parameter);
    }
}

impl Deserializable for PublicKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self::new(source.read()?, source.read()?))
    }
}

impl Serializable for Signature {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write(self.rho);
        target.write_many(self.hashes);
        target.write_many(self.authentication_path);
    }
}

impl Deserializable for Signature {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self::new(source.read()?, read_word_array(source)?, read_word_array(source)?))
    }
}

impl Serializable for SecretKey {
    /// Serializes the PRF key, parameter, activation interval, and monotonic nonce cursor.
    ///
    /// Authentication paths and the public root are regenerated during deserialization. Crucially,
    /// `next_epoch` is persisted, so a loaded key continues to reject consumed epochs.
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(SECRET_KEY_VERSION);
        target.write_bytes(&self.prf_key);
        target.write(self.public_key.parameter);
        target.write_u32(self.activation_epoch);
        target.write_u32(self.num_active_epochs);
        target.write_u64(self.next_epoch);
    }
}

impl Deserializable for SecretKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let version = source.read_u8()?;
        if version != SECRET_KEY_VERSION {
            return Err(DeserializationError::InvalidValue(alloc::format!(
                "unsupported LeanSig secret-key version {version}"
            )));
        }

        let prf_key = source.read_array()?;
        let parameter = source.read()?;
        let activation_epoch = source.read_u32()?;
        let num_active_epochs = source.read_u32()?;
        let next_epoch = source.read_u64()?;
        let activation_end = u64::from(activation_epoch) + u64::from(num_active_epochs);

        if num_active_epochs == 0 || activation_end > (1u64 << TREE_DEPTH) {
            return Err(DeserializationError::InvalidValue(
                "invalid LeanSig activation interval".into(),
            ));
        }
        if !(u64::from(activation_epoch)..=activation_end).contains(&next_epoch) {
            return Err(DeserializationError::InvalidValue(
                "invalid LeanSig next-epoch cursor".into(),
            ));
        }

        Ok(Self::from_material(
            prf_key,
            parameter,
            activation_epoch,
            num_active_epochs,
            next_epoch,
        ))
    }
}

fn read_word_array<const N: usize, R: ByteReader>(
    source: &mut R,
) -> Result<[Word; N], DeserializationError> {
    let mut words = [EMPTY_WORD; N];
    for word in &mut words {
        *word = source.read()?;
    }
    Ok(words)
}

/// Errors returned while generating a LeanSig key.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyGenerationError {
    /// The requested activation interval contains no epochs.
    #[error("LeanSig activation interval must contain at least one epoch")]
    EmptyActivationInterval,

    /// The requested activation interval extends past the `u32` epoch space.
    #[error(
        "LeanSig activation interval ({activation_epoch}, {num_active_epochs}) exceeds the u32 epoch space"
    )]
    ActivationIntervalOverflow {
        /// First requested epoch.
        activation_epoch: u32,
        /// Number of requested epochs.
        num_active_epochs: u32,
    },
}

/// Errors returned while signing with a LeanSig key.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SigningError {
    /// The requested epoch is outside the key's activation interval.
    #[error(
        "LeanSig epoch {epoch} is outside activation interval starting at {activation_epoch} with length {num_active_epochs}"
    )]
    EpochNotActive {
        /// Requested epoch.
        epoch: u32,
        /// First active epoch.
        activation_epoch: u32,
        /// Number of active epochs.
        num_active_epochs: u32,
    },

    /// The requested epoch has already been consumed or skipped.
    #[error("LeanSig epoch {epoch} is older than the next unused epoch {next_epoch}")]
    EpochAlreadyUsed {
        /// Requested epoch.
        epoch: u32,
        /// Monotonic nonce cursor after the most recent signature.
        next_epoch: u64,
    },

    /// Every epoch in the activation interval has been consumed or skipped.
    #[error("LeanSig secret key has no unused active epochs")]
    KeyExhausted,

    /// Rejection sampling did not produce an incomparable encoding.
    #[error("LeanSig encoding failed after {attempts} attempts")]
    EncodingAttemptsExceeded {
        /// Number of attempted encodings.
        attempts: u32,
    },
}

// TREE CONSTRUCTION
// ================================================================================================

struct TreeBuilder {
    prf_key: [u8; PRF_KEY_LENGTH],
    parameter: Word,
    activation_start: u64,
    activation_end: u64,
    nodes: Map<(u8, u32), Word>,
}

impl TreeBuilder {
    fn build_node(&mut self, level: u8, position: u32) -> Word {
        if let Some(node) = self.nodes.get(&(level, position)) {
            return *node;
        }

        let subtree_start = u64::from(position) << level;
        let subtree_end = (u64::from(position) + 1) << level;
        if subtree_end <= self.activation_start || subtree_start >= self.activation_end {
            return inactive_node(&self.prf_key, level, position);
        }

        let node = if level == 0 {
            self.one_time_public_key(position)
        } else {
            let child_level = level - 1;
            let left = self.build_node(child_level, position * 2);
            let right = self.build_node(child_level, position * 2 + 1);
            hash_parent(left, right, level, position)
        };
        self.nodes.insert((level, position), node);
        node
    }

    fn one_time_public_key(&self, epoch: u32) -> Word {
        let chain_ends = core::array::from_fn(|chain_index| {
            let start = derive_chain_start(&self.prf_key, epoch, chain_index as u8);
            chain(start, self.parameter, epoch, chain_index as u8, 0, BASE - 1)
        });
        hash_leaf(&chain_ends, epoch)
    }

    fn authentication_path(&self, epoch: u32) -> [Word; TREE_DEPTH] {
        core::array::from_fn(|level| {
            let level = level as u8;
            let sibling_position = (epoch >> level) ^ 1;
            self.nodes
                .get(&(level, sibling_position))
                .copied()
                .unwrap_or_else(|| inactive_node(&self.prf_key, level, sibling_position))
        })
    }
}

impl Drop for TreeBuilder {
    fn drop(&mut self) {
        self.prf_key.zeroize();
    }
}

// HASH AND ENCODING HELPERS
// ================================================================================================

fn encode_message(
    message: Word,
    parameter: Word,
    epoch: u32,
    rho: Word,
) -> Option<[u8; DIMENSION]> {
    let state = message_hash_state(message, parameter, epoch, rho);
    let mut codeword = [0u8; DIMENSION];
    let mut cursor = 0;

    for felt in state.iter().take(5) {
        let value = felt.as_canonical_u64();
        if value == GOLDILOCKS_P_MINUS_ONE {
            return None;
        }

        let mut quotient = value / HYPERCUBE_Q;
        for _ in 0..10 {
            if cursor == DIMENSION {
                break;
            }
            codeword[cursor] = (quotient % u64::from(BASE)) as u8;
            quotient /= u64::from(BASE);
            cursor += 1;
        }
    }

    (codeword.iter().map(|&digit| u32::from(digit)).sum::<u32>() == TARGET_SUM).then_some(codeword)
}

fn message_hash_state(message: Word, parameter: Word, epoch: u32, rho: Word) -> [Felt; 12] {
    let mut state = [Felt::ZERO; Poseidon2::STATE_WIDTH];
    state[..4].copy_from_slice(message.as_elements());
    state[4..8].copy_from_slice(parameter.as_elements());
    state[8..].copy_from_slice(&capacity(DOMAIN_MESSAGE, epoch, 0, 0));
    Poseidon2::apply_permutation(&mut state);

    state[..4].copy_from_slice(rho.as_elements());
    state[4..8].fill(Felt::ZERO);
    Poseidon2::apply_permutation(&mut state);
    state
}

fn derive_chain_start(prf_key: &[u8; PRF_KEY_LENGTH], epoch: u32, chain_index: u8) -> Word {
    let mut hasher = prf_hasher(PRF_CHAIN_START, prf_key);
    hasher.update(&epoch.to_be_bytes());
    hasher.update(&u64::from(chain_index).to_be_bytes());
    shake_word(hasher)
}

fn derive_rho(prf_key: &[u8; PRF_KEY_LENGTH], message: Word, epoch: u32, attempt: u32) -> Word {
    let mut hasher = prf_hasher(PRF_RHO, prf_key);
    hasher.update(&epoch.to_be_bytes());
    hasher.update(&message.to_bytes());
    hasher.update(&u64::from(attempt).to_be_bytes());
    shake_word(hasher)
}

fn chain(
    mut current: Word,
    parameter: Word,
    epoch: u32,
    chain_index: u8,
    start_position: u8,
    end_position: u8,
) -> Word {
    for position in start_position + 1..=end_position {
        current = permute_rate(
            current,
            parameter,
            capacity(DOMAIN_CHAIN, epoch, u32::from(chain_index), u32::from(position)),
        );
    }
    current
}

fn hash_leaf(chain_ends: &[Word; DIMENSION], epoch: u32) -> Word {
    let mut state = [Felt::ZERO; Poseidon2::STATE_WIDTH];
    state[8..].copy_from_slice(&capacity(DOMAIN_LEAF, epoch, DIMENSION as u32, 0));
    for pair in chain_ends.chunks_exact(2) {
        state[..4].copy_from_slice(pair[0].as_elements());
        state[4..8].copy_from_slice(pair[1].as_elements());
        Poseidon2::apply_permutation(&mut state);
    }
    Word::new(state[..4].try_into().expect("digest has four elements"))
}

fn hash_parent(left: Word, right: Word, level: u8, position: u32) -> Word {
    permute_rate(left, right, capacity(DOMAIN_TREE, u32::from(level), position, 0))
}

fn inactive_node(prf_key: &[u8; PRF_KEY_LENGTH], level: u8, position: u32) -> Word {
    let mut hasher = prf_hasher(PRF_INACTIVE_NODE, prf_key);
    hasher.update(&[level]);
    hasher.update(&position.to_be_bytes());
    shake_word(hasher)
}

fn prf_hasher(domain: u8, prf_key: &[u8; PRF_KEY_LENGTH]) -> Shake128 {
    let mut hasher = Shake128::default();
    hasher.update(&PRF_DOMAIN_SEPARATOR);
    hasher.update(&[domain]);
    hasher.update(prf_key);
    hasher
}

fn shake_word(hasher: Shake128) -> Word {
    let mut reader = hasher.finalize_xof();
    Word::new(core::array::from_fn(|_| {
        let mut bytes = [0u8; PRF_BYTES_PER_FELT];
        reader.read(&mut bytes);
        let value = u128::from_be_bytes(bytes) % u128::from(Felt::ORDER_U64);
        Felt::new_unchecked(value as u64)
    }))
}

fn permute_rate(left: Word, right: Word, capacity: [Felt; 4]) -> Word {
    let mut state = [Felt::ZERO; Poseidon2::STATE_WIDTH];
    state[..4].copy_from_slice(left.as_elements());
    state[4..8].copy_from_slice(right.as_elements());
    state[8..].copy_from_slice(&capacity);
    Poseidon2::apply_permutation(&mut state);
    Word::new(state[..4].try_into().expect("digest has four elements"))
}

fn capacity(domain: u32, a: u32, b: u32, c: u32) -> [Felt; 4] {
    [domain, a, b, c].map(Felt::from_u32)
}

fn random_word(rng: &mut impl Rng) -> Word {
    Word::new(core::array::from_fn(|_| {
        loop {
            if let Ok(felt) = Felt::new(rng.random::<u64>()) {
                break felt;
            }
        }
    }))
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;

    #[test]
    fn sign_and_verify_across_activation_interval() {
        let mut rng = ChaCha20Rng::from_seed([0x51; 32]);
        let mut secret_key = SecretKey::with_rng(&mut rng, 0x1020_3040, 3).unwrap();
        let public_key = secret_key.public_key();

        for epoch in 0x1020_3040..0x1020_3043 {
            let message = random_word(&mut rng);
            let signature = secret_key.sign(epoch, message).unwrap();
            assert!(public_key.verify(epoch, message, &signature));
            assert!(!public_key.verify(epoch ^ 1, message, &signature));
        }
    }

    #[test]
    fn signing_is_deterministic() {
        let mut left_rng = ChaCha20Rng::from_seed([0x52; 32]);
        let mut right_rng = ChaCha20Rng::from_seed([0x52; 32]);
        let mut left_key = SecretKey::with_rng(&mut left_rng, 7, 1).unwrap();
        let mut right_key = SecretKey::with_rng(&mut right_rng, 7, 1).unwrap();
        let message = random_word(&mut left_rng);

        assert_eq!(left_key.sign(7, message), right_key.sign(7, message));
    }

    #[test]
    fn rejects_inactive_epoch() {
        let mut rng = ChaCha20Rng::from_seed([0x53; 32]);
        let mut secret_key = SecretKey::with_rng(&mut rng, 7, 1).unwrap();

        assert!(matches!(
            secret_key.sign(8, EMPTY_WORD),
            Err(SigningError::EpochNotActive { .. })
        ));
    }

    #[test]
    fn rejects_reused_and_skipped_epochs() {
        let mut rng = ChaCha20Rng::from_seed([0x54; 32]);
        let mut secret_key = SecretKey::with_rng(&mut rng, 7, 4).unwrap();

        secret_key.sign(9, EMPTY_WORD).unwrap();
        assert_eq!(secret_key.next_epoch(), Some(10));
        assert!(matches!(
            secret_key.sign(9, EMPTY_WORD),
            Err(SigningError::EpochAlreadyUsed { .. })
        ));
        assert!(matches!(
            secret_key.sign(8, EMPTY_WORD),
            Err(SigningError::EpochAlreadyUsed { .. })
        ));

        let (epoch, _) = secret_key.sign_next(EMPTY_WORD).unwrap();
        assert_eq!(epoch, 10);
        assert_eq!(secret_key.next_epoch(), None);
    }

    #[test]
    fn serialization_persists_nonce_cursor() {
        let mut rng = ChaCha20Rng::from_seed([0x55; 32]);
        let mut secret_key = SecretKey::with_rng(&mut rng, 7, 3).unwrap();
        let public_key = secret_key.public_key();
        let first_signature = secret_key.sign(7, EMPTY_WORD).unwrap();
        assert!(public_key.verify(7, EMPTY_WORD, &first_signature));

        let encoded = secret_key.to_bytes();
        let mut restored = SecretKey::read_from_bytes(&encoded).unwrap();
        assert_eq!(restored.public_key(), public_key);
        assert_eq!(restored.next_epoch(), Some(8));
        assert!(matches!(
            restored.sign(7, EMPTY_WORD),
            Err(SigningError::EpochAlreadyUsed { .. })
        ));

        let second_signature = restored.sign(8, EMPTY_WORD).unwrap();
        assert!(public_key.verify(8, EMPTY_WORD, &second_signature));
    }
}
