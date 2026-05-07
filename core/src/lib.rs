#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

// ASSERT MATCHES MACRO
// ================================================================================================

/// This is an implementation of `std::assert_matches::assert_matches`
/// so it can be removed when that feature stabilizes upstream
#[macro_export]
macro_rules! assert_matches {
    ($left:expr, $(|)? $( $pattern:pat_param )|+ $( if $guard: expr )? $(,)?) => {
        match $left {
            $( $pattern )|+ $( if $guard )? => {}
            ref left_val => {
                panic!(r#"
assertion failed: `(left matches right)`
    left: `{:?}`,
    right: `{}`"#, left_val, stringify!($($pattern)|+ $(if $guard)?));
            }
        }
    };

    ($left:expr, $(|)? $( $pattern:pat_param )|+ $( if $guard: expr )?, $msg:literal $(,)?) => {
        match $left {
            $( $pattern )|+ $( if $guard )? => {}
            ref left_val => {
                panic!(concat!(r#"
assertion failed: `(left matches right)`
    left: `{:?}`,
    right: `{}`
"#, $msg), left_val, stringify!($($pattern)|+ $(if $guard)?));
            }
        }
    };

    ($left:expr, $(|)? $( $pattern:pat_param )|+ $( if $guard: expr )?, $msg:literal, $($arg:tt)+) => {
        match $left {
            $( $pattern )|+ $( if $guard )? => {}
            ref left_val => {
                panic!(concat!(r#"
assertion failed: `(left matches right)`
    left: `{:?}`,
    right: `{}`
"#, $msg), left_val, stringify!($($pattern)|+ $(if $guard)?), $($arg)+);
            }
        }
    }
}

// EXPORTS
// ================================================================================================

pub use miden_crypto::{EMPTY_WORD, Felt, ONE, Word, ZERO};

/// The number of field elements in a Miden word.
pub const WORD_SIZE: usize = Word::NUM_ELEMENTS;

pub mod advice;
pub mod chiplets;
pub mod events;
pub mod mast;
pub mod operations;
pub mod precompile;
pub mod program;
pub mod proof;
pub mod utils;

pub mod field {
    pub use miden_crypto::field::*;

    pub type QuadFelt = BinomialExtensionField<super::Felt, 2>;
}

pub mod serde {
    pub use miden_crypto::utils::{
        BudgetedReader, ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
        SliceReader,
    };
}

pub mod crypto {
    pub mod merkle {
        use alloc::{
            collections::{BTreeMap, BTreeSet},
            vec::Vec,
        };

        pub use miden_crypto::merkle::{
            EmptySubtreeRoots, InnerNodeInfo, MerkleError, MerklePath, MerkleTree, NodeIndex,
            PartialMerkleTree,
            smt::{LeafIndex, SMT_DEPTH, SimpleSmt, Smt, SmtProof, SmtProofError},
            store::{MerkleStore, StoreNode},
        };

        use crate::{Felt, Word, ZERO};

        pub mod mmr {
            pub use miden_crypto::merkle::mmr::{
                Forest, InOrderIndex, MmrDelta, MmrError, MmrPath, MmrProof,
            };

            use super::{BTreeMap, BTreeSet, Felt, InnerNodeInfo, MerklePath, Vec, Word, ZERO};
            use crate::serde::{
                ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
            };

            /// A fully materialized Merkle Mountain Range.
            #[derive(Debug, Clone, Default)]
            pub struct Mmr(miden_crypto::merkle::mmr::Mmr);

            impl Mmr {
                /// Constructor for an empty `Mmr`.
                pub fn new() -> Self {
                    Self(miden_crypto::merkle::mmr::Mmr::new())
                }

                /// Constructs an MMR from an iterator of leaves.
                ///
                /// # Errors
                /// Returns an error if the maximum forest size is exceeded.
                pub fn try_from_iter<T: IntoIterator<Item = Word>>(
                    values: T,
                ) -> Result<Self, MmrError> {
                    miden_crypto::merkle::mmr::Mmr::try_from_iter(values).map(Self)
                }

                /// Returns the MMR forest representation. See [`Forest`].
                pub fn forest(&self) -> Forest {
                    self.0.forest()
                }

                /// Returns an [`MmrProof`] for the leaf at the specified position.
                ///
                /// # Errors
                /// Returns an error if the specified leaf position is out of bounds for this MMR.
                pub fn open(&self, pos: usize) -> Result<MmrProof, MmrError> {
                    self.0.open(pos)
                }

                /// Returns the leaf value at position `pos`.
                ///
                /// # Errors
                /// Returns an error if the specified leaf position is out of bounds for this MMR.
                pub fn get(&self, pos: usize) -> Result<Word, MmrError> {
                    self.0.get(pos)
                }

                /// Adds a new element to the MMR.
                ///
                /// # Errors
                /// Returns an error if the MMR exceeds the maximum supported forest size.
                pub fn add(&mut self, el: Word) -> Result<(), MmrError> {
                    self.0.add(el)
                }

                /// Returns the current peaks of the MMR.
                pub fn peaks(&self) -> MmrPeaks {
                    MmrPeaks(self.0.peaks())
                }

                /// Returns the peaks of the MMR at the state specified by `forest`.
                ///
                /// # Errors
                /// Returns an error if the specified `forest` value is not valid for this MMR.
                pub fn peaks_at(&self, forest: Forest) -> Result<MmrPeaks, MmrError> {
                    self.0.peaks_at(forest).map(MmrPeaks)
                }

                /// Compute the required update to `original_forest`.
                ///
                /// # Errors
                /// Returns an error if either forest is out of bounds for this MMR.
                pub fn get_delta(
                    &self,
                    from_forest: Forest,
                    to_forest: Forest,
                ) -> Result<MmrDelta, MmrError> {
                    self.0.get_delta(from_forest, to_forest)
                }

                /// Returns the inner nodes in this MMR.
                pub fn inner_nodes(&self) -> impl Iterator<Item = InnerNodeInfo> + '_ {
                    self.0.inner_nodes()
                }
            }

            /// The peaks of an MMR at a specific forest size.
            #[derive(Debug, Clone, PartialEq, Eq, Default)]
            pub struct MmrPeaks(miden_crypto::merkle::mmr::MmrPeaks);

            impl MmrPeaks {
                /// Returns new [`MmrPeaks`] instantiated from the provided vector of peaks and the
                /// number of leaves in the underlying MMR.
                ///
                /// # Errors
                /// Returns an error if the number of leaves and the number of peaks are
                /// inconsistent.
                pub fn new(forest: Forest, peaks: Vec<Word>) -> Result<Self, MmrError> {
                    miden_crypto::merkle::mmr::MmrPeaks::new(forest, peaks).map(Self)
                }

                /// Returns the underlying forest.
                pub fn forest(&self) -> Forest {
                    self.0.forest()
                }

                /// Returns a count of leaves in the underlying MMR.
                pub fn num_leaves(&self) -> usize {
                    self.0.num_leaves()
                }

                /// Returns the number of peaks of the underlying MMR.
                pub fn num_peaks(&self) -> usize {
                    self.0.num_peaks()
                }

                /// Returns the list of peaks of the underlying MMR.
                pub fn peaks(&self) -> &[Word] {
                    self.0.peaks()
                }

                /// Returns the peak by the provided index.
                ///
                /// # Errors
                /// Returns an error if the provided peak index is greater or equal to the current
                /// number of peaks in the MMR.
                pub fn get_peak(&self, peak_idx: usize) -> Result<&Word, MmrError> {
                    self.0.get_peak(peak_idx)
                }

                /// Converts this [`MmrPeaks`] into its components.
                pub fn into_parts(self) -> (Forest, Vec<Word>) {
                    self.0.into_parts()
                }

                /// Hashes the forest leaf count and peaks.
                pub fn hash_peaks(&self) -> Word {
                    let padded_peaks = self.flatten_and_pad_peaks();
                    let mut elements = Vec::with_capacity(Word::NUM_ELEMENTS + padded_peaks.len());
                    elements.extend_from_slice(&[
                        Felt::new_unchecked(self.num_leaves() as u64),
                        ZERO,
                        ZERO,
                        ZERO,
                    ]);
                    elements.extend_from_slice(&padded_peaks);

                    miden_crypto::hash::poseidon2::Poseidon2::hash_elements(&elements)
                }

                /// Verifies the Merkle opening proof.
                ///
                /// # Errors
                /// Returns an error if the provided opening proof is invalid.
                pub fn verify(&self, value: Word, opening: MmrProof) -> Result<(), MmrError> {
                    self.0.verify(value, opening)
                }

                /// Flattens and pads the peaks to make hashing inside of the Miden VM easier.
                pub fn flatten_and_pad_peaks(&self) -> Vec<Felt> {
                    self.0.flatten_and_pad_peaks()
                }
            }

            impl From<MmrPeaks> for Vec<Word> {
                fn from(peaks: MmrPeaks) -> Self {
                    let (_, peaks) = peaks.into_parts();
                    peaks
                }
            }

            /// Partially materialized Merkle Mountain Range.
            #[derive(Debug, Clone, PartialEq, Eq, Default)]
            pub struct PartialMmr(miden_crypto::merkle::mmr::PartialMmr);

            impl PartialMmr {
                /// Returns a new [`PartialMmr`] instantiated from the specified peaks.
                pub fn from_peaks(peaks: MmrPeaks) -> Self {
                    Self(miden_crypto::merkle::mmr::PartialMmr::from_peaks(peaks.0))
                }

                /// Returns a new [`PartialMmr`] instantiated from the specified components.
                ///
                /// # Errors
                /// Returns an error if the components are inconsistent.
                pub fn from_parts(
                    peaks: MmrPeaks,
                    nodes: BTreeMap<InOrderIndex, Word>,
                    tracked_leaves: BTreeSet<usize>,
                ) -> Result<Self, MmrError> {
                    miden_crypto::merkle::mmr::PartialMmr::from_parts(
                        peaks.0,
                        nodes,
                        tracked_leaves,
                    )
                    .map(Self)
                }

                /// Returns a new [`PartialMmr`] instantiated from the specified components without
                /// validation.
                pub fn from_parts_unchecked(
                    peaks: MmrPeaks,
                    nodes: BTreeMap<InOrderIndex, Word>,
                    tracked_leaves: BTreeSet<usize>,
                ) -> Self {
                    Self(miden_crypto::merkle::mmr::PartialMmr::from_parts_unchecked(
                        peaks.0,
                        nodes,
                        tracked_leaves,
                    ))
                }

                /// Returns the current forest of this [`PartialMmr`].
                pub fn forest(&self) -> Forest {
                    self.0.forest()
                }

                /// Returns the number of leaves in the underlying MMR for this [`PartialMmr`].
                pub fn num_leaves(&self) -> usize {
                    self.0.num_leaves()
                }

                /// Returns the leaf-count-bound peaks of the MMR for this [`PartialMmr`].
                pub fn peaks(&self) -> MmrPeaks {
                    MmrPeaks(self.0.peaks())
                }

                /// Returns true if this partial MMR tracks an authentication path for the leaf at
                /// the specified position.
                pub fn is_tracked(&self, pos: usize) -> bool {
                    self.0.is_tracked(pos)
                }

                /// Returns the leaf value at the specified position, or `None` if the leaf is not
                /// tracked.
                pub fn get(&self, pos: usize) -> Option<Word> {
                    self.0.get(pos)
                }

                /// Returns an iterator over the tracked leaves as (position, value) pairs.
                pub fn leaves(&self) -> impl Iterator<Item = (usize, Word)> + '_ {
                    self.0.leaves()
                }

                /// Returns an [`MmrProof`] for the leaf at the specified position, or `None` if
                /// not tracked.
                ///
                /// # Errors
                /// Returns an error if the specified position is out of bounds for this MMR.
                pub fn open(&self, pos: usize) -> Result<Option<MmrProof>, MmrError> {
                    self.0.open(pos)
                }

                /// Returns an iterator over all authentication path nodes of this [`PartialMmr`].
                pub fn nodes(&self) -> impl Iterator<Item = (&InOrderIndex, &Word)> {
                    self.0.nodes()
                }

                /// Returns an iterator over inner nodes of this [`PartialMmr`] for the specified
                /// leaves.
                pub fn inner_nodes<'a, I: Iterator<Item = (usize, Word)> + 'a>(
                    &'a self,
                    leaves: I,
                ) -> impl Iterator<Item = InnerNodeInfo> + 'a {
                    self.0.inner_nodes(leaves)
                }

                /// Adds a new peak and optionally tracks it.
                ///
                /// # Errors
                /// Returns an error if the MMR exceeds the maximum supported forest size.
                pub fn add(
                    &mut self,
                    leaf: Word,
                    track: bool,
                ) -> Result<Vec<(InOrderIndex, Word)>, MmrError> {
                    self.0.add(leaf, track)
                }

                /// Tracks the authentication path for a leaf.
                ///
                /// # Errors
                /// Returns an error if the path is not valid for the current peaks.
                pub fn track(
                    &mut self,
                    leaf_pos: usize,
                    leaf: Word,
                    path: &MerklePath,
                ) -> Result<(), MmrError> {
                    self.0.track(leaf_pos, leaf, path)
                }

                /// Removes a tracked leaf and the unused nodes from its authentication path.
                pub fn untrack(&mut self, leaf_pos: usize) -> Vec<(InOrderIndex, Word)> {
                    self.0.untrack(leaf_pos)
                }

                /// Applies updates to this [`PartialMmr`].
                ///
                /// # Errors
                /// Returns an error if the delta is invalid for this partial MMR.
                pub fn apply(
                    &mut self,
                    delta: MmrDelta,
                ) -> Result<Vec<(InOrderIndex, Word)>, MmrError> {
                    self.0.apply(delta)
                }
            }

            impl From<MmrPeaks> for PartialMmr {
                fn from(peaks: MmrPeaks) -> Self {
                    Self::from_peaks(peaks)
                }
            }

            impl From<PartialMmr> for MmrPeaks {
                fn from(partial_mmr: PartialMmr) -> Self {
                    MmrPeaks(partial_mmr.0.into())
                }
            }

            impl From<&MmrPeaks> for PartialMmr {
                fn from(peaks: &MmrPeaks) -> Self {
                    Self::from_peaks(peaks.clone())
                }
            }

            impl From<&PartialMmr> for MmrPeaks {
                fn from(partial_mmr: &PartialMmr) -> Self {
                    MmrPeaks((&partial_mmr.0).into())
                }
            }

            impl Serializable for PartialMmr {
                fn write_into<W: ByteWriter>(&self, target: &mut W) {
                    self.0.write_into(target);
                }
            }

            impl Deserializable for PartialMmr {
                fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
                    miden_crypto::merkle::mmr::PartialMmr::read_from(source).map(Self)
                }
            }
        }

        pub use mmr::{Mmr, MmrPeaks, PartialMmr};
    }

    pub mod hash {
        pub use miden_crypto::hash::{
            blake::{Blake3_256, Blake3Digest},
            keccak::Keccak256,
            poseidon2::Poseidon2,
            rpo::Rpo256,
            rpx::Rpx256,
            sha2::{Sha256, Sha512},
        };
    }

    pub mod random {
        pub use miden_crypto::rand::RandomCoin;
    }

    pub mod dsa {
        pub use miden_crypto::dsa::{ecdsa_k256_keccak, eddsa_25519_sha512, falcon512_poseidon2};
    }
}

pub mod prettier {
    pub use miden_formatting::{prettier::*, pretty_via_display, pretty_via_to_string};

    /// Pretty-print a list of [PrettyPrint] values as comma-separated items.
    pub fn pretty_print_csv<'a, T>(items: impl IntoIterator<Item = &'a T>) -> Document
    where
        T: PrettyPrint + 'a,
    {
        let mut doc = Document::Empty;
        for (i, item) in items.into_iter().enumerate() {
            if i > 0 {
                doc += const_text(", ");
            }
            doc += item.render();
        }
        doc
    }
}

// CONSTANTS
// ================================================================================================

/// The initial value for the frame pointer, corresponding to the start address for procedure
/// locals.
pub const FMP_INIT_VALUE: Felt = Felt::new_unchecked(2_u64.pow(31));

/// The address where the frame pointer is stored in memory.
pub const FMP_ADDR: Felt = Felt::new_unchecked(u32::MAX as u64 - 1_u64);
