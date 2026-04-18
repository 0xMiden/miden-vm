use alloc::vec::Vec;

use crate::{
    Felt, Word, ZERO,
    hash::poseidon2::Poseidon2,
    merkle::mmr::{Forest, MmrError, MmrProof},
};

// MMR PEAKS
// ================================================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct MmrPeaks {
    /// The number of leaves (represented by [`Forest`]) is used to differentiate MMRs that have
    /// the same number of peaks. This happens because the number of peaks goes up-and-down as
    /// the structure is used causing existing trees to be merged and new ones to be created.
    /// As an example, every time the MMR has a power-of-two number of leaves there is a single
    /// peak.
    ///
    /// Every tree in the MMR forest has a distinct power-of-two size, this means only the right-
    /// most tree can have an odd number of elements (i.e. `1`). Additionally this means that the
    /// bits in `num_leaves` conveniently encode the size of each individual tree.
    ///
    /// Examples:
    ///
    /// - With 5 leaves, the binary `0b101`. The number of set bits is equal the number of peaks,
    ///   in this case there are 2 peaks. The 0-indexed least-significant position of the bit
    ///   determines the number of elements of a tree, so the rightmost tree has `2**0` elements
    ///   and the left most has `2**2`.
    /// - With 12 leaves, the binary is `0b1100`, this case also has 2 peaks, the leftmost tree has
    ///   `2**3=8` elements, and the right most has `2**2=4` elements.
    forest: Forest,

    /// All the peaks of every tree in the MMR forest. The peaks are always ordered by number of
    /// leaves, starting from the peak with most children, to the one with least.
    ///
    /// Invariant: The length of `peaks` must be equal to the number of true bits in `num_leaves`.
    peaks: Vec<Word>,
}

impl Default for MmrPeaks {
    /// Returns new [`MmrPeaks`] instantiated from an empty vector of peaks and 0 leaves.
    fn default() -> Self {
        Self {
            forest: Forest::empty(),
            peaks: Vec::new(),
        }
    }
}

impl MmrPeaks {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Returns new [MmrPeaks] instantiated from the provided vector of peaks and the number of
    /// leaves in the underlying MMR.
    ///
    /// # Errors
    /// Returns an error if the number of leaves and the number of peaks are inconsistent, or if
    /// the forest exceeds the maximum supported size.
    pub fn new(forest: Forest, peaks: Vec<Word>) -> Result<Self, MmrError> {
        if !Forest::is_valid_size(forest.num_leaves()) {
            return Err(MmrError::ForestSizeExceeded {
                requested: forest.num_leaves(),
                max: Forest::MAX_LEAVES,
            });
        }
        if forest.num_trees() != peaks.len() {
            return Err(MmrError::InvalidPeaks(format!(
                "number of one bits in leaves is {} which does not equal peak length {}",
                forest.num_trees(),
                peaks.len()
            )));
        }

        Ok(Self { forest, peaks })
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the underlying forest (a set of mountain range peaks).
    pub fn forest(&self) -> Forest {
        self.forest
    }

    /// Returns a count of leaves in the underlying MMR.
    pub fn num_leaves(&self) -> usize {
        self.forest.num_leaves()
    }

    /// Returns the number of peaks of the underlying MMR.
    pub fn num_peaks(&self) -> usize {
        self.peaks.len()
    }

    /// Returns the list of peaks of the underlying MMR.
    pub fn peaks(&self) -> &[Word] {
        &self.peaks
    }

    /// Returns the peak by the provided index.
    ///
    /// # Errors
    /// Returns an error if the provided peak index is greater or equal to the current number of
    /// peaks in the Mmr.
    pub fn get_peak(&self, peak_idx: usize) -> Result<&Word, MmrError> {
        self.peaks
            .get(peak_idx)
            .ok_or(MmrError::PeakOutOfBounds { peak_idx, peaks_len: self.peaks.len() })
    }

    /// Converts this [MmrPeaks] into its components: number of leaves (represented as a [`Forest`])
    /// and a vector of peaks of the underlying MMR.
    pub fn into_parts(self) -> (Forest, Vec<Word>) {
        (self.forest, self.peaks)
    }

    /// Hashes the peaks.
    ///
    /// The procedure will:
    /// - Flatten and pad the peaks to a vector of Felts.
    /// - Hash the vector of Felts.
    pub fn hash_peaks(&self) -> Word {
        Poseidon2::hash_elements(&self.flatten_and_pad_peaks())
    }

    /// Verifies the Merkle opening proof.
    ///
    /// # Errors
    /// Returns an error if:
    /// - provided opening proof is invalid.
    /// - Mmr root value computed using the provided leaf value differs from the actual one.
    pub fn verify(&self, value: Word, opening: MmrProof) -> Result<(), MmrError> {
        let root = self.get_peak(opening.peak_index())?;
        opening
            .path()
            .merkle_path()
            .verify(opening.relative_pos() as u64, value, root)
            .map_err(MmrError::InvalidMerklePath)
    }

    /// Flattens and pads the peaks to make hashing inside of the Miden VM easier.
    ///
    /// The procedure will:
    /// - Flatten the vector of Words into a vector of Felts.
    /// - Pad the peaks with ZERO to an even number of words, this removes the need to handle
    ///   Poseidon2 padding.
    /// - Pad the peaks to a minimum length of 16 words, which reduces the constant cost of hashing.
    pub fn flatten_and_pad_peaks(&self) -> Vec<Felt> {
        let num_peaks = self.peaks.len();

        // To achieve the padding rules above we calculate the length of the final vector.
        // This is calculated as the number of field elements. Each peak is 4 field elements.
        // The length is calculated as follows:
        // - If there are less than 16 peaks, the data is padded to 16 peaks and as such requires 64
        //   field elements.
        // - If there are more than 16 peaks and the number of peaks is odd, the data is padded to
        //   an even number of peaks and as such requires `(num_peaks + 1) * 4` field elements.
        // - If there are more than 16 peaks and the number of peaks is even, the data is not padded
        //   and as such requires `num_peaks * 4` field elements.
        let len = if num_peaks < 16 {
            64
        } else if num_peaks % 2 == 1 {
            (num_peaks + 1) * 4
        } else {
            num_peaks * 4
        };

        let mut elements = Vec::with_capacity(len);
        elements.extend_from_slice(Word::words_as_elements(&self.peaks));
        elements.resize(len, ZERO);
        elements
    }
}

impl From<MmrPeaks> for Vec<Word> {
    fn from(peaks: MmrPeaks) -> Self {
        peaks.peaks
    }
}
