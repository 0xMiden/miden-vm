//! Matrix-finalizer expressions shared by the MVM and PVM Eidos AIRs.

use miden_core::{Felt, field::PrimeCharacteristicRing};
use miden_crypto::hash::eidos::FINALIZER_MATRIX;

use super::layout::FOOTER_ROWS;

const RAW_WORDS_PER_FOOTER: usize = 4;

/// Index into the raw XOF output `x` of word `local_word` on footer row `footer`.
///
/// Footer `f` binds working-state lanes `2f` and `2f + 1`. It therefore carries the fold words
/// `x[2f]` and `x[2f + 1]` followed by the feed-forward words `x[8 + 2f]` and `x[8 + 2f + 1]`.
#[inline]
const fn raw_xof_word_index(footer: usize, local_word: usize) -> usize {
    debug_assert!(footer < FOOTER_ROWS);
    debug_assert!(local_word < RAW_WORDS_PER_FOOTER);
    if local_word < 2 {
        2 * footer + local_word
    } else {
        8 + 2 * footer + local_word - 2
    }
}

/// Contribution of one footer's four raw XOF words to one matrix output.
pub(super) fn matrix_partial<E>(
    footer: usize,
    raw_words: &[E; RAW_WORDS_PER_FOOTER],
    output: usize,
) -> E
where
    E: PrimeCharacteristicRing,
{
    debug_assert!(footer < FOOTER_ROWS);
    debug_assert!(output < FINALIZER_MATRIX.len());
    raw_words.iter().enumerate().fold(E::ZERO, |sum, (local_word, word)| {
        let input = raw_xof_word_index(footer, local_word);
        sum + E::from_u64(FINALIZER_MATRIX[output][input]) * word.clone()
    })
}

/// Running matrix-finalizer values stored on the four footer rows.
pub(super) fn matrix_accumulator_rows(raw_xof: [u32; 16]) -> [[Felt; 4]; FOOTER_ROWS] {
    let mut rows = [[Felt::ZERO; 4]; FOOTER_ROWS];
    let mut running = [Felt::ZERO; 4];
    for footer in 0..FOOTER_ROWS {
        let raw_words = core::array::from_fn(|local_word| {
            Felt::from_u32(raw_xof[raw_xof_word_index(footer, local_word)])
        });
        for (output, accumulator) in running.iter_mut().enumerate() {
            *accumulator += matrix_partial(footer, &raw_words, output);
        }
        rows[footer] = running;
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_accumulator_row_is_the_direct_matrix_product() {
        let raw_xof = core::array::from_fn(|idx| (idx as u32).wrapping_mul(0x9e37_79b9));
        let rows = matrix_accumulator_rows(raw_xof);
        let direct: [Felt; 4] = core::array::from_fn(|output| {
            raw_xof.iter().enumerate().fold(Felt::ZERO, |sum, (input, &word)| {
                sum + Felt::new_unchecked(FINALIZER_MATRIX[output][input]) * Felt::from_u32(word)
            })
        });

        assert_eq!(rows[3], direct);
    }
}
