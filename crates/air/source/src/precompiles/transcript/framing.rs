//! Symbolic Eidos framing shared by transcript semantic owners.

use core::array;

use miden_core::{Felt, field::PrimeCharacteristicRing};
use miden_crypto::hash::eidos::Eidos;

/// Derives a symbolic packed initial CV from `(domain_tag, param0, param1, param2)`.
pub(crate) fn initial_cv_from_frame<E>(frame: [E; 4]) -> [E; 4]
where
    E: PrimeCharacteristicRing + From<Felt>,
{
    let base = Eidos::merkle_node_init_chaining_word().into_elements();
    array::from_fn(|idx| E::from(base[idx]) + frame[idx].clone())
}

#[cfg(test)]
mod tests {
    use miden_core::deferred::{DEFERRED_AND_FRAME, EidosFrame, deferred_chunks_frame};

    use super::initial_cv_from_frame;

    #[test]
    fn symbolic_initial_cv_matches_typed_frames() {
        for frame in [
            DEFERRED_AND_FRAME,
            deferred_chunks_frame(3),
            EidosFrame::new(DEFERRED_AND_FRAME.domain(), [1, 2, 3]),
        ] {
            assert_eq!(
                initial_cv_from_frame(frame.as_word().into_elements()),
                frame.initial_chaining_word().into_elements(),
            );
        }
    }
}
