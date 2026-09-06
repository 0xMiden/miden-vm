//! Eidos framing values and their initial chaining words.

use super::{
    domain::{DomainTag, EidosDomain},
    encoding, framing,
};
use crate::{Felt, Word};

/// A structurally valid Eidos frame.
///
/// The domain defines the meaning of the three parameters and the payload schedule. This type
/// checks the numeric framing representation; registry membership and domain-specific parameter
/// rules remain the responsibility of the owning registry.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct EidosFrame {
    domain: DomainTag,
    params: [u32; 3],
}

impl EidosFrame {
    /// Number of field elements in the canonical frame representation.
    pub const FELT_LEN: usize = 4;

    /// Creates a frame from a structurally valid domain tag and its domain-defined parameters.
    pub const fn new(domain: DomainTag, params: [u32; 3]) -> Self {
        Self { domain, params }
    }

    /// Creates a frame for a typed domain.
    pub const fn for_domain<D: EidosDomain>(_: D, params: [u32; 3]) -> Self {
        Self::new(D::TAG, params)
    }

    /// Returns the frame's domain tag.
    pub const fn domain(self) -> DomainTag {
        self.domain
    }

    /// Returns the three parameters whose meanings are defined by the domain.
    pub const fn params(self) -> [u32; 3] {
        self.params
    }

    /// Returns the canonical four-u32 representation `(domain, param0, param1, param2)`.
    pub const fn as_u32s(self) -> [u32; Self::FELT_LEN] {
        [self.domain.as_u32(), self.params[0], self.params[1], self.params[2]]
    }

    /// Returns the canonical four-Felt representation used by protocol encodings.
    pub const fn as_word(self) -> Word {
        let values = self.as_u32s();
        Word::new([
            Felt::new_unchecked(values[0] as u64),
            Felt::new_unchecked(values[1] as u64),
            Felt::new_unchecked(values[2] as u64),
            Felt::new_unchecked(values[3] as u64),
        ])
    }

    /// Parses a canonical four-Felt frame.
    ///
    /// Every element must fit in a `u32`, and the first element must encode a structurally valid
    /// domain tag. This does not check membership in an owner registry.
    pub fn from_word(word: Word) -> Option<Self> {
        let [domain, param0, param1, param2] = word.into_elements().map(felt_to_u32);
        Some(Self::new(DomainTag::from_u32(domain?)?, [param0?, param1?, param2?]))
    }

    /// Derives the initial chaining word for this frame.
    #[inline]
    pub fn initial_chaining_word(self) -> Word {
        encoding::output_cv_to_word(framing::init_cv(self.domain.as_u32(), self.params))
    }

    /// Recovers a frame from an initial chaining word produced by Eidos framing.
    ///
    /// The fixed high lanes must match the masked Eidos IV. Registry membership and
    /// domain-specific parameter rules are not checked.
    pub fn from_initial_chaining_word(word: Word) -> Option<Self> {
        let lanes = encoding::word_to_cv(word);
        let expected = framing::init_cv(lanes[0], [lanes[2], lanes[4], lanes[6]]);
        if lanes != expected {
            return None;
        }

        Some(Self::new(DomainTag::from_u32(lanes[0])?, [lanes[2], lanes[4], lanes[6]]))
    }
}

impl From<EidosFrame> for Word {
    fn from(frame: EidosFrame) -> Self {
        frame.as_word()
    }
}

fn felt_to_u32(value: Felt) -> Option<u32> {
    u32::try_from(value.as_canonical_u64()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::eidos::{
        DomainVersion,
        domain::namespace,
        domains::{GENERIC_BYTE_STRING, GENERIC_FELT_SEQUENCE},
    };

    #[test]
    fn frame_round_trips_through_words_and_initial_chaining_words() {
        for frame in [
            EidosFrame::for_domain(GENERIC_FELT_SEQUENCE, [0; 3]),
            EidosFrame::for_domain(GENERIC_BYTE_STRING, [1, 2, 3]),
            EidosFrame::new(
                DomainTag::new(namespace::MIDEN_VM, u16::MAX, DomainVersion::numbered(u8::MAX)),
                [u32::MAX; 3],
            ),
        ] {
            assert_eq!(EidosFrame::from_word(frame.as_word()), Some(frame));
            assert_eq!(
                EidosFrame::from_initial_chaining_word(frame.initial_chaining_word()),
                Some(frame)
            );
        }
    }

    #[test]
    fn frame_word_rejects_non_u32_values_and_invalid_domains() {
        let too_large = Felt::new_unchecked(u32::MAX as u64 + 1);
        assert_eq!(
            EidosFrame::from_word(Word::new([too_large, Felt::ZERO, Felt::ZERO, Felt::ZERO,])),
            None
        );
        assert_eq!(EidosFrame::from_word(Word::default()), None);

        let valid = EidosFrame::for_domain(GENERIC_FELT_SEQUENCE, [0; 3]).as_word();
        for index in 1..4 {
            let mut values = valid.into_elements();
            values[index] = too_large;
            assert_eq!(EidosFrame::from_word(Word::new(values)), None);
        }
    }

    #[test]
    fn initial_chaining_word_rejects_wrong_fixed_lanes() {
        let frame = EidosFrame::for_domain(GENERIC_FELT_SEQUENCE, [1, 2, 3]);
        let mut lanes = encoding::word_to_cv(frame.initial_chaining_word());
        for index in [1, 3, 5, 7] {
            let original = lanes[index];
            lanes[index] ^= 1;
            assert_eq!(
                EidosFrame::from_initial_chaining_word(encoding::output_cv_to_word(lanes)),
                None
            );
            lanes[index] = original;
        }
    }
}
