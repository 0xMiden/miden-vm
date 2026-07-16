#![allow(unused_qualifications)]

use miden_crypto_derive::WordWrapper;

mod qualified {
    mod field {
        pub use miden_field::Word;
    }

    #[derive(super::WordWrapper)]
    pub struct QualifiedWord(miden_field::Word);

    #[derive(super::WordWrapper)]
    pub struct ModuleQualifiedWord(miden_field::word::Word);

    #[derive(super::WordWrapper)]
    pub struct ReexportedWord(field::Word);

    #[test]
    fn derives_accessors_for_qualified_word_path() {
        let word = miden_field::Word::default();
        let wrapper = QualifiedWord::from_raw(word);

        let elements: &[miden_field::Felt] = wrapper.as_elements();
        assert_eq!(elements, word.as_elements());
        assert_eq!(wrapper.as_word(), word);
    }

    #[test]
    fn derives_accessors_for_module_qualified_word_path() {
        let word = miden_field::word::Word::default();
        let wrapper = ModuleQualifiedWord::from_raw(word);

        let elements: &[miden_field::Felt] = wrapper.as_elements();
        assert_eq!(elements, word.as_elements());
        assert_eq!(wrapper.as_word(), word);
    }

    #[test]
    fn derives_accessors_for_reexported_word_path() {
        let word = field::Word::default();
        let wrapper = ReexportedWord::from_raw(word);

        let elements: &[miden_field::Felt] = wrapper.as_elements();
        assert_eq!(elements, word.as_elements());
        assert_eq!(wrapper.as_word(), word);
    }
}

mod unqualified {
    use miden_field::{Felt, Word};

    use super::WordWrapper;

    #[derive(WordWrapper)]
    pub struct UnqualifiedWord(Word);

    #[test]
    fn derives_accessors_for_unqualified_word_path() {
        let word = Word::default();
        let wrapper = UnqualifiedWord::from_raw(word);

        let elements: &[Felt] = wrapper.as_elements();
        assert_eq!(elements, word.as_elements());
        assert_eq!(wrapper.as_word(), word);
    }
}
