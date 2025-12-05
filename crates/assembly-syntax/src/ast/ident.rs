use alloc::{string::ToString, sync::Arc};
use core::{
    fmt,
    hash::{Hash, Hasher},
    str::FromStr,
};

use miden_core::utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};
use miden_debug_types::{SourceSpan, Span, Spanned};

/// Represents the types of errors that can occur when parsing/validating an [Ident]
#[derive(Debug, thiserror::Error)]
pub enum IdentError {
    #[error("invalid identifier: cannot be empty")]
    Empty,
    #[error(
        "invalid identifier '{ident}': must contain only unicode alphanumeric or ascii graphic characters"
    )]
    InvalidChars { ident: Arc<str> },
    #[error("invalid identifier: length exceeds the maximum of {max} bytes")]
    InvalidLength { max: usize },
    #[error("invalid identifier: {0}")]
    Casing(CaseKindError),
}

/// Represents the various types of casing errors that can occur, e.g. using an identifier
/// with `SCREAMING_CASE` where one with `snake_case` is expected.
#[derive(Debug, thiserror::Error)]
pub enum CaseKindError {
    #[error(
        "only uppercase characters or underscores are allowed, and must start with an alphabetic character"
    )]
    Screaming,
    #[error(
        "only lowercase characters or underscores are allowed, and must start with an alphabetic character"
    )]
    Snake,
    #[error(
        "only alphanumeric characters are allowed, and must start with a lowercase alphabetic character"
    )]
    Camel,
}

/// Represents a generic identifier in Miden Assembly source code.
///
/// This type is used internally by all other specialized identifier types, e.g.
/// [super::ProcedureName], and enforces the baseline rules for identifiers in Miden Assembly.
///
/// All identifiers are associated with a source span, and are interned to the extent possible, i.e.
/// rather than allocating a new `String` for every use of the same identifier, we attempt to have
/// all such uses share a single reference-counted allocation. This interning is not perfect or
/// guaranteed globally, but generally holds within a given module. In the future we may make these
/// actually interned strings with a global interner, but for now it is simply best-effort.
#[derive(Clone)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(winter_serde(true))
)]
pub struct Ident {
    /// The source span associated with this identifier.
    ///
    /// NOTE: To make use of this span, we need to know the context in which it was used, i.e.,
    /// either the containing module or procedure, both of which have a source file which we can
    /// use to render a source snippet for this span.
    ///
    /// If a span is not known, the default value is used, which has zero-length and thus will not
    /// be rendered as a source snippet.
    span: SourceSpan,
    /// The actual content of the identifier
    name: Arc<str>,
}

impl Ident {
    /// Reserved name for a main procedure.
    pub const MAIN: &'static str = "$main";

    /// Creates an [Ident] from `source`.
    ///
    /// This can fail if:
    ///
    /// * The identifier exceeds the maximum allowed identifier length
    /// * The identifier contains something other than Unicode alphanumeric or ASCII graphic
    ///   characters (e.g. whitespace, control)
    pub fn new(source: impl AsRef<str>) -> Result<Self, IdentError> {
        source.as_ref().parse()
    }

    /// Creates an [Ident] from `source`.
    ///
    /// This can fail if:
    ///
    /// * The identifier exceeds the maximum allowed identifier length
    /// * The identifier contains something other than Unicode alphanumeric or ASCII graphic
    ///   characters (e.g. whitespace, control)
    pub fn new_with_span(span: SourceSpan, source: impl AsRef<str>) -> Result<Self, IdentError> {
        source.as_ref().parse::<Self>().map(|id| id.with_span(span))
    }

    /// Sets the span for this identifier.
    pub fn with_span(mut self, span: SourceSpan) -> Self {
        self.span = span;
        self
    }

    /// This allows constructing an [Ident] directly from a ref-counted string that is known to be
    /// a valid identifier, and so does not require re-parsing/re-validating.
    ///
    /// This should _not_ be used to bypass validation, as other parts of the assembler still may
    /// re-validate identifiers, notably during deserialization, and may result in a panic being
    /// raised.
    ///
    /// NOTE: This function is perma-unstable, it may be removed or modified at any time.
    pub fn from_raw_parts(name: Span<Arc<str>>) -> Self {
        let (span, name) = name.into_parts();
        Self { span, name }
    }

    /// Unwraps this [Ident], extracting the inner [`Arc<str>`].
    pub fn into_inner(self) -> Arc<str> {
        self.name
    }

    /// Returns the content of this identifier as a `str`.
    pub fn as_str(&self) -> &str {
        self.name.as_ref()
    }

    /// Returns true if this identifier is a valid constant identifier
    pub fn is_constant_ident(&self) -> bool {
        self.name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    }

    /// Returns true if this identifier must be quoted in Miden Assembly syntax
    pub fn requires_quoting(&self) -> bool {
        !self.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
    }

    /// Applies the default [Ident] validation rules to `source`.
    pub fn validate(source: impl AsRef<str>) -> Result<(), IdentError> {
        let source = source.as_ref();
        if source.is_empty() {
            return Err(IdentError::Empty);
        }
        if !source
            .chars()
            .all(|c| (c.is_ascii_graphic() || c.is_alphanumeric()) && c != '#')
        {
            return Err(IdentError::InvalidChars { ident: source.into() });
        }
        Ok(())
    }
}

impl fmt::Debug for Ident {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Ident").field(&self.name).finish()
    }
}

impl Eq for Ident {}

impl PartialEq for Ident {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Ord for Ident {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.name.cmp(&other.name)
    }
}

impl PartialOrd for Ident {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for Ident {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

impl Spanned for Ident {
    fn span(&self) -> SourceSpan {
        self.span
    }
}

impl core::ops::Deref for Ident {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.name.as_ref()
    }
}

impl AsRef<str> for Ident {
    #[inline]
    fn as_ref(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for Ident {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.name, f)
    }
}

impl FromStr for Ident {
    type Err = IdentError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::validate(s)?;
        let name = Arc::from(s.to_string().into_boxed_str());
        Ok(Self { span: SourceSpan::default(), name })
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Ident {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Ident {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let name = <&'de str as serde::Deserialize>::deserialize(deserializer)?;
        Self::new(name).map_err(serde::de::Error::custom)
    }
}

impl Serializable for Ident {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_usize(self.len());
        target.write_bytes(self.as_bytes());
    }
}

impl Deserializable for Ident {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        use alloc::string::ToString;

        let len = source.read_usize()?;
        let bytes = source.read_slice(len)?;
        let id = core::str::from_utf8(bytes)
            .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;
        Self::new(id).map_err(|err| DeserializationError::InvalidValue(err.to_string()))
    }
}

#[cfg(feature = "arbitrary")]
pub mod arbitrary {
    use alloc::{borrow::Cow, string::String};

    use proptest::{char::CharStrategy, collection::vec, prelude::*};

    use super::*;

    impl Arbitrary for Ident {
        type Parameters = ();

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            ident_any_random_length().boxed()
        }

        type Strategy = BoxedStrategy<Self>;
    }

    // Our dictionary includes all ASCII graphic characters (0x21..0x7E), as well as a variety
    // of unicode alphanumerics.
    const SPECIAL: [char; 32] = const {
        let mut buf = ['a'; 32];
        let mut idx = 0;
        let mut range_idx = 0;
        while range_idx < SPECIAL_RANGES.len() {
            let range = &SPECIAL_RANGES[range_idx];
            range_idx += 1;
            let mut j = *range.start() as u32;
            let end = *range.end() as u32;
            while j <= end {
                unsafe {
                    buf[idx] = char::from_u32_unchecked(j);
                }
                idx += 1;
                j += 1;
            }
        }
        buf
    };

    const SPECIAL_RANGES: &[core::ops::RangeInclusive<char>] =
        &['!'..='/', ':'..='@', '['..='`', '{'..='~'];
    const PREFERRED_RANGES: &[core::ops::RangeInclusive<char>] = &['a'..='z', 'A'..='Z'];
    const EXTRA_RANGES: &[core::ops::RangeInclusive<char>] = &['0'..='9', 'à'..='ö', 'ø'..='ÿ'];

    const PREFERRED_CONSTANT_RANGES: &[core::ops::RangeInclusive<char>] = &['A'..='Z'];
    const EXTRA_CONSTANT_RANGES: &[core::ops::RangeInclusive<char>] = &['0'..='9'];

    prop_compose! {
        /// A strategy to produce a random character from a more restricted dictionary for bare
        /// identifiers
        fn bare_ident_chars()
                      (c in CharStrategy::new_borrowed(
                          &['_'],
                          PREFERRED_RANGES,
                          &['0'..='9']
                      )) -> char {
            c
        }
    }

    prop_compose! {
        /// A strategy to produce a random character from our valid dictionary, using the rules
        /// for selection provided by `CharStrategy`
        fn ident_chars()
                      (c in CharStrategy::new_borrowed(
                          &SPECIAL,
                          PREFERRED_RANGES,
                          EXTRA_RANGES
                      )) -> char {
            c
        }
    }

    prop_compose! {
        /// Like `ident_chars`, but for constants
        fn const_ident_chars()
                      (c in CharStrategy::new_borrowed(
                          &['_'],
                          PREFERRED_CONSTANT_RANGES,
                          EXTRA_CONSTANT_RANGES
                      )) -> char {
            c
        }
    }

    prop_compose! {
        /// A strategy to produce a raw String of no more than length `length` bytes, containing any
        /// characters from our dictionary.
        ///
        /// The returned string will always be at least 1 characters.
        fn ident_raw_any(length: u32)
                        ((leading_char, rest) in (
                            proptest::char::ranges(Cow::Borrowed(&['a'..='z', '_'..='_'])),
                            vec(ident_chars(), 0..=(length as usize))
                        )) -> String {
            let mut buf = String::with_capacity(length as usize);
            buf.push(leading_char);
            for c in rest {
                if !buf.is_empty() && buf.len() + c.len_utf8() > length as usize {
                    break;
                }
                buf.push(c);
            }
            buf
        }
    }

    prop_compose! {
        /// Like `ident_raw_any`, but for bare identifiers
        fn bare_ident_raw_any(length: u32)
                        ((leading_char, rest) in (
                            proptest::char::range('a', 'z'),
                            vec(bare_ident_chars(), 0..=(length as usize))
                        )) -> String {
            let mut buf = String::with_capacity(length as usize);
            buf.push(leading_char);
            for c in rest {
                if !buf.is_empty() && buf.len() + c.len_utf8() > length as usize {
                    break;
                }
                buf.push(c);
            }
            buf
        }
    }

    prop_compose! {
        /// Like `ident_raw_any`, but for constants
        fn const_ident_raw_any(length: u32)
                        ((leading_char, rest) in (
                            proptest::char::range('A', 'Z'),
                            vec(const_ident_chars(), 0..=(length as usize))
                        )) -> String {
            let mut buf = String::with_capacity(length as usize);
            buf.push(leading_char);
            for c in rest {
                if !buf.is_empty() && buf.len() + c.len_utf8() > length as usize {
                    break;
                }
                buf.push(c);
            }
            buf
        }
    }

    prop_compose! {
        /// Generate a random identifier of `length` containing any characters from our dictionary
        pub fn ident_any(length: u32)
                    (raw in ident_raw_any(length)
                        .prop_filter(
                            "identifiers must be valid",
                            |s| Ident::validate(s).is_ok()
                        )
                    ) -> Ident {
            Ident::from_raw_parts(Span::new(SourceSpan::UNKNOWN, raw.into_boxed_str().into()))
        }
    }

    prop_compose! {
        /// Generate a random bare identifier of `length` containing any characters from our
        /// dictionary
        pub fn bare_ident_any(length: u32)
                    (raw in bare_ident_raw_any(length)
                        .prop_filter(
                            "identifiers must be valid",
                            |s| Ident::validate(s).is_ok()
                        )
                    ) -> Ident {
            Ident::from_raw_parts(Span::new(SourceSpan::UNKNOWN, raw.into_boxed_str().into()))
        }
    }

    prop_compose! {
        /// Generate a random constant identifier of `length` containing any characters from our
        /// constant dictionary
        pub fn const_ident_any(length: u32)
                    (raw in const_ident_raw_any(length)
                        .prop_filter(
                            "identifiers must be valid",
                            |s| Ident::validate(s).is_ok()
                        )
                    ) -> Ident {
            let id = Ident::from_raw_parts(Span::new(SourceSpan::UNKNOWN, raw.into_boxed_str().into()));
            assert!(id.is_constant_ident());
            id
        }
    }

    prop_compose! {
        /// Generate a random type identifier corresponding to of one of the built-in types
        pub fn builtin_type_any()
                                (name in prop_oneof![
                                    Just(crate::ast::types::Type::I1),
                                    Just(crate::ast::types::Type::I8),
                                    Just(crate::ast::types::Type::U8),
                                    Just(crate::ast::types::Type::I16),
                                    Just(crate::ast::types::Type::U16),
                                    Just(crate::ast::types::Type::I32),
                                    Just(crate::ast::types::Type::U32),
                                    Just(crate::ast::types::Type::I64),
                                    Just(crate::ast::types::Type::U64),
                                    Just(crate::ast::types::Type::I128),
                                    Just(crate::ast::types::Type::U128),
                                    Just(crate::ast::types::Type::Felt),
                                ]) -> Ident {
            Ident::from_raw_parts(Span::new(SourceSpan::UNKNOWN, name.to_string().into_boxed_str().into()))
        }
    }

    prop_compose! {
        /// Generate a random identifier of `length` containing any characters from our dictionary
        pub fn ident_any_random_length()
            (length in 1..u8::MAX)
            (id in ident_any(length as u32)) -> Ident {
            id
        }
    }

    prop_compose! {
        /// Generate a random bare identifier of `length` containing any characters from our
        /// dictionary
        pub fn bare_ident_any_random_length()
            (length in 1..u8::MAX)
            (id in ident_any(length as u32)) -> Ident {
            id
        }
    }

    prop_compose! {
        /// Generate a random constant identifier of `length` containing any characters from our
        /// dictionary
        pub fn const_ident_any_random_length()
            (length in 1..u8::MAX)
            (id in const_ident_any(length as u32)) -> Ident {
            id
        }
    }
}
