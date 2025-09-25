use alloc::string::String;
use core::fmt;

/// Represents a pattern for matching text abstractly
/// for use in asserting contents of complex diagnostics
#[derive(Debug)]
pub enum Pattern {
    /// Searches for an exact match of the given literal in the input string
    Literal(alloc::borrow::Cow<'static, str>),
    /// Searches for a match of the given regular expression in the input string
    Regex(regex::Regex),
}
impl Pattern {
    /// Construct a [Pattern] representing the given regular expression
    #[track_caller]
    pub fn regex(pattern: impl AsRef<str>) -> Self {
        Self::Regex(regex::Regex::new(pattern.as_ref()).expect("invalid regex"))
    }

    /// Check if this pattern matches `input`
    pub fn is_match(&self, input: impl AsRef<str>) -> bool {
        match self {
            Self::Literal(pattern) => input.as_ref().contains(pattern.as_ref()),
            Self::Regex(regex) => regex.is_match(input.as_ref()),
        }
    }

    /// Assert that this pattern matches `input`.
    ///
    /// This behaves like `assert_eq!` or `assert_matches!`, i.e. it
    /// will produce a helpful panic message on failure that renders
    /// the difference between what the pattern expected, and what
    /// it actually was matched against.
    #[track_caller]
    pub fn assert_match(&self, input: impl AsRef<str>) {
        let input = input.as_ref();
        if !self.is_match(input) {
            panic!(
                r"expected string was not found in emitted diagnostics:
expected input to {expected}
matched against: `{actual}`
",
                expected = self,
                actual = input
            );
        }
    }

    /// Like [Pattern::assert_match], but renders additional context
    /// in the case of failure to aid in troubleshooting.
    #[track_caller]
    pub fn assert_match_with_context(&self, input: impl AsRef<str>, context: impl AsRef<str>) {
        let input = input.as_ref();
        let context = context.as_ref();
        if !self.is_match(input) {
            panic!(
                r"expected string was not found in emitted diagnostics:
expected input to {expected}
matched against: `{actual}`
full output: `{context}`
",
                expected = self,
                actual = input
            );
        }
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Literal(lit) => write!(f, "contain `{lit}`"),
            Self::Regex(pat) => write!(f, "match regular expression `{}`", pat.as_str()),
        }
    }
}

impl From<&'static str> for Pattern {
    fn from(s: &'static str) -> Self {
        Self::Literal(alloc::borrow::Cow::Borrowed(s.trim()))
    }
}

impl From<String> for Pattern {
    fn from(s: String) -> Self {
        Self::Literal(alloc::borrow::Cow::Owned(s))
    }
}

impl From<regex::Regex> for Pattern {
    fn from(pat: regex::Regex) -> Self {
        Self::Regex(pat)
    }
}
