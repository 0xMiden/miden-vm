//! This is a no-std-compatible implementation of shell glob matching against paths.
//!
//! This is a simplified version of the [globset](https://crates.io/crates/globset) crate that is
//! defined as part of ripgrep, designed for single globs, with only the bare minimum features we
//! need.
use alloc::{
    borrow::Cow,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::Write;
#[cfg(feature = "std")]
use std::path::is_separator;

use miden_debug_types::Uri;

#[cfg(not(feature = "std"))]
fn is_separator(c: char) -> bool {
    matches!(c, '/')
}

/// Represents an error that can occur when parsing a glob pattern.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{}", self.format_error())]
pub struct Error {
    /// The original glob provided by the caller.
    glob: Option<String>,
    /// The kind of error.
    kind: ErrorKind,
}

impl Error {
    /// Return the glob that caused this error, if one exists.
    pub fn glob(&self) -> Option<&str> {
        self.glob.as_deref()
    }

    /// Return the kind of this error.
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    fn format_error(&self) -> String {
        if let Some(glob) = self.glob() {
            format!("error parsing glob '{glob}': {}", self.kind)
        } else {
            format!("{}", self.kind)
        }
    }
}

/// The kind of error that can occur when parsing a glob pattern.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Occurs when a character class (e.g., `[abc]`) is not closed.
    #[error("unclosed character class; missing ']'")]
    UnclosedClass,
    /// Occurs when a range in a character (e.g., `[a-z]`) is invalid. For
    /// example, if the range starts with a lexicographically larger character
    /// than it ends with.
    #[error("unclosed character range")]
    InvalidRange(char, char),
    /// Occurs when a `}` is found without a matching `{`.
    #[error("unopened alternate group; missing '{{' (maybe escape '}}' with '[}}]'?)")]
    UnopenedAlternates,
    /// Occurs when a `{` is found without a matching `}`.
    #[error("unclosed alternate group; missing '}}' (maybe escape '{{' with '[{{]'?)")]
    UnclosedAlternates,
    /// Occurs when an unescaped '\' is found at the end of a glob.
    #[error("dangling '\\'")]
    DanglingEscape,
    /// An error associated with parsing or compiling a regex.
    #[error("{0}")]
    Regex(String),
}

/// Glob represents a successfully parsed shell glob pattern.
///
/// It cannot be used directly to match file paths, but it can be converted
/// to a regular expression string or a matcher.
#[derive(Clone, Eq)]
pub struct Glob {
    glob: String,
    re: String,
    tokens: Tokens,
}

impl AsRef<Glob> for Glob {
    fn as_ref(&self) -> &Glob {
        self
    }
}

impl PartialEq for Glob {
    fn eq(&self, other: &Glob) -> bool {
        self.glob == other.glob
    }
}

#[cfg(feature = "std")]
impl std::hash::Hash for Glob {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.glob.hash(state);
    }
}

impl core::fmt::Debug for Glob {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if f.alternate() {
            f.debug_struct("Glob")
                .field("glob", &self.glob)
                .field("re", &self.re)
                .field("tokens", &self.tokens)
                .finish()
        } else {
            f.debug_tuple("Glob").field(&self.glob).finish()
        }
    }
}

impl core::fmt::Display for Glob {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.glob.fmt(f)
    }
}

impl core::str::FromStr for Glob {
    type Err = Error;

    fn from_str(glob: &str) -> Result<Self, Self::Err> {
        Self::new(glob)
    }
}

/// A matcher for a single pattern.
#[derive(Clone, Debug)]
pub struct GlobMatcher {
    /// The underlying pattern.
    pat: Glob,
    /// The pattern, as a compiled regex.
    re: regex::bytes::Regex,
}

impl Eq for GlobMatcher {}
impl PartialEq for GlobMatcher {
    fn eq(&self, other: &Self) -> bool {
        self.pat == other.pat
    }
}

impl GlobMatcher {
    /// Tests whether the given path matches this pattern or not.
    pub fn is_match(&self, path: &Uri) -> bool {
        self.is_match_candidate(&Candidate::new(path))
    }

    /// Tests whether the given path matches this pattern or not.
    pub fn is_match_candidate(&self, path: &Candidate<'_>) -> bool {
        self.re.is_match(path.path.as_bytes())
    }

    /// Returns the `Glob` used to compile this matcher.
    pub fn glob(&self) -> &Glob {
        &self.pat
    }
}

/// A candidate path for matching.
///
/// All glob matching in this crate operates on `Candidate` values.
/// Constructing candidates has a very small cost associated with it, so
/// callers may find it beneficial to amortize that cost when matching a single
/// path against multiple globs or sets of globs.
#[derive(Debug, Clone)]
pub struct Candidate<'a> {
    path: Cow<'a, str>,
}

impl<'a> Candidate<'a> {
    /// Create a new candidate for matching from the given path.
    pub fn new(uri: &'a Uri) -> Candidate<'a> {
        let path = normalize_path(uri);
        Candidate { path }
    }
}

/// Normalizes a path to use `/` as a separator everywhere, even on platforms
/// that recognize other characters as separators.
#[cfg(unix)]
pub(crate) fn normalize_path(uri: &Uri) -> Cow<'_, str> {
    // UNIX only uses /, so we're good.
    Cow::Borrowed(match uri.scheme() {
        Some("file") => uri.as_str().strip_prefix("file://").unwrap(),
        Some("stdin") => match uri.as_str().strip_prefix("stdin://").unwrap() {
            "" => "stdin",
            other => other,
        },
        // Try and match this other scheme anyway, which likely looks like a UNIX-style path
        Some(_) => uri.as_str().split_once("://").unwrap().1,
        None => uri.as_str(),
    })
}

/// Normalizes a path to use `/` as a separator everywhere, even on platforms
/// that recognize other characters as separators.
#[cfg(not(unix))]
pub(crate) fn normalize_path(uri: &Uri) -> Cow<'_, str> {
    let path = match uri.scheme() {
        Some("stdin") => {
            return Cow::Borrowed(match uri.as_str().strip_prefix("stdin://").unwrap() {
                "" => "stdin",
                other => other,
            });
        },
        Some(scheme) if scheme == "file" || scheme.chars().count() == 1 => {
            uri.as_str().split_once("://").unwrap().1
        },
        Some(_) => return Cow::Borrowed(uri.as_str().split_once("://").unwrap().1),
        None => uri.as_str(),
    };
    let mut output = String::with_capacity(path.len());
    for c in path.chars() {
        if matches!(c, '/') || !is_separator(c) {
            output.push(c);
            continue;
        }
        output.push('/');
    }
    Cow::Owned(output)
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Tokens(Vec<Token>);

impl core::ops::Deref for Tokens {
    type Target = Vec<Token>;

    fn deref(&self) -> &Vec<Token> {
        &self.0
    }
}

impl core::ops::DerefMut for Tokens {
    fn deref_mut(&mut self) -> &mut Vec<Token> {
        &mut self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Token {
    Literal(char),
    Any,
    ZeroOrMore,
    RecursivePrefix,
    RecursiveSuffix,
    RecursiveZeroOrMore,
    Class { negated: bool, ranges: Vec<(char, char)> },
    Alternates(Vec<Tokens>),
}

impl Glob {
    /// Builds a case-sensitive pattern with wildcards that may cross path separators.
    pub fn new(glob: &str) -> Result<Glob, Error> {
        let mut p = Parser {
            glob,
            alternates_stack: Vec::new(),
            branches: vec![Tokens::default()],
            chars: glob.chars().peekable(),
            prev: None,
            cur: None,
        };
        p.parse()?;
        if p.branches.is_empty() {
            // OK because of how the the branches/alternate_stack are managed.
            // If we end up here, then there *must* be a bug in the parser
            // somewhere.
            unreachable!()
        } else if p.branches.len() > 1 {
            Err(Error {
                glob: Some(glob.to_string()),
                kind: ErrorKind::UnclosedAlternates,
            })
        } else {
            let tokens = p.branches.pop().unwrap();
            Ok(Glob {
                glob: glob.to_string(),
                re: tokens.to_regex(),
                tokens,
            })
        }
    }

    /// Returns a matcher for this pattern.
    pub fn compile_matcher(&self) -> GlobMatcher {
        let mut re = regex::bytes::RegexBuilder::new(&self.re);
        re.unicode(false).dot_matches_new_line(true);

        let re = re.build().expect("regex compilation shouldn't fail");
        GlobMatcher { pat: self.clone(), re }
    }

    /// Returns the original glob pattern used to build this pattern.
    pub fn glob(&self) -> &str {
        &self.glob
    }

    /// Returns the regular expression string for this glob.
    ///
    /// Note that regular expressions for globs are intended to be matched on
    /// arbitrary bytes (`&[u8]`) instead of Unicode strings (`&str`). In
    /// particular, globs are frequently used on file paths, where there is no
    /// general guarantee that file paths are themselves valid UTF-8. As a
    /// result, callers will need to ensure that they are using a regex API
    /// that can match on arbitrary bytes. For example, the
    /// [`regex`](https://crates.io/regex)
    /// crate's
    /// [`Regex`](https://docs.rs/regex/*/regex/struct.Regex.html)
    /// API is not suitable for this since it matches on `&str`, but its
    /// [`bytes::Regex`](https://docs.rs/regex/*/regex/bytes/struct.Regex.html)
    /// API is suitable for this.
    pub fn regex(&self) -> &str {
        &self.re
    }
}

impl Tokens {
    /// Convert this pattern to a string that is guaranteed to be a valid
    /// regular expression and will represent the matching semantics of this
    /// glob pattern.
    fn to_regex(&self) -> String {
        let mut re = String::new();
        re.push_str("(?-u)");
        re.push('^');
        // Special case. If the entire glob is just `**`, then it should match
        // everything.
        if self.len() == 1 && self[0] == Token::RecursivePrefix {
            re.push_str(".*");
            re.push('$');
            return re;
        }
        Self::tokens_to_regex(self, &mut re);
        re.push('$');
        re
    }

    fn tokens_to_regex(tokens: &[Token], re: &mut String) {
        for tok in tokens.iter() {
            match *tok {
                Token::Literal(c) => {
                    re.push_str(&char_to_escaped_literal(c));
                },
                Token::Any => {
                    re.push('.');
                },
                Token::ZeroOrMore => {
                    re.push_str(".*");
                },
                Token::RecursivePrefix => {
                    re.push_str("(?:/?|.*/)");
                },
                Token::RecursiveSuffix => {
                    re.push_str("/.*");
                },
                Token::RecursiveZeroOrMore => {
                    re.push_str("(?:/|/.*/)");
                },
                Token::Class { negated, ref ranges } => {
                    re.push('[');
                    if negated {
                        re.push('^');
                    }
                    for r in ranges {
                        if r.0 == r.1 {
                            // Not strictly necessary, but nicer to look at.
                            re.push_str(&char_to_escaped_literal(r.0));
                        } else {
                            re.push_str(&char_to_escaped_literal(r.0));
                            re.push('-');
                            re.push_str(&char_to_escaped_literal(r.1));
                        }
                    }
                    re.push(']');
                },
                Token::Alternates(ref patterns) => {
                    let mut parts = vec![];
                    for pat in patterns {
                        let mut altre = String::new();
                        Self::tokens_to_regex(pat, &mut altre);
                        if !altre.is_empty() {
                            parts.push(altre);
                        }
                    }

                    // It is possible to have an empty set in which case the
                    // resulting alternation '()' would be an error.
                    if !parts.is_empty() {
                        re.push_str("(?:");
                        re.push_str(&parts.join("|"));
                        re.push(')');
                    }
                },
            }
        }
    }
}

/// Convert a Unicode scalar value to an escaped string suitable for use as
/// a literal in a non-Unicode regex.
fn char_to_escaped_literal(c: char) -> String {
    let mut buf = [0; 4];
    let bytes = c.encode_utf8(&mut buf).as_bytes();
    bytes_to_escaped_literal(bytes)
}

/// Converts an arbitrary sequence of bytes to a UTF-8 string. All non-ASCII
/// code units are converted to their escaped form.
fn bytes_to_escaped_literal(bs: &[u8]) -> String {
    let mut s = String::with_capacity(bs.len());
    for &b in bs {
        if b <= 0x7f {
            regex_syntax::escape_into(char::from(b).encode_utf8(&mut [0; 4]), &mut s);
        } else {
            write!(&mut s, "\\x{b:02x}").unwrap();
        }
    }
    s
}

struct Parser<'a> {
    /// The glob to parse.
    glob: &'a str,
    /// Marks the index in `stack` where the alternation started.
    alternates_stack: Vec<usize>,
    /// The set of active alternation branches being parsed.
    /// Tokens are added to the end of the last one.
    branches: Vec<Tokens>,
    /// A character iterator over the glob pattern to parse.
    chars: core::iter::Peekable<core::str::Chars<'a>>,
    /// The previous character seen.
    prev: Option<char>,
    /// The current character.
    cur: Option<char>,
}

impl<'a> Parser<'a> {
    fn error(&self, kind: ErrorKind) -> Error {
        Error { glob: Some(self.glob.to_string()), kind }
    }

    fn parse(&mut self) -> Result<(), Error> {
        while let Some(c) = self.bump() {
            match c {
                '?' => self.push_token(Token::Any)?,
                '*' => self.parse_star()?,
                '[' => self.parse_class()?,
                '{' => self.push_alternate()?,
                '}' => self.pop_alternate()?,
                ',' => self.parse_comma()?,
                '\\' => self.parse_backslash()?,
                c => self.push_token(Token::Literal(c))?,
            }
        }
        Ok(())
    }

    #[expect(clippy::unnecessary_wraps, reason = "Parser actions share a fallible interface")]
    fn push_alternate(&mut self) -> Result<(), Error> {
        self.alternates_stack.push(self.branches.len());
        self.branches.push(Tokens::default());
        Ok(())
    }

    fn pop_alternate(&mut self) -> Result<(), Error> {
        let Some(start) = self.alternates_stack.pop() else {
            return Err(self.error(ErrorKind::UnopenedAlternates));
        };
        assert!(start <= self.branches.len());
        let alts = Token::Alternates(self.branches.drain(start..).collect());
        self.push_token(alts)?;
        Ok(())
    }

    fn push_token(&mut self, tok: Token) -> Result<(), Error> {
        if let Some(ref mut pat) = self.branches.last_mut() {
            pat.push(tok);
            return Ok(());
        }
        Err(self.error(ErrorKind::UnopenedAlternates))
    }

    fn pop_token(&mut self) -> Result<Token, Error> {
        if let Some(ref mut pat) = self.branches.last_mut() {
            return Ok(pat.pop().unwrap());
        }
        Err(self.error(ErrorKind::UnopenedAlternates))
    }

    fn have_tokens(&self) -> Result<bool, Error> {
        match self.branches.last() {
            None => Err(self.error(ErrorKind::UnopenedAlternates)),
            Some(pat) => Ok(!pat.is_empty()),
        }
    }

    fn parse_comma(&mut self) -> Result<(), Error> {
        // If we aren't inside a group alternation, then don't
        // treat commas specially. Otherwise, we need to start
        // a new alternate branch.
        if self.alternates_stack.is_empty() {
            self.push_token(Token::Literal(','))
        } else {
            self.branches.push(Tokens::default());
            Ok(())
        }
    }

    fn parse_backslash(&mut self) -> Result<(), Error> {
        if !is_separator('\\') {
            match self.bump() {
                None => Err(self.error(ErrorKind::DanglingEscape)),
                Some(c) => self.push_token(Token::Literal(c)),
            }
        } else {
            // Normalize all patterns to use / as a separator.
            self.push_token(Token::Literal('/'))
        }
    }

    fn parse_star(&mut self) -> Result<(), Error> {
        let prev = self.prev;
        if self.peek() != Some('*') {
            self.push_token(Token::ZeroOrMore)?;
            return Ok(());
        }
        assert!(self.bump() == Some('*'));
        if !self.have_tokens()? {
            if !self.peek().is_none_or(is_separator) {
                self.push_token(Token::ZeroOrMore)?;
                self.push_token(Token::ZeroOrMore)?;
            } else {
                self.push_token(Token::RecursivePrefix)?;
                assert!(self.bump().is_none_or(is_separator));
            }
            return Ok(());
        }

        if !prev.map(is_separator).unwrap_or(false)
            && (self.branches.len() <= 1 || (prev != Some(',') && prev != Some('{')))
        {
            self.push_token(Token::ZeroOrMore)?;
            self.push_token(Token::ZeroOrMore)?;
            return Ok(());
        }
        let is_suffix = match self.peek() {
            None => {
                assert!(self.bump().is_none());
                true
            },
            Some(',' | '}') if self.branches.len() >= 2 => true,
            Some(c) if is_separator(c) => {
                assert!(self.bump().map(is_separator).unwrap_or(false));
                false
            },
            _ => {
                self.push_token(Token::ZeroOrMore)?;
                self.push_token(Token::ZeroOrMore)?;
                return Ok(());
            },
        };
        match self.pop_token()? {
            Token::RecursivePrefix => {
                self.push_token(Token::RecursivePrefix)?;
            },
            Token::RecursiveSuffix => {
                self.push_token(Token::RecursiveSuffix)?;
            },
            _ => {
                if is_suffix {
                    self.push_token(Token::RecursiveSuffix)?;
                } else {
                    self.push_token(Token::RecursiveZeroOrMore)?;
                }
            },
        }
        Ok(())
    }

    fn parse_class(&mut self) -> Result<(), Error> {
        fn add_to_last_range(glob: &str, r: &mut (char, char), add: char) -> Result<(), Error> {
            r.1 = add;
            if r.1 < r.0 {
                Err(Error {
                    glob: Some(glob.to_string()),
                    kind: ErrorKind::InvalidRange(r.0, r.1),
                })
            } else {
                Ok(())
            }
        }
        let mut ranges = vec![];
        let negated = match self.chars.peek() {
            Some(&'!' | &'^') => {
                let bump = self.bump();
                assert!(bump == Some('!') || bump == Some('^'));
                true
            },
            _ => false,
        };
        let mut first = true;
        let mut in_range = false;
        loop {
            let Some(c) = self.bump() else {
                return Err(self.error(ErrorKind::UnclosedClass));
            };
            match c {
                ']' => {
                    if first {
                        ranges.push((']', ']'));
                    } else {
                        break;
                    }
                },
                '-' => {
                    if first {
                        ranges.push(('-', '-'));
                    } else if in_range {
                        // invariant: in_range is only set when there is
                        // already at least one character seen.
                        let r = ranges.last_mut().unwrap();
                        add_to_last_range(self.glob, r, '-')?;
                        in_range = false;
                    } else {
                        assert!(!ranges.is_empty());
                        in_range = true;
                    }
                },
                c => {
                    if in_range {
                        // invariant: in_range is only set when there is
                        // already at least one character seen.
                        add_to_last_range(self.glob, ranges.last_mut().unwrap(), c)?;
                    } else {
                        ranges.push((c, c));
                    }
                    in_range = false;
                },
            }
            first = false;
        }
        if in_range {
            // Means that the last character in the class was a '-', so add
            // it as a literal.
            ranges.push(('-', '-'));
        }
        self.push_token(Token::Class { negated, ranges })
    }

    fn bump(&mut self) -> Option<char> {
        self.prev = self.cur;
        self.cur = self.chars.next();
        self.cur
    }

    fn peek(&mut self) -> Option<char> {
        self.chars.peek().copied()
    }
}

#[cfg(test)]
mod tests;
