use alloc::{string::ToString, sync::Arc};
use core::{fmt, iter::FusedIterator};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{Path, PathError};
use crate::{ast::Ident, debuginfo::Span};

// PATH COMPONENT
// ================================================================================================

/// Represents a single component of a [Path]
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PathComponent<'a> {
    /// The root anchor, indicating that the path is absolute/fully qualified
    Root,
    /// A normal component of the path, i.e. an identifier
    Normal(&'a str),
}

impl<'a> PathComponent<'a> {
    /// Get this component as a [prim@str]
    ///
    /// NOTE: If the component is quoted, the resulting string does _not_ contain quotes. Depending
    /// on how the resulting string is used, you may need to ensure quotes are added manually. In
    /// general, the `Path`/`PathBuf` APIs handle this for you.
    pub fn as_str(&self) -> &'a str {
        match self {
            Self::Root => "::",
            Self::Normal(id) if id.starts_with('"') && id.ends_with('"') => &id[1..(id.len() - 1)],
            Self::Normal(id) => id,
        }
    }

    /// Get this component as an [Ident], if it represents an identifier
    #[inline]
    pub fn to_ident(&self) -> Option<Ident> {
        if matches!(self, Self::Root) {
            None
        } else {
            Some(Ident::from_raw_parts(Span::unknown(Arc::from(
                self.as_str().to_string().into_boxed_str(),
            ))))
        }
    }

    /// Get the size in [prim@char]s of this component when printed
    pub fn char_len(&self) -> usize {
        self.as_str().chars().count()
    }

    /// Returns true if this path component is a quoted string
    pub fn is_quoted(&self) -> bool {
        matches!(self, Self::Normal(component) if component.starts_with('"') && component.ends_with('"'))
    }

    /// Returns true if this path component requires quoting when displayed/stored as a string
    pub fn requires_quoting(&self) -> bool {
        matches!(self, Self::Normal(component) if component.contains("::"))
    }
}

impl PartialEq<str> for PathComponent<'_> {
    fn eq(&self, other: &str) -> bool {
        self.as_str().eq(other)
    }
}

impl AsRef<str> for PathComponent<'_> {
    #[inline(always)]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for PathComponent<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Returns an iterator over the path components represented in the provided source.
///
/// A path consists of at list of components separated by `::` delimiter. A path must contain
/// at least one component. Path components may be quoted, in which `::` delimiters are ignored.
/// Quoted path components may also contain characters that are not otherwise valid identifiers in
/// Miden Assembly.
///
/// Note that quoted components may not contain nested quotes - the appearance of a nested quote in
/// a quoted component will be treated as a closing quote resulting in unexpected behavior or
/// validation errors as a result.
///
/// # Errors
///
/// Returns an error if:
///
/// * The path is empty.
/// * Any component of the path is empty.
/// * Any quoted component is missing a closing/opening quote (depending on order of iteration)
/// * Any unquoted component is not a valid identifier (quoted or unquoted) in Miden Assembly
///   syntax, i.e. starts with an ASCII alphabetic character, contains only printable ASCII
///   characters, except for `::`, which must only be used as a path separator.
#[derive(Debug)]
pub struct Iter<'a> {
    components: Components<'a>,
}

impl<'a> Iter<'a> {
    pub fn new(path: &'a str) -> Self {
        Self {
            components: Components {
                path,
                original: path,
                front_pos: 0,
                front: State::Start,
                back_pos: path.len(),
                back: State::Body,
            },
        }
    }

    #[inline]
    pub fn as_path(&self) -> &'a Path {
        Path::new(self.components.path)
    }
}

impl FusedIterator for Iter<'_> {}

impl<'a> Iterator for Iter<'a> {
    type Item = Result<PathComponent<'a>, PathError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.components.next() {
            Some(Ok(PathComponent::Normal(component)))
                if component.len() > Path::MAX_COMPONENT_LENGTH =>
            {
                Some(Err(PathError::InvalidComponent(crate::ast::IdentError::InvalidLength {
                    max: Path::MAX_COMPONENT_LENGTH,
                })))
            },
            next => next,
        }
    }
}

impl<'a> DoubleEndedIterator for Iter<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        match self.components.next_back() {
            Some(Ok(PathComponent::Normal(component)))
                if component.len() > Path::MAX_COMPONENT_LENGTH =>
            {
                Some(Err(PathError::InvalidComponent(crate::ast::IdentError::InvalidLength {
                    max: Path::MAX_COMPONENT_LENGTH,
                })))
            },
            next => next,
        }
    }
}

/// The underlying path component iterator used by [Iter]
#[derive(Debug)]
struct Components<'a> {
    original: &'a str,
    /// The path left to parse components from
    path: &'a str,
    // To support double-ended iteration, these states keep tack of what has been produced from
    // each end
    front_pos: usize,
    front: State,
    back_pos: usize,
    back: State,
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum State {
    // We're at the start of the path
    Start,
    // We're parsing components of the path
    Body,
    // We've started parsing a quoted component
    QuoteOpened(usize),
    // We've parsed a quoted component
    QuoteClosed(usize),
    // We're at the end of the path
    Done,
}

impl<'a> Components<'a> {
    fn finished(&self) -> bool {
        match (self.front, self.back) {
            (State::Done, _) => true,
            (_, State::Done) => true,
            (State::Body | State::QuoteOpened(_) | State::QuoteClosed(_), State::Start) => true,
            (..) => false,
        }
    }
}

impl<'a> Iterator for Components<'a> {
    type Item = Result<PathComponent<'a>, PathError>;

    fn next(&mut self) -> Option<Self::Item> {
        // This is used when consuming a quoted item, to hold the result of the QuoteOpened state
        // until we've finished transitioning through the QuoteClosed state. It is never used
        // otherwise.
        let mut quote_opened = None;
        while !self.finished() || quote_opened.is_some() {
            match self.front {
                State::Start => match self.path.strip_prefix("::") {
                    Some(rest) => {
                        self.path = rest;
                        self.front = State::Body;
                        self.front_pos += 2;
                        return Some(Ok(PathComponent::Root));
                    },
                    None if self.path.starts_with(Path::KERNEL_PATH)
                        || self.path.starts_with(Path::EXEC_PATH) =>
                    {
                        self.front = State::Body;
                        return Some(Ok(PathComponent::Root));
                    },
                    None => {
                        self.front = State::Body;
                    },
                },
                State::Body => {
                    if let Some(rest) = self.path.strip_prefix('"') {
                        self.front = State::QuoteOpened(self.front_pos);
                        self.front_pos += 1;
                        self.path = rest;
                        continue;
                    }
                    match self.path.split_once("::") {
                        Some(("", rest)) => {
                            self.path = rest;
                            self.front_pos += 2;
                            return Some(Err(PathError::InvalidComponent(
                                crate::ast::IdentError::Empty,
                            )));
                        },
                        Some((component, rest)) => {
                            self.front_pos += component.len() + 2;
                            if rest.is_empty() {
                                self.path = "::";
                            } else {
                                self.path = rest;
                            }
                            if let Err(err) =
                                Ident::validate(component).map_err(PathError::InvalidComponent)
                            {
                                return Some(Err(err));
                            }
                            return Some(Ok(PathComponent::Normal(component)));
                        },
                        None if self.path.is_empty() => {
                            self.front = State::Done;
                        },
                        None => {
                            self.front = State::Done;
                            let component = self.path;
                            self.path = "";
                            if let Err(err) =
                                Ident::validate(component).map_err(PathError::InvalidComponent)
                            {
                                return Some(Err(err));
                            }
                            self.front_pos += component.len();
                            return Some(Ok(PathComponent::Normal(component)));
                        },
                    }
                },
                State::QuoteOpened(opened_at) => match self.path.split_once('"') {
                    Some(("", rest)) => {
                        self.path = rest;
                        self.front = State::QuoteClosed(self.front_pos);
                        self.front_pos += 1;
                        quote_opened = Some(Err(PathError::EmptyComponent));
                    },
                    Some((quoted, rest)) => {
                        self.path = rest;
                        self.front_pos += quoted.len();
                        self.front = State::QuoteClosed(self.front_pos);
                        self.front_pos += 1;
                        let quoted = &self.original[opened_at..self.front_pos];
                        quote_opened = Some(Ok(PathComponent::Normal(quoted)));
                    },
                    None => {
                        self.front = State::Done;
                        self.front_pos += self.path.len();
                        return Some(Err(PathError::UnclosedQuotedComponent));
                    },
                },
                State::QuoteClosed(_) => {
                    if self.path.is_empty() {
                        self.front = State::Done;
                    } else {
                        match self.path.strip_prefix("::") {
                            Some(rest) => {
                                self.path = rest;
                                self.front = State::Body;
                                self.front_pos += 2;
                            },
                            // If we would raise an error, but we have a quoted component to return
                            // first, leave the state untouched, return the quoted component, and we
                            // will return here on the next call to `next_back`
                            None if quote_opened.is_some() => (),
                            None => {
                                self.front = State::Done;
                                return Some(Err(PathError::MissingPathSeparator));
                            },
                        }
                    }

                    if quote_opened.is_some() {
                        return quote_opened;
                    }
                },
                State::Done => break,
            }
        }

        None
    }
}

impl<'a> DoubleEndedIterator for Components<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        // This is used when consuming a quoted item, to hold the result of the QuoteClosed state
        // until we've finished transitioning through the QuoteOpened state. It is never used
        // otherwise.
        let mut quote_closed = None;
        while !self.finished() || quote_closed.is_some() {
            match self.back {
                State::Start => {
                    self.back = State::Done;
                    match self.path {
                        "" => break,
                        "::" => {
                            self.back_pos = 0;
                            return Some(Ok(PathComponent::Root));
                        },
                        other => {
                            assert!(
                                other.starts_with(Path::KERNEL_PATH)
                                    || other.starts_with(Path::EXEC_PATH),
                                "expected path in start state to be a valid path prefix, got '{other}'"
                            );
                            return Some(Ok(PathComponent::Root));
                        },
                    }
                },
                State::Body => {
                    if let Some(rest) = self.path.strip_suffix('"') {
                        self.back = State::QuoteClosed(self.back_pos);
                        self.back_pos -= 1;
                        self.path = rest;
                        continue;
                    }
                    match self.path.rsplit_once("::") {
                        Some(("", "")) => {
                            self.back = State::Start;
                            self.back_pos -= 2;
                            continue;
                        },
                        Some((prefix, component)) => {
                            self.back_pos -= component.len() + 2;
                            if prefix.is_empty() {
                                self.path = "::";
                                self.back = State::Start;
                            } else {
                                self.path = prefix;
                            }
                            if let Err(err) =
                                Ident::validate(component).map_err(PathError::InvalidComponent)
                            {
                                return Some(Err(err));
                            }
                            return Some(Ok(PathComponent::Normal(component)));
                        },
                        None if self.path.is_empty() => {
                            self.back = State::Start;
                        },
                        None => {
                            self.back = State::Start;
                            let component = self.path;
                            if component.starts_with(Path::KERNEL_PATH)
                                || component.starts_with(Path::EXEC_PATH)
                            {
                                self.path = "::";
                            } else {
                                self.path = "";
                            }
                            self.back_pos = 0;
                            if let Err(err) =
                                Ident::validate(component).map_err(PathError::InvalidComponent)
                            {
                                return Some(Err(err));
                            }
                            return Some(Ok(PathComponent::Normal(component)));
                        },
                    }
                },
                State::QuoteOpened(_) => {
                    if self.path.is_empty() {
                        self.back = State::Start;
                    } else {
                        match self.path.strip_suffix("::") {
                            Some("") => {
                                self.back = State::Start;
                                self.back_pos -= 2;
                            },
                            Some(rest) => {
                                self.back_pos -= 2;
                                self.path = rest;
                                self.back = State::Body;
                            },
                            // If we would raise an error, but we have a quoted component to return
                            // first, leave the state untouched, return the quoted component, and we
                            // will return here on the next call to `next_back`
                            None if quote_closed.is_some() => (),
                            None => {
                                self.back = State::Done;
                                return Some(Err(PathError::MissingPathSeparator));
                            },
                        }
                    }

                    if quote_closed.is_some() {
                        return quote_closed;
                    }
                },
                State::QuoteClosed(closed_at) => match self.path.rsplit_once('"') {
                    Some((rest, "")) => {
                        self.back_pos -= 1;
                        self.path = rest;
                        self.back = State::QuoteOpened(self.back_pos);
                        quote_closed = Some(Err(PathError::EmptyComponent));
                    },
                    Some((rest, quoted)) => {
                        self.back_pos -= quoted.len() + 1;
                        let quoted = &self.original[self.back_pos..closed_at];
                        self.path = rest;
                        self.back = State::QuoteOpened(self.back_pos);
                        quote_closed = Some(Ok(PathComponent::Normal(quoted)));
                    },
                    None => {
                        self.back = State::Done;
                        self.back_pos = 0;
                        return Some(Err(PathError::UnclosedQuotedComponent));
                    },
                },
                State::Done => break,
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use miden_core::assert_matches;

    use super::*;

    #[test]
    fn empty_path() {
        let mut components = Iter::new("");
        assert_matches!(components.next(), None);
    }

    #[test]
    fn empty_path_back() {
        let mut components = Iter::new("");
        assert_matches!(components.next_back(), None);
    }

    #[test]
    fn root_prefix_path() {
        let mut components = Iter::new("::");
        assert_matches!(components.next(), Some(Ok(PathComponent::Root)));
        assert_matches!(components.next(), None);
    }

    #[test]
    fn root_prefix_path_back() {
        let mut components = Iter::new("::");
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Root)));
        assert_matches!(components.next_back(), None);
    }

    #[test]
    fn absolute_path() {
        let mut components = Iter::new("::foo");
        assert_matches!(components.next(), Some(Ok(PathComponent::Root)));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next(), None);
    }

    #[test]
    fn absolute_path_back() {
        let mut components = Iter::new("::foo");
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Root)));
        assert_matches!(components.next_back(), None);
    }

    #[test]
    fn absolute_nested_path() {
        let mut components = Iter::new("::foo::bar");
        assert_matches!(components.next(), Some(Ok(PathComponent::Root)));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("bar"))));
        assert_matches!(components.next(), None);
    }

    #[test]
    fn absolute_nested_path_back() {
        let mut components = Iter::new("::foo::bar");
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Normal("bar"))));
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Root)));
        assert_matches!(components.next_back(), None);
    }

    #[test]
    fn relative_path() {
        let mut components = Iter::new("foo");
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next(), None);
    }

    #[test]
    fn relative_path_back() {
        let mut components = Iter::new("foo");
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next_back(), None);
    }

    #[test]
    fn relative_nested_path() {
        let mut components = Iter::new("foo::bar");
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("bar"))));
        assert_matches!(components.next(), None);
    }

    #[test]
    fn relative_nested_path_back() {
        let mut components = Iter::new("foo::bar");
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Normal("bar"))));
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next_back(), None);
    }

    #[test]
    fn special_path() {
        let mut components = Iter::new("$kernel");
        assert_matches!(components.next(), Some(Ok(PathComponent::Root)));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("$kernel"))));
        assert_matches!(components.next(), None);
    }

    #[test]
    fn special_path_back() {
        let mut components = Iter::new("$kernel");
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Normal("$kernel"))));
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Root)));
        assert_matches!(components.next_back(), None);
    }

    #[test]
    fn special_nested_path() {
        let mut components = Iter::new("$kernel::bar");
        assert_matches!(components.next(), Some(Ok(PathComponent::Root)));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("$kernel"))));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("bar"))));
        assert_matches!(components.next(), None);
    }

    #[test]
    fn special_nested_path_back() {
        let mut components = Iter::new("$kernel::bar");
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Normal("bar"))));
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Normal("$kernel"))));
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Root)));
        assert_matches!(components.next_back(), None);
    }

    #[test]
    fn path_with_quoted_component() {
        let mut components = Iter::new("\"foo\"");
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("\"foo\""))));
        assert_matches!(components.next(), None);
    }

    #[test]
    fn path_with_quoted_component_back() {
        let mut components = Iter::new("\"foo\"");
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Normal("\"foo\""))));
        assert_matches!(components.next_back(), None);
    }

    #[test]
    fn nested_path_with_quoted_component() {
        let mut components = Iter::new("foo::\"bar\"");
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("\"bar\""))));
        assert_matches!(components.next(), None);
    }

    #[test]
    fn nested_path_with_quoted_component_back() {
        let mut components = Iter::new("foo::\"bar\"");
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Normal("\"bar\""))));
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next_back(), None);
    }

    #[test]
    fn nested_path_with_interspersed_quoted_component() {
        let mut components = Iter::new("foo::\"bar\"::baz");
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("\"bar\""))));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("baz"))));
        assert_matches!(components.next(), None);
    }

    #[test]
    fn nested_path_with_interspersed_quoted_component_back() {
        let mut components = Iter::new("foo::\"bar\"::baz");
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Normal("baz"))));
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Normal("\"bar\""))));
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next_back(), None);
    }
}
