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
    #[inline(always)]
    pub fn as_str(&self) -> &'a str {
        match self {
            Self::Root => "::",
            Self::Normal(id) => id,
        }
    }

    /// Get this component as an [Ident], if it represents an identifier
    #[inline]
    pub fn to_ident(&self) -> Option<Ident> {
        match self {
            Self::Root => None,
            Self::Normal(id) => Some(Ident::from_raw_parts(Span::unknown(Arc::from(
                id.to_string().into_boxed_str(),
            )))),
        }
    }

    /// Get the size in [prim@char]s of this component when printed
    pub fn char_len(&self) -> usize {
        match self {
            Self::Root => 2,
            Self::Normal(id) => id.chars().count(),
        }
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
/// at least one component.
///
/// # Errors
///
/// Returns an error if:
///
/// * The path is empty.
/// * Any component of the path is empty.
/// * Any component is not a valid identifier (quoted or unquoted) in Miden Assembly syntax, i.e.
///   starts with an ASCII alphabetic character, contains only printable ASCII characters, except
///   for `::`, which must only be used as a path separator.
pub struct Iter<'a> {
    components: Components<'a>,
}

impl<'a> Iter<'a> {
    pub fn new(path: &'a str) -> Self {
        Self {
            components: Components {
                path,
                front: State::Start,
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
struct Components<'a> {
    /// The path left to parse components from
    path: &'a str,
    // To support double-ended iteration, these states keep tack of what has been produced from
    // each end
    front: State,
    back: State,
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum State {
    // We're at the start of the path
    Start,
    // We're parsing components of the path
    Body,
    // We've started parsing a quoted component
    QuoteOpened,
    // We've parsed a quoted component
    QuoteClosed,
    // We're at the end of the path
    Done,
}

impl<'a> Components<'a> {
    fn finished(&self) -> bool {
        match (self.front, self.back) {
            (State::Done, _) => true,
            (_, State::Done) => true,
            (State::Body | State::QuoteOpened | State::QuoteClosed, State::Start) => true,
            (..) => false,
        }
    }
}

impl<'a> Iterator for Components<'a> {
    type Item = Result<PathComponent<'a>, PathError>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.finished() {
            match self.front {
                State::Start => match self.path.strip_prefix("::") {
                    Some(rest) => {
                        self.path = rest;
                        self.front = State::Body;
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
                        self.front = State::QuoteOpened;
                        self.path = rest;
                        continue;
                    }
                    match self.path.split_once("::") {
                        Some(("", rest)) => {
                            self.path = rest;
                            return Some(Err(PathError::InvalidComponent(
                                crate::ast::IdentError::Empty,
                            )));
                        },
                        Some((component, rest)) => {
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
                            return Some(Ok(PathComponent::Normal(component)));
                        },
                    }
                },
                State::QuoteOpened => match self.path.split_once('"') {
                    Some(("", rest)) => {
                        self.path = rest;
                        self.front = State::QuoteClosed;
                        return Some(Err(PathError::EmptyComponent));
                    },
                    Some((quoted, rest)) => {
                        self.path = rest;
                        self.front = State::QuoteClosed;
                        return Some(Ok(PathComponent::Normal(quoted)));
                    },
                    None => {
                        self.front = State::Done;
                        return Some(Err(PathError::UnclosedQuotedComponent));
                    },
                },
                State::QuoteClosed => {
                    if self.path.is_empty() {
                        self.front = State::Done;
                        continue;
                    }
                    match self.path.strip_prefix("::") {
                        Some(rest) => {
                            self.path = rest;
                            self.front = State::Body;
                        },
                        None => {
                            self.front = State::Done;
                            return Some(Err(PathError::MissingPathSeparator));
                        },
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
        while !self.finished() {
            match self.back {
                State::Start => {
                    self.back = State::Done;
                    match self.path {
                        "" => break,
                        "::" => return Some(Ok(PathComponent::Root)),
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
                        self.back = State::QuoteClosed;
                        self.path = rest;
                        continue;
                    }
                    match self.path.rsplit_once("::") {
                        Some(("", "")) => {
                            self.back = State::Start;
                            continue;
                        },
                        Some((prefix, component)) => {
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
                            if let Err(err) =
                                Ident::validate(component).map_err(PathError::InvalidComponent)
                            {
                                return Some(Err(err));
                            }
                            return Some(Ok(PathComponent::Normal(component)));
                        },
                    }
                },
                State::QuoteOpened => {
                    if self.path.is_empty() {
                        self.back = State::Start;
                        continue;
                    }
                    match self.path.strip_suffix("::") {
                        Some("") => {
                            self.back = State::Start;
                        },
                        Some(rest) => {
                            self.path = rest;
                            self.back = State::Body;
                        },
                        None => {
                            self.back = State::Done;
                            return Some(Err(PathError::MissingPathSeparator));
                        },
                    }
                },
                State::QuoteClosed => match self.path.rsplit_once('"') {
                    Some((rest, "")) => {
                        self.path = rest;
                        self.back = State::QuoteOpened;
                        return Some(Err(PathError::EmptyComponent));
                    },
                    Some((rest, quoted)) => {
                        self.path = rest;
                        self.back = State::QuoteOpened;
                        return Some(Ok(PathComponent::Normal(quoted)));
                    },
                    None => {
                        self.back = State::Done;
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
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next(), None);
    }

    #[test]
    fn path_with_quoted_component_back() {
        let mut components = Iter::new("\"foo\"");
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next_back(), None);
    }

    #[test]
    fn nested_path_with_quoted_component() {
        let mut components = Iter::new("foo::\"bar\"");
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("bar"))));
        assert_matches!(components.next(), None);
    }

    #[test]
    fn nested_path_with_quoted_component_back() {
        let mut components = Iter::new("foo::\"bar\"");
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Normal("bar"))));
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next_back(), None);
    }

    #[test]
    fn nested_path_with_interspersed_quoted_component() {
        let mut components = Iter::new("foo::\"bar\"::baz");
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("bar"))));
        assert_matches!(components.next(), Some(Ok(PathComponent::Normal("baz"))));
        assert_matches!(components.next(), None);
    }

    #[test]
    fn nested_path_with_interspersed_quoted_component_back() {
        let mut components = Iter::new("foo::\"bar\"::baz");
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Normal("baz"))));
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Normal("bar"))));
        assert_matches!(components.next_back(), Some(Ok(PathComponent::Normal("foo"))));
        assert_matches!(components.next_back(), None);
    }
}
