mod components;
#[expect(clippy::module_inception)]
mod path;
mod path_buf;

pub use self::{
    components::{Iter, PathComponent},
    path::Path,
    path_buf::PathBuf,
};
#[cfg(feature = "serde")]
use crate::debuginfo::Span;
use crate::diagnostics::{Diagnostic, miette};

/// Represents errors that can occur when creating, parsing, or manipulating [Path]s
#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error("invalid item path: cannot be empty")]
    Empty,
    #[error("invalid item path component: cannot be empty")]
    EmptyComponent,
    #[error("invalid item path component: {0}")]
    InvalidComponent(crate::ast::IdentError),
    #[error("invalid item path: contains invalid utf8 byte sequences")]
    InvalidUtf8,
    #[error(transparent)]
    InvalidNamespace(NamespaceError),
    #[error("cannot join a path with reserved name to other paths")]
    UnsupportedJoin,
    #[error("'::' delimiter found where path component was expected")]
    UnexpectedDelimiter,
    #[error("path is missing a '::' delimiter between quoted/unquoted components")]
    MissingPathSeparator,
    #[error("quoted path component is missing a closing '\"'")]
    UnclosedQuotedComponent,
}

/// Represents an error when parsing or validating a library namespace
#[derive(Debug, thiserror::Error, Diagnostic)]
pub enum NamespaceError {
    #[error("invalid library namespace name: cannot be empty")]
    #[diagnostic()]
    Empty,
    #[error("invalid library namespace name: too many characters")]
    #[diagnostic()]
    Length,
    #[error(
        "invalid character in library namespace: expected lowercase ascii-alphanumeric character or '_'"
    )]
    #[diagnostic()]
    InvalidChars,
    #[error("invalid library namespace name: must start with lowercase ascii-alphabetic character")]
    #[diagnostic()]
    InvalidStart,
}

/// This trait abstracts over the concept of matching a prefix pattern against a path
pub trait StartsWith<Prefix: ?Sized> {
    /// Returns true if the current path, sans root component, starts with `prefix`
    fn starts_with(&self, prefix: &Prefix) -> bool;

    /// Returns true if the current path, including root component, starts with `prefix`
    fn starts_with_exactly(&self, prefix: &Prefix) -> bool;
}

/// Serialize a [Path]-like value
#[cfg(feature = "serde")]
pub fn serialize<P, S>(path: P, serializer: S) -> Result<S::Ok, S::Error>
where
    P: AsRef<Path>,
    S: serde::Serializer,
{
    use serde::Serialize;
    path.as_ref().serialize(serializer)
}

/// Deserialize a [Path]-like value
#[cfg(feature = "serde")]
pub fn deserialize<'de, P, D>(deserializer: D) -> Result<P, D::Error>
where
    P: From<&'de Path>,
    D: serde::Deserializer<'de>,
{
    let path = <&'de Path as serde::Deserialize>::deserialize(deserializer)?;
    Ok(P::from(path))
}

/// Deserialize a [Path]-like value wrapped in a [Span]
#[cfg(feature = "serde")]
pub fn deserialize_spanned<'de, P, D>(deserializer: D) -> Result<Span<P>, D::Error>
where
    P: From<&'de Path>,
    D: serde::Deserializer<'de>,
{
    let path = <&'de Path as serde::Deserialize>::deserialize(deserializer)?;
    Ok(Span::unknown(P::from(path)))
}

#[cfg(feature = "arbitrary")]
pub mod arbitrary {
    use alloc::{sync::Arc, vec::Vec};

    use proptest::{arbitrary::Arbitrary, collection::vec, prelude::*};

    use super::*;
    use crate::ast::{Ident, ident};

    impl Arbitrary for PathBuf {
        type Parameters = ();

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            pathbuf_random_length(1).boxed()
        }

        type Strategy = BoxedStrategy<Self>;
    }

    prop_compose! {
        /// A strategy to produce a raw vector of between `min` and `max` path components,
        /// either quoted or bare.
        fn components_any(min: u8, max: u8)
                            (components in vec(prop_oneof![
                                ident::arbitrary::ident_any_random_length(),
                                ident::arbitrary::bare_ident_any_random_length()
                             ], (min as usize)..=(max as usize))) -> Vec<Ident> {
            components
        }
    }

    prop_compose! {
        /// A strategy to produce a raw vector of between `min` and `max` bare path
        /// components.
        fn bare_components_any(min: u8, max: u8)
                            (components in vec(ident::arbitrary::bare_ident_any_random_length(), (min as usize)..=(max as usize))) -> Vec<Ident> {
            components
        }
    }

    prop_compose! {
        /// A strategy to produce a PathBuf of between `min` and `max` components (either bare or
        /// quoted).
        pub fn pathbuf(min: u8, max: u8)
                      (components in components_any(min, max)) -> PathBuf {
            let mut buf = PathBuf::default();
            for component in components {
                buf.push(&component);
            }
            buf
        }
    }

    prop_compose! {
        /// A strategy to produce a PathBuf of up between `min` and `max` bare components.
        pub fn bare_pathbuf(min: u8, max: u8)
                      (components in bare_components_any(min, max)) -> PathBuf {
            let mut buf = PathBuf::default();
            for component in components {
                buf.push(&component);
            }
            buf
        }
    }

    prop_compose! {
        /// A strategy to produce a PathBuf of between `min` and `max` prefix components (either
        /// bare or quoted), with a constant identifier as the last component.
        ///
        /// The returned PathBuf will always have at least one component
        pub fn constant_pathbuf(min: u8, max: u8)
                        (prefix in components_any(min, max), name in ident::arbitrary::const_ident_any_random_length()) -> PathBuf {
            let mut buf = PathBuf::default();
            for component in prefix {
                buf.push(&component);
            }
            buf.push(&name);
            buf
        }
    }

    prop_compose! {
        /// A strategy to produce a PathBuf corresponding to a built-in type reference.
        ///
        /// The returned PathBuf will always have a single component
        pub fn builtin_type_pathbuf()
                (name in ident::arbitrary::builtin_type_any()) -> PathBuf {
            PathBuf::from(name)
        }
    }

    prop_compose! {
        /// A strategy to produce a PathBuf of up to between `min` and `max` prefix components
        /// (either bare or quoted), with a user-defined type identifier as the last component.
        pub fn user_defined_type_pathbuf(min: u8, max: u8)
                          ((name, prefix) in (ident::arbitrary::bare_ident_any_random_length(), components_any(min, max))) -> PathBuf {
            let mut buf = PathBuf::default();
            for component in prefix {
                buf.push(&component);
            }
            buf.push(&name);
            buf
        }
    }

    prop_compose! {
        /// A strategy to produce a PathBuf corresponding to a valid `TypeExpr::Ref`, where
        /// user-defined type paths will have between `min` and `max` components.
        pub fn type_pathbuf(min: u8, max: u8)
                (path in prop_oneof![
                    1 => user_defined_type_pathbuf(min, max),
                    2 => builtin_type_pathbuf()
                ]) -> PathBuf {
            path
        }
    }

    prop_compose! {
        /// Generate a PathBuf of random length, but at least `min` components.
        ///
        /// The returned PathBuf will always have at least one component, regardless of `min`
        pub fn pathbuf_random_length(min: u8)
                (max in min..=core::cmp::max(min.saturating_add(1), 10))
                (path in pathbuf(min, max)) -> PathBuf {
            path
        }
    }

    prop_compose! {
        /// Generate a PathBuf of random length, but at least `min` components.
        ///
        /// The returned PathBuf will always have at least one component, regardless of `min`.
        ///
        /// All components of the path will be valid bare identifiers.
        pub fn bare_pathbuf_random_length(min: u8)
                (max in min..=core::cmp::max(min.saturating_add(1), 10))
                (path in bare_pathbuf(min, max)) -> PathBuf {
            path
        }
    }

    prop_compose! {
        /// Generate a PathBuf of random length, but at least `min` prefix components, that is valid
        /// for use with constant items.
        ///
        /// The returned PathBuf will always have at least one component, the name of the constant.
        pub fn constant_pathbuf_random_length(min: u8)
                (max in min..=core::cmp::max(min.saturating_add(1), 10))
                (path in constant_pathbuf(min, max)) -> PathBuf {
            path
        }
    }

    prop_compose! {
        /// Generate a PathBuf of random length, but at least `min` prefix components, that is valid
        /// for use as a type reference.
        ///
        /// The returned PathBuf will always have at least one component, the name of the type.
        pub fn type_pathbuf_random_length(min: u8)
                (max in min..=core::cmp::max(min.saturating_add(1), 10))
                (path in type_pathbuf(min, max)) -> PathBuf {
            path
        }
    }

    prop_compose! {
        /// Generate a PathBuf of random length, but at least `min` prefix components, that is valid
        /// for use with user-defined type items.
        ///
        /// The returned PathBuf will always have at least one component, the name of the type.
        pub fn user_defined_type_pathbuf_random_length(min: u8)
                (max in min..=core::cmp::max(min.saturating_add(1), 10))
                (path in user_defined_type_pathbuf(min, max)) -> PathBuf {
            path
        }
    }

    prop_compose! {
        /// Generate a `Arc<Path>` of random length, but at least `min` components.
        pub fn path_random_length(min: u8)
            (path in pathbuf_random_length(min)) -> Arc<Path> {
            path.into()
        }
    }

    prop_compose! {
        /// Generate a `Arc<Path>` of random length, but at least `min` components.
        ///
        /// All components of the path will be valid bare identifiers.
        pub fn bare_path_random_length(min: u8)
            (path in bare_pathbuf_random_length(min)) -> Arc<Path> {
            path.into()
        }
    }

    prop_compose! {
        /// Generate a `Arc<Path>` of random length, but at least `min` prefix components, that is
        /// valid for use with constant items.
        ///
        /// The returned PathBuf will always have at least one component, the name of the constant.
        pub fn constant_path_random_length(min: u8)
            (path in constant_pathbuf_random_length(min)) -> Arc<Path> {
            path.into()
        }
    }

    prop_compose! {
        /// Generate a `Arc<Path>` of random length, but at least `min` prefix components, that is
        /// valid for use with type references.
        ///
        /// The returned PathBuf will always have at least one component, the name of the type.
        pub fn type_path_random_length(min: u8)
            (path in type_pathbuf_random_length(min)) -> Arc<Path> {
            path.into()
        }
    }

    prop_compose! {
        /// Generate a `Arc<Path>` of random length, but at least `min` prefix components, that is
        /// valid for use with user-defined type items.
        ///
        /// The returned PathBuf will always have at least one component, the name of the type.
        pub fn user_defined_type_path_random_length(min: u8)
            (path in user_defined_type_pathbuf_random_length(min)) -> Arc<Path> {
            path.into()
        }
    }
}
