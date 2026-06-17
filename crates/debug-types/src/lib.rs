#![no_std]

extern crate alloc;

#[cfg(any(feature = "std", test))]
extern crate std;

mod location;
mod selection;
mod source_file;
mod source_manager;
mod span;

#[cfg(feature = "arbitrary")]
use alloc::vec;
use alloc::{string::String, sync::Arc};

use miden_crypto::utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};
#[cfg(feature = "arbitrary")]
use proptest::prelude::*;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
pub use serde_spanned;

#[cfg(feature = "std")]
pub use self::source_manager::SourceManagerExt;
pub use self::{
    location::{FileLineCol, Location},
    selection::{Position, Selection},
    source_file::{
        ByteIndex, ByteOffset, ColumnIndex, ColumnNumber, LineIndex, LineNumber, SourceContent,
        SourceContentUpdateError, SourceFile, SourceFileRef, SourceLanguage,
    },
    source_manager::{
        DefaultSourceManager, SourceId, SourceManager, SourceManagerError, SourceManagerSync,
    },
    span::{SourceSpan, Span, Spanned},
};

// URI
// ================================================================================================

/// A [URI reference](https://datatracker.ietf.org/doc/html/rfc3986#section-4.1) that specifies
/// the location of a source file, whether on disk, on the network, or elsewhere.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true))
)]
pub struct Uri(Arc<str>);

impl Uri {
    pub fn new(uri: impl AsRef<str>) -> Self {
        uri.as_ref().into()
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Returns the scheme portion of this URI, if present.
    pub fn scheme(&self) -> Option<&str> {
        match self.0.split_once("://") {
            Some((prefix, _))
                if prefix.contains(|c: char| {
                    !c.is_ascii_alphanumeric() && !matches!(c, '+' | '-' | '.')
                }) =>
            {
                None
            },
            Some((prefix, _)) => Some(prefix),
            None => None,
        }
    }

    /// Returns the authority portion of this URI, if present.
    pub fn authority(&self) -> Option<&str> {
        let rest = self.hierarchical_part();
        let authority_and_path = rest.strip_prefix("//")?;
        match authority_and_path.split_once(['/', '?', '#']) {
            Some((authority, _)) => Some(authority),
            None => Some(authority_and_path),
        }
    }

    /// Returns the path portion of this URI.
    pub fn path(&self) -> &str {
        let rest = self.hierarchical_part();
        let path = match rest.strip_prefix("//") {
            Some(authority_and_path) => match authority_and_path.find('/') {
                Some(pos) => &authority_and_path[pos..],
                None => return "",
            },
            None => rest,
        };
        strip_query_and_fragment(path)
    }

    /// Convert this URI to a [std::path::PathBuf], if it represents a file path
    #[cfg(feature = "std")]
    pub fn to_path(&self) -> Option<std::path::PathBuf> {
        if has_windows_drive_prefix(self.as_str()) {
            return Some(std::path::PathBuf::from(self.as_str()));
        }

        match self.scheme() {
            None if has_restricted_scheme_prefix_without_slashes(self.as_str()) => None,
            None if self.authority().is_none() => Some(std::path::PathBuf::from(self.as_str())),
            None => None,
            Some(scheme)
                if scheme.eq_ignore_ascii_case("file")
                    && (matches!(self.authority(), None | Some(""))
                        || self.authority().is_some_and(|authority| {
                            authority.eq_ignore_ascii_case("localhost")
                        })) =>
            {
                Some(std::path::PathBuf::from(local_file_uri_path(self.path())))
            },
            Some(_) => None,
        }
    }

    fn hierarchical_part(&self) -> &str {
        match self.scheme() {
            Some(scheme) => &self.0[scheme.len() + 1..],
            None => self.0.as_ref(),
        }
    }
}

#[cfg(feature = "std")]
fn has_windows_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}

#[cfg(feature = "std")]
fn has_restricted_scheme_prefix_without_slashes(uri: &str) -> bool {
    matches!(
        uri.split_once(':'),
        Some((prefix, rest))
            if !rest.starts_with("//")
                && !prefix.is_empty()
                && prefix
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    )
}

#[cfg(feature = "std")]
fn local_file_uri_path(path: &str) -> &str {
    match path.strip_prefix('/') {
        Some(path_without_leading_slash)
            if has_windows_drive_prefix(path_without_leading_slash) =>
        {
            path_without_leading_slash
        },
        _ => path,
    }
}

fn strip_query_and_fragment(path: &str) -> &str {
    match path.split_once(['?', '#']) {
        Some((path, _)) => path,
        None => path,
    }
}

impl core::fmt::Display for Uri {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, f)
    }
}

impl AsRef<str> for Uri {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl From<&str> for Uri {
    #[inline]
    fn from(value: &str) -> Self {
        use alloc::string::ToString;

        value.to_string().into()
    }
}

impl From<Uri> for Arc<str> {
    fn from(value: Uri) -> Self {
        value.0
    }
}

impl From<Arc<str>> for Uri {
    #[inline]
    fn from(uri: Arc<str>) -> Self {
        Self(uri)
    }
}

impl From<alloc::boxed::Box<str>> for Uri {
    #[inline]
    fn from(uri: alloc::boxed::Box<str>) -> Self {
        Self(uri.into())
    }
}

impl From<String> for Uri {
    #[inline]
    fn from(uri: String) -> Self {
        Self(uri.into_boxed_str().into())
    }
}

#[cfg(feature = "std")]
impl<'a> From<&'a std::path::Path> for Uri {
    fn from(path: &'a std::path::Path) -> Self {
        use alloc::string::ToString;

        Self::from(path.display().to_string())
    }
}

#[cfg(feature = "std")]
impl From<std::path::PathBuf> for Uri {
    fn from(path: std::path::PathBuf) -> Self {
        use alloc::string::ToString;

        Self::from(path.display().to_string())
    }
}

#[cfg(feature = "std")]
impl From<Arc<std::path::Path>> for Uri {
    fn from(path: Arc<std::path::Path>) -> Self {
        use alloc::string::ToString;

        Self::from(path.display().to_string())
    }
}

impl Serializable for Uri {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.as_str().write_into(target);
    }
}

impl Deserializable for Uri {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        String::read_from(source).map(Self::from)
    }
}

impl core::str::FromStr for Uri {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(s))
    }
}

#[cfg(feature = "arbitrary")]
impl Arbitrary for Uri {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use alloc::string::String;

        proptest::collection::vec(
            proptest::prop_oneof![
                proptest::char::range('a', 'z'),
                proptest::char::range('A', 'Z'),
                proptest::char::range('0', '9'),
                Just('/'),
                Just(':'),
                Just('.'),
                Just('-'),
                Just('_'),
                Just('#'),
                Just('?'),
                Just('@'),
            ],
            1..48,
        )
        .prop_map(|chars| Self::from(chars.into_iter().collect::<String>()))
        .boxed()
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_scheme_extraction() {
        let relative_file = Uri::new("foo.masm");
        let relative_file_path = Uri::new("./foo.masm");
        let relative_file_path_with_colon = Uri::new("file:foo.masm");
        let absolute_file_path = Uri::new("file:///tmp/foo.masm");
        let http_simple_uri = Uri::new("http://www.example.com");
        let http_simple_uri_with_userinfo = Uri::new("http://foo:bar@www.example.com");
        let http_simple_uri_with_userinfo_and_port = Uri::new("http://foo:bar@www.example.com:443");
        let http_simple_uri_with_userinfo_and_path =
            Uri::new("http://foo:bar@www.example.com/api/v1");
        let http_simple_uri_with_userinfo_and_query =
            Uri::new("http://foo:bar@www.example.com?param=1");
        let http_simple_uri_with_userinfo_and_fragment =
            Uri::new("http://foo:bar@www.example.com#about");
        let http_simple_uri_with_userinfo_and_path_and_query =
            Uri::new("http://foo:bar@www.example.com/api/v1/user?id=1");
        let http_simple_uri_with_userinfo_and_path_and_query_and_fragment =
            Uri::new("http://foo:bar@www.example.com/api/v1/user?id=1#redirect=/home");

        assert_eq!(relative_file.scheme(), None);
        assert_eq!(relative_file_path.scheme(), None);
        assert_eq!(relative_file_path_with_colon.scheme(), None);
        assert_eq!(absolute_file_path.scheme(), Some("file"));
        assert_eq!(http_simple_uri.scheme(), Some("http"));
        assert_eq!(http_simple_uri_with_userinfo.scheme(), Some("http"));
        assert_eq!(http_simple_uri_with_userinfo_and_port.scheme(), Some("http"));
        assert_eq!(http_simple_uri_with_userinfo_and_path.scheme(), Some("http"));
        assert_eq!(http_simple_uri_with_userinfo_and_query.scheme(), Some("http"));
        assert_eq!(http_simple_uri_with_userinfo_and_fragment.scheme(), Some("http"));
        assert_eq!(http_simple_uri_with_userinfo_and_path_and_query.scheme(), Some("http"));
        assert_eq!(
            http_simple_uri_with_userinfo_and_path_and_query_and_fragment.scheme(),
            Some("http")
        );
    }

    #[test]
    fn uri_authority_extraction() {
        let relative_file = Uri::new("foo.masm");
        let relative_file_path = Uri::new("./foo.masm");
        let relative_file_path_with_empty_segment = Uri::new("foo//bar/baz");
        let relative_file_path_with_colon = Uri::new("file:foo.masm");
        let absolute_file_path = Uri::new("file:///tmp/foo.masm");
        let network_path_reference = Uri::new("//www.example.com/api/v1");
        let http_simple_uri = Uri::new("http://www.example.com");
        let http_simple_uri_with_userinfo = Uri::new("http://foo:bar@www.example.com");
        let http_simple_uri_with_userinfo_and_port = Uri::new("http://foo:bar@www.example.com:443");
        let http_simple_uri_with_userinfo_and_path =
            Uri::new("http://foo:bar@www.example.com/api/v1");
        let http_simple_uri_with_userinfo_and_query =
            Uri::new("http://foo:bar@www.example.com?param=1");
        let http_simple_uri_with_userinfo_and_fragment =
            Uri::new("http://foo:bar@www.example.com#about");
        let http_simple_uri_with_userinfo_and_path_and_query =
            Uri::new("http://foo:bar@www.example.com/api/v1/user?id=1");
        let http_simple_uri_with_userinfo_and_path_and_query_and_fragment =
            Uri::new("http://foo:bar@www.example.com/api/v1/user?id=1#redirect=/home");

        assert_eq!(relative_file.authority(), None);
        assert_eq!(relative_file_path.authority(), None);
        assert_eq!(relative_file_path_with_empty_segment.authority(), None);
        assert_eq!(relative_file_path_with_colon.authority(), None);
        assert_eq!(absolute_file_path.authority(), Some(""));
        assert_eq!(network_path_reference.authority(), Some("www.example.com"));
        assert_eq!(http_simple_uri.authority(), Some("www.example.com"));
        assert_eq!(http_simple_uri_with_userinfo.authority(), Some("foo:bar@www.example.com"));
        assert_eq!(
            http_simple_uri_with_userinfo_and_port.authority(),
            Some("foo:bar@www.example.com:443")
        );
        assert_eq!(
            http_simple_uri_with_userinfo_and_path.authority(),
            Some("foo:bar@www.example.com")
        );
        assert_eq!(
            http_simple_uri_with_userinfo_and_query.authority(),
            Some("foo:bar@www.example.com")
        );
        assert_eq!(
            http_simple_uri_with_userinfo_and_fragment.authority(),
            Some("foo:bar@www.example.com")
        );
        assert_eq!(
            http_simple_uri_with_userinfo_and_path_and_query.authority(),
            Some("foo:bar@www.example.com")
        );
        assert_eq!(
            http_simple_uri_with_userinfo_and_path_and_query_and_fragment.authority(),
            Some("foo:bar@www.example.com")
        );
    }

    #[test]
    fn uri_path_extraction() {
        let relative_file = Uri::new("foo.masm");
        let relative_file_path = Uri::new("./foo.masm");
        let relative_file_path_with_empty_segment = Uri::new("foo//bar/baz");
        let relative_file_path_with_colon = Uri::new("file:foo.masm");
        let absolute_file_path = Uri::new("file:///tmp/foo.masm");
        let network_path_reference = Uri::new("//www.example.com/api/v1");
        let http_simple_uri = Uri::new("http://www.example.com");
        let http_simple_uri_with_userinfo = Uri::new("http://foo:bar@www.example.com");
        let http_simple_uri_with_userinfo_and_port = Uri::new("http://foo:bar@www.example.com:443");
        let http_simple_uri_with_userinfo_and_path =
            Uri::new("http://foo:bar@www.example.com/api/v1");
        let http_simple_uri_with_userinfo_and_query =
            Uri::new("http://foo:bar@www.example.com?param=1");
        let http_simple_uri_with_userinfo_and_fragment =
            Uri::new("http://foo:bar@www.example.com#about");
        let http_simple_uri_with_userinfo_and_path_and_query =
            Uri::new("http://foo:bar@www.example.com/api/v1/user?id=1");
        let http_simple_uri_with_userinfo_and_path_and_query_and_fragment =
            Uri::new("http://foo:bar@www.example.com/api/v1/user?id=1#redirect=/home");

        assert_eq!(relative_file.path(), "foo.masm");
        assert_eq!(relative_file_path.path(), "./foo.masm");
        assert_eq!(relative_file_path_with_empty_segment.path(), "foo//bar/baz");
        assert_eq!(relative_file_path_with_colon.path(), "file:foo.masm");
        assert_eq!(absolute_file_path.path(), "/tmp/foo.masm");
        assert_eq!(network_path_reference.path(), "/api/v1");
        assert_eq!(http_simple_uri.path(), "");
        assert_eq!(http_simple_uri_with_userinfo.path(), "");
        assert_eq!(http_simple_uri_with_userinfo_and_port.path(), "");
        assert_eq!(http_simple_uri_with_userinfo_and_path.path(), "/api/v1");
        assert_eq!(http_simple_uri_with_userinfo_and_query.path(), "");
        assert_eq!(http_simple_uri_with_userinfo_and_fragment.path(), "");
        assert_eq!(http_simple_uri_with_userinfo_and_path_and_query.path(), "/api/v1/user");
        assert_eq!(
            http_simple_uri_with_userinfo_and_path_and_query_and_fragment.path(),
            "/api/v1/user"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn uri_file_paths_convert_to_paths() {
        assert_eq!(Uri::new("foo.masm").to_path(), Some(std::path::PathBuf::from("foo.masm")));
        assert_eq!(
            Uri::new("foo#bar?.masm").to_path(),
            Some(std::path::PathBuf::from("foo#bar?.masm"))
        );
        assert_eq!(
            Uri::new("C:\\tmp\\foo.masm").to_path(),
            Some(std::path::PathBuf::from("C:\\tmp\\foo.masm"))
        );
        assert_eq!(
            Uri::new("C:/tmp/foo.masm").to_path(),
            Some(std::path::PathBuf::from("C:/tmp/foo.masm"))
        );
        assert_eq!(Uri::new("file:foo.masm").to_path(), None);
        assert_eq!(
            Uri::new("file:///tmp/foo.masm").to_path(),
            Some(std::path::PathBuf::from("/tmp/foo.masm"))
        );
        assert_eq!(
            Uri::new("FILE:///tmp/foo.masm").to_path(),
            Some(std::path::PathBuf::from("/tmp/foo.masm"))
        );
        assert_eq!(
            Uri::new("File:///tmp/foo.masm").to_path(),
            Some(std::path::PathBuf::from("/tmp/foo.masm"))
        );
        assert_eq!(
            Uri::new("file:///C:/tmp/foo.masm").to_path(),
            Some(std::path::PathBuf::from("C:/tmp/foo.masm"))
        );
        assert_eq!(
            Uri::new("file://localhost/tmp/foo.masm").to_path(),
            Some(std::path::PathBuf::from("/tmp/foo.masm"))
        );
        assert_eq!(
            Uri::new("file://LOCALHOST/tmp/foo.masm").to_path(),
            Some(std::path::PathBuf::from("/tmp/foo.masm"))
        );
        assert_eq!(Uri::new("//www.example.com/api/v1").to_path(), None);
        assert_eq!(Uri::new("file://www.example.com/tmp/foo.masm").to_path(), None);
        assert_eq!(Uri::new("memory:foo.masm").to_path(), None);
    }
}
