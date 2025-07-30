#![no_std]

extern crate alloc;

#[cfg(any(feature = "std", test))]
extern crate std;

mod location;
mod selection;
mod source_file;
mod source_manager;
mod span;

use alloc::{string::String, sync::Arc};

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
    source_manager::{DefaultSourceManager, SourceId, SourceManager, SourceManagerSync},
    span::{SourceSpan, Span, Spanned},
};

/// A [URI reference](https://datatracker.ietf.org/doc/html/rfc3986#section-4.1) that specifies
/// the location of a source file, whether on disk, on the network, or elsewhere.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
        match self.0.split_once(':') {
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

    /// Returns the scheme portion of this URI, if present.
    pub fn authority(&self) -> Option<&str> {
        let uri = self.0.as_ref();
        let (_, rest) = uri.split_once("//")?;
        match rest.split_once(['/', '?', '#']) {
            Some((authority, _)) => Some(authority),
            None => Some(rest),
        }
    }

    /// Returns the path portion of this URI.
    pub fn path(&self) -> &str {
        let uri = self.0.as_ref();
        let path = match uri.split_once("//") {
            Some((_, rest)) => match rest.find('/').map(|pos| rest.split_at(pos)) {
                Some((_, path)) => path,
                None => return "",
            },
            None => match uri.split_once(':') {
                Some((prefix, _))
                    if prefix.contains(|c: char| {
                        !c.is_ascii_alphanumeric() && !matches!(c, '+' | '-' | '.')
                    }) =>
                {
                    uri
                },
                Some((_, path)) => path,
                None => uri,
            },
        };
        match path.split_once(['?', '#']) {
            Some((path, _)) => path,
            None => path,
        }
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

impl core::str::FromStr for Uri {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_scheme_extraction() {
        let relative_file = Uri::new("foo.masm");
        let relative_file_path = Uri::new("./foo.masm");
        let relative_file_path_with_scheme = Uri::new("file:foo.masm");
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
        assert_eq!(relative_file_path_with_scheme.scheme(), Some("file"));
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
        let relative_file_path_with_scheme = Uri::new("file:foo.masm");
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

        assert_eq!(relative_file.authority(), None);
        assert_eq!(relative_file_path.authority(), None);
        assert_eq!(relative_file_path_with_scheme.authority(), None);
        assert_eq!(absolute_file_path.authority(), Some(""));
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
        let relative_file_path_with_scheme = Uri::new("file:foo.masm");
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

        assert_eq!(relative_file.path(), "foo.masm");
        assert_eq!(relative_file_path.path(), "./foo.masm");
        assert_eq!(relative_file_path_with_scheme.path(), "foo.masm");
        assert_eq!(absolute_file_path.path(), "/tmp/foo.masm");
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
}
