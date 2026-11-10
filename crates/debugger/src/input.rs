use alloc::{borrow::Cow, boxed::Box};

use miden_debug_types::Uri;

#[derive(Clone)]
pub struct InputFile {
    path: Uri,
    content: Option<Box<[u8]>>,
}

impl core::fmt::Debug for InputFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use alloc::string::ToString;

        let content = match self.content.as_deref() {
            None => "None".to_string(),
            Some(content) => {
                format!("Some({{ length: {}, data: .. }})", content.len())
            }
        };
        f.debug_struct("InputFile")
            .field("path", &self.path)
            .field("content", &content)
            .finish()
    }
}

impl Default for InputFile {
    fn default() -> Self {
        Self {
            path: Uri::new("stdin://"),
            content: Some(Box::from([])),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InvalidInputError {
    #[error("invalid input: unsupported uri scheme in '{0}'")]
    UnsupportedScheme(Uri),
    #[error("expected valid file path, got '{0}'")]
    InvalidPath(Uri),
    #[cfg(feature = "std")]
    #[error("failed to read input file: {0}")]
    Io(#[from] std::io::Error),
}

impl InputFile {
    pub fn uri(&self) -> &Uri {
        &self.path
    }

    pub fn file_name(&self) -> &str {
        match self.path.scheme().unwrap_or("file") {
            "stdin" => match self.path.as_str().rsplit_once('/') {
                None => self.path.as_str().strip_prefix("stdin://").unwrap(),
                Some((_, "")) => "<noname>",
                Some((_, file_name)) => file_name,
            },
            _ => match self.path.as_str().rsplit_once('/') {
                None => self.path.as_str().split_once("://").unwrap().1,
                Some((_, file_name)) => file_name,
            },
        }
    }

    #[cfg(feature = "std")]
    pub fn bytes(&self) -> Result<Cow<'_, [u8]>, InvalidInputError> {
        match self.path.scheme() {
            Some("stdin") => Ok(Cow::Borrowed(self.content.as_deref().unwrap_or(&[]))),
            Some("file") | None => {
                let path = self
                    .path
                    .to_path()
                    .ok_or_else(|| InvalidInputError::InvalidPath(self.path.clone()))?;
                std::fs::read(path).map(Cow::Owned).map_err(InvalidInputError::Io)
            }
            Some(_) => Err(InvalidInputError::UnsupportedScheme(self.path.clone())),
        }
    }

    #[cfg(not(feature = "std"))]
    pub fn bytes(&self) -> Result<Cow<'_, [u8]>, InvalidInputError> {
        Ok(Cow::Borrowed(self.content.as_deref().unwrap_or(&[])))
    }

    /// Create a new [InputFile] from a raw [Uri] and the content associated with it, if any
    ///
    /// If no content is provided, then the URI must be loadable from disk, which requires the `std`
    /// feature. If you are not building with the `std` feature enabled, then you should provide
    /// the content here, or the input file will be useless.
    pub fn new(path: impl Into<Uri>, content: Option<Box<[u8]>>) -> Self {
        Self {
            path: path.into(),
            content,
        }
    }

    /// Get an [InputFile] representing the contents of `path`.
    ///
    /// This function returns an error if the contents are not a valid supported file type.
    #[cfg(feature = "std")]
    pub fn from_path<P: AsRef<std::path::Path>>(path: P) -> Self {
        let path = path.as_ref();
        Self {
            path: Uri::from(path),
            content: None,
        }
    }

    /// Get an [InputFile] representing the contents received from standard input.
    ///
    /// This function returns an error if the contents are not a valid supported file type.
    #[cfg(feature = "std")]
    pub fn from_stdin() -> Result<Self, std::io::Error> {
        use std::io::Read;

        let mut input = std::vec::Vec::with_capacity(1024);
        std::io::stdin().read_to_end(&mut input)?;
        Ok(Self {
            content: Some(input.into_boxed_slice()),
            ..Default::default()
        })
    }

    #[cfg(feature = "std")]
    pub fn to_path(&self) -> Option<std::path::PathBuf> {
        self.path.to_path()
    }
}

#[cfg(feature = "std")]
impl clap::builder::ValueParserFactory for InputFile {
    type Parser = InputFileParser;

    fn value_parser() -> Self::Parser {
        InputFileParser
    }
}

#[doc(hidden)]
#[derive(Clone)]
#[cfg(feature = "std")]
pub struct InputFileParser;

#[cfg(feature = "std")]
impl clap::builder::TypedValueParser for InputFileParser {
    type Value = InputFile;

    fn parse_ref(
        &self,
        _cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::error::Error> {
        use clap::error::{Error, ErrorKind};

        match value.to_str() {
            Some("-") => InputFile::from_stdin().map_err(|err| Error::raw(ErrorKind::Io, err)),
            Some(_) | None => {
                let path = std::path::PathBuf::from(value);
                if !path.exists() {
                    return Err(Error::raw(
                        ErrorKind::ValueValidation,
                        format!("invalid input '{}': file does not exist", path.display()),
                    ));
                }
                if path.extension().is_none_or(|extension| !extension.eq_ignore_ascii_case("masp"))
                {
                    return Err(Error::raw(
                        ErrorKind::ValueValidation,
                        format!(
                            "invalid input '{}': expected a compiled .masp package",
                            path.display()
                        ),
                    ));
                }
                Ok(InputFile::from_path(path))
            }
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests;
