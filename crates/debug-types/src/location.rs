use core::{fmt, ops::Range};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{
    ByteIndex, Uri,
    source_file::{ColumnNumber, LineNumber},
};

/// A [Location] represents file and span information for portability across source managers
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct Location {
    /// The path to the source file in which the relevant source code can be found
    pub uri: Uri,
    /// The starting byte index (inclusive) of this location
    pub start: ByteIndex,
    /// The ending byte index (exclusive) of this location
    pub end: ByteIndex,
}

impl Location {
    /// Creates a new [Location].
    pub const fn new(uri: Uri, start: ByteIndex, end: ByteIndex) -> Self {
        Self { uri, start, end }
    }

    /// Get the name (or path) of the source file
    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Returns the byte range represented by this location
    pub const fn range(&self) -> Range<ByteIndex> {
        self.start..self.end
    }
}

/// A [FileLineCol] represents traditional file/line/column information for use in rendering.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct FileLineCol {
    /// The path to the source file in which the relevant source code can be found
    pub uri: Uri,
    /// The one-indexed number of the line to which this location refers
    pub line: LineNumber,
    /// The one-indexed column of the line on which this location starts
    pub column: ColumnNumber,
}

impl FileLineCol {
    /// Creates a new [Location].
    pub fn new(
        uri: impl Into<Uri>,
        line: impl Into<LineNumber>,
        column: impl Into<ColumnNumber>,
    ) -> Self {
        Self {
            uri: uri.into(),
            line: line.into(),
            column: column.into(),
        }
    }

    /// Get the name (or path) of the source file
    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Returns the line of the location.
    pub const fn line(&self) -> LineNumber {
        self.line
    }

    /// Moves the column by the given offset.
    pub fn move_column(&mut self, offset: i32) {
        self.column += offset;
    }
}

impl fmt::Display for FileLineCol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}@{}:{}]", &self.uri, self.line, self.column)
    }
}
