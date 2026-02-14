use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::{fmt, num::NonZeroU32, ops::Range};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{FileLineCol, Position, Selection, SourceId, SourceSpan, Uri};

// SOURCE LANGUAGE
// ================================================================================================

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SourceLanguage {
    Masm,
    Rust,
    Other(&'static str),
}

impl AsRef<str> for SourceLanguage {
    fn as_ref(&self) -> &str {
        match self {
            Self::Masm => "masm",
            Self::Rust => "rust",
            Self::Other(other) => other,
        }
    }
}

// SOURCE FILE
// ================================================================================================

/// A [SourceFile] represents a single file stored in a [super::SourceManager]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct SourceFile {
    /// The unique identifier allocated for this [SourceFile] by its owning [super::SourceManager]
    id: SourceId,
    /// The file content
    #[cfg_attr(
        feature = "serde",
        serde(deserialize_with = "SourceContent::deserialize_and_recompute_line_starts")
    )]
    content: SourceContent,
}

impl miette::SourceCode for SourceFile {
    fn read_span<'a>(
        &'a self,
        span: &miette::SourceSpan,
        context_lines_before: usize,
        context_lines_after: usize,
    ) -> Result<alloc::boxed::Box<dyn miette::SpanContents<'a> + 'a>, miette::MietteError> {
        let mut start =
            u32::try_from(span.offset()).map_err(|_| miette::MietteError::OutOfBounds)?;
        let len = u32::try_from(span.len()).map_err(|_| miette::MietteError::OutOfBounds)?;
        let mut end = start.checked_add(len).ok_or(miette::MietteError::OutOfBounds)?;
        if context_lines_before > 0 {
            let line_index = self.content.line_index(start.into());
            let start_line_index = line_index.saturating_sub(context_lines_before as u32);
            start = self.content.line_start(start_line_index).map(|idx| idx.to_u32()).unwrap_or(0);
        }
        if context_lines_after > 0 {
            let line_index = self.content.line_index(end.into());
            let end_line_index = line_index
                .checked_add(context_lines_after as u32)
                .ok_or(miette::MietteError::OutOfBounds)?;
            end = self
                .content
                .line_range(end_line_index)
                .map(|range| range.end.to_u32())
                .unwrap_or_else(|| self.content.source_range().end.to_u32());
        }
        Ok(Box::new(ScopedSourceFileRef {
            file: self,
            span: miette::SourceSpan::new((start as usize).into(), end.abs_diff(start) as usize),
        }))
    }
}

impl SourceFile {
    /// Create a new [SourceFile] from its raw components
    pub fn new(id: SourceId, lang: SourceLanguage, uri: Uri, content: impl Into<Box<str>>) -> Self {
        let content = SourceContent::new(lang, uri, content.into());
        Self { id, content }
    }

    /// This function is intended for use by [super::SourceManager] implementations that need to
    /// construct a [SourceFile] from its raw components (i.e. the identifier for the source file
    /// and its content).
    ///
    /// Since the only entity that should be constructing a [SourceId] is a [super::SourceManager],
    /// it is only valid to call this function in one of two scenarios:
    ///
    /// 1. You are a [super::SourceManager] constructing a [SourceFile] after allocating a
    ///    [SourceId]
    /// 2. You pass [`SourceId::default()`], i.e. [`SourceId::UNKNOWN`] for the source identifier.
    ///    The resulting [SourceFile] will be valid and safe to use in a context where there isn't a
    ///    [super::SourceManager] present. If there is a source manager in use, then constructing
    ///    detached [SourceFile]s is _not_ recommended, because it will make it confusing to
    ///    determine whether a given [SourceFile] reference is safe to use.
    ///
    /// You should rarely, if ever, fall in camp 2 - but it can be handy in some narrow cases
    pub fn from_raw_parts(id: SourceId, content: SourceContent) -> Self {
        Self { id, content }
    }

    /// Get the [SourceId] associated with this file
    pub const fn id(&self) -> SourceId {
        self.id
    }

    /// Get the name of this source file
    pub fn uri(&self) -> &Uri {
        self.content.uri()
    }

    /// Returns a reference to the underlying [SourceContent]
    pub fn content(&self) -> &SourceContent {
        &self.content
    }

    /// Returns a mutable reference to the underlying [SourceContent]
    pub fn content_mut(&mut self) -> &mut SourceContent {
        &mut self.content
    }

    /// Returns the number of lines in this file
    pub fn line_count(&self) -> usize {
        self.content.line_starts.len()
    }

    /// Returns the number of bytes in this file
    pub fn len(&self) -> usize {
        self.content.len()
    }

    /// Returns true if this file is empty
    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
    }

    /// Get the underlying content of this file
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        self.content.as_str()
    }

    /// Get the underlying content of this file as a byte slice
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        self.content.as_bytes()
    }

    /// Returns a [SourceSpan] covering the entirety of this file
    #[inline]
    pub fn source_span(&self) -> SourceSpan {
        let range = self.content.source_range();
        SourceSpan::new(self.id, range.start.0..range.end.0)
    }

    /// Returns a subset of the underlying content as a string slice.
    ///
    /// The bounds of the given span are byte indices, _not_ character indices.
    ///
    /// Returns `None` if the given span is out of bounds, or if the bounds do not
    /// fall on valid UTF-8 character boundaries.
    #[inline(always)]
    pub fn source_slice(&self, span: impl Into<Range<usize>>) -> Option<&str> {
        self.content.source_slice(span)
    }

    /// Returns a [SourceFileRef] corresponding to the bytes contained in the specified span.
    pub fn slice(self: &Arc<Self>, span: impl Into<Range<u32>>) -> SourceFileRef {
        SourceFileRef::new(Arc::clone(self), span)
    }

    /// Get a [SourceSpan] which points to the first byte of the character at `column` on `line`
    ///
    /// Returns `None` if the given line/column is out of bounds for this file.
    pub fn line_column_to_span(
        &self,
        line: LineNumber,
        column: ColumnNumber,
    ) -> Option<SourceSpan> {
        let offset = self.content.line_column_to_offset(line.into(), column.into())?;
        Some(SourceSpan::at(self.id, offset.0))
    }

    /// Get a [FileLineCol] equivalent to the start of the given [SourceSpan]
    pub fn location(&self, span: SourceSpan) -> FileLineCol {
        assert_eq!(span.source_id(), self.id, "mismatched source ids");

        self.content
            .location(ByteIndex(span.into_range().start))
            .expect("invalid source span: starting byte is out of bounds")
    }
}

impl AsRef<str> for SourceFile {
    #[inline(always)]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for SourceFile {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

// SOURCE FILE REF
// ================================================================================================

/// A reference to a specific spanned region of a [SourceFile], that provides access to the actual
/// [SourceFile], but scoped to the span it was created with.
///
/// This is useful in error types that implement [miette::Diagnostic], as it contains all of the
/// data necessary to render the source code being referenced, without a [super::SourceManager] on
/// hand.
#[derive(Debug, Clone)]
pub struct SourceFileRef {
    file: Arc<SourceFile>,
    span: SourceSpan,
}

impl SourceFileRef {
    /// Create a [SourceFileRef] from a [SourceFile] and desired span (in bytes)
    ///
    /// The given span will be constrained to the bytes of `file`, so a span that reaches out of
    /// bounds will have its end bound set to the last byte of the file.
    pub fn new(file: Arc<SourceFile>, span: impl Into<Range<u32>>) -> Self {
        let span = span.into();
        let end = core::cmp::min(span.end, file.len() as u32);
        let span = SourceSpan::new(file.id(), span.start..end);
        Self { file, span }
    }

    /// Returns a ref-counted handle to the underlying [SourceFile]
    pub fn source_file(&self) -> Arc<SourceFile> {
        self.file.clone()
    }

    /// Returns the URI of the file this [SourceFileRef] is selecting
    pub fn uri(&self) -> &Uri {
        self.file.uri()
    }

    /// Returns the [SourceSpan] selected by this [SourceFileRef]
    pub const fn span(&self) -> SourceSpan {
        self.span
    }

    /// Returns the underlying `str` selected by this [SourceFileRef]
    pub fn as_str(&self) -> &str {
        self.file.source_slice(self.span).unwrap()
    }

    /// Returns the underlying bytes selected by this [SourceFileRef]
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }

    /// Returns the number of bytes represented by the subset of the underlying file that is covered
    /// by this [SourceFileRef]
    pub fn len(&self) -> usize {
        self.span.len()
    }

    /// Returns true if this selection is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Eq for SourceFileRef {}

impl PartialEq for SourceFileRef {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Ord for SourceFileRef {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PartialOrd for SourceFileRef {
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl core::hash::Hash for SourceFileRef {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl AsRef<str> for SourceFileRef {
    #[inline(always)]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for SourceFileRef {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<&SourceFileRef> for miette::SourceSpan {
    fn from(source: &SourceFileRef) -> Self {
        source.span.into()
    }
}

/// Used to implement [miette::SpanContents] for [SourceFile] and [SourceFileRef]
struct ScopedSourceFileRef<'a> {
    file: &'a SourceFile,
    span: miette::SourceSpan,
}

impl<'a> miette::SpanContents<'a> for ScopedSourceFileRef<'a> {
    #[inline]
    fn data(&self) -> &'a [u8] {
        let start = self.span.offset();
        let end = start + self.span.len();
        &self.file.as_bytes()[start..end]
    }

    #[inline]
    fn span(&self) -> &miette::SourceSpan {
        &self.span
    }

    fn line(&self) -> usize {
        let offset = self.span.offset() as u32;
        self.file.content.line_index(offset.into()).to_usize()
    }

    fn column(&self) -> usize {
        let start = self.span.offset() as u32;
        let end = start + self.span.len() as u32;
        let span = SourceSpan::new(self.file.id(), start..end);
        let loc = self.file.location(span);
        loc.column.to_index().to_usize()
    }

    #[inline]
    fn line_count(&self) -> usize {
        self.file.line_count()
    }

    #[inline]
    fn name(&self) -> Option<&str> {
        Some(self.file.uri().as_ref())
    }

    #[inline]
    fn language(&self) -> Option<&str> {
        None
    }
}

impl miette::SourceCode for SourceFileRef {
    #[inline]
    fn read_span<'a>(
        &'a self,
        span: &miette::SourceSpan,
        context_lines_before: usize,
        context_lines_after: usize,
    ) -> Result<alloc::boxed::Box<dyn miette::SpanContents<'a> + 'a>, miette::MietteError> {
        self.file.read_span(span, context_lines_before, context_lines_after)
    }
}

// SOURCE CONTENT
// ================================================================================================

/// Represents key information about a source file and its content:
///
/// * The path to the file (or its name, in the case of virtual files)
/// * The content of the file
/// * The byte offsets of every line in the file, for use in looking up line/column information
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct SourceContent {
    /// The language identifier for this source file
    language: Box<str>,
    /// The path (or name) of this file
    uri: Uri,
    /// The underlying content of this file
    content: String,
    /// The byte offsets for each line in this file
    #[cfg_attr(feature = "serde", serde(default, skip))]
    line_starts: Vec<ByteIndex>,
    /// The document version
    #[cfg_attr(feature = "serde", serde(default))]
    version: i32,
}

impl fmt::Debug for SourceContent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let Self {
            language,
            uri,
            content,
            line_starts,
            version,
        } = self;
        f.debug_struct("SourceContent")
            .field("version", version)
            .field("language", language)
            .field("uri", uri)
            .field("size_in_bytes", &content.len())
            .field("line_count", &line_starts.len())
            .field("content", content)
            .finish()
    }
}

impl Eq for SourceContent {}

impl PartialEq for SourceContent {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.language == other.language && self.uri == other.uri && self.content == other.content
    }
}

impl Ord for SourceContent {
    #[inline]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.uri.cmp(&other.uri).then_with(|| self.content.cmp(&other.content))
    }
}

impl PartialOrd for SourceContent {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl core::hash::Hash for SourceContent {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.language.hash(state);
        self.uri.hash(state);
        self.content.hash(state);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SourceContentUpdateError {
    #[error("invalid content selection: start position of {}:{} is out of bounds", .0.line, .0.character)]
    InvalidSelectionStart(Position),
    #[error("invalid content selection: end position of {}:{} is out of bounds", .0.line, .0.character)]
    InvalidSelectionEnd(Position),
}

impl SourceContent {
    /// Create a new [SourceContent] from the (possibly virtual) file path, and its content as a
    /// UTF-8 string.
    ///
    /// When created, the line starts for this file will be computed, which requires scanning the
    /// file content once.
    pub fn new(language: impl AsRef<str>, uri: impl Into<Uri>, content: impl Into<String>) -> Self {
        let language = language.as_ref().to_string().into_boxed_str();
        let content: String = content.into();
        let bytes = content.as_bytes();

        assert!(
            bytes.len() < u32::MAX as usize,
            "unsupported source file: current maximum supported length in bytes is 2^32"
        );

        let line_starts = compute_line_starts(&content, None);

        Self {
            language,
            uri: uri.into(),
            content,
            line_starts,
            version: 0,
        }
    }

    /// Get the language identifier of this source file
    pub fn language(&self) -> &str {
        &self.language
    }

    /// Get the current version of this source file's content
    pub fn version(&self) -> i32 {
        self.version
    }

    /// Set the current version of this content
    #[inline(always)]
    pub fn set_version(&mut self, version: i32) {
        self.version = version;
    }

    /// Get the URI of this source file
    #[inline]
    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Returns the underlying content as a string slice
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        self.content.as_ref()
    }

    /// Returns the underlying content as a byte slice
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        self.content.as_bytes()
    }

    /// Returns the size in bytes of the underlying content
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.content.len()
    }

    /// Returns true if the underlying content is empty
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
    }

    /// Returns the range of valid byte indices for this file
    #[inline]
    pub fn source_range(&self) -> Range<ByteIndex> {
        ByteIndex(0)..ByteIndex(self.content.len() as u32)
    }

    /// Returns a subset of the underlying content as a string slice.
    ///
    /// The bounds of the given span are byte indices, _not_ character indices.
    ///
    /// Returns `None` if the given span is out of bounds, or if the bounds do not
    /// fall on valid UTF-8 character boundaries.
    #[inline(always)]
    pub fn source_slice(&self, span: impl Into<Range<usize>>) -> Option<&str> {
        self.as_str().get(span.into())
    }

    /// Returns a subset of the underlying content as a byte slice.
    ///
    /// Returns `None` if the given span is out of bounds
    #[inline(always)]
    pub fn byte_slice(&self, span: impl Into<Range<ByteIndex>>) -> Option<&[u8]> {
        let Range { start, end } = span.into();
        self.as_bytes().get(start.to_usize()..end.to_usize())
    }

    /// Like [Self::source_slice], but the slice is computed like a selection in an editor, i.e.
    /// based on line/column positions, rather than raw character indices.
    ///
    /// This is useful when mapping LSP operations to content in the source file.
    pub fn select(&self, mut range: Selection) -> Option<&str> {
        range.canonicalize();

        let start = self.line_column_to_offset(range.start.line, range.start.character)?;
        let end = self.line_column_to_offset(range.end.line, range.end.character)?;

        Some(&self.as_str()[start.to_usize()..end.to_usize()])
    }

    /// Returns the number of lines in the source content
    pub fn line_count(&self) -> usize {
        self.line_starts.len()
    }

    /// Returns the byte index at which the line corresponding to `line_index` starts
    ///
    /// Returns `None` if the given index is out of bounds
    pub fn line_start(&self, line_index: LineIndex) -> Option<ByteIndex> {
        self.line_starts.get(line_index.to_usize()).copied()
    }

    /// Returns the index of the last line in this file
    pub fn last_line_index(&self) -> LineIndex {
        LineIndex(self.line_count().saturating_sub(1).try_into().expect("too many lines in file"))
    }

    /// Get the range of byte indices covered by the given line
    pub fn line_range(&self, line_index: LineIndex) -> Option<Range<ByteIndex>> {
        let line_start = self.line_start(line_index)?;
        match self.line_start(line_index + 1) {
            Some(line_end) => Some(line_start..line_end),
            None => Some(line_start..ByteIndex(self.content.len() as u32)),
        }
    }

    /// Get the index of the line to which `byte_index` belongs
    pub fn line_index(&self, byte_index: ByteIndex) -> LineIndex {
        match self.line_starts.binary_search(&byte_index) {
            Ok(line) => LineIndex(line as u32),
            Err(next_line) => LineIndex(next_line as u32 - 1),
        }
    }

    /// Get the [ByteIndex] corresponding to the given line and column indices.
    ///
    /// Returns `None` if the line or column indices are out of bounds.
    pub fn line_column_to_offset(
        &self,
        line_index: LineIndex,
        column_index: ColumnIndex,
    ) -> Option<ByteIndex> {
        let column_index = column_index.to_usize();
        let line_span = self.line_range(line_index)?;
        let line_src = self
            .content
            .get(line_span.start.to_usize()..line_span.end.to_usize())
            .expect("invalid line boundaries: invalid utf-8");
        if line_src.len() < column_index {
            return None;
        }
        let (pre, _) = line_src.split_at(column_index);
        let start = line_span.start;
        Some(start + ByteOffset::from_str_len(pre))
    }

    /// Get a [FileLineCol] corresponding to the line/column in this file at which `byte_index`
    /// occurs
    pub fn location(&self, byte_index: ByteIndex) -> Option<FileLineCol> {
        let line_index = self.line_index(byte_index);
        let line_start_index = self.line_start(line_index)?;
        let line_src = self.content.get(line_start_index.to_usize()..byte_index.to_usize())?;
        let column_index = ColumnIndex::from(line_src.chars().count() as u32);
        Some(FileLineCol {
            uri: self.uri.clone(),
            line: line_index.number(),
            column: column_index.number(),
        })
    }

    /// Update the source document after being notified of a change event.
    ///
    /// The `version` indicates the new version of the document
    ///
    /// NOTE: This is intended to update a [super::SourceManager]'s view of the content of the
    /// document, _not_ to perform an update against the actual file, wherever it may be.
    pub fn update(
        &mut self,
        text: String,
        range: Option<Selection>,
        version: i32,
    ) -> Result<(), SourceContentUpdateError> {
        match range {
            Some(range) => {
                let start = self
                    .line_column_to_offset(range.start.line, range.start.character)
                    .ok_or(SourceContentUpdateError::InvalidSelectionStart(range.start))?
                    .to_usize();
                let end = self
                    .line_column_to_offset(range.end.line, range.end.character)
                    .ok_or(SourceContentUpdateError::InvalidSelectionEnd(range.end))?
                    .to_usize();
                assert!(start <= end, "start of range must be less than end, got {start}..{end}",);
                self.content.replace_range(start..end, &text);

                let added_line_starts = compute_line_starts(&text, Some(start as u32));
                let num_added = added_line_starts.len();
                let splice_start = range.start.line.to_usize() + 1;
                // Determine deletion range in line_starts to respect Selection semantics.
                // For multi-line edits, remove line starts from (start.line + 1) up to end.line
                // inclusive, since all intervening newlines are removed by the
                // replacement, regardless of end.character.
                enum Deletion {
                    Empty,
                    Inclusive(usize), // inclusive end index
                }
                let deletion = if range.start.line == range.end.line {
                    Deletion::Empty
                } else {
                    let mut end_line_for_splice = range.end.line.to_usize();
                    if !self.line_starts.is_empty() {
                        let max_idx = self.line_starts.len() - 1;
                        if end_line_for_splice > max_idx {
                            end_line_for_splice = max_idx;
                        }
                    }
                    if end_line_for_splice >= splice_start {
                        Deletion::Inclusive(end_line_for_splice)
                    } else {
                        Deletion::Empty
                    }
                };

                match deletion {
                    Deletion::Empty => {
                        self.line_starts.splice(splice_start..splice_start, added_line_starts);
                    },
                    Deletion::Inclusive(end_idx) => {
                        self.line_starts.splice(splice_start..=end_idx, added_line_starts);
                    },
                }

                let diff =
                    (text.len() as i32).saturating_sub_unsigned((end as u32) - (start as u32));
                if diff != 0 {
                    for i in (splice_start + num_added)..self.line_starts.len() {
                        self.line_starts[i] =
                            ByteIndex(self.line_starts[i].to_u32().saturating_add_signed(diff));
                    }
                }
            },
            None => {
                self.line_starts = compute_line_starts(&text, None);
                self.content = text;
            },
        }

        self.version = version;

        Ok(())
    }
}

#[cfg(feature = "serde")]
impl SourceContent {
    fn deserialize_and_recompute_line_starts<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut content = SourceContent::deserialize(deserializer)?;
        content.line_starts = compute_line_starts(&content.content, None);
        Ok(content)
    }
}

fn compute_line_starts(text: &str, text_offset: Option<u32>) -> Vec<ByteIndex> {
    let bytes = text.as_bytes();
    let initial_line_offset = match text_offset {
        Some(_) => None,
        None => Some(ByteIndex(0)),
    };
    let text_offset = text_offset.unwrap_or(0);
    initial_line_offset
        .into_iter()
        .chain(
            memchr::memchr_iter(b'\n', bytes)
                .map(|offset| ByteIndex(text_offset + (offset + 1) as u32)),
        )
        .collect()
}

// SOURCE CONTENT INDICES
// ================================================================================================

/// An index representing the offset in bytes from the start of a source file
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct ByteIndex(pub u32);

impl ByteIndex {
    /// Create a [ByteIndex] from a raw `u32` index
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    /// Get the raw index as a usize
    #[inline(always)]
    pub const fn to_usize(self) -> usize {
        self.0 as usize
    }

    /// Get the raw index as a u32
    #[inline(always)]
    pub const fn to_u32(self) -> u32 {
        self.0
    }
}

impl core::ops::Add<ByteOffset> for ByteIndex {
    type Output = ByteIndex;

    fn add(self, rhs: ByteOffset) -> Self {
        Self((self.0 as i64 + rhs.0) as u32)
    }
}

impl core::ops::Add<u32> for ByteIndex {
    type Output = ByteIndex;

    fn add(self, rhs: u32) -> Self {
        Self(self.0 + rhs)
    }
}

impl core::ops::AddAssign<ByteOffset> for ByteIndex {
    fn add_assign(&mut self, rhs: ByteOffset) {
        *self = *self + rhs;
    }
}

impl core::ops::AddAssign<u32> for ByteIndex {
    fn add_assign(&mut self, rhs: u32) {
        self.0 += rhs;
    }
}

impl core::ops::Sub<ByteOffset> for ByteIndex {
    type Output = ByteIndex;

    fn sub(self, rhs: ByteOffset) -> Self {
        Self((self.0 as i64 - rhs.0) as u32)
    }
}

impl core::ops::Sub<u32> for ByteIndex {
    type Output = ByteIndex;

    fn sub(self, rhs: u32) -> Self {
        Self(self.0 - rhs)
    }
}

impl core::ops::SubAssign<ByteOffset> for ByteIndex {
    fn sub_assign(&mut self, rhs: ByteOffset) {
        *self = *self - rhs;
    }
}

impl core::ops::SubAssign<u32> for ByteIndex {
    fn sub_assign(&mut self, rhs: u32) {
        self.0 -= rhs;
    }
}

impl From<u32> for ByteIndex {
    fn from(index: u32) -> Self {
        Self(index)
    }
}

impl From<ByteIndex> for u32 {
    fn from(index: ByteIndex) -> Self {
        index.0
    }
}

impl fmt::Display for ByteIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// An offset in bytes relative to some [ByteIndex]
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteOffset(i64);

impl ByteOffset {
    /// Compute the offset in bytes represented by the given `char`
    pub fn from_char_len(c: char) -> ByteOffset {
        Self(c.len_utf8() as i64)
    }

    /// Compute the offset in bytes represented by the given `str`
    pub fn from_str_len(s: &str) -> ByteOffset {
        Self(s.len() as i64)
    }
}

impl core::ops::Add for ByteOffset {
    type Output = ByteOffset;

    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl core::ops::AddAssign for ByteOffset {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0;
    }
}

impl core::ops::Sub for ByteOffset {
    type Output = ByteOffset;

    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

impl core::ops::SubAssign for ByteOffset {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0;
    }
}

impl fmt::Display for ByteOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

macro_rules! declare_dual_number_and_index_type {
    ($name:ident, $description:literal) => {
        paste::paste! {
            declare_dual_number_and_index_type!([<$name Index>], [<$name Number>], $description);
        }
    };

    ($index_name:ident, $number_name:ident, $description:literal) => {
        #[doc = concat!("A zero-indexed ", $description, " number")]
        #[derive(Default, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
        #[cfg_attr(feature = "serde", serde(transparent))]
        pub struct $index_name(pub u32);

        impl $index_name {
            #[doc = concat!("Convert to a [", stringify!($number_name), "]")]
            pub const fn number(self) -> $number_name {
                $number_name(unsafe { NonZeroU32::new_unchecked(self.0 + 1) })
            }

            /// Get the raw index value as a usize
            #[inline(always)]
            pub const fn to_usize(self) -> usize {
                self.0 as usize
            }

            /// Get the raw index value as a u32
            #[inline(always)]
            pub const fn to_u32(self) -> u32 {
                self.0
            }

            /// Add `offset` to this index, returning `None` on overflow
            pub fn checked_add(self, offset: u32) -> Option<Self> {
                self.0.checked_add(offset).map(Self)
            }

            /// Add a signed `offset` to this index, returning `None` on overflow
            pub fn checked_add_signed(self, offset: i32) -> Option<Self> {
                self.0.checked_add_signed(offset).map(Self)
            }

            /// Subtract `offset` from this index, returning `None` on underflow
            pub fn checked_sub(self, offset: u32) -> Option<Self> {
                self.0.checked_sub(offset).map(Self)
            }

            /// Add `offset` to this index, saturating to `u32::MAX` on overflow
            pub const fn saturating_add(self, offset: u32) -> Self {
                Self(self.0.saturating_add(offset))
            }

            /// Add a signed `offset` to this index, saturating to `0` on underflow, and `u32::MAX`
            /// on overflow.
            pub const fn saturating_add_signed(self, offset: i32) -> Self {
                Self(self.0.saturating_add_signed(offset))
            }

            /// Subtract `offset` from this index, saturating to `0` on overflow
            pub const fn saturating_sub(self, offset: u32) -> Self {
                Self(self.0.saturating_sub(offset))
            }
        }

        impl From<u32> for $index_name {
            #[inline]
            fn from(index: u32) -> Self {
                Self(index)
            }
        }

        impl From<$number_name> for $index_name {
            #[inline]
            fn from(index: $number_name) -> Self {
                Self(index.to_u32() - 1)
            }
        }

        impl core::ops::Add<u32> for $index_name {
            type Output = Self;

            #[inline]
            fn add(self, rhs: u32) -> Self {
                Self(self.0 + rhs)
            }
        }

        impl core::ops::AddAssign<u32> for $index_name {
            fn add_assign(&mut self, rhs: u32) {
                let result = *self + rhs;
                *self = result;
            }
        }

        impl core::ops::Add<i32> for $index_name {
            type Output = Self;

            fn add(self, rhs: i32) -> Self {
                self.checked_add_signed(rhs).expect("invalid offset: overflow occurred")
            }
        }

        impl core::ops::AddAssign<i32> for $index_name {
            fn add_assign(&mut self, rhs: i32) {
                let result = *self + rhs;
                *self = result;
            }
        }

        impl core::ops::Sub<u32> for $index_name {
            type Output = Self;

            #[inline]
            fn sub(self, rhs: u32) -> Self {
                Self(self.0 - rhs)
            }
        }

        impl core::ops::SubAssign<u32> for $index_name {
            fn sub_assign(&mut self, rhs: u32) {
                let result = *self - rhs;
                *self = result;
            }
        }

        impl fmt::Display for $index_name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        #[doc = concat!("A one-indexed ", $description, " number")]
        #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
        #[cfg_attr(feature = "serde", serde(transparent))]
        pub struct $number_name(NonZeroU32);

        impl Default for $number_name {
            fn default() -> Self {
                Self(unsafe { NonZeroU32::new_unchecked(1) })
            }
        }

        impl $number_name {
            pub const fn new(number: u32) -> Option<Self> {
                match NonZeroU32::new(number) {
                    Some(num) => Some(Self(num)),
                    None => None,
                }
            }

            #[doc = concat!("Convert to a [", stringify!($index_name), "]")]
            pub const fn to_index(self) -> $index_name {
                $index_name(self.to_u32().saturating_sub(1))
            }

            /// Get the raw value as a usize
            #[inline(always)]
            pub const fn to_usize(self) -> usize {
                self.0.get() as usize
            }

            /// Get the raw value as a u32
            #[inline(always)]
            pub const fn to_u32(self) -> u32 {
                self.0.get()
            }

            /// Add `offset` to this index, returning `None` on overflow
            pub fn checked_add(self, offset: u32) -> Option<Self> {
                self.0.checked_add(offset).map(Self)
            }

            /// Add a signed `offset` to this index, returning `None` on overflow
            pub fn checked_add_signed(self, offset: i32) -> Option<Self> {
                self.0.get().checked_add_signed(offset).and_then(Self::new)
            }

            /// Subtract `offset` from this index, returning `None` on underflow
            pub fn checked_sub(self, offset: u32) -> Option<Self> {
                self.0.get().checked_sub(offset).and_then(Self::new)
            }

            /// Add `offset` to this index, saturating to `u32::MAX` on overflow
            pub const fn saturating_add(self, offset: u32) -> Self {
                Self(unsafe { NonZeroU32::new_unchecked(self.0.get().saturating_add(offset)) })
            }

            /// Add a signed `offset` to this index, saturating to `0` on underflow, and `u32::MAX`
            /// on overflow.
            pub fn saturating_add_signed(self, offset: i32) -> Self {
                Self::new(self.to_u32().saturating_add_signed(offset)).unwrap_or_default()
            }

            /// Subtract `offset` from this index, saturating to `0` on overflow
            pub fn saturating_sub(self, offset: u32) -> Self {
                Self::new(self.to_u32().saturating_sub(offset)).unwrap_or_default()
            }
        }

        impl From<NonZeroU32> for $number_name {
            #[inline]
            fn from(index: NonZeroU32) -> Self {
                Self(index)
            }
        }

        impl From<$index_name> for $number_name {
            #[inline]
            fn from(index: $index_name) -> Self {
                Self(unsafe { NonZeroU32::new_unchecked(index.to_u32() + 1) })
            }
        }

        impl core::ops::Add<u32> for $number_name {
            type Output = Self;

            #[inline]
            fn add(self, rhs: u32) -> Self {
                Self(unsafe { NonZeroU32::new_unchecked(self.0.get() + rhs) })
            }
        }

        impl core::ops::AddAssign<u32> for $number_name {
            fn add_assign(&mut self, rhs: u32) {
                let result = *self + rhs;
                *self = result;
            }
        }

        impl core::ops::Add<i32> for $number_name {
            type Output = Self;

            fn add(self, rhs: i32) -> Self {
                self.to_u32()
                    .checked_add_signed(rhs)
                    .and_then(Self::new)
                    .expect("invalid offset: overflow occurred")
            }
        }

        impl core::ops::AddAssign<i32> for $number_name {
            fn add_assign(&mut self, rhs: i32) {
                let result = *self + rhs;
                *self = result;
            }
        }

        impl core::ops::Sub<u32> for $number_name {
            type Output = Self;

            #[inline]
            fn sub(self, rhs: u32) -> Self {
                self.to_u32()
                    .checked_sub(rhs)
                    .and_then(Self::new)
                    .expect("invalid offset: overflow occurred")
            }
        }

        impl core::ops::SubAssign<u32> for $number_name {
            fn sub_assign(&mut self, rhs: u32) {
                let result = *self - rhs;
                *self = result;
            }
        }

        impl fmt::Display for $number_name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

declare_dual_number_and_index_type!(Line, "line");
declare_dual_number_and_index_type!(Column, "column");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_content_line_starts() {
        const CONTENT: &str = "\
begin
  push.1
  push.2
  add
end
";
        let content = SourceContent::new("masm", "foo.masm", CONTENT);

        assert_eq!(content.line_count(), 6);
        assert_eq!(
            content
                .byte_slice(content.line_range(LineIndex(0)).expect("invalid line"))
                .expect("invalid byte range"),
            "begin\n".as_bytes()
        );
        assert_eq!(
            content
                .byte_slice(content.line_range(LineIndex(1)).expect("invalid line"))
                .expect("invalid byte range"),
            "  push.1\n".as_bytes()
        );
        assert_eq!(
            content
                .byte_slice(content.line_range(content.last_line_index()).expect("invalid line"))
                .expect("invalid byte range"),
            "".as_bytes()
        );
    }

    #[test]
    fn source_content_line_starts_after_update() {
        const CONTENT: &str = "\
begin
  push.1
  push.2
  add
end
";
        const FRAGMENT: &str = "  push.2
  mul
end
";
        let mut content = SourceContent::new("masm", "foo.masm", CONTENT);
        content
            .update(FRAGMENT.to_string(), Some(Selection::from(LineIndex(4)..LineIndex(5))), 1)
            .expect("update failed");

        assert_eq!(
            content.as_str(),
            "\
begin
  push.1
  push.2
  add
  push.2
  mul
end
"
        );
        assert_eq!(content.line_count(), 8);
        assert_eq!(
            content
                .byte_slice(content.line_range(LineIndex(0)).expect("invalid line"))
                .expect("invalid byte range"),
            "begin\n".as_bytes()
        );
        assert_eq!(
            content
                .byte_slice(content.line_range(LineIndex(3)).expect("invalid line"))
                .expect("invalid byte range"),
            "  add\n".as_bytes()
        );
        assert_eq!(
            content
                .byte_slice(content.line_range(LineIndex(4)).expect("invalid line"))
                .expect("invalid byte range"),
            "  push.2\n".as_bytes()
        );
        assert_eq!(
            content
                .byte_slice(content.line_range(content.last_line_index()).expect("invalid line"))
                .expect("invalid byte range"),
            "".as_bytes()
        );
    }

    /// Test that backslash-before-newline is NOT treated as a line continuation.
    #[test]
    fn source_content_line_starts_with_trailing_backslash() {
        const CONTENT: &str =
            "//! Build with:\n//!   cargo build \\\n//!     --release\nfn main() {}\n";

        let content = SourceContent::new("rust", "example.rs", CONTENT);

        // Should have 5 lines (4 lines of content + 1 empty line after final newline)
        // Line 0: "//! Build with:\n"
        // Line 1: "//!   cargo build \\\n"
        // Line 2: "//!     --release\n"
        // Line 3: "fn main() {}\n"
        // Line 4: "" (empty line after final newline)
        assert_eq!(content.line_count(), 5);

        // Verify each line's content
        assert_eq!(
            content
                .byte_slice(content.line_range(LineIndex(0)).expect("invalid line"))
                .expect("invalid byte range"),
            "//! Build with:\n".as_bytes()
        );
        assert_eq!(
            content
                .byte_slice(content.line_range(LineIndex(1)).expect("invalid line"))
                .expect("invalid byte range"),
            "//!   cargo build \\\n".as_bytes()
        );
        assert_eq!(
            content
                .byte_slice(content.line_range(LineIndex(2)).expect("invalid line"))
                .expect("invalid byte range"),
            "//!     --release\n".as_bytes()
        );
        assert_eq!(
            content
                .byte_slice(content.line_range(LineIndex(3)).expect("invalid line"))
                .expect("invalid byte range"),
            "fn main() {}\n".as_bytes()
        );

        // Verify line_column_to_offset works for all lines, including those after
        // backslash-ended lines.
        let offset_line0 = content.line_column_to_offset(LineIndex(0), ColumnIndex(0));
        let offset_line1 = content.line_column_to_offset(LineIndex(1), ColumnIndex(0));
        let offset_line2 = content.line_column_to_offset(LineIndex(2), ColumnIndex(0));
        let offset_line3 = content.line_column_to_offset(LineIndex(3), ColumnIndex(0));

        assert!(offset_line0.is_some(), "line 0 should be accessible");
        assert!(offset_line1.is_some(), "line 1 should be accessible");
        assert!(offset_line2.is_some(), "line 2 should be accessible");
        assert!(offset_line3.is_some(), "line 3 should be accessible");

        // Verify the offsets are at the expected byte positions
        assert_eq!(offset_line0.unwrap().to_u32(), 0);
        assert_eq!(offset_line1.unwrap().to_u32(), 16); // After "//! Build with:\n"
        assert_eq!(offset_line2.unwrap().to_u32(), 36); // After "//!   cargo build \\\n"
        assert_eq!(offset_line3.unwrap().to_u32(), 54); // After "//!     --release\n"
    }

    /// Test with multiple consecutive backslash-ended lines
    #[test]
    fn source_content_line_starts_multiple_trailing_backslashes() {
        // Multiple lines ending with backslashes
        const CONTENT: &str = "line1 \\\nline2 \\\nline3 \\\nline4\n";

        let content = SourceContent::new("text", "test.txt", CONTENT);

        // Should have 5 lines (4 lines of content + 1 empty line after final newline)
        assert_eq!(content.line_count(), 5);

        // Verify each line is correctly separated
        assert_eq!(
            content
                .byte_slice(content.line_range(LineIndex(0)).expect("invalid line"))
                .expect("invalid byte range"),
            "line1 \\\n".as_bytes()
        );
        assert_eq!(
            content
                .byte_slice(content.line_range(LineIndex(1)).expect("invalid line"))
                .expect("invalid byte range"),
            "line2 \\\n".as_bytes()
        );
        assert_eq!(
            content
                .byte_slice(content.line_range(LineIndex(2)).expect("invalid line"))
                .expect("invalid byte range"),
            "line3 \\\n".as_bytes()
        );
        assert_eq!(
            content
                .byte_slice(content.line_range(LineIndex(3)).expect("invalid line"))
                .expect("invalid byte range"),
            "line4\n".as_bytes()
        );
    }
}
