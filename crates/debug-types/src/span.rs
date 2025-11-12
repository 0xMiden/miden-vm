use core::{
    borrow::Borrow,
    fmt,
    hash::{Hash, Hasher},
    ops::{Bound, Deref, DerefMut, Index, Range, RangeBounds},
};

use miden_crypto::utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

use super::{ByteIndex, ByteOffset, SourceId};

/// This trait should be implemented for any type that has an associated [SourceSpan].
pub trait Spanned {
    fn span(&self) -> SourceSpan;
}

impl Spanned for SourceSpan {
    #[inline(always)]
    fn span(&self) -> SourceSpan {
        *self
    }
}

impl<T: ?Sized + Spanned> Spanned for alloc::boxed::Box<T> {
    fn span(&self) -> SourceSpan {
        (**self).span()
    }
}

impl<T: ?Sized + Spanned> Spanned for alloc::rc::Rc<T> {
    fn span(&self) -> SourceSpan {
        (**self).span()
    }
}

impl<T: ?Sized + Spanned> Spanned for alloc::sync::Arc<T> {
    fn span(&self) -> SourceSpan {
        (**self).span()
    }
}

// SPAN
// ================================================================================================

/// This type is used to wrap any `T` with a [SourceSpan], and is typically used when it is not
/// convenient to add a [SourceSpan] to the type - most commonly because we don't control the type.
pub struct Span<T> {
    span: SourceSpan,
    spanned: T,
}

#[cfg(feature = "serde")]
impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for Span<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let spanned = T::deserialize(deserializer)?;
        Ok(Self { span: SourceSpan::UNKNOWN, spanned })
    }
}

#[cfg(feature = "serde")]
impl<T: serde::Serialize> serde::Serialize for Span<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        T::serialize(&self.spanned, serializer)
    }
}

impl<T> Spanned for Span<T> {
    fn span(&self) -> SourceSpan {
        self.span
    }
}

impl<T: Copy> Copy for Span<T> {}

impl<T: Clone> Clone for Span<T> {
    fn clone(&self) -> Self {
        Self {
            span: self.span,
            spanned: self.spanned.clone(),
        }
    }
}

impl<T: Default> Default for Span<T> {
    fn default() -> Self {
        Self {
            span: SourceSpan::UNKNOWN,
            spanned: T::default(),
        }
    }
}

impl<T> Span<T> {
    /// Creates a span for `spanned` with `span`.
    #[inline]
    pub fn new(span: impl Into<SourceSpan>, spanned: T) -> Self {
        Self { span: span.into(), spanned }
    }

    /// Creates a span for `spanned` representing a single location, `offset`.
    #[inline]
    pub fn at(source_id: SourceId, offset: usize, spanned: T) -> Self {
        let offset = u32::try_from(offset).expect("invalid source offset: too large");
        Self {
            span: SourceSpan::at(source_id, offset),
            spanned,
        }
    }

    /// Creates a [Span] from a value with an unknown/default location.
    pub fn unknown(spanned: T) -> Self {
        Self { span: Default::default(), spanned }
    }

    /// Consume this [Span] and get a new one with `span` as the underlying source span
    #[inline]
    pub fn with_span(mut self, span: SourceSpan) -> Self {
        self.span = span;
        self
    }

    /// Gets the associated [SourceSpan] for this spanned item.
    #[inline(always)]
    pub const fn span(&self) -> SourceSpan {
        self.span
    }

    /// Gets a reference to the spanned item.
    #[inline(always)]
    pub const fn inner(&self) -> &T {
        &self.spanned
    }

    /// Applies a transformation to the spanned value while retaining the same [SourceSpan].
    #[inline]
    pub fn map<U, F>(self, mut f: F) -> Span<U>
    where
        F: FnMut(T) -> U,
    {
        Span {
            span: self.span,
            spanned: f(self.spanned),
        }
    }

    /// Like [`Option<T>::as_deref`], this constructs a [`Span<U>`] wrapping the result of
    /// dereferencing the inner value of type `T` as a value of type `U`.
    pub fn as_deref<U>(&self) -> Span<&U>
    where
        U: ?Sized,
        T: Deref<Target = U>,
    {
        Span {
            span: self.span,
            spanned: self.spanned.deref(),
        }
    }

    /// Gets a new [Span] that borrows the inner value.
    pub fn as_ref(&self) -> Span<&T> {
        Span { span: self.span, spanned: &self.spanned }
    }

    /// Manually set the source id for the span of this item
    ///
    /// See also [SourceSpan::set_source_id].
    pub fn set_source_id(&mut self, id: SourceId) {
        self.span.set_source_id(id);
    }

    /// Shifts the span right by `count` units
    #[inline]
    pub fn shift(&mut self, count: ByteOffset) {
        self.span.start += count;
        self.span.end += count;
    }

    /// Extends the end of the span by `count` units.
    #[inline]
    pub fn extend(&mut self, count: ByteOffset) {
        self.span.end += count;
    }

    /// Consumes this span, returning the component parts, i.e. the [SourceSpan] and value of type
    /// `T`.
    #[inline]
    pub fn into_parts(self) -> (SourceSpan, T) {
        (self.span, self.spanned)
    }

    /// Unwraps the spanned value of type `T`.
    #[inline]
    pub fn into_inner(self) -> T {
        self.spanned
    }
}

impl<T> Borrow<T> for Span<T> {
    fn borrow(&self) -> &T {
        &self.spanned
    }
}

impl<T: Borrow<str>> Borrow<str> for Span<T> {
    fn borrow(&self) -> &str {
        self.spanned.borrow()
    }
}

impl<U, T: Borrow<[U]>> Borrow<[U]> for Span<T> {
    fn borrow(&self) -> &[U] {
        self.spanned.borrow()
    }
}

impl<T> Deref for Span<T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.spanned
    }
}

impl<T> DerefMut for Span<T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.spanned
    }
}

impl<T: ?Sized, U: AsRef<T>> AsRef<T> for Span<U> {
    fn as_ref(&self) -> &T {
        self.spanned.as_ref()
    }
}

impl<T: ?Sized, U: AsMut<T>> AsMut<T> for Span<U> {
    fn as_mut(&mut self) -> &mut T {
        self.spanned.as_mut()
    }
}

impl<T: fmt::Debug> fmt::Debug for Span<T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.spanned, f)
    }
}

impl<T: fmt::Display> fmt::Display for Span<T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.spanned, f)
    }
}

impl<T: miden_formatting::prettier::PrettyPrint> miden_formatting::prettier::PrettyPrint
    for Span<T>
{
    fn render(&self) -> miden_formatting::prettier::Document {
        self.spanned.render()
    }
}

impl<T: Eq> Eq for Span<T> {}

impl<T: PartialEq> PartialEq for Span<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.spanned.eq(&other.spanned)
    }
}

impl<T: PartialEq> PartialEq<T> for Span<T> {
    #[inline]
    fn eq(&self, other: &T) -> bool {
        self.spanned.eq(other)
    }
}

impl<T: Ord> Ord for Span<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.spanned.cmp(&other.spanned)
    }
}

impl<T: PartialOrd> PartialOrd for Span<T> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        self.spanned.partial_cmp(&other.spanned)
    }
}

impl<T: Hash> Hash for Span<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.spanned.hash(state);
    }
}

impl<T: Serializable> Span<T> {
    pub fn write_into_with_options<W: ByteWriter>(&self, target: &mut W, debug: bool) {
        if debug {
            self.span.write_into(target);
        }
        self.spanned.write_into(target);
    }
}

impl<T: Serializable> Serializable for Span<T> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.span.write_into(target);
        self.spanned.write_into(target);
    }
}

impl<T: Deserializable> Span<T> {
    pub fn read_from_with_options<R: ByteReader>(
        source: &mut R,
        debug: bool,
    ) -> Result<Self, DeserializationError> {
        let span = if debug {
            SourceSpan::read_from(source)?
        } else {
            SourceSpan::default()
        };
        let spanned = T::read_from(source)?;
        Ok(Self { span, spanned })
    }
}

impl<T: Deserializable> Deserializable for Span<T> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let span = SourceSpan::read_from(source)?;
        let spanned = T::read_from(source)?;
        Ok(Self { span, spanned })
    }
}

// SOURCE SPAN
// ================================================================================================

/// This represents a span of bytes in a Miden Assembly source file.
///
/// It is compact, using only 8 bytes to represent the full span. This does, however, come at the
/// tradeoff of only supporting source files of up to 2^32 bytes.
///
/// This type is produced by the lexer and carried through parsing. It can be converted into a
/// line/column range as well, if needed.
///
/// This representation is more convenient to produce, and allows showing source spans in error
/// messages, whereas line/column information is useful at a glance in debug output, it is harder
/// to produce nice errors with it compared to this representation.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct SourceSpan {
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "SourceId::is_unknown"))]
    source_id: SourceId,
    start: ByteIndex,
    end: ByteIndex,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid byte index range: maximum supported byte index is 2^32")]
pub struct InvalidByteIndexRange;

impl SourceSpan {
    /// A sentinel [SourceSpan] that indicates the span is unknown/invalid
    pub const UNKNOWN: Self = Self {
        source_id: SourceId::UNKNOWN,
        start: ByteIndex::new(0),
        end: ByteIndex::new(0),
    };

    /// Creates a new [SourceSpan] from the given range.
    pub fn new<B>(source_id: SourceId, range: Range<B>) -> Self
    where
        B: Into<ByteIndex>,
    {
        Self {
            source_id,
            start: range.start.into(),
            end: range.end.into(),
        }
    }

    /// Creates a new [SourceSpan] for a specific offset.
    pub fn at(source_id: SourceId, offset: impl Into<ByteIndex>) -> Self {
        let offset = offset.into();
        Self { source_id, start: offset, end: offset }
    }

    /// Try to create a new [SourceSpan] from the given range with `usize` bounds.
    pub fn try_from_range(
        source_id: SourceId,
        range: Range<usize>,
    ) -> Result<Self, InvalidByteIndexRange> {
        const MAX: usize = u32::MAX as usize;
        if range.start > MAX || range.end > MAX {
            return Err(InvalidByteIndexRange);
        }

        Ok(SourceSpan {
            source_id,
            start: ByteIndex::from(range.start as u32),
            end: ByteIndex::from(range.end as u32),
        })
    }

    /// Returns `true` if this [SourceSpan] represents the unknown span
    pub const fn is_unknown(&self) -> bool {
        self.source_id.is_unknown()
    }

    /// Get the [SourceId] associated with this source span
    #[inline(always)]
    pub fn source_id(&self) -> SourceId {
        self.source_id
    }

    /// Manually set the [SourceId] associated with this source span
    ///
    /// This is useful in cases where the range of the span is known, but the source id itself
    /// is not available yet, due to scope or some other limitation. In such cases you might wish
    /// to visit parsed objects once the source id is available, and update all of their spans
    /// accordingly.
    pub fn set_source_id(&mut self, id: SourceId) {
        self.source_id = id;
    }

    /// Gets the offset in bytes corresponding to the start of this span (inclusive).
    #[inline(always)]
    pub fn start(&self) -> ByteIndex {
        self.start
    }

    /// Gets the offset in bytes corresponding to the end of this span (exclusive).
    #[inline(always)]
    pub fn end(&self) -> ByteIndex {
        self.end
    }

    /// Gets the length of this span in bytes.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.end.to_usize() - self.start.to_usize()
    }

    /// Returns true if this span is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Converts this span into a [`Range<u32>`].
    #[inline]
    pub fn into_range(self) -> Range<u32> {
        self.start.to_u32()..self.end.to_u32()
    }

    /// Converts this span into a [`Range<usize>`].
    #[inline]
    pub fn into_slice_index(self) -> Range<usize> {
        self.start.to_usize()..self.end.to_usize()
    }
}

impl From<SourceSpan> for miette::SourceSpan {
    fn from(span: SourceSpan) -> Self {
        Self::new(miette::SourceOffset::from(span.start().to_usize()), span.len())
    }
}

impl Serializable for SourceSpan {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u32(self.source_id.to_u32());
        target.write_u32(self.start.into());
        target.write_u32(self.end.into())
    }
}

impl Deserializable for SourceSpan {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let source_id = SourceId::new_unchecked(source.read_u32()?);
        let start = ByteIndex::from(source.read_u32()?);
        let end = ByteIndex::from(source.read_u32()?);
        Ok(Self { source_id, start, end })
    }
}

impl From<SourceSpan> for Range<u32> {
    #[inline(always)]
    fn from(span: SourceSpan) -> Self {
        span.into_range()
    }
}

impl From<SourceSpan> for Range<usize> {
    #[inline(always)]
    fn from(span: SourceSpan) -> Self {
        span.into_slice_index()
    }
}

impl From<Range<u32>> for SourceSpan {
    #[inline]
    fn from(range: Range<u32>) -> Self {
        Self::new(SourceId::UNKNOWN, range)
    }
}

impl From<Range<ByteIndex>> for SourceSpan {
    #[inline]
    fn from(range: Range<ByteIndex>) -> Self {
        Self {
            source_id: SourceId::UNKNOWN,
            start: range.start,
            end: range.end,
        }
    }
}

impl Index<SourceSpan> for [u8] {
    type Output = [u8];

    #[inline]
    fn index(&self, index: SourceSpan) -> &Self::Output {
        &self[index.start().to_usize()..index.end().to_usize()]
    }
}

impl RangeBounds<ByteIndex> for SourceSpan {
    #[inline(always)]
    fn start_bound(&self) -> Bound<&ByteIndex> {
        Bound::Included(&self.start)
    }

    #[inline(always)]
    fn end_bound(&self) -> Bound<&ByteIndex> {
        Bound::Excluded(&self.end)
    }
}
