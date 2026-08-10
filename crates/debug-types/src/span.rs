use core::{
    borrow::Borrow,
    fmt,
    hash::{Hash, Hasher},
    ops::{Deref, DerefMut},
};

use miden_crypto::utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use miden_diagnostics::SourceKey;
pub use miden_diagnostics::{SourceSpan, Spanned, TextRange, TextRangeError};

use super::{ByteIndex, ByteOffset, SourceId, source_manager::source_id_from_wire};

// SPAN
// ================================================================================================

/// This type is used to wrap any `T` with a [SourceSpan], and is typically used when it is not
/// convenient to add a [SourceSpan] to the type - most commonly because we don't control the type.
#[derive(Clone, Copy)]
pub struct Span<T> {
    span: SourceSpan,
    spanned: T,
}

#[cfg(feature = "serde")]
impl<T> Span<T> {
    pub fn from_serde_spanned(source_id: SourceId, spanned: serde_spanned::Spanned<T>) -> Self {
        let range = spanned.span();
        let start = range.start as u32;
        let end = range.end as u32;
        let spanned = spanned.into_inner();
        Self {
            span: SourceSpan::session(
                source_id,
                TextRange::new(start, end).expect("invalid serde source span"),
            ),
            spanned,
        }
    }
}

#[cfg(feature = "serde")]
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Span<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let spanned = T::deserialize(deserializer)?;
        Ok(Self { span: SourceSpan::UNKNOWN, spanned })
    }
}

#[cfg(feature = "serde")]
impl<T: Serialize> Serialize for Span<T> {
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
            span: SourceSpan::at(SourceKey::Session(source_id), None, offset),
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
        Span { span: self.span, spanned: &*self.spanned }
    }

    /// Gets a new [Span] that borrows the inner value.
    pub fn as_ref(&self) -> Span<&T> {
        Span { span: self.span, spanned: &self.spanned }
    }

    /// Manually set the source id for the span of this item
    ///
    /// See also [SourceSpan::set_source_id].
    pub fn set_source_id(&mut self, id: SourceId) {
        self.span.set_source_key(SourceKey::Session(id));
    }

    /// Shifts the span right by `count` units
    #[inline]
    pub fn shift(&mut self, count: ByteOffset) {
        let range = self.span.range();
        let start = ByteIndex::new(range.start()) + count;
        let end = ByteIndex::new(range.end()) + count;
        self.span = SourceSpan::new(
            self.span.source(),
            self.span.revision(),
            TextRange::new(start.to_u32(), end.to_u32()).expect("invalid shifted source span"),
        );
    }

    /// Extends the end of the span by `count` units.
    #[inline]
    pub fn extend(&mut self, count: ByteOffset) {
        let range = self.span.range();
        let end = ByteIndex::new(range.end()) + count;
        self.span = SourceSpan::new(
            self.span.source(),
            self.span.revision(),
            TextRange::new(range.start(), end.to_u32()).expect("invalid extended source span"),
        );
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
            write_source_span(self.span, target);
        }
        self.spanned.write_into(target);
    }
}

impl<T: Serializable> Serializable for Span<T> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        write_source_span(self.span, target);
        self.spanned.write_into(target);
    }
}

impl<T: Deserializable> Span<T> {
    pub fn read_from_with_options<R: ByteReader>(
        source: &mut R,
        debug: bool,
    ) -> Result<Self, DeserializationError> {
        let span = if debug {
            read_source_span(source)?
        } else {
            SourceSpan::default()
        };
        let spanned = T::read_from(source)?;
        Ok(Self { span, spanned })
    }
}

impl<T: Deserializable> Deserializable for Span<T> {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let span = read_source_span(source)?;
        let spanned = T::read_from(source)?;
        Ok(Self { span, spanned })
    }
}

// LEGACY SOURCE SPAN CODEC
// ================================================================================================

/// Writes a canonical diagnostic span using the established VM wire representation:
/// `(source-local-id, start, end)`, each encoded as `u32`.
///
/// The source namespace, source-key kind, and revision are session metadata and are intentionally
/// not part of this historical codec. Deserialization places the local ID in the default VM source
/// namespace as a session span.
fn write_source_span<W: ByteWriter>(span: SourceSpan, target: &mut W) {
    target.write_u32(span.source().id().local());
    target.write_u32(span.range().start());
    target.write_u32(span.range().end());
}

fn read_source_span<R: ByteReader>(source: &mut R) -> Result<SourceSpan, DeserializationError> {
    let source_id = source_id_from_wire(source.read_u32()?);
    let start = source.read_u32()?;
    let end = source.read_u32()?;
    let range = TextRange::new(start, end).map_err(|err| {
        DeserializationError::InvalidValue(alloc::format!("invalid source span: {err}"))
    })?;
    Ok(SourceSpan::session(source_id, range))
}

#[cfg(test)]
mod tests {
    use miden_crypto::utils::{Deserializable, Serializable};

    use super::*;
    use crate::DEFAULT_SOURCE_NAMESPACE;

    #[test]
    fn span_codec_preserves_established_three_u32_layout() {
        let source_id = SourceId::new(DEFAULT_SOURCE_NAMESPACE, 7);
        let span =
            Span::new(SourceSpan::session(source_id, TextRange::new(11, 19).unwrap()), 23_u32);

        let bytes = span.to_bytes();
        assert_eq!(bytes.len(), 16);
        assert_eq!(&bytes[..12], &[7, 0, 0, 0, 11, 0, 0, 0, 19, 0, 0, 0]);

        let decoded = Span::<u32>::read_from_bytes(&bytes).unwrap();
        assert_eq!(decoded.span().source().id(), source_id);
        assert_eq!(decoded.span().range(), TextRange::new(11, 19).unwrap());
        assert_eq!(*decoded, 23);
    }
}
