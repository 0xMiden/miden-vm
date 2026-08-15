use core::ops::Range;

use miden_diagnostics::{SourceProvider, SourceSpan, TextRange};
use miden_serde_utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};
#[cfg(feature = "arbitrary")]
use proptest::prelude::*;

use super::{ByteIndex, Uri};

/// A [Location] represents file and span information that is portable across source-provider
/// sessions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serialization_macros::serialization_test
)]
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

    /// Resolves this portable location to a session span using `sources`.
    pub fn to_span(&self, sources: &dyn SourceProvider) -> Option<SourceSpan> {
        let source_id = sources.find_by_name(self.uri.as_str())?;
        let source = sources.get(source_id)?;
        let range = TextRange::new(self.start.to_u32(), self.end.to_u32()).ok()?;
        if range.end() > source.byte_len
            || source.text.is_some_and(|text| {
                !text.is_char_boundary(range.start() as usize)
                    || !text.is_char_boundary(range.end() as usize)
            })
        {
            return None;
        }

        let span = SourceSpan::session(source_id, range);
        Some(source.revision.map_or(span, |revision| span.with_revision(revision)))
    }

    /// Resolve a session span to a portable source location.
    pub fn from_span(span: SourceSpan, sources: &dyn SourceProvider) -> Option<Self> {
        let source = sources.get(span.source().id())?;
        if span.revision().is_some_and(|revision| source.revision != Some(revision))
            || span.range().end() > source.byte_len
            || source.text.is_some_and(|text| {
                !text.is_char_boundary(span.range().start() as usize)
                    || !text.is_char_boundary(span.range().end() as usize)
            })
        {
            return None;
        }
        Some(Self::new(
            Uri::from(source.display_name),
            ByteIndex::new(span.range().start()),
            ByteIndex::new(span.range().end()),
        ))
    }
}

impl Serializable for Location {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.uri.write_into(target);
        self.start.to_u32().write_into(target);
        self.end.to_u32().write_into(target);
    }
}

impl Deserializable for Location {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let uri = Uri::read_from(source)?;
        let start = ByteIndex::from(source.read_u32()?);
        let end = ByteIndex::from(source.read_u32()?);
        Ok(Self::new(uri, start, end))
    }
}

#[cfg(feature = "arbitrary")]
impl Arbitrary for Location {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (any::<Uri>(), any::<u32>(), any::<u32>())
            .prop_map(|(uri, start, end)| {
                let (start, end) = if start <= end { (start, end) } else { (end, start) };
                Self::new(uri, ByteIndex::new(start), ByteIndex::new(end))
            })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use miden_diagnostics::{SourceMap, SourceNamespace, SourceRevision};

    use super::*;

    #[test]
    fn portable_locations_round_trip_through_a_source_provider() {
        let mut sources = SourceMap::new(SourceNamespace::new_unchecked(41));
        let source_id = sources
            .insert("memory:///unicode.masm", "a😀z", Some(SourceRevision(7)))
            .unwrap();
        let location =
            Location::new(Uri::new("memory:///unicode.masm"), ByteIndex::new(1), ByteIndex::new(5));

        let span = location.to_span(&sources).unwrap();
        assert_eq!(span.source().id(), source_id);
        assert_eq!(span.revision(), Some(SourceRevision(7)));
        assert_eq!(Location::from_span(span, &sources), Some(location));
    }

    #[test]
    fn portable_locations_reject_missing_and_non_boundary_ranges() {
        let mut sources = SourceMap::new(SourceNamespace::new_unchecked(42));
        sources.insert("memory:///unicode.masm", "a😀z", None).unwrap();

        let missing =
            Location::new(Uri::new("memory:///missing.masm"), ByteIndex::new(0), ByteIndex::new(1));
        assert!(missing.to_span(&sources).is_none());

        let unaligned =
            Location::new(Uri::new("memory:///unicode.masm"), ByteIndex::new(2), ByteIndex::new(3));
        assert!(unaligned.to_span(&sources).is_none());
    }
}
