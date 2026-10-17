use miden_crypto::utils::{ByteWriter, Deserializable, DeserializationError, Serializable};
use miden_debug_types::{
    ByteIndex, DefaultSourceManager, Location, SourceFileRef, SourceId, SourceLanguage,
    SourceManager, SourceSpan,
};

#[test]
fn reversed_bounds_are_rejected() {
    let mut bytes = Vec::new();
    bytes.write_u32(0);
    bytes.write_u32(5);
    bytes.write_u32(3);
    assert_eq!(
        SourceSpan::read_from_bytes(&bytes),
        Err(DeserializationError::InvalidValue("source span start 5 exceeds end 3".into()))
    );
}

#[test]
fn ordered_and_sentinel_spans_round_trip() {
    for span in [
        SourceSpan::new(SourceId::from(0), 3u32..5u32),
        SourceSpan::at(SourceId::from(0), u32::MAX),
        SourceSpan::UNKNOWN,
        SourceSpan::SYNTHETIC,
        SourceSpan::try_from_range(SourceId::from(0), 3..5).unwrap(),
        SourceSpan::from(3u32..5u32),
        SourceSpan::from(ByteIndex::new(3)..ByteIndex::new(5)),
    ] {
        assert_eq!(SourceSpan::read_from_bytes(&span.to_bytes()), Ok(span));
    }
}

#[test]
fn checked_constructor_rejects_invalid_bounds() {
    let mut ranges = vec![core::ops::Range { start: 5, end: 3 }];
    if let Some(end) = (u32::MAX as usize).checked_add(1) {
        ranges.push(0..end);
    }
    for range in ranges {
        let expected = format!(
            "invalid byte index range {}..{}: expected start <= end <= u32::MAX",
            range.start, range.end
        );
        let error = SourceSpan::try_from_range(SourceId::from(0), range).unwrap_err();
        assert_eq!(error.to_string(), expected);
    }
}

#[test]
#[should_panic(expected = "source span start 5 exceeds end 3")]
fn constructor_rejects_reversed_bounds() {
    SourceSpan::new(SourceId::from(0), core::ops::Range { start: 5u32, end: 3u32 });
}

#[test]
#[should_panic(expected = "source span start 5 exceeds end 3")]
fn byte_index_conversion_rejects_reversed_bounds() {
    let _ = SourceSpan::from(core::ops::Range {
        start: ByteIndex::new(5),
        end: ByteIndex::new(3),
    });
}

#[test]
#[should_panic(expected = "source span start 5 exceeds end 3")]
fn u32_conversion_rejects_reversed_bounds() {
    let _ = SourceSpan::from(core::ops::Range { start: 5u32, end: 3u32 });
}

#[test]
#[cfg(feature = "serde")]
fn serde_enforces_ordered_bounds() {
    let error = serde_json::from_str::<SourceSpan>(r#"{"start":5,"end":3}"#).unwrap_err();
    assert_eq!(error.to_string(), "source span start 5 exceeds end 3");
    for span in [
        SourceSpan::new(SourceId::from(0), 3u32..5u32),
        SourceSpan::UNKNOWN,
        SourceSpan::SYNTHETIC,
    ] {
        let encoded = serde_json::to_string(&span).unwrap();
        assert_eq!(serde_json::from_str::<SourceSpan>(&encoded).unwrap(), span);
    }
}

#[test]
fn location_conversion_rejects_reversed_bounds() {
    let manager = DefaultSourceManager::default();
    let file = manager.load_anonymous(SourceLanguage::Masm, "abcdef".into());
    let location = Location::new(file.uri().clone(), ByteIndex::new(5), ByteIndex::new(3));
    assert_eq!(manager.location_to_span(location), None);
    let location = Location::new(file.uri().clone(), ByteIndex::new(3), ByteIndex::new(5));
    assert_eq!(manager.location_to_span(location), Some(SourceSpan::new(file.id(), 3u32..5u32)));
}

#[test]
fn source_file_reference_clamps_ordered_bounds() {
    let manager = DefaultSourceManager::default();
    let file = manager.load_anonymous(SourceLanguage::Masm, "abcdef".into());
    for (range, expected) in [(3u32..10u32, 3u32..6u32), (8u32..10u32, 6u32..6u32)] {
        let reference = SourceFileRef::new(file.clone(), range);
        assert_eq!(reference.span().into_range(), expected);
        assert_eq!(
            reference.as_str(),
            file.source_slice(expected.start as usize..expected.end as usize).unwrap()
        );
    }
}

#[test]
fn location_conversion_round_trips_eof_and_empty_files() {
    let manager = DefaultSourceManager::default();
    for text in ["abcdef", ""] {
        let file = manager.load_anonymous(SourceLanguage::Masm, text.into());
        for span in [SourceSpan::at(file.id(), file.len() as u32), file.source_span()] {
            let location = manager.location(span).unwrap();
            assert_eq!(manager.location_to_span(location), Some(span));
        }
    }
}
