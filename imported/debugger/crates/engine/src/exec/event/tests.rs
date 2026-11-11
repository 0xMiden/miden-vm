use alloc::string::ToString;
#[cfg(feature = "std")]
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

use super::*;

#[test]
fn print_ln_event_roundtrips() {
    assert_eq!(Event::from(PRINTLN_EVENT.to_event_id()), Event::PrintLn);
    assert_eq!(Event::PrintLn.as_event_id(), *PRINTLN_EVENT_ID);
    assert_eq!(Event::from(PRINTLN_EVENT), Event::PrintLn);
}

#[test]
fn event_metadata_covers_builtin_custom_and_unknown_events() {
    let custom_name = EventName::new("test::custom");
    let custom = Event::from(custom_name.clone());
    let unknown = Event::Unknown(EventId::from_u64(99));

    for event in [Event::FrameStart, Event::FrameEnd, Event::PrintLn] {
        assert!(event.as_event_name().is_some());
        assert!(event.has_builtin_handler());
        assert!(!event.to_string().is_empty());
    }
    assert!(custom.as_event_name().is_some());
    assert!(!custom.has_builtin_handler());
    assert_eq!(custom.to_string(), "test::custom");
    assert!(unknown.as_event_name().is_none());
    assert!(!unknown.has_builtin_handler());
    assert_eq!(unknown.to_string(), "99");

    assert!(Event::FrameStart.is_frame_start());
    assert!(!Event::FrameEnd.is_frame_start());
    assert!(Event::FrameEnd.is_frame_end());
    assert!(!Event::PrintLn.is_frame_end());
    assert_eq!(EventId::from(Event::FrameStart), *FRAME_START_EVENT_ID);
}

#[test]
#[cfg(feature = "std")]
fn events_order_by_name_with_unknown_values_last() {
    let custom = Event::from(EventName::new("test::custom"));
    let earlier = Event::from(EventName::new("test::alpha"));
    assert!(earlier < custom);
    assert!(custom > earlier);
    assert_eq!(custom.cmp(&custom), core::cmp::Ordering::Equal);
    let unknown = Event::Unknown(EventId::from_u64(1));
    assert!(Event::FrameStart < unknown);
    assert!(custom < unknown);
    assert_eq!(unknown, Event::Unknown(EventId::from_u64(1)));
    assert!(unknown > Event::FrameEnd);

    let mut first = DefaultHasher::new();
    unknown.hash(&mut first);
    let mut second = DefaultHasher::new();
    Event::Unknown(EventId::from_u64(1)).hash(&mut second);
    assert_eq!(first.finish(), second.finish());
}
