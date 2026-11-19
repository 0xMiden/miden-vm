use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

struct Sink(Arc<AtomicUsize>);

impl Log for Sink {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, _record: &log::Record<'_>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    fn flush(&self) {}
}

#[test]
fn logger_filters_forwards_bounds_and_queries_captured_records() {
    let logger = DebugLogger::default();
    let metadata = log::Metadata::builder().level(Level::Info).target("test").build();
    assert!(!logger.enabled(&metadata));
    logger.log(&log::Record::builder().args(format_args!("ignored")).level(Level::Info).build());
    assert!(logger.clone_captured().is_empty());
    let forwarded = Arc::new(AtomicUsize::new(0));
    logger.set_inner(Box::new(Sink(forwarded.clone())));
    assert!(logger.enabled(&metadata));
    for index in 0..HISTORY_SIZE + 2 {
        logger.log(
            &log::Record::builder()
                .args(format_args!("entry {index}"))
                .level(Level::Info)
                .target("test")
                .file_static(Some("source.rs"))
                .line(Some(7))
                .build(),
        );
    }
    logger.log(&log::Record::builder().args(format_args!("ignored")).level(Level::Debug).build());
    assert_eq!(forwarded.load(Ordering::Relaxed), HISTORY_SIZE + 2);
    let captured = logger.clone_captured();
    assert_eq!(captured.len(), HISTORY_SIZE);
    assert_eq!(captured[0].message, "entry 2");
    assert_eq!(captured[0].file.as_deref(), Some("source.rs"));
    assert_eq!(captured[0].line, Some(7));
    assert_eq!(logger.count_matching(|entry| entry.target == "test"), HISTORY_SIZE);
    assert!(logger.contains_matching(|entry| entry.message == "entry 1001"));
    assert_eq!(logger.select_matching(|entry| entry.message == "entry 1001").len(), 1);
    assert!(logger.select_matching(|entry| entry.level == Level::Error).is_empty());
    assert_eq!(logger.take_captured().len(), HISTORY_SIZE);
    assert!(logger.take_captured().is_empty());
    let file = String::from("owned.rs");
    logger.log(
        &log::Record::builder()
            .args(format_args!("owned file"))
            .level(Level::Info)
            .file(Some(&file))
            .build(),
    );
    assert_eq!(logger.take_captured()[0].file.as_deref(), Some("owned.rs"));
    logger.flush();
}
