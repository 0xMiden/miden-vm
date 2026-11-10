// Each test binary includes this module but only uses a subset of the helpers.
#![allow(dead_code)]

use std::sync::Arc;

use miden_assembly::SourceManager;
use miden_debug::{
    Executor,
    logger::{self, DebugLogger},
};

pub fn execute_trace(
    source: &str,
    source_manager: Arc<dyn SourceManager>,
) -> miden_debug::ExecutionTrace {
    let program = miden_assembly::Assembler::new(source_manager.clone())
        .assemble_program("program", source)
        .unwrap();

    Executor::new(vec![]).capture_trace(program.into(), source_manager)
}

pub fn execute_debug(
    source: &str,
    source_manager: Arc<dyn SourceManager>,
) -> miden_debug::DebugExecutor {
    let program = miden_assembly::Assembler::new(source_manager.clone())
        .assemble_program("program", source)
        .unwrap();

    Executor::new(vec![]).into_debug(program.into(), source_manager)
}

/// Initializes the debug logger for tests
///
/// # Panics
///
/// Panics if called more than once per process, as integration tests should not share a
/// `DebugLogger`
pub fn init_test_debug_logger() {
    DebugLogger::init_for_tests().expect(
        "integration tests should run in different processes to isolate their `DebugLogger`",
    );
}

/// Counts the number of log entries in the global logger which match `predicate`
pub fn count_matching<F>(predicate: F) -> usize
where
    F: FnMut(&logger::LogEntry) -> bool,
{
    DebugLogger::get().count_matching(predicate)
}

/// Returns true if any entry in the global logger matches `predicate`
pub fn contains_matching<F>(predicate: F) -> bool
where
    F: FnMut(&logger::LogEntry) -> bool,
{
    DebugLogger::get().contains_matching(predicate)
}

/// Clear the current contents of the global logger
///
/// This does not guarantee that the logger will remain empty, but the buffer is reset
pub fn clear_logs() {
    let _ = DebugLogger::get().take_captured();
}

#[macro_export]
macro_rules! assert_println {
    ($message:literal) => {
        $crate::assert_logged!(entry => entry.target == "stdout" && entry.message.contains($message));
    };

    ($message:expr) => {
        $crate::assert_logged!(entry => entry.target == "stdout" && entry.message.contains($message));
    };

    ($entry:ident => $filter:expr) => {{
        $crate::assert_logged!($entry => $entry.target == "stdout" && $filter);
    }}
}

#[macro_export]
macro_rules! assert_logged {
    ($message:literal) => {
        $crate::assert_println!(entry => entry.level > log::LevelFilter::Info && entry.message.contains($message));
    };

    ($level:ident, $message:expr) => {{
        let level_filter = stringify!($level).parse::<log::LevelFilter>().expect("invalid log level");
        $crate::assert_println!(entry => entry.level > level_filter && entry.message.contains($message));
    }};

    ($entry:ident => $filter:expr) => {{
        let logger = miden_debug::logger::DebugLogger::get();
        if !logger.contains_matching(|$entry| $filter) {
            use core::fmt::Write;
            let log = logger.clone_captured();
            let mut buf = String::new();
            for (i, entry) in log.into_iter().enumerate() {
                if i > 0 {
                    buf.push('\n');
                }
                write!(&mut buf, "[{}][{}]: {}", &entry.target, entry.level, &entry.message).unwrap();
            }
            let expr = stringify!($filter);
            panic!("expected message matching `{expr}` to have been logged:

======== stdout ===========
{buf}
===========================");
        }
    }};
}
