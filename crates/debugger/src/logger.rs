use std::{
    borrow::Cow,
    boxed::Box,
    collections::VecDeque,
    string::{String, ToString},
    sync::{Arc, LazyLock, Mutex},
    vec::Vec,
};

use compact_str::CompactString;
use log::{Level, LevelFilter, Log};

static LOGGER: LazyLock<DebugLogger> = LazyLock::new(DebugLogger::default);

/// The maximum depth of the debug log.
///
/// When reached, older messages are dropped first
const HISTORY_SIZE: usize = 1000;

#[derive(Default)]
struct DebugLoggerImpl {
    inner: Option<Box<dyn Log>>,
    captured: VecDeque<LogEntry>,
}

#[derive(Clone)]
pub struct LogEntry {
    pub level: Level,
    pub target: CompactString,
    pub file: Option<Cow<'static, str>>,
    pub line: Option<u32>,
    pub message: String,
}

#[derive(Default, Clone)]
pub struct DebugLogger(Arc<Mutex<DebugLoggerImpl>>);

impl Log for DebugLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        let guard = self.0.lock().unwrap();
        guard.inner.as_ref().is_some_and(|inner| inner.enabled(metadata))
    }

    fn log(&self, record: &log::Record) {
        let mut guard = self.0.lock().unwrap();
        if !guard.inner.as_ref().is_some_and(|inner| inner.enabled(record.metadata())) {
            return;
        }

        let target = CompactString::new(record.target());
        let file = record
            .file_static()
            .map(Cow::Borrowed)
            .or_else(|| record.file().map(|f| f.to_string()).map(Cow::Owned));
        let entry = LogEntry {
            target,
            level: record.level(),
            file,
            line: record.line(),
            message: format!("{}", record.args()),
        };
        guard.captured.push_back(entry);
        if guard.captured.len() > HISTORY_SIZE {
            guard.captured.pop_front();
        }
        if let Some(inner) = guard.inner.as_ref() {
            inner.log(record);
        }
    }

    fn flush(&self) {}
}

impl DebugLogger {
    /// Returns an error if the global logger was already initialized.
    pub fn install_with_max_level(
        inner: Box<dyn Log>,
        max_level: LevelFilter,
    ) -> Result<(), log::SetLoggerError> {
        let logger = &*LOGGER;
        log::set_logger(logger)?;
        // Update `inner` only if `set_logger` succeeded.
        logger.set_inner(inner);
        log::set_max_level(max_level);
        Ok(())
    }

    pub fn get() -> &'static Self {
        &LOGGER
    }

    pub fn take_captured(&self) -> VecDeque<LogEntry> {
        let mut guard = self.0.lock().unwrap();
        core::mem::take(&mut guard.captured)
    }

    /// Counts the number of log entries in the ring buffer which match `predicate`
    pub fn count_matching<F>(&self, mut predicate: F) -> usize
    where
        F: FnMut(&LogEntry) -> bool,
    {
        let guard = self.0.lock().unwrap();
        guard.captured.iter().filter(move |entry| predicate(entry)).count()
    }

    /// Returns true if any entry in the ring buffer matches `predicate`
    pub fn contains_matching<F>(&self, predicate: F) -> bool
    where
        F: FnMut(&LogEntry) -> bool,
    {
        let guard = self.0.lock().unwrap();
        guard.captured.iter().any(predicate)
    }

    /// Clones all of the log entries in the buffer which match `predicate`.
    pub fn select_matching<F>(&self, mut predicate: F) -> Vec<LogEntry>
    where
        F: FnMut(&LogEntry) -> bool,
    {
        let guard = self.0.lock().unwrap();
        guard
            .captured
            .iter()
            .filter_map(move |entry| {
                if predicate(entry) {
                    Some(entry.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn clone_captured(&self) -> VecDeque<LogEntry> {
        self.0.lock().unwrap().captured.clone()
    }

    fn set_inner(&self, logger: Box<dyn Log>) {
        drop(self.0.lock().unwrap().inner.replace(logger));
    }

    /// Returns an error if the global logger was already initialized.
    pub fn init_for_tests() -> Result<(), log::SetLoggerError> {
        use env_logger::Env;
        let env = Env::new().filter_or("MIDENC_TRACE", "info");
        let mut builder = env_logger::Builder::from_env(env);
        builder.format_indent(Some(2));
        builder.format_timestamp(None);
        Self::install_with_max_level(Box::new(builder.build()), LevelFilter::Trace)
    }
}

#[cfg(test)]
mod tests;
