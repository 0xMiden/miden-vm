use alloc::string::String;
use std::collections::HashMap;

use miden_core::operations::Operation;

use super::*;
use crate::profiling::{OutputResult, OutputWriter, ProfilerConfig};

/// A minimal `Instrument` to test event dispatch.
struct CountingInstrument {
    name: &'static str,
    ops: u32,
}

impl Instrument for CountingInstrument {
    fn name(&self) -> &'static str {
        self.name
    }

    fn on_operation_execution_cycle(&mut self, _op: Operation, _proc: Option<&str>) {
        self.ops += 1;
    }

    fn write_report_to(&self, writer: &mut dyn OutputWriter) -> OutputResult<()> {
        writer.write_fmt(format_args!("{}:{}", self.name, self.ops))
    }
}

#[test]
fn profiler_writes_reports_to_directory() {
    let tmp_dir = tempfile::tempdir().unwrap();

    let config = ProfilerConfig {
        instruments: vec![
            Box::new(CountingInstrument {
                name: "alpha",
                ops: 0,
            }),
            Box::new(CountingInstrument {
                name: "beta",
                ops: 0,
            }),
        ],
        reports_dir: Some(tmp_dir.path().to_path_buf()),
    };
    let mut profiler = Profiler::from_config(config);

    // Record some operations so the instruments have data to report.
    profiler.on_operation_execution_cycle(Operation::Add, None);
    profiler.on_operation_execution_cycle(Operation::Noop, None);
    profiler.on_operation_execution_cycle(Operation::Add, None);

    profiler.write_reports();

    // Verify files were created with expected content.
    let alpha_content = std::fs::read_to_string(tmp_dir.path().join("alpha")).unwrap();
    assert_eq!(alpha_content, "alpha:3");

    let beta_content = std::fs::read_to_string(tmp_dir.path().join("beta")).unwrap();
    assert_eq!(beta_content, "beta:3");
}

#[test]
fn profiler_dispatches_events_to_all_instruments() {
    let config = ProfilerConfig {
        instruments: vec![
            Box::new(CountingInstrument { name: "a", ops: 0 }),
            Box::new(CountingInstrument { name: "b", ops: 0 }),
        ],
        ..Default::default()
    };
    let mut profiler = Profiler::from_config(config);

    // Each instrument must observe every recorded op.
    profiler.on_operation_execution_cycle(Operation::Add, None);
    profiler.on_operation_execution_cycle(Operation::Noop, None);

    // Collect each report into an in-memory buffer and construct string from there.
    fn report_of(instrument: &dyn Instrument) -> String {
        let mut buf = Vec::new();
        instrument.write_report_to(&mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    let reports: HashMap<&'static str, String> = profiler
        .instruments
        .iter()
        .map(|instrument| (instrument.name(), report_of(instrument.as_ref())))
        .collect();

    assert_eq!(reports.get("a").unwrap(), "a:2");
    assert_eq!(reports.get("b").unwrap(), "b:2");
}
