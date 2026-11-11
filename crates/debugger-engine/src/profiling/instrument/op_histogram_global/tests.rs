use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use miden_core::operations::Operation;

use super::OpHistogramGlobal;
use crate::profiling::instrument::Instrument;

#[test]
fn op_histogram_reports_recorded_ops() {
    let mut hist = OpHistogramGlobal::default();

    // 3 cycles, procedure names are ignored by the global histogram.
    hist.on_operation_execution_cycle(Operation::Add, Some("main"));
    hist.on_operation_execution_cycle(Operation::Add, Some("sum"));
    hist.on_operation_execution_cycle(Operation::Noop, None);

    let mut buf = Vec::new();
    hist.write_report_to(&mut buf).unwrap();
    let report = String::from_utf8(buf).unwrap();

    let lines: Vec<&str> = report.lines().collect();
    // First line is the header reporting 100% of 3 cycles.
    assert!(lines[0].contains("total_cycles") && lines[0].contains('3'));

    // `Add` must preceed `Noop`, due to higher count.
    assert!(lines[1].contains(Operation::Add.to_string().as_str()) && lines[1].contains("2"));
    assert!(lines[2].contains(Operation::Noop.to_string().as_str()) && lines[2].contains("1"));

    // no further lines
    assert_eq!(lines.len(), 3);
}

/// The global histogram must not be affected by which procedure an op is recorded in.
#[test]
fn op_histogram_ignores_procedure() {
    let mut across_procs = OpHistogramGlobal::default();
    let mut single_proc = OpHistogramGlobal::default();

    across_procs.on_operation_execution_cycle(Operation::Add, Some("sum"));
    across_procs.on_operation_execution_cycle(Operation::Add, Some("main"));
    across_procs.on_operation_execution_cycle(Operation::Noop, None);

    single_proc.on_operation_execution_cycle(Operation::Add, Some("main"));
    single_proc.on_operation_execution_cycle(Operation::Add, Some("main"));
    single_proc.on_operation_execution_cycle(Operation::Noop, Some("main"));

    assert_eq!(across_procs.hist.report(), single_proc.hist.report());
}
