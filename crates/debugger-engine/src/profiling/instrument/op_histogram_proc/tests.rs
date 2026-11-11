use alloc::{string::String, vec::Vec};

use miden_core::operations::Operation;

use super::OpHistogramProc;
use crate::profiling::instrument::Instrument;

/// Returns the part of `report` that belongs to the section started by `procedure: <name>`.
fn section<'a>(report: &'a str, name: &str) -> &'a str {
    let marker = format!("procedure: {name}\n");
    let start = report.find(&marker).expect("section exists") + marker.len();
    match report[start..].find("procedure: ") {
        Some(rel) => &report[start..start + rel],
        None => &report[start..],
    }
}

/// Returns the count shown on the report line for `label` within `section`, or `None` if
/// the section has no line for `label`.
///
/// Matching op and count on a single line ensures the count is actually attributed to
/// `label` and not to another op in the same section.
fn count_for(section: &str, label: &str) -> Option<u64> {
    section
        .lines()
        .find(|line| line.split_whitespace().next() == Some(label))
        .map(parse_count_from_line)
}

/// Sums `total_cycles` over all procedure sections in `report`, including `<unknown>`.
fn sum_total_cycles(report: &str) -> u64 {
    report
        .lines()
        .filter(|line| line.split_whitespace().next() == Some("total_cycles"))
        .map(parse_count_from_line)
        .sum()
}

/// Parses the count from the last column of a report line.
fn parse_count_from_line(line: &str) -> u64 {
    line.split_whitespace()
        .last()
        .and_then(|count| count.parse().ok())
        .expect("report line ends with the count")
}

#[test]
fn op_histogram_proc_reports_per_procedure_histograms() {
    let mut hist = OpHistogramProc::default();

    hist.on_operation_execution_cycle(Operation::Add, Some("main"));
    hist.on_operation_execution_cycle(Operation::Add, Some("main"));
    hist.on_operation_execution_cycle(Operation::Noop, Some("sum"));
    hist.on_operation_execution_cycle(Operation::Mul, Some("sum"));

    let mut buf = Vec::new();
    hist.write_report_to(&mut buf).unwrap();
    let report = String::from_utf8(buf).unwrap();

    // `main` recorded 2 cycles, both `add`.
    let main = section(&report, "main");
    assert_eq!(count_for(main, "total_cycles"), Some(2));
    assert_eq!(count_for(main, "add"), Some(2));
    assert_eq!(count_for(main, "noop"), None);

    // `sum` recorded 2 cycles, one `noop` and one `mul`.
    let sum = section(&report, "sum");
    assert_eq!(count_for(sum, "total_cycles"), Some(2));
    assert_eq!(count_for(sum, "noop"), Some(1));
    assert_eq!(count_for(sum, "mul"), Some(1));

    // All 4 recorded cycles are accounted for across the sections.
    assert_eq!(sum_total_cycles(&report), 4);
}

#[test]
fn op_histogram_proc_sorts_by_total_cycles() {
    let mut hist = OpHistogramProc::default();

    // `z` has more cycles than `a`, so it's printed first despite the alphabetical order.
    hist.on_operation_execution_cycle(Operation::Add, Some("z"));
    hist.on_operation_execution_cycle(Operation::Add, Some("z"));
    hist.on_operation_execution_cycle(Operation::Add, Some("z"));
    hist.on_operation_execution_cycle(Operation::Noop, Some("a"));

    let mut buf = Vec::new();
    hist.write_report_to(&mut buf).unwrap();
    let report = String::from_utf8(buf).unwrap();

    let z_pos = report.find("procedure: z").unwrap();
    let a_pos = report.find("procedure: a").unwrap();
    assert!(z_pos < a_pos, "histogram with more cycles must be printed first:\n{report}");

    // All 4 recorded cycles are accounted for across the sections.
    assert_eq!(sum_total_cycles(&report), 4);
}

#[test]
fn op_histogram_proc_collects_unattributed_ops_separately() {
    let mut hist = OpHistogramProc::default();

    hist.on_operation_execution_cycle(Operation::Add, None);
    hist.on_operation_execution_cycle(Operation::Add, None);
    hist.on_operation_execution_cycle(Operation::Noop, Some("main"));

    let mut buf = Vec::new();
    hist.write_report_to(&mut buf).unwrap();
    let report = String::from_utf8(buf).unwrap();

    // The `<unknown>` section holds both unattributed `add`s and is not merged into `main`.
    let unknown = section(&report, "<unknown>");
    assert_eq!(count_for(unknown, "total_cycles"), Some(2));
    assert_eq!(count_for(unknown, "add"), Some(2));
    assert_eq!(count_for(unknown, "noop"), None);

    let main = section(&report, "main");
    assert_eq!(count_for(main, "noop"), Some(1));
    assert_eq!(count_for(main, "add"), None);

    // All 3 recorded cycles (2 unattributed, 1 in `main`) are accounted for.
    assert_eq!(sum_total_cycles(&report), 3);
}
