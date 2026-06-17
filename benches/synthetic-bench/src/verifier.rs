//! Verification helpers for synthetic-trace matching.
//!
//! Hard checks:
//! - `padded_core(actual) == padded_core(target)`
//! - `padded_chiplets(actual) == padded_chiplets(target)`
//! - `padded_blakeg_compression(actual) == padded_blakeg_compression(target)`
//!
//! Soft reporting:
//! - dynamic AIR totals within [`PER_COMPONENT_TOLERANCE`]
//! - advisory breakdown deltas (info only)

use std::fmt::{self, Display};

use crate::snapshot::TraceShape;

/// Reporting tolerance for raw row totals; never used for pass/fail.
pub const PER_COMPONENT_TOLERANCE: f64 = 0.02;

/// Result of comparing an emitted program's measured shape against the snapshot target.
#[derive(Debug, Clone)]
pub struct VerificationReport {
    pub target: TraceShape,
    pub actual: TraceShape,
    pub total_deltas: Vec<ComponentDelta>,
    pub breakdown_deltas: Vec<ComponentDelta>,
}

/// How a row-count entry participates in the verifier's reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaStatus {
    /// Prints `ok` if within tolerance, `out` otherwise.
    Enforced,
    /// Always prints `info`; used for rows the solver does not target.
    Informational,
}

/// Per-row-count comparison.
#[derive(Debug, Clone, Copy)]
pub struct ComponentDelta {
    pub name: &'static str,
    pub target: u64,
    pub actual: u64,
    pub delta_pct: f64,
    pub within_tolerance: bool,
    pub status: DeltaStatus,
}

impl VerificationReport {
    pub fn new(target: TraceShape, actual: TraceShape) -> Self {
        let total_rows: &[(&'static str, u64, u64, DeltaStatus)] = &[
            (
                "core_rows",
                target.totals.core_rows,
                actual.totals.core_rows,
                DeltaStatus::Enforced,
            ),
            (
                "chiplets_rows",
                target.totals.chiplets_rows,
                actual.totals.chiplets_rows,
                DeltaStatus::Enforced,
            ),
            (
                "blakeg_compression_rows",
                target.totals.blakeg_compression_rows,
                actual.totals.blakeg_compression_rows,
                DeltaStatus::Enforced,
            ),
        ];
        let breakdown_rows: &[(&'static str, u64, u64, DeltaStatus)] = &[
            (
                "hasher",
                target.breakdown.hasher_rows,
                actual.breakdown.hasher_rows,
                DeltaStatus::Informational,
            ),
            (
                "bitwise",
                target.breakdown.bitwise_rows,
                actual.breakdown.bitwise_rows,
                DeltaStatus::Informational,
            ),
            (
                "memory",
                target.breakdown.memory_target(),
                actual.breakdown.memory_rows,
                DeltaStatus::Informational,
            ),
        ];
        Self {
            target,
            actual,
            total_deltas: total_rows.iter().map(|r| component_delta(*r)).collect(),
            breakdown_deltas: breakdown_rows.iter().map(|r| component_delta(*r)).collect(),
        }
    }

    /// True when all dynamic AIR padded brackets match their targets exactly.
    pub fn brackets_match(&self) -> bool {
        self.target.totals.padded_core() == self.actual.totals.padded_core()
            && self.target.totals.padded_chiplets() == self.actual.totals.padded_chiplets()
            && self.target.totals.padded_blakeg_compression()
                == self.actual.totals.padded_blakeg_compression()
    }
}

fn component_delta((name, t, a, status): (&'static str, u64, u64, DeltaStatus)) -> ComponentDelta {
    let delta_pct = if t == 0 {
        if a == 0 { 0.0 } else { f64::INFINITY }
    } else {
        (a as f64 - t as f64) / t as f64
    };
    ComponentDelta {
        name,
        target: t,
        actual: a,
        delta_pct,
        within_tolerance: delta_pct.abs() <= PER_COMPONENT_TOLERANCE,
        status,
    }
}

impl Display for VerificationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "-- hard brackets (padded power-of-two) --")?;
        write_bracket_row(
            f,
            "padded_core",
            self.target.totals.padded_core(),
            self.actual.totals.padded_core(),
        )?;
        write_bracket_row(
            f,
            "padded_chiplets",
            self.target.totals.padded_chiplets(),
            self.actual.totals.padded_chiplets(),
        )?;
        write_bracket_row(
            f,
            "padded_blakeg",
            self.target.totals.padded_blakeg_compression(),
            self.actual.totals.padded_blakeg_compression(),
        )?;
        writeln!(f, "\n-- totals (soft: {:.0}% band) --", PER_COMPONENT_TOLERANCE * 100.0)?;
        write_delta_header(f)?;
        for d in &self.total_deltas {
            write_delta_row(f, d)?;
        }

        writeln!(f, "\n-- breakdown (info) --")?;
        write_delta_header(f)?;
        for d in &self.breakdown_deltas {
            write_delta_row(f, d)?;
        }

        writeln!(f)?;
        if self.brackets_match() {
            writeln!(f, "=> BRACKET MATCH")?;
        } else {
            writeln!(f, "=> BRACKET MISS")?;
        }
        Ok(())
    }
}

fn write_delta_header(f: &mut fmt::Formatter<'_>) -> fmt::Result {
    writeln!(
        f,
        "{:<16} {:>12} {:>12} {:>10}  status",
        "component", "target", "actual", "delta"
    )
}

fn write_delta_row(f: &mut fmt::Formatter<'_>, d: &ComponentDelta) -> fmt::Result {
    let delta_str = if d.delta_pct.is_finite() {
        format!("{:+6.2}%", d.delta_pct * 100.0)
    } else {
        "+inf".to_string()
    };
    let status = match d.status {
        DeltaStatus::Enforced => {
            if d.within_tolerance {
                "ok"
            } else {
                "out"
            }
        },
        DeltaStatus::Informational => "info",
    };
    writeln!(
        f,
        "{:<16} {:>12} {:>12} {:>10}  {}",
        d.name, d.target, d.actual, delta_str, status
    )
}

fn write_bracket_row(
    f: &mut fmt::Formatter<'_>,
    name: &str,
    target: u64,
    actual: u64,
) -> fmt::Result {
    let ok = if target == actual { "==" } else { "MISS" };
    writeln!(f, "{name:<16} {target:>12} {actual:>12} {ok:>10}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{TraceBreakdown, TraceTotals};

    fn shape(core: u64, hasher: u64, memory: u64) -> TraceShape {
        let breakdown = TraceBreakdown {
            hasher_rows: hasher,
            bitwise_rows: 0,
            memory_rows: memory,
            kernel_rom_rows: 0,
            ace_rows: 0,
        };
        let totals = TraceTotals {
            core_rows: core,
            chiplets_rows: breakdown.chiplets_sum(),
            blakeg_compression_rows: hasher,
        };
        TraceShape::new(totals, breakdown)
    }

    #[test]
    fn exact_match_is_bracket_ok_and_all_within_tolerance() {
        let t = shape(68000, 8000, 12000);
        let r = VerificationReport::new(t, t);
        assert!(r.brackets_match());
        assert!(r.total_deltas.iter().all(|d| d.within_tolerance));
        assert!(r.breakdown_deltas.iter().all(|d| d.within_tolerance));
    }

    #[test]
    fn bracket_miss_is_reported_when_core_bracket_differs() {
        // target.core=68000 -> 131072; actual.core=30000 -> 32768.
        let target = shape(68000, 8000, 12000);
        let actual = shape(30000, 2000, 1000);
        let r = VerificationReport::new(target, actual);
        assert!(!r.brackets_match());
        assert!(r.to_string().contains("BRACKET MISS"));
    }

    #[test]
    fn chiplets_bracket_can_miss_independently_of_core() {
        // core is the same (same padded bracket); chiplets_rows lands in different brackets.
        // target chiplets = 8000 + 12000 + 1 = 20001 -> 32768
        // actual chiplets = 20000 + 30000 + 1 = 50001 -> 65536
        let target = shape(40000, 8000, 12000);
        let actual = shape(40000, 20000, 30000);
        let r = VerificationReport::new(target, actual);
        // padded_core: both 40000 -> 65536.
        assert_eq!(target.totals.padded_core(), actual.totals.padded_core());
        // padded_chiplets differs
        assert_ne!(target.totals.padded_chiplets(), actual.totals.padded_chiplets());
        assert!(!r.brackets_match());
    }

    #[test]
    fn per_component_overshoot_stays_within_bracket() {
        // Hasher overshoots but every AIR stays within its padded bracket.
        let target = shape(68000, 8000, 12000);
        let actual = shape(68000, 8170, 12000);
        let r = VerificationReport::new(target, actual);
        assert!(r.brackets_match());
        let hasher_delta = r.breakdown_deltas.iter().find(|d| d.name == "hasher").unwrap();
        assert!(!hasher_delta.within_tolerance);
    }
}
