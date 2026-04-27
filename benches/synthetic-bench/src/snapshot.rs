//! Snapshot schema for the VM-side synthetic benchmark.
//!
//! A producer JSON file (e.g. `bench-tx.json` from `protocol/bin/bench-transaction/`) maps
//! scenario keys to entries; only the `trace` section of each entry is consumed.
//!
//! `trace` carries the AIR-side row totals used by the verifier (`core_rows`, `chiplets_rows`,
//! `range_rows`). `shape` (nested under `trace`) is an advisory per-chiplet breakdown used by the
//! solver. The loader checks `trace.chiplets_rows == shape.chiplets_sum()`.

use std::{collections::BTreeMap, path::Path};

use serde::Deserialize;

/// Mirrors `miden_air::trace::MIN_TRACE_LEN`. Keep in sync when the processor's minimum padded
/// length changes.
const MIN_TRACE_LEN: u64 = 64;

/// A single scenario's trace snapshot, extracted from a producer JSON file.
///
/// On disk, `shape` is nested under `trace` (`{ "trace": { "core_rows": ..., "shape": ... } }`).
/// Here `shape` is a sibling of `trace` so callers can write `snap.shape.hasher_rows` instead of
/// `snap.trace.shape.hasher_rows`; `RawScenarioEntry` / `RawTrace` below bridge the layouts at
/// deserialization time.
#[derive(Debug, Clone)]
pub struct TraceSnapshot {
    /// Hard-target totals. The verifier's bracket check operates on these.
    pub trace: TraceTotals,
    /// Advisory per-chiplet breakdown used by the solver for shaping.
    pub shape: TraceBreakdown,
}

/// Hard-target aggregates -- the verifier's primary contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceTotals {
    /// System + decoder + stack trace length.
    pub core_rows: u64,
    /// Total chiplets trace length, matching `ChipletsLengths::trace_len` in the processor (sum of
    /// per-chiplet lengths + 1 mandatory padding row).
    pub chiplets_rows: u64,
    /// Range-checker trace length. Derived from memory + bitwise activity; not independently
    /// targeted but tracked so the verifier can warn if it ever dominates.
    pub range_rows: u64,
}

/// Per-chiplet row counts. Advisory only -- the solver uses these to size individual snippets so
/// the synthetic program stays representative (hasher work looks like hasher work, not a pile of
/// decoder-pad), but the verifier does not treat individual values as hard targets.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub struct TraceBreakdown {
    pub hasher_rows: u64,
    pub bitwise_rows: u64,
    pub memory_rows: u64,
    /// Kernel ROM rows. Not drivable from plain MASM; folded into memory.
    #[serde(default)]
    pub kernel_rom_rows: u64,
    /// ACE chiplet rows. Not drivable from plain MASM; folded into memory. Some producer versions
    /// may report this as zero until their processor dependency exposes the ACE trace accessor.
    #[serde(default)]
    pub ace_rows: u64,
}

/// In-memory bundle used by the solver and verifier; not serialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceShape {
    pub totals: TraceTotals,
    pub breakdown: TraceBreakdown,
}

impl TraceTotals {
    /// Padded power-of-two bracket for the non-chiplet side of the trace:
    /// `next_pow2(max(core_rows, range_rows))`. Under the current AIR this covers core
    /// (system/decoder/stack) and range together; if a future AIR separates them, this accessor
    /// can be revisited.
    pub fn padded_core_side(&self) -> u64 {
        self.core_rows.max(self.range_rows).next_power_of_two().max(MIN_TRACE_LEN)
    }

    /// Padded power-of-two bracket for the chiplets side of the trace.
    pub fn padded_chiplets(&self) -> u64 {
        self.chiplets_rows.next_power_of_two().max(MIN_TRACE_LEN)
    }

    /// Single global padded length as reported by the processor's
    /// `TraceLenSummary::padded_trace_len`. Used by the calibrator to cross-check our derived
    /// formulas against the prover.
    pub fn padded_total(&self) -> u64 {
        self.core_rows
            .max(self.range_rows)
            .max(self.chiplets_rows)
            .next_power_of_two()
            .max(MIN_TRACE_LEN)
    }

    /// True iff `range_rows` is the largest unpadded component.
    pub fn range_dominates(&self) -> bool {
        self.range_rows > self.core_rows && self.range_rows > self.chiplets_rows
    }
}

impl TraceBreakdown {
    /// Sum of all chiplet sub-traces plus the mandatory +1 padding row, matching
    /// `ChipletsLengths::trace_len` in the processor. Used as the loader's consistency check
    /// against `TraceTotals::chiplets_rows`.
    pub fn chiplets_sum(&self) -> u64 {
        self.hasher_rows
            + self.bitwise_rows
            + self.memory_rows
            + self.kernel_rom_rows
            + self.ace_rows
            + 1
    }

    /// Memory-row target the solver aims for: snapshot memory plus ACE and kernel_rom (both
    /// unreachable from plain MASM) folded in.
    pub fn memory_target(&self) -> u64 {
        self.memory_rows + self.kernel_rom_rows + self.ace_rows
    }

    /// Rows folded into the memory target from unreachable chiplets.
    pub fn substituted_rows(&self) -> u64 {
        self.kernel_rom_rows + self.ace_rows
    }
}

impl TraceShape {
    pub fn new(totals: TraceTotals, breakdown: TraceBreakdown) -> Self {
        Self { totals, breakdown }
    }
}

impl TraceSnapshot {
    /// Load every scenario in a producer JSON file, returning `(scenario_key, snapshot)` pairs in
    /// alphabetical order. Each scenario's trace section is extracted; cycle counts and other
    /// per-scenario fields are ignored.
    pub fn load_all(path: impl AsRef<Path>) -> Result<Vec<(String, Self)>, SnapshotError> {
        let path_str = path.as_ref().display().to_string();
        let bytes = std::fs::read(path.as_ref())
            .map_err(|source| SnapshotError::Io { path: path_str, source })?;
        let raw: BTreeMap<String, RawScenarioEntry> =
            serde_json::from_slice(&bytes).map_err(SnapshotError::Parse)?;

        let mut out = Vec::with_capacity(raw.len());
        for (key, entry) in raw {
            let trace = TraceTotals {
                core_rows: entry.trace.core_rows,
                chiplets_rows: entry.trace.chiplets_rows,
                range_rows: entry.trace.range_rows,
            };
            let shape = entry.trace.shape;
            let expected = shape.chiplets_sum();
            if trace.chiplets_rows != expected {
                return Err(SnapshotError::InconsistentChipletsTotal {
                    scenario: key,
                    from_trace: trace.chiplets_rows,
                    from_shape: expected,
                });
            }
            out.push((key, TraceSnapshot { trace, shape }));
        }
        Ok(out)
    }

    /// Combined target shape that the solver and verifier consume.
    pub fn shape(&self) -> TraceShape {
        TraceShape::new(self.trace, self.shape)
    }
}

/// Each scenario entry in a producer JSON. The producer also writes cycle counts at the top level
/// (`prologue`, `epilogue`, ...), but the consumer ignores everything except `trace`.
#[derive(Deserialize)]
struct RawScenarioEntry {
    trace: RawTrace,
}

#[derive(Deserialize)]
struct RawTrace {
    core_rows: u64,
    chiplets_rows: u64,
    range_rows: u64,
    shape: TraceBreakdown,
}

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("failed to read snapshot at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse snapshot JSON: {0}")]
    Parse(#[source] serde_json::Error),
    #[error(
        "snapshot inconsistency in scenario {scenario:?}: trace.chiplets_rows = {from_trace} but shape sums to {from_shape}"
    )]
    InconsistentChipletsTotal {
        scenario: String,
        from_trace: u64,
        from_shape: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expected padded brackets for each committed scenario. Keyed by `(producer_stem,
    /// scenario_key)` since each producer file holds many scenarios. A mismatch means refresh
    /// the snapshot from the producer before updating these numbers.
    struct CommittedScenarioExpectation {
        producer_stem: &'static str,
        scenario_key: &'static str,
        padded_core_side: u64,
        padded_chiplets: u64,
    }

    const COMMITTED_SCENARIO_EXPECTATIONS: &[CommittedScenarioExpectation] = &[
        CommittedScenarioExpectation {
            producer_stem: "bench-tx",
            scenario_key: "consume single P2ID note",
            padded_core_side: 131_072,
            padded_chiplets: 131_072,
        },
        CommittedScenarioExpectation {
            producer_stem: "bench-tx",
            scenario_key: "consume two P2ID notes",
            padded_core_side: 131_072,
            padded_chiplets: 262_144,
        },
        CommittedScenarioExpectation {
            producer_stem: "bench-tx",
            scenario_key: "create single P2ID note",
            padded_core_side: 131_072,
            padded_chiplets: 131_072,
        },
    ];

    fn expectation_for(
        producer_stem: &str,
        scenario_key: &str,
    ) -> Option<&'static CommittedScenarioExpectation> {
        COMMITTED_SCENARIO_EXPECTATIONS.iter().find(|expected| {
            expected.producer_stem == producer_stem && expected.scenario_key == scenario_key
        })
    }

    fn sample_shape() -> (TraceTotals, TraceBreakdown) {
        let breakdown = TraceBreakdown {
            hasher_rows: 200,
            bitwise_rows: 50,
            memory_rows: 300,
            kernel_rom_rows: 40,
            ace_rows: 60,
        };
        let totals = TraceTotals {
            core_rows: 1000,
            chiplets_rows: breakdown.chiplets_sum(),
            range_rows: 100,
        };
        (totals, breakdown)
    }

    #[test]
    fn memory_target_folds_ace_and_kernel_rom() {
        let (_, b) = sample_shape();
        assert_eq!(b.memory_target(), 400);
        assert_eq!(b.substituted_rows(), 100);
        // 200 + 50 + 300 + 40 + 60 + 1 padding row = 651
        assert_eq!(b.chiplets_sum(), 651);
    }

    #[test]
    fn padded_totals_match_processor_formula() {
        let (t, _) = sample_shape();
        // max(1000, 100, 651) = 1000 → next pow2 = 1024
        assert_eq!(t.padded_total(), 1024);
        // core + range: max(1000, 100) = 1000 → 1024
        assert_eq!(t.padded_core_side(), 1024);
        // chiplets alone: 651 → 1024
        assert_eq!(t.padded_chiplets(), 1024);
    }

    #[test]
    fn padded_total_clamps_to_min_trace_len() {
        let totals = TraceTotals {
            core_rows: 1,
            chiplets_rows: 1,
            range_rows: 0,
        };
        assert_eq!(totals.padded_total(), MIN_TRACE_LEN);
        assert_eq!(totals.padded_core_side(), MIN_TRACE_LEN);
        assert_eq!(totals.padded_chiplets(), MIN_TRACE_LEN);
    }

    #[test]
    fn range_dominates_is_detected() {
        let totals = TraceTotals {
            core_rows: 100,
            chiplets_rows: 200,
            range_rows: 500,
        };
        assert!(totals.range_dominates());
        let totals = TraceTotals {
            core_rows: 500,
            chiplets_rows: 200,
            range_rows: 100,
        };
        assert!(!totals.range_dominates());
    }

    #[test]
    fn committed_snapshots_load() {
        use std::collections::BTreeSet;

        let snapshots_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("snapshots");
        let entries = std::fs::read_dir(&snapshots_dir)
            .unwrap_or_else(|e| panic!("read {}: {e}", snapshots_dir.display()));

        // Defer the table-vs-files check to the end so a single test run reports all drift,
        // not just the first mismatch.
        let mut discovered: BTreeSet<(String, String)> = BTreeSet::new();
        let mut unexpected: BTreeSet<(String, String)> = BTreeSet::new();
        for entry in entries {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let producer_stem =
                path.file_stem().and_then(|s| s.to_str()).expect("producer stem").to_string();
            let scenarios = TraceSnapshot::load_all(&path)
                .unwrap_or_else(|e| panic!("load {}: {e}", path.display()));
            assert!(!scenarios.is_empty(), "{} contained no scenarios", path.display());
            for (key, snap) in &scenarios {
                assert!(snap.trace.core_rows > 0, "{key}: core_rows must be > 0");
                assert!(snap.trace.chiplets_rows > 0, "{key}: chiplets_rows must be > 0");
                assert_eq!(
                    snap.trace.chiplets_rows,
                    snap.shape.chiplets_sum(),
                    "{key}: chiplets_rows must equal sum(shape) + 1",
                );

                match expectation_for(&producer_stem, key) {
                    Some(expected) => {
                        assert_eq!(
                            snap.trace.padded_core_side(),
                            expected.padded_core_side,
                            "{producer_stem}/{key}: padded_core_side moved to a different bracket; \
                             refresh the snapshot and update COMMITTED_SCENARIO_EXPECTATIONS",
                        );
                        assert_eq!(
                            snap.trace.padded_chiplets(),
                            expected.padded_chiplets,
                            "{producer_stem}/{key}: padded_chiplets moved to a different bracket; \
                             refresh the snapshot and update COMMITTED_SCENARIO_EXPECTATIONS",
                        );
                        discovered.insert((producer_stem.clone(), key.clone()));
                    },
                    None => {
                        unexpected.insert((producer_stem.clone(), key.clone()));
                    },
                }
            }
        }

        let expected: BTreeSet<(String, String)> = COMMITTED_SCENARIO_EXPECTATIONS
            .iter()
            .map(|e| (e.producer_stem.to_string(), e.scenario_key.to_string()))
            .collect();
        let missing: BTreeSet<_> = expected.difference(&discovered).cloned().collect();
        assert!(
            unexpected.is_empty() && missing.is_empty(),
            "committed scenarios drifted from COMMITTED_SCENARIO_EXPECTATIONS in snapshot.rs:\n  \
             unexpected (in snapshots/ but not in the table -- add an entry): {unexpected:?}\n  \
             missing    (in the table but not in any snapshots/*.json -- refresh the snapshot or remove the entry): {missing:?}",
        );
    }

    #[test]
    fn missing_optional_fields_default_to_zero() {
        let minimal = r#"{
            "consume single P2ID note": {
                "trace": {
                    "core_rows": 100,
                    "chiplets_rows": 11,
                    "range_rows": 50,
                    "shape": { "hasher_rows": 10, "bitwise_rows": 0, "memory_rows": 0 }
                }
            }
        }"#;
        let tmp = std::env::temp_dir().join("synthetic-bench-defaults.json");
        std::fs::write(&tmp, minimal).unwrap();
        let scenarios = TraceSnapshot::load_all(&tmp).expect("load defaults snapshot");
        let _ = std::fs::remove_file(&tmp);
        let (_, snap) = &scenarios[0];
        assert_eq!(snap.shape.kernel_rom_rows, 0);
        assert_eq!(snap.shape.ace_rows, 0);
    }

    #[test]
    fn rejects_inconsistent_chiplets_total() {
        // chiplets_rows says 500 but the breakdown sums to 11 (10 + 0 + 0 + 0 + 0 + 1).
        let mismatched = r#"{
            "broken": {
                "trace": {
                    "core_rows": 100,
                    "chiplets_rows": 500,
                    "range_rows": 0,
                    "shape": { "hasher_rows": 10, "bitwise_rows": 0, "memory_rows": 0 }
                }
            }
        }"#;
        let tmp = std::env::temp_dir().join("synthetic-bench-chiplets-mismatch.json");
        std::fs::write(&tmp, mismatched).unwrap();
        let err = TraceSnapshot::load_all(&tmp).expect_err("expected inconsistency rejection");
        let _ = std::fs::remove_file(&tmp);
        assert!(matches!(err, SnapshotError::InconsistentChipletsTotal { .. }));
    }

    #[test]
    fn ignores_extra_fields_per_scenario() {
        // Real bench-tx.json has cycle-count siblings (prologue, epilogue, ...) we don't care
        // about; the loader must tolerate them.
        let realistic = r#"{
            "consume single P2ID note": {
                "prologue": 3501,
                "notes_processing": 1761,
                "epilogue": { "total": 72351 },
                "trace": {
                    "core_rows": 77699,
                    "chiplets_rows": 123129,
                    "range_rows": 20203,
                    "shape": {
                        "hasher_rows": 120352,
                        "bitwise_rows": 416,
                        "memory_rows": 2297,
                        "kernel_rom_rows": 63,
                        "ace_rows": 0
                    }
                }
            }
        }"#;
        let tmp = std::env::temp_dir().join("synthetic-bench-realistic.json");
        std::fs::write(&tmp, realistic).unwrap();
        let scenarios = TraceSnapshot::load_all(&tmp).expect("load realistic snapshot");
        let _ = std::fs::remove_file(&tmp);
        assert_eq!(scenarios.len(), 1);
        let (key, snap) = &scenarios[0];
        assert_eq!(key, "consume single P2ID note");
        assert_eq!(snap.trace.core_rows, 77_699);
        assert_eq!(snap.shape.hasher_rows, 120_352);
    }
}
