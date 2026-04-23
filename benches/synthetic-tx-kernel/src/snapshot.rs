//! Snapshot schema shared by the protocol-side producer and the VM-side synthetic benchmark.
//!
//! `trace` contains the hard-target totals used by the verifier:
//! - `core_rows`
//! - `chiplets_rows`
//! - `range_rows`
//!
//! `shape` contains an advisory per-chiplet breakdown used by the solver to keep the synthetic
//! workload representative. The loader validates `trace.chiplets_rows == shape.chiplets_sum()`.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Schema version this crate understands.
pub const CURRENT_SCHEMA_VERSION: &str = "0";

/// Mirrors `miden_air::trace::MIN_TRACE_LEN`. Keep in sync when the processor's minimum padded
/// length changes.
const MIN_TRACE_LEN: u64 = 64;

/// A snapshot captured from a representative transaction execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSnapshot {
    pub schema_version: String,
    pub source: String,
    pub timestamp: String,
    pub miden_vm_version: String,
    /// Hard-target totals. The verifier's bracket check operates on these.
    pub trace: TraceTotals,
    /// Advisory per-chiplet breakdown used by the solver for shaping.
    pub shape: TraceBreakdown,
}

/// Hard-target aggregates -- the verifier's primary contract.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
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
    /// Load a snapshot from disk, validate its schema version, and cross-check the internal
    /// consistency of the two tiers.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, SnapshotError> {
        let bytes = std::fs::read(path.as_ref()).map_err(|source| SnapshotError::Io {
            path: path.as_ref().display().to_string(),
            source,
        })?;
        let snap: Self = serde_json::from_slice(&bytes).map_err(SnapshotError::Parse)?;

        if snap.schema_version != CURRENT_SCHEMA_VERSION {
            return Err(SnapshotError::SchemaVersion {
                file: snap.schema_version,
                supported: CURRENT_SCHEMA_VERSION,
            });
        }

        let expected = snap.shape.chiplets_sum();
        if snap.trace.chiplets_rows != expected {
            return Err(SnapshotError::InconsistentChipletsTotal {
                from_trace: snap.trace.chiplets_rows,
                from_shape: expected,
            });
        }

        Ok(snap)
    }

    /// Combined target shape that the solver and verifier consume.
    pub fn shape(&self) -> TraceShape {
        TraceShape::new(self.trace, self.shape)
    }
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
        "unsupported snapshot schema version {file:?}; this crate understands version {supported:?}"
    )]
    SchemaVersion { file: String, supported: &'static str },
    #[error(
        "snapshot inconsistency: trace.chiplets_rows = {from_trace} but shape sums to {from_shape}"
    )]
    InconsistentChipletsTotal { from_trace: u64, from_shape: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CommittedSnapshotExpectation {
        file_stem: &'static str,
        source: &'static str,
        padded_core_side: u64,
        padded_chiplets: u64,
    }

    const COMMITTED_SNAPSHOT_EXPECTATIONS: &[CommittedSnapshotExpectation] = &[
        CommittedSnapshotExpectation {
            file_stem: "consume-single-p2id",
            source: "protocol/bench-transaction:consume-single-p2id",
            padded_core_side: 131_072,
            padded_chiplets: 131_072,
        },
        CommittedSnapshotExpectation {
            file_stem: "consume-two-p2id",
            source: "protocol/bench-transaction:consume-two-p2id",
            padded_core_side: 131_072,
            padded_chiplets: 262_144,
        },
    ];

    fn expectation_for(file_stem: &str) -> Option<&'static CommittedSnapshotExpectation> {
        COMMITTED_SNAPSHOT_EXPECTATIONS
            .iter()
            .find(|expected| expected.file_stem == file_stem)
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
    fn committed_snapshots_roundtrip() {
        let snapshots_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("snapshots");
        let entries = std::fs::read_dir(&snapshots_dir)
            .unwrap_or_else(|e| panic!("read {}: {e}", snapshots_dir.display()));
        let mut discovered = Vec::new();
        for entry in entries {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let file_stem = path.file_stem().and_then(|s| s.to_str()).expect("snapshot stem");
            let expected = expectation_for(file_stem)
                .unwrap_or_else(|| panic!("unexpected committed snapshot: {}", path.display()));
            let snap = TraceSnapshot::load(&path)
                .unwrap_or_else(|e| panic!("load {}: {e}", path.display()));
            assert_eq!(snap.schema_version, CURRENT_SCHEMA_VERSION);
            assert_eq!(snap.source, expected.source);
            assert!(snap.trace.core_rows > 0);
            assert!(snap.trace.chiplets_rows > 0);
            assert_eq!(snap.trace.chiplets_rows, snap.shape.chiplets_sum());
            assert_eq!(snap.trace.padded_core_side(), expected.padded_core_side);
            assert_eq!(snap.trace.padded_chiplets(), expected.padded_chiplets);

            let reserialized = serde_json::to_string(&snap).expect("reserialize");
            let roundtripped: TraceSnapshot =
                serde_json::from_str(&reserialized).expect("deserialize reserialized");
            assert_eq!(snap.trace, roundtripped.trace);
            assert_eq!(snap.shape, roundtripped.shape);
            discovered.push(file_stem.to_string());
        }
        discovered.sort();
        let mut expected: Vec<_> = COMMITTED_SNAPSHOT_EXPECTATIONS
            .iter()
            .map(|expected| expected.file_stem)
            .collect();
        expected.sort();
        assert_eq!(discovered, expected);
    }

    #[test]
    fn missing_optional_fields_default_to_zero() {
        let minimal = r#"{
            "schema_version": "0",
            "source": "test",
            "timestamp": "t",
            "miden_vm_version": "x",
            "trace": { "core_rows": 100, "chiplets_rows": 11, "range_rows": 50 },
            "shape": { "hasher_rows": 10, "bitwise_rows": 0, "memory_rows": 0 }
        }"#;
        let snap: TraceSnapshot = serde_json::from_str(minimal).expect("parse minimal");
        assert_eq!(snap.shape.kernel_rom_rows, 0);
        assert_eq!(snap.shape.ace_rows, 0);
    }

    #[test]
    fn rejects_unsupported_schema_version() {
        let wrong = r#"{
            "schema_version": "9999",
            "source": "test",
            "timestamp": "t",
            "miden_vm_version": "x",
            "trace": { "core_rows": 100, "chiplets_rows": 11, "range_rows": 0 },
            "shape": { "hasher_rows": 10, "bitwise_rows": 0, "memory_rows": 0 }
        }"#;
        let tmp = std::env::temp_dir().join("synthetic-tx-kernel-schema-wrong-version.json");
        std::fs::write(&tmp, wrong).unwrap();
        let err = TraceSnapshot::load(&tmp).expect_err("expected schema version rejection");
        assert!(matches!(err, SnapshotError::SchemaVersion { .. }));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn rejects_inconsistent_chiplets_total() {
        // chiplets_rows says 500 but the breakdown sums to 11 (10 + 0 + 0 + 1).
        let mismatched = r#"{
            "schema_version": "0",
            "source": "test",
            "timestamp": "t",
            "miden_vm_version": "x",
            "trace": { "core_rows": 100, "chiplets_rows": 500, "range_rows": 0 },
            "shape": { "hasher_rows": 10, "bitwise_rows": 0, "memory_rows": 0 }
        }"#;
        let tmp = std::env::temp_dir().join("synthetic-tx-kernel-chiplets-mismatch.json");
        std::fs::write(&tmp, mismatched).unwrap();
        let err = TraceSnapshot::load(&tmp).expect_err("expected inconsistency rejection");
        assert!(matches!(err, SnapshotError::InconsistentChipletsTotal { .. }));
        let _ = std::fs::remove_file(&tmp);
    }
}
