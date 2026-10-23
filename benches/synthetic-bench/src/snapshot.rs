//! Snapshot schema for the VM-side synthetic benchmark.
//!
//! A producer JSON file (e.g. `bench-tx.json` from `protocol/bin/bench-transaction/`) maps
//! scenario keys to entries. Each entry supplies provenance metadata and a `trace` section.
//!
//! `trace` carries the AIR-side row totals used by the verifier (`core_rows`, `chiplets_rows`,
//! `eidos_compression_rows`, `byte_pair_lookup_rows`). `chiplets_shape` (nested under `trace`) is
//! an advisory per-chiplet breakdown used by the solver. The loader checks its sum against
//! `trace.chiplets_rows`, including the mandatory padding row.

use std::{collections::BTreeMap, path::Path};

use serde::Deserialize;

/// Mirrors `miden_air::trace::MIN_TRACE_LEN`. Keep in sync when the processor's minimum padded
/// length changes.
const MIN_TRACE_LEN: u64 = 64;

/// One Eidos compression cycle occupies 32 rows.
const EIDOS_COMPRESSION_CYCLE_LEN: u64 = 32;

/// Representative protocol P2ID scenarios measured separately for each signing scheme.
pub const DEFAULT_SCENARIOS: &[&str] = &[
    "consume single P2ID note with Falcon signing",
    "consume single P2ID note with ECDSA signing",
    "consume two P2ID notes with Falcon signing",
    "consume two P2ID notes with ECDSA signing",
    "create single P2ID note with Falcon signing",
    "create single P2ID note with ECDSA signing",
];

/// Measured AIR totals and an advisory per-chiplet breakdown for one producer scenario.
/// The JSON stores the breakdown under `trace.chiplets_shape`; this type exposes it as `shape`.
#[derive(Debug, Clone)]
pub struct TraceSnapshot {
    /// The row counts must come from execution of the producer workload.
    pub provenance: SnapshotProvenance,
    /// Hard-target totals. The verifier's bracket check operates on these.
    pub trace: TraceTotals,
    /// Advisory per-chiplet breakdown used by the solver for shaping.
    pub shape: TraceBreakdown,
}

/// Origin of a snapshot's trace-row counts.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotProvenance {
    ProducerMeasured,
}

impl SnapshotProvenance {
    pub fn label(self) -> &'static str {
        match self {
            Self::ProducerMeasured => "producer_measured",
        }
    }
}

/// Hard-target aggregates -- the verifier's primary contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceTotals {
    /// System + decoder + stack trace length.
    pub core_rows: u64,
    /// Total chiplets trace length, matching `ChipletsLengths::trace_len` in the processor (sum of
    /// per-chiplet lengths + 1 mandatory padding row).
    pub chiplets_rows: u64,
    /// Eidos compression AIR trace length.
    pub eidos_compression_rows: u64,
    /// Fixed And8 byte-pair lookup AIR height.
    pub byte_pair_lookup_rows: u64,
}

/// Per-chiplet producer counts used for advisory reporting and memory targeting.
/// Only the independently padded AIR heights are hard targets for synthesized programs.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TraceBreakdown {
    pub hasher_rows: u64,
    pub bitwise_rows: u64,
    pub memory_rows: u64,
    /// Kernel ROM rows. Not driven independently by the synthetic suite.
    pub kernel_rom_rows: u64,
    /// ACE chiplet rows. Not driven independently by the synthetic suite.
    pub ace_rows: u64,
}

/// In-memory bundle used by the solver and verifier; not serialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceShape {
    pub totals: TraceTotals,
    pub breakdown: TraceBreakdown,
}

impl TraceTotals {
    /// Padded power-of-two bracket for the core AIR.
    pub fn padded_core(&self) -> u64 {
        self.core_rows.next_power_of_two().max(MIN_TRACE_LEN)
    }

    /// Padded power-of-two bracket for the fixed And8 byte-pair lookup AIR.
    pub fn padded_and8_lookup(&self) -> u64 {
        self.byte_pair_lookup_rows.next_power_of_two().max(MIN_TRACE_LEN)
    }

    /// Padded power-of-two bracket for the chiplets side of the trace.
    pub fn padded_chiplets(&self) -> u64 {
        self.chiplets_rows.next_power_of_two().max(MIN_TRACE_LEN)
    }

    /// Padded power-of-two bracket for the Eidos compression trace.
    pub fn padded_eidos_compression(&self) -> u64 {
        self.eidos_compression_rows.next_power_of_two().max(MIN_TRACE_LEN)
    }

    /// Maximum physical AIR height. Used by the calibrator to cross-check the benchmark formulas
    /// against the processor's authoritative per-AIR heights.
    pub fn padded_total(&self) -> u64 {
        self.core_rows
            .max(self.byte_pair_lookup_rows)
            .max(self.chiplets_rows)
            .max(self.eidos_compression_rows)
            .next_power_of_two()
            .max(MIN_TRACE_LEN)
    }
}

impl TraceBreakdown {
    /// Sum of all chiplet sub-traces plus the mandatory +1 padding row, matching
    /// `ChipletsLengths::trace_len` in the processor. Panics if the sum exceeds `u64`.
    pub fn chiplets_sum(&self) -> u64 {
        self.checked_chiplets_sum().expect("chiplet row total overflow")
    }

    fn checked_chiplets_sum(&self) -> Option<u64> {
        self.hasher_rows
            .checked_add(self.bitwise_rows)?
            .checked_add(self.memory_rows)?
            .checked_add(self.kernel_rom_rows)?
            .checked_add(self.ace_rows)?
            .checked_add(1)
    }

    /// Advisory memory-like rows: snapshot memory plus ACE and kernel ROM.
    pub fn memory_target(&self) -> u64 {
        self.memory_rows + self.kernel_rom_rows + self.ace_rows
    }

    /// Rows combined with memory in advisory reporting because this suite does not drive them
    /// independently.
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
                eidos_compression_rows: entry.trace.eidos_compression_rows,
                byte_pair_lookup_rows: entry.trace.byte_pair_lookup_rows,
            };
            let shape = entry.trace.chiplets_shape;
            if trace.byte_pair_lookup_rows != 65_536 {
                return Err(SnapshotError::InvalidBytePairLookupRows {
                    scenario: key,
                    rows: trace.byte_pair_lookup_rows,
                });
            }
            let expected = shape
                .checked_chiplets_sum()
                .ok_or_else(|| SnapshotError::ChipletsTotalOverflow { scenario: key.clone() })?;
            if trace.chiplets_rows != expected {
                return Err(SnapshotError::InconsistentChipletsTotal {
                    scenario: key,
                    from_trace: trace.chiplets_rows,
                    from_shape: expected,
                });
            }
            if !trace.eidos_compression_rows.is_multiple_of(EIDOS_COMPRESSION_CYCLE_LEN) {
                return Err(SnapshotError::InvalidEidosCompressionRows {
                    scenario: key,
                    rows: trace.eidos_compression_rows,
                    cycle_len: EIDOS_COMPRESSION_CYCLE_LEN,
                });
            }
            for (field, rows) in [
                ("core_rows", trace.core_rows),
                ("chiplets_rows", trace.chiplets_rows),
                ("eidos_compression_rows", trace.eidos_compression_rows),
            ] {
                if rows.checked_next_power_of_two().is_none() {
                    return Err(SnapshotError::InvalidAirRows { scenario: key, field, rows });
                }
            }
            out.push((
                key,
                TraceSnapshot {
                    provenance: entry.provenance,
                    trace,
                    shape,
                },
            ));
        }
        Ok(out)
    }

    /// Combined target shape that the solver and verifier consume.
    pub fn shape(&self) -> TraceShape {
        TraceShape::new(self.trace, self.shape)
    }
}

/// Each scenario entry in a producer JSON. The producer also writes cycle counts at the top level
/// (`prologue`, `epilogue`, ...), but the consumer ignores everything except provenance and
/// `trace`.
#[derive(Deserialize)]
struct RawScenarioEntry {
    provenance: SnapshotProvenance,
    trace: RawTrace,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTrace {
    core_rows: u64,
    chiplets_rows: u64,
    eidos_compression_rows: u64,
    byte_pair_lookup_rows: u64,
    chiplets_shape: TraceBreakdown,
}

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("snapshot scenario {scenario:?}: chiplet row total overflows u64")]
    ChipletsTotalOverflow { scenario: String },
    #[error(
        "snapshot scenario {scenario:?}: {field}={rows} cannot be padded to a u64 power-of-two height"
    )]
    InvalidAirRows {
        scenario: String,
        field: &'static str,
        rows: u64,
    },
    #[error("snapshot scenario {scenario:?}: byte_pair_lookup_rows must be 65536, got {rows}")]
    InvalidBytePairLookupRows { scenario: String, rows: u64 },
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
    #[error(
        "snapshot inconsistency in scenario {scenario:?}: eidos_compression_rows = {rows} is not a multiple of {cycle_len}"
    )]
    InvalidEidosCompressionRows {
        scenario: String,
        rows: u64,
        cycle_len: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independently pin the four AIR heights of the default producer scenarios.
    const SCENARIO_HEIGHTS: &[(&str, [u64; 4])] = &[
        ("consume single P2ID note with Falcon signing", [65_536, 8_192, 131_072, 65_536]),
        ("consume single P2ID note with ECDSA signing", [16_384, 4_096, 65_536, 65_536]),
        ("consume two P2ID notes with Falcon signing", [65_536, 8_192, 131_072, 65_536]),
        ("consume two P2ID notes with ECDSA signing", [32_768, 4_096, 65_536, 65_536]),
        ("create single P2ID note with Falcon signing", [65_536, 8_192, 131_072, 65_536]),
        ("create single P2ID note with ECDSA signing", [16_384, 4_096, 65_536, 65_536]),
    ];

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
            eidos_compression_rows: 300,
            byte_pair_lookup_rows: 100,
        };
        (totals, breakdown)
    }

    fn load_test_snapshot(
        fixture_name: &str,
        snapshot: &str,
    ) -> Result<Vec<(String, TraceSnapshot)>, SnapshotError> {
        let tmp = std::env::temp_dir()
            .join(format!("synthetic-bench-{fixture_name}-{}.json", std::process::id()));
        std::fs::write(&tmp, snapshot).unwrap();
        let result = TraceSnapshot::load_all(&tmp);
        std::fs::remove_file(&tmp).unwrap();
        result
    }

    fn assert_eidos_snapshot_parse_error(
        fixture_name: &str,
        snapshot: &str,
        expected_message: &str,
    ) {
        let err = load_test_snapshot(fixture_name, snapshot)
            .expect_err("invalid schema must be rejected");

        match err {
            SnapshotError::Parse(source) => {
                let message = source.to_string();
                assert!(
                    message.contains(expected_message),
                    "expected parse error containing {expected_message:?}, got {message:?}"
                );
            },
            other => panic!("expected a schema parse error, got {other}"),
        }
    }

    #[test]
    fn advisory_memory_target_includes_ace_and_kernel_rom() {
        let (_, b) = sample_shape();
        assert_eq!(b.memory_target(), 400);
        assert_eq!(b.substituted_rows(), 100);
        // 200 + 50 + 300 + 40 + 60 + 1 padding row = 651
        assert_eq!(b.chiplets_sum(), 651);
    }

    #[test]
    fn padded_totals_match_processor_formula() {
        let (t, _) = sample_shape();
        // max(1000, 100, 651, 300) = 1000 -> next pow2 = 1024
        assert_eq!(t.padded_total(), 1024);
        // Core: 1000 → 1024. Fixed byte-pair lookup: 100 → 128.
        assert_eq!(t.padded_core(), 1024);
        assert_eq!(t.padded_and8_lookup(), 128);
        // chiplets alone: 651 → 1024
        assert_eq!(t.padded_chiplets(), 1024);
        // Eidos compression alone: 300 -> 512
        assert_eq!(t.padded_eidos_compression(), 512);
    }

    #[test]
    fn padded_total_clamps_to_min_trace_len() {
        let totals = TraceTotals {
            core_rows: 1,
            chiplets_rows: 1,
            eidos_compression_rows: 0,
            byte_pair_lookup_rows: 0,
        };
        assert_eq!(totals.padded_total(), MIN_TRACE_LEN);
        assert_eq!(totals.padded_core(), MIN_TRACE_LEN);
        assert_eq!(totals.padded_and8_lookup(), MIN_TRACE_LEN);
        assert_eq!(totals.padded_chiplets(), MIN_TRACE_LEN);
    }

    #[test]
    fn committed_snapshots_load() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("snapshots/bench-tx.json");
        let scenarios = TraceSnapshot::load_all(path).expect("load measured protocol snapshot");
        for &name in DEFAULT_SCENARIOS {
            let (_, heights) = SCENARIO_HEIGHTS
                .iter()
                .find(|(key, _)| *key == name)
                .unwrap_or_else(|| panic!("missing expected heights: {name}"));
            let (_, snapshot) = scenarios
                .iter()
                .find(|(key, _)| key == name)
                .unwrap_or_else(|| panic!("missing default scenario: {name}"));
            let totals = snapshot.trace;
            assert_eq!(
                [
                    totals.padded_core(),
                    totals.padded_chiplets(),
                    totals.padded_eidos_compression(),
                    totals.padded_and8_lookup()
                ],
                *heights,
                "{name}: measured AIR heights changed",
            );
        }
        assert_eq!(SCENARIO_HEIGHTS.len(), DEFAULT_SCENARIOS.len());
    }

    #[test]
    fn rejects_unmeasured_provenance() {
        assert_eidos_snapshot_parse_error(
            "unmeasured-provenance",
            r#"{"unmeasured": {"provenance": "derived_pending_producer_port", "trace": {}}}"#,
            "unknown variant",
        );
    }

    #[test]
    fn rejects_a_variable_and8_height() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("snapshots/bench-tx.json");
        let mut json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        json[DEFAULT_SCENARIOS[0]]["trace"]["byte_pair_lookup_rows"] = 32768.into();
        let result = load_test_snapshot("invalid-and8-height", &json.to_string());
        assert!(matches!(
            result,
            Err(SnapshotError::InvalidBytePairLookupRows { rows: 32768, .. })
        ));
    }

    #[test]
    fn rejects_overflowing_chiplet_totals() {
        let snapshot = serde_json::json!({
            "overflow": {
                "provenance": "producer_measured",
                "trace": {
                    "core_rows": 64,
                    "chiplets_rows": 0,
                    "eidos_compression_rows": 32,
                    "byte_pair_lookup_rows": 65536,
                    "chiplets_shape": {
                        "hasher_rows": u64::MAX,
                        "bitwise_rows": 0,
                        "memory_rows": 0,
                        "kernel_rom_rows": 0,
                        "ace_rows": 0
                    }
                }
            }
        });
        assert!(matches!(
            load_test_snapshot("overflowing-chiplet-totals", &snapshot.to_string()),
            Err(SnapshotError::ChipletsTotalOverflow { .. })
        ));
    }

    #[test]
    fn rejects_unrepresentable_padded_air_heights() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("snapshots/bench-tx.json");
        let mut json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        json[DEFAULT_SCENARIOS[0]]["trace"]["core_rows"] = u64::MAX.into();
        assert!(matches!(
            load_test_snapshot("overflowing-air-height", &json.to_string()),
            Err(SnapshotError::InvalidAirRows { field: "core_rows", rows: u64::MAX, .. })
        ));
    }

    #[test]
    fn rejects_missing_schema_fields() {
        let snapshot: serde_json::Value =
            serde_json::from_str(include_str!("../snapshots/bench-tx.json")).unwrap();
        for (parent, field) in [
            ("", "provenance"),
            ("/trace", "eidos_compression_rows"),
            ("/trace/chiplets_shape", "kernel_rom_rows"),
        ] {
            let mut scenario = snapshot[DEFAULT_SCENARIOS[0]].clone();
            assert!(
                scenario
                    .pointer_mut(parent)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove(field)
                    .is_some()
            );
            let incomplete = serde_json::json!({ "incomplete": scenario });
            assert_eidos_snapshot_parse_error(
                &format!("missing-{field}"),
                &incomplete.to_string(),
                field,
            );
        }
    }

    #[test]
    fn rejects_unknown_trace_fields() {
        let snapshot: serde_json::Value =
            serde_json::from_str(include_str!("../snapshots/bench-tx.json")).unwrap();
        for parent in ["/trace", "/trace/chiplets_shape"] {
            let mut scenario = snapshot[DEFAULT_SCENARIOS[0]].clone();
            scenario.pointer_mut(parent).unwrap()["unexpected_rows"] = 0.into();
            let unknown_field = serde_json::json!({ "unknown field": scenario });
            assert_eidos_snapshot_parse_error(
                "unknown-trace-field",
                &unknown_field.to_string(),
                "unexpected_rows",
            );
        }
    }

    #[test]
    fn rejects_inconsistent_chiplets_total() {
        // chiplets_rows says 500 but the breakdown sums to 11 (10 + 0 + 0 + 0 + 0 + 1).
        let mismatched = r#"{
            "broken": {
                "provenance": "producer_measured",
                "trace": {
                    "core_rows": 100,
                    "chiplets_rows": 500,
                    "eidos_compression_rows": 64,
                    "byte_pair_lookup_rows": 65536,
                    "chiplets_shape": {
                        "hasher_rows": 10,
                        "bitwise_rows": 0,
                        "memory_rows": 0,
                        "kernel_rom_rows": 0,
                        "ace_rows": 0
                    }
                }
            }
        }"#;
        let err = load_test_snapshot("chiplets-mismatch", mismatched)
            .expect_err("expected inconsistency rejection");
        assert!(matches!(err, SnapshotError::InconsistentChipletsTotal { .. }));
    }

    #[test]
    fn rejects_misaligned_eidos_compression_rows() {
        let misaligned = r#"{
            "broken": {
                "provenance": "producer_measured",
                "trace": {
                    "core_rows": 100,
                    "chiplets_rows": 11,
                    "eidos_compression_rows": 17,
                    "byte_pair_lookup_rows": 65536,
                    "chiplets_shape": {
                        "hasher_rows": 10,
                        "bitwise_rows": 0,
                        "memory_rows": 0,
                        "kernel_rom_rows": 0,
                        "ace_rows": 0
                    }
                }
            }
        }"#;
        let err = load_test_snapshot("eidos-compression-misaligned", misaligned)
            .expect_err("expected EidosCompression row rejection");
        assert!(matches!(err, SnapshotError::InvalidEidosCompressionRows { rows: 17, .. }));
    }

    #[test]
    fn ignores_extra_fields_per_scenario() {
        // Real bench-tx.json has cycle-count siblings (prologue, epilogue, ...) the loader must
        // tolerate.
        let realistic = r#"{
            "consume single P2ID note": {
                "provenance": "producer_measured",
                "prologue": 3501,
                "notes_processing": 1761,
                "epilogue": { "total": 72351 },
                "trace": {
                    "core_rows": 77699,
                    "chiplets_rows": 6538,
                    "eidos_compression_rows": 120352,
                    "byte_pair_lookup_rows": 65536,
                    "chiplets_shape": {
                        "hasher_rows": 3761,
                        "bitwise_rows": 416,
                        "memory_rows": 2297,
                        "kernel_rom_rows": 63,
                        "ace_rows": 0
                    }
                }
            }
        }"#;
        let scenarios =
            load_test_snapshot("realistic", realistic).expect("load realistic snapshot");
        assert_eq!(scenarios.len(), 1);
        let (key, snap) = &scenarios[0];
        assert_eq!(key, "consume single P2ID note");
        assert_eq!(snap.trace.core_rows, 77_699);
        assert_eq!(snap.shape.hasher_rows, 3_761);
        assert_eq!(snap.trace.eidos_compression_rows, 120_352);
    }
}
