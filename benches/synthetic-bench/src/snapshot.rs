//! Snapshot schema for the VM-side synthetic benchmark.
//!
//! A producer JSON file (e.g. `bench-tx.json` from `protocol/bin/bench-transaction/`) maps
//! scenario keys to entries. Each entry supplies provenance metadata and a `trace` section.
//!
//! `trace` carries the AIR-side row totals used by the verifier (`core_rows`, `chiplets_rows`,
//! `eidos_compression_rows`, `byte_pair_lookup_rows`). `shape` (nested under `trace`) is an
//! advisory per-chiplet breakdown used by the solver. The loader checks
//! `trace.chiplets_rows == shape.chiplets_sum()`.

use std::{collections::BTreeMap, path::Path};

use serde::Deserialize;

/// Mirrors `miden_air::trace::MIN_TRACE_LEN`. Keep in sync when the processor's minimum padded
/// length changes.
const MIN_TRACE_LEN: u64 = 64;

/// One Eidos compression cycle occupies 32 rows.
const EIDOS_COMPRESSION_CYCLE_LEN: u64 = 32;

/// One Poseidon2 permutation cycle occupies 16 rows.
const POSEIDON2_CYCLE_LEN: u64 = 16;

/// Explicit authentication scenarios retained in the upstream Poseidon2 producer artifact.
///
/// The Eidos benchmark does not execute these source rows. The list is kept here so fixture
/// tooling and coverage tests cannot silently fall back to the old ambiguous P2ID scenario keys.
pub const POSEIDON2_AUTH_SCENARIOS: &[&str] = &[
    "consume single P2ID note with Falcon signing",
    "consume single P2ID note with ECDSA signing",
    "consume two P2ID notes with Falcon signing",
    "consume two P2ID notes with ECDSA signing",
    "create single P2ID note with Falcon signing",
    "create single P2ID note with ECDSA signing",
];

/// A single scenario's trace snapshot, extracted from a producer JSON file.
///
/// On disk, the chiplet breakdown is nested under `trace` as `chiplets_shape`
/// (`{ "trace": { "core_rows": ..., "chiplets_shape": ... } }`). Here it's hoisted to a sibling
/// of `trace` and renamed `shape` so callers can write `snap.shape.hasher_rows` instead of
/// `snap.trace.chiplets_shape.hasher_rows`; `RawScenarioEntry` / `RawTrace` below bridge the
/// layouts at deserialization time.
#[derive(Debug, Clone)]
pub struct TraceSnapshot {
    /// Whether the row counts came from an Eidos-capable producer or from a documented provisional
    /// conversion of an older snapshot.
    pub provenance: SnapshotProvenance,
    /// Hard-target totals. The verifier's bracket check operates on these.
    pub trace: TraceTotals,
    /// Advisory per-chiplet breakdown used by the solver for shaping.
    pub shape: TraceBreakdown,
}

/// One entry from the preserved Poseidon2 producer artifact.
///
/// This type exists to validate source coverage only. It deliberately does not implement
/// [`TraceSnapshot::shape`], so Poseidon2 rows cannot be fed to the Eidos solver accidentally.
#[derive(Debug, Clone)]
pub struct Poseidon2SourceSnapshot {
    /// Poseidon2 AIR-side row totals from the producer.
    pub trace: Poseidon2SourceTraceTotals,
    /// Per-chiplet breakdown from the producer.
    pub shape: TraceBreakdown,
}

/// AIR-side row totals in the preserved Poseidon2 producer schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Poseidon2SourceTraceTotals {
    /// System + decoder + stack trace length.
    pub core_rows: u64,
    /// Total chiplets trace length.
    pub chiplets_rows: u64,
    /// Poseidon2 permutation AIR trace length.
    pub poseidon2_permutation_rows: u64,
    /// Range-checker trace length.
    pub range_rows: u64,
}

/// Origin of a snapshot's trace-row counts.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotProvenance {
    ProducerMeasured,
    DerivedPendingProducerPort,
}

impl SnapshotProvenance {
    pub fn label(self) -> &'static str {
        match self {
            Self::ProducerMeasured => "producer_measured",
            Self::DerivedPendingProducerPort => "derived_pending_producer_port",
        }
    }

    pub fn is_provisional(self) -> bool {
        self == Self::DerivedPendingProducerPort
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

/// Per-chiplet row counts. Advisory only -- the solver uses these to size individual snippets so
/// the synthetic program stays representative (hasher work looks like hasher work, not a pile of
/// decoder-pad), but the verifier does not treat individual values as hard targets.
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

impl Poseidon2SourceTraceTotals {
    /// Padded bracket shared by the core and range traces in the Poseidon2 topology.
    pub fn padded_core_side(&self) -> u64 {
        self.core_rows.max(self.range_rows).next_power_of_two().max(MIN_TRACE_LEN)
    }

    /// Padded chiplets bracket in the Poseidon2 topology.
    pub fn padded_chiplets(&self) -> u64 {
        self.chiplets_rows.next_power_of_two().max(MIN_TRACE_LEN)
    }

    /// Padded Poseidon2 permutation bracket.
    pub fn padded_poseidon2_permutation(&self) -> u64 {
        self.poseidon2_permutation_rows.next_power_of_two().max(MIN_TRACE_LEN)
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
            let expected = shape.chiplets_sum();
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

impl Poseidon2SourceSnapshot {
    /// Load and validate the preserved Poseidon2 producer artifact.
    ///
    /// These rows are source evidence only; callers that need an executable Eidos target must use
    /// [`TraceSnapshot::load_all`] on an Eidos snapshot instead.
    pub fn load_all(path: impl AsRef<Path>) -> Result<Vec<(String, Self)>, SnapshotError> {
        let path_str = path.as_ref().display().to_string();
        let bytes = std::fs::read(path.as_ref())
            .map_err(|source| SnapshotError::Io { path: path_str, source })?;
        let raw: BTreeMap<String, RawPoseidon2SourceEntry> =
            serde_json::from_slice(&bytes).map_err(SnapshotError::Parse)?;

        let mut out = Vec::with_capacity(raw.len());
        for (key, entry) in raw {
            let trace = Poseidon2SourceTraceTotals {
                core_rows: entry.trace.core_rows,
                chiplets_rows: entry.trace.chiplets_rows,
                poseidon2_permutation_rows: entry.trace.poseidon2_permutation_rows,
                range_rows: entry.trace.range_rows,
            };
            if trace.poseidon2_permutation_rows == 0
                || !trace.poseidon2_permutation_rows.is_multiple_of(POSEIDON2_CYCLE_LEN)
            {
                return Err(SnapshotError::InvalidPoseidon2Rows {
                    scenario: key,
                    rows: trace.poseidon2_permutation_rows,
                    cycle_len: POSEIDON2_CYCLE_LEN,
                });
            }

            let shape = entry.trace.chiplets_shape;
            let expected = shape.chiplets_sum();
            if trace.chiplets_rows != expected {
                return Err(SnapshotError::InconsistentChipletsTotal {
                    scenario: key,
                    from_trace: trace.chiplets_rows,
                    from_shape: expected,
                });
            }
            out.push((key, Self { trace, shape }));
        }
        Ok(out)
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

#[derive(Deserialize)]
struct RawPoseidon2SourceEntry {
    trace: RawPoseidon2SourceTrace,
}

#[derive(Deserialize)]
struct RawPoseidon2SourceTrace {
    core_rows: u64,
    chiplets_rows: u64,
    poseidon2_permutation_rows: u64,
    range_rows: u64,
    chiplets_shape: TraceBreakdown,
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
    #[error(
        "snapshot inconsistency in scenario {scenario:?}: eidos_compression_rows = {rows} is not a multiple of {cycle_len}"
    )]
    InvalidEidosCompressionRows {
        scenario: String,
        rows: u64,
        cycle_len: u64,
    },
    #[error(
        "snapshot inconsistency in scenario {scenario:?}: poseidon2_permutation_rows = {rows} is not a positive multiple of {cycle_len}"
    )]
    InvalidPoseidon2Rows {
        scenario: String,
        rows: u64,
        cycle_len: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Provisional padded brackets for each checked-in derived scenario. Keyed by
    /// `(producer_stem, scenario_key)` since each file holds many scenarios. Replace this table
    /// when an Eidos-capable producer supplies measured row counts.
    struct ProvisionalScenarioExpectation {
        producer_stem: &'static str,
        scenario_key: &'static str,
        padded_core: u64,
        padded_and8: u64,
        padded_chiplets: u64,
        padded_eidos_compression: u64,
    }

    struct Poseidon2SourceExpectation {
        scenario_key: &'static str,
        padded_core_side: u64,
        padded_chiplets: u64,
        padded_poseidon2: u64,
    }

    const PROVISIONAL_SCENARIO_EXPECTATIONS: &[ProvisionalScenarioExpectation] = &[
        ProvisionalScenarioExpectation {
            producer_stem: "bench-tx",
            scenario_key: "consume single P2ID note",
            padded_core: 131_072,
            padded_and8: 65_536,
            padded_chiplets: 8_192,
            padded_eidos_compression: 131_072,
        },
        ProvisionalScenarioExpectation {
            producer_stem: "bench-tx",
            scenario_key: "consume two P2ID notes",
            padded_core: 131_072,
            padded_and8: 65_536,
            padded_chiplets: 8_192,
            padded_eidos_compression: 262_144,
        },
        ProvisionalScenarioExpectation {
            producer_stem: "bench-tx",
            scenario_key: "create single P2ID note",
            padded_core: 131_072,
            padded_and8: 65_536,
            padded_chiplets: 8_192,
            padded_eidos_compression: 131_072,
        },
        ProvisionalScenarioExpectation {
            producer_stem: "bench-tx",
            scenario_key: "consume CLAIM note (L1 to Miden)",
            padded_core: 65_536,
            padded_and8: 65_536,
            padded_chiplets: 16_384,
            padded_eidos_compression: 262_144,
        },
        ProvisionalScenarioExpectation {
            producer_stem: "bench-tx",
            scenario_key: "consume CLAIM note (L2 to Miden)",
            padded_core: 65_536,
            padded_and8: 65_536,
            padded_chiplets: 16_384,
            padded_eidos_compression: 262_144,
        },
        ProvisionalScenarioExpectation {
            producer_stem: "bench-tx",
            scenario_key: "consume B2AGG note (bridge-out)",
            padded_core: 262_144,
            padded_and8: 65_536,
            padded_chiplets: 65_536,
            padded_eidos_compression: 1_048_576,
        },
    ];

    const POSEIDON2_SOURCE_EXPECTATIONS: &[Poseidon2SourceExpectation] = &[
        Poseidon2SourceExpectation {
            scenario_key: "consume single P2ID note with Falcon signing",
            padded_core_side: 131_072,
            padded_chiplets: 16_384,
            padded_poseidon2: 65_536,
        },
        Poseidon2SourceExpectation {
            scenario_key: "consume single P2ID note with ECDSA signing",
            padded_core_side: 16_384,
            padded_chiplets: 8_192,
            padded_poseidon2: 32_768,
        },
        Poseidon2SourceExpectation {
            scenario_key: "consume two P2ID notes with Falcon signing",
            padded_core_side: 131_072,
            padded_chiplets: 16_384,
            padded_poseidon2: 65_536,
        },
        Poseidon2SourceExpectation {
            scenario_key: "consume two P2ID notes with ECDSA signing",
            padded_core_side: 16_384,
            padded_chiplets: 8_192,
            padded_poseidon2: 32_768,
        },
        Poseidon2SourceExpectation {
            scenario_key: "create single P2ID note with Falcon signing",
            padded_core_side: 131_072,
            padded_chiplets: 16_384,
            padded_poseidon2: 65_536,
        },
        Poseidon2SourceExpectation {
            scenario_key: "create single P2ID note with ECDSA signing",
            padded_core_side: 16_384,
            padded_chiplets: 8_192,
            padded_poseidon2: 32_768,
        },
    ];

    fn expectation_for(
        producer_stem: &str,
        scenario_key: &str,
    ) -> Option<&'static ProvisionalScenarioExpectation> {
        PROVISIONAL_SCENARIO_EXPECTATIONS.iter().find(|expected| {
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
            eidos_compression_rows: 300,
            byte_pair_lookup_rows: 100,
        };
        (totals, breakdown)
    }

    fn assert_eidos_snapshot_parse_error(
        fixture_name: &str,
        snapshot: &str,
        expected_message: &str,
    ) {
        let tmp = std::env::temp_dir()
            .join(format!("synthetic-bench-{fixture_name}-{}.json", std::process::id()));
        std::fs::write(&tmp, snapshot).unwrap();
        let err = TraceSnapshot::load_all(&tmp).expect_err("invalid schema must be rejected");
        let _ = std::fs::remove_file(&tmp);

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
                assert_eq!(
                    snap.provenance,
                    SnapshotProvenance::DerivedPendingProducerPort,
                    "{producer_stem}/{key}: checked-in snapshot must remain visibly provisional \
                     until replaced by an Eidos-capable producer measurement",
                );
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
                            snap.trace.padded_core(),
                            expected.padded_core,
                            "{producer_stem}/{key}: padded_core does not match expectation; \
                             replace the provisional snapshot or update \
                             PROVISIONAL_SCENARIO_EXPECTATIONS",
                        );
                        assert_eq!(
                            snap.trace.padded_and8_lookup(),
                            expected.padded_and8,
                            "{producer_stem}/{key}: padded_and8 does not match expectation; \
                             replace the provisional snapshot or update \
                             PROVISIONAL_SCENARIO_EXPECTATIONS",
                        );
                        assert_eq!(
                            snap.trace.padded_chiplets(),
                            expected.padded_chiplets,
                            "{producer_stem}/{key}: padded_chiplets does not match expectation; \
                             replace the provisional snapshot or update \
                             PROVISIONAL_SCENARIO_EXPECTATIONS",
                        );
                        assert_eq!(
                            snap.trace.padded_eidos_compression(),
                            expected.padded_eidos_compression,
                            "{producer_stem}/{key}: padded_eidos_compression does not match expectation; \
                             replace the provisional snapshot or update \
                             PROVISIONAL_SCENARIO_EXPECTATIONS",
                        );
                        assert_eq!(
                            snap.trace.byte_pair_lookup_rows, 65_536,
                            "{producer_stem}/{key}: fixed And8 table must contain 65,536 rows",
                        );
                        discovered.insert((producer_stem.clone(), key.clone()));
                    },
                    None => {
                        unexpected.insert((producer_stem.clone(), key.clone()));
                    },
                }
            }
        }

        let expected: BTreeSet<(String, String)> = PROVISIONAL_SCENARIO_EXPECTATIONS
            .iter()
            .map(|e| (e.producer_stem.to_string(), e.scenario_key.to_string()))
            .collect();
        let missing: BTreeSet<_> = expected.difference(&discovered).cloned().collect();
        assert!(
            unexpected.is_empty() && missing.is_empty(),
            "checked-in scenarios drifted from PROVISIONAL_SCENARIO_EXPECTATIONS in snapshot.rs:\n  \
             unexpected (in snapshots/ but not in the table -- add an entry): {unexpected:?}\n  \
             missing    (in the table but not in any snapshots/*.json -- refresh the snapshot or remove the entry): {missing:?}",
        );
    }

    #[test]
    fn poseidon2_source_snapshot_preserves_upstream_coverage() {
        use std::collections::{BTreeMap, BTreeSet};

        let source_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("snapshots/poseidon2-source/bench-tx.json");
        let scenarios = Poseidon2SourceSnapshot::load_all(&source_path)
            .unwrap_or_else(|err| panic!("load {}: {err}", source_path.display()));
        assert_eq!(scenarios.len(), 43, "the preserved upstream producer artifact drifted");

        let by_key: BTreeMap<&str, &Poseidon2SourceSnapshot> =
            scenarios.iter().map(|(key, snapshot)| (key.as_str(), snapshot)).collect();
        let source_keys: BTreeSet<&str> = by_key.keys().copied().collect();
        let selected_keys: BTreeSet<&str> = POSEIDON2_AUTH_SCENARIOS.iter().copied().collect();
        let expected_keys: BTreeSet<&str> =
            POSEIDON2_SOURCE_EXPECTATIONS.iter().map(|entry| entry.scenario_key).collect();
        assert_eq!(selected_keys, expected_keys, "auth scenario selection drifted");
        assert!(
            selected_keys.is_subset(&source_keys),
            "the preserved source is missing explicit Falcon/ECDSA fixture keys"
        );
        assert!(!source_keys.contains("consume single P2ID note"));
        assert!(!source_keys.contains("consume two P2ID notes"));
        assert!(!source_keys.contains("create single P2ID note"));

        for expected in POSEIDON2_SOURCE_EXPECTATIONS {
            let snapshot = by_key[expected.scenario_key];
            assert_eq!(snapshot.trace.padded_core_side(), expected.padded_core_side);
            assert_eq!(snapshot.trace.padded_chiplets(), expected.padded_chiplets);
            assert_eq!(snapshot.trace.padded_poseidon2_permutation(), expected.padded_poseidon2);
        }
    }

    #[test]
    fn eidos_loader_rejects_poseidon2_source_schema() {
        let source_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("snapshots/poseidon2-source/bench-tx.json");
        let err = TraceSnapshot::load_all(&source_path)
            .expect_err("Poseidon2 source rows must not be interpreted as Eidos targets");
        assert!(matches!(err, SnapshotError::Parse(_)));
    }

    #[test]
    fn executable_eidos_snapshot_requires_complete_schema() {
        let incomplete = r#"{
            "missing eidos fields": {
                "provenance": "producer_measured",
                "trace": {
                    "core_rows": 100,
                    "chiplets_rows": 33,
                    "byte_pair_lookup_rows": 50,
                    "chiplets_shape": {
                        "hasher_rows": 32,
                        "bitwise_rows": 0,
                        "memory_rows": 0,
                        "kernel_rom_rows": 0,
                        "ace_rows": 0
                    }
                }
            }
        }"#;
        let tmp = std::env::temp_dir().join("synthetic-bench-incomplete-schema.json");
        std::fs::write(&tmp, incomplete).unwrap();
        let err = TraceSnapshot::load_all(&tmp).expect_err("incomplete schema must be rejected");
        let _ = std::fs::remove_file(&tmp);
        assert!(matches!(err, SnapshotError::Parse(_)));
    }

    #[test]
    fn executable_eidos_snapshot_requires_provenance() {
        let missing_provenance = r#"{
            "missing provenance": {
                "trace": {
                    "core_rows": 100,
                    "chiplets_rows": 33,
                    "eidos_compression_rows": 64,
                    "byte_pair_lookup_rows": 65536,
                    "chiplets_shape": {
                        "hasher_rows": 32,
                        "bitwise_rows": 0,
                        "memory_rows": 0,
                        "kernel_rom_rows": 0,
                        "ace_rows": 0
                    }
                }
            }
        }"#;

        assert_eidos_snapshot_parse_error("missing-provenance", missing_provenance, "provenance");
    }

    #[test]
    fn executable_eidos_snapshot_requires_complete_chiplets_shape() {
        let missing_kernel_rom_rows = r#"{
            "missing kernel ROM rows": {
                "provenance": "producer_measured",
                "trace": {
                    "core_rows": 100,
                    "chiplets_rows": 33,
                    "eidos_compression_rows": 64,
                    "byte_pair_lookup_rows": 65536,
                    "chiplets_shape": {
                        "hasher_rows": 32,
                        "bitwise_rows": 0,
                        "memory_rows": 0,
                        "ace_rows": 0
                    }
                }
            }
        }"#;

        assert_eidos_snapshot_parse_error(
            "missing-kernel-rom-rows",
            missing_kernel_rom_rows,
            "kernel_rom_rows",
        );
    }

    #[test]
    fn executable_eidos_snapshot_rejects_unknown_chiplets_shape_fields() {
        let unknown_shape_field = r#"{
            "unknown chiplet shape field": {
                "provenance": "producer_measured",
                "trace": {
                    "core_rows": 100,
                    "chiplets_rows": 33,
                    "eidos_compression_rows": 64,
                    "byte_pair_lookup_rows": 65536,
                    "chiplets_shape": {
                        "hasher_rows": 32,
                        "bitwise_rows": 0,
                        "memory_rows": 0,
                        "kernel_rom_rows": 0,
                        "ace_rows": 0,
                        "unexpected_rows": 0
                    }
                }
            }
        }"#;

        assert_eidos_snapshot_parse_error(
            "unknown-chiplets-shape-field",
            unknown_shape_field,
            "unexpected_rows",
        );
    }

    #[test]
    fn executable_eidos_snapshot_rejects_non_eidos_trace_fields() {
        for field in ["blakeg_compression_rows", "range_rows"] {
            let snapshot = format!(
                r#"{{
                    "invalid field": {{
                        "provenance": "producer_measured",
                        "trace": {{
                            "core_rows": 100,
                            "chiplets_rows": 33,
                            "eidos_compression_rows": 64,
                            "byte_pair_lookup_rows": 65536,
                            "{field}": 64,
                            "chiplets_shape": {{
                                "hasher_rows": 32,
                                "bitwise_rows": 0,
                                "memory_rows": 0,
                                "kernel_rom_rows": 0,
                                "ace_rows": 0
                            }}
                        }}
                    }}
                }}"#,
            );
            let tmp = std::env::temp_dir().join(format!("synthetic-bench-{field}.json"));
            std::fs::write(&tmp, snapshot).unwrap();
            let err = TraceSnapshot::load_all(&tmp).expect_err("unknown field must be rejected");
            let _ = std::fs::remove_file(&tmp);
            assert!(matches!(err, SnapshotError::Parse(_)), "unexpected error for {field}: {err}");
        }
    }

    #[test]
    fn loads_explicit_provisional_provenance() {
        let provisional = r#"{
            "derived": {
                "provenance": "derived_pending_producer_port",
                "trace": {
                    "core_rows": 100,
                    "chiplets_rows": 33,
                    "eidos_compression_rows": 64,
                    "byte_pair_lookup_rows": 65536,
                    "chiplets_shape": {
                        "hasher_rows": 32,
                        "bitwise_rows": 0,
                        "memory_rows": 0,
                        "kernel_rom_rows": 0,
                        "ace_rows": 0
                    }
                }
            }
        }"#;
        let tmp = std::env::temp_dir().join("synthetic-bench-provenance.json");
        std::fs::write(&tmp, provisional).unwrap();
        let scenarios = TraceSnapshot::load_all(&tmp).expect("load provisional snapshot");
        let _ = std::fs::remove_file(&tmp);
        assert_eq!(scenarios[0].1.provenance, SnapshotProvenance::DerivedPendingProducerPort);
        assert!(scenarios[0].1.provenance.is_provisional());
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
                    "byte_pair_lookup_rows": 0,
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
        let tmp = std::env::temp_dir().join("synthetic-bench-chiplets-mismatch.json");
        std::fs::write(&tmp, mismatched).unwrap();
        let err = TraceSnapshot::load_all(&tmp).expect_err("expected inconsistency rejection");
        let _ = std::fs::remove_file(&tmp);
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
                    "byte_pair_lookup_rows": 0,
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
        let tmp = std::env::temp_dir().join("synthetic-bench-eidos_compression-misaligned.json");
        std::fs::write(&tmp, misaligned).unwrap();
        let err =
            TraceSnapshot::load_all(&tmp).expect_err("expected EidosCompression row rejection");
        let _ = std::fs::remove_file(&tmp);
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
        let tmp = std::env::temp_dir().join("synthetic-bench-realistic.json");
        std::fs::write(&tmp, realistic).unwrap();
        let scenarios = TraceSnapshot::load_all(&tmp).expect("load realistic snapshot");
        let _ = std::fs::remove_file(&tmp);
        assert_eq!(scenarios.len(), 1);
        let (key, snap) = &scenarios[0];
        assert_eq!(key, "consume single P2ID note");
        assert_eq!(snap.trace.core_rows, 77_699);
        assert_eq!(snap.shape.hasher_rows, 3_761);
        assert_eq!(snap.trace.eidos_compression_rows, 120_352);
    }
}
