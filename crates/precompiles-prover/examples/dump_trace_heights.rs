//! Sweeps the precompile-prover chiplet stack over a grid of Keccak /
//! ECDSA workload sizes, driving real proving runs and letting the
//! `DUMP_TRACE_HEIGHTS`-gated probes in the trace-gen code (see
//! `crates/precompiles-prover/src/{hash,transcript,uint,ec}/**/trace.rs` and
//! `crates/precompiles-prover/src/session/mod.rs`) report each chiplet's real
//! (pre-padding) and padded row counts to stderr.
//!
//! Run with:
//!
//! ```sh
//! DUMP_TRACE_HEIGHTS=1 cargo run --release \
//!     --example dump_trace_heights -p miden-precompiles-prover \
//!     2> heights.log
//! ```
//!
//! `heights.log` is a line-oriented log with four record kinds, meant to
//! be fed to `parse_trace_heights.py`:
//!
//! ```text
//! COMBO keccaks=<k> ecdsas=<e>
//! REAL_HEIGHT <ChipletName> <rows>
//! PADDED_HEIGHT <ChipletName> <rows>
//! PROVE_MS <milliseconds>
//! ```
//!
//! `PROVE_MS` times only the `prove_once_with_hash` call (wall-clock,
//! single sample, no warm-up) — a rough per-combo comparison point, not a
//! criterion-grade benchmark.
//!
//! Three chiplets are merged AIRs built from multiple sub-traces sharing
//! one row range, so their real height is the `max` of several probes
//! rather than a single number:
//! - `ChunkNodeSponge` real = `max(ChunkNodeSponge_chunk, ChunkNodeSponge_node,
//!   ChunkNodeSponge_sponge)`.
//! - `UintStoreMul` real = `max(UintStoreMul_store, UintStoreMul_mul)`.
//! - `EcPointStoreGroups` real = `max(EcPointStoreGroups_points, EcPointStoreGroups_groups)`.
//!
//! `BytePairLut`'s trace is a fixed `TRACE_HEIGHT` regardless of workload,
//! so it has no `REAL_HEIGHT` probe — its real row count always equals its
//! padded one.
//!
//! The full grid is `KECCAK_LEVELS` × `ECDSA_LEVELS`; pairs already listed
//! in `ALREADY_MEASURED` are skipped so a run only fills gaps left by
//! prior sweeps.

#[path = "../../precompiles/benches/precompiles_bench/support.rs"]
#[allow(dead_code, unused_imports, reason = "reusing the shared bench fixture module as-is")]
mod support;

use miden_vm::HashFunction;
use support::{PrecompileFixture, input_generation::PrecompileWorkload, prove_once_with_hash};

/// Keccak call counts to sweep. Edit freely.
const KECCAK_LEVELS: &[usize] = &[10, 16, 50, 64, 100, 200, 256, 300, 512, 1000, 1024];
/// ECDSA verification counts to sweep. Edit freely.
const ECDSA_LEVELS: &[usize] = &[1, 4, 8, 10, 16, 25, 32, 50, 64, 100, 128];

/// `(keccaks, ecdsas)` pairs already measured in prior runs — skipped here
/// so this sweep only fills the gaps in the full `KECCAK_LEVELS` ×
/// `ECDSA_LEVELS` grid. Clear this list (or remove pairs from it) to
/// re-measure combos that were already covered.
const ALREADY_MEASURED: &[(usize, usize)] = &[
    (10, 4),
    (10, 8),
    (10, 16),
    (10, 32),
    (10, 64),
    (16, 1),
    (16, 10),
    (16, 25),
    (16, 50),
    (16, 100),
    (50, 4),
    (50, 8),
    (50, 16),
    (50, 32),
    (50, 64),
    (64, 1),
    (64, 10),
    (64, 25),
    (64, 50),
    (64, 100),
    (100, 4),
    (100, 8),
    (100, 16),
    (100, 32),
    (100, 64),
    (200, 4),
    (200, 8),
    (200, 16),
    (200, 32),
    (200, 64),
    (256, 1),
    (256, 10),
    (256, 25),
    (256, 50),
    (256, 100),
    (300, 4),
    (300, 8),
    (300, 16),
    (300, 32),
    (300, 64),
    (512, 1),
    (512, 10),
    (512, 25),
    (512, 50),
    (512, 100),
    (1024, 1),
    (1024, 10),
    (1024, 25),
    (1024, 50),
    (1024, 100),
];

fn main() {
    // SAFETY: single-threaded at this point in `main`, before any fixture
    // generation or proving spawns worker threads.
    unsafe {
        std::env::set_var("DUMP_TRACE_HEIGHTS", "1");
    }

    for &keccaks in KECCAK_LEVELS {
        for &ecdsas in ECDSA_LEVELS {
            if ALREADY_MEASURED.contains(&(keccaks, ecdsas)) {
                continue;
            }
            eprintln!("COMBO keccaks={keccaks} ecdsas={ecdsas}");
            let workload = PrecompileWorkload { keccaks, ecdsas };
            let fixture = PrecompileFixture::generate(workload);
            let started_at = std::time::Instant::now();
            let _ = prove_once_with_hash(&fixture, HashFunction::Eidos);
            let elapsed_ms = started_at.elapsed().as_millis();
            eprintln!("PROVE_MS {elapsed_ms}");
        }
    }
}
