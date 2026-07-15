//! Sweeps the precompile-prover chiplet stack over a grid of Keccak /
//! ECDSA workload sizes, driving real proving runs and letting the
//! `DUMP_TRACE_HEIGHTS`-gated probes in the trace-gen code (see
//! `precompiles-prover/src/{hash,transcript,uint,ec}/**/trace.rs` and
//! `precompiles-prover/src/session/mod.rs`) report each chiplet's real
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
//! `heights.log` is a line-oriented log with three record kinds, meant to
//! be fed to `parse_trace_heights.py`:
//!
//! ```text
//! COMBO keccaks=<k> ecdsas=<e>
//! REAL_HEIGHT <ChipletName> <rows>
//! PADDED_HEIGHT <ChipletName> <rows>
//! ```
//!
//! Two chiplets are built from a pair of sub-traces sharing one row
//! range, so their real height is the `max` of two probes rather than a
//! single number:
//! - `ChunkNode` real = `max(ChunkNode_chunk, ChunkNode_node)`.
//! - `UintStoreMul` real = `max(UintStoreMul_mul, UintStoreMul_store)`.
//!
//! `BytePairLut`'s trace is a fixed `TRACE_HEIGHT` (`1 << 16` rows, see
//! `primitives/byte_pair_lut.rs`) regardless of workload, so it has no
//! `REAL_HEIGHT` probe — its real row count always equals its padded one.

use miden_vm::HashFunction;
use miden_vm_precompiles_bench::{
    PrecompileFixture, input_generation::PrecompileWorkload, prove_once_with_hash,
};

/// Keccak call counts to sweep. Edit freely.
const KECCAK_LEVELS: &[usize] = &[16, 64, 256, 512, 1024];
/// ECDSA verification counts to sweep. Edit freely.
const ECDSA_LEVELS: &[usize] = &[1, 10, 25, 50, 100];

fn main() {
    // SAFETY: single-threaded at this point in `main`, before any fixture
    // generation or proving spawns worker threads.
    unsafe {
        std::env::set_var("DUMP_TRACE_HEIGHTS", "1");
    }

    for &keccaks in KECCAK_LEVELS {
        for &ecdsas in ECDSA_LEVELS {
            eprintln!("COMBO keccaks={keccaks} ecdsas={ecdsas}");
            let workload = PrecompileWorkload { keccaks, ecdsas };
            let fixture = PrecompileFixture::generate(workload);
            let _ = prove_once_with_hash(&fixture, HashFunction::Blake3_256);
        }
    }
}
