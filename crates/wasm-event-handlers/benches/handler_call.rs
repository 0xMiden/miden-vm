//! Benchmarks for per-event overhead and host-call fuel calibration.
//!
//! Three measurements matter:
//!
//! - `call_empty_handler`: the fixed cost of one event call (fresh store, instantiation, one export
//!   invocation) — the price of the stateless instantiate-per-call design.
//! - `guest_arith_100k_iters`: pure guest execution with a known instruction count, giving the
//!   wall-clock cost of one fuel unit.
//! - `host_extend_4096_felts` / `host_stack_read_4096_felts`: one host call moving 4096 field
//!   elements, giving the wall-clock cost per felt moved.
//! - `host_poseidon2_merge` / `host_keccak256_4096_bytes`: one host call computing a hash, giving
//!   the wall-clock cost of one permutation and of one hashed byte.
//!
//! The ratio (time per unit of host work) / (time per guest instruction) calibrates the fuel
//! charges in `src/host.rs`: a charge should make host-side work cost roughly as much fuel as the
//! guest spends to cause it.

use std::{sync::Arc, time::Duration};

use criterion::{Criterion, criterion_group, criterion_main};
use miden_event_handler_abi::ABI_VERSION;
use miden_processor::{FastProcessor, StackInputs, event::EventName};
use miden_wasm_event_handlers::{WasmHandlerLimits, WasmHandlerModule};

const EVENT: EventName = EventName::new("bench::wasm::handler");

/// The empty handler: measures the fixed per-call cost.
const EMPTY_WAT: &str = r#"(module (func (export "handler")))"#;

/// A counting loop with 100k iterations of ~4 instructions each.
const ARITH_WAT: &str = r#"(module
  (func (export "handler")
    (local $i i64)
    (local.set $i (i64.const 100000))
    (loop $l
      (local.set $i (i64.sub (local.get $i) (i64.const 1)))
      (br_if $l (i64.ne (local.get $i) (i64.const 0))))))"#;

/// One host call buffering 4096 (zero, hence canonical) felts from guest memory.
const EXTEND_WAT: &str = r#"(module
  (import "miden:event/v1" "adv_stack_extend" (func $ext (param i32 i32)))
  (memory (export "memory") 1)
  (func (export "handler")
    (call $ext (i32.const 0) (i32.const 4096))))"#;

/// One host call batch-reading 4096 operand-stack elements into guest memory.
const STACK_READ_WAT: &str = r#"(module
  (import "miden:event/v1" "stack_read" (func $read (param i32 i32 i32)))
  (memory (export "memory") 1)
  (func (export "handler")
    (call $read (i32.const 0) (i32.const 0) (i32.const 4096))))"#;

/// One host call merging two words; fresh guest memory is zero, and zero is canonical.
const POSEIDON2_MERGE_WAT: &str = r#"(module
  (import "miden:event/v1" "poseidon2_merge" (func $merge (param i32 i64 i32)))
  (memory (export "memory") 1)
  (func (export "handler")
    (call $merge (i32.const 0) (i64.const 0) (i32.const 64))))"#;

/// One host call hashing 4096 bytes of guest memory with Keccak-256.
const KECCAK256_WAT: &str = r#"(module
  (import "miden:event/v1" "keccak256" (func $keccak (param i32 i32 i32)))
  (memory (export "memory") 1)
  (func (export "handler")
    (call $keccak (i32.const 0) (i32.const 4096) (i32.const 4096))))"#;

/// One host call hashing 4096 bytes of guest memory with SHA-256.
const SHA256_WAT: &str = r#"(module
  (import "miden:event/v1" "sha256" (func $sha256 (param i32 i32 i32)))
  (memory (export "memory") 1)
  (func (export "handler")
    (call $sha256 (i32.const 0) (i32.const 4096) (i32.const 4096))))"#;

/// One host call hashing 4096 bytes of guest memory with SHA-512.
const SHA512_WAT: &str = r#"(module
  (import "miden:event/v1" "sha512" (func $sha512 (param i32 i32 i32)))
  (memory (export "memory") 1)
  (func (export "handler")
    (call $sha512 (i32.const 0) (i32.const 4096) (i32.const 4096))))"#;

/// One host call hashing 4096 bytes of guest memory with BLAKE3.
const BLAKE3_WAT: &str = r#"(module
  (import "miden:event/v1" "blake3" (func $blake3 (param i32 i32 i32)))
  (memory (export "memory") 1)
  (func (export "handler")
    (call $blake3 (i32.const 0) (i32.const 4096) (i32.const 4096))))"#;

fn bench_handlers(c: &mut Criterion) {
    let mut group = c.benchmark_group("wasm_event_handlers");
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(2));

    let processor = FastProcessor::new(StackInputs::default());

    for (name, wat_src) in [
        ("call_empty_handler", EMPTY_WAT),
        ("guest_arith_100k_iters", ARITH_WAT),
        ("host_extend_4096_felts", EXTEND_WAT),
        ("host_stack_read_4096_felts", STACK_READ_WAT),
        ("host_poseidon2_merge", POSEIDON2_MERGE_WAT),
        ("host_keccak256_4096_bytes", KECCAK256_WAT),
        ("host_sha256_4096_bytes", SHA256_WAT),
        ("host_sha512_4096_bytes", SHA512_WAT),
        ("host_blake3_4096_bytes", BLAKE3_WAT),
    ] {
        let wasm = wat::parse_str(wat_src).expect("bench WAT parses");
        let module = Arc::new(
            WasmHandlerModule::new(
                &wasm,
                ABI_VERSION,
                vec![(EVENT, "handler".to_string())],
                WasmHandlerLimits::default(),
            )
            .expect("bench module loads"),
        );
        let handlers = module.handlers();
        let (_, handler) = handlers.first().expect("one handler");

        group.bench_function(name, |bencher| {
            bencher.iter(|| {
                let state = processor.state();
                std::hint::black_box(handler.on_event(&state).expect("bench handler succeeds"))
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_handlers);
criterion_main!(benches);
