//! Benchmarks for per-event overhead and host-call fuel calibration.
//!
//! Four measurements matter:
//!
//! - `call_empty_handler`: the fixed cost of one event call (fresh store, instantiation, one export
//!   invocation) — the price of the stateless instantiate-per-call design. Every fixture exports
//!   its linear memory, which the loader requires, so this number also includes the allocation and
//!   zeroing of one 64 KiB page per call. Subtract that term before you read it as the cost of the
//!   call machinery alone.
//! - `guest_arith_100k_iters`: pure guest execution with a known instruction count, giving the
//!   wall-clock cost of one fuel unit.
//! - `host_extend_4096_felts` / `host_stack_read_4096_felts`: one host call moving 4096 field
//!   elements, giving the wall-clock cost per felt moved.
//! - `host_poseidon2_merge` / `host_keccak256_4096_bytes`: one host call computing a hash, giving
//!   the wall-clock cost of one permutation and of one hashed byte.
//! - `host_mem_read_4096_felts_populated`: one host call reading 4096 memory elements out of a
//!   populated VM memory, giving the wall-clock cost of one map probe. Read it against
//!   `host_stack_read_4096_felts`, which moves the same number of felts without a probe. This case
//!   calibrates `FUEL_PER_MAP_PROBE`.
//!
//! The ratio (time per unit of host work) / (time per guest instruction) calibrates the fuel
//! charges in `src/host.rs`: a charge should make host-side work cost roughly as much fuel as the
//! guest spends to cause it.

use std::{sync::Arc, time::Duration};

use criterion::{Criterion, criterion_group, criterion_main};
use miden_assembly::{Assembler, DefaultSourceManager};
use miden_event_handler_abi::ABI_VERSION;
use miden_processor::{DefaultHost, FastProcessor, StackInputs, event::EventName};
use miden_wasm_event_handlers::{WasmHandlerLimits, WasmHandlerModule};

const EVENT: EventName = EventName::new("bench::wasm::handler");

/// The number of memory words the populated-memory fixture writes.
///
/// VM memory is a `BTreeMap` keyed by `(context, word address)`, so a probe costs more the more
/// words the map holds. 65536 words is far past the working set of a small program, so the map
/// the handler probes is as deep as a heavy program makes it.
const MEMORY_WORDS: u32 = 65536;

/// The empty handler: measures the fixed per-call cost.
const EMPTY_WAT: &str = r#"(module
  (memory (export "memory") 1)
  (func (export "handler")))"#;

/// A counting loop with 100k iterations of ~4 instructions each.
const ARITH_WAT: &str = r#"(module
  (memory (export "memory") 1)
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

/// One host call reading 4096 memory elements of the current context into guest memory.
///
/// Each element is one probe of the VM memory map, so this case calibrates
/// `FUEL_PER_MAP_PROBE` in `src/host.rs`: subtract `host_stack_read_4096_felts`, which moves the
/// same 4096 felts with no probe, and divide the remainder by 4096.
///
/// The read is one contiguous range, so its probes share cache lines and tree nodes. The result
/// is therefore the cheap end of the probe cost, while the 250-fuel charge prices the expensive
/// end (a scattered probe of a large map, ~200 ns at ~0.8 ns per fuel unit).
const MEM_READ_WAT: &str = r#"(module
  (import "miden:event/v1" "mem_read" (func $mem_read (param i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "handler")
    (drop (call $mem_read (i32.const 0) (i32.const 0) (i32.const 4096)))))"#;

/// Returns a processor whose memory holds [`MEMORY_WORDS`] written words.
///
/// Only a program writes VM memory, so a MASM loop stores one element per word. The program runs
/// once, in bench setup; the measured handler then probes the map the program left behind.
fn processor_with_populated_memory() -> FastProcessor {
    let source = format!(
        r#"
        begin
            push.0
            push.1
            while.true
                push.7
                dup.1
                mem_store
                add.4
                dup
                neq.{limit}
            end
            drop
        end"#,
        limit = MEMORY_WORDS * 4,
    );
    let program = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .assemble_program("bench_memory", source)
        .expect("the bench program assembles")
        .unwrap_program();

    let mut processor = FastProcessor::new(StackInputs::default());
    processor
        .execute_mut_sync(&program, &mut DefaultHost::default())
        .expect("the bench program populates the memory");
    processor
}

fn bench_handlers(c: &mut Criterion) {
    let mut group = c.benchmark_group("wasm_event_handlers");
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(2));

    let processor = FastProcessor::new(StackInputs::default());
    let populated = processor_with_populated_memory();

    for (name, wat_src, processor) in [
        ("call_empty_handler", EMPTY_WAT, &processor),
        ("guest_arith_100k_iters", ARITH_WAT, &processor),
        ("host_extend_4096_felts", EXTEND_WAT, &processor),
        ("host_stack_read_4096_felts", STACK_READ_WAT, &processor),
        ("host_poseidon2_merge", POSEIDON2_MERGE_WAT, &processor),
        ("host_keccak256_4096_bytes", KECCAK256_WAT, &processor),
        ("host_sha256_4096_bytes", SHA256_WAT, &processor),
        ("host_sha512_4096_bytes", SHA512_WAT, &processor),
        ("host_blake3_4096_bytes", BLAKE3_WAT, &processor),
        ("host_mem_read_4096_felts_populated", MEM_READ_WAT, &populated),
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
