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
//!
//! The ratio (time per felt moved) / (time per guest instruction) calibrates `FUEL_PER_FELT` in
//! `src/host.rs`: the charge should make host-moved data cost roughly as much fuel as the guest
//! spends to cause it.

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
