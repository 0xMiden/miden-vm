//! WAT-fixture tests for the Wasm event handler host adapter.
//!
//! The tests build small handler modules from WAT text, run them against a real
//! [`FastProcessor`] state, and check the buffered mutations or the reported errors. No wasm32
//! toolchain is involved.

use std::{string::String, sync::Arc, vec::Vec};

use miden_event_handler_abi::{ABI_VERSION, Status};
use miden_processor::{
    DefaultHost, FastProcessor, Felt, StackInputs, Word,
    advice::{AdviceInputs, AdviceMap, AdviceMutation, AdviceStack},
    crypto::{hash::Poseidon2, merkle::InnerNodeInfo},
    event::EventName,
};
use miden_wasm_event_handlers::{WasmHandlerLimits, WasmHandlerLoadError, WasmHandlerModule};

// FIXTURE HELPERS
// ================================================================================================

const EVENT: EventName = EventName::new("test::wasm::handler");

/// Imports for every host function, so each fixture also checks that all signatures resolve.
const IMPORTS: &str = r#"
  (import "miden:event/v1" "stack_depth" (func $stack_depth (result i32)))
  (import "miden:event/v1" "stack_get" (func $stack_get (param i32) (result i64)))
  (import "miden:event/v1" "stack_read" (func $stack_read (param i32 i32 i32)))
  (import "miden:event/v1" "clk" (func $clk (result i64)))
  (import "miden:event/v1" "ctx" (func $ctx (result i32)))
  (import "miden:event/v1" "mem_get" (func $mem_get (param i32 i32) (result i32)))
  (import "miden:event/v1" "mem_read" (func $mem_read (param i32 i32 i32) (result i32)))
  (import "miden:event/v1" "adv_stack_len" (func $adv_stack_len (result i32)))
  (import "miden:event/v1" "adv_stack_read" (func $adv_stack_read (param i32 i32 i32) (result i32)))
  (import "miden:event/v1" "adv_map_value_len" (func $adv_map_value_len (param i32 i32) (result i32)))
  (import "miden:event/v1" "adv_map_value_read" (func $adv_map_value_read (param i32 i32 i32) (result i32)))
  (import "miden:event/v1" "adv_stack_extend" (func $adv_stack_extend (param i32 i32)))
  (import "miden:event/v1" "adv_map_insert" (func $adv_map_insert (param i32 i32 i32)))
  (import "miden:event/v1" "merkle_store_extend" (func $merkle_store_extend (param i32 i32)))
  (import "miden:event/v1" "fail" (func $fail (param i32 i32)))
"#;

/// Builds a fixture module with extra module-level items (e.g. data segments) and a handler
/// body.
fn fixture_with(items: &str, body: &str) -> String {
    format!(
        "(module {IMPORTS} (memory (export \"memory\") 1) {items} \
         (func (export \"handler\") {body}))"
    )
}

/// Builds a fixture module with only a handler body.
fn fixture(body: &str) -> String {
    fixture_with("", body)
}

/// Loads a fixture with the default single-event manifest and default limits.
fn load(wat_src: &str) -> Arc<WasmHandlerModule> {
    load_with_limits(wat_src, WasmHandlerLimits::default())
}

/// Loads a fixture with the default single-event manifest and the given limits.
fn load_with_limits(wat_src: &str, limits: WasmHandlerLimits) -> Arc<WasmHandlerModule> {
    let wasm = wat::parse_str(wat_src).expect("fixture WAT must parse");
    let manifest = vec![(EVENT, "handler".to_string())];
    Arc::new(WasmHandlerModule::new(&wasm, ABI_VERSION, manifest, limits).expect("fixture loads"))
}

/// Loads a fixture with an explicit manifest and returns the load result.
fn try_load(
    wat_src: &str,
    manifest: Vec<(EventName, String)>,
) -> Result<WasmHandlerModule, WasmHandlerLoadError> {
    let wasm = wat::parse_str(wat_src).expect("fixture WAT must parse");
    WasmHandlerModule::new(&wasm, ABI_VERSION, manifest, WasmHandlerLimits::default())
}

/// Runs the fixture's `handler` export against the processor state; errors as display strings.
fn run(
    module: &Arc<WasmHandlerModule>,
    processor: &FastProcessor,
) -> Result<Vec<AdviceMutation>, String> {
    let handlers = module.handlers();
    let (_, handler) = handlers
        .iter()
        .find(|(event, _)| *event == EVENT)
        .expect("event is in the manifest");
    handler.on_event(&processor.state()).map_err(|err| err.to_string())
}

fn processor() -> FastProcessor {
    FastProcessor::new(StackInputs::default())
}

fn processor_with_stack(values: &[u64]) -> FastProcessor {
    let felts: Vec<Felt> = values.iter().map(|value| Felt::new_unchecked(*value)).collect();
    FastProcessor::new(StackInputs::new(&felts).expect("valid stack inputs"))
}

/// Encodes field-element values as the escaped little-endian bytes of a WAT data segment.
fn data_bytes(values: &[u64]) -> String {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .map(|byte| format!("\\{byte:02x}"))
        .collect()
}

// QUERY AND MUTATION TESTS
// ================================================================================================

#[test]
fn stack_item_echoed_to_advice_stack() {
    let wat_src = fixture(
        "(i64.store (i32.const 0) (call $stack_get (i32.const 1)))
         (call $adv_stack_extend (i32.const 0) (i32.const 1))",
    );
    let module = load(&wat_src);
    let processor = processor_with_stack(&[5, 7]);
    let expected = processor.state().get_stack_item(1);

    let mutations = run(&module, &processor).expect("handler succeeds");
    assert_eq!(mutations, vec![AdviceMutation::extend_advice_stack_with([expected])]);
}

#[test]
fn stack_word_inserted_into_advice_map() {
    let wat_src = fixture(
        "(call $stack_read (i32.const 1) (i32.const 0) (i32.const 4))
         (call $adv_map_insert (i32.const 0) (i32.const 0) (i32.const 4))",
    );
    let module = load(&wat_src);
    let processor = processor_with_stack(&[1, 2, 3, 4, 5]);
    let word = processor.state().get_stack_word(1);

    let mutations = run(&module, &processor).expect("handler succeeds");
    let mut expected = AdviceMap::default();
    expected.insert(word, vec![word[0], word[1], word[2], word[3]]);
    assert_eq!(mutations, vec![AdviceMutation::extend_map(expected)]);
}

#[test]
fn stack_read_batches_elements() {
    // Read three elements starting below the top, including positions past the stack depth.
    let wat_src = fixture(
        "(call $stack_read (i32.const 1) (i32.const 0) (i32.const 3))
         (call $adv_stack_extend (i32.const 0) (i32.const 3))",
    );
    let module = load(&wat_src);
    let processor = processor_with_stack(&[9, 8]);
    let state = processor.state();
    let expected = [state.get_stack_item(1), state.get_stack_item(2), state.get_stack_item(3)];

    let mutations = run(&module, &processor).expect("handler succeeds");
    assert_eq!(mutations, vec![AdviceMutation::extend_advice_stack_with(expected)]);
}

#[test]
fn mem_read_reports_uninit_and_out_of_bounds() {
    // Fresh memory: a batch over unwritten cells is Uninit; a range past the u32 address space
    // is OutOfBounds.
    let wat_src = fixture(
        "(i64.store (i32.const 0)
             (i64.extend_i32_u (call $mem_read (i32.const 0) (i32.const 16) (i32.const 2))))
         (i64.store (i32.const 8)
             (i64.extend_i32_u (call $mem_read (i32.const -1) (i32.const 16) (i32.const 2))))
         (call $adv_stack_extend (i32.const 0) (i32.const 2))",
    );
    let module = load(&wat_src);

    let mutations = run(&module, &processor()).expect("handler succeeds");
    let expected = [
        Felt::new_unchecked(Status::Uninit.as_raw() as u64),
        Felt::new_unchecked(Status::OutOfBounds.as_raw() as u64),
    ];
    assert_eq!(mutations, vec![AdviceMutation::extend_advice_stack_with(expected)]);
}

#[test]
fn clk_ctx_and_depth_are_visible() {
    let wat_src = fixture(
        "(i64.store (i32.const 0) (call $clk))
         (i64.store (i32.const 8) (i64.extend_i32_u (call $ctx)))
         (i64.store (i32.const 16) (i64.extend_i32_u (call $stack_depth)))
         (call $adv_stack_extend (i32.const 0) (i32.const 3))",
    );
    let module = load(&wat_src);
    let processor = processor();
    let state = processor.state();
    let expected = [
        Felt::new_unchecked(u64::from(state.clock())),
        Felt::new_unchecked(u64::from(u32::from(state.ctx()))),
        Felt::new_unchecked(u64::from(state.stack_depth())),
    ];

    let mutations = run(&module, &processor).expect("handler succeeds");
    assert_eq!(mutations, vec![AdviceMutation::extend_advice_stack_with(expected)]);
}

#[test]
fn mem_get_reports_uninitialized_memory() {
    let wat_src = fixture(
        "(i64.store (i32.const 0)
             (i64.extend_i32_u (call $mem_get (i32.const 0) (i32.const 8))))
         (call $adv_stack_extend (i32.const 0) (i32.const 1))",
    );
    let module = load(&wat_src);
    let processor = processor();

    let mutations = run(&module, &processor).expect("handler succeeds");
    let status = Felt::new_unchecked(Status::Uninit.as_raw() as u64);
    assert_eq!(mutations, vec![AdviceMutation::extend_advice_stack_with([status])]);
}

#[test]
fn advice_stack_roundtrip() {
    let wat_src = fixture(
        "(local $len i32)
         (local.set $len (call $adv_stack_len))
         (drop (call $adv_stack_read (i32.const 0) (i32.const 0) (local.get $len)))
         (call $adv_stack_extend (i32.const 0) (local.get $len))",
    );
    let module = load(&wat_src);
    let advice_stack: AdviceStack = [7u64, 8, 9].into_iter().map(Felt::new_unchecked).collect();
    let processor = FastProcessor::new(StackInputs::default())
        .with_advice(AdviceInputs::default().with_stack(advice_stack))
        .expect("advice inputs fit");
    let expected = processor.state().advice_provider().stack();
    assert_eq!(expected.len(), 3);

    let mutations = run(&module, &processor).expect("handler succeeds");
    assert_eq!(mutations, vec![AdviceMutation::extend_advice_stack_with(expected)]);
}

#[test]
fn advice_stack_read_out_of_bounds_status() {
    let wat_src = fixture(
        "(i64.store (i32.const 0)
             (i64.extend_i32_u
                 (call $adv_stack_read
                     (i32.const 0)
                     (i32.const 8)
                     (i32.add (call $adv_stack_len) (i32.const 1)))))
         (call $adv_stack_extend (i32.const 0) (i32.const 1))",
    );
    let module = load(&wat_src);
    let processor = processor();

    let mutations = run(&module, &processor).expect("handler succeeds");
    let status = Felt::new_unchecked(Status::OutOfBounds.as_raw() as u64);
    assert_eq!(mutations, vec![AdviceMutation::extend_advice_stack_with([status])]);
}

#[test]
fn advice_map_value_read_after_len() {
    let key_values = [1u64, 2, 3, 4];
    let key = Word::new([
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
    ]);
    let values: Vec<Felt> = [10u64, 11, 12].into_iter().map(Felt::new_unchecked).collect();

    // The advice-map key sits in a data segment at offset 0.
    let items = format!("(data (i32.const 0) \"{}\")", data_bytes(&key_values));
    let wat_src = fixture_with(
        &items,
        "(drop (call $adv_map_value_len (i32.const 0) (i32.const 32)))
         (drop (call $adv_map_value_read (i32.const 0) (i32.const 48) (i32.const 8)))
         (call $adv_stack_extend (i32.const 48) (i32.const 3))",
    );
    let module = load(&wat_src);
    let processor = FastProcessor::new(StackInputs::default())
        .with_advice(AdviceInputs::default().with_map([(key, values.clone())]))
        .expect("advice inputs fit");

    let mutations = run(&module, &processor).expect("handler succeeds");
    assert_eq!(mutations, vec![AdviceMutation::extend_advice_stack_with(values)]);
}

#[test]
fn advice_map_missing_key_status() {
    // The key at offset 0 is all zeros (fresh memory) and is not in the advice map.
    let wat_src = fixture(
        "(i64.store (i32.const 40)
             (i64.extend_i32_u (call $adv_map_value_len (i32.const 0) (i32.const 32))))
         (call $adv_stack_extend (i32.const 40) (i32.const 1))",
    );
    let module = load(&wat_src);
    let processor = processor();

    let mutations = run(&module, &processor).expect("handler succeeds");
    let status = Felt::new_unchecked(Status::NotFound.as_raw() as u64);
    assert_eq!(mutations, vec![AdviceMutation::extend_advice_stack_with([status])]);
}

#[test]
fn merkle_store_accepts_consistent_node() {
    let left = Word::new([1u64, 2, 3, 4].map(Felt::new_unchecked));
    let right = Word::new([5u64, 6, 7, 8].map(Felt::new_unchecked));
    let value = Poseidon2::merge(&[left, right]);

    let mut felts = Vec::new();
    for word in [value, left, right] {
        felts.extend((0..4).map(|idx| word[idx].as_canonical_u64()));
    }
    let items = format!("(data (i32.const 0) \"{}\")", data_bytes(&felts));
    let wat_src = fixture_with(&items, "(call $merkle_store_extend (i32.const 0) (i32.const 1))");
    let module = load(&wat_src);
    let processor = processor();

    let mutations = run(&module, &processor).expect("handler succeeds");
    let node = InnerNodeInfo { value, left, right };
    assert_eq!(mutations, vec![AdviceMutation::extend_merkle_store([node])]);
}

#[test]
fn stateless_across_calls() {
    let wat_src = format!(
        "(module {IMPORTS}
           (memory (export \"memory\") 1)
           (global $count (mut i64) (i64.const 0))
           (func (export \"handler\")
             (global.set $count (i64.add (global.get $count) (i64.const 1)))
             (i64.store (i32.const 0) (global.get $count))
             (call $adv_stack_extend (i32.const 0) (i32.const 1))))"
    );
    let module = load(&wat_src);
    let processor = processor();

    let one = AdviceMutation::extend_advice_stack_with([Felt::new_unchecked(1)]);
    // Both calls observe a fresh instance, so the counter restarts at zero each time.
    assert_eq!(run(&module, &processor).expect("first call succeeds"), vec![one]);
    let one = AdviceMutation::extend_advice_stack_with([Felt::new_unchecked(1)]);
    assert_eq!(run(&module, &processor).expect("second call succeeds"), vec![one]);
}

// DEFECT AND LIMIT TESTS
// ================================================================================================

#[test]
fn non_canonical_felt_from_guest_is_rejected() {
    let wat_src = fixture(
        "(i64.store (i32.const 0) (i64.const -1))
         (call $adv_stack_extend (i32.const 0) (i32.const 1))",
    );
    let module = load(&wat_src);
    let err = run(&module, &processor()).expect_err("handler must trap");
    assert!(err.contains("non-canonical"), "unexpected error: {err}");
}

#[test]
fn out_of_bounds_pointer_is_rejected() {
    // Offset 65536 is one past the single 64 KiB memory page.
    let wat_src = fixture("(call $adv_stack_extend (i32.const 65536) (i32.const 1))");
    let module = load(&wat_src);
    let err = run(&module, &processor()).expect_err("handler must trap");
    assert!(err.contains("pointer range"), "unexpected error: {err}");
}

#[test]
fn overflowing_pointer_arithmetic_is_rejected() {
    // ptr = u32::MAX; ptr + len goes far past the guest memory and must not wrap.
    let wat_src = fixture("(call $fail (i32.const -1) (i32.const 16))");
    let module = load(&wat_src);
    let err = run(&module, &processor()).expect_err("handler must trap");
    assert!(err.contains("pointer range"), "unexpected error: {err}");
}

#[test]
fn merkle_store_rejects_inconsistent_node() {
    let left = Word::new([1u64, 2, 3, 4].map(Felt::new_unchecked));
    let right = Word::new([5u64, 6, 7, 8].map(Felt::new_unchecked));
    // A value word that is not hash(left, right).
    let bogus = Word::new([9u64, 9, 9, 9].map(Felt::new_unchecked));

    let mut felts = Vec::new();
    for word in [bogus, left, right] {
        felts.extend((0..4).map(|idx| word[idx].as_canonical_u64()));
    }
    let items = format!("(data (i32.const 0) \"{}\")", data_bytes(&felts));
    let wat_src = fixture_with(&items, "(call $merkle_store_extend (i32.const 0) (i32.const 1))");
    let module = load(&wat_src);
    let err = run(&module, &processor()).expect_err("handler must trap");
    assert!(err.contains("digest"), "unexpected error: {err}");
}

#[test]
fn fail_reports_the_guest_message() {
    let msg = "boom: fixture failure";
    let items = format!("(data (i32.const 0) \"{msg}\")");
    let body = format!("(call $fail (i32.const 0) (i32.const {}))", msg.len());
    let wat_src = fixture_with(&items, &body);
    let module = load(&wat_src);

    let err = run(&module, &processor()).expect_err("handler must fail");
    assert_eq!(err, msg);
}

#[test]
fn mutations_before_fail_are_discarded() {
    let wat_src = fixture(
        "(call $adv_stack_extend (i32.const 0) (i32.const 1))
         (call $fail (i32.const 0) (i32.const 4))",
    );
    let module = load(&wat_src);
    // `on_event` returns an error, so the processor never sees the buffered mutation.
    run(&module, &processor()).expect_err("handler must fail");
}

#[test]
fn infinite_loop_runs_out_of_fuel() {
    let wat_src = fixture("(loop $l (br $l))");
    let module = load(&wat_src);
    let err = run(&module, &processor()).expect_err("handler must trap");
    assert!(err.contains("out of fuel"), "unexpected error: {err}");
}

#[test]
fn host_call_work_is_metered() {
    // 13 memory pages fit the 100k-felt output buffer, so the pointer check passes; without the
    // host-call fuel charge, the empty advice stack would make this a cheap OutOfBounds status.
    let wat_src = format!(
        "(module {IMPORTS} (memory (export \"memory\") 13)
           (func (export \"handler\")
             (drop (call $adv_stack_read (i32.const 0) (i32.const 0) (i32.const 100000)))))"
    );
    let limits = WasmHandlerLimits { fuel: 1000, ..Default::default() };
    let module = load_with_limits(&wat_src, limits);
    let err = run(&module, &processor()).expect_err("handler must trap");
    assert!(err.contains("out of fuel"), "unexpected error: {err}");
}

#[test]
fn memory_growth_is_capped() {
    // 512 pages = 32 MiB, above the 16 MiB default cap; the failed grow traps.
    let wat_src = fixture("(drop (memory.grow (i32.const 512)))");
    let module = load(&wat_src);
    run(&module, &processor()).expect_err("handler must trap");
}

#[test]
fn mutation_size_limit_is_enforced() {
    let wat_src = fixture("(call $adv_stack_extend (i32.const 0) (i32.const 5))");
    let limits = WasmHandlerLimits {
        max_mutation_felts: 4,
        ..Default::default()
    };
    let module = load_with_limits(&wat_src, limits);
    let err = run(&module, &processor()).expect_err("handler must trap");
    assert!(err.contains("mutation size limit"), "unexpected error: {err}");
}

// LOAD-TIME VALIDATION TESTS
// ================================================================================================

#[test]
fn foreign_imports_are_rejected() {
    let wat_src = r#"(module
        (import "wasi_snapshot_preview1" "proc_exit" (func (param i32)))
        (func (export "handler")))"#;
    let err = try_load(wat_src, vec![(EVENT, "handler".to_string())]).unwrap_err();
    assert!(
        matches!(err, WasmHandlerLoadError::ForbiddenImport { ref module, .. }
            if module == "wasi_snapshot_preview1"),
        "unexpected error: {err}"
    );
}

#[test]
fn start_sections_are_rejected() {
    let wat_src = r#"(module (func $f) (start $f) (func (export "handler")))"#;
    let err = try_load(wat_src, vec![(EVENT, "handler".to_string())]).unwrap_err();
    assert!(matches!(err, WasmHandlerLoadError::StartSection), "unexpected error: {err}");
}

#[test]
fn missing_manifest_export_is_rejected() {
    let err = try_load("(module)", vec![(EVENT, "handler".to_string())]).unwrap_err();
    assert!(matches!(err, WasmHandlerLoadError::BadExport { .. }), "unexpected error: {err}");
}

#[test]
fn wrong_export_signature_is_rejected() {
    let wat_src = r#"(module (func (export "handler") (param i32)))"#;
    let err = try_load(wat_src, vec![(EVENT, "handler".to_string())]).unwrap_err();
    assert!(matches!(err, WasmHandlerLoadError::BadExport { .. }), "unexpected error: {err}");
}

#[test]
fn wrong_import_signature_is_rejected() {
    let wat_src = r#"(module
        (import "miden:event/v1" "stack_depth" (func (param i32)))
        (func (export "handler")))"#;
    let err = try_load(wat_src, vec![(EVENT, "handler".to_string())]).unwrap_err();
    assert!(matches!(err, WasmHandlerLoadError::Instantiation(_)), "unexpected error: {err}");
}

#[test]
fn duplicate_manifest_events_are_rejected() {
    let manifest = vec![(EVENT, "a".to_string()), (EVENT, "b".to_string())];
    let err = try_load("(module)", manifest).unwrap_err();
    assert!(
        matches!(err, WasmHandlerLoadError::DuplicateEvent { .. }),
        "unexpected error: {err}"
    );
}

#[test]
fn reserved_event_names_are_rejected() {
    let manifest = vec![(EventName::new("sys::custom"), "handler".to_string())];
    let err = try_load("(module)", manifest).unwrap_err();
    assert!(
        matches!(err, WasmHandlerLoadError::ReservedEvent { .. }),
        "unexpected error: {err}"
    );
}

#[test]
fn abi_version_policy_is_enforced() {
    let wasm = wat::parse_str("(module)").expect("valid WAT");
    let load = |version: u32| {
        WasmHandlerModule::new(
            &wasm,
            version,
            vec![(EVENT, "handler".to_string())],
            WasmHandlerLimits::default(),
        )
    };

    // Newer-than-supported and zero versions are rejected; version bumps are additive, so every
    // version from 1 through ABI_VERSION is accepted (module validation runs after the check).
    for bad in [0, ABI_VERSION + 1] {
        let err = load(bad).unwrap_err();
        assert!(
            matches!(err, WasmHandlerLoadError::AbiVersionMismatch { declared, supported }
                if declared == bad && supported == ABI_VERSION),
            "unexpected error: {err}"
        );
    }
    for good in 1..=ABI_VERSION {
        // The manifest export is missing, so passing the version check surfaces BadExport.
        let err = load(good).unwrap_err();
        assert!(matches!(err, WasmHandlerLoadError::BadExport { .. }), "unexpected error: {err}");
    }
}

#[test]
fn float_instructions_are_rejected_by_default() {
    let wat_src = r#"(module
        (func (export "handler") (drop (f32.add (f32.const 1) (f32.const 2)))))"#;
    let err = try_load(wat_src, vec![(EVENT, "handler".to_string())]).unwrap_err();
    assert!(matches!(err, WasmHandlerLoadError::InvalidModule(_)), "unexpected error: {err}");
}

#[test]
fn invalid_wasm_bytes_are_rejected() {
    let err = WasmHandlerModule::new(
        b"not wasm at all",
        ABI_VERSION,
        vec![(EVENT, "handler".to_string())],
        WasmHandlerLimits::default(),
    )
    .unwrap_err();
    assert!(matches!(err, WasmHandlerLoadError::InvalidModule(_)), "unexpected error: {err}");
}

// HOST REGISTRATION
// ================================================================================================

#[test]
fn handlers_register_in_a_default_host() {
    const EVENT_A: EventName = EventName::new("test::wasm::a");
    const EVENT_B: EventName = EventName::new("test::wasm::b");

    let wat_src = format!(
        "(module {IMPORTS}
           (memory (export \"memory\") 1)
           (func (export \"a\"))
           (func (export \"b\")))"
    );
    let wasm = wat::parse_str(&wat_src).expect("fixture WAT must parse");
    let manifest = vec![(EVENT_A, "a".to_string()), (EVENT_B, "b".to_string())];
    let module = Arc::new(
        WasmHandlerModule::new(&wasm, ABI_VERSION, manifest, WasmHandlerLimits::default())
            .expect("fixture loads"),
    );

    let mut host = DefaultHost::default();
    for (event, handler) in module.handlers() {
        host.register_handler(event, handler).expect("registration succeeds");
    }
    use miden_processor::BaseHost;
    assert_eq!(host.resolve_event(EVENT_A.to_event_id()), Some(&EVENT_A));
    assert_eq!(host.resolve_event(EVENT_B.to_event_id()), Some(&EVENT_B));
}
