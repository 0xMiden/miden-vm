//! WAT-fixture tests for the Wasm event handler host adapter.
//!
//! The tests build small handler modules from WAT text, run them against a real
//! [`FastProcessor`] state, and check the buffered mutations or the reported errors. No wasm32
//! toolchain is involved.

use std::{string::String, sync::Arc, vec::Vec};

use miden_crypto::hash::{
    blake::Blake3_256,
    keccak::Keccak256,
    sha2::{Sha256, Sha512},
};
use miden_event_handler_abi::{ABI_VERSION, Status};
use miden_processor::{
    DefaultHost, FastProcessor, Felt, StackInputs, Word,
    advice::{AdviceInputs, AdviceMap, AdviceMutation, AdviceStack},
    crypto::{
        hash::Poseidon2,
        merkle::{InnerNodeInfo, MerkleStore},
    },
    event::{EventError, EventName},
};
use miden_wasm_event_handlers::{
    WasmHandlerLimits, WasmHandlerLoadError, WasmHandlerModule, WasmHandlerRunError,
};

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
  (import "miden:event/v1" "mem_read_ctx" (func $mem_read_ctx (param i32 i32 i32 i32) (result i32)))
  (import "miden:event/v1" "merkle_get_node" (func $merkle_get_node (param i32 i32 i64 i32) (result i32)))
  (import "miden:event/v1" "merkle_has_path" (func $merkle_has_path (param i32 i32 i64) (result i32)))
  (import "miden:event/v1" "poseidon2_merge" (func $poseidon2_merge (param i32 i64 i32)))
  (import "miden:event/v1" "poseidon2_hash" (func $poseidon2_hash (param i32 i32 i64 i32)))
  (import "miden:event/v1" "poseidon2_permute" (func $poseidon2_permute (param i32)))
  (import "miden:event/v1" "keccak256" (func $keccak256 (param i32 i32 i32)))
  (import "miden:event/v1" "sha256" (func $sha256 (param i32 i32 i32)))
  (import "miden:event/v1" "sha512" (func $sha512 (param i32 i32 i32)))
  (import "miden:event/v1" "blake3" (func $blake3 (param i32 i32 i32)))
  (import "miden:event/v1" "adv_stack_len" (func $adv_stack_len (result i32)))
  (import "miden:event/v1" "adv_stack_read" (func $adv_stack_read (param i32 i32 i32) (result i32)))
  (import "miden:event/v1" "adv_map_value_len" (func $adv_map_value_len (param i32 i32) (result i32)))
  (import "miden:event/v1" "adv_map_value_read" (func $adv_map_value_read (param i32 i32 i32 i32) (result i32)))
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
    run_raw(module, processor).map_err(|err| err.to_string())
}

/// Runs the fixture's `handler` export and keeps the raw error, so tests can match the
/// [`WasmHandlerRunError`] variant with `downcast_ref`.
fn run_raw(
    module: &Arc<WasmHandlerModule>,
    processor: &FastProcessor,
) -> Result<Vec<AdviceMutation>, EventError> {
    let handlers = module.handlers();
    let (_, handler) = handlers
        .iter()
        .find(|(event, _)| *event == EVENT)
        .expect("event is in the manifest");
    handler.on_event(&processor.state())
}

/// Asserts that the raw event error is the given [`WasmHandlerRunError`] variant.
macro_rules! assert_run_error {
    ($err:expr, $variant:pat) => {
        let err = $err;
        assert!(
            matches!(err.downcast_ref::<WasmHandlerRunError>(), Some($variant)),
            "unexpected error: {err}"
        );
    };
}

/// Returns a processor with an empty operand stack and empty advice inputs.
fn processor() -> FastProcessor {
    FastProcessor::new(StackInputs::default())
}

/// Returns a processor whose operand stack is initialized with `values`.
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

/// Encodes the elements of the given words as the bytes of a WAT data segment.
fn word_bytes(words: &[Word]) -> String {
    let values: Vec<u64> = words
        .iter()
        .flat_map(|word| word.as_elements().iter().map(Felt::as_canonical_u64))
        .collect();
    data_bytes(&values)
}

/// Builds a guest body that reposts the `bytes`-byte digest at `digest` as little-endian `u32`
/// limbs at `felts`, and buffers those limbs onto the advice stack.
fn digest_to_advice_stack(digest: u32, felts: u32, bytes: u32) -> String {
    let limbs = bytes / 4;
    let stores: String = (0..limbs)
        .map(|idx| {
            format!(
                "(i64.store (i32.const {}) (i64.extend_i32_u (i32.load (i32.const {}))))",
                felts + idx * 8,
                digest + idx * 4,
            )
        })
        .collect();
    format!("{stores} (call $adv_stack_extend (i32.const {felts}) (i32.const {limbs}))")
}

/// Splits digest bytes into the little-endian `u32` limbs [`digest_to_advice_stack`] produces.
fn digest_limbs(bytes: &[u8]) -> Vec<Felt> {
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|chunk| Felt::new_unchecked(u64::from(u32::from_le_bytes(*chunk))))
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
    let expected = processor.state().stack_item(1);

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
    let word = processor.state().stack_word(1);

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
    let expected = [state.stack_item(1), state.stack_item(2), state.stack_item(3)];

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
        Felt::new_unchecked(u64::from(u32::from(state.context_id()))),
        Felt::new_unchecked(u64::try_from(state.stack_depth()).unwrap()),
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
fn mem_get_presence_is_word_granular() {
    use miden_assembly::{Assembler, DefaultSourceManager};

    // VM memory initializes one word (four elements) at a time, so after the program writes
    // address 0, address 1 reads as `Ok` with the value zero, and only the next word (address 4)
    // is `Uninit`. The handler needs a program to write that word, so this test runs the whole
    // VM instead of calling the handler against a fresh state.
    //
    // The sentinel at address 0 of the guest memory proves that the host wrote the zero, instead
    // of leaving the output buffer as it was.
    let wat_src = fixture(
        "(i64.store (i32.const 0) (i64.const 7))
         (i64.store (i32.const 8)
             (i64.extend_i32_u (call $mem_get (i32.const 1) (i32.const 0))))
         (i64.store (i32.const 16)
             (i64.extend_i32_u (call $mem_get (i32.const 4) (i32.const 24))))
         (call $adv_stack_extend (i32.const 0) (i32.const 3))",
    );
    let module = load(&wat_src);

    let source = format!(
        r#"
        begin
            push.1 mem_store.0
            emit.event("{event}")
            adv_push push.0 assert_eq
            adv_push push.{ok} assert_eq
            adv_push push.{uninit} assert_eq
        end"#,
        event = EVENT.as_str(),
        ok = Status::Ok.as_raw(),
        uninit = Status::Uninit.as_raw(),
    );
    let package = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .assemble_program("wasm_handler_partial_word", source)
        .expect("program assembles");
    let program = package.unwrap_program();

    let mut host = DefaultHost::default();
    for (event, handler) in module.handlers() {
        host.register_handler(event, handler).expect("registration succeeds");
    }
    FastProcessor::new(StackInputs::default())
        .execute_sync(&program, &mut host)
        .expect("the unwritten cell of a written word reads as Ok with the value zero");
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
    let expected = processor.state().advice_stack().iter().copied().collect::<Vec<_>>();
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
         (drop (call $adv_map_value_read (i32.const 0) (i32.const 48) (i32.const 8) (i32.const 40)))
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
fn adv_map_value_read_reports_the_count_when_the_capacity_is_too_small() {
    let key_values = [1u64, 2, 3, 4];
    let key = Word::new([1u64, 2, 3, 4].map(Felt::new_unchecked));
    let values: Vec<Felt> = [10u64, 11, 12].into_iter().map(Felt::new_unchecked).collect();

    // The key sits at offset 0; the 1-element buffer at 64 is too small for the 3-element
    // value, so the call returns `CapacityTooSmall` and writes the needed count to 40.
    let items = format!("(data (i32.const 0) \"{}\")", data_bytes(&key_values));
    let wat_src = fixture_with(
        &items,
        "(i64.store (i32.const 48)
             (i64.extend_i32_u
                 (call $adv_map_value_read
                     (i32.const 0) (i32.const 64) (i32.const 1) (i32.const 40))))
         (i64.store (i32.const 56) (i64.extend_i32_u (i32.load (i32.const 40))))
         (call $adv_stack_extend (i32.const 48) (i32.const 2))",
    );
    let module = load(&wat_src);
    let processor = FastProcessor::new(StackInputs::default())
        .with_advice(AdviceInputs::default().with_map([(key, values)]))
        .expect("advice inputs fit");

    let mutations = run(&module, &processor).expect("handler succeeds");
    let expected = [
        Felt::new_unchecked(Status::CapacityTooSmall.as_raw() as u64),
        Felt::new_unchecked(3),
    ];
    assert_eq!(mutations, vec![AdviceMutation::extend_advice_stack_with(expected)]);
}

#[test]
fn status_calls_validate_output_pointers() {
    // The key is absent, so the result would be `NotFound` — but the bad output pointer is a
    // defect and must trap first.
    let wat_src = fixture("(drop (call $adv_map_value_len (i32.const 0) (i32.const 100000000)))");
    let module = load(&wat_src);
    let err = run_raw(&module, &processor()).expect_err("a bad output pointer must trap");
    assert_run_error!(err, WasmHandlerRunError::Trapped(_));
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
fn mem_read_ctx_statuses() {
    // Context 0 of a fresh processor has no written cell, so the batch read is Uninit; a range
    // past the u32 address space is OutOfBounds.
    let wat_src = fixture(
        "(i64.store (i32.const 0)
             (i64.extend_i32_u
                 (call $mem_read_ctx (i32.const 0) (i32.const 0) (i32.const 16) (i32.const 2))))
         (i64.store (i32.const 8)
             (i64.extend_i32_u
                 (call $mem_read_ctx (i32.const 0) (i32.const -1) (i32.const 16) (i32.const 2))))
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

// MERKLE QUERY TESTS
// ================================================================================================

#[test]
fn merkle_queries() {
    let left = Word::new([1u64, 2, 3, 4].map(Felt::new_unchecked));
    let right = Word::new([5u64, 6, 7, 8].map(Felt::new_unchecked));
    let root = Poseidon2::merge(&[left, right]);
    // A root no tree in the store has.
    let unknown = Word::new([9u64, 9, 9, 9].map(Felt::new_unchecked));

    let mut store = MerkleStore::new();
    store.extend([InnerNodeInfo { value: root, left, right }]);
    let processor = FastProcessor::new(StackInputs::default())
        .with_advice(AdviceInputs::default().with_merkle_store(store))
        .expect("advice inputs fit");

    // The known root sits at offset 0, the unknown one at offset 32.
    let items = format!("(data (i32.const 0) \"{}\")", word_bytes(&[root, unknown]));
    let wat_src = fixture_with(
        &items,
        "(drop (call $merkle_get_node (i32.const 0) (i32.const 1) (i64.const 0) (i32.const 64)))
         (call $adv_stack_extend (i32.const 64) (i32.const 4))
         (i64.store (i32.const 200)
             (i64.extend_i32_u (call $merkle_has_path (i32.const 0) (i32.const 1) (i64.const 0))))
         (i64.store (i32.const 208)
             (i64.extend_i32_u
                 (call $merkle_get_node (i32.const 32) (i32.const 1) (i64.const 0)
                       (i32.const 96))))
         (call $adv_stack_extend (i32.const 200) (i32.const 2))",
    );
    let module = load(&wat_src);

    let mutations = run(&module, &processor).expect("handler succeeds");
    let statuses = [Felt::new_unchecked(1), Felt::new_unchecked(Status::NotFound.as_raw() as u64)];
    assert_eq!(
        mutations,
        vec![
            AdviceMutation::extend_advice_stack_with(left.as_elements().to_vec()),
            AdviceMutation::extend_advice_stack_with(statuses),
        ]
    );
}

// HASHING TESTS
// ================================================================================================

#[test]
fn poseidon2_merge_matches_native() {
    let a = Word::new([1u64, 2, 3, 4].map(Felt::new_unchecked));
    let b = Word::new([5u64, 6, 7, 8].map(Felt::new_unchecked));

    let items = format!("(data (i32.const 0) \"{}\")", word_bytes(&[a, b]));
    let wat_src = fixture_with(
        &items,
        "(call $poseidon2_merge (i32.const 0) (i64.const 0) (i32.const 64))
         (call $adv_stack_extend (i32.const 64) (i32.const 4))",
    );
    let module = load(&wat_src);

    let mutations = run(&module, &processor()).expect("handler succeeds");
    let expected = Poseidon2::merge(&[a, b]);
    assert_eq!(
        mutations,
        vec![AdviceMutation::extend_advice_stack_with(expected.as_elements().to_vec())]
    );
}

#[test]
fn poseidon2_merge_in_domain_matches_native() {
    let a = Word::new([1u64, 2, 3, 4].map(Felt::new_unchecked));
    let b = Word::new([5u64, 6, 7, 8].map(Felt::new_unchecked));

    let items = format!("(data (i32.const 0) \"{}\")", word_bytes(&[a, b]));
    let wat_src = fixture_with(
        &items,
        "(call $poseidon2_merge (i32.const 0) (i64.const 7) (i32.const 64))
         (call $adv_stack_extend (i32.const 64) (i32.const 4))",
    );
    let module = load(&wat_src);

    let mutations = run(&module, &processor()).expect("handler succeeds");
    let expected = Poseidon2::merge_in_domain(&[a, b], Felt::new_unchecked(7));
    assert_eq!(
        mutations,
        vec![AdviceMutation::extend_advice_stack_with(expected.as_elements().to_vec())]
    );
}

#[test]
fn poseidon2_hash_matches_native() {
    let values = [11u64, 22, 33, 44, 55];
    let felts: Vec<Felt> = values.iter().map(|value| Felt::new_unchecked(*value)).collect();

    let items = format!("(data (i32.const 0) \"{}\")", data_bytes(&values));
    let wat_src = fixture_with(
        &items,
        "(call $poseidon2_hash (i32.const 0) (i32.const 5) (i64.const 0) (i32.const 64))
         (call $adv_stack_extend (i32.const 64) (i32.const 4))",
    );
    let module = load(&wat_src);

    let mutations = run(&module, &processor()).expect("handler succeeds");
    let expected = Poseidon2::hash_elements(&felts);
    assert_eq!(
        mutations,
        vec![AdviceMutation::extend_advice_stack_with(expected.as_elements().to_vec())]
    );
}

#[test]
fn poseidon2_permute_matches_native() {
    let values: [u64; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let mut expected = values.map(Felt::new_unchecked);

    let items = format!("(data (i32.const 0) \"{}\")", data_bytes(&values));
    let wat_src = fixture_with(
        &items,
        "(call $poseidon2_permute (i32.const 0))
         (call $adv_stack_extend (i32.const 0) (i32.const 12))",
    );
    let module = load(&wat_src);

    let mutations = run(&module, &processor()).expect("handler succeeds");
    Poseidon2::apply_permutation(&mut expected);
    assert_eq!(mutations, vec![AdviceMutation::extend_advice_stack_with(expected)]);
}

#[test]
fn keccak256_matches_native() {
    let body = format!(
        "(call $keccak256 (i32.const 0) (i32.const 3) (i32.const 64)) {}",
        digest_to_advice_stack(64, 128, 32)
    );
    let wat_src = fixture_with("(data (i32.const 0) \"abc\")", &body);
    let module = load(&wat_src);

    let mutations = run(&module, &processor()).expect("handler succeeds");
    let expected = digest_limbs(Keccak256::hash(b"abc").as_bytes());
    assert_eq!(mutations, vec![AdviceMutation::extend_advice_stack_with(expected)]);
}

#[test]
fn sha256_matches_native() {
    let body = format!(
        "(call $sha256 (i32.const 0) (i32.const 3) (i32.const 64)) {}",
        digest_to_advice_stack(64, 128, 32)
    );
    let wat_src = fixture_with("(data (i32.const 0) \"abc\")", &body);
    let module = load(&wat_src);

    let mutations = run(&module, &processor()).expect("handler succeeds");
    let expected = digest_limbs(Sha256::hash(b"abc").as_bytes());
    assert_eq!(mutations, vec![AdviceMutation::extend_advice_stack_with(expected)]);
}

#[test]
fn sha512_matches_native() {
    let body = format!(
        "(call $sha512 (i32.const 0) (i32.const 3) (i32.const 64)) {}",
        digest_to_advice_stack(64, 256, 64)
    );
    let wat_src = fixture_with("(data (i32.const 0) \"abc\")", &body);
    let module = load(&wat_src);

    let mutations = run(&module, &processor()).expect("handler succeeds");
    let expected = digest_limbs(Sha512::hash(b"abc").as_bytes());
    assert_eq!(mutations, vec![AdviceMutation::extend_advice_stack_with(expected)]);
}

#[test]
fn blake3_matches_native() {
    let body = format!(
        "(call $blake3 (i32.const 0) (i32.const 3) (i32.const 64)) {}",
        digest_to_advice_stack(64, 128, 32)
    );
    let wat_src = fixture_with("(data (i32.const 0) \"abc\")", &body);
    let module = load(&wat_src);

    let mutations = run(&module, &processor()).expect("handler succeeds");
    let expected = digest_limbs(Blake3_256::hash(b"abc").as_bytes());
    assert_eq!(mutations, vec![AdviceMutation::extend_advice_stack_with(expected)]);
}

#[test]
// wasm32 hosts (the wasip1 smoke-test run) have no threads.
#[cfg_attr(target_family = "wasm", ignore = "no threads on wasm32 hosts")]
fn concurrent_calls_share_one_module_deterministically() {
    // One compiled module, called from many threads at once, each against its own processor
    // state. This exercises the Send + Sync claims of the handler and yields the determinism
    // check: identical state must produce identical mutations everywhere.
    let wat_src = fixture(
        "(i64.store (i32.const 0) (call $stack_get (i32.const 1)))
         (call $adv_stack_extend (i32.const 0) (i32.const 1))",
    );
    let module = load(&wat_src);

    let expected = {
        let processor = processor_with_stack(&[5, 7]);
        run(&module, &processor).expect("handler succeeds")
    };

    std::thread::scope(|scope| {
        for _ in 0..8 {
            let module = &module;
            let expected = &expected;
            scope.spawn(move || {
                for _ in 0..50 {
                    let processor = processor_with_stack(&[5, 7]);
                    let mutations = run(module, &processor).expect("handler succeeds");
                    assert_eq!(&mutations, expected);
                }
            });
        }
    });
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
fn pointer_range_past_the_address_space_is_rejected() {
    // ptr = u32::MAX, so ptr + len lands past the end of the 32-bit address space and far past
    // the guest memory. The range check refuses it.
    let wat_src = fixture("(call $fail (i32.const -1) (i32.const 16))");
    let module = load(&wat_src);
    let err = run(&module, &processor()).expect_err("handler must trap");
    assert!(err.contains("pointer range"), "unexpected error: {err}");
}

#[test]
fn merkle_invalid_depth_traps() {
    // Depth 200 is outside the valid range for a Merkle tree; that is a defect, not a miss.
    let wat_src = fixture(
        "(drop (call $merkle_get_node (i32.const 0) (i32.const 200) (i64.const 0) (i32.const 64)))",
    );
    let module = load(&wat_src);
    let err = run(&module, &processor()).expect_err("handler must trap");
    assert!(err.contains("invalid merkle node"), "unexpected error: {err}");
}

#[test]
fn non_canonical_domain_traps() {
    let wat_src = fixture("(call $poseidon2_merge (i32.const 0) (i64.const -1) (i32.const 64))");
    let module = load(&wat_src);
    let err = run(&module, &processor()).expect_err("handler must trap");
    assert!(err.contains("non-canonical"), "unexpected error: {err}");
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
    let err = run_raw(&module, &processor()).expect_err("handler must trap");
    assert_run_error!(err, WasmHandlerRunError::OutOfFuel(_));
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
    // The budget covers the 13-page instantiation charge plus 1000 fuel for the body — far
    // less than the 100k-felt read the host call asks for.
    let limits = WasmHandlerLimits {
        fuel: 13 * 65536 / 8 + 1000,
        ..Default::default()
    };
    let module = load_with_limits(&wat_src, limits);
    let err = run_raw(&module, &processor()).expect_err("handler must trap");
    // Fuel exhaustion inside a host call must classify as `OutOfFuel`, not `Trapped`.
    assert_run_error!(err, WasmHandlerRunError::OutOfFuel(_));
}

#[test]
fn memory_growth_is_capped() {
    // 512 pages = 32 MiB, above the 16 MiB default cap; the failed grow traps.
    let wat_src = fixture("(drop (memory.grow (i32.const 512)))");
    let module = load(&wat_src);
    let err = run_raw(&module, &processor()).expect_err("handler must trap");
    assert_run_error!(err, WasmHandlerRunError::LimitExceeded(_));
}

#[test]
fn instantiation_cost_over_the_fuel_budget_is_rejected_at_load() {
    // 16 initial pages (1 MiB) cost 131072 fuel to zero on every instantiation, far over a
    // 1000-fuel budget: no call could ever run.
    let wat_src =
        format!("(module {IMPORTS} (memory (export \"memory\") 16) (func (export \"handler\")))");
    let wasm = wat::parse_str(&wat_src).expect("fixture WAT must parse");
    let limits = WasmHandlerLimits { fuel: 1000, ..Default::default() };
    let manifest = vec![(EVENT, "handler".to_string())];
    let err = WasmHandlerModule::new(&wasm, ABI_VERSION, manifest, limits).unwrap_err();
    assert!(
        matches!(err, WasmHandlerLoadError::InstantiationOverBudget { .. }),
        "unexpected error: {err}"
    );
}

#[test]
fn data_segments_count_toward_the_instantiation_cost() {
    // One initial page costs 8192 fuel; the 4096-byte data segment adds 512 more. A budget
    // between the two accepts the module without the segment and refuses it with the segment.
    let segment = format!("(data (i32.const 0) \"{}\")", data_bytes(&vec![0u64; 512]));
    let with_segment = fixture_with(&segment, "(nop)");
    let without_segment = fixture("(nop)");
    let limits = WasmHandlerLimits { fuel: 8500, ..Default::default() };
    load_with_limits(&without_segment, limits.clone());
    let wasm = wat::parse_str(&with_segment).expect("fixture WAT must parse");
    let manifest = vec![(EVENT, "handler".to_string())];
    let err = WasmHandlerModule::new(&wasm, ABI_VERSION, manifest, limits).unwrap_err();
    assert!(
        matches!(err, WasmHandlerLoadError::InstantiationOverBudget { .. }),
        "unexpected error: {err}"
    );
}

#[test]
fn instantiation_cost_is_charged_on_every_call() {
    // Two initial pages cost 16384 fuel per instantiation. A margin of 5 above that cannot
    // pay for the host call in the body (flat charge 25); a comfortable margin can.
    let wat_src = format!(
        "(module {IMPORTS} (memory (export \"memory\") 2)
           (func (export \"handler\") (drop (call $clk))))"
    );
    let starved = WasmHandlerLimits { fuel: 16384 + 5, ..Default::default() };
    let module = load_with_limits(&wat_src, starved);
    let err = run_raw(&module, &processor()).expect_err("handler must run out of fuel");
    assert_run_error!(err, WasmHandlerRunError::OutOfFuel(_));

    let comfortable = WasmHandlerLimits { fuel: 16384 + 1000, ..Default::default() };
    let module = load_with_limits(&wat_src, comfortable);
    run(&module, &processor()).expect("handler succeeds");
}

#[test]
fn element_segments_count_toward_the_instantiation_cost() {
    // wasmi materializes every element segment — passive included — on each instantiation,
    // one boxed value plus a const-expr evaluation per item. 8000 passive items encode as
    // ~8 KB but cost ~131k fuel at the element rate, far over a 100k budget that the same
    // module without the segment fits (one page costs 8192).
    let segment = format!("(elem func {})", "0 ".repeat(8000));
    let with_segment = fixture_with(&segment, "(nop)");
    let without_segment = fixture("(nop)");
    let limits = WasmHandlerLimits { fuel: 100_000, ..Default::default() };
    load_with_limits(&without_segment, limits.clone());
    let wasm = wat::parse_str(&with_segment).expect("fixture WAT must parse");
    let manifest = vec![(EVENT, "handler".to_string())];
    let err = WasmHandlerModule::new(&wasm, ABI_VERSION, manifest, limits).unwrap_err();
    assert!(
        matches!(err, WasmHandlerLoadError::InstantiationOverBudget { .. }),
        "unexpected error: {err}"
    );
}

#[test]
fn long_form_table_reftype_is_accepted_by_the_section_walk() {
    // Hand-crafted module: header + table section `04 05 01 63 70 00 01` — one table whose
    // reference type uses the long-form encoding 0x63 0x70, `(ref null func)`. wasmi
    // validates it, so the loader's static section analysis must accept it too (the
    // differential fuzz target asserts exactly this pairing).
    let mut wasm = b"\x00\x61\x73\x6d\x01\x00\x00\x00".to_vec();
    wasm.extend_from_slice(&[0x04, 0x05, 0x01, 0x63, 0x70, 0x00, 0x01]);
    assert!(
        wasmi::Module::new(&wasmi::Engine::default(), &wasm).is_ok(),
        "the fixture must be wasmi-valid"
    );
    assert!(
        miden_wasm_event_handlers::fuzz_module_statics(&wasm),
        "the section walk must accept what wasmi validates"
    );

    // The real load path must accept it too. The module has no `memory` export, so the load
    // stops there — after the static walk, which is what this test pins.
    let err = WasmHandlerModule::new(&wasm, ABI_VERSION, Vec::new(), WasmHandlerLimits::default())
        .unwrap_err();
    assert!(
        matches!(err, WasmHandlerLoadError::MissingMemoryExport),
        "unexpected error: {err}"
    );
}

#[test]
fn unknown_table_reftype_is_refused_by_the_section_walk() {
    // The same module with an unknown reference-type byte (0x71). wasmi rejects it today, so the
    // static walk must reject it as well: a lead byte it cannot read makes every following byte
    // ambiguous, and a wrong instantiation charge would be silent.
    let mut wasm = b"\x00\x61\x73\x6d\x01\x00\x00\x00".to_vec();
    wasm.extend_from_slice(&[0x04, 0x04, 0x01, 0x71, 0x00, 0x01]);
    assert!(
        wasmi::Module::new(&wasmi::Engine::default(), &wasm).is_err(),
        "the fixture must stay wasmi-invalid"
    );
    assert!(
        !miden_wasm_event_handlers::fuzz_module_statics(&wasm),
        "the section walk must fail closed on an unknown reference type"
    );
}

#[test]
fn unknown_imports_are_rejected_at_load() {
    // Distinct unknown names in the right namespace must fail at load, not accumulate and
    // fail later inside instantiation.
    let wat_src = r#"(module
        (import "miden:event/v1" "not_a_host_fn" (func))
        (memory (export "memory") 1)
        (func (export "handler")))"#;
    let err = try_load(wat_src, vec![(EVENT, "handler".to_string())]).unwrap_err();
    assert!(
        matches!(err, WasmHandlerLoadError::UnknownImport { ref name } if name == "not_a_host_fn"),
        "unexpected error: {err}"
    );
}

#[test]
fn oversized_export_count_is_rejected_at_load() {
    // wasmi rebuilds the export map on every per-call instantiation, unmetered, so the
    // export count is capped at load (1024).
    let exports: String = (0..1025).map(|idx| format!("(export \"e{idx}\" (func $f))")).collect();
    let wat_src = format!("(module (func $f) (func (export \"handler\")) {exports})");
    let err = try_load(&wat_src, vec![(EVENT, "handler".to_string())]).unwrap_err();
    assert!(
        matches!(err, WasmHandlerLoadError::TooManyExports { count: 1026, .. }),
        "unexpected error: {err}"
    );
}

#[test]
fn zero_length_mutations_buffer_no_records() {
    let wat_src = fixture(
        "(call $adv_stack_extend (i32.const 0) (i32.const 0))
         (call $merkle_store_extend (i32.const 0) (i32.const 0))",
    );
    let module = load(&wat_src);
    let mutations = run(&module, &processor()).expect("handler succeeds");
    assert!(mutations.is_empty(), "empty extensions must buffer no records: {mutations:?}");
}

/// A handler that calls `adv_stack_extend` with a zero length 1000 times.
///
/// Fuel arithmetic, measured on this fixture: the 1-page memory costs 8192 fuel per
/// instantiation and the guest instructions of the loop cost 4192 more, so the run costs 12384
/// fuel without the flat host-call charge. The 1000 host calls add 1000 * 25 = 25000, for a
/// total of 37384. The two tests below sit on either side of that gap.
fn empty_host_call_loop() -> String {
    fixture(
        "(local $i i32)
         (local.set $i (i32.const 1000))
         (loop $l
           (call $adv_stack_extend (i32.const 0) (i32.const 0))
           (local.tee $i (i32.sub (local.get $i) (i32.const 1)))
           (br_if $l))",
    )
}

#[test]
fn empty_host_calls_cost_fuel() {
    // Every host call pays a flat transition charge, so a loop of zero-length extends cannot
    // burn host transitions (or accumulate mutation records) for free. The budget is over the
    // 12384 fuel the guest instructions cost, so only the flat charge can exhaust it.
    let module = load_with_limits(
        &empty_host_call_loop(),
        WasmHandlerLimits { fuel: 20_000, ..Default::default() },
    );
    let err = run_raw(&module, &processor()).expect_err("handler must run out of fuel");
    assert_run_error!(err, WasmHandlerRunError::OutOfFuel(_));
}

#[test]
fn empty_host_calls_fit_a_budget_above_their_cost() {
    // The counterpart of `empty_host_calls_cost_fuel`: a budget over the full 37384 fuel of the
    // same loop, so the flat charge bounds the host calls without refusing a legitimate handler.
    let module = load_with_limits(
        &empty_host_call_loop(),
        WasmHandlerLimits { fuel: 60_000, ..Default::default() },
    );
    run(&module, &processor()).expect("handler succeeds");
}

/// The element values of the advice-map entry [`adv_map_read_processor`] seeds.
const ADV_MAP_READ_VALUES: [u64; 3] = [10, 11, 12];

/// The exact fuel budget one call of [`adv_map_read_fixture`] needs.
///
/// Derived from the `src/host.rs` constants; only the guest-instruction term is measured:
///
/// - instantiation: the 1-page memory costs 65536 / 8 = 8192 fuel (`module.rs` charges one unit per
///   8 bytes), and the fixture declares no data, table, or element section;
/// - the guest instructions of the fixture body cost 8 fuel (measured);
/// - the `adv_map_value_read` prologue costs `HOST_CALL_BASE_FUEL` (25) + one key word (`4 *
///   FUEL_PER_FELT` = 4) + one map probe (`FUEL_PER_MAP_PROBE` = 250) = 279;
/// - the read itself costs the value copy (`3 * FUEL_PER_FELT` = 3) + a second map probe
///   (`FUEL_PER_MAP_PROBE` = 250) = 253, because the borrow rules make it resolve the entry a
///   second time;
/// - the `adv_stack_extend` that publishes the value costs `HOST_CALL_BASE_FUEL` (25) + three felts
///   (3) = 28.
///
/// 8192 + 8 + 279 + 253 + 28 = 8760.
const ADV_MAP_READ_FUEL: u64 = 8760;

/// A handler that reads the three-element advice-map value of a key it writes into memory, and
/// publishes the value on the advice stack.
fn adv_map_read_fixture() -> String {
    // The key word sits at offset 0, the value buffer at 48, and the element count at 40.
    fixture(
        "(i64.store (i32.const 0) (i64.const 1))
         (i64.store (i32.const 8) (i64.const 2))
         (i64.store (i32.const 16) (i64.const 3))
         (i64.store (i32.const 24) (i64.const 4))
         (drop (call $adv_map_value_read
             (i32.const 0) (i32.const 48) (i32.const 8) (i32.const 40)))
         (call $adv_stack_extend (i32.const 48) (i32.const 3))",
    )
}

/// Returns a processor whose advice map holds [`ADV_MAP_READ_VALUES`] under the key
/// [`adv_map_read_fixture`] builds.
fn adv_map_read_processor() -> FastProcessor {
    let key = Word::new([1u64, 2, 3, 4].map(Felt::new_unchecked));
    let values: Vec<Felt> = ADV_MAP_READ_VALUES.into_iter().map(Felt::new_unchecked).collect();
    FastProcessor::new(StackInputs::default())
        .with_advice(AdviceInputs::default().with_map([(key, values)]))
        .expect("advice inputs fit")
}

#[test]
fn the_advice_map_read_charges_its_second_map_probe() {
    // One fuel under the exact cost must fail. The read resolves the advice-map entry a second
    // time and charges `FUEL_PER_MAP_PROBE` (250) for it; without that charge the call would
    // cost 250 less and this budget would pass.
    let module = load_with_limits(
        &adv_map_read_fixture(),
        WasmHandlerLimits {
            fuel: ADV_MAP_READ_FUEL - 1,
            ..Default::default()
        },
    );
    let err =
        run_raw(&module, &adv_map_read_processor()).expect_err("handler must run out of fuel");
    assert_run_error!(err, WasmHandlerRunError::OutOfFuel(_));
}

#[test]
fn the_advice_map_read_fits_its_exact_charge() {
    // The counterpart of `the_advice_map_read_charges_its_second_map_probe`: the exact budget
    // completes the read, so the charge is not one fuel unit more than the arithmetic states.
    let module = load_with_limits(
        &adv_map_read_fixture(),
        WasmHandlerLimits {
            fuel: ADV_MAP_READ_FUEL,
            ..Default::default()
        },
    );
    let mutations = run(&module, &adv_map_read_processor()).expect("handler succeeds");
    let expected: Vec<Felt> = ADV_MAP_READ_VALUES.into_iter().map(Felt::new_unchecked).collect();
    assert_eq!(mutations, vec![AdviceMutation::extend_advice_stack_with(expected)]);
}

#[test]
fn mutation_size_limit_is_enforced() {
    let wat_src = fixture("(call $adv_stack_extend (i32.const 0) (i32.const 5))");
    let limits = WasmHandlerLimits {
        max_mutation_felts: 4,
        ..Default::default()
    };
    let module = load_with_limits(&wat_src, limits);
    let err = run_raw(&module, &processor()).expect_err("handler must trap");
    assert_run_error!(err, WasmHandlerRunError::LimitExceeded(_));
}

// LOAD-TIME VALIDATION TESTS
// ================================================================================================

#[test]
fn the_import_fixture_declares_every_abi_host_function() {
    // `build_linker` in `src/host.rs` states that this fixture declares the whole host set, so
    // every fixture also resolves and type-checks each host function. A new host function that
    // the fixture misses would leave its signature untested.
    for name in miden_event_handler_abi::host_fn::ALL {
        assert!(
            IMPORTS.contains(&format!("\"{name}\"")),
            "the import fixture does not declare the host function '{name}'"
        );
    }
}

#[test]
fn oversized_table_is_rejected_at_load() {
    // 1M funcref elements fit the fuel budget (the instantiation charge) but overstep the
    // table-element cap, so the load-time dry run refuses the eager 8 MB allocation.
    let wat_src = format!("(module {IMPORTS} (table 1000000 funcref) (func (export \"handler\")))");
    let err = try_load(&wat_src, vec![(EVENT, "handler".to_string())]).unwrap_err();
    assert!(matches!(err, WasmHandlerLoadError::Instantiation(_)), "unexpected error: {err}");
}

#[test]
fn structural_bomb_is_rejected_at_load() {
    // 1001 globals overstep wasmi's strict enforced limits (at most 1000 globals), which
    // defend module compilation itself.
    let globals = "(global i32 (i32.const 0))".repeat(1001);
    let wat_src = format!("(module {globals} (func (export \"handler\")))");
    let err = try_load(&wat_src, vec![(EVENT, "handler".to_string())]).unwrap_err();
    assert!(matches!(err, WasmHandlerLoadError::InvalidModule(_)), "unexpected error: {err}");
}

#[test]
fn oversized_module_is_rejected_at_load() {
    let wat_src = fixture("(nop)");
    let wasm = wat::parse_str(&wat_src).expect("fixture WAT must parse");
    let limits = WasmHandlerLimits {
        max_module_bytes: 16,
        ..Default::default()
    };
    let manifest = vec![(EVENT, "handler".to_string())];
    let err = WasmHandlerModule::new(&wasm, ABI_VERSION, manifest, limits).unwrap_err();
    assert!(
        matches!(err, WasmHandlerLoadError::ModuleTooLarge { .. }),
        "unexpected error: {err}"
    );
}

#[test]
fn duplicate_imports_are_rejected_at_load() {
    // wasmi re-resolves every import on each per-call instantiation and meters none of it, so
    // an import-bomb module (the same import declared many times) must be refused at load.
    let wat_src = r#"(module
        (import "miden:event/v1" "clk" (func (result i64)))
        (import "miden:event/v1" "clk" (func (result i64)))
        (func (export "handler")))"#;
    let err = try_load(wat_src, vec![(EVENT, "handler".to_string())]).unwrap_err();
    assert!(
        matches!(err, WasmHandlerLoadError::DuplicateImport { ref name } if name == "clk"),
        "unexpected error: {err}"
    );
}

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
        matches!(err, WasmHandlerLoadError::InvalidManifest(_)),
        "unexpected error: {err}"
    );
}

#[test]
fn reserved_event_names_are_rejected() {
    // A real system event: no handler module may take over the name of a built-in event.
    let manifest = vec![(EventName::new("sys::map_value_to_stack"), "handler".to_string())];
    let err = try_load("(module)", manifest).unwrap_err();
    assert!(
        matches!(err, WasmHandlerLoadError::InvalidManifest(_)),
        "unexpected error: {err}"
    );
}

#[test]
fn unknown_reserved_event_names_are_rejected() {
    // The whole namespace is reserved, so a name that no system event uses is refused too.
    let manifest = vec![(EventName::new("sys::not_a_real_event"), "handler".to_string())];
    let err = try_load("(module)", manifest).unwrap_err();
    assert!(
        matches!(err, WasmHandlerLoadError::InvalidManifest(_)),
        "unexpected error: {err}"
    );
}

#[test]
fn oversized_manifest_is_rejected() {
    // The loader and the package section share one rule set, so the manifest cap (256 entries)
    // also bounds the manifest a host registers directly.
    let manifest: Vec<(EventName, String)> = (0..257)
        .map(|index| {
            (
                EventName::from_string(format!("test::wasm::h{index:03}")),
                "handler".to_string(),
            )
        })
        .collect();
    let err = try_load("(module)", manifest).unwrap_err();
    assert!(
        matches!(err, WasmHandlerLoadError::InvalidManifest(_)),
        "unexpected error: {err}"
    );
}

#[test]
fn missing_memory_export_is_rejected_at_load() {
    // Every host function that takes a guest pointer needs the `memory` export, so a module
    // without it is refused at load, not at the first host call.
    let wat_src = r#"(module (func (export "handler")))"#;
    let err = try_load(wat_src, vec![(EVENT, "handler".to_string())]).unwrap_err();
    assert!(
        matches!(err, WasmHandlerLoadError::MissingMemoryExport),
        "unexpected error: {err}"
    );
}

#[test]
fn empty_manifest_names_are_rejected() {
    let empty_event = vec![(EventName::new(""), "handler".to_string())];
    let err = try_load("(module)", empty_event).unwrap_err();
    assert!(
        matches!(err, WasmHandlerLoadError::InvalidManifest(_)),
        "unexpected error: {err}"
    );

    let empty_export = vec![(EVENT, String::new())];
    let err = try_load("(module)", empty_export).unwrap_err();
    assert!(
        matches!(err, WasmHandlerLoadError::InvalidManifest(_)),
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
