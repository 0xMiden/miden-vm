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
        .chunks_exact(4)
        .map(|chunk| {
            let limb = u32::from_le_bytes(chunk.try_into().expect("chunk is 4 bytes"));
            Felt::new_unchecked(u64::from(limb))
        })
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

// The `StatePtr` safety argument relies on `ProcessorState` being `Sync`; keep that fact
// checked at compile time.
const _: () = {
    const fn assert_sync<T: Sync>() {}
    assert_sync::<miden_processor::ProcessorState<'static>>();
};

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
fn overflowing_pointer_arithmetic_is_rejected() {
    // ptr = u32::MAX; ptr + len goes far past the guest memory and must not wrap.
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
    let limits = WasmHandlerLimits { fuel: 13 * 65536 / 8 + 1000, ..Default::default() };
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
    let wat_src = format!(
        "(module {IMPORTS} (memory (export \"memory\") 16) (func (export \"handler\")))"
    );
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
fn zero_length_mutations_buffer_no_records() {
    let wat_src = fixture(
        "(call $adv_stack_extend (i32.const 0) (i32.const 0))
         (call $merkle_store_extend (i32.const 0) (i32.const 0))",
    );
    let module = load(&wat_src);
    let mutations = run(&module, &processor()).expect("handler succeeds");
    assert!(mutations.is_empty(), "empty extensions must buffer no records: {mutations:?}");
}

#[test]
fn empty_host_calls_cost_fuel() {
    // Every host call pays a flat transition charge, so a loop of zero-length extends cannot
    // burn host transitions (or accumulate mutation records) for free.
    let wat_src = fixture(
        "(local $i i32)
         (local.set $i (i32.const 100000))
         (loop $l
           (call $adv_stack_extend (i32.const 0) (i32.const 0))
           (local.tee $i (i32.sub (local.get $i) (i32.const 1)))
           (br_if $l))",
    );
    let limits = WasmHandlerLimits { fuel: 100_000, ..Default::default() };
    let module = load_with_limits(&wat_src, limits);
    let err = run_raw(&module, &processor()).expect_err("handler must run out of fuel");
    assert_run_error!(err, WasmHandlerRunError::OutOfFuel(_));
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
fn oversized_table_is_rejected_at_load() {
    // 1M funcref elements fit the fuel budget (the instantiation charge) but overstep the
    // table-element cap, so the load-time dry run refuses the eager 8 MB allocation.
    let wat_src =
        format!("(module {IMPORTS} (table 1000000 funcref) (func (export \"handler\")))");
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
fn unknown_reserved_event_names_are_rejected() {
    // The whole namespace is reserved, so a name that no system event uses is refused too.
    let manifest = vec![(EventName::new("sys::not_a_real_event"), "handler".to_string())];
    let err = try_load("(module)", manifest).unwrap_err();
    assert!(
        matches!(err, WasmHandlerLoadError::ReservedEvent { .. }),
        "unexpected error: {err}"
    );
}

#[test]
fn empty_manifest_names_are_rejected() {
    let empty_event = vec![(EventName::new(""), "handler".to_string())];
    let err = try_load("(module)", empty_event).unwrap_err();
    assert!(
        matches!(err, WasmHandlerLoadError::EmptyManifestName),
        "unexpected error: {err}"
    );

    let empty_export = vec![(EVENT, String::new())];
    let err = try_load("(module)", empty_export).unwrap_err();
    assert!(
        matches!(err, WasmHandlerLoadError::EmptyManifestName),
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
