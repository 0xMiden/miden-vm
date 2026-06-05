# Miden precompiles
This crate is the home for concrete deferred precompile implementations used by Miden VM.

The generic deferred-computation framework stays in [`miden-core`](../core), under `miden_core::deferred`: the node/DAG data model, the `Precompile` trait, the `PrecompileRegistry`, deferred state, and wire validation. This crate builds on that framework and provides the concrete precompiles that programs can defer their semantic checks to, exposing them through a single `registry()` constructor.

## Usage
This crate exposes a `registry()` function that returns a `miden_core::deferred::PrecompileRegistry` — the registry that routes deferred tags to their owning precompile — populated with the precompiles this crate provides.

## Provided precompiles
- **Hashes** (`keccak256`, `sha512`): a `preimage` → `digest` reduction plus an `eq` predicate, with MASM wrappers under `miden::precompiles::crypto::hashes::{keccak256,sha512}` (`hash`, `hash_bytes`, `merge`).
- **Signatures** (`ecdsa_k256_keccak`, `eddsa_ed25519`): a single `verify` predicate over a fixed 5-chunk (40-felt) calldata buffer (`pk || digest || sig`), with a `verify_prehash` MASM wrapper under `miden::precompiles::crypto::dsa::{ecdsa_k256_keccak,eddsa_ed25519}` that registers the buffer and folds the verify statement into the deferred root.
- **Arithmetic** (`u256`): wrapping unsigned 256-bit `add`, `sub`, and `mul`; unsigned integer `div`; equality predicates; constant-digest helpers; memory loading; and expression evaluation wrappers under `miden::precompiles::math::u256`.

### U256 MASM interface

The U256 precompile keeps public operands as deferred node digests. Canonical values are encoded as one deferred data chunk containing eight little-endian u32 limbs (`VALUE_U32[8]`, least-significant limb first). The MASM wrapper module is `miden::precompiles::math::u256` and exposes:

| Procedure | Stack input | Stack output | Notes |
| --- | --- | --- | --- |
| `load` | `[ptr, ...]` | `[VALUE_DIGEST, ...]` | Registers the eight u32 felts at `ptr` as a canonical value. `ptr` must be double-word aligned because registration binds memory with `mem_stream`. |
| `push_zero` / `push_one` / `push_max` | `[...]` | `[VALUE_DIGEST, ...]` | Pushes digests of pre-initialized constants `0`, `1`, and `2^256 - 1`. |
| `add` / `sub` / `mul` / `div` | `[rhs_DIGEST, lhs_DIGEST, ...]` | `[RESULT_DIGEST, ...]` | Registers an expression node and replaces the two input digests with the result digest. Add/sub/mul wrap modulo `2^256`; div is unsigned integer division and rejects division by zero when evaluated. |
| `is_eq` | `[rhs_DIGEST, lhs_DIGEST, ...]` | `[is_equal, ...]` | Evaluates each digest, binds each advised canonical value to the deferred root, and returns `1` when the two canonical values match, otherwise `0`. It does not trap on inequality. |
| `assert_eq` | `[rhs_DIGEST, lhs_DIGEST, ...]` | `[...]` | Calls `is_eq` and asserts the returned bit, so callers opt into trapping behavior. |
| `eval` | `[EXPR_DIGEST, ...]` | `[VALUE_U32[8], ...]` | Evaluates the digest through the host, returns the eight limbs, re-registers the returned value, and logs equality between the expression and returned value to bind the advice. |

## Crate features
Miden precompiles can be compiled with the following features:

* `std` - enabled by default and relies on the Rust standard library.
* `no_std` does not rely on the Rust standard library and enables compilation to WebAssembly.
    * Only the `wasm32-unknown-unknown` and `wasm32-wasip1` targets are officially supported.

To compile with `no_std`, disable default features via `--no-default-features` flag.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
