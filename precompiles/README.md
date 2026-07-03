# Miden precompiles
This crate is the home for concrete precompile implementations used by Miden VM's deferred framework.

The generic deferred-computation framework stays in [`miden-core`](../core), under `miden_core::deferred`: the node/DAG data model, the `Precompile` trait, the `PrecompileRegistry`, deferred state, and wire validation. This crate builds on that framework and provides the concrete precompiles that programs can defer their semantic checks to, exposing them through a single `registry()` constructor.

## Usage
This crate exposes a `registry()` function that returns a `miden_core::deferred::PrecompileRegistry` — the registry that routes deferred tags to their owning precompile — populated with the precompiles this crate provides.

## Provided precompiles
- **Hashes** (`keccak256`): a `preimage` → `digest` reduction plus an `eq` predicate, used by bundled MASM support code for core hash facades.
- **Math-native secp256k1 ECDSA** (`ecdsa_secp256k1`): a trapping prehashed verifier used by bundled MASM support code. It verifies raw affine secp256k1 public keys, prehashes, and `(r, s)` signatures stored as little-endian `u32` limbs. It uses the UInt and curve precompiles, applying the signature equation's scalar multiplications with a two-pair curve MSM.

## secp256k1 ECDSA trapping verifier ABI

The internal secp256k1 ECDSA support wrapper has stack contract:

```text
Input:  [pubkey_ptr, digest_ptr, sig_ptr, ...]
Output: [...]
```

It is assert/trap-only and returns no boolean. All pointers are element addresses and must be double-word aligned (`ptr % 8 == 0`). Public-key coordinates, the prehash, and signature scalars are 256-bit integers stored as 8 little-endian `u32` limbs, one limb per felt:

```text
pubkey_ptr[0..8]   = qx, little-endian u32 limbs
pubkey_ptr[8..16]  = qy, little-endian u32 limbs

digest_ptr[0..8]   = prehash z, little-endian u32 limbs

sig_ptr[0..8]      = r, little-endian u32 limbs
sig_ptr[8..16]     = s, little-endian u32 limbs
```

The verifier traps on malformed limbs, non-canonical scalars, invalid/off-curve public keys, `r = 0`, or a failed ECDSA equation. `s = 0` is rejected by the existing `k1_scalar::inv(s)` path rather than a separate zero check. Because secp256k1 has cofactor 1, the verifier assumes the curve-membership check is sufficient and does not perform a separate subgroup check.

`assert_verify_prehash` registers `[u1]G + [u2]Q` as one two-pair curve MSM over scalar/point digest pairs.


## Crate features
Miden precompiles can be compiled with the following features:

* `std` - enabled by default and relies on the Rust standard library.
* `no_std` does not rely on the Rust standard library and enables compilation to WebAssembly.
    * Only the `wasm32-unknown-unknown` and `wasm32-wasip1` targets are officially supported.

To compile with `no_std`, disable default features via `--no-default-features` flag.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
