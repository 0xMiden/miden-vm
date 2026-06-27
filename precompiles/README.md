# Miden precompiles

This crate is the home for concrete deferred precompile implementations used by the Miden VM.

The generic deferred-computation framework stays in [`miden-core`](../core), under `miden_core::deferred`: the node/DAG data model, the `Precompile` trait, the `PrecompileRegistry`, deferred state, and wire validation. This crate builds on that framework and provides concrete precompiles that programs can defer their semantic checks to, exposing them through a single `registry()` constructor.

## Usage

This crate exposes a `registry()` function that returns a `miden_core::deferred::PrecompileRegistry` — the registry that routes deferred tags to their owning precompile — populated with the precompiles this crate provides.

The crate also embeds the `miden::precompiles` MASM package. Link [`PrecompilesLibrary`] into an assembler/host to call the MASM wrappers and install `registry()` in the processor/prover/verifier path to validate the deferred assertions those wrappers log.

## Provided precompiles

- **Hashes** (`keccak256`, `sha512`): a reusable `preimage → digest` assertion protocol with MASM wrappers under `miden::precompiles::crypto::hashes::{keccak256,sha512}` (`hash`, `hash_bytes`, `merge`). The wrappers register generic `CHUNKS` inputs and expected digests, request the digest from a host event, then log a deferred hash assertion checked by the verifier-side registry.
- **Uint and prime-field arithmetic** (`u256`, `k1_base`, `k1_scalar`, `r1_base`, `r1_scalar`, `ed25519_base`, `ed25519_scalar`): generated MASM wrappers under `miden::precompiles::math` that register typed integer/field nodes, request untrusted helper witnesses where needed, and log assertions checked by the `UintPrecompile`.
- **Curve operations** (`secp256k1`, `secp256r1`, `ed25519`): generated MASM wrappers for curve membership, addition, doubling, scalar multiplication, and multi-scalar multiplication over the supported curve domains, checked by the `CurvePrecompile`.
- **Math-native secp256k1 ECDSA** (`ecdsa_secp256k1`): a trapping prehashed verifier exposed as `miden::precompiles::crypto::dsa::ecdsa_secp256k1::assert_verify_prehash`. It verifies raw affine secp256k1 public keys, prehashes, and `(r, s)` signatures stored as little-endian `u32` limbs. It uses the uint and curve deferred precompiles, applying the signature equation's scalar multiplications with a two-pair curve MSM.
- **Math-native Ed25519 EdDSA** (`eddsa_ed25519`): a trapping verifier exposed as `miden::precompiles::crypto::dsa::eddsa_ed25519::assert_verify`. It verifies native affine `A` and `R` points, a canonical scalar `S`, and a fixed 32-byte message. It recompresses `R` and `A` only to build the Ed25519 challenge `SHA512(R_compressed || A_compressed || message)`. The signature memory is contiguous as `R || S`.

## secp256k1 ECDSA trapping verifier ABI

`miden::precompiles::crypto::dsa::ecdsa_secp256k1::assert_verify_prehash` has stack contract:

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

## Ed25519 EdDSA trapping verifier ABI

`miden::precompiles::crypto::dsa::eddsa_ed25519::assert_verify` has stack contract:

```text
Input:  [a_ptr, sig_ptr, msg_ptr, ...]
Output: [...]
```

It is assert/trap-only and returns no boolean. `A` and `R` are supplied as native affine Ed25519 points; the MASM verifier does not decompress compressed encodings. Point and scalar limbs are stored as little-endian `u32` felts:

```text
a_ptr[0..8]      = A.x, little-endian u32 limbs over the Ed25519 base field
a_ptr[8..16]     = A.y, little-endian u32 limbs over the Ed25519 base field

sig_ptr[0..8]    = R.x, little-endian u32 limbs over the Ed25519 base field
sig_ptr[8..16]   = R.y, little-endian u32 limbs over the Ed25519 base field
sig_ptr[16..24]  = S, little-endian u32 limbs modulo the Ed25519 scalar field

msg_ptr[0..8]    = fixed 32-byte message, packed as eight little-endian u32 felts
```

The verifier builds `R_compressed || A_compressed || message[32]` in local scratch memory, hashes it with the SHA-512 precompile, reduces the 512-bit digest modulo the Ed25519 scalar field, rejects low-order `A` and `R` by checking `[8]P != identity`, and asserts:

```text
[S]B == R + [h]A
```

## Crate features

Miden precompiles can be compiled with the following features:

- `std` - enabled by default and relies on the Rust standard library.
- `no_std` does not rely on the Rust standard library and enables compilation to WebAssembly.
  - Only the `wasm32-unknown-unknown` and `wasm32-wasip1` targets are officially supported.
- `codegen-tools` - enables the generated-MASM regeneration binary used by drift checks.

To compile with `no_std`, disable default features via `--no-default-features` flag.

## License

This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.

[`PrecompilesLibrary`]: crate::PrecompilesLibrary
