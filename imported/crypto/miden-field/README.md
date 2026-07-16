# `miden-field`

A unified field element type for Miden Rust code that needs to run in two very different
environments:

- **Off-chain** (native, or regular Wasm): `Felt` is a thin wrapper around Plonky3’s
  `Goldilocks` field element.
- **On-chain** (Wasm compiled for the Miden VM): `Felt` is represented using Miden compiler
  intrinsics.

## Motivation

In the Miden on-chain execution environment, field elements are currently represented by the
compiler using a *Wasm primitive type* (`f32`) that the compiler “reinterprets” as a felt.
That works for on-chain code generation, but it means the on-chain `Felt` is not the same type
as the off-chain `Felt` used throughout the Rust ecosystem.

The result is that any code meant to be shared between on-chain and off-chain ends up either:

- duplicated, or
- littered with `#[cfg(...)]` gates and wrapper types to bridge the two representations.

`miden-field` exists to provide a single `miden_field::Felt` API surface that compiles in both
contexts without forcing downstream crates to pick a side.

## How it works

`miden-field` uses conditional compilation to select the backing implementation:

- `cfg(all(target_family = "wasm", miden))` (on-chain): `Felt` is a `#[repr(transparent)]`
  record with an `inner: f32` field (matching the WIT shape expected by bindings). Arithmetic
  and conversions are implemented by calling Miden compiler intrinsics (e.g.
  `intrinsics::felt::add`), and `f32` is never treated as a floating-point number.
- otherwise (off-chain): `Felt` is `#[repr(transparent)]` over `p3_goldilocks::Goldilocks` and
  implements the usual field traits. The modulus is the Goldilocks prime `2^64 - 2^32 + 1`.

The rest of the crate (e.g. `Word`) builds on top of `Felt` and therefore works in both
environments as well.

