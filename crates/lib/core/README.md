# Miden core library
Core library for Miden VM.

Miden core library provides a set of procedures which can be used by any Miden program. These procedures build on the core instruction set of [Miden assembly](../../assembly) expanding the functionality immediately available to the user.

The goals of Miden core library are:
* Provide highly-optimized and battle-tested implementations of commonly-used primitives.
* Reduce the amount of code that needs to be shared between parties for proving and verifying program execution.

The second goal can be achieved because calls to procedures in the core library can always be serialized as 32 bytes, regardless of how large the procedure is.

`CoreLibrary` provides the `miden-core` Miden package (a `.masp` file) in addition to its associated event handlers. This package occupies the `miden::core` namespace.

Generated core-library MASM can be inspected locally:

```sh
cargo run -p miden-core-lib-codegen -- --out target/miden-core-lib-generated-asm
```

Complete generated verifier MASM is tracked in `asm/sys/vm` and `asm/sys/pvm` beside handwritten assembly. The build assembles a copy under `OUT_DIR` (`MIDEN_CORE_ASM_DIR` for tests), without compiling AIR definitions. After changing the AIRs or typed templates, run `make regenerate-verifiers`, then `make check-verifiers` to check regeneration, independent evaluator checks, and pinned verifier roots. `make stage-verifiers DIR=<path>` checks and copies the complete tree for inspection or release tooling.

Documentation builds also write under `OUT_DIR` by default. Run
`make regenerate-core-docs` to update the published API documentation explicitly,
or `make check-core-docs` to check it without changing the checkout.

## Caller-maintained precompile roots

Deferred precompile procedures have `_with_root` variants that return an independent obligation
without changing the VM's built-in deferred root. They take the same ordinary arguments as their
native counterparts and return `[ROOT, ordinary results..., ...]`. Assertions and signature
verification return only ROOT. Memory hashes also return only ROOT and write their digest to
memory, retaining their encoding, alignment, padding, overlap, and length-limit contracts.

A single-binding operation returns its registered assertion directly. A compound operation combines
all of its own advice-binding assertions into one root. Callers explicitly combine these independent
roots with `precompiles::append_root`; no operation takes the caller's accumulator as an argument.
Comparisons can return false successfully: ROOT binds the values used to compute their result rather
than asserting the result is true. Expression constructors, arithmetic expressions, loads,
reductions, and MSM remain shared and produce no obligation.

`precompiles::append_root` takes `[LHS_ROOT, RHS_ROOT, ...]` and returns the exact digest of
`AND(LHS_ROOT, RHS_ROOT)`, registering and hashing the same ordered payload without logging. Both
children must be registered true assertions or implicit TRUE. The helper also combines independently
built roots, and does not simplify TRUE children.

`precompiles::append_root_ptr` takes `[ROOT_PTR, ASSERTION, ...]` and updates a word-aligned
root in memory to `AND(ROOT, ASSERTION)`, preserving the operand-stack tail. AND obligations are
commutative, so callers can use the existing stack order; swapping children changes their digest
without changing the obligations.

```masm
use miden::core::precompiles::fields::k1_scalar
use miden::core::precompiles::hashes::sha256
use miden::core::precompiles
use miden::core::sys

begin
    exec.k1_scalar::push_two_digest
    exec.k1_scalar::inv_with_root
    # => [INV_ROOT, INV_TWO_EXPR, ...]
    swapw
    # => [INV_TWO_EXPR, INV_ROOT, ...]
    exec.k1_scalar::push_two_digest
    exec.k1_scalar::mul
    exec.k1_scalar::push_one_digest
    exec.k1_scalar::assert_eq_with_root
    # => [EQUALITY_ROOT, INV_ROOT, ...]
    exec.precompiles::append_root
    # => [ROOT2, ...]

    # Hash the packed bytes "abc" and explicitly include the returned obligation.
    push.6513249 push.128 mem_store
    push.256 push.3 push.128
    exec.sha256::hash_bytes_mem_with_root
    # => [HASH_ROOT, ROOT2, ...] (digest written to address 256)
    exec.precompiles::append_root
    # => [ROOT3, ...]
    adv.export_deferred_witness
    exec.sys::truncate_stack
end
```

Export validates the selected root and regenerates its portable witness on every call, then stores
it under the original digest, replacing any existing advice value. A preloaded or program-created
dummy entry cannot suppress export. Failed validation, export or advice-budget checks leave an
existing entry unchanged. Both stacks and the VM's built-in root are preserved; there is no export
cache. Consumers must still validate the witness and bind its reconstructed root to an independently
established expected digest. Skip export for an untouched literal TRUE root: no obligation was
created, and literal TRUE cannot be exported.

Registration evaluates assertions eagerly in the host, but a VM proof with an unchanged built-in
root does not prove these caller-maintained obligations. Callers must retain the final root and
arrange its proof and verification separately. `open_value` adds no obligation and still requires
an already-bound canonical VALUE digest; an arbitrary expression digest does not meet that contract.

Native ECDSA and EdDSA entry points keep their stack interfaces and acceptance rules. Their shared
algorithm bodies build a complete obligation graph, and the native wrapper logs that graph once.
Algorithm phases keep their obligations on the stack, combining them as intermediate values are
consumed.
This changes their deferred commitment digests and can change their cycle counts.

## Available modules
Currently, Miden core library contains just a few modules, which are listed below. Over time, we plan to add many more modules which will include various cryptographic primitives, additional numeric data types and operations, and many others.

- [miden::core::collections::mmr](./docs/collections/mmr.md)
- [miden::core::collections::smt](./docs/collections/smt.md)
- [miden::core::collections::sorted_array](./docs/collections/sorted_array.md)
- [miden::core::crypto::aead_eidos](./docs/crypto/aead_eidos.md)
- [miden::core::crypto::dsa::ecdsa_k256_keccak](./docs/crypto/dsa/ecdsa_k256_keccak.md)
- [miden::core::crypto::dsa::ecdsa_p256_sha256](./docs/crypto/dsa/ecdsa_p256_sha256.md)
- [miden::core::crypto::dsa::eddsa_25519_sha512](./docs/crypto/dsa/eddsa_25519_sha512.md)
- [miden::core::crypto::dsa::falcon512_eidos](./docs/crypto/dsa/falcon512_eidos.md)
- [miden::core::crypto::ecdh::ecgfp5](./docs/crypto/ecdh/ecgfp5.md)
- [miden::core::crypto::hashes::eidos](./docs/crypto/hashes/eidos.md)
- [miden::core::crypto::hashes::blake3](./docs/crypto/hashes/blake3.md)
- [miden::core::crypto::hashes::keccak256](./docs/crypto/hashes/keccak256.md)
- [miden::core::crypto::hashes::sha256](./docs/crypto/hashes/sha256.md)
- [miden::core::crypto::ies::ecgfp5_eidos](./docs/crypto/ies/ecgfp5_eidos.md)
- [miden::core::math::u256](./docs/math/u256.md)
- [miden::core::math::u64](./docs/math/u64.md)
- [miden::core::mem](./docs/mem.md)
- [miden::core::pcs::fri::frie2f4](./docs/pcs/fri/frie2f4.md)
- [miden::core::stark](./docs/stark.md)
- [miden::core::stark::constants](./docs/stark/constants.md)
- [miden::core::stark::deep_queries](./docs/stark/deep_queries.md)
- [miden::core::stark::ood_frames](./docs/stark/ood_frames.md)
- [miden::core::stark::public_inputs](./docs/stark/public_inputs.md)
- [miden::core::stark::random_coin](./docs/stark/random_coin.md)
- [miden::core::stark::security](./docs/stark/security.md)
- [miden::core::stark::utils](./docs/stark/utils.md)
- [miden::core::stark::verifier](./docs/stark/verifier.md)
- [miden::core::sys](./docs/sys.md)
- [miden::core::word](./docs/word.md)

## Status

At this point, all implementations listed above are considered to be experimental and are subject to change.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
