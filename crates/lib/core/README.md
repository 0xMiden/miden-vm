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

## Caller-maintained precompile roots

Deferred precompile procedures have `_with_root` variants for programs that accumulate their own
obligations without changing the VM's built-in deferred root. Field/uint and curve operations take
the caller's four-felt root after their ordinary arguments and append every advice-binding
assertion. Start with the implicit TRUE digest (`padw`). Evaluation, inversion/division, and
predicates return `[ordinary results..., NEXT_ROOT, ...]`; assertions return only `NEXT_ROOT`.
Comparisons can return false successfully: the root binds the values used to compute their result
rather than asserting the result is true. Expression constructors, arithmetic expressions, loads,
reductions, and MSM remain shared; they take no root.

Hash and signature procedures take the same arguments as their original procedures and return
`[ROOT, ordinary results..., ...]`. They build an independent obligation, which the caller must
include in its own root using `precompiles::append_root`. A hash returns its registered assertion
directly, without an initial AND with TRUE; a signature returns its complete graph, including all
nested advice bindings. Memory hashes write the digest to memory and return only ROOT, retaining
their existing encoding, alignment, padding, overlap, and length-limit contracts.

`precompiles::append_root` takes `[ASSERTION, ROOT, ...]` and returns the exact digest of
`AND(ROOT, ASSERTION)`, registering and hashing the same ordered payload without logging. Both
children must be registered true assertions or implicit TRUE. The helper also combines independently
built roots, and does not simplify TRUE children.

```masm
use miden::core::precompiles::fields::k1_scalar
use miden::core::precompiles::hashes::sha256
use miden::core::precompiles
use miden::core::sys

begin
    padw
    exec.k1_scalar::push_two_digest
    exec.k1_scalar::inv_with_root
    # => [INV_TWO_EXPR, ROOT1, ...]
    exec.k1_scalar::push_two_digest
    exec.k1_scalar::mul
    exec.k1_scalar::push_one_digest
    exec.k1_scalar::assert_eq_with_root
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

Export preserves the selected root and writes its portable witness to the advice map under that
digest. Skip export for an untouched TRUE root: no obligation was created, and the export
instruction rejects literal TRUE. Registration evaluates assertions eagerly in the host, but a VM proof with an unchanged
built-in root does not prove these caller-maintained obligations. Callers must retain the final
root and arrange its proof and verification separately. `open_value` adds no obligation and still
requires an already-bound canonical VALUE digest; an arbitrary expression digest does not meet
that contract.

Native ECDSA and EdDSA entry points keep their stack interfaces and acceptance rules. Their shared
algorithm bodies build an obligation graph from TRUE, and the native wrapper logs that graph once.
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
- [miden::core::crypto::hashes::eidos](./docs/crypto/hashes/eidos.md)
- [miden::core::crypto::hashes::blake3](./docs/crypto/hashes/blake3.md)
- [miden::core::crypto::hashes::keccak256](./docs/crypto/hashes/keccak256.md)
- [miden::core::crypto::hashes::sha256](./docs/crypto/hashes/sha256.md)
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
