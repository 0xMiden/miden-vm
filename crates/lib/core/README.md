# Miden core library
Core library for Miden VM.

Miden core library provides a set of procedures which can be used by any Miden program. These procedures build on the core instruction set of [Miden assembly](../assembly) expanding the functionality immediately available to the user.

The goals of Miden core library are:
* Provide highly-optimized and battle-tested implementations of commonly-used primitives.
* Reduce the amount of code that needs to be shared between parties for proving and verifying program execution.

The second goal can be achieved because calls to procedures in the core library can always be serialized as 32 bytes, regardless of how large the procedure is.

## Available modules
Currently, Miden core library contains just a few modules, which are listed below. Over time, we plan to add many more modules which will include various cryptographic primitives, additional numeric data types and operations, and many others.

- [miden::core::collections::mmr](./docs/collections/mmr.md)
- [miden::core::collections::smt](./docs/collections/smt.md)
- [miden::core::collections::sorted_array](./docs/collections/sorted_array.md)
- [miden::core::crypto::dsa::ecdsa_k256_keccak](./docs/crypto/dsa/ecdsa_k256_keccak.md)
- [miden::core::crypto::dsa::falcon512poseidon2](./docs/crypto/dsa/falcon512poseidon2.md)
- [miden::core::crypto::hashes::poseidon2](./docs/crypto/hashes/poseidon2.md)
- [miden::core::crypto::hashes::blake3](./docs/crypto/hashes/blake3.md)
- [miden::core::crypto::hashes::keccak256](./docs/crypto/hashes/keccak256.md)
- [miden::core::crypto::hashes::sha256](./docs/crypto/hashes/sha256.md)
- [miden::core::math::u256](./docs/math/u256.md)
- [miden::core::math::u64](./docs/math/u64.md)
- [miden::core::mem](./docs/mem.md)
- [miden::core::pcs::fri::frie2f4](./docs/pcs/frie2f4.md)
- [miden::core::stark](./docs/stark/mod.md)
- [miden::core::stark::constants](./docs/stark/constants.md)
- [miden::core::stark::deep_queries](./docs/stark/deep_queries.md)
- [miden::core::stark::ood_frames](./docs/stark/ood_frames.md)
- [miden::core::stark::public_inputs](./docs/stark/public_inputs.md)
- [miden::core::stark::random_coin](./docs/stark/random_coin.md)
- [miden::core::stark::utils](./docs/stark/utils.md)
- [miden::core::stark::verifier](./docs/stark/verifier.md)
- [miden::core::sys](./docs/sys.md)
- [miden::core::word](./docs/word.md)

## Status
At this point, all implementations listed above are considered to be experimental and are subject to change.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
