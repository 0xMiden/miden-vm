# Miden stdlib
Standard library for Miden VM.

Miden standard library provides a set of procedures which can be used by any Miden program. These procedures build on the core instruction set of [Miden assembly](../assembly) expanding the functionality immediately available to the user.

The goals of Miden standard library are:
* Provide highly-optimized and battle-tested implementations of commonly-used primitives.
* Reduce the amount of code that needs to be shared between parties for proving and verifying program execution.

The second goal can be achieved because calls to procedures in the standard library can always be serialized as 32 bytes, regardless of how large the procedure is.

## Available modules
Currently, Miden standard library contains just a few modules, which are listed below. Over time, we plan to add many more modules which will include various cryptographic primitives, additional numeric data types and operations, and many others.

- [std::crypto::hashes::blake3](./docs/crypto/hashes/blake3.md)
- [std::crypto::hashes::keccak256](./docs/crypto/hashes/keccak256.md)
- [std::crypto::hashes::sha256](./docs/crypto/hashes/sha256.md)
- [std::pcs::fri::frie2f4](./docs/pcs/frie2f4.md)
- [std::math::u256](./docs/math/u256.md)
- [std::math::u64](./docs/math/u64.md)
- [std::math::secp256k1](./docs/math/secp256k1/group.md)
- [std::mem](./docs/mem.md)
- [std::sys](./docs/sys.md)

## Status
At this point, all implementations listed above are considered to be experimental and are subject to change.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
