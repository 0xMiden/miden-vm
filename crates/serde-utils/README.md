# Miden Serialization Utilities

This crate provides serialization and deserialization utilities for the Miden projects.

## Features

- `Serializable` and `Deserializable` traits for custom types.
- `ByteWriter` trait for writing primitive values to byte sinks.
- `ByteReader` trait for reading primitive values from byte sources.
- `SliceReader` struct - a reader implementation for reading `Deserializable` from a slice of bytes.
- `BudgetedReader` struct - a reader implementation that enforces a byte budget during deserialization.
- Support for both `std` and `no_std` environments.

## Crate Features

- `std` - enabled by default; enables standard library support.

## License

Any contribution intentionally submitted for inclusion in this repository, as defined in the Apache-2.0 license, shall be dual licensed under the [MIT](../LICENSE-MIT) and [Apache 2.0](../LICENSE-APACHE) licenses, without any additional terms or conditions.
