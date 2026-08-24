# miden-test-serde-macros

Proc macros generating serde round-trip tests for Miden VM workspace types.

The `serde_test` attribute derives a `proptest` strategy for the annotated type from its
`Arbitrary` impl and asserts that values survive a binary (`Serializable`/`Deserializable`)
round trip — and, optionally, a serde (JSON-oriented) round trip:

```rust
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
#[derive(Debug, Default, PartialEq)]
pub struct MyReplayType { /* ... */ }
```

This crate is a test-only helper: it is `publish = false` and is not part of the released
workspace. It is consumed as a dev-dependency by crates that carry binary serialization of
replay or witness types and want round-trip coverage without hand-writing strategies.
