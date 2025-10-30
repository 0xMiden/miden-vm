# miden-utils-indexing

Type-safe u32-indexed vector utilities for Miden.

This crate provides utilities for working with u32-indexed vectors in a type-safe manner, including the `IndexVec` type and related functionality.

## Main Types

### IndexVec<I, T>

A dense vector indexed by ID types that provides O(1) access and storage for dense ID-indexed data.

### DenseIdMap<From, To>

A dense mapping from ID to ID, equivalent to `IndexVec<From, Option<To>>`.

## Usage

Create typed IDs using the `newtype_id!` macro:

```rust
use miden_utils_indexing::{IndexVec, newtype_id};

newtype_id!(UserId);  // Creates a newtyped ID type

let mut users = IndexVec::<UserId, String>::new();
let alice_id = users.push("Alice".to_string()).unwrap();
let bob_id = users.push("Bob".to_string()).unwrap();

// Access by typed ID
println!("User: {}", users[alice_id]);
```

## Features

- `std` (default): Enable standard library support
- `serde`: Enable serialization/deserialization support

