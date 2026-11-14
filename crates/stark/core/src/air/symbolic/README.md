# Symbolic AIR provenance

This directory is derived from the six `air/src/symbolic/*.rs` files shipped in
`p3-air` **0.8.0**, the exact version locked by this workspace when the fork was made.
The source crate archive has SHA-256
`be7a317aa82ba3d758229db6dd1e2baa75f9aa6f1179d98b3b1e0c2c6b930d59`.
Its `.cargo_vcs_info.json` identifies upstream revision
`a21e3ed42905040ad49c519e402f018381c12d0c`, with `path_in_vcs` set to `air`.

The upstream code is Copyright (c) 2022 The Plonky3 Authors, licensed under
**MIT OR Apache-2.0**. Both license texts, read from that exact upstream revision,
are preserved beside this file. Source file headers identify the copied code.

The native implementation owns a unified expression representation. `Expr<F, EF, Base>`
and `Expr<F, EF, Extension>` share operation storage while retaining their authored algebraic
domains. Inline leaves support the ring's associated constants; immutable operation nodes use
`Arc` sharing. Construction is private, and borrowed expression views provide inspection.
`BaseInput` and `AuxInput` remain field-independent addresses with explicit current/next rows.
Checked native capture constructs expression-valued rows once, and its private `SymbolicSink`
records every assertion in global order together with owned diagnostics.

The operation vocabulary preserves sums, products, typed linear combinations, powers,
power-of-two scaling, and boolean checks in addition to ordinary ring arithmetic. Every
operation produces one expression value. Quadratic-extension squares use Plonky3's default
arithmetic expansion; XOR, XOR3 and ANDN retain their polynomial expansions. Same-type
`Algebra<Self>` batched-linear-combination calls still follow Plonky3's blanket implementation;
heterogeneous linear combinations are recorded directly.

The version-2 topological serialization preserves operation sharing and reconstructs checked
degree information rather than accepting cached degrees from the wire. The native relation
fingerprint uses `miden.native-air.source` and actual operation data; allocation
addresses, node IDs, diagnostics, and phantom extension parameters are excluded. The runtime
relation descriptor remains independent of the captured expression representation and contains
checked degree recipes for actual trace heights.

The constraint compiler owns the captured symbolic assertions and derives their scalar
arithmetic graph directly. Native Rust generation borrows those expressions through a temporary
index for structural CSE, use counts, and preparation slots. One emitter preserves authored
operation boundaries; ACE and arithmetic analyses consume the deterministic lowering.
The captured expressions and derived graph are immutable through the program interface.

The upstream trait builder, variable wrappers, and builder-based expression
resolution were removed. Evaluation uses the native immutable frame, uniform
inputs, and separate mutable sink. Constraint layout and alpha decomposition live
in the native AIR analysis module. Raw degree queries remain diagnostic helpers; actual-height capacity queries use the checked
native degree profile, independently of expression caches. Arithmetic,
flattening, and serialization tests remain; native capture, kernel, and degree-profile
tests cover the replacement interfaces. Tests use the existing Goldilocks field and
its quadratic extension. The upstream complex-tower conversion remains, while its
test requiring the unrelated Mersenne31/QM31 dependency is omitted.

The original source hashes below allow the exact copied inputs to be verified;
they intentionally describe the unmodified upstream files, before local imports,
headers and unit-test field substitutions.

| Upstream filename | SHA-256 |
| --- | --- |
| `builder.rs` | `db31d468a62d7b3d27fe039d0eb9217ae2dd9d21cd5dfaa0c6279bff6483ebf0` |
| `expression.rs` | `a168a38b2dbd7f5053c003e4bc4838514df7e0df4a7ef050a9d18a0c73fed2f4` |
| `expression_ext.rs` | `2878fd86061eb7896b4829cc2f4c336607559145c1e9054813ef20b452ea2d30` |
| `flatten.rs` | `11341b376739654f433a1077950fbdbe0e896f27097e3a6a950c65c49d1ca384` |
| `mod.rs` | `0c40d4ee95ed43e691fd47b30d21446b38357f6adf307b38eb65d583409a9a22` |
| `variable.rs` | `ee956530752af34616102c1d6bd1e14b12fb1226f84e45505d836c2f02833906` |
