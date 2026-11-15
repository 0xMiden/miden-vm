# Native symbolic arithmetic provenance

This module owns the expression arithmetic used by native AIR inputs. It adapts the generic tree,
constant folding, base lifting, concrete field conversions and flattened serde representation from
`p3-air` **0.8.0**. It does not depend on upstream AIR traits, symbolic builders or variable wrappers.
The symbolic trees are independent of upstream AIR builders and variable wrappers.

## Pinned independent source

The allowed base lockfile pins crate archive SHA-256
`be7a317aa82ba3d758229db6dd1e2baa75f9aa6f1179d98b3b1e0c2c6b930d59`.
The local registry archive and unpacked arithmetic files were compared byte-for-byte.
`.cargo_vcs_info.json` identifies independent upstream
[`Plonky3/Plonky3` commit a21e3ed42905040ad49c519e402f018381c12d0c](https://github.com/Plonky3/Plonky3/tree/a21e3ed42905040ad49c519e402f018381c12d0c),
package path `air`. Exact upstream source lengths and hashes are recorded in
[provenance.json](provenance.json). They identify the inputs, not the modified local output.

| Upstream file | Adapted local responsibility |
|---|---|
| `src/symbolic/mod.rs` | `tree.rs`: Arc-backed Add/Sub/Neg/Mul, identity/constant folding, cached raw degrees, Dup/ring/arithmetic traits |
| `src/symbolic/expression.rs` | `base.rs`: base constants/selectors, field conversion and algebra implementations |
| `src/symbolic/expression_ext.rs` | `extension.rs`: base lifting, extension constants and non-overlapping concrete extension conversions |
| `src/symbolic/flatten.rs` | `flatten.rs`: post-order serde arena, shared-child indices and prior-only reconstruction |

The crate archive declares `MIT OR Apache-2.0` but contains neither license text. Exact texts were
retrieved from the **same pinned independent upstream commit**, through read-only GitHub file
fetches; no migrated Miden code or documentation was consulted. Their local Git blob hashes match
upstream: [LICENSE-MIT](LICENSE-MIT) `ae8393261a5c288d5efe1208b7ea3de22b861f84`,
[LICENSE-APACHE](LICENSE-APACHE) `1e5006dc141e22213c898c27abaded8d936c32f0`.
Their URLs, byte lengths and SHA-256 hashes are in the provenance record. Copyright attribution is
retained in adapted files, with notices identifying the modifications.

## Local interfaces and deliberate changes

`RowOffset::{Current,Next}`, `BaseInput` and `AuxInput` are local, field-independent addresses.
`BaseInput` distinguishes main/preprocessed current-next cells, public values and periodic values;
`AuxInput` distinguishes auxiliary current-next cells, challenges and exports. They are addresses,
not arithmetic variables. Expressions use `SymbolicExpr<BaseLeaf<F>>` and
`SymbolicExpr<ExtLeaf<F,EF>>`; extension leaves preserve complete lifted base subtrees.

The generic tree keeps upstream operand order and constant/zero/one folding. `Dup` duplicates
non-Copy trees, and arithmetic assignment uses it explicitly. Cached raw degrees keep trace inputs
and periodic inputs at degree multiple one, boundaries at one, transition at zero and uniforms at
zero. This preserves the raw diagnostic convention; it is not an actual-height capacity rule.

Old variable/window types, their arithmetic and builder-based `resolve` are omitted. Circle
transition weighting, unchecked polynomial-degree walks and unused extension-to-base lowering are
also omitted. Actual-height analysis must independently inspect addresses/arithmetic and perform
checked operations. It must not trust a cached raw degree. This also applies to trees deserialized
through serde: flattening validates topology, but does not authenticate caches, addresses or the
relation's schema.

Concrete Binomial, CubicTrinomial, QuinticTrinomial and degree-four complex-tower conversions retain
the upstream coherence boundary. A blanket `From<EF>` or `Algebra<EF>` would overlap base-field
implementations when `EF = F`, so it is not introduced. Allocation uses `alloc` (`Arc`, `Vec`,
`BTreeMap`); serde uses the existing alloc-capable dependency. No new field/backend dependency or
`std` requirement is added. Upstream tests requiring unrelated field crates were not imported.

The flattened representation preserves shared Arc children and rejects forward/self references.
Its byte shape is not a promised compatibility encoding with any other native AIR implementation,
and it is not itself a protocol identity or validated descriptor.
