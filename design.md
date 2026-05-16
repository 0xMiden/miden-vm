# Multi-app precompile schema — design notes

*Living scratchpad. Status: aligning on shape before any code.*

## Goal

Replace the current monolithic `Schema` (one trait impl owns the entire 4-felt
tag space) with a **composite of apps**, where each app is a self-contained
semantic module (Field, Curve, Keccak, …) that claims a slice of the tag
space. The framework dispatches; apps own their kinds.

This is the substrate to migrate existing precompiles (256-bit field, future
curves, hashes, signature verification) into a uniform framework.

## What currently exists (anchor)

- `core/src/deferred/schema.rs`: `Schema` trait — `decode(Tag) -> TagInfo` and
  `reduce(&Node, &mut dyn ChildResolver) -> Node`. Single impl per processor.
- `core/src/deferred/mod.rs`: `Node { tag: [Felt; 4], payload: Expression(8 felts) | Chunk(Arc<[Chunk]>) }`.
  Digest is Poseidon2 over tag (capacity) + payload (rate).
- `core/src/deferred/field0.rs` (`feature = "testing"`): reference handler.
  Tag layout `[1, 0, op, 0]`; op ∈ {0=leaf, 1=add, 2=mul, 3=assert_eq}.
- `core/src/deferred/state.rs`: `DeferredState` (DAG + root). Carried through
  `ExecutionOutput`/`TraceBuildOutput` and the verifier's transcript walk.
- Processor: `FastProcessor` holds a single `deferred_schema: Box<dyn Schema>`,
  defaults to `NoopSchema`.

## Proposal (as understood from user, pending grill answers)

### Terminology

- **App** — a self-contained semantic module (Field, Curve, Keccak, …).
  Owns a small enum of *node discriminants* and an optional *immediate* per
  tag. Parameterised: `Field<P>` over a prime, `Curve<C>` over curve params.
- **App ID** — felt derived by hashing `(app_name, params, discriminant_list)`
  with a weak hash (Blake3 → felt). Two instances of `Field` with different
  primes have different IDs.
- **Schema ID** — felt derived by hashing `(version_domsep, sorted_app_ids…)`.
  Commits to the exact composition.
- **AppTag** — the per-app 2-felt portion of the global tag: `(node_disc, imm)`.
- **PrecompileSchema** — the composite installed on the processor. Holds a
  `Vec<Box<dyn App>>` (open question: dyn vs static tuple). Implements the
  existing `Schema` trait by strip-and-forward.

### Tag layout (Option A, current preference)

```
[schema_id, app_id, node_disc, imm]
```

Alt (Option B): `[schema_app_id, node_disc, imm0, imm1]` if we ever need two
immediates. Defer until forced.

### Catalogue of apps (initial set)

- `Field<P>`: `add`, `sub`, `mul`, `value` (leaf), `eq` (predicate).
- `Curve<C>`: `combine [Field<C::Base>.leaf; 2]`, `add`, `sub`, `eq`.
  Requires `Field<C::Base>` and `Field<C::Scalar>`.
- `Keccak`: chunk `preimage(n_bytes)`, leaf `digest`, `eq`.
- `Sha512`: chunk `preimage(n_bytes)`, chunk-2 `digest`, `eq`.
- `Ecdsa`: chunk `sig` (predicate; verifies against embedded msg+pubkey).
- `Eddsa`: chunk `sig` (predicate; ditto).

### Existing reference

`Field0Handler` stays as-is for now (legacy single-schema reference), retired
once `Field<P>` lands as an app.

## Open questions (block design before they're answered)

**Q1. What is `schema_id` for, given one schema is installed at a time?**
Candidates: cross-context binding (program binaries committing to schema),
recursive proofs (parent commits to child's schema). If neither matters, drop
it from the on-wire tag and reclaim the felt.

**Q2. App dependencies — runtime invocation, or static assertion?**
Likely (a)+(b): composite refuses to build without declared deps; deps are
expressed as IDs that the dependent app is constructed with (so e.g. `Curve`
knows how to mint a `Field` leaf tag).

**Q3. Tag-minting from one app to another.** `curve.add` outputs a curve point
whose coordinates are field leaves. The curve app must construct field-tagged
nodes during canonicalisation → it must hold the field's app_id.

**Q4. Curve-point data model.** Is a curve point an expression node with two
field-leaf digests in its payload, or a chunk with 16 inline felts, or
something else? Affects degree/witness size.

**Q5. Immediate slot usage.** Only `keccak.preimage` / `sha512.preimage` seem
to need it (n_bytes). Confirm no other app needs two. If confirmed, lock in
Option A.

**Q6. ID hash strength.** Weak hash (Blake3→felt) gives ~32-bit birthday
security per ID. Fine for ~tens of apps; check whether the design ever scales
to hundreds of parameter-instantiated apps.

**Q7. App trait shape.** Strawman:

```rust
trait App {
    fn id_inputs(&self) -> AppIdInputs;
    fn decode(&self, local: AppTag) -> Result<TagInfo, _>;
    fn reduce(&self, node: &Node, children: &mut dyn ChildResolver) -> Result<Node, _>;
}
```

Confirm — does the app see only `AppTag` (composite strips schema_id/app_id)
or does it see the full `Tag`?

**Q8. `Field0Handler` lifecycle.** Keep as legacy reference until `Field<P>`
exists? Or migrate it first as the smallest possible app to prove the
framework works?

**Q9. Crate location.** Confirm: everything new lives in `core/src/deferred/`,
no new crate.

**Q10. Sig verification semantics.** A sig is a chunk-shaped predicate node.
Pubkey + message — embedded in the chunk, or referenced by child digests?
Affects whether `Ecdsa`/`Eddsa` fit the chunk-app mold or need extra structure.

## Alternatives sketched

- **Static composition (`tuple`-based) instead of `Vec<Box<dyn App>>`.** Faster
  dispatch, compile-time dep-checking via trait bounds, but every schema is its
  own concrete type. Reasonable v2; v1 stays dyn for ergonomics.
- **Drop `schema_id` from tag if Q1 says we don't need it.** Frees the felt
  for a second immediate (Option B collapses into Option A's slot count).
