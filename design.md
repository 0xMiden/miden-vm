# Multi-app precompile schema — design notes

*Living scratchpad. Status: shape converging; minting model is the live open question.*

## Goal

Replace the current monolithic `Schema` with a **composite of apps**. Each app
is a self-contained semantic module (Field, Group, Keccak, Sha512, Sig …)
that claims a slice of the tag space. The composite dispatches; apps own their
node kinds.

Substrate to migrate every existing precompile (256-bit field, future curves,
hashes, signature verification) into one uniform framework.

## Anchor: what exists today

- `core/src/deferred/schema.rs`: `Schema` trait — `decode(Tag) -> TagInfo` and
  `reduce(&Node, &mut dyn ChildResolver) -> Node`. Single impl per processor.
- `core/src/deferred/mod.rs`: `Node { tag: [Felt; 4], payload: Expression(8 felts) | Chunk(Arc<[Chunk]>) }`.
  Digest = Poseidon2 over tag (capacity) + payload (rate).
- `core/src/deferred/field0.rs` (`feature = "testing"`): reference handler.
- `core/src/deferred/state.rs`: `DeferredState` (DAG + root), now carried
  through `ExecutionOutput` / `TraceBuildOutput` and the verifier's transcript
  walk.

## Decisions so far

### Tag layout

```
[app_id, node_disc, imm, ZERO]
```

- `schema_id` dropped. Versioning rolls into `app_id` (the app's ID hash mixes
  in a version felt). Two schemas sharing an app safely share its app_id; if
  the app changes shape, the version bumps and the id moves.
- One immediate is enough. Chunk apps use `imm = n_bytes` (covers both number
  of chunks and last-chunk padding). Sigs have no imm. Field/Group ops have no
  imm.
- 4th felt reserved zero for now. Keep available; promote to `imm1` if a
  future app needs two.

### Apps (initial set, scoped down)

- **`Uint256`** — promote `Field0` to a properly-app-shaped handler with
  wrapping (mod 2^256) semantics. Discriminants: `value` (leaf), `add`,
  `sub`, `mul`, `eq`.
- **`MockGroup<F>`** (over `Uint256`) — minimal "group-element" app to
  exercise inter-app composition. Discriminants: `combine` (self-evaluating
  bin-op: payload = `digest(x) || digest(y)`, x and y are `F` nodes),
  `add`, `sub`, `eq`. Group arithmetic is fake/placeholder — just enough
  to exercise the framework.
- Later: `Keccak`, `Sha512`, `Ecdsa`/`Eddsa`-style sigs.

### Composite

- `PrecompileSchema { apps: BTreeMap<Felt /* app_id */, Box<dyn App> }`.
  Order doesn't matter (no schema_id binds it).
- Implements `Schema` by `tag[0]` lookup → forward to the app's local
  `decode` / `reduce`.

### Dependency declaration: dropped

No "requires" mechanism. Apps that consume another app's tags (Group reading
Field digests) hold the other app's `app_id` as a constructor arg, so they
can mint correctly-tagged children and recognise resolved-child tags.
Mis-composition fails at runtime.

### `Field0Handler` lifecycle

Repurpose into `Uint256` as the very first concrete app. No legacy keep-around.

## App trait — strawman

```rust
struct AppTag {
    pub node_disc: Felt,
    pub imm: Felt,
}

trait App: core::fmt::Debug + Send {
    /// Stable ID derived from (name, version, params, discriminant list).
    /// Returned pre-computed; app caches it at construction.
    fn id(&self) -> Felt;

    /// Decode the app-local tag (the bits the composite hasn't claimed).
    fn decode(&self, local: AppTag) -> Result<TagInfo, SchemaError>;

    /// Reduce a node owned by this app.
    fn reduce(
        &self,
        node: &Node,
        children: &mut dyn ChildResolver,
        interner: &mut dyn NodeInterner,  // OPEN — see Q-mint
    ) -> Result<Node, SchemaError>;
}

trait NodeInterner {
    fn intern(&mut self, node: Node) -> Digest;
}
```

## Minting model (decided: M1)

`Group::add(g1, g2)` reduces by:

1. Resolve `g1` and `g2` to canonical `Group::combine(h_x, h_y)` leaves.
2. Resolve each field digest to a field leaf, decode limbs.
3. Compute `(x3, y3)` via the group op.
4. **Mint** new field leaves `Field::leaf(x3)`, `Field::leaf(y3)`, getting back
   `h_x3` and `h_y3`.
5. Return `Group::combine(h_x3, h_y3)`.

This requires extending the `reduce` API with a `NodeInterner` so apps can
intern auxiliary canonical nodes mid-reduce. Both prover-side
(`DeferredState`) and verifier-side reducers implement it. Determinism of
reduce ensures both sides mint identical digests.

## Group::combine reduce semantics (decided)

`Group::combine(h_x, h_y)` recurses: resolve `h_x` and `h_y`, take the canonical
forms' digests, return `Group::combine(h_x_canon, h_y_canon)`. This guarantees
any canonical group element references field **leaves** (not field
expressions) — `Group::add` and friends can therefore trust that resolved
group children's payload digests are already field-leaf digests, no further
canonicalisation needed inside the math kernel.

## App cross-read (decided)

Apps don't need typed access to other apps. `ChildResolver::resolve` dispatches
on `tag[0]` (`app_id`) and forwards to the right app's `reduce`, so a Group app
reading a field-leaf digest just calls `children.resolve(h_x)` and gets back a
canonical field-leaf node. The Group app holds the Field app's `app_id` as a
constructor arg so it can (a) mint correctly-tagged field leaves and (b)
sanity-check resolved-child tags.

Coupling on payload encoding (group app knowing field leaves are 8 u32-limbs
little-endian) is handled by exposing constructor/decoder helpers from the
field app's module — e.g. `Uint256::leaf_node(limbs) -> Node`,
`Uint256::limbs_of(&Node) -> Result<[u32; 8]>`. Not a trait method, just public
helpers on the concrete app type.

## v1 scope (decided)

Four apps:

- **`Uint256`** — promote Field0 with wrapping semantics. No minting needed.
- **`MockGroup<F>`** — exercises minting + cross-app composition.
- **`MockHash`** — chunk preimage → digest leaf (mint), `digest` leaf
  (self-evaluating), `eq` predicate. Mock hash function (e.g. linear-hash via
  Poseidon2 over chunks, or even simpler XOR-fold for v1). Exercises
  chunk-bodied input → expression-bodied output.
- **`MockSig`** — single discriminant `verify` (chunk-bodied predicate; payload
  is opaque `sig || pk || msg`). Reduces to TRUE on a stub check (e.g. n>0).
  Exercises chunk-bodied predicate. No imm.

## Open questions (next round)

**Q-interner-api** — strawman:

```rust
trait NodeInterner {
    /// Intern `node` (idempotent by digest). Returns the node's digest.
    /// Caller is responsible for ensuring `node` is in canonical form.
    fn intern(&mut self, node: Node) -> Digest;
}
```

Both `DeferredState` (prover) and the verifier's witness-side store implement
it. Reduce's signature becomes:

```rust
fn reduce(
    &self,
    node: &Node,
    children: &mut dyn ChildResolver,
    interner: &mut dyn NodeInterner,
) -> Result<Node, SchemaError>;
```

Concern: the `Schema` trait gets a third resolver-ish parameter. Could combine
into a single `ReduceCtx` trait that bundles both, but at the cost of one more
indirection. Vote one way.

**Q-chunk-tag-imm-binding** — chunk-app tags must encode `n` somehow so
`decode(tag)` can return `BodyShape::Chunk(n)`. Options:
- (a) `imm = n_bytes` (or `n_chunks`). The decode reads `imm` into `BodyShape::Chunk`.
- (b) Fixed-size chunks per discriminant (e.g. `MockSig::verify` always 5 chunks).
  `imm` unused; decode returns the fixed constant.

For `MockHash::preimage`: variable, so (a). For `MockSig::verify`: you said no
imm, so (b) — hardcode n. Confirm.

**Q-impl-order** — three options:
- (a) Build the `App` trait + composite + extend `Schema::reduce` first, then
  migrate Field0 → Uint256, then add MockGroup with minting, then mocks.
- (b) Migrate Field0 → Uint256 first (no minting needed — proves the trait
  works on the simplest case without framework changes), then introduce the
  interner extension together with MockGroup, then add the mocks.
- (c) Top-down: scaffold all four apps with stubs, then fill in semantics.

I'd vote (b): minimum disruption per step, each step shippable
independently. The interner change rides in with the first app that needs it
(MockGroup), so it isn't speculative.

## Alternatives parked

- Static-tuple composition (compile-time-known apps). Faster, no allocation,
  but every schema is its own concrete type. Defer; dyn map is fine for v1.
- 4-slot `[schema_id, app_id, node, imm]` tag — dropped (version rolls into
  `app_id`).
- Bundled `ReduceCtx` instead of separate `children` + `interner` —
  consider only if the parameter list gets unwieldy.
