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

## Open: the minting problem (Q-mint, top priority)

`Group::add(g1, g2)` resolves two `Group::combine` leaves, recurses into their
field digests to get coords, computes `(x3, y3) = ec_add(x1, y1, x2, y2)`, and
must canonicalise to a `Group::combine` leaf whose payload is two field
digests — i.e. it must **mint two new field leaves and reference them by
digest**. Today's `reduce` returns a single node; the framework interns it
post-call. There's no way to intern auxiliary nodes mid-reduce.

Three approaches:

1. **Extend `reduce` with a `NodeInterner`.** Reduce calls
   `interner.intern(field_leaf(x3))` to get `h_x3`, same for `y3`, then
   returns the group leaf with payload `h_x3 || h_y3`. Clean, but ripples
   through `Schema::reduce`'s signature.
2. **Group leaves carry raw 16-felt coords**, not digests. No minting; reduce
   self-contained. Loses sharing of field elements across group points and
   diverges from "everything is a digest" uniformity.
3. **Group::add doesn't produce a canonical leaf** — it's a predicate
   (`add_eq(g1, g2, g3)`): the user supplies the expected sum and the app
   verifies. Side-steps minting entirely. Changes the user-facing API
   significantly.

**Leaning toward (1)** because it preserves uniformity and the change is
local. (2) is the simpler v1 if we want to defer the framework change. (3) is
viable but changes the programming model — every producing op becomes a
check, and the user has to supply expected outputs from off-chip.

## Open questions

**Q-mint** — which approach above? Decides whether v1 needs a framework change.

**Q-app-cross-read** — when `Group::add` resolves a child, it gets back a
canonical `Group::combine` leaf. To dig into its field-leaf children, it
recurses through `children.resolve(h_x)`. That works as-is: the resolver is
schema-wide and dispatches by tag. App doesn't need extra access. Confirm — or
do we want apps to be able to call into other apps directly (typed)?

**Q-id-derivation** — concrete inputs to `app_id` hash:
`H(framework_version, app_name, app_version, params_bytes, [discriminant_names…])`?
Treat `framework_version` as the single domain separator we bump if we ever
change the hashing convention itself; `app_version` for per-app evolution.
Use Blake3-to-felt (extract 64 bits of the digest).

**Q-reduce-of-self-evaluating-group** — when reduce gets a `Group::combine`
leaf, what does it return? Just clones the node (its payload's field digests
are already canonical addresses)? Or also walks the resolver to confirm the
referenced field digests resolve (and resolve to field leaves of the right
app)? Cheapest: return the clone, let consumers (Group::add) do the recursion
when they actually need coords. Confirm.

**Q-v1-scope** — `Uint256` + `MockGroup<Uint256>` enough for v1? Or also a
single-discriminant chunk-predicate app (the sig stub) to prove chunk-bodied
apps work end-to-end?

**Q-resolved-tag-validation** — when `Group::add` resolves a child and expects
"a `Group::combine` leaf of *my* group", how does it verify? `node.tag[0]`
should equal the group's `app_id` (held internally) and `node.tag[1]` should
equal the `combine` discriminant. Worth a small helper on the app side. Any
appetite for a typed view (`AppNode<G>` wrapper) instead of raw tag checks?

## Alternatives parked

- Static-tuple composition (compile-time-known apps). Faster, no allocation,
  but every schema is its own concrete type. Defer; dyn map is fine for v1.
- 4-slot `[schema_id, app_id, node, imm]` tag (the original Option A).
  Dropped per Q1 answer.
