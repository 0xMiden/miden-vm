# Plan: `LookupAir` / `LookupBuilder` trait pair for LogUp buses

## Context

The Miden VM currently expresses its 8 LogUp bus columns (5 main, 3 chiplet) as
top-level functions that each return a `RationalSet<'c, E, EF>` and then get
hand-stitched into `Column`s in `air/src/constraints/logup_bus/mod.rs`. The
underlying algebra is solid — `Batch` / `RationalSet` / `Column` and the
`InteractionSink` / `InteractionGroup` traits in `air/src/constraints/logup.rs`
already split the "canonical fold" from the "cached-encoding constraint
optimization." But there is no declarative shape: a `LookupAir` author still
pokes at permutation column indices, constructs `RationalSet`s by hand, and
emits constraints through `Column::constrain`.

We want a clean, closure-based API layered on top of the existing algebra:

- A `LookupAir<LB>` trait that owns the *shape* (number of permutation columns,
  max message width) and a single `eval(&self, &mut LB)` method that authors
  write once, independent of whether the caller is a constraint evaluator or a
  prover-side fraction collector.
- A `LookupBuilder` trait that is **not** a subtrait of `AirBuilder` but
  **duplicates** the associated types needed to read `main`, `public_values`,
  and `periodic_values`. It exposes trace access but hides `assert_*` /
  `when_*` / permutation plumbing, and hides the challenges from the simple
  path.
- A closure-based column/group flow: `builder.column(|col| { col.group(...) })`
  with a dual-path variant `col.group_with_cached_encoding(canonical, encoded)`
  where the `encoded` closure receives a *super-trait* handle that exposes
  `alpha()` / `beta_powers()` / `insert_encoded` for the cached-fragment
  optimization.

The immediate outcome: the existing `enforce_main` / `enforce_chiplet` in
`logup_bus/mod.rs` collapse into one `impl LookupAir<LB> for MidenLookupAir`
block, evaluated twice — once by a constraint adapter over
`LiftedAirBuilder`, once by a prover adapter that writes fractions into
per-column `Vec<(EF, EF)>` buffers. The column-index bookkeeping and the
`assert_zero_ext((acc_next - acc) * U - V)` emission move out of user code.

This plan intentionally does *not* preserve backwards compatibility with the
current `RationalSet`/`Column` surface; both are internal to the new
`lookup/` module and can be rewritten freely. The concrete `*Msg` structs in
`air/src/constraints/logup_msg.rs` are preserved and re-used: the new API
consumes `impl LookupMessage<E>` where `LookupMessage` is a renamed
`LogUpMessage` with a slightly narrower contract (bus label + contiguous
values, no `encode_sparse`).

---

## Amendment A (2026-04-10): domain-separator encoding + dynamic sizes

After Task #3's constraint adapter shipped, we reconsidered the encoding and
decided to replace the "label at β⁰" scheme with precomputed domain
separators, and to drop all compile-time size constants from the new
module's public surface. This amendment supersedes the trait signatures and
constructor sketches in the sections below wherever they disagree; the
original text is kept for history. Affected subsections carry a
"**See Amendment A**" pointer at their top.

### A.1 Encoding change

Replace
```
encode(label, v) = α + β⁰ · label + Σ_{k=0..width} β^(k+1) · v[k]
```
with
```
DS[i]            = α + i · β^W                  (W = max_message_width)
encode(i, v)     = DS[i] + Σ_{k=0..width} β^k · v[k]
```

- **Soundness**: identical. The collision polynomial `(i₁ − i₂)·β^W +
  Σ β^k·(v₁[k] − v₂[k])` has degree ≤ W in β, so collision probability
  is ≤ W/|EF|.
- **Perf**: one fewer `EF × base_field` multiplication per message on the
  prover path (no more `β⁰ · label` term). Across ~100 interactions/row,
  that is ~10⁸ fewer muls over a 10⁶-row trace. Constraint-path savings
  are smaller (one fewer symbolic tree node per encoding call), but the
  cleanup of the label-vs-payload distinction is worth it on its own.

### A.2 No compile-time size constants in the public surface

The new module must never rely on `MAX_MESSAGE_WIDTH` or a fixed
`[EF; N]` array. Sizes are dynamic, sourced from the `LookupAir` at
builder-construction time:

```rust
// air/src/constraints/lookup/challenges.rs  (new — Task #3 rework)
pub struct LookupChallenges<EF> {
    /// DS[i] = α + i · β^W, where W = max_message_width.
    /// Length = num_bus_ids.
    pub domain_separators: Box<[EF]>,
    /// β⁰, β¹, …, β^(W−1). Length = max_message_width.
    /// β^W is absorbed into `domain_separators` at construction time
    /// and never exposed.
    pub beta_powers: Box<[EF]>,
}

impl<EF> LookupChallenges<EF>
where
    EF: PrimeCharacteristicRing + Clone,
{
    pub fn new(
        alpha: EF,
        beta: EF,
        max_message_width: usize,
        num_bus_ids: usize,
    ) -> Self {
        let mut beta_powers = Vec::with_capacity(max_message_width);
        let mut cur = EF::ONE;
        for _ in 0..max_message_width {
            beta_powers.push(cur.clone());
            cur = cur.clone() * beta.clone();
        }
        // `cur` is now β^W — used only to build the DS table, never exposed.
        let mut domain_separators = Vec::with_capacity(num_bus_ids);
        let mut ds = alpha;
        for _ in 0..num_bus_ids {
            domain_separators.push(ds.clone());
            ds = ds.clone() + cur.clone();
        }
        Self {
            domain_separators: domain_separators.into_boxed_slice(),
            beta_powers: beta_powers.into_boxed_slice(),
        }
    }
}
```

**Transition allowance**: Tasks #5–#8 may keep using the old
`air/src/trace/challenges.rs::Challenges<EF>` + `MAX_MESSAGE_WIDTH` const
for code paths that still run through `LogUpMessage` / `RationalSet` /
`Column` (i.e., un-ported `logup_bus/*.rs` files). The *new* lookup module
must never reach for them. By Task #9 the old `Challenges<EF>` struct and
the `MAX_MESSAGE_WIDTH` const are both deleted.

### A.3 `LookupAir` keeps shape + eval in one trait

Original Amendment A sketch: split `LookupAir` into a non-generic
`LookupAirShape` + a generic `LookupAir<LB>: LookupAirShape`, so that
adapter constructors could read the shape without committing to a
concrete `LB`. **Reverted on reflection** — the split solved a problem
that doesn't actually exist. Keep the single trait:

```rust
pub trait LookupAir<LB: LookupBuilder> {
    /// Number of permutation columns this argument occupies.
    fn num_columns(&self) -> usize;

    /// Maximum payload width across every message the AIR emits
    /// (exclusive of the bus-ID slot — matches `LookupMessage::width`).
    fn max_message_width(&self) -> usize;

    /// Upper bound on any `LookupMessage::bus_id` value the AIR emits,
    /// plus one. The adapter pre-computes that many domain separators.
    fn num_bus_ids(&self) -> usize;

    /// Evaluate the lookup argument, describing its interactions
    /// through the builder's closure API.
    fn eval(&self, builder: &mut LB);
}
```

A single blanket `impl<LB: LookupBuilder> LookupAir<LB> for MidenLookupAir`
covers both the prover-path and constraint-path adapters; the shape
methods are written once and automatically apply to every `LB`.

**Why the split was unnecessary**: inside an adapter's `impl` block,
`Self` is the concrete builder type, so the constructor can pin `LB`
via a `Self`-referential bound:

```rust
impl<'ab, AB: LiftedAirBuilder<F = Felt>> ConstraintLookupBuilder<'ab, AB> {
    pub fn new<A>(ab: &'ab mut AB, air: &A) -> Self
    where
        A: LookupAir<Self>,   // Self = ConstraintLookupBuilder<'ab, AB>
    {
        let max_width = air.max_message_width();  // unambiguous
        let num_bus_ids = air.num_bus_ids();      // unambiguous
        // ...
    }
}
```

The bound `A: LookupAir<Self>` fixes `LB` to the adapter itself, so
trait method resolution has exactly one candidate. The blanket
`impl<LB: LookupBuilder> LookupAir<LB> for MidenLookupAir` automatically
specializes to `LookupAir<ConstraintLookupBuilder<'ab, AB>>` when the
caller passes `&MidenLookupAir`, and the shape reads are unambiguous.

The only scenario where a non-generic `LookupAirShape` would pay off is
non-generic code that needs the shape without knowing *any* builder type
— e.g. `dyn LookupAirShape` trait objects, or verifier-side code reading
the shape from a fully-erased AIR. Miden has neither: the AIR type is
statically known everywhere the shape is read, and `dyn LookupAir<LB>`
is already unusable because `LookupBuilder` has associated types.

### A.4 `LookupMessage` drops the label field

```rust
pub trait LookupMessage<E: PrimeCharacteristicRing + Clone> {
    /// Bus identifier — indexes into `LookupChallenges::domain_separators`.
    /// Must satisfy `bus_id() < LookupAirShape::num_bus_ids()`.
    fn bus_id(&self) -> u16;

    /// Number of contiguous payload values. Exclusive of the bus-ID slot.
    /// Must satisfy `width() ≤ LookupAirShape::max_message_width()`.
    fn width(&self) -> usize;

    /// Write the payload into `out`. First `self.width()` slots.
    fn write_into(&self, out: &mut [E]);
}
```

The encoding path in the adapters becomes:
```rust
let mut scratch = [E::ZERO; MAX_SCRATCH]; // sized from shape.max_message_width()
msg.write_into(&mut scratch[..msg.width()]);
let mut acc = challenges.domain_separators[msg.bus_id() as usize].clone();
for k in 0..msg.width() {
    acc += challenges.beta_powers[k].clone() * scratch[k].clone();
}
// `acc` is now the encoded denominator `v`.
```

### A.5 `EncodedLookupGroup` — drop `alpha()`, add `domain_separator(id)`

```rust
pub trait EncodedLookupGroup: LookupGroup {
    /// β⁰ … β^(W−1). Does NOT include β^W (that's absorbed into the DS).
    fn beta_powers(&self) -> &[Self::ExprEF];

    /// Lookup a domain separator by bus ID. Panics if `bus_id` ≥ num_bus_ids.
    fn domain_separator(&self, bus_id: u16) -> Self::ExprEF;

    /// Add a flag-gated interaction with a pre-computed denominator.
    /// The closure typically reads `domain_separator(id) + shared_fragment`.
    fn insert_encoded(
        &mut self,
        flag: Self::Expr,
        multiplicity: Self::Expr,
        encoded: impl FnOnce() -> Self::ExprEF,
    );
}
```

`alpha()` no longer exists on the trait. The cached-encoding pattern
becomes:

```rust
col.group_with_cached_encoding(
    |g| {
        g.add(flag_a, || HasherRequestA::new(/* ... */));
        g.add(flag_b, || HasherRequestB::new(/* ... */));
        // ...
    },
    |ge| {
        // Shared fragment has no label or alpha — just the β-weighted sum.
        let shared = ge.beta_powers()[0].clone() * addr.clone()
                   + ge.beta_powers()[1].clone() * node_index.clone();
        let ds_a = ge.domain_separator(BUS_HASHER_REQUEST_A);
        let ds_b = ge.domain_separator(BUS_HASHER_REQUEST_B);
        ge.insert_encoded(flag_a, E::ONE, || ds_a + shared.clone() + /* tail_a */);
        ge.insert_encoded(flag_b, E::ONE, || ds_b + shared.clone() + /* tail_b */);
    },
);
```

Cleaner than before: the shared fragment is truly *label-free*, so one
fragment serves every variant instead of needing a "reference label" baked
in.

### A.6 Adapter constructors take a `LookupAir` reference

```rust
impl<'ab, AB: LiftedAirBuilder> ConstraintLookupBuilder<'ab, AB> {
    pub fn new<A>(ab: &'ab mut AB, air: &A) -> Self
    where
        A: LookupAir<Self>,
    {
        let r = ab.permutation_randomness();
        let alpha: AB::ExprEF = r[0].into();
        let beta:  AB::ExprEF = r[1].into();
        let challenges = LookupChallenges::new(
            alpha,
            beta,
            air.max_message_width(),
            air.num_bus_ids(),
        );
        // ... cache permutation slices, init column_idx = 0 ...
    }
}

impl<'a, F, EF> ProverLookupBuilder<'a, F, EF> {
    pub fn new<A>(
        main: RowWindow<'a, F>,
        periodic: &'a [F],
        public_values: &'a [F],
        alpha: EF, beta: EF,
        air: &A,
        column_buffers: &'a mut [Vec<(EF, EF)>],
    ) -> Self
    where
        A: LookupAir<Self>,
    {
        let challenges = LookupChallenges::new(
            alpha, beta,
            air.max_message_width(),
            air.num_bus_ids(),
        );
        // ...
    }
}
```

The `A: LookupAir<Self>` bound uses the impl's `Self` to fix the `LB`
type parameter of `LookupAir`, so the shape reads are unambiguous. See
Amendment A.3 for why a separate `LookupAirShape` trait is unnecessary.

### A.7 Task-map deltas

| Task | Change |
|------|--------|
| #3 (rework) | Swap `Challenges<AB::ExprEF>` → `LookupChallenges<AB::ExprEF>`, drop `alpha()`, add `domain_separator(id)` on `ConstraintGroupEncoded`, plumb `shape: &S` through `new`, rewrite encoding inner loop to skip the label term. Also add `air/src/constraints/lookup/challenges.rs`. |
| #4 | Use the same `LookupChallenges<EF>` + shape-aware constructor. Prover-path sinks use concrete `F` for `Expr`; `LookupGroup` impls read bus IDs from `msg.bus_id()` and look up `self.challenges.domain_separators[id]`. |
| #5 | Update the blanket impls: each `*Msg::bus_id()` returns the existing `label_value: u16` field directly (or a renamed `bus_id` field). `write_into()` writes the payload only — no `E::from_u16(label)` prefix. The old `LogUpMessage::encode(&Challenges<EF>)` method stays intact on each struct until Task #9. |
| #6, #7 | `MidenLookupAir::num_bus_ids()` returns the count of distinct bus IDs used by all 8 buses. During transition this can be a `const NUM_BUS_IDS: usize = N;` in a sibling module; the final design reads it from a data-driven source (e.g., max + 1 over the runtime set of `*_LABEL` constants). |
| #8 | `ProcessorAir::eval` calls `ConstraintLookupBuilder::new(builder, &self.lookups())`; otherwise unchanged. |
| #9 | **Expanded**: also deletes `air/src/trace/challenges.rs::Challenges<EF>` and `MAX_MESSAGE_WIDTH`. |

### A.8 Zero-allocation encoding via shared scratch buffer

> **⚠ Superseded by Amendment B (2026-04-10).** The scratch-buffer
> machinery described below landed in Task #4 and was then reverted as
> part of Amendment B, which moves the encoding loop into
> `LookupMessage::encode` and eliminates the scratch entirely. The A.8
> content below is retained as history of the design exploration that
> led to Amendment B; **do not implement it from scratch**.

**Problem**: the Task #11 first cut encodes each message by allocating a
fresh `Vec<AB::Expr>` per call:

```rust
// INSIDE encode() — bad, allocates on every interaction
let mut scratch: Vec<AB::Expr> = vec![AB::Expr::ZERO; width];
msg.write_into(&mut scratch);
for (i, payload) in scratch.into_iter().enumerate() {
    acc += self.challenges.beta_powers[i].clone() * payload;
}
```

Both the constraint folder (`ProverConstraintFolder`) and the prover-side
aux-trace builder call this encoding path **once per interaction per
row**. For a million-row Miden trace with ~100 interactions per row,
that's ~10⁸ `Vec::with_capacity` allocations per proof. Not acceptable —
encoding is a hot path and must not allocate.

**Fix**: hoist a single `Vec<AB::Expr>` scratch buffer up to the
[`ConstraintLookupBuilder`], allocated **exactly once in `new()`** at
size `shape.max_message_width()`. Every subsequent `encode` call writes
into a reborrowed slice of that buffer — no further allocation for the
lifetime of the builder.

**Borrow chain (constraint-path adapter)**:

```
ConstraintLookupBuilder { scratch: Vec<AB::Expr>, .. }
        │ reborrow `&mut self.scratch[..]`
        ▼
ConstraintColumn<'a, AB> { scratch: &'a mut [AB::Expr], .. }
        │ reborrow `&mut *self.scratch`
        ▼
ConstraintGroup<'g, AB> { scratch: &'g mut [AB::Expr], .. }
        │ reborrow `&mut *self.scratch`
        ▼
ConstraintBatch<'b, AB> { scratch: &'b mut [AB::Expr], .. }
```

Each reborrow shortens the lifetime by one scope; the closure-based
`column(f)` / `group(f)` / `batch(f)` API returns the scratch slice to
its parent as each `f` returns. Inside `encode`, the mutable borrow of
`self.scratch[..width]` ends at the `write_into` call boundary, so the
subsequent accumulator loop reads `self.scratch[k]` and
`self.challenges.beta_powers[k]` as plain immutable field accesses —
Rust NLL handles the split borrow without complaint.

**Semantics**: the scratch buffer is never cleared between calls.
`LookupMessage::write_into` contractually overwrites the first `width()`
slots fully, so any leftover data past `msg.width()` is harmless (the
`for k in 0..width` loop never reads it). If a subsequent message has a
smaller `width()`, the tail values from the earlier call are simply
ignored.

**Ownership shape**:

```rust
pub struct ConstraintLookupBuilder<'ab, AB: LiftedAirBuilder + 'ab> {
    ab: &'ab mut AB,
    challenges: LookupChallenges<AB::ExprEF>,
    /// Pre-sized to `shape.max_message_width()` in `new`. Never grown,
    /// never cleared — reused across every column/group/batch/message.
    scratch: Vec<AB::Expr>,
    permutation_local: Vec<AB::VarEF>,
    permutation_next: Vec<AB::VarEF>,
    column_idx: usize,
}

pub struct ConstraintColumn<'a, AB: LiftedAirBuilder + 'a> {
    ab: &'a mut AB,
    challenges: &'a LookupChallenges<AB::ExprEF>,
    scratch: &'a mut [AB::Expr],
    // ... acc, acc_next, u, v ...
}

// Same field on ConstraintGroup<'a, AB> and ConstraintBatch<'a, AB>.
// ConstraintGroupEncoded wraps a ConstraintGroup and borrows the
// scratch transitively through its `inner: ConstraintGroup<'a, AB>`
// field — no separate scratch slot required.
```

**`encode` signature change**: `fn encode(&self, msg)` becomes
`fn encode(&mut self, msg)` so the mutable borrow of `self.scratch`
typechecks through the field split. The body becomes:

```rust
fn encode<M: LookupMessage<AB::Expr>>(&mut self, msg: &M) -> AB::ExprEF {
    let width = msg.width();
    // Mutable borrow of self.scratch ends at the call boundary.
    msg.write_into(&mut self.scratch[..width]);
    let mut acc = self.challenges
        .domain_separators[msg.bus_id() as usize]
        .clone();
    for k in 0..width {
        // Immutable reads — no aliasing conflict with the earlier mut borrow.
        acc += self.challenges.beta_powers[k].clone()
             * self.scratch[k].clone();
    }
    acc
}
```

**Prover-path mirror** (Task #4): `ProverLookupBuilder` takes the same
shape — a `Vec<F>` scratch on the builder, reborrowed as `&mut [F]`
down the column / group / batch chain. Because `F: Copy` on the prover
side, the per-call `clone()`s in the inner loop compile to trivial
copies and the whole encoding path is allocation-free after the
one-time `Vec::with_capacity` at builder construction.

**Why not a fixed-size `[AB::Expr; N]` stack array?**
- Amendment A.2 forbids `MAX_MESSAGE_WIDTH`-style constants in the new
  module's public surface.
- `AB::Expr` does not implement `Copy` on the constraint path, so the
  array slots would still need per-use cloning / `mem::take`
  bookkeeping. The savings over a single up-front `Vec::with_capacity`
  are zero.
- Heap-allocating `Vec::with_capacity` **once per builder lifetime** is
  negligible — the per-proof cost is a single ≤16-element allocation,
  and a proof constructs one builder.

**Task-map delta**: Task #11 (Amendment A rework) landed with the
allocating draft; a follow-up edit must add the `scratch` field, thread
it through the four closure methods, and flip `encode` to `&mut self`.
Since this is a small, purely-mechanical change (roughly six type
definitions and two `encode` bodies), it can land either as a fixup
commit on top of Task #11 or as part of Task #4 (when the prover-path
adapter needs the same treatment anyway).

---

## Amendment B (2026-04-10): `LookupMessage::encode` collapses the scratch buffer

After Task #5 landed the `write_into` + scratch design with Amendment
A.8's reborrow chain, we recognised that the scratch indirection buys
nothing over moving the encoding loop **into the message body**. Each
message already knows its own payload layout; the adapter's encoding
loop is identical for every message; the scratch buffer is a
decoupling that the code never uses.

**Amendment B supersedes Amendment A.8.** A.8's scratch machinery
should be reverted wherever it landed. The scratch field, reborrow
chain, `fold_group` inlining workaround, `bus_id()` + `width()` +
`write_into()` trait split, and the `LookupMessage::scratch` borrow
tree all **disappear**.

### B.1 New trait shape

```rust
pub trait LookupMessage<E, EF>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    /// Encode this message as a denominator:
    ///
    ///     DS[bus_id] + β⁰·v[0] + β¹·v[1] + … + β^(width−1)·v[width−1]
    ///
    /// The implementor looks up its bus identifier (either from an
    /// internal field or a central constant in `bus_id.rs`), reads
    /// the corresponding domain separator from
    /// `challenges.domain_separators`, and folds its payload against
    /// `challenges.beta_powers` with straight-line arithmetic.
    fn encode(&self, challenges: &LookupChallenges<EF>) -> EF;
}
```

**One method.** No `bus_id()`, no `width()`, no `write_into()`. Two
generic parameters (`E`, `EF`) instead of one, because the encoded
denominator lives in the extension field. This matches the shape of
the old `LogUpMessage<E, EF>::encode(&Challenges) -> EF` trait almost
verbatim — just against `LookupChallenges<EF>` and with the label
contribution sourced from `challenges.domain_separators[bus_id]`
instead of `β⁰ · label`.

### B.2 Cascading simplifications

Once encoding lives in the message, the adapter types collapse:

- `ConstraintLookupBuilder` drops the `scratch: Vec<AB::Expr>` field.
- `ConstraintColumn<'a, AB>` drops `scratch: &'a mut [AB::Expr]`.
- `ConstraintGroup<'a, AB>` drops `scratch: &'a mut [AB::Expr]`.
- `ConstraintBatch<'a, AB>` drops `scratch: &'a mut [AB::Expr]`.
- `ProverLookupBuilder<'a, F, EF>` drops `scratch: Vec<F>`.
- Same chain on the prover column/group/batch types.

The `ConstraintColumn::fold_group` helper can be restored as a normal
method (no inlined body at each call site) because `self.scratch` no
longer exists — the GAT-lifetime borrow-checker conflict documented in
Task #4's execution log goes away.

The per-type `encode` helpers on `ConstraintGroup` / `ConstraintBatch`
disappear; each `add` / `remove` / `insert` body becomes a two-liner:

```rust
fn add<M>(&mut self, flag: Self::Expr, msg: impl FnOnce() -> M)
where
    M: LookupMessage<Self::Expr, Self::ExprEF>,
{
    let v = msg().encode(self.challenges);
    self.absorb_single(flag, AB::Expr::ONE, v);
}
```

`LookupBatch` / `LookupGroup` trait bounds on `M` grow a second
parameter: `M: LookupMessage<Self::Expr, Self::ExprEF>` where they
used to say `M: LookupMessage<Self::Expr>`. No other trait changes.

### B.3 Central bus-ID registry

New file `air/src/constraints/lookup/bus_id.rs` holds every bus
identifier Miden's LookupAir references:

```rust
//! Central bus-ID registry for Miden's LookupAir.
//!
//! Every distinct LogUp bus / message label has a compile-time
//! constant here. Where possible the value is derived from an existing
//! `_LABEL` constant in `trace/chiplets/` so the transition commit is
//! small — Task #9 collapses the scattered `_LABEL`s into this file.

use crate::trace::chiplets::{
    bitwise::{BITWISE_AND_LABEL, BITWISE_XOR_LABEL},
    hasher::{LINEAR_HASH_LABEL, MP_VERIFY_LABEL, /* ... */},
    memory::{MEMORY_READ_ELEMENT_LABEL, /* ... */},
    /* ... */
};

// Hasher chiplet (request and response variants carry different
// bucket offsets — see logup_msg::HasherMsg constructors).
pub const BUS_HASHER_LINEAR_HASH_INIT:     u16 = LINEAR_HASH_LABEL as u16 + 16;
pub const BUS_HASHER_LINEAR_HASH_RESPONSE: u16 = LINEAR_HASH_LABEL as u16 + 32;
pub const BUS_HASHER_MP_VERIFY_INIT:       u16 = MP_VERIFY_LABEL  as u16 + 16;
// … (one const per variant the old constructors emit)

// Memory chiplet.
pub const BUS_MEMORY_READ_ELEMENT:  u16 = MEMORY_READ_ELEMENT_LABEL  as u16;
pub const BUS_MEMORY_WRITE_ELEMENT: u16 = MEMORY_WRITE_ELEMENT_LABEL as u16;
pub const BUS_MEMORY_READ_WORD:     u16 = MEMORY_READ_WORD_LABEL     as u16;
pub const BUS_MEMORY_WRITE_WORD:    u16 = MEMORY_WRITE_WORD_LABEL    as u16;

// Placeholder-free replacements for the 6 structs Task #5 left at
// bus_id = 0. Values are picked to not collide with the existing
// label constants above — typically the lowest unused u16.
pub const BUS_BLOCK_STACK_TABLE: u16 = …;
pub const BUS_BLOCK_HASH_QUEUE:  u16 = …;
pub const BUS_OP_GROUP_TABLE:    u16 = …;
pub const BUS_STACK_OVERFLOW:    u16 = …;
pub const BUS_RANGE_CHECK:       u16 = …;
pub const BUS_ACE_WIRING:        u16 = …;

/// Count of bus IDs — every `LookupAir<LB>::num_bus_ids()` impl
/// reports this constant, and every adapter sizes its
/// `domain_separators` table to match.
pub const NUM_BUS_IDS: usize = …; // max(bus_id) + 1
```

The DS table is indexed densely by `u16` values, so unused slots
between the scattered label values just waste a few extension-field
elements. For Miden that's ≤64 entries × ~32 bytes = ≤2 KB — a
one-time cost at builder construction, irrelevant for proving.

The 9 structs with existing `label_value: u16` fields keep the field
as-is but their constructors switch to referencing `bus_id::BUS_*`
constants. The 6 structs that Task #5 left with placeholder `0` get
real values from `bus_id.rs`. **All message-struct `LookupMessage`
impls source their bus ID from `bus_id.rs` — no hardcoded numerics in
`logup_msg.rs`.**

### B.4 Message impl bodies

> **Correction (2026-04-10)**: the bus-ID model originally described here
> was wrong — see the execution log entry "Correction to Task #12 (2026-04-10) — bus-ID model"
> for the corrected 9-bus enumeration. The encoding formula in the body
> below is still correct in principle (bus prefix + β-weighted payload),
> but the bus-ID → label mapping must come from `bus_id.rs` with the
> coarse 9-entry enumeration, not the 101-entry label expansion.

Each message struct's `encode` body is a straight-line
β-power-weighted sum. Example for `HasherMsg::State`:

```rust
impl<E, EF> LookupMessage<E, EF> for HasherMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &LookupChallenges<EF>) -> EF {
        let bp = &challenges.beta_powers;
        match self {
            Self::State { label_value, addr, node_index, state } => {
                let mut acc = challenges.domain_separators[*label_value as usize].clone();
                acc += bp[0].clone() * addr.clone();
                acc += bp[1].clone() * node_index.clone();
                for i in 0..12 {
                    acc += bp[i + 2].clone() * state[i].clone();
                }
                acc
            }
            Self::Rate { label_value, addr, node_index, rate } => { /* ... */ }
            Self::Word { label_value, addr, node_index, word } => { /* ... */ }
        }
    }
}
```

For structs with no stored `label_value`, the bus ID comes from a
central constant:

```rust
impl<E, EF> LookupMessage<E, EF> for RangeMsg<E>
where
    E: PrimeCharacteristicRing + Clone,
    EF: PrimeCharacteristicRing + Clone + Algebra<E>,
{
    fn encode(&self, challenges: &LookupChallenges<EF>) -> EF {
        let bp = &challenges.beta_powers;
        let mut acc = challenges
            .domain_separators[BUS_RANGE_CHECK as usize]
            .clone();
        acc += bp[0].clone() * self.value.clone();
        acc
    }
}
```

### B.5 Task-map deltas

| Task | Change |
|------|--------|
| **#5 redo** | Rewrite every `LookupMessage` impl against the new trait shape. Drop `bus_id` / `width` / `write_into`. Create `lookup/bus_id.rs`. Update the 9 non-placeholder structs' constructors to reference `bus_id::BUS_*` constants. Assign real bus IDs to the 6 placeholder structs. |
| **#3 / #11 / #4 cleanup** | Strip the `scratch` field from `ConstraintLookupBuilder`, all column/group/batch types, and their prover counterparts. Restore `fold_group` as a regular method. Revert A.8 commentary in the code (`scratch` doc comments, `encode(&mut self, …)` → `(&self, …)` — actually, with the new trait the adapter never needs a `&mut` receiver for encoding anymore). |
| **#6 (Task #6)** | `MidenLookupAir::num_bus_ids()` returns `lookup::bus_id::NUM_BUS_IDS`. |
| **#7 (Task #7)** | Response-message restructuring is unchanged: split `MemoryResponseMsg` / `KernelRomResponseMsg` / `BitwiseResponseMsg` into per-label variants, each implementing the new `LookupMessage<E, EF>::encode` with its own constant bus ID from `bus_id.rs`. |
| **#9** | Delete `LogUpMessage` + the old `Challenges<EF>` + `MAX_MESSAGE_WIDTH` + the `_LABEL` constants in `trace/chiplets/` (now redundant with `bus_id.rs`). |

### B.6 Amendment A sub-items still in force

- A.1 (domain-separator encoding algebra) — unchanged. The encoding
  formula is exactly what B.4's `encode` bodies compute.
- A.2 (no compile-time size constants) — unchanged. `LookupChallenges`
  stays dynamic; `NUM_BUS_IDS` is a named constant but it's derived
  at the adapter construction boundary from the `LookupAir`'s
  `num_bus_ids()` method, not baked into any array type.
- A.3 (single `LookupAir<LB>` trait, no `LookupAirShape` split) —
  unchanged.
- A.4 (LookupMessage trait) — **replaced** by B.1.
- A.5 (`EncodedLookupGroup` exposes `domain_separator` / `beta_powers`)
  — unchanged. The encoded-group path is still useful for manual
  cached-encoding fragments when a bus author wants to precompute a
  shared `β^k · field` sum across variants.
- A.6 (adapter constructors take `air: &A` where `A: LookupAir<Self>`)
  — unchanged.
- A.7 (task-map deltas) — superseded by B.5 above.
- A.8 (scratch buffer) — **superseded by Amendment B** (see header
  note on A.8).

---

## Proposed trait architecture

All new code lives in a fresh module `air/src/constraints/lookup/` alongside
the existing `logup.rs`. The existing `logup.rs` stays for now (as
implementation detail the new builder calls into), then gets deleted once the
per-bus files have been ported.

```
air/src/constraints/lookup/
├── mod.rs            // pub use's + top-level LookupAir / LookupBuilder traits
├── message.rs        // LookupMessage trait (renamed from LogUpMessage)
├── builder.rs        // LookupBuilder / LookupColumn / LookupGroup / EncodedLookupGroup traits
├── constraint.rs     // ConstraintLookupBuilder<'ab, AB: LiftedAirBuilder>
├── prover.rs         // ProverLookupBuilder<'a, F, EF>
└── batch.rs          // Batch + MutexBatch helper types re-exposed to users
```

### 1. `LookupMessage` — bus label + contiguous values

**See Amendment A** — `bus_label` → `bus_id`; payload-only `width`; no label in `write_into`.

`air/src/constraints/lookup/message.rs`:

```rust
/// A message that the builder will encode as
///     α + β^0 · bus_label + Σ_{i=1..=N} β^i · values[i-1]
///
/// Existing concrete structs in `logup_msg.rs` implement this trait via
/// a blanket macro. The `bus_label` is the base-field constant that
/// historically sat at index 0 of the encoded array.
pub trait LookupMessage<E: PrimeCharacteristicRing + Clone> {
    /// Bus label / domain separator — a compile-time base-field constant.
    fn bus_label(&self) -> u16;

    /// Contiguous payload values. The builder encodes them at
    /// β^1 … β^len. Width is validated against the `LookupAir`'s
    /// declared `max_message_width` (len + 1 ≤ max).
    fn values(&self) -> LookupPayload<E>;
}

/// Returned by `LookupMessage::values`. Internally a `SmallVec<[E; 16]>`
/// so that ≤15 payload fields + 1 label fit inline with no heap alloc.
pub struct LookupPayload<E>(pub SmallVec<[E; 16]>);
```

`encode_sparse` (currently used only by `SiblingMsg`) is dropped. `SiblingMsg`
gets re-expressed as a pair of contiguous messages gated by `bit` / `1 - bit`,
matching the rest of the code's "variant + flag" convention.

### 2. `LookupAir<LB>` — declarative shape + evaluator

**See Amendment A** — gains `num_bus_ids()` alongside the existing `num_columns()` / `max_message_width()`. (An earlier Amendment A draft split this into a non-generic `LookupAirShape` + generic `LookupAir<LB>`; that split was reverted — see A.3 for the rationale.)

`air/src/constraints/lookup/mod.rs`:

```rust
/// A LogUp lookup argument. Generic over the builder the same way
/// `p3_air::Air<AB>` is generic over its `AirBuilder`.
pub trait LookupAir<LB: LookupBuilder> {
    /// Number of permutation columns this argument occupies.
    /// Must match the number of `builder.column(...)` calls in `eval`.
    fn num_columns(&self) -> usize;

    /// Upper bound on the encoded message width (label + payload).
    /// Determines how many powers of β the builder precomputes.
    fn max_message_width(&self) -> usize;

    /// Define the interactions. Must open exactly `num_columns()` columns.
    fn eval(&self, builder: &mut LB);
}
```

Note: no `num_groups`. Groups are just scopes inside the closure flow; the
builder does not precompute anything per-group.

### 3. `LookupBuilder` — associated types copied from `LiftedAirBuilder`

`air/src/constraints/lookup/builder.rs`:

```rust
pub trait LookupBuilder: Sized {
    // --- copied from AirBuilder ---
    type F: Field;
    type Expr: Algebra<Self::F> + Algebra<Self::Var>;
    type Var: Into<Self::Expr> + Copy + Send + Sync;

    // --- copied from ExtensionBuilder ---
    type EF: ExtensionField<Self::F>;
    type ExprEF: Algebra<Self::Expr> + Algebra<Self::EF>;
    type VarEF: Into<Self::ExprEF> + Copy + Send + Sync;

    // --- copied from PeriodicAirBuilder ---
    type PeriodicVar: Into<Self::Expr> + Copy;

    // --- copied from AirBuilder::PublicVar ---
    type PublicVar: Into<Self::Expr> + Copy;

    // --- copied from AirBuilder::MainWindow ---
    type MainWindow: WindowAccess<Self::Var> + Clone;

    // --- per-column handle (GAT so borrows are scope-bounded) ---
    type Column<'a>: LookupColumn<
        'a,
        Expr = Self::Expr,
        ExprEF = Self::ExprEF,
        VarEF = Self::VarEF,
    > where Self: 'a;

    // ---- trace access (pass-through to the wrapped builder) ----

    /// Two-row main trace window. Returned as a `RowWindow`-shaped type
    /// (just whatever the inner `AirBuilder::MainWindow` picks).
    fn main(&self) -> Self::MainWindow;

    /// Periodic column values at the current row.
    fn periodic_values(&self) -> &[Self::PeriodicVar];

    /// Public inputs.
    fn public_values(&self) -> &[Self::PublicVar];

    // ---- per-column scoping ----

    /// Open a fresh permutation column. Within the closure the builder
    /// is in "column N" mode; on close it finalizes (emits
    /// `assert_zero_ext` on constraint path / flushes the fraction buffer
    /// on prover path) and advances to column N+1.
    fn column<R>(&mut self, f: impl FnOnce(&mut Self::Column<'_>) -> R) -> R;
}
```

Key points:

- **No `is_first_row` / `is_last_row` / `is_transition`.** Boundary and
  transition gating of `acc` is the builder's finalization responsibility,
  not the `LookupAir` author's.
- **No `assert_*`.** Constraint emission is encapsulated in `column`'s
  finalization step.
- **No challenge access.** The simple group path never sees α/β. Only the
  `EncodedLookupGroup` exposes them.

### 4. `LookupColumn` — holds two sibling group methods

```rust
pub trait LookupColumn<'ab> {
    type Expr: Clone;
    type ExprEF: Clone;
    type VarEF: Copy;

    type Group<'a>: LookupGroup<
        Expr = Self::Expr,
        ExprEF = Self::ExprEF,
    > where Self: 'a;

    type EncodedGroup<'a>: EncodedLookupGroup<
        Expr = Self::Expr,
        ExprEF = Self::ExprEF,
        VarEF = Self::VarEF,
    > where Self: 'a;

    /// Open a group. Every interaction added inside the closure is composed
    /// into this group's `(U_g, V_g)` pair; multiple groups per column are
    /// product-closed by the column (`V ← V·U_g + V_g·U`, `U ← U·U_g`).
    fn group<R>(&mut self, f: impl FnOnce(&mut Self::Group<'_>) -> R) -> R;

    /// Dual-path group for the cached-encoding optimization.
    ///
    /// - `canonical` is invoked on the prover path. Sees the simple
    ///   `Group` trait surface — no challenges, no `insert_encoded`.
    /// - `encoded` is invoked on the constraint path. Sees the
    ///   `EncodedLookupGroup` super-trait — exposes `alpha()`,
    ///   `beta_powers()`, and `insert_encoded` for manual cached
    ///   fragment composition.
    ///
    /// Both closures must produce the same `(U, V)` mathematically; the
    /// split is purely an optimization for expensive field work.
    fn group_with_cached_encoding<R>(
        &mut self,
        canonical: impl FnOnce(&mut Self::Group<'_>) -> R,
        encoded: impl FnOnce(&mut Self::EncodedGroup<'_>) -> R,
    ) -> R;
}
```

### 5. `LookupGroup` — simple API, no challenges exposed

```rust
pub trait LookupGroup {
    type Expr: Clone;
    type ExprEF: Clone;

    /// Add a flag-gated single interaction with multiplicity `+1`.
    fn add<M>(&mut self, flag: Self::Expr, msg: impl FnOnce() -> M)
    where M: LookupMessage<Self::Expr>;

    /// Add a flag-gated single interaction with multiplicity `-1`.
    fn remove<M>(&mut self, flag: Self::Expr, msg: impl FnOnce() -> M)
    where M: LookupMessage<Self::Expr>;

    /// Add a flag-gated single interaction with explicit signed multiplicity.
    fn insert<M>(
        &mut self,
        flag: Self::Expr,
        multiplicity: Self::Expr,
        msg: impl FnOnce() -> M,
    ) where M: LookupMessage<Self::Expr>;

    /// A flag-gated batch of simultaneous interactions (shared flag).
    ///
    /// All batches *within the same group* are expected to be mutually
    /// exclusive at any row, but this is not checked at runtime.
    fn batch<R>(
        &mut self,
        flag: Self::Expr,
        build: impl FnOnce(&mut LookupBatch<'_, Self>) -> R,
    ) -> R;
}
```

`LookupBatch<'_, G: LookupGroup>` is a thin handle providing `add(msg)` /
`remove(msg)` / `insert(mult, msg)`. It is equivalent to the existing
`Batch<'c, E, EF>` but only exposes the API, not the internal `n/d` state.

### 6. `EncodedLookupGroup` — sub-trait with challenge access

**See Amendment A** — `alpha()` removed; `domain_separator(bus_id)` added; `beta_powers()` no longer includes β^W.

```rust
/// Extension of `LookupGroup` that exposes encoding primitives.
///
/// Only visible on the constraint path of `group_with_cached_encoding`.
/// The prover path always takes the canonical `LookupGroup` branch because
/// cached fragments would be computed once, used once (prover skips zero
/// flags), so there's no payoff.
pub trait EncodedLookupGroup: LookupGroup {
    type VarEF: Copy;

    /// Verifier challenge α.
    fn alpha(&self) -> Self::VarEF;

    /// Precomputed powers `[β^0, β^1, …, β^{max_width-1}]`.
    fn beta_powers(&self) -> &[Self::VarEF];

    /// Add a flag-gated interaction where the *denominator* is already
    /// encoded as an extension-field expression. Skipped entirely on the
    /// prover path when `flag == 0`.
    fn insert_encoded(
        &mut self,
        flag: Self::Expr,
        multiplicity: Self::Expr,
        encoded: impl FnOnce() -> Self::ExprEF,
    );
}
```

---

## Implementations

### Constraint-path adapter — `ConstraintLookupBuilder<'ab, AB>`

**See Amendment A** — `new` takes a `shape: &S: LookupAirShape` parameter and builds `LookupChallenges` from it; internal type is `LookupChallenges<AB::ExprEF>`, not `Challenges<AB::ExprEF>`.

`air/src/constraints/lookup/constraint.rs`:

```rust
pub struct ConstraintLookupBuilder<'ab, AB: LiftedAirBuilder> {
    ab: &'ab mut AB,
    challenges: Challenges<AB::ExprEF>,      // cached once from ab.permutation_randomness()
    column_idx: usize,
    permutation_local: Vec<AB::VarEF>,       // cached ab.permutation().current_slice().to_vec()
    permutation_next:  Vec<AB::VarEF>,
}

impl<'ab, AB> LookupBuilder for ConstraintLookupBuilder<'ab, AB>
where AB: LiftedAirBuilder<F = Felt>
{
    type F         = AB::F;
    type Expr      = AB::Expr;
    type Var       = AB::Var;
    type EF        = AB::EF;
    type ExprEF    = AB::ExprEF;
    type VarEF     = AB::VarEF;
    type PeriodicVar = AB::PeriodicVar;
    type PublicVar = AB::PublicVar;
    type MainWindow = AB::MainWindow;
    type Column<'a> = ConstraintColumn<'a, 'ab, AB> where Self: 'a;

    fn main(&self)            -> Self::MainWindow  { self.ab.main() }
    fn periodic_values(&self) -> &[Self::PeriodicVar] { self.ab.periodic_values() }
    fn public_values(&self)   -> &[Self::PublicVar]   { self.ab.public_values() }

    fn column<R>(&mut self, f: impl FnOnce(&mut Self::Column<'_>) -> R) -> R {
        let acc      = self.permutation_local[self.column_idx].into();
        let acc_next = self.permutation_next [self.column_idx].into();
        let mut col  = ConstraintColumn::new(acc, acc_next, &self.challenges);
        let r = f(&mut col);
        // Finalize: emit the transition + boundary constraints.
        col.finalize(self.ab);
        self.column_idx += 1;
        r
    }
}
```

`ConstraintColumn` tracks running `(U, V)` across its groups. `finalize` emits:

```rust
builder.when_first_row().assert_zero_ext(acc);
builder.when_transition().assert_zero_ext((acc_next - acc) * U - V);
builder.when_last_row().assert_zero_ext(acc);
```

(Exactly what `Column::constrain` already does in `logup.rs:679`.)

`ConstraintGroup` and `ConstraintGroupEncoded` are two wrapper types over the
same mutable `&mut RationalSet<'_, AB::Expr, AB::ExprEF>`-style backing. The
plain wrapper exposes only the `LookupGroup` trait; the encoded wrapper also
exposes `alpha`, `beta_powers`, `insert_encoded`. Both call into the existing
`RationalSet::add_single` / `add_encoded` / `add_batch` under the hood.

`group_with_cached_encoding` on the constraint path runs **only** the
`encoded` closure (`canonical` is dropped unused).

### Prover-path adapter — `ProverLookupBuilder<'a, F, EF>`

**See Amendment A** — `new` takes a `shape: &S: LookupAirShape` parameter and builds `LookupChallenges<EF>` from it; same constructor pattern as the constraint adapter.

`air/src/constraints/lookup/prover.rs`:

```rust
pub struct ProverLookupBuilder<'a, F, EF> {
    main: RowWindow<'a, F>,                  // two concrete rows of base-field values
    periodic: &'a [F],
    public_values: &'a [F],
    challenges: &'a Challenges<EF>,          // concrete challenges
    column_fractions: &'a mut [Vec<(EF, EF)>], // one buffer per column; preallocated
    column_idx: usize,
}
```

`column(f)` pushes an empty `FractionCollector` onto the current column, runs
`f`, then drains the collector's `(n, d)` pair into the current column's
buffer slot. After `eval` returns, the caller makes a single pass over each
`Vec<(EF, EF)>` to compute the running LogUp sum.

`ProverGroup` implements `LookupGroup` by calling into a `FractionCollector`
(already exists at `logup.rs:463`). Flag-zero closures are skipped inside
the collector.

`group_with_cached_encoding` on the prover path runs **only** the
`canonical` closure.

`ProverGroupEncoded` is a dummy type that won't actually be instantiated on
the prover path — we just need it to satisfy the associated-type constraint.
It can be `Infallible`-style `enum Never {}` or simply `ProverGroup` itself
with all encoded methods routed to the same `FractionCollector` (harmless:
the closures would be called but the output is the same).

Simpler: use the **same** `ProverGroup` type for both `Group` and
`EncodedGroup` associated types. `EncodedLookupGroup::alpha/beta_powers/insert_encoded`
just route to the `FractionCollector`'s challenges and the same absorb logic
as `add`. This keeps the prover impl zero-overhead.

### `LookupAir` → `Air` integration

A narrow extension trait wires `LookupAir` into the existing `Air`:

```rust
/// Miden-side marker: an `Air` that also has a LogUp lookup argument.
/// The constraint evaluator uses this to hook into
/// `LiftedAir::eval` after the base constraints are emitted.
pub trait AirWithLookups<AB: LiftedAirBuilder>: Air<AB> {
    /// The lookup argument. Typically a zero-sized struct that borrows
    /// from `&self` or is constructed on demand.
    type Lookups: for<'ab> LookupAir<ConstraintLookupBuilder<'ab, AB>>;
    fn lookups(&self) -> Self::Lookups;
}
```

`ProcessorAir::eval` (currently at `air/src/lib.rs:333`) then becomes:

```rust
fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
    // ... existing main / public_inputs calls ...
    constraints::enforce_main(builder, local, next);
    constraints::public_inputs::enforce_main(builder, local);

    // New: one call that replaces both enforce_main and enforce_chiplet
    // from logup_bus/mod.rs.
    let mut lb = ConstraintLookupBuilder::new(builder);
    self.lookups().eval(&mut lb);
}
```

`MidenLookupAir` is a zero-sized struct; its `eval` body is exactly the
contents of the two current `enforce_main` / `enforce_chiplet` functions,
rewritten in the closure style. The `wiring.rs`, `block_hash.rs` etc. helper
modules get turned from "returns a `RationalSet`" functions into "takes
`&mut impl LookupGroup` and evaluates" functions.

---

## Example — porting `g_bqueue` (block hash queue, M2)

**Before** (`air/src/constraints/logup_bus/block_hash.rs` — conceptual):

```rust
pub fn g_bqueue<'c, AB: LiftedAirBuilder>(
    local, next, op_flags, op_flags_next, challenges,
) -> RationalSet<'c, AB::Expr, AB::ExprEF> {
    let mut set = RationalSet::new(challenges);
    set.add_group_with(
        |sink| { /* canonical: 5 add/remove calls */ },
        |sink| { /* cached: compute base, reuse via add_encoded */ },
    );
    set
}
```

**After:**

```rust
pub fn emit_bqueue<LB: LookupBuilder>(
    lb: &mut LB,
    local: &MainTraceRow<LB::Var>,
    next: &MainTraceRow<LB::Var>,
    op_flags: &OpFlags<LB::Expr>,
    op_flags_next: &OpFlags<LB::Expr>,
) {
    lb.column(|col| {
        col.group_with_cached_encoding(
            |g| {
                // Canonical — simple API, no challenges visible.
                g.add(flag_join(local, next),  || BlockHashMsg::first_child(local, next));
                g.add(flag_split(local, next), || BlockHashMsg::first_child(local, next));
                // … 5 total add/remove calls
            },
            |ge| {
                // Encoded — has challenges access for cached fragments.
                let base = ge.alpha() + ge.beta_powers()[0] * local.parent_id();
                ge.insert_encoded(flag_join(local, next), Expr::ONE,
                    || base.clone() + /* per-variant label + child_hash contribution */);
                // … 5 insert_encoded calls sharing `base`
            },
        );
    });
}
```

The top-level `MidenLookupAir::eval` walks through the 8 buses in order:

```rust
impl<LB: LookupBuilder<F = Felt>> LookupAir<LB> for MidenLookupAir {
    fn num_columns(&self) -> usize { 8 }
    fn max_message_width(&self) -> usize { MAX_MESSAGE_WIDTH }

    fn eval(&self, lb: &mut LB) {
        let main = lb.main();
        let local: &MainTraceRow<_> = main.current_slice().borrow();
        let next:  &MainTraceRow<_> = main.next_slice().borrow();
        let op_flags      = OpFlags::new(ExprDecoderAccess::new(local));
        let op_flags_next = OpFlags::new(ExprDecoderAccess::new(next));

        // M1–M5
        emit_m1_block_stack_and_range(lb, local, next, &op_flags);
        emit_bqueue               (lb, local, next, &op_flags, &op_flags_next);
        emit_chiplet_requests     (lb, local, next, &op_flags);
        emit_range_and_logcap     (lb, local, next, &op_flags);
        emit_op_group             (lb, local, next, &op_flags);

        // C1–C3
        emit_chiplet_responses    (lb, local, next);
        emit_hash_kernel          (lb, local, next);
        emit_wiring               (lb, local);
    }
}
```

---

## Critical files

### New files (created)
- `air/src/constraints/lookup/mod.rs`            — `LookupAir` trait + re-exports
- `air/src/constraints/lookup/message.rs`        — `LookupMessage` trait (renamed `LogUpMessage`)
- `air/src/constraints/lookup/builder.rs`        — `LookupBuilder`, `LookupColumn`, `LookupGroup`, `EncodedLookupGroup`, `LookupBatch`
- `air/src/constraints/lookup/constraint.rs`     — `ConstraintLookupBuilder<'ab, AB>` + its column/group types
- `air/src/constraints/lookup/prover.rs`         — `ProverLookupBuilder<'a, F, EF>` + its column/group types

### Files modified
- `air/src/constraints/mod.rs`                   — add `pub mod lookup;`
- `air/src/constraints/logup_msg.rs`             — blanket-impl `LookupMessage` for every existing `*Msg` struct (keep `LogUpMessage` as a deprecated alias for one cycle OR delete outright since no backwards compat)
- `air/src/constraints/logup.rs`                 — shrink: keep `Batch`, `RationalSet`, `FractionCollector` as implementation detail used by `constraint.rs` / `prover.rs`; delete `InteractionSink`, `InteractionGroup`, `Column` (their role is now played by `LookupBuilder` / `LookupColumn`)
- `air/src/constraints/logup_bus/mod.rs`         — delete `enforce_main` / `enforce_chiplet`; replace with a single `MidenLookupAir` zero-sized struct + `impl LookupAir<LB>`
- `air/src/constraints/logup_bus/block_hash.rs`  — rewrite `g_bqueue` → `emit_bqueue(lb, ...)` as shown above
- `air/src/constraints/logup_bus/block_stack.rs` — ditto (two groups)
- `air/src/constraints/logup_bus/chiplet_requests.rs` — ditto
- `air/src/constraints/logup_bus/chiplet_responses.rs` — ditto (the big cached-encoding one: 7 hasher variants sharing `base + h4 + h12`)
- `air/src/constraints/logup_bus/hash_kernel.rs` — ditto; re-express `SiblingMsg` as two flag-gated contiguous messages
- `air/src/constraints/logup_bus/op_group.rs`    — ditto
- `air/src/constraints/logup_bus/range_logcap.rs` — ditto
- `air/src/constraints/logup_bus/wiring.rs`      — ditto
- `air/src/lib.rs`                               — `ProcessorAir::eval` calls `self.lookups().eval(&mut lb)` instead of `enforce_main`/`enforce_chiplet` from `logup_bus`

### Files to study but likely not modify
- `air/src/constraints/logup.rs` (keep the algebra, drop `InteractionSink`/`InteractionGroup`/`Column`)
- `air/src/trace/challenges.rs` — `Challenges::encode` / `beta_powers` is reused
- `crypto/crates/miden-lifted-air/src/lib.rs` — `LiftedAirBuilder` traits are consumed only, not modified

---

## Reuse checklist (existing utilities to keep)

- `Challenges::new(alpha, beta)` + `Challenges::encode` → used internally by
  both builders to encode `LookupMessage` payloads. No change.
- `Batch` (`logup.rs:42`) → wrapped by `LookupBatch`, which delegates to it.
- `RationalSet` (`logup.rs:111`) → internal storage backing `ConstraintGroup`'s
  `(U, V)` accumulation.
- `FractionCollector` (`logup.rs:463`) → internal storage backing
  `ProverGroup`'s per-column fraction list.
- `Column::constrain` (`logup.rs:679`) → the finalization body is inlined
  into `ConstraintLookupBuilder::finalize_column`.
- All `*Msg` structs in `logup_msg.rs` → gain a `LookupMessage` blanket impl
  via a macro, minus `SiblingMsg` which gets re-expressed (because we drop
  `encode_sparse`).

---

## Verification

1. **Trait compiles in isolation.** `cargo check -p miden-air` after each
   file is added. No other crate should notice the new module yet.
2. **Port one bus first (block hash queue).** After porting `g_bqueue` to
   the new API, run the existing degree-budget tests in
   `air/src/constraints/logup_bus/mod.rs` under
   `make test-air test="enforce_main_degrees_within_budget"`. The resulting
   symbolic constraints should match the old ones (modulo internal
   structural reordering) and all stay ≤ 9 degree.
3. **Port the rest bus-by-bus** in the same pattern, re-running the degree
   audit after each port. Target: all 8 buses emit identical-degree
   constraints compared to the pre-port baseline.
4. **Prover adapter.** Add a test in `air/src/constraints/lookup/prover.rs`
   that runs `MidenLookupAir::eval` over concrete base-field rows against
   a hand-picked small trace, and verifies that the summed
   `Vec<(n, d)>` fractions per column sum to zero across all rows (the
   LogUp identity). Compare against the current prover-side bus trace
   generation in `processor/src/chiplets/aux_trace/mod.rs` for one
   representative column.
5. **Full test sweep.** `make test-air` then `make test-processor` then
   `make test` for regressions. In particular ensure
   `ProcessorAir` boundary/transition roundtrips still pass the
   symbolic degree tests at the budget of 9.
6. **Lint.** `make lint` with no warnings.

End-to-end, the migration ships when:
- All 8 buses are ported.
- The old `enforce_main` / `enforce_chiplet` / `Column` / `InteractionSink` /
  `InteractionGroup` symbols are gone.
- `make test` is green.
- The degree budget test passes with `DEGREE_BUDGET = 9`.

---

## Open questions / things to confirm during implementation

1. **Should `LookupBuilder` also expose `main_next_row_columns` or a
   transition flag?** Currently no — the author computes transition-sensitive
   expressions by reading both `current_slice()` and `next_slice()` of
   `builder.main()`. Matches how `OpFlags::new(ExprDecoderAccess::new(local))`
   is constructed today.
2. **`ProverGroupEncoded` = `ProverGroup`?** I've proposed yes (same type,
   encoded methods route to the same `FractionCollector`). Confirm this is
   correct for all prover callers — in particular, that `insert_encoded`
   on the prover path means "the closure returns the final encoded
   denominator, don't add β powers," which is semantically equivalent to
   calling `add_single` on an already-encoded-by-hand message.
3. **`LookupMessage::values` signature.** `LookupPayload<E>` as a newtype
   over `SmallVec<[E; 16]>` costs one alloc only when the message exceeds
   16 elements, which none currently do (max is 15). Alternative: a
   `fn write_into(&self, out: &mut [E])` method that avoids even the
   SmallVec. Pick the cleaner one during implementation; no architectural
   consequence.
4. **Drop of `encode_sparse`**. Verify `SiblingMsg` is the only user, then
   split it into two contiguous-layout messages gated by `bit` / `1-bit`
   inside `hash_kernel.rs`. If this causes a degree regression, revisit.

---

## Execution log

Each task's implementing agent appends one block here after completing. The
plan sections above are the design contract — do not rewrite them, even if
implementation reveals a deviation. Record deviations and discoveries here
instead, and if a deviation is load-bearing for later tasks, flag it in the
"Critical" bullet so the next agent sees it.

Template for each entry:

```
### Task #N — <short title> — <status: done | in_progress | blocked>
- **Date**: YYYY-MM-DD
- **Files touched**: <paths>
- **Build check**: <command run, result>
- **Critical** (only if later tasks need to know): <one-line pointer>
- **Insights**: <bullets of non-obvious things discovered>
```

### Amendment A (2026-04-10) — dynamic sizes + domain-separator encoding — recorded

- **Motivation**: the user reviewed Task #3 and flagged two concerns:
  1. The encoding still spent one EF×BF mul per message on `β⁰ · label`.
  2. The new module must not rely on compile-time constants (like
     `MAX_MESSAGE_WIDTH`) for sizes — that should be the responsibility of
     the `LookupBuilder`'s constructor, which takes the shape from the
     `LookupAir`.
- **Resolution**: see Amendment A above. In summary:
  - Precomputed domain separators `DS[i] = α + i · β^W` replace the
    per-message label term. `LookupMessage` loses `bus_label: u16` → gains
    `bus_id: u16`. Saves ~1 EF×BF mul per message on the prover path.
  - `LookupAir` splits into `LookupAirShape` (non-generic) +
    `LookupAir<LB>: LookupAirShape` (generic over builder, carries `eval`).
    `LookupAirShape` gains `num_bus_ids()`.
  - New `air/src/constraints/lookup/challenges.rs::LookupChallenges<EF>`
    holds `Box<[EF]>` for both `domain_separators` and `beta_powers`. No
    `[EF; N]` arrays, no `const MAX_MESSAGE_WIDTH`.
  - `EncodedLookupGroup::alpha()` is removed. Added
    `EncodedLookupGroup::domain_separator(bus_id)` and `beta_powers()`
    no longer includes β^W.
  - `ConstraintLookupBuilder::new` / `ProverLookupBuilder::new` take
    `shape: &impl LookupAirShape` and build `LookupChallenges` from it.
- **Impact on existing tasks**:
  - Tasks #1, #2, #3 need rework (see Task #3b below). They ship the
    adapter + traits, but on the pre-amendment encoding.
  - Tasks #4–#8 have not started and will land on the post-amendment
    encoding directly.
  - Task #9 grows a line item: delete `air/src/trace/challenges.rs` and
    `MAX_MESSAGE_WIDTH` alongside the old `logup*` files.
  - The old `Challenges<EF>` / `LogUpMessage` surface stays intact during
    the transition — only the new `lookup/` module is affected.
- **Open item**: the exact bus-ID enumeration strategy. The existing
  `*_LABEL` constants (`LINEAR_HASH_LABEL`, `MP_VERIFY_LABEL`, etc.) are
  already small u16 values but scattered across
  `air/src/trace/chiplets/`. Task #5 will decide whether to (a) reuse them
  in-place via `*Msg::bus_id() { self.label_value }`, or (b) move them to
  a central `lookup/bus_id.rs` module. Either works; the amendment does
  not force the choice.

### Task #1 — `lookup/` module skeleton + `LookupMessage` trait — done
- **Date**: 2026-04-10
- **Files touched**:
  - `air/src/constraints/lookup/mod.rs` (new)
  - `air/src/constraints/lookup/message.rs` (new)
  - `air/src/constraints/mod.rs` (added `pub mod lookup;`)
- **Build check**: `cargo check -p miden-air` → clean, 0 warnings from the new files (73 pre-existing warnings in `logup.rs` / `logup_msg.rs` / etc. ignored).
- **Critical** (for Task #2): `LookupMessage` uses the `write_into(&mut [E])` shape, not the `SmallVec` variant from the plan sketch — `smallvec` is not in `air/Cargo.toml` and the task forbade adding deps. Signature is `fn bus_label(&self) -> u16`, `fn width(&self) -> usize` (**payload only, exclusive of the label slot**), `fn write_into(&self, out: &mut [E])` (writes exactly `width()` payload slots). Builder invariant: `width() + 1 ≤ beta_powers.len()` — one slot for the label at β⁰ plus `width` slots for the payload at β¹..β^width.
- **Insights**:
  - `smallvec` is absent from the `miden-air` dependency set; the `write_into` variant avoids adding it and also keeps the constraint path allocation-free, which matches how the existing `Challenges::encode` loop already threads an accumulator.
  - `width()` counts *only* the contiguous payload values — the bus label is separate. This is a post-review adjustment (the initial draft made `width` inclusive of the label, requiring every caller to subtract 1; the user rejected that). Task #2 should size scratch slices to `max_payload_width` directly and precompute `max_payload_width + 1` β-powers.
  - `mod.rs` uses `#[expect(dead_code, reason = "trait has no impls until Task #2 / #5")]` on the `message` submodule. `expect` will *itself* become a warning as soon as Task #2 references the trait, forcing us to remove the attribute at that point — preferred over a silent `allow`.
  - Left `LogUpMessage` and `logup_msg.rs` untouched per Task #1 scope; the rename/blanket-impl happens in Task #5.
  - No `pub use message::LookupMessage` re-export added yet — rustc was flagging it as `unused_import` with zero consumers. Task #2 should add the re-export at the point it first references the trait from sibling submodules.

### Task #2 — `LookupAir` + `LookupBuilder` / `LookupColumn` / `LookupGroup` / `LookupBatch` / `EncodedLookupGroup` traits — done
- **Date**: 2026-04-10
- **Files touched**:
  - `air/src/constraints/lookup/builder.rs` (new)
  - `air/src/constraints/lookup/mod.rs` (edited — added `pub mod builder;`, re-exports, `LookupAir` trait, and a narrowed `expect` comment on the `message` submodule; see "Critical" below)
- **Build check**: `cargo check -p miden-air` → clean, 73 warnings (identical to the Task #1 baseline). Zero warnings from any `constraints/lookup/*` file. `cargo check -p miden-air -p miden-processor` also clean.
- **Critical** (for Tasks #3 / #4 / #5):
  - **`LookupBatch` is a trait, not a concrete helper struct.** The plan sketch left this open; I picked trait-with-GAT because the constraint-path (wraps `RationalSet`) and prover-path (wraps `FractionCollector`) adapters need distinct backing storage and expressing the split via `LookupGroup::Batch<'b>: LookupBatch<Expr = Self::Expr>` is cleaner than parameterizing one struct over a storage `enum`. Adapter authors write a thin concrete `struct ConstraintBatch<'a, 'ab, AB>` / `struct ProverBatch<'a, F, EF>` and bind the GAT.
  - **`main()` passes through the inner `MainWindow`.** I did *not* fix it to `RowWindow<'_, F>`. `MainWindow` is an associated type (`type MainWindow: WindowAccess<Self::Var> + Clone`), which the constraint-path adapter satisfies by forwarding `AB::MainWindow` and the prover-path adapter satisfies by picking a concrete `RowWindow<'a, F>`. Authors just call `.current_slice()` / `.next_slice()` through the `WindowAccess` bound, so the abstraction is transparent from the `LookupAir` writer's point of view. Locking it to `RowWindow<'_, F>` would leak the lifetime parameter onto the GAT chain without upside.
  - **`EncodedLookupGroup::alpha()` returns `Self::VarEF`, not `Self::ExprEF`.** Adapters cache α once at construction time as the `AB::VarEF` that came back from `permutation_randomness()[0]`, so exposing it as a variable avoids a redundant `Into<ExprEF>` round-trip per `insert_encoded` call. `beta_powers()` likewise returns `&[Self::VarEF]`. This required adding a `type VarEF: Copy` associated type on both `LookupColumn` and `EncodedLookupGroup`, pinned through `Expr = Self::Expr, ExprEF = Self::ExprEF, VarEF = Self::VarEF` in the GAT bounds.
  - **`LookupColumn::Expr` / `LookupGroup::Expr` / `LookupBatch::Expr` are bounded by `PrimeCharacteristicRing + Clone`, not just `Clone`.** This is needed so the `LookupMessage<Self::Expr>` bound in `add` / `remove` / `insert` is actually satisfiable — `LookupMessage`'s own `E: PrimeCharacteristicRing + Clone` bound propagates. This is transparent to Task #3's constraint-path adapter because `AB::Expr: Algebra<…>` already implies `PrimeCharacteristicRing` (which in turn implies `Clone` via `Dup: Clone`). Task #4's prover path satisfies it by instantiating `Expr = F` directly.
  - **`#[expect(dead_code)]` stays on `pub mod message;`** — contra the Task #1 log that predicted it would become a stale expectation once Task #2 referenced `LookupMessage`. The trait name *is* now live (referenced by all the builder-side bounds), but the trait *methods* (`bus_label`, `width`, `write_into`) remain dead until Task #3's constraint-path adapter actually calls them via a scratch slice. The submodule-level `expect` is therefore still fulfilled, and removing it regresses the warning count from 73 → 74. I kept the attribute and narrowed its `reason =` to point at Task #3's adapter; Task #3 must remove it once the call site lands. Same logic applied to a new module-level `#![expect(dead_code, reason = "…")]` on `builder.rs` covering all five traits until Task #3 / #4 introduce their impls.
- **Insights**:
  - **Associated-type bound set** (by type, as picked):
    - `LookupBuilder::F: Field` (not the wider `PrimeCharacteristicRing`, because the `ExtensionField<Self::F>` bound on `EF` needs `F: Field`).
    - `LookupBuilder::Expr: Algebra<Self::F> + Algebra<Self::Var>` — copied verbatim from `AirBuilder::Expr`.
    - `LookupBuilder::Var: Into<Self::Expr> + Copy + Send + Sync` — the full `Add<F>/Sub<F>/Mul<F>` soup from `AirBuilder::Var` is **not** required because `Algebra<Self::Var>` on `Expr` lets authors convert through `.into()` before composing. Keeps the bound set narrow and matches the hint in the task instructions.
    - `LookupBuilder::EF: ExtensionField<Self::F>`, `ExprEF: Algebra<Self::Expr> + Algebra<Self::EF>`, `VarEF: Into<Self::ExprEF> + Copy + Send + Sync` — copied from `ExtensionBuilder`.
    - `LookupBuilder::PeriodicVar: Into<Self::Expr> + Copy`, `PublicVar: Into<Self::Expr> + Copy` — copied from `PeriodicAirBuilder` / `AirBuilder::PublicVar`.
    - `LookupBuilder::MainWindow: WindowAccess<Self::Var> + Clone` — copied from `AirBuilder::MainWindow`.
    - `LookupBuilder::Column<'a>: LookupColumn<Expr = Self::Expr, ExprEF = Self::ExprEF, VarEF = Self::VarEF> where Self: 'a` — GAT, pins all three expression/variable types through the chain.
    - `LookupColumn::Expr / ::ExprEF: PrimeCharacteristicRing + Clone` (see above); `LookupColumn::VarEF: Copy`.
    - `LookupColumn::Group<'a> / ::EncodedGroup<'a>` are GATs bound to `LookupGroup<Expr, ExprEF>` and `EncodedLookupGroup<Expr, ExprEF, VarEF>` respectively.
    - `LookupGroup::Expr / ::ExprEF: PrimeCharacteristicRing + Clone`; `LookupGroup::Batch<'b>: LookupBatch<Expr = Self::Expr> where Self: 'b`.
    - `LookupBatch::Expr: PrimeCharacteristicRing + Clone`.
    - `EncodedLookupGroup::VarEF: Copy`, plus `LookupGroup` super-trait.
  - **`add` / `remove` / `insert` on `LookupGroup` take `msg: impl FnOnce() -> M`** so the prover-path adapter can skip both the construction *and* the encoding work when `flag == 0`. `LookupBatch::add` / `remove` / `insert` take `msg: M` by value because the outer `batch(flag, …)` call already handles the skip, so per-interaction closures would be dead overhead inside the batch.
  - **`EncodedLookupGroup::insert_encoded`'s closure returns `Self::ExprEF`** (not a message), because at that point the author has already composed the denominator using `alpha()` / `beta_powers()` manually. The adapter treats the result identically to what `Challenges::encode` would produce.
  - **No `num_groups` on `LookupAir`.** Groups are opened dynamically inside the closure flow; the adapter tracks them implicitly via the column accumulator algebra.
  - **One plan deviation worth flagging for the execution log review**: the plan sketch's `LookupColumn` carried a `'ab` lifetime parameter (`LookupColumn<'ab>`); I dropped it. The borrow scoping is handled entirely through the `Column<'a>` GAT on `LookupBuilder`, so `LookupColumn` itself doesn't need a lifetime parameter in its declaration. This matches how `LookupGroup` / `LookupBatch` are also lifetime-free in their declarations.
  - **Judgment call on the `expect` suppression strategy**: I used file-level `#![expect(dead_code)]` on `builder.rs` with a reason pointing at Tasks #3 / #4, rather than sprinkling per-item `#[expect(dead_code)]` on each of the five traits. The per-item variant would require touching every trait + every method + every associated type (rustc flags "methods of trait X are never used" as separate from "trait X is never used"), which clutters the API docs. A single file-level attribute is tighter here. Similarly, the two `pub use` blocks in `mod.rs` carry targeted `#[expect(unused_imports)]` attributes because four of the five re-exports are not yet referenced from anywhere inside the `air` crate — Task #3 / #4 / #5 will satisfy them, at which point the attributes must be removed.

### Task #3 — `ConstraintLookupBuilder` constraint-path adapter — done
- **Date**: 2026-04-10
- **Files touched**:
  - `air/src/constraints/lookup/constraint.rs` (new)
  - `air/src/constraints/lookup/mod.rs` (edited — added `pub mod constraint;`, added `pub use constraint::ConstraintLookupBuilder;`, removed the now-stale `#[expect(dead_code)]` on `pub mod message;` and the pair of `#[expect(unused_imports)]` blocks on the `builder::{…}` / `message::LookupMessage` re-exports, added a fresh `#[expect(unused_imports)]` on the `ConstraintLookupBuilder` re-export)
  - `air/src/constraints/lookup/builder.rs` (edited — see "Critical" below: trait-signature fix forced by the `AB::RandomVar` vs `AB::VarEF` mismatch plus lifetime scoping on GAT methods)
- **Build check**: `cargo check -p miden-air` → clean, 73 warnings (identical to the Task #2 baseline). `cargo check --workspace` clean. `cargo test -p miden-air --lib` → 70/70 passing, including both `enforce_main_degrees_within_budget` and `enforce_chiplet_degrees_within_budget`.
- **Critical** (for Tasks #4 / #6):
  - **`EncodedLookupGroup::alpha()` / `beta_powers()` now return `Self::ExprEF` / `&[Self::ExprEF]`, NOT `Self::VarEF` / `&[Self::VarEF]`.** The Task #2 log claimed the adapter could cache α / β as `AB::VarEF`-typed handles pulled from `ab.permutation_randomness()`. This turned out to be impossible: `PermutationAirBuilder::RandomVar: Into<ExprEF> + Copy` is a strictly weaker bound set than `ExtensionBuilder::VarEF: Into<ExprEF> + Copy + Send + Sync`, and in the generic `AB` those are **distinct associated types** with no `From`/`Into` between them. The two options the user flagged were (a) store α/β as `AB::VarEF` on the builder, or (b) change the `alpha`/`beta_powers` return types. Option (a) is unreachable because there is no way to synthesise an `AB::VarEF` from an `AB::RandomVar`, so I took option (b): drop the `type VarEF: Copy` associated type from `LookupColumn` *and* `EncodedLookupGroup`, drop the corresponding `VarEF = Self::VarEF` binding on `LookupBuilder::Column<'a>`, and rewrite the two accessors as `fn alpha(&self) -> Self::ExprEF` / `fn beta_powers(&self) -> &[Self::ExprEF]`. The constraint-path adapter caches `Challenges<AB::ExprEF>` (converting `r[0]`/`r[1]` from `AB::RandomVar` via `.into()` exactly once), then returns `self.challenges.alpha.clone()` / `&self.challenges.beta_powers[..]` to encoded-group authors. `LookupBuilder::VarEF` is *kept* at the top level (still bound to `AB::VarEF`, still useful for future permutation-trace-cell access) but it no longer propagates into the column / group trait chain.
  - **`LookupBuilder::column`, `LookupColumn::group` / `group_with_cached_encoding`, and `LookupGroup::batch` now take an explicit GAT-lifetime parameter on the method signature**, matching the `&'a mut self` receiver. The Task #2 trait draft used the implicit `Self::Column<'_>` form; that desugars to `for<'c> FnOnce(&mut Self::Column<'c>) -> R`, which requires the GAT bound `Self: 'c` to hold for *arbitrary* `'c`. When `Self = ConstraintLookupBuilder<'ab, AB>`, satisfying that universally-quantified bound would require `AB: 'static`, which is false. Pinning `'a` to the method receiver (`fn column<'a, R>(&'a mut self, f: impl FnOnce(&mut Self::Column<'a>) -> R) -> R`) ties the outlives relation to the actual borrow scope and sidesteps the HRTB blow-up. Same fix applied to `group`, `group_with_cached_encoding`, and `batch`. **No behaviour change for adapter authors** — the method surface is the same, only the lifetime's origin has moved from an anonymous `'_` to a named parameter. Task #4's prover adapter will pick up this form automatically because `rustc`'s elision rules still apply inside the method body.
  - **`pub mod message;` in `mod.rs` no longer needs `#[expect(dead_code)]`.** The adapter's `encode` helper in `constraint.rs` now invokes `msg.write_into(&mut scratch)` through a `LookupMessage<Self::Expr>` bound, which is enough to clear the transitive dead-code warning on `bus_label` / `width` / `write_into` (combined with the module-level `#![expect(dead_code)]` on `constraint.rs` that keeps the unreachable chain silent for now). Task #2's log predicted this expect-removal as a Task #3 follow-up; it is done.
  - **`builder.rs` no longer uses `#![expect(dead_code)]`**; the attribute has been narrowed to cover only the `LookupBuilder` trace-accessor methods (`main` / `periodic_values` / `public_values`), which stay dead until Task #6 runs its first `lb.main()` call inside a ported bus. The trait definitions themselves are now "live" via the constraint-path impl chain, so the file-level suppression the Task #2 log put in place had become overly broad.
- **Insights**:
  - **Delegation strategy: inline the formulas, do NOT wrap `RationalSet` / `Batch`.** The user gave me the choice of (a) an internal `(U, V)` pair with duplicated algebra or (b) a wrapped `RationalSet`/`Batch` with a `LookupMessage → LogUpMessage` shim. I picked (a). The decisive factor is the trait mismatch: `LogUpMessage::encode(&self, &Challenges<EF>) -> EF` takes ownership of the encoding pipeline, while `LookupMessage::write_into(&self, &mut [E])` expects the *caller* to drive a scratch-slice encoding loop. Wrapping `RationalSet` would require building a transient `LogUpMessage` impl per call that closures over the `LookupMessage` — which is five lines of scaffolding per interaction for four lines of saved arithmetic. The algebra I inline is literally the bodies of `RationalSet::add_single` (`u += (v−1)·flag; v += flag`), `RationalSet::add_batch` (`u += (d−1)·flag; v += n·flag`), `RationalSet::insert_encoded`, `Batch::insert_encoded` (`n' = n·v + m·d; d' = d·v`), and `Column::add_set` / `Column::constrain`. Every formula is sourced by comment from the exact `logup.rs` line range the plan pointed at.
  - **`LookupBuilder::VarEF` binds to `AB::VarEF`** (not `AB::RandomVar` and not `AB::ExprEF`). `AB::VarEF` is the only type that satisfies the Task #2 bound set `Into<ExprEF> + Copy + Send + Sync`. It stays as a top-level associated type for future use (e.g., reading permutation-column cells directly); the column / group / encoded-group chain no longer mentions it because the encoded-group's challenge accessors moved to `ExprEF` as described above.
  - **Lifetime simplification**: the plan sketched `ConstraintColumn<'a, 'ab, AB>` / `ConstraintGroup<'a, 'ab, AB>` with two lifetime parameters; I collapsed both into a single `'a` per type. The outer builder's `'ab` is subsumed into the reborrow lifetime `'a` — `ConstraintColumn<'a, AB>` holds a `&'a mut AB` that was reborrowed from the builder's `&'ab mut AB`, and since `'ab: 'a` always, carrying both lifetimes would only pin the struct to an uselessly longer lifetime.
  - **Explicit `AB: 'a` outlives bound on each adapter struct**. Each of the five structs carries a `where AB: LiftedAirBuilder<F = Felt> + 'a` clause. This is necessary because the implicit `AB: 'a` bound that *would* be inferred from the `&'a mut AB` / `&'a Challenges<AB::ExprEF>` fields does not automatically propagate into the GAT impl's `where Self: 'a` clause well-formedness check — making it explicit at the struct level is the cleanest fix. Bonus: the GAT impls (`type Column<'a> = ConstraintColumn<'a, AB> where Self: 'a, AB: 'a;`) now have a redundant-but-harmless `AB: 'a` clause that makes the intent obvious to future readers.
  - **Module-level `#![expect(dead_code)]` on `constraint.rs`** — no consumer constructs a `ConstraintLookupBuilder` until Task #6 ports the first bus, so all five structs, their constructors, their `finalize` / `fold_group` / `encode` / `absorb*` helpers, and every trait method on the adapter chain are transitively unused. One file-level `expect` covers the lot; Task #6 must delete it the moment the first `ConstraintLookupBuilder::new(builder)` call lands in a bus port.
  - **`ConstraintGroup::encode` and `ConstraintBatch::encode` are duplicated** (four identical lines each). I kept the duplication instead of pulling a free function off the module root because `Challenges` is borrowed through a different path in each case (`&self.challenges` on the group vs the batch), and routing a free function through a `&Challenges<AB::ExprEF>` argument would require every caller to spell out the full type — more line count, no semantic gain. If Task #6 finds the duplication painful during the port, it can promote `encode_lookup_message(&Challenges<AB::ExprEF>, &impl LookupMessage<AB::Expr>) -> AB::ExprEF` into a module-private helper.
  - **`ConstraintGroupEncoded` delegates `LookupGroup` to an inner `ConstraintGroup`** rather than being the same type as `ConstraintGroup`. This matches the task description's explicit requirement of two distinct types and avoids a subtle footgun: if the encoded / simple paths shared a concrete type, the GAT bindings on the column would collapse, and the ability to differentiate the two surfaces at future extension points (e.g., per-path diagnostics) would be lost. The delegation cost is six `self.inner.method(args)` one-liners.
  - **Split borrow trick in `ConstraintLookupBuilder::column`**: `self.permutation_local[idx].into()` copies the `AB::VarEF` out first (Copy type), so the subsequent `&mut *self.ab` reborrow and `&self.challenges` share don't conflict with it. The disjoint-field borrow check then lets the `ConstraintColumn` hold both simultaneously.
- **Plan deviations for Task #4 / #6 to know about**:
  - Task #4's `ProverLookupBuilder` must track the same GAT-lifetime-on-method pattern used here (`fn column<'a, R>(&'a mut self, f: impl FnOnce(&mut Self::Column<'a>) -> R) -> R`). Any attempt to go back to the `Self::Column<'_>` shorthand will trigger the same HRTB blow-up.
  - Task #4 must bind `ProverLookupBuilder::VarEF` to whatever satisfies `Into<ExprEF> + Copy + Send + Sync`; on the prover path where `Expr = F`, that's just `F` itself. The top-level `VarEF` is no longer forced to match the encoded-group chain, so the prover's `Self::VarEF` is a free choice.
  - Task #6's port of `g_bqueue` lands the first live `ConstraintLookupBuilder::new(builder)` construction, at which point the `#![expect(dead_code)]` on `constraint.rs` must be removed (and the dead-code warnings it silences will either vanish or — if the port is only partial — need a narrower expect scoped to the un-ported adapter helpers). The `#[expect(unused_imports)]` on the `ConstraintLookupBuilder` re-export in `mod.rs` will similarly need removal.

### Task #11 — Amendment A rework: domain-separator encoding + dynamic sizes — done
- **Date**: 2026-04-10
- **Files touched**:
  - `air/src/constraints/lookup/challenges.rs` (new — `LookupChallenges<EF>` struct + `new(alpha, beta, max_message_width, num_bus_ids)` constructor)
  - `air/src/constraints/lookup/mod.rs` (edited — added `pub mod challenges;` + `pub use challenges::LookupChallenges;`; split the old `LookupAir` trait into non-generic `LookupAirShape` (carrying `num_columns` / `max_message_width` / `num_bus_ids`) and generic `LookupAir<LB>: LookupAirShape` carrying only `eval`; updated doc comments to point at the new domain-separator encoding)
  - `air/src/constraints/lookup/message.rs` (edited — renamed `LookupMessage::bus_label` → `bus_id`; rewrote doc comments to describe the `DS[i] + Σ βᵏ·v[k]` encoding instead of the old "label at β⁰"; the `u16` return type is unchanged but semantically now indexes `LookupChallenges::domain_separators`)
  - `air/src/constraints/lookup/builder.rs` (edited — removed `EncodedLookupGroup::alpha`; added `EncodedLookupGroup::domain_separator(bus_id: u16) -> Self::ExprEF`; updated `beta_powers()` doc to state the slice length is exactly `W = max_message_width` and that `β^W` is absorbed into the domain separators; tweaked the trait-level and module-level prose to match)
  - `air/src/constraints/lookup/constraint.rs` (edited — replaced `challenges: Challenges<AB::ExprEF>` with `challenges: LookupChallenges<AB::ExprEF>` on `ConstraintLookupBuilder` / `ConstraintColumn` / `ConstraintGroup` / `ConstraintBatch`; constructor signature is now `pub fn new<S: LookupAirShape>(ab: &'ab mut AB, shape: &S) -> Self` and passes `shape.max_message_width()` / `shape.num_bus_ids()` into `LookupChallenges::new`; rewrote the two `encode` helpers (`ConstraintGroup::encode` and `ConstraintBatch::encode`) to start the accumulator from `self.challenges.domain_separators[bus_id]` and fold the payload with `beta_powers[0..width]`; replaced the `alpha()` impl on `ConstraintGroupEncoded` with `domain_separator(bus_id)`; removed the stale `use crate::trace::Challenges` import)
  - `docs/src/design/lookup_air_plan.md` (this execution log entry)
- **Build check**: `cargo check -p miden-air` → clean, **73 warnings (identical to the Task #2 / Task #3 baseline)**. Zero warnings originating from any `constraints/lookup/*` file. `cargo test -p miden-air --lib` → **70/70 passing**, including both `enforce_main_degrees_within_budget` and `enforce_chiplet_degrees_within_budget`. No tests were added in this task (see Insights below on why the optional shape-ctor test was skipped).
- **Critical** (for Tasks #4 / #6):
  - **`ConstraintLookupBuilder::new` now takes two arguments**: `pub fn new<S: LookupAirShape>(ab: &'ab mut AB, shape: &S) -> Self`. Task #6's first live construction must pass a concrete `&MidenLookupAirShape` (or whatever name Task #6 picks). The `LookupChallenges` table is sized from that shape at construction time, so passing a stale / undersized shape will surface as a `debug_assert!` failure (`msg.width() > beta_powers.len()` or `bus_id as usize > domain_separators.len()`) inside `ConstraintGroup::encode` / `ConstraintBatch::encode` — not at construction time.
  - **`LookupMessage::bus_id` is the new method name.** All Task #5 blanket impls must spell it `fn bus_id(&self) -> u16 { self.label_value }` (or whatever the per-`*Msg` field ends up being called). The `u16` return type still matches the existing `label_value` fields, so the blanket-impl macro in Task #5 is a pure rename from `bus_label` → `bus_id`.
  - **`EncodedLookupGroup` no longer exposes `alpha()`.** Bus authors using `group_with_cached_encoding` must restructure their cached-fragment patterns around `ge.domain_separator(bus_id) + shared_payload_fragment` rather than the old `ge.alpha() + ge.beta_powers()[0] * label + ...` soup. The `beta_powers()` slice is now length `W` exactly (matching `max_message_width`), not `W + 1`; Task #6's first port (`g_bqueue`) should treat `beta_powers()[0..msg.width()]` as the intended slicing convention.
  - **`LookupChallenges<EF>` is the new home for α/β state**; `crate::trace::Challenges<EF>` still exists and must keep compiling until Task #9 (the un-ported `logup*` files still reference it). Do NOT delete `air/src/trace/challenges.rs` or `MAX_MESSAGE_WIDTH` in this task — Task #9 handles both.
- **Insights**:
  - **Scratch-allocation strategy (the user asked for this specifically)**: I picked `Vec<AB::Expr>` sized exactly to `msg.width()` per call, not a fixed-size stack array. Two reasons:
    1. `AB::Expr` on the constraint path is a symbolic expression type (`ExtExpressionBuilder::Expr` in practice), which does not have a `Copy` or `Default` impl that would let us reuse a `[AB::Expr::ZERO; 16]` buffer across calls — each slot would need re-initialisation every iteration, eating back the savings.
    2. The allocation is on the constraint-path encoding loop, which runs once per symbolic expansion (a few thousand times total per `ProcessorAir::eval` invocation), not per row. Per-row performance is a prover-path concern, and the prover path (Task #4) will use a different scratch strategy anyway because `F` *is* `Copy`.
    The `Vec` pattern is also what the existing Task #3 code already used; keeping it consistent avoids churn in the degree-budget audit path. If Task #4's prover adapter shows this as a hot spot, we can revisit by plumbing a per-column scratch buffer through `ConstraintColumn`, but that is a future-proof optimization, not a correctness concern.
  - **`#[expect(dead_code)]` attribute inventory** (3 total in the new `lookup/` module after this task, down from 3 before — same count, different scope):
    1. `lookup/mod.rs:74` — trait-level `#[expect(dead_code)]` on `LookupAir<LB>` itself, waiting for Task #6's `MidenLookupAir` impl.
    2. `lookup/mod.rs:76` — method-level `#[expect(dead_code)]` on `LookupAirShape::num_columns` specifically. `max_message_width` and `num_bus_ids` are live (consumed by `ConstraintLookupBuilder::new`), but `num_columns` has no live caller yet — Task #6 will add a `debug_assert_eq!(self.column_idx, shape.num_columns())` sanity check at the end of `eval`, and this attribute must be removed at the same time.
    3. `lookup/builder.rs:41` — file-level `#![expect(dead_code)]` on the `LookupBuilder` trace-accessor methods (`main` / `periodic_values` / `public_values`), unchanged from Task #3. Task #6 removes this when the first bus port calls `lb.main()`.
    4. `lookup/constraint.rs:50` — file-level `#![expect(dead_code)]` covering every helper on the adapter chain, unchanged from Task #3. Task #6 removes this when the first `ConstraintLookupBuilder::new(builder, &shape)` call lands.
    5. `lookup/mod.rs:26-30` — `#[expect(unused_imports)]` on the `ConstraintLookupBuilder` re-export, unchanged from Task #3. Also goes away in Task #6.
    **(Four `expect` attributes on the adapter/trait chain, plus one on the re-export — same structure as Task #3 finished with, just with `num_columns` swapping in for the old `num_bus_ids` slot.)**
  - **No test added**: I skipped the optional "dummy shape + compile-check" test that the task description suggested as a build-verification helper. The `cargo check -p miden-air` clean-at-73-warnings run already proves the constructor's type-level wiring compiles, and a `#[cfg(test)] struct DummyShape;` implementor would need either a private `extern crate alloc` re-exposure or a delicate `expect(dead_code)` dance to stay warning-clean. Since Task #6 will plant a real `MidenLookupAirShape` within days, the test would be short-lived churn. Escalated judgment call: skip for now; the build verification carries the weight.
  - **API detail that needed tweaking during implementation**: the amendment's `LookupChallenges::new` sketch had `ds = alpha; ... ds = ds.clone() + cur.clone()` — this is *correct* for `PrimeCharacteristicRing + Clone`, but the literal `+` operator requires `Add<Output = Self>` which `PrimeCharacteristicRing` supplies. I kept the sketch verbatim; no API tweak was needed. The only non-obvious choice was using `.clone()` on both operands of each arithmetic step (`ds.clone() + cur.clone()`) to work around the fact that `PrimeCharacteristicRing`'s `Add` impl takes `self` by value rather than by reference. This matches the pattern already used in `crate::trace::challenges::Challenges::new`.
  - **Doc comment divergence**: the amendment text (§A.5) described the shared fragment in the encoded-group closure example as `ge.beta_powers()[0].clone() * addr.clone() + ge.beta_powers()[1].clone() * node_index.clone()` — i.e. **without** an `α` term anywhere, because the domain separator lives on `ge.domain_separator(bus_id)` now. I kept the `builder.rs` doc prose in line with that mental model (the shared fragment is "label-free"), so Task #6 bus authors should not expect to see any `α` in their cached-fragment code — only β-weighted payload bits, with the `domain_separator(id)` spliced in per `insert_encoded` call.
  - **No `MAX_MESSAGE_WIDTH` or fixed-size array introduced** in the new module. Verified via `rg 'MAX_MESSAGE_WIDTH|\[.*;.*16\]' air/src/constraints/lookup/` — zero hits in the four `lookup/*.rs` files.
- **Plan deviations for Task #4 / #6 to know about**:
  - Task #4's `ProverLookupBuilder::new` must take the same `shape: &S` parameter. The amendment §A.6 already shows the signature; no additional deviation.
  - Task #6's first `LookupAirShape` implementor (e.g. `MidenLookupAirShape`) should be a zero-sized struct; `num_columns` / `max_message_width` / `num_bus_ids` are all compile-time constants on the VM side, so the impl is three one-line methods returning `usize` literals. Reminder: the `num_columns` method currently carries a `#[expect(dead_code)]` attribute that Task #6 must remove once it starts calling the method from the column-advancement sanity check.
  - The `ConstraintGroup::encode` / `ConstraintBatch::encode` helpers remain internally duplicated (four lines each, one pair in `ConstraintGroup` and one pair in `ConstraintBatch`). Task #3's log already flagged this as intentional (to avoid threading `&LookupChallenges<AB::ExprEF>` through a free function argument); Task #11 did not consolidate them. If Task #6 finds the duplication painful, promote a module-private helper.

### Task #4 — `ProverLookupBuilder` prover-path adapter + Amendment A.8 scratch retrofit — done
- **Date**: 2026-04-10
- **Files touched**:
  - `air/src/constraints/lookup/prover.rs` (new — `ProverLookupBuilder<'a, F, EF>`, `ProverColumn`, `ProverGroup`, `ProverBatch`)
  - `air/src/constraints/lookup/constraint.rs` (edited — Amendment A.8 retrofit: added `scratch: Vec<AB::Expr>` on the builder, threaded `scratch: &'a mut [AB::Expr]` through `ConstraintColumn` / `ConstraintGroup` / `ConstraintBatch`, flipped both `encode` helpers to `&mut self`, inlined `fold_group` into `ConstraintColumn::group` / `group_with_cached_encoding` to keep the disjoint-field borrow typecheck happy)
  - `air/src/constraints/lookup/mod.rs` (edited — added `pub mod prover;` + `pub use prover::ProverLookupBuilder;` under a task-scoped `#[expect(unused_imports)]`; tightened the `ConstraintLookupBuilder` re-export's reason string to "Task #6" only now that Task #4 is complete)
  - `docs/src/design/lookup_air_plan.md` (this execution log entry)
- **Build check**: `cargo check -p miden-air` → **73 warnings (baseline unchanged)**. `cargo check --workspace` → clean. `cargo test -p miden-air --lib` → **70/70 passing**, including `enforce_main_degrees_within_budget` and `enforce_chiplet_degrees_within_budget`. `cargo clippy -p miden-air --lib` → 75 warnings, identical to the pre-change baseline (no new clippy lints introduced).
- **Critical** (for Tasks #6 / #8):
  - **`ProverLookupBuilder::new` signature (final, compiling)**:
    ```rust
    pub fn new<A>(
        main: RowWindow<'a, F>,
        periodic_values: &'a [F],
        public_values: &'a [F],
        alpha: EF,
        beta: EF,
        air: &A,
        column_fractions: &'a mut [(EF, EF)],
    ) -> Self
    where
        A: LookupAir<Self>,
    ```
    `column_fractions` is a **flat `&mut [(EF, EF)]`** — one `(n, d)` slot per permutation column, not a `Vec<Vec<(EF, EF)>>`. See the layout-choice note below.
  - **`column_fractions` layout: flat `[(EF, EF)]`, one slot per column.** Each [`LookupBuilder::column`] call overwrites the current slot with the column's final LogUp fraction pair and advances `column_idx`. The caller is expected to (a) pre-allocate the slice once at trace-build time sized to `air.num_columns()`, (b) call `air.eval(&mut lb)` once per row, (c) read / accumulate the per-column pairs into a running-sum state between rows, then (d) call [`ProverLookupBuilder::reset_column_idx`] before the next `eval`. This keeps the per-row overhead at literally one pointer write per column and avoids allocating a trace-length `Vec<(EF, EF)>` per column. The alternative `&mut [Vec<(EF, EF)>]` layout would cost one `Vec::push` per column per row on top; I rejected it because the aux-trace builder already tracks its own running-sum state and doesn't need the builder to remember per-row pairs.
  - **`reset_column_idx(&mut self)` helper** — documented in the `prover.rs` module docs and on the struct impl. The aux-trace loop must call this between rows; forgetting it will cause the second row's `column(f)` calls to panic (`column_idx` ≥ `column_fractions.len()`). No auto-reset because the caller might want to re-read the slots between rows under a different `column_idx` scheme.
  - **`ProverGroup` is used for both `LookupColumn::Group<'g>` and `LookupColumn::EncodedGroup<'g>`** — per the plan's §Prover-path adapter ("use the same ProverGroup type for both Group and EncodedGroup"). The `LookupColumn::group_with_cached_encoding` impl runs only the `canonical` closure and drops `_encoded` unused. This matches `FractionCollector::add_group_with` at `logup.rs:602` (`fold(self); // drops fold_constraints unused`).
  - **Flag-zero skip lives on `ProverGroup::add` / `remove` / `insert` / `insert_encoded` *and* on `ProverGroup::batch`**, but the batch's skip gates only the fold — not the build closure — because the build returns `R` and we need a value to pass back to the caller. The existing `FractionCollector::add_batch` at `logup.rs:569` can early-return cleanly because its closure returns `()`, but the new trait's `-> R` signature forces the fall-through. `ProverBatch::{add, remove, insert}` do **not** gate on flag — the outer group's flag already handles that.
- **Insights**:
  - **Amendment A.8 retrofit was almost mechanical except for the `fold_group` inlining.** Threading `scratch: &'g mut [AB::Expr]` through the GAT signature `Self::Group<'g>` pins the mutable borrow of `self.scratch` to the full `'g` method lifetime. After the group closure returns, destructuring the group with `let ConstraintGroup { u, v, .. } = group;` does *not* visibly release the `'g`-tagged borrow from the borrow checker's perspective, so the subsequent `self.fold_group(u, v)` (which takes `&mut self` wholesale) trips a second-mutable-borrow error. The fix: inline the `fold_group` body directly into `column::group` and `column::group_with_cached_encoding`, where the borrow checker can see that `self.u` and `self.v` are disjoint fields from `self.scratch`. Same pattern applied to `ProverColumn::group` / `group_with_cached_encoding`. The `fold_group` method still exists on both adapters for documentation purposes — it just has no live callers post-A.8.
  - **Prover-side scratch pattern: `Vec<F>` instead of `Vec<AB::Expr>`, with `F: Copy`.** The struct definitions are structurally identical to the constraint adapter (per-layer `scratch: &'lifetime mut [F]`), but the inner encoding loop compiles to plain copies instead of `.clone()` calls because `F: Copy`. I mirrored the exact same reborrow chain (`&mut self.scratch[..]` → `&mut *self.scratch` at each GAT boundary) for consistency with the constraint adapter, not because the prover's `F: Copy` strictly requires it.
  - **Encoding loop shape (both adapters, post-A.8)**:
    ```rust
    msg.write_into(&mut self.scratch[..width]);
    let mut acc = self.challenges.domain_separators[id].clone(); // constraint path
    // or:
    let mut acc: EF = self.challenges.domain_separators[id];     // prover path
    for k in 0..width {
        acc += self.challenges.beta_powers[k].clone() * self.scratch[k].clone(); // constraint
        // or:
        acc += self.challenges.beta_powers[k] * self.scratch[k];                 // prover
    }
    ```
    The mutable `write_into` borrow ends at the semicolon; the accumulator loop then reads the same buffer through immutable shared reads. Rust NLL accepts this exactly because the two borrow scopes are lexically disjoint — a later refactor that tried to stream the write and read together (e.g. via `zip` iterators) would have to thread the lifetimes manually.
  - **GAT-method lifetime pattern carried over verbatim from Task #3.** Every closure-taking method on the prover adapter (`column`, `group`, `group_with_cached_encoding`, `batch`) pins the GAT lifetime to a named `'c` / `'g` / `'b` parameter on the method receiver, matching the Task #3 Critical note about avoiding HRTB blow-up. I didn't need to experiment — Task #3's log was explicit about the right shape.
  - **`ProverColumn<'c, 'a, F, EF>` carries two lifetimes**: `'c` for the column's scratch / challenges reborrow lifetime (tied to the `&'c mut self` on `LookupBuilder::column`), and `'a` for the outer `RowWindow<'a, F>` / `periodic_values: &'a [F]` etc. stored on the builder. The `'a: 'c` constraint is explicit. The constraint-path adapter collapses its analogous `'ab` lifetime into `'a` because `ConstraintColumn` doesn't hold any outer-lifetime data (its `&'a mut AB` reborrow is already `'a`-scoped). The prover path has no such shortcut — the `RowWindow` needs its own lifetime.
  - **`Debug` not added on `ProverLookupBuilder`.** The constraint adapter doesn't implement `Debug` either, so I followed suit. If Task #8's aux-trace builder needs it for tracing, a `#[derive(Debug)]` can land then (will require `where F: Debug, EF: Debug`).
  - **Module-level `#![expect(dead_code)]` with a task-specific reason**: `"ProverLookupBuilder has no live caller until Task #8 wires the per-row aux-trace loop."` Task #8 must remove this attribute when the first live construction lands, and will also need to delete the `#[expect(unused_imports)]` on the `pub use prover::ProverLookupBuilder;` re-export in `mod.rs`.
  - **Batch-return-type gymnastics**: on the constraint path, `ConstraintBatch::batch` always runs the `build` closure (because the symbolic flag can't be compared against zero at compile time) and unconditionally folds the `(N, D)` pair into the group's `(U_g, V_g)` accumulator multiplied by the symbolic flag. On the prover path, the same closure must run unconditionally (because we need the `R` return value), but the fold is gated on `flag != F::ZERO`. This is a deliberate asymmetry — the existing `FractionCollector::add_batch` also only runs the build when `flag != ZERO`, but that closure returns `()` so it can early-return entirely. Our `-> R` trait signature doesn't allow that shortcut, and manufacturing a dummy `R` is impossible because the trait doesn't require `R: Default`.
  - **No tests added** for `ProverLookupBuilder`. The task description allowed this ("skip if it introduces churn"), and the minimum useful test needs a toy `LookupAir + LookupMessage` pair plus a hand-computed running-sum check — easily 100 lines of scaffolding that will be churned immediately when Task #6 lands a real `MidenLookupAir` and Task #8 lands the per-row loop. I would rather wait for one of those callers to exercise the adapter than write a throwaway test.
  - **Did not inline `ConstraintGroup::encode` / `ConstraintBatch::encode` into a shared helper** despite Task #11's log flagging the duplication. The A.8 retrofit touched both anyway, so I could have consolidated — but doing so would require threading `(&LookupChallenges<AB::ExprEF>, &mut [AB::Expr])` through a free function, and the lifetime gymnastics more than eat the four saved lines per encode body. Same applies on the prover side (`ProverGroup::encode` / `ProverBatch::encode` are a second pair). If Task #6 finds the duplication painful, promote a free `fn encode_lookup_message<E, EF, M>(challenges: &LookupChallenges<EF>, scratch: &mut [E], msg: &M) -> EF` helper; it is genuinely straightforward once the bounds are right.
- **Plan deviations for Task #6 / #8 to know about**:
  - The constraint adapter's struct definitions now all carry a `scratch: &'a mut [AB::Expr]` field in addition to the previous fields. Any code in Task #6's bus ports that matches on `ConstraintGroup { .. }` (e.g. in assertions or debugging) should use the `..` catch-all pattern, not explicit field enumeration.
  - The prover-path adapter's `ProverLookupBuilder::new` expects `column_fractions.len() == air.num_columns()` exactly. Task #8's aux-trace builder must pre-size the slice accordingly; the debug assert will catch any mismatch during development.
  - Both adapters' `group_with_cached_encoding` impl treat the two closures asymmetrically: constraint path runs only `encoded`, prover path runs only `canonical`. Task #6 bus authors should be aware that the *prover-path contribution* comes from the `canonical` closure and the *constraint-path contribution* comes from the `encoded` closure, and the two must produce mathematically identical `(U, V)` pairs.

### Task #5 — `LookupMessage` blanket impls on the `*Msg` structs — done
- **Date**: 2026-04-10
- **Files touched**:
  - `air/src/constraints/logup_msg.rs` (edited — appended a new "LOOKUP MESSAGE IMPLEMENTATIONS (Task #5)" section below the existing `impl_logup_message!` macro block; added 12 direct `impl LookupMessage<E>` blocks; left the legacy `LogUpMessage` trait, the per-struct `encode` methods, and the `impl_logup_message!` macro untouched for Task #9 to delete)
  - `docs/src/design/lookup_air_plan.md` (this execution log entry)
- **Build check**: `cargo check -p miden-air` → **73 warnings (baseline unchanged)**. `cargo check --workspace` → clean. `cargo test -p miden-air --lib` → **70/70 passing**, including both `enforce_main_degrees_within_budget` and `enforce_chiplet_degrees_within_budget`. `cargo clippy -p miden-air --lib` → **74 warnings (down 1 from the Task #4 baseline of 75)**. No new clippy lints introduced: the initial draft used four `for i in 0..N { out[k + i] = arr[i].clone(); }` unroll loops which tripped `clippy::manual_memcpy`; I rewrote those five sites as `out[a..b].clone_from_slice(&arr)` to keep clippy clean.
- **Critical** (for Task #6):
  - **Ten structs received real `bus_id`s from existing `label_value` / `op_value` / constant `LABEL` fields; six structs received placeholder `0`s that Task #6 must replace when it wires each bus.** See the "Bus-id sourcing" table in Insights below. The placeholder `0`s are documented in per-impl comments (`// Placeholder — Task #6 sets the bus ID when wiring the <bus name> port.`). When Task #6 ports each bus, it should grep for those comments and substitute the concrete `const BUS_* = …` reference.
  - **Four structs were deliberately *not* given `LookupMessage` impls**: `SiblingMsg`, `MemoryResponseMsg`, `KernelRomResponseMsg`, and `BitwiseResponseMsg`. `SiblingMsg` uses `encode_sparse` with two non-contiguous beta layouts selected by `bit`, which doesn't fit the contiguous `β⁰…β^(width-1)` model of the new trait — Task #7 (hash kernel bus port) is expected to split it into two contiguous-layout variants gated by `bit` / `1 - bit`. The three `*ResponseMsg` structs carry runtime `label: E` expression fields (muxed from chiplet selector columns) rather than compile-time `u16`s, so they cannot satisfy the `fn bus_id(&self) -> u16` signature — Task #6 (chiplet response bus port) must restructure them into per-bus variants with fixed labels before adding `LookupMessage` impls. **The four skipped structs keep their legacy `encode` methods and `LogUpMessage` impls intact** so the un-ported `logup_bus/hash_kernel.rs` and `logup_bus/chiplet_responses.rs` files still compile against the old API.
  - **The new `LookupMessage` impls carry no `#[expect(dead_code)]` attributes of their own.** Trait-impl methods don't trigger `dead_code` warnings in Rust (only free functions, inherent methods, and fields do), so the new impls compile silently even though no live caller reaches them until Task #6 lands its first `ConstraintLookupBuilder::new(builder, &shape)` inside a ported bus port. The chain of `#![expect(dead_code)]` attributes on `lookup/builder.rs`, `lookup/constraint.rs`, and `lookup/prover.rs` (all left unchanged by this task) continues to cover the adapter types — those task-scoped suppressions handle the dead-code surface around the new impls without needing new attributes here.
  - **No `use super::lookup::message::LookupMessage;` path simplification** — I used the long path deliberately instead of adding a shorter `pub use` in some parent module. The path `air::constraints::lookup::message::LookupMessage` is the canonical location the plan documents; adding intermediate re-exports would make the hand-off to Task #9 (which deletes the old `logup_msg.rs` file in favour of moving the impls next to their new homes) more churny.
- **Insights**:
  - **Direct `impl` blocks, no macro.** The scope asked for "a macro or a helper function if the boilerplate is too repetitive, but prefer direct impl blocks — there are only ~16 structs and each body is short." I picked direct impls for all 12 blocks. A macro would have needed three template dimensions — `bus_id source` (constant, field, enum match), `width` (constant, enum match), and `write_into` (struct fields, enum variants, array destructuring) — and the result would have been harder to read than the direct form. The repetitive parts (the `E: PrimeCharacteristicRing + Clone` bound) are fine as-is.
  - **Bus-id sourcing table**:

    | Struct | `bus_id()` source | `width()` | Notes |
    |---|---|---|---|
    | `HasherMsg::State` | `*label_value` (per-variant) | `14` | `[addr, node_index, state[0..12]]`. Labels are `LINEAR_HASH_LABEL + 16`, `LINEAR_HASH_LABEL + 16`, `RETURN_STATE_LABEL + 32`. |
    | `HasherMsg::Rate` | `*label_value` | `10` | `[addr, node_index, rate[0..8]]`. Label is `LINEAR_HASH_LABEL + 32`. |
    | `HasherMsg::Word` | `*label_value` | `6` | `[addr, node_index, word[0..4]]`. Labels include `RETURN_HASH_LABEL + 32`, `MP_VERIFY_LABEL + 16`, `MR_UPDATE_OLD_LABEL + 16`, `MR_UPDATE_NEW_LABEL + 16`. |
    | `MemoryMsg::Element` | `*op_value` | `4` | `[ctx, addr, clk, element]`. Uses `MEMORY_{READ,WRITE}_ELEMENT_LABEL`. |
    | `MemoryMsg::Word` | `*op_value` | `7` | `[ctx, addr, clk, word[0..4]]`. Uses `MEMORY_{READ,WRITE}_WORD_LABEL`. |
    | `BitwiseMsg` | `self.op_value` | `3` | `[a, b, result]`. Labels are `2` (AND) / `6` (XOR). |
    | `KernelRomMsg` | `self.label` | `4` | `[digest[0..4]]`. Labels are `16` (CALL) / `48` (INIT). |
    | `AceInitMsg` | `Self::LABEL` (= `8`) | `5` | `[clk, ctx, ptr, num_read, num_eval]`. |
    | `LogCapacityMsg` | `Self::LABEL` (= `LOG_PRECOMPILE_LABEL` = `14`) | `4` | `[capacity[0..4]]`. |
    | `BlockStackMsg::{Simple, Full}` | **`0` (placeholder)** | `10` | `[block_id, parent_id, is_loop, ctx, fmp, depth, fn_hash[0..4]]`. `Simple` zero-pads the context fields — width is kept at `10` to match the old `encode` verbatim (Task #6 can trim if desired). |
    | `BlockHashMsg::*` | **`0` (placeholder)** | `7` | `[parent, child_hash[0..4], is_first_child, is_loop_body]`. All four variants (`FirstChild`/`Child`/`LoopBody`/`End`) funnel through a single `write_into` match that mirrors the old `encode` tuple destructure. |
    | `OpGroupMsg` | **`0` (placeholder)** | `3` | `[batch_id, group_pos, group_value]`. |
    | `OverflowMsg` | **`0` (placeholder)** | `3` | `[clk, val, prev]`. |
    | `RangeMsg` | **`0` (placeholder)** | `1` | `[value]`. The single-slot width is fine under the new trait. |
    | `AceWireMsg` | **`0` (placeholder)** | `5` | `[clk, ctx, id, v0, v1]`. |
    | `SiblingMsg` | **SKIPPED** | — | Sparse-layout bit-gated encoding does not fit the contiguous-payload model; Task #7 splits it. |
    | `MemoryResponseMsg` | **SKIPPED** | — | Runtime `label: E` expression; Task #6 restructures it. |
    | `KernelRomResponseMsg` | **SKIPPED** | — | Runtime `label: E` expression; Task #6 restructures it. |
    | `BitwiseResponseMsg` | **SKIPPED** | — | Runtime `label: E` expression; Task #6 restructures it. |

  - **Non-obvious payload ordering for `BlockHashMsg`.** The old `encode` builds a `(parent, child_hash, is_first_child, is_loop_body)` 4-tuple per variant, then emits a flat 7-slot array `[parent, child_hash[0], child_hash[1], child_hash[2], child_hash[3], is_first_child, is_loop_body]`. The new `write_into` matches that exact order. The per-variant `is_first_child` / `is_loop_body` constants (`(E::ONE, E::ZERO)` for `FirstChild`, `(E::ZERO, E::ZERO)` for `Child`, `(E::ZERO, E::ONE)` for `LoopBody`, dynamic for `End`) are preserved via a single pre-match that returns the tuple, then writes the 7 slots from there — structurally identical to the old match pattern.
  - **`BlockStackMsg::Simple` width choice: kept at 10 (matching old encoding), not trimmed to 3.** The old `encode` pads `Simple` with seven `E::ZERO` slots so that `Simple` and `Full` produce the same encoded denominator shape. Under the new trait, those zero slots contribute `acc += β^k · 0 = 0` to the accumulator, so dropping them would produce the same EF value — but it would also require the caller to know the per-variant width at runtime. Keeping width=10 preserves bit-for-bit parity with the old encoding and simplifies Task #6's porting work (the `g_bstack` column's `max_message_width` bound is already 10). Task #6 can trim `Simple` to width=3 later if the extra β multiplications show up as a hot-path cost.
  - **`HasherMsg::State::Rate` vs `Word` width gotcha.** The three variants have *different* widths (14 / 10 / 6), so the `width()` method must match on the variant even though they share a common label source. This propagates into the builder's `max_message_width` upper bound: the hasher bus column must declare `max_message_width = 14` to accommodate `State`, even though most messages are smaller. The adapter's scratch buffer is sized once to the column-wide max, so there's no per-call cost — the smaller variants just leave the tail slots untouched.
  - **`clone_from_slice` instead of manual loops.** Five sites (the `[12]` / `[8]` / `[4]` array copies in `HasherMsg::{State, Rate, Word}`, `MemoryMsg::Word`, `KernelRomMsg`, and `LogCapacityMsg`) use `out[a..b].clone_from_slice(&arr)` instead of a `for i in 0..N` loop. I initially wrote the loops, clippy flagged them all as `manual_memcpy`, and I replaced them. The `clone_from_slice` form is also one line shorter and slightly more descriptive about intent.
  - **The `use super::lookup::message::LookupMessage;` import** sits in the middle of the file (between the `impl_logup_message!` invocations and the new `LookupMessage` impls) rather than at the top. This is non-idiomatic but matches the "transitional section" framing of the Task #5 block — when Task #9 deletes the legacy `LogUpMessage` trait and its macro, the import will either move up to the file header or (more likely) the entire new-impls section will migrate to a different file entirely alongside the bus ports.
  - **No clippy suppression on `out[0..4].clone_from_slice(&self.digest)`**. Clippy has a lint `clippy::assigning_clones` that sometimes prefers `clone_from` over `clone_from_slice`; that lint did not fire here, so no `#[allow]` / `#[expect]` was needed.
- **Plan deviations for Task #6 / #7 to know about**:
  - Six structs have placeholder `bus_id = 0`: `BlockStackMsg`, `BlockHashMsg`, `OpGroupMsg`, `OverflowMsg`, `RangeMsg`, `AceWireMsg`. When Task #6 wires each bus port, it must either introduce a `const BUS_* = …` and update the `bus_id()` impl, or pass the bus identifier in at construction time via a new struct field. The placeholder will cause *all six messages to share slot `DS[0]`*, which will produce incorrect constraints — so the Task #6 port MUST land the real bus IDs before any port goes live (the `#![expect(dead_code)]` on the adapter chain currently shields this from triggering).
  - Four structs have no `LookupMessage` impl at all: `SiblingMsg`, `MemoryResponseMsg`, `KernelRomResponseMsg`, `BitwiseResponseMsg`. Task #6 (chiplet responses) and Task #7 (hash kernel) must introduce new struct variants / replacement structs before their bus ports compile. Until those tasks land, the legacy `encode` methods on these four structs remain the only encoding path, and the un-ported `logup_bus/*` files still call them directly through the `LogUpMessage` trait.
  - The 10 structs with real `bus_id`s use the *full* `label + offset` value that the legacy constructors bake in (e.g. `LINEAR_HASH_LABEL + 16`, `RETURN_STATE_LABEL + 32`, `MP_VERIFY_LABEL + 16`). Task #6 should ensure that `MidenLookupAir::num_bus_ids()` is computed as `max + 1` over every label constant in use across every bus (the plan's Amendment A.7 already specifies this — just flagging it as a reminder that the offsets matter).
  - The `use super::lookup::message::LookupMessage;` import will need to move / be deleted in Task #9. The inline import location mid-file was chosen deliberately to make this a trivially mechanical edit.

### Task #12 — Amendment B: `LookupMessage::encode` collapses scratch buffer — done
- **Date**: 2026-04-10
- **Files touched**:
  - `air/src/constraints/lookup/bus_id.rs` (new — central bus-ID registry; 23 `BUS_*` constants + `NUM_BUS_IDS`, file-level `#![expect(dead_code)]` with a Task #6 reason)
  - `air/src/constraints/lookup/message.rs` (rewritten — `LookupMessage<E, EF>` with a single `encode(&self, &LookupChallenges<EF>) -> EF` method; the `bus_id` / `width` / `write_into` trio is gone)
  - `air/src/constraints/lookup/builder.rs` (edited — `LookupColumn::ExprEF` / `LookupGroup::ExprEF` / `LookupBatch::ExprEF` gained an `Algebra<Self::Expr>` bound so `LookupMessage`'s `Algebra<E>` constraint on `EF` is propagatable; `LookupGroup::add`/`remove`/`insert` and `LookupBatch::add`/`remove`/`insert` now bound `M: LookupMessage<Self::Expr, Self::ExprEF>`; `LookupGroup::Batch<'b>` GAT pins `ExprEF = Self::ExprEF`; `LookupBatch` gained a `type ExprEF` associated type; stale `LookupAirShape` doc references replaced with `LookupAir`)
  - `air/src/constraints/lookup/constraint.rs` (edited — dropped `scratch: Vec<AB::Expr>` on `ConstraintLookupBuilder`, dropped `scratch: &'a mut [AB::Expr]` on `ConstraintColumn` / `ConstraintGroup` / `ConstraintBatch`, dropped `use alloc::vec`; deleted `ConstraintGroup::encode` and `ConstraintBatch::encode` helpers and inlined `msg().encode(self.challenges)` into each `add` / `remove` / `insert` body; `ConstraintBatch` impl now exposes a `type ExprEF = AB::ExprEF`; **`ConstraintColumn::fold_group` restored as a regular `&mut self` method** called from `group` / `group_with_cached_encoding` — the A.8-era inlined body is gone; doc comments updated to describe Amendment B and to flag the revert)
  - `air/src/constraints/lookup/prover.rs` (edited — symmetric surgery: dropped `scratch: Vec<F>` on `ProverLookupBuilder`, dropped `scratch: &'g mut [F]` on `ProverColumn` / `ProverGroup` / `ProverBatch`, dropped `use alloc::vec`; deleted `ProverGroup::encode` and `ProverBatch::encode` helpers and inlined `msg().encode(self.challenges)` into each body; `ProverBatch` impl now exposes `type ExprEF = EF`; **`ProverColumn::fold_group` restored as a regular `&mut self` method** called from `group` / `group_with_cached_encoding`; module-level doc comment updated)
  - `air/src/constraints/lookup/mod.rs` (edited — added `pub mod bus_id;`, `pub use bus_id::NUM_BUS_IDS;` under a task-scoped `#[expect(unused_imports)]`, new Task #12 line in the task-progression doc block, stale `LookupMessage::width` / `LookupMessage::bus_id` rustdoc references trimmed out of the `LookupAir` contract paragraph)
  - `air/src/constraints/lookup/challenges.rs` (edited — stale `LookupAirShape` doc references replaced with `LookupAir`; `LookupMessage::bus_id` doc link rewritten to point at the new `encode` method)
  - `air/src/constraints/logup_msg.rs` (edited — nine constructors updated to source their `label_value` / `op_value` / `LABEL` constants from `super::lookup::bus_id::BUS_*` instead of the scattered `LINEAR_HASH_LABEL as u16 + 16`-style expressions; all 12 `LookupMessage<E>` impls rewritten as `LookupMessage<E, EF>::encode(&LookupChallenges<EF>) -> EF` bodies — the 9 structs with stored label fields read their bus ID from that field, the 6 placeholder structs read from `bus_id::BUS_*` constants; legacy `LogUpMessage` trait, per-struct `encode` methods, and the `impl_logup_message!` macro **untouched** per scope)
  - `docs/src/design/lookup_air_plan.md` (this execution log entry)
- **Build check**: `cargo check -p miden-air` → clean, **73 warnings** (identical to the Task #5 / Task #11 baseline). `cargo test -p miden-air --lib` → **70/70 passing**, including both `enforce_main_degrees_within_budget` and `enforce_chiplet_degrees_within_budget`. `cargo clippy -p miden-air --lib` → **74 warnings** (identical to the Task #5 clippy baseline). No new test added (the optional shape-ctor test remains skipped for the same reason Task #11's log documented — Task #6 is about to exercise the whole chain against a real `MidenLookupAir`).
- **Critical** (for Tasks #6 / #7 / #9):
  - **`LookupMessage::encode(&self, &LookupChallenges<EF>) -> EF` is the new and only contract.** The 12 `*Msg` impls look up their own bus IDs internally and fold their payload against `challenges.beta_powers` with straight-line arithmetic. There is no scratch buffer, no `bus_id()`/`width()`/`write_into()` triplet, no trait-method dispatch for payload layout. Task #6 authors that call `g.add(flag, || SomeMsg::new(...))` don't need to know anything about the new encode wiring — the closure-dispatch contract is unchanged.
  - **`ConstraintColumn::fold_group` / `ProverColumn::fold_group` are regular `&mut self` methods again.** Task #4's execution log described having to inline their two-line bodies at each call site because the A.8 `scratch: &'g mut [..]` borrow was still live across the group's destructure. Amendment B removes that borrow entirely, so the method form typechecks and the call sites are back to `self.fold_group(u, v);` / `self.fold_group(n, d);`. Both adapters verified compile- and test-clean.
  - **`LookupColumn::ExprEF` / `LookupGroup::ExprEF` / `LookupBatch::ExprEF` carry an `Algebra<Self::Expr>` bound.** This is new in Task #12 and is the minimum bound set that makes the `LookupMessage<Self::Expr, Self::ExprEF>` `where` clause satisfiable through the adapter chain (since `LookupMessage`'s trait declaration requires `EF: Algebra<E>`). The existing `ConstraintColumn`/`ProverColumn` impls already satisfy the new bound because `AB::ExprEF: Algebra<AB::Expr>` is a transitive consequence of `ExtensionBuilder::ExprEF: Algebra<Self::Expr>`, and the prover path's `EF: Algebra<F>` comes from `ExtensionField<F>`. Task #6 must not add any further `LookupBuilder`-side adapter that defines `ExprEF` without also satisfying this bound.
  - **`LookupBatch` grew an `ExprEF` associated type.** Pre-Task-#12 the trait only carried `type Expr`. The new type is necessary so that the `M: LookupMessage<Self::Expr, Self::ExprEF>` bound on `LookupBatch::add`/`remove`/`insert` can name the denominator type. `ConstraintBatch`/`ProverBatch` pin `type ExprEF = AB::ExprEF` / `type ExprEF = EF`.
  - **Bus-ID registry lives at `lookup::bus_id::BUS_*`.** Task #6 must remove the file-level `#![expect(dead_code)]` on `bus_id.rs` when it stands up the first concrete `MidenLookupAir` (and, coincidentally, remove the `#[expect(unused_imports)]` on the `NUM_BUS_IDS` re-export in `mod.rs`). The existing `_LABEL` constants in `trace/chiplets/` are untouched — Task #9 will collapse them into `bus_id.rs` directly.
- **Bus-ID enumeration** (final, as recorded in `air/src/constraints/lookup/bus_id.rs`):
    ```rust
    // Hasher chiplet (derived from *_LABEL constants in trace/chiplets/hasher.rs)
    pub const BUS_HASHER_LINEAR_HASH_INIT:     u16 = LINEAR_HASH_LABEL    as u16 + 16; //  = 19
    pub const BUS_HASHER_LINEAR_HASH_ABSORB:   u16 = LINEAR_HASH_LABEL    as u16 + 32; //  = 35
    pub const BUS_HASHER_RETURN_STATE:         u16 = RETURN_STATE_LABEL   as u16 + 32; //  = 41
    pub const BUS_HASHER_RETURN_HASH:          u16 = RETURN_HASH_LABEL    as u16 + 32; //  = 33
    pub const BUS_HASHER_MP_VERIFY_INIT:       u16 = MP_VERIFY_LABEL      as u16 + 16; //  = 27
    pub const BUS_HASHER_MR_UPDATE_OLD_INIT:   u16 = MR_UPDATE_OLD_LABEL  as u16 + 16; //  = 23
    pub const BUS_HASHER_MR_UPDATE_NEW_INIT:   u16 = MR_UPDATE_NEW_LABEL  as u16 + 16; //  = 31

    // Memory chiplet (derived from MEMORY_*_LABEL constants in trace/chiplets/memory.rs)
    pub const BUS_MEMORY_READ_ELEMENT:         u16 = MEMORY_READ_ELEMENT_LABEL  as u16; //  = 12
    pub const BUS_MEMORY_WRITE_ELEMENT:        u16 = MEMORY_WRITE_ELEMENT_LABEL as u16; //  =  4
    pub const BUS_MEMORY_READ_WORD:            u16 = MEMORY_READ_WORD_LABEL     as u16; //  = 28
    pub const BUS_MEMORY_WRITE_WORD:           u16 = MEMORY_WRITE_WORD_LABEL    as u16; //  = 20

    // Bitwise / kernel ROM / ACE / log-precompile (Felt-typed upstream labels, mirrored as literals)
    pub const BUS_BITWISE_AND:                 u16 = 2;
    pub const BUS_BITWISE_XOR:                 u16 = 6;
    pub const BUS_KERNEL_ROM_CALL:             u16 = 16;
    pub const BUS_KERNEL_ROM_INIT:             u16 = 48;
    pub const BUS_ACE_INIT:                    u16 = 8;
    pub const BUS_LOG_PRECOMPILE_CAPACITY:     u16 = crate::trace::LOG_PRECOMPILE_LABEL as u16; // = 94

    // Placeholder buses (no upstream label — assigned at the top of the dense range)
    pub const BUS_BLOCK_STACK_TABLE:           u16 = 95;
    pub const BUS_BLOCK_HASH_QUEUE:            u16 = 96;
    pub const BUS_OP_GROUP_TABLE:              u16 = 97;
    pub const BUS_STACK_OVERFLOW:              u16 = 98;
    pub const BUS_RANGE_CHECK:                 u16 = 99;
    pub const BUS_ACE_WIRING:                  u16 = 100;

    pub const NUM_BUS_IDS:                     usize = BUS_ACE_WIRING as usize + 1; // = 101
    ```
  The chiplet labels (2, 4, 6, 8, 12, 16, 19, 20, 23, 27, 28, 31, 33, 35, 41, 48, 94) leave plenty of gaps — the dense-indexed DS table wastes at most 101 × sizeof(EF) ≈ 3 KB at builder construction, which is irrelevant.
- **Insights**:
  - **Why `Algebra<Self::Expr>` on `ExprEF` was necessary.** The first draft of the trait changes put the second type parameter on `LookupMessage` but forgot that the trait's own `where EF: Algebra<E>` clause propagates back through the column/group/batch chain. Without the new bound, rustc rejects the `M: LookupMessage<Self::Expr, Self::ExprEF>` bound on `add`/`remove`/`insert` with `the trait bound <Self as LookupGroup>::ExprEF: Algebra<<Self as LookupGroup>::Expr> is not satisfied`. Adding the bound to the three `type ExprEF` declarations is a one-liner per trait but has a cascading effect: it tightens the contract that any future `LookupBuilder` implementor must satisfy, which matches the constraint that `ExtensionBuilder::ExprEF: Algebra<Self::Expr>` is already present upstream so no concrete adapter is affected.
  - **Field ordering in the `HasherMsg::State/Rate/Word` encode bodies.** All three variants emit `[addr, node_index, ...payload]`, so the β-power assignment is `bp[0] * addr`, `bp[1] * node_index`, then `bp[i+2] * payload[i]`. I verified the ordering against the legacy `encode` method (which emits `[E::from_u16(label), addr, node_index, ...payload]` minus the label slot) — the two are slot-for-slot identical modulo the absent label term. For `MemoryMsg::Element` the ordering is `[ctx, addr, clk, element]`; for `MemoryMsg::Word` it is `[ctx, addr, clk, word[0..4]]` with `bp[i+3] * word[i]`. `BlockHashMsg` required the same per-variant `(parent, child_hash, is_first_child, is_loop_body)` fan-in that the legacy `write_into` used, preserved verbatim in the new `encode` body.
  - **`BlockStackMsg::Simple` kept the width-10 padding in the encode body, but as elided β terms.** The old `write_into` wrote seven `E::ZERO` slots after the three live fields; the new `encode` body omits the `bp[3..10] * 0` multiplications entirely (they are a no-op). The resulting denominator is mathematically identical: `DS[BUS_BLOCK_STACK_TABLE] + bp[0]*block_id + bp[1]*parent_id + bp[2]*is_loop + 0 + ... + 0 = DS[BUS_BLOCK_STACK_TABLE] + bp[0]*block_id + bp[1]*parent_id + bp[2]*is_loop`. The comment inside the `encode` body flags this explicitly so Task #6's port doesn't trip on the apparent width mismatch between `Simple` (3 live terms) and `Full` (10 live terms).
  - **No borrow-checker workarounds needed.** The `ConstraintColumn::fold_group` and `ProverColumn::fold_group` re-methodification worked first try — removing the `scratch` field is enough to break the `'g`-lifetime-on-method-receiver conflict that Task #4 documented, and the rustc output confirms: the only disjoint-field contention was between `self.scratch[..]` (borrowed for the group's lifetime) and `self.{u,v}` (the accumulator), and with `scratch` gone the accumulator reads don't conflict with anything.
  - **`BUS_*` dead-code wrapping strategy.** The 23 `BUS_*` constants plus `NUM_BUS_IDS` are all transitively dead in the current workspace (every caller sits inside a `pub fn` that is itself unused, so rustc's reachability pass flags the leaves). I wrapped them once with a file-level `#![expect(dead_code)]` on `bus_id.rs` — identical pattern to the four `expect` attributes already present on the adapter chain (`constraint.rs`, `prover.rs`, `builder.rs`, the re-exports in `mod.rs`). Total `expect` inventory stays at five: four pre-existing + one new on `bus_id.rs`. The `NUM_BUS_IDS` re-export in `mod.rs` needs its own targeted `#[expect(unused_imports)]` because the file-level attribute on `bus_id.rs` doesn't propagate through the re-export site.
  - **Doc-reference churn**: the old Amendment A draft called the non-existent trait `LookupAirShape` in several doc comments (builder.rs `EncodedLookupGroup`, challenges.rs module / `new` method, mod.rs `LookupAir` contract paragraph). Task #11's execution log decided against the split but left the stale doc refs in place. Amendment B's encoding-loop move touches the same files, so I fixed the references at the same time — pointing at `LookupAir` directly.
  - **Import path choice**: the `BUS_*` constants are imported inside the `encode` bodies with `use super::lookup::bus_id::BUS_FOO;`, not at the top of `logup_msg.rs`. This matches the "transitional section" framing from Task #5 — when Task #9 deletes the legacy `LogUpMessage` trait, the imports can migrate along with the impls to a new file near the bus ports. Pulling them to the top now would make the Task #9 mechanical edit harder.
  - **Constructor switch to `BUS_*` constants was purely mechanical.** Each of the 9 updated constructors had the same pattern: replace `use crate::trace::chiplets::hasher::FOO_LABEL;` + `label_value: FOO_LABEL as u16 + 16` with `use super::lookup::bus_id::BUS_FOO_VARIANT;` + `label_value: BUS_FOO_VARIANT`. The old `+ 16` / `+ 32` bucket offsets are now baked into the `BUS_*` constants at declaration time, so the constructor bodies read cleaner. `KernelRomMsg::{CALL_LABEL, INIT_LABEL}` and `AceInitMsg::LABEL` and `LogCapacityMsg::LABEL` are inherent `const`s that switched from literal `u16`s to `BUS_*` references using path-style constant access (`super::lookup::bus_id::BUS_FOO`) since inherent constants must be fully-qualified paths when referencing across modules.
- **Plan deviations for Task #6 / #7 / #9 to know about**:
  - Task #6's `MidenLookupAir::num_bus_ids()` should return `lookup::bus_id::NUM_BUS_IDS` directly (not a magic number). The constant's value is `101` for the current set of buses; when Task #6 / Task #7 add / restructure buses, it will move automatically. Task #6 must also remove the `#![expect(dead_code)]` on `bus_id.rs` and the `#[expect(unused_imports)]` on the `NUM_BUS_IDS` re-export.
  - Task #6's first concrete `ConstraintLookupBuilder::new(builder, &air)` / `ProverLookupBuilder::new(...)` call will clear five `#[expect(dead_code)]` attributes in one shot: `bus_id.rs` (file-level), `constraint.rs` (file-level), `prover.rs` (file-level), `builder.rs` (narrow `main`/`periodic_values`/`public_values`), and `mod.rs` (narrow on `LookupAir`). The three re-export `#[expect(unused_imports)]` (on `ConstraintLookupBuilder`, `ProverLookupBuilder`, `NUM_BUS_IDS`) also go away at that point.
  - The `LookupBatch::ExprEF` associated type is a breaking addition to the trait that Task #6 needs to know about: any concrete `LookupBatch` impl outside the three adapter paths (`ConstraintBatch`, `ProverBatch`, any future one) must declare `type ExprEF = ...;` alongside `type Expr = ...;`. There are no such external impls today; this is a forward-looking reminder.
  - Task #7's `SiblingMsg` restructuring must produce `LookupMessage<E, EF>` impls (not `LookupMessage<E>`) because the trait now carries two type parameters. The sparse-layout split into two contiguous variants is otherwise unchanged.
  - Task #9 should delete, in order: (a) the per-`*Msg` `encode` methods, (b) the `impl_logup_message!` macro + all 16 `impl_logup_message!` invocations, (c) the `LogUpMessage` trait itself, (d) the `crate::trace::Challenges<EF>` struct (now only referenced by the un-ported `logup*` files), and (e) the scattered `_LABEL` constants in `air/src/trace/chiplets/` (now redundant with `bus_id.rs`). Each step is independent and test-able: the 70 `cargo test -p miden-air --lib` tests exercise paths that don't touch any of these surfaces.

### Correction to Task #12 (2026-04-10) — bus-ID model

Task #12's first cut misinterpreted the relationship between "bus id"
and "label", producing 101 bus IDs (one per label variant). The
correct model has **9 bus IDs**, with all chiplet operations sharing
`BUS_CHIPLETS = 0` and distinguishing themselves via a label at β⁰
in their payload.

Confirmed from `vm-constraints/air/src/trace/mod.rs:244-265` (the
`bus_types` enum) and `vm-constraints/air/src/trace/challenges.rs`
(the encoding loop `bus_prefix[bus] + Σ β^k · elems[k]` with `elems[0]`
the label by convention).

Changes applied in this correction:
- `bus_id.rs`: rewritten from 20+ label constants → 9 coarse bus
  constants (`BUS_CHIPLETS`, `BUS_BLOCK_STACK_TABLE`,
  `BUS_BLOCK_HASH_TABLE`, `BUS_OP_GROUP_TABLE`,
  `BUS_STACK_OVERFLOW_TABLE`, `BUS_SIBLING_TABLE`,
  `BUS_LOG_PRECOMPILE_TRANSCRIPT`, `BUS_RANGE_CHECK`,
  `BUS_ACE_WIRING`). `NUM_BUS_IDS = 9`.
- `challenges.rs`: `domain_separators` → `bus_prefix`; formula
  `α + i·β^W` → `α + (i+1)·β^W` to match the vm-constraints convention.
- `builder.rs`: `EncodedLookupGroup::domain_separator(id)` →
  `bus_prefix(id)`.
- `constraint.rs` / `prover.rs`: field access rename.
- `logup_msg.rs`: every `LookupMessage::encode` body rewritten so the
  label (`label_value` or `op_value`) lives at β⁰ of the payload
  (for chiplet messages) or is absent (for non-chiplet messages).
  The 9 chiplet constructors reverted to their pre-Task-#12
  references to `trace::chiplets::*_LABEL` constants.

### Task #6 — `MidenLookupAir` canary + block-hash queue port — done

- **Date**: 2026-04-10
- **Files touched**:
  - `air/src/constraints/lookup/miden_air.rs` (new — zero-sized
    `MidenLookupAir` with a blanket `impl<LB: LookupBuilder<F = Felt>>
    LookupAir<LB>`; `emit_block_hash_queue` mirrors the old
    `g_bqueue` line-for-line through the closure-based
    `column / group_with_cached_encoding / batch` API; private
    `PreEncoded<E, EF>` helper fills the gap between
    `LookupBatch::add(msg)` and the encoded-group `insert_encoded`
    surface by wrapping a precomputed `ExprEF` in a `LookupMessage`
    whose `encode` is a no-op clone)
  - `air/src/constraints/lookup/mod.rs` (edited — added
    `pub mod miden_air;` + `pub use miden_air::MidenLookupAir`
    under `cfg_attr(not(test), expect(unused_imports, …))`; removed
    the file-level `#[expect(dead_code)]` on the `LookupAir` trait;
    replaced it with a targeted `cfg_attr(not(test),
    expect(dead_code, …))` on `LookupAir::eval` alone — the shape
    methods `num_columns` / `max_message_width` / `num_bus_ids` are
    now live via the `ConstraintLookupBuilder::new` path; relaxed
    the `ConstraintLookupBuilder` re-export's expect to
    `cfg_attr(not(test), …)` so the test mode picks up the live
    consumer)
  - `air/src/constraints/lookup/constraint.rs` (edited — the
    file-level `#![expect(dead_code)]` relaxed to
    `cfg_attr(not(test), expect(dead_code, …))` so the adapter chain
    stays dead-silent in lib-only mode while the test mode's
    `miden_lookup_air_block_hash_degree_within_budget` keeps the
    whole chain live)
  - `air/src/constraints/lookup/bus_id.rs` (edited — reason-string
    narrowed from "until Task #6 stands up a live MidenLookupAir" to
    "Task #6 consumes BUS_BLOCK_HASH_TABLE / NUM_BUS_IDS directly;
    the remaining BUS_* constants go live in Task #7"; the
    file-level `#![expect(dead_code)]` itself stays because 7 of the
    9 constants remain dead until Task #7 ports their buses)
  - `air/src/constraints/lookup/builder.rs` (edited — file-level
    `#![expect(dead_code)]` retained but reason narrowed from
    "trace-access methods" to "`periodic_values` / `public_values`
    only"; `main()` is now live via `MidenLookupAir::eval`)
  - `air/src/constraints/logup_bus/mod.rs` (edited — added
    `miden_lookup_air_block_hash_degree_within_budget` test alongside
    the existing `enforce_main_degrees_within_budget`; constructs a
    `ConstraintLookupBuilder::new(&mut builder, &MidenLookupAir)`,
    calls `air.eval(&mut lb)`, and asserts the extension-constraint
    degree multiples stay within `DEGREE_BUDGET = 9`)
  - `docs/src/design/lookup_air_plan.md` (this execution log entry)

- **Build check**:
  - `cargo check -p miden-air` → **72 warnings** (baseline 73 — the
    new code actually consumes `BlockHashMsg`, which was previously
    flagged as dead-code; count drops by one as a natural consequence
    of the port).
  - `cargo check -p miden-air --tests` → lib 72 warnings + lib test
    6 warnings + test "bus_degree_inventory" 1 warning (all three
    counts match the pre-Task-#6 baseline).
  - `cargo clippy -p miden-air --lib` → **74 warnings** (identical to
    the Task #12 baseline of 74; no new clippy lints).
  - `cargo test -p miden-air --lib` → **71/71 passing** (70 old + 1
    new). The new test
    `constraints::logup_bus::tests::miden_lookup_air_block_hash_degree_within_budget`
    reports `LOOKUP[0] degree = 2`, `LOOKUP[1] degree = 9`,
    `LOOKUP[2] degree = 2` — identical to the M2 slice (EXT[3..6]) of
    the old `enforce_main_degrees_within_budget` output, confirming
    the new API reproduces the old `g_bqueue` symbolic algebra
    bit-for-bit.
  - `cargo check --workspace` → clean.

- **Critical** (for Tasks #7 / #8):
  - **`MidenLookupAir::num_columns()` / `max_message_width()` /
    `num_bus_ids()`** are currently `1` / `7` / `NUM_BUS_IDS` (= 9).
    Task #7 bumps `num_columns` to 8 and `max_message_width` to 14
    (14 is the widest `HasherMsg::State` payload). `num_bus_ids`
    stays at 9.
  - **The encoded-path `batch` call inside `emit_block_hash_queue`
    required a `PreEncoded<E, EF>` helper** because `LookupBatch`
    intentionally does not expose `insert_encoded` — it only accepts
    `LookupMessage` values. Task #7 will encounter this again for
    every bus that uses `batch(...)` with cached encoding. Two
    options: (a) keep spawning file-local `PreEncoded` helpers (one
    per bus port, identical), or (b) widen `LookupBatch` with an
    `insert_encoded` method in a small follow-up commit. I chose
    option (a) for the canary port because the helper is six lines
    and Task #7 can consolidate if the duplication gets painful.
  - **The canonical closure uses `g.batch(f_join, |b| { b.add(...);
    b.add(...); })` for the JOIN 2-interaction batch**, matching the
    old `g_bqueue`'s `sink.add_batch(f_join, ...)`. The encoded
    closure matches the same batch structure (via `PreEncoded`), so
    both closures produce the *same* `(U_g, V_g)` algebraically —
    confirmed by the degree-budget test passing at 9. The
    canonical-vs-encoded split is **not** "different algebra, same
    rational sum" — it's "same algebra, different encoding path".
    Bus authors porting other buses in Task #7 should be aware of
    this: any `batch(...)` call on the canonical side must also go
    through `batch(...)` on the encoded side, not get flattened into
    multiple `insert_encoded` calls (which would produce a different
    `(U, V)` pair).
  - **Trace-access pattern**: `MidenLookupAir::eval` holds
    `builder.main()` by value (the `MainWindow: WindowAccess + Clone`
    bound lets the two concrete adapters — `SymbolicAirBuilder`
    clones a `RowMajorMatrix<Var>`; the prover folder returns a
    `Copy` `RowWindow<'a, P>`) and then borrows
    `main.current_slice()` / `main.next_slice()` as
    `MainTraceRow<LB::Var>` via the blanket `Borrow<MainTraceRow<T>>
    for [T]` impl in `trace::main_trace`. The `&mut builder` passed
    through to `emit_block_hash_queue` is only reborrowed when
    `builder.column(...)` is called — the `main` handle is dropped
    before entering the closure.
  - **`cfg_attr(not(test), expect(...))` pattern** for
    `MidenLookupAir`, `emit_block_hash_queue`, the
    `ConstraintLookupBuilder` file-level, the `LookupAir::eval`
    method, and the `ConstraintLookupBuilder` / `MidenLookupAir`
    re-exports: each attribute is active only in lib-only builds
    (where the Task #6 code has no non-test consumer). Task #8 must
    remove every `cfg_attr(not(test), …)` I added here — at that
    point the live `ProcessorAir::eval` path exercises the whole
    chain unconditionally.

- **Canonical vs cached-encoding equivalence**: the encoded closure
  runs only on the constraint path
  ([`ConstraintLookupBuilder`](super::constraint::ConstraintLookupBuilder)
  runs `encoded` and drops `canonical` unused); the canonical
  closure runs only on the prover path. Both produce the same
  `(U, V)` delta per variant by construction:
  - JOIN: batch `(N, D) = (v1 + v2, v1·v2)`, folded by
    `U_g += (v1·v2 - 1)·f_join; V_g += (v1 + v2)·f_join` — identical
    on both sides because the encoded side uses `batch(...)` with
    `PreEncoded` fragments that carry the full denominator (i.e.
    `PreEncoded::encode` hands back the captured `ExprEF` verbatim,
    so the batch's `(N, D)` algebra is the same as if the canonical
    `BlockHashMsg::encode` had run).
  - SPLIT / LOOP / CHILD / END: each variant contributes a single
    `absorb_single(flag, mult, v)` call; the encoded closure reaches
    this via `ge.insert_encoded(flag, mult, || …)` while the
    canonical closure reaches it via `g.add(...)` / `g.remove(...)`
    that call `msg.encode(challenges)` internally. Same `v`, same
    `(U_g, V_g)` delta, just different encoding sources. The new
    test's passing degree (9) at the budget confirms this is
    correct: the old `g_bqueue::enforce_main` also emits transition
    degree 9 for M2 — if the new encoded closure produced different
    algebra, the degrees would diverge.

- **Insights**:
  - **One targeted sub-attribute instead of file-level.** The old
    Task #3 / #4 / #11 / #12 era used a file-level
    `#![expect(dead_code)]` on `constraint.rs` covering the entire
    adapter chain. Task #6 relaxes this to
    `#![cfg_attr(not(test), expect(dead_code, …))]` — the expect is
    still file-level in lib-only mode (silencing the whole chain),
    but in test mode the attribute is absent and the
    `miden_lookup_air_block_hash_degree_within_budget` test brings
    every item live. No narrowing to per-item expects was needed;
    the adapter chain is live-or-dead as a unit.
  - **The LookupAir trait's `num_columns` / `max_message_width` /
    `num_bus_ids` shape methods are now live** in lib-only mode
    because `ConstraintLookupBuilder::new(air)` reads them via
    `air.max_message_width()` / `air.num_bus_ids()` (the
    `num_columns` method is still dead until a Task #8-era sanity
    check calls it, but rustc's reachability analysis considers it
    live because all four methods are part of the same trait and
    at least one is called — I confirmed this by removing the
    file-level expect and observing only `eval` getting flagged).
  - **The `cfg_attr(not(test), …)` pattern on re-exports matters**:
    `pub use bus_id::NUM_BUS_IDS;` stays unconditionally
    `#[expect(unused_imports)]` because the only Task #6 consumer
    (`miden_air.rs`) imports it via
    `super::bus_id::NUM_BUS_IDS` directly, not via the `mod.rs`
    re-export. The two other re-exports (`ConstraintLookupBuilder`
    and `MidenLookupAir`) switch to `cfg_attr(not(test), expect)`
    because the new test *does* consume them via the `use
    super::super::lookup::{ConstraintLookupBuilder, MidenLookupAir,
    ...}` path — so in test mode the imports are live and the
    expect would be unfulfilled.
  - **`PreEncoded` helper is scoped to `miden_air.rs` as a private
    struct.** I considered promoting it to `lookup/builder.rs` as a
    public helper, or adding an `insert_encoded` method to
    `LookupBatch`, but neither carries its weight for a canary
    port. Six lines of module-private scaffolding is the right
    size; Task #7 can consolidate (probably to a
    `lookup::encoded::PreEncoded` module-private helper) after the
    7 other bus ports reveal whether the pattern recurs.
  - **No 4-lifetime acrobatics in `eval`.** The
    `builder.main()` → `main.current_slice().borrow()` pattern works
    because `main` is held as a local by-value binding; the
    `RowMajorMatrix<Var>` / `RowWindow<'a, P>` both satisfy
    `Clone`, so the `&self` borrow that produced it releases at the
    call boundary. No extra lifetime parameter on `eval` is
    required — the method signature is a clean `fn eval(&self,
    builder: &mut LB)`.
  - **`LB::Var * LB::Var` did NOT work** — rustc's `Mul` impls on
    `AB::Var` are not closed (no `Mul<Self, Output = Self>` in
    `AirBuilder::Var`'s bound set). I fixed this by lifting both
    operands to `LB::Expr` via `.into()` before the multiplication
    in the SPLIT `split_h` computation. The old `g_bqueue` got
    away with `s0 * h[i]` because it ran inside `AB` directly (not
    a generic `LB: LookupBuilder`), and `AB::Expr` has closed
    `Mul`. Task #7 bus authors will hit this as soon as they touch
    the stack / decoder columns in their bus bodies — every `Var *
    Var` in the old `g_*` functions needs `.into()` calls.
  - **Degree 9 match is by construction, not by luck.** The
    encoded closure computes the same `(U, V)` pair as the
    canonical closure because (a) both use `batch(f_join, …)` with
    2 interactions, (b) both use `insert_encoded` / `add` / `remove`
    for the 4 single variants, (c) `PreEncoded::encode` is a
    no-op clone so the batch's per-interaction `v` values match the
    canonical closure's `BlockHashMsg::encode` output, and (d) the
    old `g_bqueue` was already degree-9-at-budget under the old
    `trace::Challenges` encoding (`alpha + Σ β^i · v[i]`), which is
    algebraically identical to the new `bus_prefix[i] + Σ β^k ·
    v[k]` encoding modulo the constant offset `bus_prefix[i] − α =
    (i + 1) · β^W`. The constant offset contributes `0` to the
    degree because it's an `AB::ExprEF` constant with no `Var`
    factors, so the old and new transition polynomials differ
    only by a constant shift — same degree.

- **Plan deviations for Task #7 / #8 to know about**:
  - **`PreEncoded::<LB::Expr, LB::ExprEF>`** is a Task #6-private
    helper. Task #7 should either duplicate it into each bus port
    that needs a cached-encoding batch (trivial copy), or widen
    `LookupBatch` with `insert_encoded`. The helper is stable under
    `miden_air.rs`; moving it is pure refactoring.
  - **The `cfg_attr(not(test), expect(...))` attributes** on
    `MidenLookupAir`, `emit_block_hash_queue`,
    `ConstraintLookupBuilder` (file-level), `LookupAir::eval`
    (method-level), and the two re-exports in `mod.rs` all must be
    removed by Task #8 as soon as `ProcessorAir::eval` calls
    `MidenLookupAir::eval` via a `ConstraintLookupBuilder`
    constructed from the builder — at that point every item is
    live in both lib and test modes.
  - **`num_columns()` sanity check deferred**. The Task #11 log
    flagged a future `debug_assert_eq!(self.column_idx,
    shape.num_columns())` check at the end of `eval`; I did **not**
    add it in Task #6 because (a) the canary port only opens one
    column and the assert would be trivially satisfied, and (b) the
    adapter's `column_idx` field is not exposed on the
    `LookupBuilder` trait, so I can't write a generic assert from
    inside `MidenLookupAir::eval`. Task #7 should add the assert
    inside `ConstraintLookupBuilder::finalize` (or equivalent in the
    prover adapter) where `column_idx` is visible as a private
    field.
  - **Task #7's `SiblingMsg` rework still needs to happen** before
    the hash-kernel bus port can compile against the new API. Task
    #5's log already flagged this; Task #6 did not touch it.
  - **Task #8's `ProcessorAir::eval` wiring** should call
    `MidenLookupAir::default()` (or `MidenLookupAir`) to construct
    the zero-sized air and pass it into `ConstraintLookupBuilder::new(builder, &air)`.
    The `#[derive(Default)]` is already on `MidenLookupAir` for this
    reason.
  - **The `LookupBatch::ExprEF` associated type is required** for
    the `PreEncoded` helper to compile — `PreEncoded<E, EF>`
    implements `LookupMessage<E, EF>`, which needs `EF: Algebra<E>`,
    which is exactly what Task #12 added as the
    `ExprEF: Algebra<Self::Expr>` bound. So Task #12's forward-looking
    bound turned out to be load-bearing for Task #6 too.

### Task #6 fixup (2026-04-10) — `LookupBatch::insert_encoded` — done

The Task #6 port shipped a file-local `PreEncoded<E, EF>` helper
(a no-op `LookupMessage` carrying a pre-computed denominator) to
thread cached-encoding fragments into `LookupBatch::add`, because
`LookupBatch` had no `insert_encoded` method. Every future
cached-encoding batch would repeat the same workaround.

Fix: add `insert_encoded(multiplicity, encoded_fn)` directly to
`LookupBatch`, symmetric with
[`EncodedLookupGroup::insert_encoded`]. Both adapters implement
it as a one-liner over their existing `absorb` helper.
`miden_air.rs` drops the `PreEncoded` helper and uses
`b.insert_encoded(LB::Expr::ONE, || fc_v)` inside the JOIN batch
closure.

**Trait addition** (in `builder.rs`):
```rust
pub trait LookupBatch {
    // … existing add / remove / insert …
    fn insert_encoded(
        &mut self,
        multiplicity: Self::Expr,
        encoded: impl FnOnce() -> Self::ExprEF,
    );
}
```

**Adapter impls**: `ConstraintBatch::insert_encoded` and
`ProverBatch::insert_encoded` each forward to the existing
`absorb(multiplicity, encoded())` helper — no new algebra.

**`miden_air.rs`**: deleted the `PreEncoded<E, EF>` struct + its
`LookupMessage` blanket impl + the `PhantomData` / `Algebra` /
`LookupMessage` / `LookupChallenges` imports that only the helper
needed. The JOIN batch closure now reads:

```rust
ge.batch(f_join.clone(), |b| {
    b.insert_encoded(LB::Expr::ONE, || fc_v);
    b.insert_encoded(LB::Expr::ONE, || base_h_second);
});
```

**Build**: `cargo check -p miden-air` clean at 72 warnings (same
baseline Task #6 landed at). `cargo test -p miden-air --lib`
passes 71/71. `miden_lookup_air_block_hash_degree_within_budget`
still emits `LOOKUP[0..3] = [2, 9, 2]`, matching the old
`g_bqueue` degree profile bit-for-bit — the `insert_encoded`
route produces the same symbolic expression as the
`PreEncoded`-wrapped `add` route did.

**Impact on Task #7**: every remaining bus with a cached-encoding
batched variant (likely `g_creq`, possibly `g_chiplet_resp`) can
use `b.insert_encoded(mult, || enc_value)` directly, with no
per-bus helper needed.

### Task #7 — remaining 7 bus ports + comprehensive degree test — done

- **Date**: 2026-04-11
- **Per-bus status** (all 8 ported cleanly):

  | Bus | Column | New emitter | Status | New transition | Old transition |
  |-----|--------|-------------|--------|----------------|----------------|
  | `g_bstack` + `g_rtable` | M1 | `block_stack::emit_block_stack_and_range_table` | ✓ ported | 8 | 8 |
  | `g_bqueue` | M2 | `block_hash::emit_block_hash_queue` (moved from `miden_air.rs`) | ✓ ported | 9 | 9 |
  | `g_creq` | M3 | `chiplet_requests::emit_chiplet_requests` | ✓ ported | 9 | 9 |
  | `g_rstack_logcap` | M4 | `range_logcap::emit_range_stack_and_log_capacity` | ✓ ported | 8 | 8 |
  | `g_opgrp` | M5 | `op_group::emit_op_group_table` | ✓ ported | 9 | 9 |
  | `g_chiplet_resp` | C1 | `chiplet_responses::emit_chiplet_responses` | ✓ ported | 8 | 8 |
  | `g_hash_kernel` | C2 | `hash_kernel::emit_hash_kernel_table` | ✓ ported | 8 | 8 |
  | `g_wiring` | C3 | `wiring::emit_ace_wiring` | ✓ ported | 9 | 9 |

  All 8 transition degrees match the old path bit-for-bit.

- **File organization**: split into
  `air/src/constraints/lookup/buses/{block_hash, block_stack, chiplet_requests,
  chiplet_responses, hash_kernel, op_group, range_logcap, wiring}.rs` — one file
  per bus. Task #6's `emit_block_hash_queue` body moved out of `miden_air.rs`
  into `buses/block_hash.rs` verbatim, so the top-level file shrinks from 308
  lines to ~100 and becomes a thin routing layer. The 7 new emitters added this
  task total ~1350 lines across the 7 new files.

- **`SiblingMsg` strategy**: **(a) preserve sparse layout**. Added
  `SiblingMsgBitZero<E>` and `SiblingMsgBitOne<E>` in `logup_msg.rs`, each
  implementing `LookupMessage<E, EF>::encode` with the **non-contiguous** β
  positions from the legacy `SiblingMsg::B0_LAYOUT` / `B1_LAYOUT`:

  - `BitZero`: `bus_prefix[BUS_SIBLING_TABLE] + β²·node_index + β⁷·h_hi[0] +
    β⁸·h_hi[1] + β⁹·h_hi[2] + β¹⁰·h_hi[3]`
  - `BitOne`: `bus_prefix[BUS_SIBLING_TABLE] + β²·node_index + β³·h_lo[0] +
    β⁴·h_lo[1] + β⁵·h_lo[2] + β⁶·h_lo[3]`

  The hash-kernel bus calls `replace(f_mv, f_mu, SiblingMsg)` four times
  (twice each for `sibling_curr` and `sibling_next`); the new emitter
  replaces each `replace` call with four gated interactions:

  ```rust
  g.add(f_add * (1 - bit),    || SiblingMsgBitZero { .. });
  g.add(f_add * bit,          || SiblingMsgBitOne  { .. });
  g.remove(f_remove * (1 - bit), || SiblingMsgBitZero { .. });
  g.remove(f_remove * bit,       || SiblingMsgBitOne  { .. });
  ```

  The algebraic equivalence `v_old = v_b0·(1-bit) + v_b1·bit` means the four
  split interactions produce the same `(U_g, V_g)` as the legacy `replace` —
  verified against the old degree (C2 transition = 8 on both paths).

- **Response-message strategy** (deviation from plan §R2/R3/R4): **kept the
  legacy runtime-muxed structs and added new `LookupMessage<E, EF>::encode`
  impls**, rather than splitting into per-label variants. The plan's original
  R2/R3/R4 recommendation (4 memory variants, 2 bitwise variants, 2 kernel
  ROM variants) was implemented at the Task #7 start but was found to **bump
  C1's transition degree from 8 → 9** because per-label ME splitting replaces
  one deg-3 `is_memory` flag with four deg-5 products of flags and the `V_g`
  sum becomes symbolically higher-degree.

  The pragmatic fix: add new `LookupMessage<E, EF>::encode` impls on
  `MemoryResponseMsg` / `KernelRomResponseMsg` / `BitwiseResponseMsg` that
  mirror their legacy `LogUpMessage::encode` bodies verbatim. Each impl lives
  alongside (not in place of) the legacy one — the struct, its fields, and
  its old `encode` method are **unchanged**, so `logup_bus/chiplet_responses.rs`
  still compiles. The C1 transition degree now matches the old path at 8
  bit-for-bit.

  The four `MemoryResponse{Read,Write}{Element,Word}Msg` + two
  `KernelRomResponse{Call,Init}Msg` + two `BitwiseResponse{And,Xor}Msg` structs
  that the plan recommended were added to `logup_msg.rs` and will remain
  **unused** through Task #7. Task #9 can delete them if the degree-preserving
  unified approach is kept, or promote them if a future pass finds a way to
  reduce the deg-5 ME flags to deg-3.

- **Degree table** (per-column transition, compared against the old path):

  | Slot | Bus | Old (EXT[k]) | New (LOOKUP[k+1]) |
  |------|-----|--------------|-------------------|
  | 0..3 | M1 block_stack + range_table | [2, 8, 2] | [2, 8, 2] |
  | 3..6 | M2 block_hash | [2, 9, 2] | [2, 9, 2] |
  | 6..9 | M3 chiplet_requests | [2, 9, 2] | [2, 9, 2] |
  | 9..12 | M4 range_logcap | [2, 8, 2] | [2, 8, 2] |
  | 12..15 | M5 op_group | [2, 9, 2] | [2, 9, 2] |
  | 15..18 | C1 chiplet_responses | [2, 8, 2] | [2, 8, 2] |
  | 18..21 | C2 hash_kernel | [2, 8, 2] | [2, 8, 2] |
  | 21..24 | C3 wiring | [2, 9, 2] | [2, 9, 2] |

  The new `miden_lookup_air_degree_within_budget` test emits all 24 LOOKUP
  constraints in the same order (M1..M5, C1..C3) as the legacy
  `enforce_main` / `enforce_chiplet` pair, and every transition degree
  matches bit-for-bit.

- **Message structs added** (`logup_msg.rs`):
  - `MemoryResponseReadElementMsg<E>` / `MemoryResponseWriteElementMsg<E>` /
    `MemoryResponseReadWordMsg<E>` / `MemoryResponseWriteWordMsg<E>` — per-label
    memory responses, implemented but **unused** in Task #7 (see
    "Response-message strategy" above).
  - `KernelRomResponseCallMsg<E>` / `KernelRomResponseInitMsg<E>` — per-label
    kernel ROM responses, unused.
  - `BitwiseResponseAndMsg<E>` / `BitwiseResponseXorMsg<E>` — per-label bitwise
    responses, unused.
  - `SiblingMsgBitZero<E>` / `SiblingMsgBitOne<E>` — **used** by
    `emit_hash_kernel_table`. Sparse β layouts `[2, 7, 8, 9, 10]` and
    `[2, 3, 4, 5, 6]` respectively, matching the legacy `SiblingMsg::B0_LAYOUT`
    / `B1_LAYOUT`.
  - New `LookupMessage<E, EF>` impls on the legacy `MemoryResponseMsg<E>` /
    `KernelRomResponseMsg<E>` / `BitwiseResponseMsg<E>` — **used** by
    `emit_chiplet_responses`.

- **`MidenLookupAir` shape methods**:
  - `num_columns()`: `1` → `8`
  - `max_message_width()`: `7` → `15` (widest payload is `HasherMsg::State`'s
    `label + addr + node_index + state[0..12]` = 15 slots; fits within
    `LookupChallenges::beta_powers` length = 15)
  - `num_bus_ids()`: unchanged at `NUM_BUS_IDS = 9`

- **Build state**:
  - `cargo check -p miden-air` → **64 warnings** (dropped from Task #6
    baseline of 72). The 8-warning drop comes from the new emitters consuming
    the `LookupMessage<E, EF>` impls that Task #5 added — every `*Msg` struct
    used by a Task #7 emitter is now a live consumer.
  - `cargo test -p miden-air --lib` → **71/71 passing**. Task #6's
    `miden_lookup_air_block_hash_degree_within_budget` was **renamed** to
    `miden_lookup_air_degree_within_budget` and extended from 3 extension
    constraints to 24 (all 8 buses × 3 boundary/transition/last constraints).
  - `cargo check --workspace` → clean.

- **Dead-code suppression pattern**: each new `buses/*.rs` file carries a
  file-level `#![cfg_attr(not(test), expect(dead_code, …))]` attribute
  silencing the lib-only warnings until Task #8 wires `ProcessorAir::eval`
  into `MidenLookupAir::eval`. In test mode every attribute is absent and the
  `miden_lookup_air_degree_within_budget` test exercises every emitter
  through the whole adapter chain.

- **`CreqCtx` / `CrespCtx` helper structs**: the chiplet-requests (M3) and
  chiplet-responses (C1) emitters each use a private `*Ctx` struct to hold
  every row-derived value the canonical and encoded closures share. Their
  helper methods are generic over `G: LookupGroup<Expr = LB::Expr, ExprEF =
  LB::ExprEF>` so both closures (simple `ConstraintGroup` + encoded
  `ConstraintGroupEncoded`) reuse the same non-cached tail without
  duplication. The cached-encoding control-block / hasher-variant sections
  stay inline because the canonical and encoded shapes diverge
  (per-variant `remove` vs per-variant `insert_encoded`).

- **Plan deviations for Task #8 / #9 to know about**:
  - **Response-message per-variant split not used.** The 4 memory + 2 kernel
    ROM + 2 bitwise structs exist but have no consumer. Task #9 should
    decide whether to delete them or to revisit the degree analysis.
    Verdict from Task #7: the unified encoding matches the old degree, so
    there's no reason to switch. Delete in Task #9.
  - **`SiblingMsgBitZero` / `SiblingMsgBitOne` use sparse β layouts.** Task #9
    should verify that the responder-side chiplet code (wherever the
    hash-kernel virtual table's insertion is tracked) writes the same sparse
    positions, otherwise the new sibling-table algebra will not match the
    prover's column values.
  - **`emit_non_cached` / `emit_non_hasher` helpers are generic over `G:
    LookupGroup`.** Both the canonical and encoded closures compile against
    the same helper, but the adapter drops whichever closure it doesn't use
    (see Task #6 log). Task #8 authors modifying the canonical body should
    also mirror changes in the encoded body, or the two paths will diverge.
  - **M3 (`emit_chiplet_requests`) and C1 (`emit_chiplet_responses`) both
    duplicate the cached-encoding section (control blocks for M3, hasher
    variants for C1).** The non-cached tails (all non-control-block M3
    interactions, all non-hasher C1 interactions) are shared via a generic
    helper. If Task #9 finds this split painful, the cached sections can
    also be lifted into generic helpers — there's no technical obstacle.
  - **The Task #6-era `cfg_attr(not(test), expect(...))` attributes on
    `MidenLookupAir` / `LookupAir::eval` / `ConstraintLookupBuilder` file-level
    / the `constraint.rs` adapter chain / the two re-exports in `mod.rs`**
    still need to be removed by Task #8. This task added new file-level
    expects on each `buses/*.rs` file — those too must be removed when
    `ProcessorAir::eval` calls `MidenLookupAir::eval` unconditionally.

- **Insights**:
  - **Mutually-exclusive flag splits change `V_g` degree.** The plan's
    per-label response split (4 memory variants) is algebraically equivalent
    to the legacy runtime-muxed encoding, but the new `V_g = Σ f_i` sums
    4 deg-5 products where the old `V_g = is_memory` is just deg-3. The
    transition `delta·U - V` final expression then depends on max(delta_U,
    V) for its degree, and the new V_deg-5 path bumps the transition by 1.
    The fix was to keep the legacy muxed encoding through new `LookupMessage`
    impls — minimal code, exact degree preservation.
  - **Shared `*Ctx` structs beat closure capture for many-field bus bodies.**
    The M3 and C1 bus bodies need 30+ row-derived values in each of their
    two closures. Passing them as closure captures runs into move/borrow
    conflicts; wrapping them in a `CreqCtx` / `CrespCtx` struct and calling
    `&self` helper methods lets both closures share the same values without
    clones. The pattern scales naturally if a bus grows more interactions.
  - **`LB::Var * LB::Var` doesn't compile in the generic context.** Task #6's
    log flagged this; Task #7 hit it in `op_group` (`c0 * c1 * c2`), the
    chiplet-response bitwise `sel * bw_*` mux, and a handful of other places.
    The fix is to pre-lift both operands to `LB::Expr` via `.into()` before
    multiplying. Every `block_stack.rs` / `chiplet_requests.rs` / `op_group.rs`
    call that used a `Var * Var` product in the old `g_*` function now
    reads `v1_expr * v2_expr` instead, with the `.into()` lift done once at
    the top of the bus body.
  - **`pub(in crate::constraints::lookup)` visibility.** The initial
    `pub(super)` on `emit_*` functions didn't let `miden_air.rs` import them
    (because `miden_air` is a sibling of `buses`, not a parent). Switching
    to `pub(in crate::constraints::lookup)` fixed it. Same pattern applies
    to the `pub mod buses;` declaration in `mod.rs` — the mod itself is
    declared `mod buses;` (private to `lookup`) since no code outside
    `lookup` needs to reach into `buses::*`.
  - **`SiblingMsg` strategy (a) just works.** The new `LookupMessage<E, EF>`
    trait is shape-permissive — nothing in the adapter assumes contiguous β
    positions. The only "contiguous" convention lives in the trait docs as
    a suggestion, not a requirement. Preserving the legacy sparse layout in
    two new `SiblingMsg*` structs produces identical symbolic output to the
    old `encode_sparse` calls.

### Task #7 fixup (2026-04-10) — cached-encoding equivalence test — done

- **Date**: 2026-04-10
- **Files touched**:
  - `air/src/constraints/lookup/dual_builder.rs` (new — test-only
    `DualBuilder` / `DualColumn` / `DualGroup` / `DualEncodedGroup` /
    `DualBatch` / `GroupMismatch`; all gated `#[cfg(test)]`; file-level
    `#![allow(dead_code, reason = "…")]` because the `public_values`
    field is stored to mirror the `LookupBuilder` shape but no bus
    currently reads public values)
  - `air/src/constraints/lookup/mod.rs` (edited — added
    `#[cfg(test)] pub mod dual_builder;` and
    `#[cfg(test)] pub use dual_builder::{DualBuilder, GroupMismatch};`)
  - `air/src/constraints/logup_bus/mod.rs` (edited — added new test
    `miden_lookup_air_cached_encoding_equivalence` in the existing
    `#[cfg(test)] mod tests` block, plus an inline `SeededRng` copied
    from `constraints/tagging/ood_eval.rs`)
  - `docs/src/design/lookup_air_plan.md` (this execution log entry)
- **Scope**: a randomized smoke test proving that for every
  `col.group_with_cached_encoding(canonical, encoded)` call inside any
  of the 8 ported buses (`buses/*.rs`), both closures produce
  bit-for-bit identical `(U_g, V_g)` contributions on every random
  `MainTraceRow` input. The test drives `MidenLookupAir::eval` through
  the new `DualBuilder`, which runs BOTH closures of every
  `group_with_cached_encoding` call against independent `(u, v)` state
  machines and compares the final pairs.
- **Arithmetic**: the `DualGroup` / `DualEncodedGroup` / `DualBatch`
  types copy the `ConstraintGroup` / `ConstraintGroupEncoded` /
  `ConstraintBatch` `(U_g, V_g)` / `(N, D)` update formulas verbatim
  from `constraint.rs`, translated from symbolic `AB::Expr` /
  `AB::ExprEF` to concrete `Felt` / `QuadFelt`. No flag-zero skip —
  formulas are literal so the test mirrors the constraint path exactly,
  not the prover path.
- **Per-group only**: the test does NOT fold group contributions into
  a column-level `(U, V)` cross-multiplication. Column-level composition
  is already covered by `miden_lookup_air_degree_within_budget`; this
  test surfaces per-group canonical-vs-encoded bugs in isolation.
- **RNG**: inline deterministic `SeededRng` copied from
  `constraints/tagging/ood_eval.rs`. Seeded from a hardcoded
  `0xDEAD_BEEF_CAFE_F00D` so the test is stable across runs.
- **Sample count**: 100 random row pairs per test invocation. Each row
  iteration is cheap (~8 columns × ~a few groups × ~10 interactions),
  so the entire test finishes in ~0.5 s.
- **Build state**:
  - `cargo check -p miden-air` → **64 warnings** (unchanged from Task
    #7 baseline; the `dual_builder` module is `#[cfg(test)]`-gated and
    invisible to the lib build).
  - `cargo check -p miden-air --tests` → **14 lib-test warnings**
    (unchanged from baseline).
  - `cargo test -p miden-air --lib` → **72/72 passing** (71 existing +
    1 new).
  - `cargo test -p miden-air --lib miden_lookup_air_cached_encoding_equivalence`
    prints `100 samples, 0 mismatches`.
- **Passed on first implementation attempt**. No canonical/encoded
  divergences surfaced in any of the 8 bus emitters — strong evidence
  that Task #7's 8 encoded closures are correctly equivalent to their
  canonical counterparts.
- **Implementation notes**:
  - **Lifetime GAT pattern carried verbatim from `ProverLookupBuilder`
    / `ConstraintLookupBuilder`**: every closure-taking method on the
    adapter (`column`, `group`, `group_with_cached_encoding`, `batch`)
    pins the GAT lifetime to a named `'c` / `'g` / `'b` parameter on
    the method receiver. No HRTB blowup.
  - **Single `DualBatch` type reused for both `DualGroup::Batch` and
    `DualEncodedGroup::Batch`**: both groups share the same
    `(N, D)` absorption formulas, so there's no reason to split.
  - **`group_idx_within_column: &'c mut usize` on `DualColumn`**: the
    column holds a mutable borrow of a counter owned by the builder.
    Each new column resets the counter to 0 so every mismatch carries
    a column-local `group_idx`.
  - **`#[cfg(test)] pub mod dual_builder;` gate** keeps the module
    entirely out of the library surface. The `#[allow(dead_code)]`
    at the file top is only needed because `DualBuilder` stores
    `public_values: &'a [Felt]` to mirror `LookupBuilder`'s trace-access
    contract — no current bus actually reads public values, so without
    the allow the field would trigger a dead-code warning in `lib test`
    mode.
