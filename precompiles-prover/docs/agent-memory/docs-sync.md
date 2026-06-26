# Documentation sync rules

The docs **are** the spec; treat them as part of every change, not an afterthought. A code change to
a chiplet's columns, constraints, or buses is incomplete until its docs match.

## Documentation structure

- [`../../README.md`](../../README.md) — entry point: what the stack is and how to run it.
- [`../../DESIGN.md`](../../DESIGN.md) — thin index into `docs/`.
- [`../`](../) top level — cross-cutting docs: [`../architecture.md`](../architecture.md),
  [`../lookup-argument.md`](../lookup-argument.md) (the LogUp mechanism),
  [`../forward-looking.md`](../forward-looking.md), and migration/decision memos.
- **[`../chiplets/`](../chiplets/) — design rationale ("why").** One file per chiplet: the shape,
  the trade-offs, and the soundness arguments.
- **[`../airs/`](../airs/) — audit reference ("what").** One file per AIR, enumerating **every
  column** (index, range, meaning), **every constraint** (degree + rationale), and **every bus
  interaction** (provides/consumes, multiplicities, mutex batching). Written so an external auditor
  can check the implementation against one written spec. The cross-cutting bus list is
  [`../airs/relation-registry.md`](../airs/relation-registry.md).

## Sync rule

- Change a chiplet's columns / constraints / buses / `COLUMN_SHAPE` / `NUM_*` / lqd → update its
  `docs/airs/<chiplet>.md`, and update `docs/airs/relation-registry.md` if a bus is added or
  changed. A PR that moves a column or bus without touching `airs/` is **incomplete**.
- Change the *why* — a new soundness argument or layout trade-off → update its
  `docs/chiplets/<chiplet>.md`.
- Both doc families are cross-linked and both are canonical.
- After a framework or seam change, **grep the docs** for old names: removed APIs, renamed buses,
  dropped constants, old version strings. A stale audit doc is worse than none, because it reads
  authoritative.
