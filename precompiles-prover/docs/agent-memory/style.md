# Style and sticky preferences

These came up across prior sessions and should be honored by default, subject to stricter
system/developer instructions in the current agent environment.

## Git and docs

- **Never push without an explicit command**. Force-push only when explicitly told.
- If the current environment and user explicitly allow committing, use tight commit messages that
  say what and why, with co-author trailer: `Co-Authored-By: Claude Opus 4.8 (1M context)
  <noreply@anthropic.com>`.
- **Rustdoc is for users, not project management. Rustdoc is not a changelog.** No forward-looking
  text ("upcoming X", "future deliverable", "deferred"), no historical context ("legacy was 3 cols",
  "previously asserted X", "was removed when…"), no speculative future code. Keep rustdoc consistent
  with what the API does *now*. Memos, migration plans, and project planning live in `docs/` or
  agent memory, never inline in module docs.
- **Doc-link style**: prefer bare names that resolve via existing `use` imports; fall back to
  display-syntax (``[`Name`](full::Path)``) where the path is foreign. Avoid ``[`crate::foo::Bar`]``
  rendered literally.

## Rust style

- **`std::iter::zip(a, b)`** over `a.iter().zip(b.iter())` for peer iterators;
  **`itertools::izip!`** for ≥3-way zips. Prefer `IntoIterator` impls (`for x in &v`) where natural
  — but **`column.iter_mut()` is preferred over `for x in &mut *column`** reborrow pattern.
- **Don't add unnecessary Felt arithmetic** in hot paths. Prefer direct byte/u32/u64 → Felt casts
  where possible.
- **`assert!`**, not `debug_assert!`, for caller-bug-detecting preconditions in IR construction
  APIs. Witness-construction time is not perf-sensitive; silent corruption is worse than panic.
- **Fixed-size key spaces want a `Vec`** (e.g. BPL's `BytePairLutRequires::counts`), not a
  `BTreeMap`/`HashMap`. Direct array indexing is simpler and faster on the hot path.
- **Tests in `src/tests/{chiplet}.rs`**, never inline.
- **Trait-bound conciseness**: when an existing trait has all the super-bounds you need, prefer the
  single bound, e.g. `EF: Algebra<E>` over `PrimeCharacteristicRing + Clone + Algebra<E> +
  core::fmt::Debug`.
- **`use core::array;`** at the top, then `array::from_fn(...)`; no inline `core::array::from_fn`
  FQNs.
- **Sanity-check container choices.** If a `VecDeque`/`HashMap` is reached for, ask whether the
  access pattern actually justifies it — VecDeque-as-append-only-Vec was a real trap.
- **`vec.extend([..])` over chained `.push` calls.** A run of consecutive `.push(x)` writing a fixed
  group of values collapses to `vec.extend([x1, x2, ..., xn])`. Reads cleanly as a single conceptual
  unit and skips the per-call dispatch.
- **`cargo fmt` on every change.** Run `cargo fmt` or `rustfmt --edition 2024 <files>` for surgical
  scope before committing any Rust edit. The repo baseline is fmt-clean for all non-WIP files;
  preserve that property.

## Handles and multiplicities

- **Cross-chiplet interned identifiers are newtyped handles** minted only by the owning accumulator:
  `UintPtr`, `EcGroupPtr` / `EcPointPtr`, `PermSeqId` / `PermSpan`, `ChunkSeqId`, `SpongeSeqId`. Use
  a private field; the interning/allocating entry is the sole constructor; raw numbers surface only
  at trace-cell writes (`.addr()` / `.seq()`) and in bare-chiplet tests via the `cfg(test)`
  `forged()` escapes. Namespace conversions are named methods, never inline arithmetic
  (`ChunkSeqId::ptr()` is the chunk-row → Memory64-word-address seam, replacing scattered
  `*4`/`/4`). A raw `u32`/`u64` id crossing a requires boundary is a smell.
- **Provide/consume multiplicities are the `ProvideMult` alias** (`relations.rs`), never a bare
  `u32`: a demand ledger reads `Ptr → ProvideMult`, and every new `_mult` / consumer-count field or
  param takes the alias. It's a transparent `u32` — arithmetic is untouched — but it names the
  LogUp-multiplicity role so the next rebase needn't retype freshly-added counters.
