# Agent memory router

Use this router only when repo-specific memory is genuinely needed. For simple localized
edits, skip agent-memory and inspect the relevant code/tests/docs directly.

If you use this router, choose at most one or two matching chunks. Do not read all files
unless the user explicitly asks for broad onboarding/handoff.

## Task-based routing

- Understanding this repo at a high level:
  `overview.md`
- Changing columns, constraints, buses, relation IDs, tags, public inputs, public
  semantics, `COLUMN_SHAPE`, or `NUM_*`:
  `docs-sync.md`, `architectural-decisions.md`
- Editing LogUp / lookup-argument code:
  `architectural-decisions.md`, `docs-sync.md`
- Editing trace generation or `generate_trace`:
  `tracegen.md`, maybe `style.md`
- Editing Keccak, sponge, node, round, Bitwise64, Memory64, Chunk, or related edge cases:
  `chiplet-gotchas.md`, maybe `tracegen.md`
- Rust cleanup, rustdoc, containers, iterators, tests, handles, or multiplicity aliases:
  `style.md`
- Large refactor, design change, or ambiguous structural change:
  `workflow.md`, plus the relevant task chunk

## Path-based routing

- `src/logup/**`:
  `architectural-decisions.md`, `docs-sync.md`
- `src/primitives/bitwise64.rs`:
  `chiplet-gotchas.md`, `tracegen.md`
- `src/hash/**`:
  `chiplet-gotchas.md`, `tracegen.md`
- `src/transcript/**`:
  `overview.md`, `docs-sync.md`
- `docs/airs/**`:
  `docs-sync.md`
- `docs/chiplets/**`:
  `docs-sync.md`
- `src/tests/**`:
  `style.md`

## If unsure

Prefer no memory plus targeted search. If memory is still needed, read only the most likely
one or two chunks, then search the code/docs for the specific symbol being changed.
