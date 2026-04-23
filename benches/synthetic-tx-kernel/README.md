# miden-synthetic-tx-kernel

Criterion benchmark that reproduces the **proving-cost brackets** of a real
Miden transaction workload from a small JSON snapshot -- without pulling in
any protocol-level code.

## Approach

STARK proving cost is dominated by the padded power-of-two lengths of the
execution trace's segments. Everything else -- per-chiplet row counts,
instruction mix, which procedures get called -- is second-order once the
brackets are known.

This crate takes a snapshot of per-segment trace-row counts captured from
a real transaction in the `protocol` repo, generates a tiny MASM program
whose execution reproduces those brackets, and runs `execute` +
`execute_and_prove` Criterion groups against it. The result is a
VM-level regression detector that isolates *prover* changes from
*workload* changes without depending on protocol's transaction
machinery.

## Pipeline (per bench run)

Each bench invocation rebuilds every synthetic program from scratch,
so the numbers always reflect the current commit's VM -- there are no
stale calibration constants checked into the repo.

1. **Calibrate (once)** -- run each MASM snippet as `repeat.K ...` and
   divide the resulting per-component row counts by `K` to learn how
   many core/hasher/memory/... rows a single iteration costs *on this
   VM*. Running this on every bench invocation is what keeps the
   bench honest across VM changes: if `hperm` gets cheaper tomorrow,
   tomorrow's iteration count grows to compensate, and the target
   bracket is still hit.

For each snapshot under `snapshots/` (or the single path in
`SYNTH_SNAPSHOT`):

2. **Load snapshot** -- read the target row counts; this is the shape
   we want the emitted program to reproduce. See
   [Snapshot format](#snapshot-format).
3. **Solve** -- pick an iteration count for each snippet so that their
   combined row contributions add up to the snapshot's target. We do
   this by fixed-point refinement: start from zero, and on each pass
   update every snippet's count from the current guesses of the others,
   clamping negatives to zero. A handful of passes is enough because
   each snippet is designed to drive mostly *one* component, so the
   counts barely depend on each other and the sweep converges quickly.
   (For the linear-algebra reader: this is Jacobi iteration on a
   near-diagonal matrix with a non-negativity projection.)
4. **Emit** -- wrap each snippet's body in a `repeat.N ... end` block,
   concatenate, and enclose in `begin ... end`. The output is the MASM
   program that Criterion actually runs.
5. **Verify** -- execute the emitted program, measure its real row
   counts, and assert that `padded_core_side` and `padded_chiplets`
   match the snapshot's. A bracket miss fails the bench; smaller drift
   inside the same bracket is reported but tolerated, because proving
   cost is driven by the padded length, not the raw count.

## Snippets

Five patterns cover every component the solver targets:

| Snippet       | Body                                         | Drives                        |
|---------------|----------------------------------------------|-------------------------------|
| `hasher`      | `hperm`                                      | Poseidon2 hasher chiplet      |
| `bitwise`     | `u32split u32xor`                            | bitwise chiplet               |
| `u32arith`    | `u32assert2 push.65537 add swap push.65537 add swap` | range chiplet |
| `memory`      | `dup.4 mem_storew_le dup.4 mem_loadw_le movup.4 push.262148 add movdn.4` | memory chiplet |
| `decoder_pad` | `swap dup.1 add`                             | core (decoder + stack)        |

`u32arith` and `memory` use banded counters (strides of 65537 and
262148) so that their 16-bit limbs form disjoint contiguous bands,
keeping the range chiplet from deduplicating limb values across
iterations.

The solver has no snippets targeting the ACE or kernel-ROM chiplets.

- **ACE** is reachable from plain MASM, but exercising it requires
  building an arithmetic circuit and preparing a memory region for its
  READ section -- more setup than the other snippets warrant, and not
  currently done here.
- **Kernel-ROM** rows are a small, near-constant contribution in
  practice, so we simplify by folding them into the memory target
  rather than driving them directly.

Since snapshots still carry row counts for both, they're **folded into
the memory target** -- growing memory ops preserves the overall
chiplet-trace length and therefore the chiplet bracket.

One producer-side caveat: the consumer can measure `ace_chiplet_len()`
when it runs synthetic programs, but protocol snapshots may report
`ace_rows: 0` until the protocol-side `miden-processor` dependency
exposes that accessor. Treat zero ACE rows in a snapshot as a producer
visibility limitation, not as proof that the VM emitted no ACE rows.

## Snapshot format

Two-tier: **hard-contract totals** in `trace`, **advisory breakdown** in
`shape`. The loader validates `trace.chiplets_rows == sum(shape) + 1`.
Schema version is currently `"0"`.

```json
{
  "schema_version": "0",
  "source": "protocol/bench-transaction:consume-single-p2id",
  "timestamp": "unix-1776428820",
  "miden_vm_version": "0.22",
  "trace": {
    "core_rows":     77699,
    "chiplets_rows": 123129,
    "range_rows":    20203
  },
  "shape": {
    "hasher_rows":     120352,
    "bitwise_rows":       416,
    "memory_rows":       2297,
    "kernel_rom_rows":     63,
    "ace_rows":             0
  }
}
```

Snapshots live in `snapshots/`. The bench loads every `*.json` file in
that directory and runs one Criterion group per snapshot, named
`synthetic_transaction_kernel/<file-stem>`. Set
`SYNTH_SNAPSHOT=/path/to/file.json` to bench a single snapshot
instead.

## Verifier contract

Once the emitted program has run, the verifier compares its actual
row counts against the snapshot's targets and decides whether the
bench passed. The checks come in three tiers -- **hard**, **soft**,
and **info** -- graded by how directly each number maps to proving
cost. There's also one free-standing **warning** for snippet-balance
regressions.

### Hard checks -- fail the bench

Proving cost is dominated by the padded (power-of-two) length of each
trace segment, not by the raw row count. So the only assertions that
can fail the bench are on two padded proxies:

- `padded_core_side = next_pow2(max(core_rows, range_rows))` -- the
  non-chiplets side of the AIR.
- `padded_chiplets   = next_pow2(chiplets_rows)`.

These two can land in *different* brackets on the same workload --
`consume-two-p2id`, for example, has `padded_core_side = 131072` but
`padded_chiplets = 262144`. Checking them independently catches a
bracket miss on either side that a single global `padded_total`
check would hide.

### Soft checks -- report, don't fail

`core_rows` and `chiplets_rows` are compared against the targets
within a 2% band. A drift inside that band is harmless for proving
cost (same bracket either way), so the bench only reports it. A
drift that *crosses* a bracket is already caught by the hard tier
above, so this tier exists purely to surface in-bracket near-misses
worth noticing.

### Info -- no judgement

Per-chiplet deltas (hasher/bitwise/memory/...) from `shape` are
printed for visibility but never asserted. Some divergence is
unavoidable: MAST hashing at program init contributes hasher rows
that the synthetic program can't suppress, so a snapshot with
`core_rows / hasher_rows > 4` cannot be per-chiplet-matched even
though it still matches both padded brackets. See `src/snippets.rs`
for the cases where this structural mismatch shows up.

### Warning -- range dominates

If `range_rows` turns out to be the largest unpadded component in
either the target or the actual shape, the bench prints a warning.
The solver treats range as a derived quantity driven mostly by u32
arithmetic; if it starts setting the bracket, snippet balance has
drifted and should be revisited.

## Refreshing snapshots from protocol

The producer lives in the `protocol` repo as
`bin/bench-transaction/src/bin/tx-trace-snapshot.rs` and emits one
JSON per scenario under `bin/bench-transaction/snapshots/`. Flow:

1. In `protocol`: `cargo run --release -p bench-transaction --bin tx-trace-snapshot`
2. Copy the regenerated JSONs over the same-named files in
   `miden-vm/benches/synthetic-tx-kernel/snapshots/`.
3. Run `cargo bench -p miden-synthetic-tx-kernel` and verify
   `=> BRACKET MATCH` for every snapshot in the printed verifier
   tables.

Snapshots travel by hand so that the two repos can evolve independently. The
loader rejects unknown `schema_version` values. A `miden_vm_version` major/minor
mismatch is intentionally a loud warning, not a hard failure, because protocol
often pins one miden-vm release behind `next`. Read bracket matches across a
version mismatch as useful regression signals, then refresh the snapshots when
the protocol-side pin catches up.

## Running

```sh
cargo bench -p miden-synthetic-tx-kernel
```

Env vars:

- `SYNTH_SNAPSHOT=<path>` -- bench only the specified snapshot file
  (instead of iterating over every `snapshots/*.json`).
- `SYNTH_MASM_WRITE=1` -- dump each emitted MASM program to
  `target/synthetic_kernel_<snapshot-stem>.masm` for inspection.
