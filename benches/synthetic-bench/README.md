# miden-vm-synthetic-bench

Criterion benchmark that reproduces the **proving-cost brackets** of a real
workload from a small JSON snapshot, without depending on any
producer-side runtime code.

## Approach

STARK proving cost is dominated by the padded power-of-two lengths of the
execution trace's segments. Everything else -- per-chiplet row counts,
instruction mix, which procedures get called -- is second-order once the
brackets are known.

This crate takes a snapshot of per-segment trace-row counts captured by
an external producer (e.g. `protocol/bin/bench-transaction/`'s
`bench-tx.json`), generates a tiny MASM program whose execution
reproduces those brackets, and runs `execute` + `execute_and_prove`
Criterion groups against it. The result is a VM-level regression detector
that isolates *prover* changes from *workload* changes without depending
on the producer's machinery.

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

For each scenario in every producer file under `snapshots/` (or the
single file in `SYNTH_SNAPSHOT`):

2. **Load scenario** -- read the target row counts from the producer's
   `trace` section. See [Snapshot format](#snapshot-format).
3. **Solve** -- pick an iteration count for each snippet so that their
   combined row contributions add up to the scenario's target. We do
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
   match the scenario's. A bracket miss fails the bench; smaller drift
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
when it runs synthetic programs, but a producer pinned to an older
`miden-processor` may report `ace_rows: 0` until that dependency
exposes the accessor. Treat zero ACE rows in a snapshot as a producer
visibility limitation, not as proof that the VM emitted no ACE rows.

## Snapshot format

A producer JSON file is a map of scenario keys to entries. Each entry
must carry a `trace` section; any sibling fields (cycle counts,
metadata, ...) are silently ignored. Inside `trace`, the AIR-side
totals (`core_rows`, `chiplets_rows`, `range_rows`) are the verifier's
hard contract; nested `chiplets_shape` is an advisory per-chiplet
breakdown. The loader checks
`trace.chiplets_rows == sum(trace.chiplets_shape) + 1`.

```json
{
  "consume single P2ID note": {
    "trace": {
      "core_rows": 77699,
      "chiplets_rows": 123129,
      "range_rows": 20203,
      "chiplets_shape": {
        "hasher_rows": 120352,
        "bitwise_rows": 416,
        "memory_rows": 2297,
        "kernel_rom_rows": 63,
        "ace_rows": 0
      }
    }
  }
}
```

Snapshots live in `snapshots/`. The bench loads every `*.json` file in
that directory and runs one Criterion group per `(producer_file,
scenario_key)` pair, named `<producer-stem>/<scenario-slug>`. See the
[Running](#running) section below for `SYNTH_SNAPSHOT` /
`SYNTH_SCENARIO` filters.

There is no schema-version field; the on-disk shape is the contract.
If the producer changes that shape, the loader fails loudly (serde
error or chiplet-sum mismatch). Update both repos together.

## Verifier contract

Once the emitted program has run, the verifier compares its actual
row counts against the scenario's targets and decides whether the
bench passed. The checks come in three tiers -- **hard**, **soft**,
and **info** -- graded by how directly each number maps to proving
cost. There's also one free-standing **warning** for snippet-balance
regressions.

### Hard checks -- fail the bench

Proving cost is dominated by the padded (power-of-two) length of each
trace segment, not by the raw row count. So the only assertions that
can fail the bench are on two padded proxies:

- `padded_core_side = max(64, next_pow2(max(core_rows, range_rows)))`
  -- the non-chiplets side of the AIR.
- `padded_chiplets   = max(64, next_pow2(chiplets_rows))`.

These two can land in *different* brackets on the same workload --
`consume two P2ID notes`, for example, has `padded_core_side = 131072`
but `padded_chiplets = 262144`. Checking them independently catches a
bracket miss on either side that a single global `padded_total` check
would hide.

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

## Refreshing snapshots from a producer

Snapshots travel by hand so that producer and consumer can evolve
independently. For the `protocol/bin/bench-transaction/` producer:

1. In `protocol`: `cargo run --release --bin bench-transaction --features concurrent`.
2. Copy `bin/bench-transaction/bench-tx.json` over
   `miden-vm/benches/synthetic-bench/snapshots/bench-tx.json`.
3. Run `cargo bench -p miden-vm-synthetic-bench` and verify
   `=> BRACKET MATCH` for every scenario in the printed verifier
   tables.

If a kernel change moves a scenario into a different padded bucket,
the `committed_snapshots_load` test in `src/snapshot.rs` fails with
the producer/scenario pair and the new bracket -- update
`COMMITTED_SCENARIO_EXPECTATIONS` accordingly.

## Running

```sh
cargo bench -p miden-vm-synthetic-bench
```

Env vars:

- `SYNTH_SNAPSHOT=<path>` -- bench only the specified producer JSON
  (instead of iterating over every `snapshots/*.json`).
- `SYNTH_SCENARIO=<substr>` -- restrict to scenarios whose slugified
  key contains this slugified substring. Both sides are slugified
  before comparison, so `"P2ID"`, `"p2id"`, `"P2ID note"`, and
  `"p2id-note"` all match `"consume single P2ID note"`.
- `SYNTH_MASM_WRITE=1` -- dump each emitted MASM program to
  `target/synthetic_bench_<producer-stem>__<scenario-slug>.masm` for
  inspection.

The `prove` and `verify` axes use `HashFunction::Poseidon2` for STARK
proof generation (see the `BENCH_HASH` constant in `benches/synthetic_bench.rs`).

## License

This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
