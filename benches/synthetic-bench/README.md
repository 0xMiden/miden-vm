# miden-vm-synthetic-bench

Criterion benchmark that reproduces the **proving-cost brackets** of a real
workload from a small JSON snapshot, without depending on any
producer-side runtime code.

> **Current snapshot status:** the executable `snapshots/bench-tx.json` is marked
> `derived_pending_producer_port`. It is a provisional Eidos calibration target derived from a
> pre-Eidos producer capture, not a transaction measurement from the current VM. Benchmark output
> repeats this warning for every derived scenario. Do not publish its timings as measured Eidos
> transaction performance.
>
> The exact 43-scenario Poseidon2 producer artifact from `next` is preserved at
> `snapshots/poseidon2-source/bench-tx.json`. It includes the six explicit Falcon/ECDSA P2ID keys,
> but it is source evidence only: the default benchmark glob does not descend into that directory,
> and the Eidos loader rejects its Poseidon2 trace schema. There is no sound field-wise conversion
> from those rows to Eidos rows.

## Approach

STARK proving cost is dominated by the padded power-of-two lengths of the
execution trace's segments. Everything else -- per-chiplet row counts,
instruction mix, which procedures get called -- is second-order once the
brackets are known.

This crate takes a snapshot of per-segment trace-row counts supplied by
an external producer (e.g. `protocol/bin/bench-transaction/`'s
`bench-tx.json`), generates a tiny MASM program whose execution
reproduces those brackets, and runs execution, trace-preparation, proving, and verification
Criterion groups against it. The result is a VM-level regression detector
that isolates *prover* changes from *workload* changes without depending
on the producer's machinery.

The checked-in `bench-tx.json` is a provisional calibration target, not a producer measurement. Its
Eidos compression and controller-row values are estimates, and its And8 target is the fixed
65,536-row table. These values preserve useful proving-cost brackets, but they are not evidence of
a producer trace shape.

## Pipeline (per bench run)

Each bench invocation rebuilds every synthetic program from scratch,
so the numbers always reflect the current commit's VM -- there are no
stale calibration constants checked into the repo.

1. **Calibrate (once)** -- run each MASM snippet as `repeat.K ...` and
   divide the resulting per-component row counts by `K` to learn how
   many core, Eidos-compression, chiplet, and memory rows a single iteration costs *on this VM*.
   Running this on every bench invocation is what keeps the
   bench honest across VM changes: if `compress` gets cheaper tomorrow,
   tomorrow's iteration count grows to compensate, and the target
   bracket is still hit.

For each scenario in every top-level Eidos file under `snapshots/` (or the
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
   counts, and assert that all four padded brackets match the scenario's:
   core, chiplets, Eidos compression, and the fixed And8 byte-pair lookup table.
   A bracket miss fails the bench; smaller drift inside the same bracket
   is reported but tolerated, because proving cost is driven by the
   padded length, not the raw count.

## Snippets

Four patterns cover every dynamic component the solver targets:

| Snippet       | Body                                         | Drives                        |
|---------------|----------------------------------------------|-------------------------------|
| `eidos_compression` | `compress`                            | Eidos compression work        |
| `bitwise`     | `u32split u32xor`                            | total chiplets bracket        |
| `memory`      | `dup.4 mem_storew_le dup.4 mem_loadw_le movup.4 push.262148 add movdn.4` | advisory memory composition |
| `decoder_pad` | `swap dup.1 add`                             | core (decoder + stack)        |

`memory` advances its word-aligned address by 262148 so each iteration
touches a distinct address. The fixed And8 lookup table is not workload
shaped; only its multiplicity column varies with Eidos compression activity.

The solver has no snippets targeting the ACE or kernel-ROM chiplets.

- **ACE** is reachable from plain MASM, but exercising it requires
  building an arithmetic circuit and preparing a memory region for its
  READ section -- more setup than the other snippets warrant, and not
  currently done here.
- **Kernel-ROM** rows are a small, near-constant contribution in
  practice, so a dedicated driver would add complexity without
  materially improving the profile.

Instead of trying to reproduce every chiplet subtype, the bitwise
snippet acts as the efficient adjustable filler for the authoritative
total-chiplets target. The memory snippet keeps the advisory memory mix
representative; bitwise, ACE, and kernel-ROM composition is reported for
visibility but is not a hard constraint. This preserves the total
chiplets proving bracket while the separate Eidos compression target preserves
native-hash work.

## Snapshot format

A producer JSON file is a map of scenario keys to entries. Each entry
must carry a `provenance` value and a `trace` section; other sibling fields (cycle counts,
metadata, ...) are silently ignored. `provenance` is either `producer_measured` or
`derived_pending_producer_port`. Inside `trace`, the AIR-side
totals (`core_rows`, `chiplets_rows`, `eidos_compression_rows`,
`byte_pair_lookup_rows`) are the verifier's contract; nested
`chiplets_shape` is an advisory per-chiplet breakdown containing `hasher_rows`, `bitwise_rows`,
`memory_rows`, `kernel_rom_rows`, and `ace_rows`. These fields are all required; unknown fields are
rejected so a topology or schema mismatch fails at load time. The loader checks
`trace.chiplets_rows == sum(trace.chiplets_shape) + 1`.

```json
{
  "consume single P2ID note": {
    "provenance": "derived_pending_producer_port",
    "trace": {
      "core_rows": 77683,
      "chiplets_rows": 6537,
      "eidos_compression_rows": 120384,
      "byte_pair_lookup_rows": 65536,
      "chiplets_shape": {
        "hasher_rows": 3762,
        "bitwise_rows": 416,
        "memory_rows": 2294,
        "kernel_rom_rows": 64,
        "ace_rows": 0
      }
    }
  }
}
```

Executable Eidos snapshots live directly in `snapshots/`. The bench loads every top-level
`*.json` file in that directory (non-recursively) and runs one Criterion group per `(producer_file,
scenario_key)` pair, named `<producer-stem>/<scenario-slug>`. See the
[Running](#running) section below for `SYNTH_SNAPSHOT` /
`SYNTH_SCENARIO` filters.

Poseidon2 producer artifacts live below `snapshots/poseidon2-source/`. They retain upstream
scenario and schema coverage, including the explicit
`... with Falcon signing` / `... with ECDSA signing` fixture keys, without pretending that the
captured Poseidon2 rows are Eidos measurements. They are intentionally outside the default glob
and cannot be passed to `SYNTH_SNAPSHOT` as executable Eidos targets.

There is no schema-version field; the on-disk shape and provenance marker are the contract.
If the producer changes that shape, the loader fails loudly (serde
error or chiplet-sum mismatch). Update both repos together.

## Verifier contract

Once the emitted program has run, the verifier compares its actual
row counts against the scenario's targets and decides whether the
bench passed. The checks come in three tiers -- **hard**, **soft**,
and **info** -- graded by how directly each number maps to proving
cost.

### Hard checks -- fail the bench

Proving cost is dominated by the padded (power-of-two) height of each AIR, not by the raw row
count. The assertions that can fail the bench are on the four independently padded AIR heights:

- `padded_core     = max(64, next_pow2(core_rows))`.
- `padded_chiplets = max(64, next_pow2(chiplets_rows))`.
- `padded_eidos_compression   = max(64, next_pow2(eidos_compression_rows))`.
- `padded_and8     = max(64, next_pow2(byte_pair_lookup_rows))`.
- `padded_total    = max(padded_core, padded_chiplets, padded_eidos_compression, padded_and8)`.

These can land in *different* brackets on the same workload -- `consume two P2ID notes`, for
example, has `padded_core = 131072`, `padded_chiplets = 8192`, `padded_eidos_compression = 262144`, and
`padded_and8 = 65536`. Checking them independently catches a bracket miss that a single global
`padded_total` check would hide.

### Soft checks -- report, don't fail

`core_rows`, `chiplets_rows`, `eidos_compression_rows`, and
`byte_pair_lookup_rows` are
compared against the targets within a 2% band. A drift inside that band
usually leaves the proving bracket unchanged, so the bench only reports
it. A drift that *crosses* a bracket is always caught by the hard tier
above; this tier exists to surface raw-count near-misses worth noticing.

### Info -- no judgement

Per-chiplet deltas (hasher/bitwise/memory/...) from `shape` are
printed for visibility but never asserted. Some divergence is
unavoidable: MAST hashing at program init contributes hasher rows
that the synthetic program can't suppress, so a snapshot with
`core_rows / hasher_rows > 4` cannot be per-chiplet-matched even
though it still matches all padded AIR brackets. See `src/snippets.rs`
for the cases where this structural mismatch shows up.

## Replacing provisional snapshots from a producer

Snapshots travel by hand so that producer and consumer can evolve independently. Replace the
checked-in provisional data only with producer output that reports the four Eidos AIR totals:

1. In `protocol`: `cargo run --release --bin bench-transaction --features concurrent`.
2. Confirm every scenario contains current `core_rows`, `chiplets_rows`,
   `eidos_compression_rows`, and `byte_pair_lookup_rows` values, and mark its provenance
   `producer_measured`.
3. Copy the Eidos producer output over
   `miden-vm/benches/synthetic-bench/snapshots/bench-tx.json`. Do not derive it from
   `snapshots/poseidon2-source/bench-tx.json`.
4. Replace the provisional bracket table in `src/snapshot.rs` with expectations derived from the
   measured file.
5. Run `cargo bench -p miden-vm-synthetic-bench` and verify
   `=> BRACKET MATCH` for every scenario in the printed verifier
   tables.

If a kernel change moves a scenario into a different padded bucket,
the `committed_snapshots_load` test in `src/snapshot.rs` fails with
the producer/scenario pair and the new bracket. Update the expectation table only from the new
producer measurement, not by mechanically transforming the old capture.

## Running

```sh
cargo bench -p miden-vm-synthetic-bench
```

Env vars:

- `SYNTH_SNAPSHOT=<path>` -- bench only the specified **Eidos** producer JSON
  (instead of iterating over every top-level `snapshots/*.json`). Poseidon2 source artifacts are
  rejected rather than reinterpreted as Eidos targets.
- `SYNTH_SCENARIO=<substr>` -- restrict to scenarios whose slugified
  key contains this slugified substring. Both sides are slugified
  before comparison, so `"P2ID"`, `"p2id"`, `"P2ID note"`, and
  `"p2id-note"` all match `"consume single P2ID note"`.
- `SYNTH_BENCH_AXES=<axes>` -- comma-separated subset of `exec`, `trace_prep`, `prove`, and
  `verify`; `all` selects every axis.
- `SYNTH_SAMPLE_SIZE=<n>`, `SYNTH_MEASUREMENT_TIME_SECS=<n>`, and
  `SYNTH_WARM_UP_TIME_SECS=<n>` -- Criterion timing controls.
- `SYNTH_MASM_WRITE=1` -- dump each emitted MASM program to
  `target/synthetic_bench_<producer-stem>__<scenario-slug>.masm` for
  inspection.

The `prove` and `verify` axes use `HashFunction::Eidos`, matching the
production STARK proof-hash backend (see `BENCH_HASH` in
`benches/synthetic_bench.rs`).

## Recursive-verification benchmarks

The `recursive_verify` benchmark measures recursive verification of synthetic transaction proofs.
First emit the `consume-single-p2id-note` transaction fixture:

```sh
SYNTH_SCENARIO="consume single P2ID note" \
SYNTH_BENCH_AXES=exec \
SYNTH_MASM_WRITE=1 \
cargo bench -p miden-vm-synthetic-bench --bench synthetic_bench --profile optimized
```

Then pass the generated MASM program to the recursive benchmark. By default it measures two
through eight MVM proofs:

```sh
RECURSION_BENCH_MASM="benches/synthetic-bench/target/synthetic_bench_bench-tx__consume-single-p2id-note.masm" \
cargo bench -p miden-vm-synthetic-bench --bench recursive_verify --profile optimized
```

The recursive verifier requires the inner MVM and PVM proofs to use Eidos. The optional
`RECURSION_BENCH_HASH` setting controls only the outer proof's STARK hash and defaults to
Poseidon2.

Set `RECURSION_BENCH_TX_PROOF_CACHE_DIR` to reuse the generated transaction proofs across runs.
Relative cache paths are resolved from the workspace root.

### PVM comparison

The focused comparison places mixed cases containing one proof of the canonical
100-Keccak/4-ECDSA deferred workload beside pure-MVM baselines:

```sh
RECURSION_BENCH_MASM="benches/synthetic-bench/target/synthetic_bench_bench-tx__consume-single-p2id-note.masm" \
RECURSION_PVM_COMPARISON=1 \
RECURSION_BENCH_TX_PROOF_CACHE_DIR="${PWD}/target/recursive-bench-cache/tx" \
RECURSION_BENCH_PVM_PROOF_CACHE_DIR="${PWD}/target/recursive-bench-cache/pvm" \
RECURSION_PROFILE_PROVE=1 \
RECURSION_PROFILE_PROVE_REPEATS=10 \
RECURSION_PROFILE_PROVE_WARMUPS=1 \
cargo bench -p miden-vm-synthetic-bench --bench recursive_verify --profile optimized
```

The four cases are `4 MVM + 1 PVM`, `7 MVM`, `5 MVM + 1 PVM`, and `8 MVM`, in that order. Eight
distinct proofs of the same synthetic transaction program and the single PVM proof are loaded or
generated before any timed section. Set `RECURSION_PROFILE_ONLY=1` to print trace shapes without
Criterion timing, or `RECURSION_PROFILE_PROVE=1` to record repeated outer-proof measurements. The
profile mode rotates the starting case in each round to limit cache and thermal ordering bias.

## License

This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
