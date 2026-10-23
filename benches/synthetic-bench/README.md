# Synthetic transaction benchmarks

This package generates MASM programs with the same padded AIR heights as measured protocol
transactions. `synthetic_bench` measures their execution, witness preparation, proving, and native
verification. `recursive_verify` measures the cost of verifying X MVM proofs and one PVM proof
inside another MVM program.

The standalone MVM defaults cover consuming one P2ID note, consuming two notes, and creating one
note, each with Falcon or ECDSA signing. Recursive benchmarks default to the two-note consumption
workloads. Use `SYNTH_SCENARIO` to select a workload. The standalone MVM benchmark also supports
the other scenarios in the snapshot.

## MVM benchmarks

```sh
cargo bench -p miden-vm-synthetic-bench --bench synthetic_bench --profile optimized
```

`exec` measures execution. `trace_prep` measures execution and replay-witness preparation.
`prove` includes execution, trace construction, and proof generation. `verify` measures native
verification of a proof generated during setup.

| Environment variable | Meaning |
| --- | --- |
| `SYNTH_SNAPSHOT` | Use one JSON file; default: all top-level `snapshots/*.json` files |
| `SYNTH_SCENARIO` | Match part of a scenario name, ignoring case and separators |
| `SYNTH_BENCH_AXES` | Comma-separated `exec`, `trace_prep`, `prove`, `verify`, or `all`; default: all |
| `SYNTH_HASH_LDE_BLOCKS` | Hash completed LDE blocks when proving: `0` or `1`; default: `0` |
| `SYNTH_SAMPLE_SIZE` | Criterion sample size; default: 30 |
| `SYNTH_MEASUREMENT_TIME_SECS` | Measurement duration in seconds; default: 30 |
| `SYNTH_WARM_UP_TIME_SECS` | Warm-up duration in seconds; default: 1 |
| `SYNTH_MASM_WRITE` | Write generated programs to this package's `target/` |

## Recursive benchmarks

Each case verifies X distinct MVM proofs and one PVM proof, for X = 3, 4, 5, 6, 7. All X MVM
proofs use the same P2ID scenario and signing scheme.

The single PVM proof covers X secp256k1 ECDSA verifications and their X Keccak prehashes, each
over a distinct 32-byte message. Both signing schemes use this PVM workload for comparison;
Falcon transactions verify their signatures inside the MVM.

The synthetic MVM programs contain no deferred work. The PVM proof is generated separately from
one witness. This measures verification cost without checking settlement of the transactions'
deferred work or exercising PVM proofs with multiple public roots.

The defaults run two-note consumption separately for Falcon and ECDSA, with five proof counts
per scheme: ten cases in total.

```sh
cargo bench -p miden-vm-synthetic-bench --bench recursive_verify --profile optimized
```

Set `SYNTH_SCENARIO="consume single P2ID note"` or `SYNTH_SCENARIO="create single P2ID note"`
to run the other P2ID workloads. `SYNTH_SCENARIO=signing` selects all six scenarios.

Before timing, the benchmark loads or generates all inner proofs and verifies them natively.
It prepares one PVM proof for each X and reuses it across scenarios with the same X.

Inner proofs are cached in `target/recursive-bench-cache/{tx,pvm}`. When `CARGO_TARGET_DIR` is set,
the cache goes under that directory instead of `target`. Use `RECURSION_BENCH_TX_PROOF_CACHE_DIR`
and `RECURSION_BENCH_PVM_PROOF_CACHE_DIR` to choose other directories. Relative overrides start
at the VM root. Invalid cached proofs are regenerated; delete an entry to force regeneration.

Cache keys include the AIR relation and proof parameters, plus the MVM program and inputs or
the PVM deferred root. MVM keys also include the proof format and MVM/PVM verifier roots. The
benchmark checks each synthetic program against its snapshot before looking up MVM proofs.

Each case reports four measurements:

| Measurement | Includes |
| --- | --- |
| `execute` | Execution and replay-witness preparation |
| `build_trace` | Trace construction after execution |
| `total` | Execution, replay-witness preparation, and trace construction |
| `prove` | Execution, trace construction, and outer proof generation |

Trace summaries report row counts for all four MVM AIRs and individual chiplets in each case.

For repeated outer proving measurements:

```sh
RECURSION_PROFILE_PROVE=1 \
RECURSION_PROFILE_PROVE_REPEATS=10 \
RECURSION_PROFILE_PROVE_WARMUPS=1 \
cargo bench -p miden-vm-synthetic-bench --bench recursive_verify --profile optimized
```

The starting case rotates between rounds. The report includes mean, median, minimum, maximum,
and proof size. Outer-proof verification happens outside the timer.

| Environment variable | Meaning |
| --- | --- |
| `RECURSION_PROOF_COUNTS` | Comma-separated counts from 3 through 7; default: all five |
| `RECURSION_HASH_LDE_BLOCKS` | Hash completed LDE blocks when proving the outer MVM: `0` or `1`; default: `0` |
| `RECURSION_PROFILE_ONLY` | Prepare inner proofs and print trace sizes, without collecting timings |
| `RECURSION_SAMPLE_SIZE` | Criterion sample size; default: 10 |
| `RECURSION_WARM_UP_TIME_SECS` | Warm-up duration in seconds; default: 1 |
| `RECURSION_MEASUREMENT_TIME_SECS` | Measurement duration in seconds; default: 10 |
| `RECURSION_MASM_WRITE` | Write recursive programs to this package's `target/` |
| `RECURSION_BENCH_STACK` | Initial MVM proof inputs; default: `0,1`, with the first value incremented for each proof |

## Results

Each time is the mean of 20 samples from two separate process runs, excluding warmup.
Peak RSS is the larger whole-process peak from those runs.

All builds use Rust 1.99.0, `--profile optimized`, and `-C target-cpu=native` on Amazon Linux 2023
with glibc 2.34. The Workers column gives `RAYON_NUM_THREADS`. All runs set
`RUST_MIN_STACK=16777216`.

Huge pages improved proving time on all three machines. All runs used
`GLIBC_TUNABLES=glibc.malloc.hugetlb=1` with the kernel's `madvise` huge-page policy. Separate checks
confirmed 2 MiB huge-page use.

Runs with 32 workers were restricted to CPUs 0-31; runs with 64 workers used CPUs 0-63.
On Intel, these CPU sets use one hardware thread per core.

### Two-note ECDSA P2ID: one MVM proof

| Machine | Workers | Mean proving time | Peak process RSS |
| --- | ---: | ---: | ---: |
| AMD EPYC 9R45 (m8a.16xlarge)[^epyc-m8a] | 32 | 0.145 s | 1.38 GiB |
| Intel Xeon 6975P-C (c8i.32xlarge)[^intel-c8i] | 32 | 0.176 s | 1.36 GiB |
| AWS Graviton4 (c8g.16xlarge)[^graviton-c8g] | 64 | 0.161 s | 1.58 GiB |

This measures the synthetic MVM workload; its PVM authentication proof is separate.

### Two-note Falcon P2ID: one MVM proof

| Machine | Workers | Mean proving time | Peak process RSS |
| --- | ---: | ---: | ---: |
| AMD EPYC 9R45 (m8a.16xlarge)[^epyc-m8a] | 64 | 0.232 s | 2.04 GiB |
| Intel Xeon 6975P-C (c8i.32xlarge)[^intel-c8i] | 64 | 0.269 s | 2.06 GiB |
| AWS Graviton4 (c8g.16xlarge)[^graviton-c8g] | 64 | 0.267 s | 2.03 GiB |

### 5 MVM + 1 PVM: outer MVM proof

The five MVM proofs use the two-note ECDSA P2ID workload. The PVM proof covers five ECDSA
verifications and their five Keccak prehashes. Timing includes outer execution, trace construction,
and proving; cached inner-proof preparation and native verification are outside the timer.

| Machine | Workers | Mean proving time | Peak process RSS |
| --- | ---: | ---: | ---: |
| AMD EPYC 9R45 (m8a.16xlarge)[^epyc-m8a] | 64 | 1.154 s | 14.37 GiB |
| Intel Xeon 6975P-C (c8i.32xlarge)[^intel-c8i] | 64 | 1.384 s | 14.35 GiB |
| AWS Graviton4 (c8g.16xlarge)[^graviton-c8g] | 64 | 1.839 s | 14.32 GiB |

[^epyc-m8a]: This instance has 64 physical cores, 256 GiB RAM, and one NUMA node. We enabled
    blockwise LDE hashing for Falcon and 5 MVM + 1 PVM because it improved their proving times.
    ECDSA and 5 MVM + 1 PVM use PGO, which also reduced their proving times.

[^intel-c8i]: This instance has 64 physical cores, 128 logical CPUs, 256 GiB RAM, and two NUMA
    nodes. Falcon uses a PGO build; 5 MVM + 1 PVM enables blockwise LDE hashing. Both changes
    reduced proving time. We used the default NUMA memory policy.

[^graviton-c8g]: This instance has 64 physical cores, 128 GiB RAM, and one NUMA node. PGO made
    these workloads slower. Blockwise LDE hashing changed proving times by less than 1%, so we
    left both options off.

## Workload generation

Both suites generate programs in the same way:

1. Measure how many rows each snippet adds to each trace, once per run.
2. Read the selected scenarios' row counts from the snapshot.
3. Choose how many times to repeat each snippet. The solver adjusts the counts over several
   passes, accounting for rows added to other traces and keeping the counts non-negative.
4. Generate a MASM program using `repeat.N ... end` blocks.
5. Execute the program and check its trace against the snapshot before measuring performance.

Keeping the snapshot fixed lets us compare VM versions against the same trace sizes. Execution
timings apply only to the generated programs.

The generated program must match the snapshot's padded height for each AIR:

| AIR | Snapshot field | Padded height |
| --- | --- | --- |
| Core | `core_rows` | `max(64, next_pow2(core_rows))` |
| Chiplets | `chiplets_rows` | `max(64, next_pow2(chiplets_rows))` |
| Eidos compression | `eidos_compression_rows` | `max(64, next_pow2(eidos_compression_rows))` |
| And8 lookup | `byte_pair_lookup_rows` | 65,536 |

The benchmark checks each program before timing it or generating its MVM proofs. Any mismatch
in padded height stops the benchmark. Checking only the largest trace could miss differences
in smaller AIRs.

Row counts before padding may differ. Differences above 2% are flagged in the report, but do
not fail the benchmark if the padded heights match.

| Snippet | Body | Main contribution |
| --- | --- | --- |
| `eidos_compression` | `compress` | Eidos compression rows |
| `bitwise` | `u32split u32xor` | Total chiplet rows |
| `memory` | `dup.4 mem_storew_le dup.4 mem_loadw_le movup.4 push.262148 add movdn.4` | Memory rows |
| `decoder_pad` | `swap dup.1 add` | Core rows |

Individual chiplet counts can differ from the snapshot. The memory snippet targets the sum of
the snapshot's memory, ACE, and kernel-ROM rows, using a different word-aligned address each
iteration. Bitwise operations fill the remaining chiplet rows.

The And8 table always has 65,536 rows; compression activity changes its lookup multiplicities.
MAST hashing adds compression rows even to programs containing only core operations, so some
small compression targets cannot be matched. See [`src/snippets.rs`](src/snippets.rs).

## Snapshot schema

A snapshot maps scenario names to objects containing `provenance: "producer_measured"` and
`trace`. All four AIR totals and all five `chiplets_shape` fields are required. Other scenario
fields, such as transaction-stage cycle counts, are ignored.

The loader rejects missing or unknown trace fields. Eidos compression counts must be multiples
of 32, and the And8 height must be 65,536. Counts must fit without overflow when added or padded.
The chiplet counts must satisfy
`chiplets_rows == hasher_rows + bitwise_rows + memory_rows + kernel_rom_rows + ace_rows + 1`.

For example, the measured Falcon workload for consuming one P2ID note has:

```json
{
  "consume single P2ID note with Falcon signing": {
    "provenance": "producer_measured",
    "trace": {
      "core_rows": 43619,
      "chiplets_rows": 5559,
      "eidos_compression_rows": 84320,
      "byte_pair_lookup_rows": 65536,
      "chiplets_shape": {
        "hasher_rows": 3504,
        "bitwise_rows": 84,
        "memory_rows": 1969,
        "kernel_rom_rows": 1,
        "ace_rows": 0
      }
    }
  }
}
```

The checked-in snapshot contains the full producer output. The
[capture metadata](snapshots/provenance/bench-tx.json) records the protocol and VM revisions and
the snapshot hash.

To reproduce the capture, run the following from the VM checkout root:

```sh
VM_CHECKOUT="$PWD"
CAPTURE_WORKDIR=$(mktemp -d)
git clone https://github.com/0xMiden/protocol.git "$CAPTURE_WORKDIR/protocol"
cd "$CAPTURE_WORKDIR/protocol"
git fetch origin e9852edb7a77c4b350873ee2453ade850dbb6513
git checkout --detach FETCH_HEAD
cargo run --locked --profile test-dev -p bench-transaction --features concurrent

cp bin/bench-transaction/bench-tx.json \
  "$VM_CHECKOUT/benches/synthetic-bench/snapshots/bench-tx.json"
```

For a new capture, select the protocol revision to measure and use its checked-in lockfile.
Update the capture metadata and expected default AIR heights in `src/snapshot.rs` from the new
data. All six P2ID workloads must pass the trace checks before recording timings.

## License

This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
