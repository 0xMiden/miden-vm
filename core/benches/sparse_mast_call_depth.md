# Sparse extraction by call depth

This benchmark measures `SparseMastForest::from_procedure_roots` at exact call
depths, counting the initial frame. It starts from
[PR #4107's tip](https://github.com/0xMiden/miden-vm/commit/8e9bcba44682d8607992d321ae9d89972cad19db).
The benchmark and results live on a separate branch.

With four roots and 1,024 copied nodes, extraction stayed near 32 µs across
all depths in both runs. With growing chains, going from eight to 32 frames
copied four times as many nodes and took 1.33 to 1.46 times as long.

The second run gave these times for four roots. Factors are relative to eight
frames within each shape.

| Shape | 8 frames | 16 frames | Factor | 32 frames | Factor |
| --- | ---: | ---: | ---: | ---: | ---: |
| Growing chains, 32 / 64 / 128 nodes | 4.97 µs | 5.67 µs | 1.14× | 7.25 µs | 1.46× |
| Fixed 1,024 nodes | 32.39 µs | 31.94 µs | 0.99× | 31.98 µs | 0.99× |

The two runs used the same binary on October 29, 2026. Some growing-chain
times fell between runs, so small differences should be treated as host noise.
The full results below include both runs and their confidence intervals.

Depth alone does not set the amount of work. A graph with more branches can
contain more nodes at the same depth. These measurements cover static calls
and joins, with either one or four selected roots.

<details>
<summary>Method and command</summary>

The existing `Arbitrary` strategy generates 4,096 basic blocks with a fixed
ChaCha seed of `[17; 32]`. Each case uses the same blocks and source exports.
Calls and joins are added outside the timed loop to set an exact frame depth.
Dynamic calls and external nodes are absent.

The growing chains copy one block and `frames - 1` calls per selected root.
The fixed cases copy one block, 31 calls, and 224 joins per selected root.
At shallower depths the calls form sibling chains joined into one root.
Extra joins reuse the same block, keeping node kinds and edge counts fixed.
Each fixture checks its call depth and the set of copied nodes before timing.

Timing includes source-root lookup, traversal, node copies, and dropping the
result. Fixture generation and checks are outside the timed loop. The source
keeps unrelated blocks and exports, so root lookup adds a fixed cost within
each group of depths.

The host was an Apple M4 Max with 16 logical CPUs and 128 GiB of RAM. Rust was
`1.99.0 (b940084d7 2026-09-28)`. The workspace's `optimized` profile enables LTO
and uses one codegen unit. Criterion takes 100 samples after a 3-second warmup
and measures each case for about 5 seconds.

Run from the repository root:

```sh
RUSTC_WRAPPER= make bench benchmark='sparse_mast_call_depth --features miden-core/arbitrary'
```

Times below are Criterion's regression slope estimates in microseconds.
Factors divide each time by the time at eight frames with the same number of
roots. They include the fixed root lookup cost.

</details>

<details>
<summary>Second run, including 95% confidence intervals</summary>

| Shape | Roots | Frames | Copied nodes | Time (µs) | 95% interval (µs) | Factor |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Chain | 1 | 8 | 8 | 1.225 | 1.222 to 1.229 | 1.00 |
| Chain | 1 | 16 | 16 | 1.406 | 1.403 to 1.410 | 1.15 |
| Chain | 1 | 32 | 32 | 1.766 | 1.761 to 1.772 | 1.44 |
| Chain | 4 | 8 | 32 | 4.965 | 4.950 to 4.985 | 1.00 |
| Chain | 4 | 16 | 64 | 5.671 | 5.659 to 5.683 | 1.14 |
| Chain | 4 | 32 | 128 | 7.251 | 7.229 to 7.277 | 1.46 |
| Fixed | 1 | 8 | 256 | 7.507 | 7.487 to 7.527 | 1.00 |
| Fixed | 1 | 16 | 256 | 7.534 | 7.512 to 7.560 | 1.00 |
| Fixed | 1 | 32 | 256 | 7.599 | 7.579 to 7.620 | 1.01 |
| Fixed | 4 | 8 | 1,024 | 32.389 | 32.283 to 32.500 | 1.00 |
| Fixed | 4 | 16 | 1,024 | 31.940 | 31.838 to 32.046 | 0.99 |
| Fixed | 4 | 32 | 1,024 | 31.981 | 31.898 to 32.071 | 0.99 |

</details>

<details>
<summary>First run, including 95% confidence intervals</summary>

| Shape | Roots | Frames | Copied nodes | Time (µs) | 95% interval (µs) | Factor |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Chain | 1 | 8 | 8 | 1.367 | 1.357 to 1.377 | 1.00 |
| Chain | 1 | 16 | 16 | 1.730 | 1.698 to 1.766 | 1.26 |
| Chain | 1 | 32 | 32 | 1.888 | 1.867 to 1.910 | 1.38 |
| Chain | 4 | 8 | 32 | 6.117 | 5.955 to 6.304 | 1.00 |
| Chain | 4 | 16 | 64 | 8.380 | 7.729 to 9.025 | 1.37 |
| Chain | 4 | 32 | 128 | 8.164 | 7.926 to 8.484 | 1.33 |
| Fixed | 1 | 8 | 256 | 7.627 | 7.574 to 7.693 | 1.00 |
| Fixed | 1 | 16 | 256 | 7.389 | 7.362 to 7.416 | 0.97 |
| Fixed | 1 | 32 | 256 | 7.822 | 7.695 to 7.972 | 1.03 |
| Fixed | 4 | 8 | 1,024 | 31.939 | 31.828 to 32.053 | 1.00 |
| Fixed | 4 | 16 | 1,024 | 32.061 | 31.737 to 32.562 | 1.00 |
| Fixed | 4 | 32 | 1,024 | 31.401 | 31.313 to 31.496 | 0.98 |

</details>
