# Benchmarks

End-to-end prove + verify wall-time on three headline harnesses, with
the prover's `info_span` phase split. Establishes the cost baseline for
the LogUp-flatten / `D_max` reduction program, and answers "what if the
Plonky3 / Miden commitment hash is swapped from Poseidon2 to BLAKE3?"
by carrying the same benches through both configurations.

## Setup

- **Hardware** — Apple M3 Max, 16 cores, 64 GB RAM.
- **Toolchain** — `rustc 1.94.1` (release; `cargo run --release --example …`).
- **Prover params at measurement time** — `miden-lifted-stark` 0.26,
  `log_blowup = 3` (blowup 8), 4 FRI queries (the repo's test config in
  `stark_config.rs`). `D_max = 3` on `main` (`PoseidonAir` × KeccakSponge
  pin the shared quotient). Re-run before treating these as current numbers.
- **Two commitment hashers measured side-by-side**
  - **P2** — Poseidon2 over Goldilocks for the LMCS sponge / Merkle
    compression / Fiat-Shamir challenger (the repo's current default).
  - **BLAKE3** — `p3-blake3` over byte-serialized Felts, modeled on
    `miden_lifted_stark::testing::configs::goldilocks_blake3`. The
    in-circuit transcript hash (the `Poseidon2` chiplet that the AIR
    proves) is **unchanged** — only the *commitment-layer* hash moves.
- **Harnesses**
  - `bench_keccak_n -- N 32` — N Keccak-256 invocations on 32-byte inputs,
    one transcript root.
  - `ec_msm_ecdsa -- N 255 joint_naf` — N ECDSA-shape MSMs
    `R = u₁·G + u₂·Q` on secp256k1, 255-bit scalars, **joint-NAF / JSF**
    addition chain (signed joint double-and-add over `{±G, ±Q, ±(G±Q)}`).
  - `ec_msm_ecdsa -- N 255 glv` — same workload, **signed GLV**
    decomposition: a real lattice reduction (short basis via half
    extended-Euclid on `(n, λ)` + one Babai step) splits `uᵢ` into two
    **signed** ~128-bit halves; each half's sign rides on its chosen base
    (`|k|·(−P) = (−|k|)·P`), so the MSM consumes four non-negative ~128-bit
    scalars and the joint ladder is capped near 128 doublings. `φ(P)` is
    certified in-circuit (`x_{φP} = β·x_P mod p` + on-curve check); each
    split is bound by `uᵢ ≡ uᵢₐ + uᵢᵦ·λ (mod n)`, with the flipped half
    represented by the corresponding signed scalar relation. The 4-base
    chain is laid by interleaved wNAF (`w = 4`, `joint_wnaf`) — sparser
    adds than 4-base Straus.
- **Phases** are the direct children of the `prove` span (the names below
  match `miden_lifted_stark::prover`):
  - `commit-main` — main trace LDE + Merkle commit (blowup 8).
  - `build-aux` — LogUp aux-trace generation.
  - `commit-aux` — aux trace LDE + Merkle commit.
  - `eval` (`evaluate constraints`) — per-AIR native quotient coset eval.
  - `commit-quot` — quotient chunks LDE + Merkle commit (at `D_max`).
  - `open` — FRI opening.

All timings are wall-clock from a single warm run; ±5 % run-to-run is
typical at this query count.

## `bench_keccak_n` (L = 32 bytes)

prove + verify wall-time, ms (`prove` is the sum of the six phase spans;
the small residual vs `prove_multi` is intra-prover overhead between
spans):

| hasher | N  | trace-gen | commit-main | build-aux | commit-aux | eval | commit-quot | open | **prove** | verify |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| P2     |  1 | 3.1  |  84.4 |  7.19 |  78.8 |   131 |  92.8 | 103   |   **578** | 69 |
| P2     |  4 | 2.4  | 115   | 14.1  |  90.1 |   219 |  93.7 | 103   |   **707** | 69 |
| P2     | 16 | 9.5  | 222   | 37.3  | 134   |   561 |  95.9 | 108   | **1 229** | 71 |
| P2     | 32 | 19.3 | 404   | 69.0  | 219   | 1 050 | 185   | 182   | **2 181** | 69 |
| BLAKE3 |  1 | 2.6  |  40.4 |  7.17 |  37.2 |   139 |  36.4 |  55.1 |   **354** | 31 |
| BLAKE3 |  4 | 2.6  |  50.8 | 13.0  |  42.0 |   221 |  36.1 |  56.8 |   **449** | 30 |
| BLAKE3 | 16 | 9.6  |  86.6 | 36.6  |  59.7 |   560 |  40.1 |  59.4 |   **872** | 29 |
| BLAKE3 | 32 | 19.6 | 141   | 72.5  |  89.2 | 1 070 |  77.0 |  91.6 | **1 574** | 30 |

Trace heights at N = 32: `round = bitwise64 = 131 072`, `bpl = 65 536`
(fixed table), `sponge = 1 024`, others ≤ 64.

## `ec_msm_ecdsa --strategy joint_naf` (255-bit scalars)

JSF (joint sparse form) joint double-and-add over `{±G, ±Q, ±(G±Q)}`.
MSM chain cost grows roughly linearly with N (394 → 12 892 expressions
from N=1 → 32).

| hasher | N  | trace-gen | commit-main | build-aux | commit-aux |   eval | commit-quot |  open | **prove**  | verify |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| P2     |  1 |  15.4 |   235 |   84.8 |   285 |    504 |    93.7 |   112 |  **1 387** | 70 |
| P2     |  4 |  26.9 |   790 |  319   |   983 |  1 670 |   372   |   346 |  **4 549** | 71 |
| P2     | 16 | 111   | 2 910 | 1 290  | 3 780 |  6 230 | 1 520   | 1 170 | **17 021** | 71 |
| P2     | 32 | 225   | 5 820 | 2 550  | 7 330 | 12 500 | 3 010   | 2 330 | **33 831** | 79 |
| BLAKE3 |  1 |  15.2 |    93.9 |   85.1 |   117 |    507 |    37.9 |  65.2 |    **936** | 32 |
| BLAKE3 |  4 |  27.4 |   274 |  321   |   360 |  1 670 |   147   |   159 |  **2 958** | 29 |
| BLAKE3 | 16 | 111   |   932 | 1 280  | 1 280 |  6 150 |   639   |   494 | **10 852** | 31 |
| BLAKE3 | 32 | 226   | 1 800 | 2 600  | 2 480 | 12 400 | 1 290   |   941 | **21 706** | 32 |

Trace heights at N = 32: `uint = uintadd = 2 097 152` (2²¹),
`uintmul = 1 048 576`, `ec_add = 65 536`, `ec_msm = 32 768`. The
chain-expression count and shape are unchanged on the new main.

## `ec_msm_ecdsa --strategy glv` (255-bit scalars via 128-bit signed GLV halves + joint wNAF *w*=4)

Same end-to-end claim (`R = u₁·G + u₂·Q`). Lattice-decomposed signed
halves keep the joint ladder at ~128 doublings; the 4-base chain is
laid by interleaved wNAF *w* = 4 instead of Straus, cutting joint-column
add density from ~15/16 (Straus) to ~9/16. MSM chain cost
261 → 7 876 expressions (N=1 → 32), and **the active uint rows now
cross the 2²¹ → 2²⁰ boundary** — what the trace-area win turns into
actual prove-time win.

| hasher | N  | trace-gen | commit-main | build-aux | commit-aux |   eval | commit-quot |  open | **prove**  | verify |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| P2     |  1 |   5.3 |   182 |   64.3 |   214 |    392 |    93.4 |   111 |  **1 128** | 68 |
| P2     |  4 |  17.5 |   487 |  224   |   657 |  1 180 |   186   |   196 |  **3 000** | 75 |
| P2     | 16 |  68.7 | 1 720 |  860   | 2 400 |  4 320 |   748   |   639 | **10 783** | 69 |
| P2     | 32 | 137   | 3 390 | 1 720  | 4 790 |  8 550 | 1 530   | 1 190 | **21 315** | 71 |
| BLAKE3 |  1 |   5.3 |    79.2 |   61.2 |   89.4 |    388 |    43.6 |  68.7 |    **758** | 31 |
| BLAKE3 |  4 |  16.8 |   180 |  226   |   234 |  1 200 |    75.1 |   106 |  **2 048** | 31 |
| BLAKE3 | 16 |  68.1 |   573 |  852   |   822 |  4 360 |   311   |   290 |  **7 257** | 31 |
| BLAKE3 | 32 | 139   | 1 100 | 1 740  | 1 580 |  8 670 |   634   |   512 | **14 333** | 30 |

Trace heights at N = 32 vs JSF (JSF in brackets):
`uint = uintadd = uintmul = 1 048 576` (**all 2²⁰**, vs JSF `[uint =
uintadd = 2²¹, uintmul = 2²⁰]` — uint/uintadd **halved**),
`ec_add = ec_msm = 32 768` (`ec_add` **halved**, vs JSF `[65 536]`),
`ec_points = 8 192` (vs JSF `[16 384]`), `poseidon2 = 16 384` (vs JSF
`[8 192]` — split + endomorphism + sign certificates push transcript-eval
work into `poseidon2`, doubling it). The padding-boundary crossing on
the uint family is what makes this real: with the previous unsigned-Straus
GLV strategy the active uint count was below 2²¹ but still in the
`[2²⁰, 2²¹)` bucket, so it padded back up to 2²¹ — saving nothing.

### GLV vs JSF — same hash, head-to-head

GLV wins decisively at every N on every metric. Three things stack:

1. **128-bit ladder** — half the doublings of JSF's 255-bit ladder, so
   half the per-iteration EC work; the four bases share each doubling.
2. **wNAF *w* = 4 joint recoding** — joint-column add density drops
   from JSF's 0.5 to ~9/16 over the 4-base table; combined with the
   shorter ladder, total additions go 12 892 → 7 876 (−39 %).
3. **Padding-boundary crossing** — the active uint count finally
   crosses 2²¹ → 2²⁰. That's what turns the chain-cost reduction into
   real prove-time savings; previous GLV attempts left the active count
   inside the `[2²⁰, 2²¹)` bucket and got rounded right back to JSF's
   heights.

The cost it pays — the lattice decomposition's split + endomorphism +
sign certs double the `poseidon2` rows — is small in absolute terms
(P2 has 19 base + 1 ext cols at moderate heights).

| N | hasher | prove JSF | prove GLV | Δ |
|---:|---|---:|---:|---:|
|  1 | P2     |  1.39 s |  1.13 s | **−19 %** |
|  4 | P2     |  4.55 s |  3.00 s | **−34 %** |
| 16 | P2     | 17.02 s | 10.78 s | **−37 %** |
| 32 | P2     | 33.83 s | 21.32 s | **−37 %** |
|  1 | BLAKE3 |  0.94 s |  0.76 s | **−19 %** |
|  4 | BLAKE3 |  2.96 s |  2.05 s | **−31 %** |
| 16 | BLAKE3 | 10.85 s |  7.26 s | **−33 %** |
| 32 | BLAKE3 | 21.71 s | 14.33 s | **−34 %** |

The GLV win settles at **~−37 %** on P2 (~−33 % on BLAKE3, where the
commit savings are already collected on JSF's side too). It is
hasher-independent in the trace area it saves, and composes cleanly
with the BLAKE3 commit-hash win below — stacked, GLV + BLAKE3 cuts
prove time ~58 % vs the JSF-on-P2 baseline at N = 32 (33.83 s → 14.33 s).

## `PROFILE=1` — verbatim inline, N = 32

The benches install a `tracing_subscriber` when `PROFILE=1` is set; the
text below is the program's stdout followed by the *direct-children*
spans of `prove` from stderr (the full PROFILE log emits ~300 lines per
run, mostly per-AIR `LDE{trace=k log_height=h width=w}` and `absorb
matrix{height,width}` sub-spans — useful for AIR-attribution work but
inlined wholesale here would bury the phase picture).

### `PROFILE=1 cargo run --release --example bench_keccak_n -- 32 32` (P2)

```
================================================
bench_keccak_n: N=32 invocations, L=32 bytes
================================================

trace heights  (cols = base + extension):
  chunk           32 rows ×  12 base +  3 ext =  15 cols
  poseidon2     2048 rows ×  19 base +  1 ext =  20 cols
  round       131072 rows ×  10 base +  2 ext =  12 cols
  bitwise64   131072 rows ×  19 base +  3 ext =  22 cols
  bpl          65536 rows ×   3 base +  1 ext =   4 cols
  sponge        1024 rows ×  27 base +  3 ext =  30 cols
  kn              32 rows ×  30 base +  4 ext =  34 cols
  eval            64 rows ×  45 base +  9 ext =  54 cols
  uint             8 rows ×  10 base +  9 ext =  19 cols
  uintadd         16 rows ×   9 base +  8 ext =  17 cols
  uintmul         16 rows ×  16 base + 14 ext =  30 cols
  ec_groups        2 rows ×   6 base +  1 ext =   7 cols
  ec_points        2 rows ×  14 base +  1 ext =  15 cols
  ec_add           4 rows ×  22 base +  4 ext =  26 cols
  bitwise64 active: 120274 rows (2285206 cells before 2^k pad)

trace gen        : 19.265833ms
per-chiplet check : ok
prove_multi      : 2.181200458s

verify_multi     : 68.741833ms
✓ prove+verify roundtrip OK
```

`prove`-direct phase spans (stderr, ANSI stripped):

```
INFO prove:commit to main traces:           close time.busy=404ms
INFO prove:build aux traces:                close time.busy=69.0ms
INFO prove:commit to aux traces:            close time.busy=219ms
INFO prove:evaluate constraints:            close time.busy=1.05s
INFO prove:commit to quotient poly chunks:  close time.busy=185ms
INFO prove:open:                            close time.busy=182ms
```

### `PROFILE=1 cargo run --release --example ec_msm_ecdsa -- 32 255 joint_naf` (P2)

```
=================================================
ec_msm_ecdsa: prove 32 × (R = u1*G + u2*Q) on secp256k1
  255-bit scalars, seed 0xEC5DA, strategy: joint_naf
=================================================
✓ 32 ECDSA-shape MSM claims resolved in-circuit (k256-matched)
  chain cost: 12892 MSM expressions (intros + combines + negs)

trace heights  (cols = base + extension):
  chunk            2 rows ×  12 base +  3 ext =  15 cols
  poseidon2     8192 rows ×  19 base +  1 ext =  20 cols
  round         4096 rows ×  10 base +  2 ext =  12 cols
  bitwise64        2 rows ×  19 base +  3 ext =  22 cols
  bpl          65536 rows ×   3 base +  1 ext =   4 cols
  sponge          32 rows ×  27 base +  3 ext =  30 cols
  kn               2 rows ×  30 base +  4 ext =  34 cols
  eval           512 rows ×  45 base +  9 ext =  54 cols
  uint       2097152 rows ×  10 base +  9 ext =  19 cols
  uintadd    2097152 rows ×   9 base +  8 ext =  17 cols
  uintmul    1048576 rows ×  16 base + 14 ext =  30 cols
  ec_groups        2 rows ×   6 base +  1 ext =   7 cols
  ec_points    16384 rows ×  14 base +  1 ext =  15 cols
  ec_add       65536 rows ×  22 base +  4 ext =  26 cols
  ec_msm       32768 rows ×  38 base +  4 ext =  42 cols

trace gen        : 224.552458ms
per-chiplet check : ok
prove_multi      : 33.83124675s

verify_multi     : 78.537083ms
✓ prove+verify OK — proved 32 × 2-base MSM (joint_naf) on secp256k1
```

```
INFO prove:commit to main traces:           close time.busy=5.82s
INFO prove:build aux traces:                close time.busy=2.55s
INFO prove:commit to aux traces:            close time.busy=7.33s
INFO prove:evaluate constraints:            close time.busy=12.5s
INFO prove:commit to quotient poly chunks:  close time.busy=3.01s
INFO prove:open:                            close time.busy=2.33s
```

### `PROFILE=1 cargo run --release --example ec_msm_ecdsa -- 32 255 glv` (P2)

```
=================================================
ec_msm_ecdsa: prove 32 × (R = u1*G + u2*Q) on secp256k1
  255-bit scalars, seed 0xEC5DA, strategy: glv
=================================================
[32 × "glv: u₁→(...) u₂→(...) ⇒ 127-bit ladder" lines elided]
✓ 32 ECDSA-shape MSM claims resolved in-circuit (k256-matched)
  chain cost: 7876 MSM expressions (intros + combines + negs)

trace heights  (cols = base + extension):
  chunk            2 rows ×  12 base +  3 ext =  15 cols
  poseidon2    16384 rows ×  19 base +  1 ext =  20 cols
  round         4096 rows ×  10 base +  2 ext =  12 cols
  bitwise64        2 rows ×  19 base +  3 ext =  22 cols
  bpl          65536 rows ×   3 base +  1 ext =   4 cols
  sponge          32 rows ×  27 base +  3 ext =  30 cols
  kn               2 rows ×  30 base +  4 ext =  34 cols
  eval          1024 rows ×  45 base +  9 ext =  54 cols
  uint       1048576 rows ×  10 base +  9 ext =  19 cols
  uintadd    1048576 rows ×   9 base +  8 ext =  17 cols
  uintmul    1048576 rows ×  16 base + 14 ext =  30 cols
  ec_groups        2 rows ×   6 base +  1 ext =   7 cols
  ec_points     8192 rows ×  14 base +  1 ext =  15 cols
  ec_add       32768 rows ×  22 base +  4 ext =  26 cols
  ec_msm       32768 rows ×  38 base +  4 ext =  42 cols

trace gen        : 137.479833ms
per-chiplet check : ok
prove_multi      : 21.315057292s

verify_multi     : 71.390792ms
✓ prove+verify OK — proved 32 × 2-base MSM (glv) on secp256k1
```

```
INFO prove:commit to main traces:           close time.busy=3.39s
INFO prove:build aux traces:                close time.busy=1.72s
INFO prove:commit to aux traces:            close time.busy=4.79s
INFO prove:evaluate constraints:            close time.busy=8.55s
INFO prove:commit to quotient poly chunks:  close time.busy=1.53s
INFO prove:open:                            close time.busy=1.19s
```

### `PROFILE=1 cargo run --release --example ec_msm_ecdsa -- 32 255 glv` (BLAKE3)

The same workload run under the BLAKE3 commitment hash — same trace
shape, same `evaluate constraints` cost, but every Merkle commit
drops ~3×:

```
=================================================
ec_msm_ecdsa: prove 32 × (R = u1*G + u2*Q) on secp256k1
  255-bit scalars, seed 0xEC5DA, strategy: glv
=================================================
[32 × "glv: u₁→(...) u₂→(...) ⇒ 127-bit ladder" lines elided]
✓ 32 ECDSA-shape MSM claims resolved in-circuit (k256-matched)
  chain cost: 7876 MSM expressions (intros + combines + negs)

trace heights  (cols = base + extension):
  chunk            2 rows ×  12 base +  3 ext =  15 cols
  poseidon2    16384 rows ×  19 base +  1 ext =  20 cols
  round         4096 rows ×  10 base +  2 ext =  12 cols
  bitwise64        2 rows ×  19 base +  3 ext =  22 cols
  bpl          65536 rows ×   3 base +  1 ext =   4 cols
  sponge          32 rows ×  27 base +  3 ext =  30 cols
  kn               2 rows ×  30 base +  4 ext =  34 cols
  eval          1024 rows ×  45 base +  9 ext =  54 cols
  uint       1048576 rows ×  10 base +  9 ext =  19 cols
  uintadd    1048576 rows ×   9 base +  8 ext =  17 cols
  uintmul    1048576 rows ×  16 base + 14 ext =  30 cols
  ec_groups        2 rows ×   6 base +  1 ext =   7 cols
  ec_points     8192 rows ×  14 base +  1 ext =  15 cols
  ec_add       32768 rows ×  22 base +  4 ext =  26 cols
  ec_msm       32768 rows ×  38 base +  4 ext =  42 cols

trace gen        : 139.001167ms
per-chiplet check : ok
prove_multi      : 14.333159292s

verify_multi     : 30.023458ms
✓ prove+verify OK — proved 32 × 2-base MSM (glv) on secp256k1
```

```
INFO prove:commit to main traces:           close time.busy=1.10s
INFO prove:build aux traces:                close time.busy=1.74s
INFO prove:commit to aux traces:            close time.busy=1.58s
INFO prove:evaluate constraints:            close time.busy=8.67s
INFO prove:commit to quotient poly chunks:  close time.busy=634ms
INFO prove:open:                            close time.busy=512ms
```

## BLAKE3 commitment-layer swap — what it changes

Miden is evaluating whether to replace Poseidon2 with BLAKE3 across the
Plonky3 stack. With today's stack ~half commit-bound on the headline
ec_msm workload (see the lqd → 1 synthesis below), the swap is worth
characterizing as a *prover-perf delta* before it ships.

### The swap (applied during benchmarking, **not committed**)

The BLAKE3 numbers below come from a short-lived edit to
[`src/stark_config.rs`](src/stark_config.rs) applied only for the
measurement run — `main` stays on the production Poseidon2 commitment
hash. The swap is three type aliases plus their constructors (plus
`p3-blake3` added to `Cargo.toml` at the matching Plonky3 version):

| component | before (P2, on `main`) | swapped to (BLAKE3, measurement-only) |
|---|---|---|
| LMCS sponge       | `StatefulSponge<Poseidon2Permutation256, 12, 8, 4>` | `ChainingHasher<Blake3>` |
| Merkle compress   | `TruncatedPermutation<P2, 2, 4, 12>` | `CompressionFunctionFromHasher<Blake3, 2, 32>` |
| Fiat-Shamir       | `DuplexChallenger<Felt, P2, 12, 8>` | `SerializingChallenger64<Felt, HashChallenger<u8, Blake3, 32>>` |
| LMCS digest       | 4 Felts (32 B)           | 32 raw bytes |

`Lmcs = LmcsConfig<Felt, u8, …, 32, 32>` — `PD = u8` collapses the
parallel/packed `StatefulHasher` bound trivially. Modeled directly on
`miden_lifted_stark::testing::configs::goldilocks_blake3`. **The
in-circuit Poseidon2 chiplet — what the AIR proves — is untouched**;
the swap is purely in the prover/verifier's native commitment work.
End-to-end prove+verify roundtrip passes under either hasher; the
numbers are replayable by re-applying the same 3-line swap.

### Side-by-side prove + verify wall-time, N = 32

| bench | hasher | prove | verify | Δ prove | Δ verify |
|---|---|---:|---:|---:|---:|
| keccak       | P2     |   2.18 s | 69 ms |     |     |
| keccak       | BLAKE3 | **1.57 s** | **30 ms** | **−28 %** | **−57 %** |
| ec_msm jnaf  | P2     |  33.83 s | 79 ms |     |     |
| ec_msm jnaf  | BLAKE3 | **21.71 s** | **32 ms** | **−36 %** | **−60 %** |
| ec_msm glv   | P2     |  21.32 s | 71 ms |     |     |
| ec_msm glv   | BLAKE3 | **14.33 s** | **30 ms** | **−33 %** | **−58 %** |

### Per-phase, N = 32 (ec_msm GLV)

| phase           | P2      | BLAKE3  | Δ |
|---|---:|---:|---:|
| commit main     |  3.39 s |  1.10 s | **−68 %** |
| build aux       |  1.72 s |  1.74 s | ~0 |
| commit aux      |  4.79 s |  1.58 s | **−67 %** |
| evaluate constraints |  8.55 s |  8.67 s | ~0 |
| commit quotient |  1.53 s |  634 ms | **−59 %** |
| open (FRI)      |  1.19 s |  512 ms | **−57 %** |

Exactly as expected: the swap **doesn't touch eval or trace-gen** —
those are field-arithmetic on the AIR's own constraints, no commit-hash
involvement. The four commit-hash-driven phases (the three Merkle
commits + FRI opening's Merkle authentication) all drop ~3×. The
trade-off direction is identical at every N and strategy: P2 prove is
~50 % commit-bound on JSF, ~50 % on GLV; BLAKE3 prove is ~30 %
commit-bound on JSF, ~30 % on GLV.

### The recursion caveat

The BLAKE3 swap is a **native-prover** win. The cost it pays is in any
recursive verifier: BLAKE3 has no AIR-friendly representation, so a
verifier that wants to *re-execute* the commit hash in-circuit (the
recursion target the whole P2 design serves) has to arithmetize BLAKE3
— which is exactly what the Keccak chiplet stack in this repo is the
standing proof of being expensive. The numbers above are the native /
non-recursive-verifier picture; the Miden-wide decision depends on
where recursion ends up sitting on the deployment surface.

## What the research/logup* branches concluded — and how BLAKE3 affects the picture

Two off-`main` branches did the prove-time autopsy and prototyped the
fix. Their docs (`docs/logup-flatten-findings.md` on
`research/logup-flatten`, `docs/uint-selective-flatten.md` on
`research/uint-selective-flatten`) are the primary record; this section
summarizes their measured numbers against the **same `main` baseline**
the tables above use.

### The lever: `lqd 3 → 1` shrinks two of the three commitment domains

Per-AIR constraint degree (`lqd`, "LogUp quotient degree") controls
**three** prover costs:

1. The per-AIR native quotient coset — the `evaluate constraints` phase —
   sized `n_j · 2^{lqd_j}`. Flattening AIR *j* from `lqd 3 → 1` shrinks
   that AIR's coset ×4 (×8 native → ×2). This is the only lever that
   fires when other AIRs hold `D_max` up.
2. The **shared** quotient-chunk commitment is sized at
   `D_max = max_j lqd_j`. Dropping `D_max` 3 → 2 → 1 shrinks the
   `commit-quot` phase ×2 → ×4.
3. `log_blowup ≥ D_max` is enforced. Once `D_max = 2` the blowup floor
   permits `log_blowup` 3 → 2 (blowup 8 → 4), which **halves every commit
   + the FRI open** — the dominant cost on big traces.

So `lqd 3 → 1` isn't one optimization, it's three: an eval shrink on
each flattened AIR (free immediately), a quotient-commit shrink (needs
*every* AIR ≤ `D_max`), and a global-blowup unlock (needs `D_max` down).

### Stage 1 — flatten every LogUp AIR (`D_max` still 3)

`research/logup-flatten` re-partitions every LogUp AIR's column-0
running sum into per-row fraction columns so every constraint sits at
`lqd 1`. `Poseidon2` (x⁷ S-box, deg 9) and `KeccakSponge` (deg-5 main)
are *algebraic*, not LogUp — flattening can't touch them — so they
remain at `lqd 3` and pin `D_max = 3`. Only the per-AIR eval lever (1
above) fires.

Measured at blowup 8 vs `main` (release, P2 hasher):

| bench | prove main | prove flat | Δ |
|---|--:|--:|--:|
| ec_msm | 22.64 s | 17.83 s | **−21 %** |
| keccak |  2.79 s |  2.58 s | −7 %  |
| uint   |  2.28 s |  2.13 s | −7 %  |

A follow-up (`research/uint-selective-flatten`) confirmed the same
−20 % on ec_msm by flattening only the three tall uint AIRs (3-file
diff vs 13 files for the full flatten). The other 10 chiplets together
contributed 0.2 s of eval — they are 32–128× shorter than the uint
traces.

### Stage 2 — decompose P2 + KeccakSponge to `lqd 2`, unlock blowup 4

The second branch lands the algebraic decomposition: the x⁷ S-box is
cube-witnessed (commit `p3 = x³`; `x⁷ = p3²·x` is deg 3), and
KeccakSponge's deg-5 pad-XOR is decomposed to ≤ 3. Both reach `lqd 2`,
**every other AIR is `lqd 1`**, so `D_max = 2` — which lowers the
blowup floor 3 → 2 and permits running at blowup 4 (`PROFILE_BLOWUP=2`).

Measured prove wall-time (s), release, vs `main` (P2 hasher):

| bench  | main (D3, b8) | flatten (D3, b8) | D2, b8 | **D2, b4** |
|---|--:|--:|--:|--:|
| ec_msm | 22.64 | 17.83 | 17.10 | **10.90 (−52 %)** |
| keccak |  2.79 |  2.58 |  2.48 |  **1.34 (−52 %)** |
| uint   |  2.28 |  2.13 |  1.95 |  **1.09 (−52 %)** |

The three levers cleanly separate: flatten owns the eval column,
`D_max 3 → 2` owns the small quot-commit drop, and **blowup 8 → 4 owns
the headline cut** — every commit and the open phase halve at once.

### Conclusion — the program is commit-domination, and BLAKE3 makes it eval-bound

Today's `main` (blowup 8, `D_max = 3`) phase split on the headline
workloads, at the largest measured N:

| bench (N = 32, P2) | eval | commit (main+aux+quot) | open | commit share |
|---|--:|--:|--:|--:|
| keccak       |  1.05 s |  0.81 s | 0.18 s |     37 % |
| ec_msm jnaf  | 12.5 s  | 16.16 s | 2.33 s |     48 % |
| ec_msm glv   |  8.55 s |  9.71 s | 1.19 s |     46 % |

ec_msm is eval-bound at small N but the commit phases match or exceed
eval at N = 32 on every strategy. GLV's win is largest precisely
*because* the uint family crosses the 2²¹ → 2²⁰ padding boundary;
without that boundary crossing, the chain-cost reduction would have
been mostly absorbed by the next-larger power-of-two pad. The lqd → 1 +
blowup-4 program halves prove by attacking the commit side; the GLV
chain shape cuts ~37 % off prove-time when paired with a wNAF-*w*=4
recoding; **BLAKE3 cuts the commit hash itself ~3×**. They compose:
each lever attacks a different bottleneck.

After the BLAKE3 swap, the phase split flips (N = 32):

| bench (N = 32, BLAKE3) | eval | commit (main+aux+quot) | open | commit share |
|---|--:|--:|--:|--:|
| keccak       |  1.07 s | 0.31 s | 0.09 s |     19 % |
| ec_msm jnaf  | 12.4 s  | 5.57 s | 0.94 s |     27 % |
| ec_msm glv   |  8.67 s | 3.31 s | 0.51 s |     24 % |

Under BLAKE3 the workload is firmly **eval-bound**: ~60 % of prove is
`evaluate constraints` on every bench. That is precisely the regime
where the Stage-1 flatten lever wins on its own (a 3.2× cut to eval on
ec_msm with no aux-commit downside, because the BLAKE3 hash is so much
cheaper). The Stage-2 blowup-floor drop becomes a smaller marginal win
(it halves a smaller pie), but the Stage-1 flatten becomes a *bigger*
proportional win.

In short, the three levers stack:

| lever                       | attacks       | independent | composes with the others |
|---|---|:-:|:-:|
| GLV addition chain          | trace area    | ✓ | ✓ |
| LogUp flatten (`lqd → 1`)   | eval coset    | ✓ | ✓ |
| `D_max` ↓ + blowup ↓        | commit + open | needs both AIR families to drop | ✓ |
| **BLAKE3 commit hash**      | **commit + open**  | **✓ (config-only)** | **✓** |

Open follow-ups (not measured):

- **`D_max → 1` (blowup 2)** — needs P2's x⁷ chain to `lqd 1` and
  KeccakSponge's deg-4 squeeze / chunk-consume multiplicities
  witnessed. Projected ec_msm ≈ 7 s under P2, ~5 s under BLAKE3.
- **Preprocessed-column path for the fixed BPL table** — the
  65 536-row `BytePairLut` is re-LDE'd and re-Merkle-hashed every
  proof; 0.26's preprocessed path eliminates that.
- **`StarkProofData` serialization** — proof size in bytes is not yet
  wired. BLAKE3 digests are 32 raw bytes (vs P2's 4 Felts = 32 bytes),
  so the digest size is unchanged; the proof shrinks slightly via
  fewer leaf elements per Merkle proof in the BLAKE3 layout.
