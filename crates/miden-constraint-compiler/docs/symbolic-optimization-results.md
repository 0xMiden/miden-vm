# Symbolic AIR optimization experiments

Recorded 2026-11-15 against baseline commit `5d95337b0`.

The selected changes preserve source nesting, share native sum fragments, and optimize the ACE DAG after capture. Preparation is excluded from every evaluator timing.

## Method

- Apple M2 Pro, aarch64, Rust 1.99.0, release profile.
- CPU 2: efficiency core; CPU 8: performance core. Each timing run is pinned to one CPU; no build runs concurrently with a timing run.
- 11 samples of 16,384 evaluations per AIR and policy, with warmed, reused input/output allocations. All four VM and twelve PVM AIRs are included.
- Percentages below are geometric means of per-AIR median latency ratios against Current in the same binary. Negative means faster. AIRs receive equal weight, independent of production trace heights.
- Scalar and packed columns measure calls, respectively. Comparisons are within the same carrier. This is not an end-to-end proving benchmark.
- Every candidate checks source-versus-generated scalar and packed values at three seeds before timing.

The [CSV](symbolic-optimization-results.csv) records per-AIR medians, median absolute deviations, and sample counts. Small differences between identical generated functions reflect placement/context effects rather than an arithmetic improvement.

## Source folding

| Policy | Efficiency scalar / packed | Performance scalar / packed | VM raw ACE ops | PVM raw ACE ops |
|---|---:|---:|---:|---:|
| Current baseline | +0.00% / +0.00% | +0.00% / +0.00% | 6,831 | 13,287 |
| Strict nesting | -0.00% / -0.49% | +0.02% / -0.20% | 6,831 | 13,279 |
| Adjacent constants | -0.09% / -0.42% | -0.00% / -0.21% | 6,831 | 13,284 |
| Left-only construction | +10.50% / +8.33% | +10.90% / +9.71% | 6,891 | 13,260 |
| Full flattening | +13.42% / +12.59% | +13.49% / +14.83% | 7,250 | 13,428 |

Strict and adjacent policies produce byte-identical VM evaluation/preparation functions; 22 of 24 PVM functions are also identical. Their small timing differences do not establish a native-performance winner. Strict nesting retains more source information and produces fewer PVM constants and operations.

## Native scheduling

| Policy | Efficiency scalar / packed |
|---|---:|
| Strict nesting | -0.35% / -0.01% |
| Use-aware left folding | +0.75% / -0.57% |
| Uniform extension preparation | -0.27% / -0.02% |
| Uniform fragments only | +0.60% / -1.09% |
| Signed dots | -0.87% / -0.16% |
| Sum fragments, at least 2 uses | -7.59% / -7.28% |
| Fragments and signed dots | -7.69% / -7.38% |

Finalist comparison:

| Policy | Efficiency scalar / packed | Performance scalar / packed |
|---|---:|---:|
| Sum fragments, at least 2 uses | -7.55% / -7.66% | -6.36% / -6.28% |
| Selected combination | -7.88% / -7.14% | -6.33% / -6.26% |
| Contiguous common factors | +0.35% / -0.18% | +1.37% / +0.30% |
| Fragments, at least 3 uses | -5.41% / -5.58% | -4.77% / -4.45% |
| Fragments, at least 4 uses | -5.88% / -5.08% | -4.94% / -3.88% |

Combined and Fragments emit byte-identical native functions and prepared capacities. Combined additionally changes primitive lowering for ACE. Its timing differences from Fragments are not separate native arithmetic gains.

On the performance core, the two-use fragment policy reduces the sum of one-row median times by 2.86% scalar and 3.93% packed. The geometric means are larger because they weight small and large AIRs equally.

Not every AIR improves. EcGroupAdd scalar regresses about 5.6% on both core types, while its packed evaluator improves about 6.7% on the performance core. Chiplets packed is 1.6% slower on the performance core but faster on the efficiency core; Keccak packed is about 0.6% slower. The per-AIR CSV includes these regressions.

The three/four-use thresholds recover some scalar regressions but lose broader gains. Factoring additional contiguous runs and signed-dot recovery did not earn inclusion in the default policy.

## ACE ablations

The following rows use strict source nesting, except the original baseline. All counts are unpadded operations.

| Cumulative change | VM operations | PVM operations |
|---|---:|---:|
| Original baseline | 6,831 | 13,287 |
| Strict source nesting | 6,831 | 13,279 |
| Negation and signed cancellation | 6,826 | 13,274 |
| Signed associative reuse | 6,815 | 13,254 |
| Reuse candidates discovered later | 6,760 | 13,073 |
| Canonically ordered signed segments | 6,645 | 12,778 |
| Use-aware left folding for primitive lowering | 6,646 | 12,728 |

Preserving the existing ACE term order instead of sorting yields 6,695 / 12,830 operations for the last combination. Canonical ordering is confined to backend arithmetic; authored expression order is retained.

| Final circuit measure | VM before → after | PVM before → after |
|---|---:|---:|
| Raw operations | 6,831 → 6,646 | 13,287 → 12,728 |
| Distinct constants | 105 → 105 | 693 → 686 |
| Padded EVAL operations | 6,836 → 6,652 | 13,292 → 12,732 |
| Stream felts | 7,048 → 6,864 | 14,680 → 14,104 |

The final combination favors the smaller PVM stream; VM has one more raw operation than strict nesting without primitive left folding, with the same padded stream.

## Implementation

- Capture: ~~gather direct constants and merge constant tails~~ **retain term order and nested sums, remove zeros, and fold wholly constant sums**.
- Primitive lowering: flatten only eligible left sum chains after canonical sharing and uniform dependencies are known. Retain shared/uniform prefixes and right-hand sum boundaries.
- Native evaluation: discover ordered typed sum fragments up to 16 operands, cache repeated fragments from two uses, and prepare uniform extension fragments once. Preserve surrounding dot-product opportunities.
- ACE: normalize signs, cancel common signed terms, reuse later-discovered candidates, and compress repeated signed segments in canonical atom order. Preserve shared subexpressions as atoms.
- A shared compiler index supports both backends; no additional public symbolic node kinds are introduced.

## Reproduction

The experiments are opt-in and do not add runtime switches to generated evaluators:

```sh
MIDEN_FOLD_POLICIES=current,strict,adjacent,left,flat,aware,uniform,fragments,prepared,signed,fragmentssigned,combined,factor,frequent,veryfrequent \
MIDEN_EVAL_ITERATIONS=16384 MIDEN_EVAL_REPEATS=11 \
taskset -c 8 cargo test --release -p miden-air --features symbolic-experiments \
  --test symbolic_optimization_bench folding_variants -- --ignored --nocapture

cargo run --release -p miden-air-definitions --features symbolic-experiments \
  --example symbolic_ace_sizes
```

Run the repository power guards before heavy local work. Build once, then run the test executable directly to keep compilation separate from measurements. Initial baseline ACE counts were recorded before the new DAG passes; the current size tool reports the new passes.

## Validation

- 29 ACE DAG tests pass, including 16 deterministic 128-operation DAGs checked against independent weighted extension-field arithmetic.
- 64 constraint-compiler tests pass.
- 66 core AIR tests, 8 generated AIR library tests, and 4 generated scalar/packed drift and degree tests pass.
- All 71 VM/PVM backend tests pass, including current proof packaging and relation bindings. Both proof fixtures are regenerated.
- VM/PVM generated artifact drift checks and deterministic PVM proof reproduction pass; embedded verifier roots match their pins.
- Focused Clippy checks pass with warnings denied; host `no_std` checks pass for core and generated AIR crates.
- The opt-in comparison harness rebuilds and passes source-value checks after cleanup; scoped formatting and whitespace checks pass.
