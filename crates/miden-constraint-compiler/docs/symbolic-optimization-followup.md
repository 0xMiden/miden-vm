# AIR product sharing and native evaluation experiments

Recorded 2026-11-15 against `4125a91596607ab0dfcd98b802ed9269ef3d131d`.

The selected implementation shares multiplication fragments, removes inverse literal offsets,
uses shorter mixed dots, and makes the PVM lookup XOR expression reuse the shared main equation.
These are compiler scheduling changes and one source simplification; no symbolic node kinds are
added. Source assertion order, classes, and polynomial values remain authoritative.

## Selected rules

- ACE mines repeated factor pairs in maximal single-use multiplication regions and can grow
  them into larger shared subsets. Shared products, sums, and negations remain atoms. Selection
  is deterministic and counts disjoint occurrences, including repeated factors. The rebuilt DAG
  must reduce both its node count and its `(padded stream felts, raw operations)` cost.
- Native product planning first observes actual emitted demand under the existing sum, dot,
  scalar, and preparation choices. It caches repeated pairs of original factors from two uses.
  It preserves squares, scalar specializations, lifts, source domains, structured operations, and
  shared/prepared boundaries. Newly created pairs are not grown into larger native subsets.
- Native sum planning cancels inverse literal offsets such as `(D - 1) + 1` before opening the
  surrounding sum. The inner sum must be single-use and unprepared; the original source graph
  is retained. Constants are compared in the base field.
- Synthesized extension/base dots have a maximum of eight terms. Their minimum remains four;
  same-type and scalar-coefficient dots retain the maximum of sixteen. Sum-fragment discovery
  remains capped at sixteen. Authored linear-combination overrides retain their own sizes.
- Both Eidos wrappers reconstruct XOR with the existing `a + b - and.double()` helper. The
  obsolete choice between doubling and repeated subtraction is removed.

For example, EC MSM has eighteen constraints shaped like:

```text
transition * (not_boundary * residual_i)
```

The compiler introduces `gate = transition * not_boundary` and reuses `gate * residual_i`.
That local pattern drops from 36 multiplications to 19. Whole-circuit counts below include
subsequent normalization and interactions, rather than extrapolating this local count.

## Circuit results

| Measure | VM before | VM after | PVM before | PVM after |
|---|---:|---:|---:|---:|
| Raw operations | 6,646 | 6,583 | 12,728 | 12,558 |
| Distinct constants | 105 | 105 | 686 | 686 |
| Padded EVAL operations | 6,652 | 6,588 | 12,732 | 12,564 |
| Stream felts | 6,864 | 6,800 | 14,104 | 13,936 |

XOR consistency independently removes 32 PVM operations and stream felts. ACE subset extraction
removes 63 VM and 138 PVM operations before that source change. Their combined result is measured
directly above. Native scheduling choices do not determine the ACE product policy.

## Investigation and rejected alternatives

Three agents worked in separate worktrees, followed by parent-owned integration and validation.
The implementation experiments covered product pairs/subsets/three-use thresholds, narrow offset
cancellation, source XOR consistency, source routing collection and direct bus deltas, generic
affine reuse, signed factoring, selected-use fragment pruning, two fragment lifetime limits, and
eight dot threshold/chunk policies. All four VM and twelve precompile AIRs were included.

| Candidate | Evidence and decision |
|---|---|
| ACE subsets | Best deterministic circuit cost; selected independently of native scheduling. |
| Native pairs | Selected after combined scalar/packed measurements on both core types. |
| Native subsets | Only one extra Core multiplication disappears; the combined efficiency-core packed Core result regresses. Retain pairs. |
| Narrow cancellation | Removes the audited LogUp inverse offsets and improves both carriers in the controlled comparison. Selected. |
| Generic affine reuse | Removes more arithmetic, including all 98 audited inverse-offset pairs, but exposes large scalar regressions. Rejected for production. |
| Signed factoring | Changes only UintStoreMul beyond affine reuse; insufficient independent benefit to retain the extra implementation. |
| Eidos routing/deltas | Smaller ACE circuits and fewer row operations, but native packed regressions. Omitted from this implementation. |
| Post-cover/lifetime fragment filters | Alter arithmetic grouping and dot choices; repeated regressions. Omitted. |
| Dot minimum two | Approximately 8% scalar aggregate regression in the initial screen. Rejected. |
| Lower mixed-dot minimum | No supported packed improvement. Retain four. |
| Mixed-dot cap eight | Useful isolated and combined measurements; selected. |
| Explicit LC slice sharing | No authored LC calls or repeated exact pair slices among the 517 inspected generated dots. No implementation. |
| Broader base-value inference | No expensive extension multiplication conversion found in the actual AIRs. No implementation. |

The broad affine prototype also demonstrated a code-generation limit of arithmetic counts:
equivalent normalized row expressions compiled with different inlining and loop-unrolling choices.
In one paired binary, scalar UIntAdd's affine version outlined mixed-dot calls while cancellation
inlined them; the observed scalar regression was much larger than the controls. This establishes
different machine code, without assigning the entire regression to any one compiler decision.

Rejected affine, routing, signed-factoring, and lifetime prototypes remain in isolated worktrees.
Retained ablations are available through testing-only generation controls; they are not production
defaults.

## Measurement method

- Apple M2 Pro, aarch64/NEON, Rust 1.99.0, release profile. CPU 8 is a performance core and CPU 2
  an efficiency core. AVX2/AVX512 dot-size cutoffs were not used to justify an M2 policy.
- Power guards passed before heavy batches. Builds and timing runs were serialized.
- Every candidate was checked against the authored evaluator at seeds `0`, `42`, and
  `u64::MAX`, for scalar and distinct packed lanes, before timing. Selectors need not be Boolean.
- Preparation and allocation are excluded. Final paired measurements share the exact input
  frame and output allocation between control and candidate, keep both prepared sessions alive,
  warm both for 256 calls, alternate timed order, and black-box the complete output builder.
- Performance-core confirmations use 11 samples of 16,384 calls; efficiency-core screening uses
  seven samples of 8,192 calls. Reported values are per-call medians and median absolute
  deviations. Scalar and packed calls are compared within their own carrier.
- Geometric means weight all sixteen AIRs equally; summed one-row medians are also retained.
  Neither measure is an end-to-end proving benchmark.

The first screen allocated separate input/output buffers for each evaluator. Identical-code
controls sometimes differed substantially despite low within-run MAD. The later shared-fixture
pairs remove that allocation-context confound, while prepared-array locations, generic helper
code generation, and code placement remain possible influences. Small changes in unchanged AIR
functions are not evidence of fewer arithmetic operations.

The final combination was measured directly, rather than adding isolated percentages. The
combination CSV includes the source-XOR-only control (`combined`), native cancellation (`cancel`),
cancellation plus mixed cap eight (`combo`), and that combination with native pairs or subsets.
All combination policies also use ACE subsets. `frozen` is a same-kernel paired control against
the baseline commit; its movement is close to zero.

| Selected pair combination | Performance core | Efficiency core |
|---|---:|---:|
| Scalar geomean vs frozen baseline | -4.06% | -5.66% |
| Packed geomean vs frozen baseline | -5.30% | -4.24% |
| Scalar incremental vs source-XOR-only control | -3.95% | -6.27% |
| Packed incremental vs source-XOR-only control | -3.04% | -3.60% |

The incremental comparison is useful because unchanged-code context shifts also contribute to
the whole-baseline figures. These prototype figures guided selection. The cleaned production
implementation was then measured in a smaller executable containing the frozen baseline,
source-XOR-only control, and actual public production kernels:

| Final production vs baseline | Performance core | Efficiency core |
|---|---:|---:|
| Scalar geomean | -3.80% | -5.56% |
| Packed geomean | -3.36% | -3.67% |
| Sum of scalar row medians | -3.77% | -6.80% |
| Sum of packed row medians | -3.22% | -2.94% |

The final run checked all sixteen AIRs against the authored evaluator at all three seeds for
both carriers. Every individual scalar/packed median improved in these runs. Same-kernel control
geomeans moved by less than 0.07%; the source-XOR-only control moved by less than 0.18%. Code
placement and helper generation still affect these measurements, so the final numbers replace
the prototype percentages as the observed production result.

## Raw results and reproduction

- [Initial full-policy screen](symbolic-optimization-followup-screen.csv): exploratory separate-allocation measurements; not final policy evidence by themselves.
- [Shared-fixture candidate comparisons](symbolic-optimization-followup-paired.csv).
- [Direct combined-policy comparisons](symbolic-optimization-followup-combinations.csv).
- [Cleaned production comparison](symbolic-optimization-followup-production.csv).

The existing opt-in folding harness now emits `control_POLICY` and candidate records using the
shared-fixture timing method. Controls use the current production kernel. For example:

```sh
# Run systemd-ac-power and headless-power-policy check-heavy first.
MIDEN_FOLD_POLICIES=combined,production,products,productsubsets,cancel,mixedcap8 \
cargo test --release -p miden-air --features symbolic-experiments \
  --test symbolic_optimization_bench --no-run

# Run the resulting executable directly; do not compile concurrently.
MIDEN_EVAL_ITERATIONS=16384 MIDEN_EVAL_REPEATS=11 \
taskset -c 8 /path/to/test-executable --ignored --exact folding_variants --nocapture
```

Reproducing the historical full-baseline comparison additionally requires generating and saving
the `combined` VM/PVM evaluator modules from commit `4125a9159`, then including those functions
beside the candidate functions in the same benchmark executable. The historical baseline uses
the original PVM XOR spelling; current source-level ablations all use the unified helper.

## Validation

The final six-crate release run executed 580 tests: 578 passed, two failed, and four manual tests
were skipped. Passing coverage includes compiler and ACE arithmetic, authored AIRs, generated
scalar/packed drift, auxiliary security, current circuit/relation pins, and native verification
of the packaged VM/PVM proof fixtures. A further 164 compiler/ACE tests passed after lint cleanup.

The two failures are unchanged cold-allocation guards in `miden-vm-stark::memory_allocations`.
Both reproduce at baseline `4125a9159` with the same counts: 53 allocations for VM and 485 for PVM.
Their tests and runtime memory-query implementation are untouched.

Two auxiliary-security capture checks also failed at the baseline: independently captured full
and lookup graphs associated sums differently according to surrounding use counts. Both captures
now use the same non-folding scope for exact root matching. Membership, multiplicity, shape,
expected degrees `119/31/7`, and security-budget inequalities are unchanged. The prepared-evaluator
golden's two stale Rustdoc words are refreshed without changing its generated arithmetic.

VM/PVM circuit digests, relation pins, MASM artifacts, embedded verifier roots, snapshots, current
proof fixtures, and packaged-advice hashes are refreshed. Both MASM regeneration checks, the
deterministic PVM proof-fixture regeneration check, and the embedded verifier-root consistency
test pass. VM fixture regeneration used the existing single-threaded maintainer test; the
serialized program remains unchanged, and its regenerated proof passes native verification.

Standard Clippy with warnings denied passes across seven affected crates and all their targets,
including the opt-in experiment harness. The additional project `xclippy` flags still reject
pre-existing unnecessary qualifications and redundant clones in unchanged `ir/index.rs` and
`ir/program.rs`; no lint suppressions or unrelated fixes are added. Host `no_std` checks pass for
AIR definitions, generated AIR, ACE runtime, VM STARK, and precompile STARK. Scoped formatting and
`git diff --check` pass. No compiler-memory, preparation-time, or end-to-end proving claim is made.
