# Source AIR algebra cleanup

Reviewed against `f9db7eab38930d82d4ceecd1141ed9578369214b` on 2026-11-15.

All 201 files under `crates/air/source/src` were read in full and reviewed. The scope includes
handwritten constraints, lookup encodings, auxiliary witnesses, trace/layout helpers, tests,
snapshots, and compiler adapters. Three agents divided the files into disjoint groups; the
remaining eight compiler/module/geometry files received a separate agent review. The 58 modified
source-tree files then received independent cross-reviews by another agent, with no findings.
The central builder change and regression test also received independent review.

The [file ledger](algebra-cleanup-files.csv) records every file, reviewer, unchanged/changed status,
decision, remaining opportunity, cross-review evidence, and final content hash. An unchanged file
is still reviewed; support code, independent reference equations, and already-clear constraints
were retained where there was no useful rewrite.

## Applied rules

- Use `assert_eq`, `assert_one`, their extension variants, and ordered array assertions to state
  the obligation directly. Expose common gates with `when`; keep each constraint independent and
  preserve global assertion order, base/extension class, and zero-gated emissions.
- Use one Boolean convention, `x * (x - 1)`, through `assert_bool(s)` or `.bool_check()`. The builder
  now dispatches through the ring method, retaining a symbolic `BoolCheck`. Normalize standalone
  checks previously written as `x * (1 - x)` deliberately; their residual signs change while their
  zero sets do not. Embedded range polynomials retain their exact signs and roots.
- Write reductions with `.map(...).sum()` or `sum_array`. Use typed homogeneous or mixed dots
  for actual weighted sums, retaining narrow coefficient domains. Long UInt reductions use
  eight-term mixed-dot chunks; retain the shared sixteen-limb prefix of a seventeen-limb value.
- Replace subtraction tails with a positive sum on the right of an equality, or a negated sum,
  where that makes the equation clearer. Keep the original residual orientation outside the
  intentional Boolean normalization.
- Factor repeated extension values through sums/differences of base gates. Share conditional-swap
  deltas between both outputs, factor repeated-source opcode mixtures into gated equalities, and
  expose challenge-only prefix differences before multiplying them by row selectors.
- Use `.square()`, `.double()`, `.mul_2exp_u64()`, and the existing ring power iterator where they
  express the operation. Preserve semantic named constants and useful Horner/prefix structures.

For example, the EC mint ordering obligations now state two independent equalities under one
named gate, with each right-hand side a sum of the pointer, one, and two radix limbs. Stack copy
positions 8–11 now state gated copies instead of constructing a weighted sum whose terms all
refer to the same source. Memory-response prefix selection separates uniform prefix differences
from its row-dependent read/write and width selectors.

The source operation vocabulary is unchanged. These rewrites expose more of the existing
`BoolCheck`, `Sum`, `LinearCombination`, `Exp`, and `ScalePow2` vocabulary to capture.

## Retained structures and remaining opportunities

| Area | Decision and reason |
|---|---|
| Two/three-term general-stack dots | Keep ordinary arithmetic and the measured synthesis threshold; forcing a short authored dot bypasses that policy. |
| Long message/position-zero weighted sums | Keep readable sums or the existing message inner-product API; do not force a large mixed dot. |
| Eidos routing and bus deltas | Keep current routing. The earlier experiment reduced ACE operations but regressed packed evaluation. |
| Three-field Eidos lookup dot | Record the opportunity; retain current arithmetic below the measured four-term synthesis minimum. |
| Uniform preparation | Memory-response prefix differences now expose uniform work. Periodic values, trace columns, and row selectors remain row-dependent. A named gate alone does not become preparable. |
| Eidos challenge powers | Keep the shared power recurrence; separate exponentiation of every entry would discard useful sharing. |
| Horner and staged polynomial evaluation | Retain useful shared prefixes and independent audit equations; a dot is not automatically clearer or faster. |
| Ternary/range membership | Preserve explicit roots and embedded polynomial orientation. These are not standalone Boolean checks. |
| Rotation normalization constants | Preserve the documented constant form and its ACE expansion rationale. |
| Stateful witness/error scans | Retain scans whose intermediate state, error order, or mutation is part of the algorithm. |

Further compiler work could make explicit structured reductions compose better with surrounding
factoring and dot scheduling. The source cleanup does not assume that recording a richer node
automatically improves final code generation.

## Semantic validation

The initial core/source/compiler/ACE library run passed 694 tests, including a new builder test
covering retained Boolean nodes, ordered assertions, zero gates, and non-Boolean numerical inputs.

Frozen generated evaluators from the starting commit were included beside the cleaned kernels in
a temporary comparison executable. All 1,420 production assertions across four VM and twelve PVM
AIRs retained their global positions and classes. Comparisons passed at four full-field seeds,
with scalar inputs and distinct packed lanes; selectors were not assumed Boolean. Exactly 54
standalone/gated Boolean assertions changed sign. Sign changes were allowed only at current
Boolean-check roots and had to be consistent across seeds and lanes. Every other residual matched
exactly. Cleaned generated kernels also matched their current handwritten source exactly.

The final comparison also pins the expected per-AIR sign-change lists from the first pass;
additional sign changes are rejected. The temporary historical modules and comparison test are
not retained in production source.

The final seven-crate release run passes 807 tests, including source/generated scalar and packed
drift, auxiliary-security bounds, current circuit snapshots, native proof verification, and
packaged-advice fixture hashes. Two pre-existing cold-allocation guards were excluded from that
final rerun: the earlier unfiltered 809-test run reproduced their baseline failures with 53 VM
and 485 PVM allocations. Their tests and runtime memory-query implementation are untouched.
The two stale advice-hash pins from that unfiltered run were refreshed from the regenerated,
verified proof fixtures and pass in the final run.

Standard Clippy with warnings denied passes across eight affected crates and all targets,
including the opt-in experiment harness. Host `no_std` checks pass for AIR definitions,
generated AIR, ACE runtime, VM STARK, and precompile STARK. The independently derived VM/PVM
circuit and relation pins, MASM artifacts, snapshots, verifier roots, current proof fixtures,
and packaged-advice hashes are current. Both MASM regeneration checks, the deterministic PVM
fixture check, and the embedded verifier-root consistency test pass. The regenerated VM
fixture retains its original program bytes. Scoped formatting and `git diff --check` pass.

Outside the source-tree inventory, the central builder, its regression test, and the README
also received independent review. Supporting contract checks consulted the compiler's expression
index, native planner/emitter, concrete-evaluation test helpers, and the pinned Plonky3 field-trait
implementation. Those were targeted API checks rather than additional full-tree coverage claims.

## Measured tradeoffs

| ACE measure | VM before | VM after | PVM before | PVM after |
|---|---:|---:|---:|---:|
| Raw operations | 6,583 | 6,556 | 12,558 | 12,583 |
| Padded EVAL operations | 6,588 | 6,556 | 12,564 | 12,588 |
| Stream felts | 6,800 | 6,768 | 13,936 | 13,960 |

Distinct constants and READ inputs remain 105/718 for VM and 686/2,286 for PVM. The cleanup
reduces VM circuit operations but increases PVM operations; it is not an across-the-board circuit
optimization.

Paired release measurements on an Apple M2 Pro, aarch64/NEON, Rust 1.99.0, give these changes in
the equally weighted geometric mean of sixteen AIR row times:

| Core | Scalar | Packed |
|---|---:|---:|
| Performance CPU 8, pooled final runs | +0.36% | +0.21% |
| Efficiency CPU 2, final run | +0.34% | -0.32% |

Positive values mean slower. The aggregate result is broadly neutral, with per-AIR tradeoffs.
The final comparison binary records a packed Core regression of 7.89% on CPU 8 and 2.66% on CPU
2, and approximately 2.8–4.1% scalar Eidos regressions. Packed Chiplets improves by approximately
3.6% and 4.8% respectively. These observations do not establish that fewer source operations or
richer capture necessarily mean faster machine code.

The earlier cleanup binary measured packed Core at +0.49%. The final consistency pass changed
only precompile source files; Core source was unchanged. The initial generated OUT_DIR was
overwritten, so identity of its generated text cannot be proven. Five retained final VM modules
are byte-identical, and the final comparison build reused its generated library while rebuilding
the test executable with additional oracle assertions. The timed helper was unchanged. Code
placement or compiler optimization context is a plausible explanation for the shift, but is not
proven. The regression is retained in the results rather than attributed entirely to an arithmetic
rewrite or discarded as noise.

The [per-AIR results](algebra-cleanup-bench.csv) include medians, MAD, matched control times,
sample counts, same-kernel controls, and stage labels. `initial` precedes the bounded consistency
pass; `final` and `final_repeat` measure the final equations in the same executable. The table
uses `final_pooled` on CPU 8 and `final` on CPU 2. Both evaluators share one input/frame/output
allocation; preparation and allocation are outside the timer. Timed order alternates after 256 interleaved
warmup calls per evaluator. Each CPU-8 run uses eleven samples of 16,384 calls; the pooled final
result combines two runs for 22 samples. CPU 2 uses seven samples of 8,192 calls.
Builds and timing runs were serialized, and power guards passed. This is not an end-to-end proving
benchmark or a compiler/preparation-time claim.

The subsequent [scaling follow-up](../../../miden-constraint-compiler/docs/symbolic-optimization-followup.md#power-of-two-scaling-follow-up-2026-11-16)
restores native dot discovery through `ScalePow2` while retaining explicit scaling on short-chunk
backends. Final Eidos measurements improve both scalar and packed evaluation on both core types.
The measurements above describe the source cleanup before that follow-up; its own results,
rejected alternatives, and code-generation limits are recorded separately. Source equations,
the 201-file ledger hashes, preparation, and ACE artifacts are unchanged by the follow-up.
