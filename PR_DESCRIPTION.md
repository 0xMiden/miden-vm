# Preserve AIR operations and validate polynomial equivalence

This PR keeps useful ring and algebra operations in one symbolic expression representation.
The compiler emits specialized native Rust from those expressions and derives primitive
arithmetic for ACE. The correctness requirement is that both paths evaluate the same
polynomials. Their nodes, grouping, and original Rust overloads do not have to match.

For example, both spellings below multiply by the same field constant:

```rust
x * Felt::from_u64(7)
x * BaseExpr::from(Felt::from_u64(7))
```

They should normalize to the same useful native computation. Similarly, `(a + b) + c` and
`a + (b + c)` may have different circuit layouts while evaluating the same polynomial.

**Status:** complete. The foundation is checkpointed in `d666c968a`, followed by one commit for
each of A1–A8. The examples below describe the resulting implementation; abbreviated snippets
omit unrelated code. Validation results are recorded under A8.

## Direction and scope

- Keep one owned symbolic AST, typed base/extension handles, explicit lifts, and checked degree
  rules. Native Rust and the ACE arithmetic graph use the same authored capture.
- Preserve useful operations so concrete field implementations can supply specialized methods.
  Choose coefficient types from their values and domains, without preserving incidental source
  overloads.
- Test polynomial values against an independent current source implementation. Exact gate IDs,
  equivalent tree layouts, and historical encoded circuits are not contracts.
- Remove archived implementation comparisons and old proof-version fixtures, preserving useful
  cases as current tests.
- Keep current circuit authentication, preprocessing association, and prover/verifier agreement.
- Treat compilation time and compiler memory consumption as negligible for this work.
  :codex-annotation{index="5"}
- Backwards compatibility with previous symbolic schemas, historical circuits, or archived
  proof versions is not a goal. Current schema checks and current protocol bindings remain.
  :codex-annotation{index="9"}
- Benchmarks are deferred. They are not an approval gate, and this PR makes no unmeasured
  performance claim. :codex-annotation{index="10"}

We are not implementing a general canonical polynomial representation. These changes normalize
constants, conversions, and coefficient selection. They do not require structural CSE to prove
that arbitrary distributed, factored, reordered, or reassociated expressions are identical.

## Foundation already implemented

The previous generic binary tree used separate base/extension leaf types. Extension leaves
could embed a whole base tree. The current handles share private storage:

```rust
pub struct Expr<F, EF = F, D = Base> {
    raw: RawExpr<F, EF>,
    marker: PhantomData<D>,
}

type SymbolicExpression<F, EF = F> = Expr<F, EF, Base>;
type SymbolicExpressionExt<F, EF> = Expr<F, EF, Extension>;
```

The markers identify the source algebra, not the numerical field at an out-of-domain
verification point. Base polynomials can still be evaluated in an extension field. Leaves
remain inline for associated ring constants; operations are shared by `Arc` and inspected
through borrowed `ExprRef`/`ExprView` values.

The retained operation vocabulary is:

| Source operation | Recorded operation |
| --- | --- |
| Addition, subtraction, multiplication, negation | `Add`, `Sub`, `Mul`, `Neg` |
| Base-to-extension conversion | `Lift` |
| Iterator sum/product | `Sum`, `Product` |
| Dot products and supported mixed combinations | `LinearCombination` |
| Square, cube, constant/runtime `u64` exponentiation | `Exp` |
| Repeated squaring | `ExpPowerOf2` |
| Double, halve, multiply/divide by powers of two | Signed `ScalePow2` |
| Boolean polynomial check | `BoolCheck` |

Every node produces one value. Quadratic-extension squaring, XOR, XOR3, and ANDN use their
arithmetic defaults; no pair/projection representation is retained. Plonky3's traits remain
unchanged, including their same-type blanket implementations.

`CapturedProgram` owns the original assertions and their derived arithmetic graph:

```rust
// Type names abbreviated.
pub struct CapturedProgram {
    assertions: Vec<Assertion<BaseExpr, ExtExpr>>,
    graph: Graph,
    constraints: CapturedConstraints,
}
```

There is one native emitter and one preparation planner. A temporary borrowed index supplies
CSE, use counts, and preparation slots. There is no separately owned `RichNode`/`RichOp`/
`RichLeaf` language. The old leaf-constructor enums, compatibility alias, duplicate degree
rule table, and duplicate emitter/preparation path have already been removed.

## Approved implementation changes

| ID | Change | Status |
| --- | --- | --- |
| A1 | Normalize coefficient values/conversions and remove original-overload metadata end to end | Implemented |
| A2 | Use a clear current source/setup fingerprint policy without semantic-equality or historical-version promises | Implemented |
| A3 | Replace structural ACE/generated-code comparisons with independent semantic checks and delete redundant helpers | Implemented |
| A4 | Delete archived AIR references and comparisons; retain useful scenarios as current tests | Implemented |
| A5 | Delete old PVM proof-version fixtures; preserve rejection coverage with current proofs | Implemented |
| A6 | Consolidate current documentation and remove duplicated/historical implementation prose | Implemented |
| A7 | Add compact current normalization, conversion, wire, and compiled-evaluation regression tables | Implemented |
| A8 | Regenerate affected current artifacts and run focused validation | Implemented |

A1 normalizes the representation; A2 updates its source-identity namespace. A3 establishes
independent semantic checks, A4/A5 remove archives, A6 consolidates documentation, and A7 extends
current regressions. A8 refreshes affected outputs and validates the completed change.

### A1. Normalize coefficients instead of recording the original overload

Before A1, the `CoefficientDomain` tag recorded whether a coefficient came from a field value,
a base expression, or the same expression type. It carried source provenance without additional
mathematical information. The optimizer already ignored some of these distinctions.

**Before — overload metadata, abbreviated:**

```rust
Mul { x, y, coefficient_domain: CoefficientDomain }
LinearCombination { values, coefficients, coefficient_domain: CoefficientDomain }

pub struct SymbolicOperand<F, EF, D> { /* raw value, overload tag, marker */ }
pub trait IntoSymbolicOperand<F, EF, D> { /* ... */ }
```

**After — current shape:**

```rust
Mul { x, y }
LinearCombination { values, coefficients }

// Ordinary operators use the existing conversions into the result type.
impl<..., T: Into<Self>> Mul<T> for Expr<...> { /* ... */ }
```

This last `impl` abbreviates the field and domain bounds. `Base`/`Extension` handles keep their
conversion boundaries. The wrappers that retained the author's overload choice are removed.

Constants use common constructors, including checked decoding:

```rust
// Base result: same normalized constant child.
x * Felt::from_u64(7)
x * B::from(Felt::from_u64(7))

// Extension result: same normalized extension-domain constant child.
e * Felt::from_u64(7)
e * B::from(Felt::from_u64(7))
e * E::from(Felt::from_u64(7))
```

Base-embedded extension constants should use that same normal form. A genuinely extension-
valued constant remains distinct. Dynamic base expressions still require an explicit lift:

```text
e * b  ->  Mul(e, Lift(b))
```

Linear-combination coefficients are converted into the result's symbolic domain. Deleting only
the tag would leave different raw children and prevent the desired CSE.

These two base combinations should normalize together:

```rust
B::dot_product(&xs, &[B::from(c0), B::from(c1)])
<B as Algebra<Felt>>::mixed_dot_product(&xs, &[c0, c1])
```

Their inferred native call is:

```rust
<AB::Expr as Algebra<Felt>>::mixed_dot_product::<2>(&values, &[c0, c1])
```

Coefficient selection follows actual values and domains:

| Result domain | Recognized coefficients | Native coefficient type/call |
| --- | --- | --- |
| Base | All known field constants | `Felt`, using `Algebra<Felt>` |
| Base | Other base expressions | Base expressions, using homogeneous `dot_product` |
| Extension | Constants and base expressions/lifts | Base expressions, using `Algebra<BaseExpr>` |
| Extension | Some genuinely extension-valued expressions | Extension expressions, lifting other coefficients as needed |

Keep batched mixed combinations for long inputs. A public input is not a known constant just
because its polynomial degree is zero. A dynamic base expression can vary across packed lanes.
The builder promises `B: Algebra<Felt>` and `E: Algebra<B>`, not `E: Algebra<Felt>`; choose calls
that those bounds permit. The emitter still rejects arbitrary extension literals
that the current builder bounds cannot construct.

**Supporting changes, all part of A1:**

- `symbolic/mod.rs`: remove `CoefficientDomain`, `SymbolicOperand`, `IntoSymbolicOperand`, their
  impls, and `scalar_valid`; simplify binary/LC validation to the normalized domain invariant.
- `symbolic/expression_ext.rs`: simplify the concrete extension-family macro; normalize
  base-embedded constants; keep required `From`/`Algebra` implementations.
- `symbolic/traversal.rs`: remove overload fields from views and base reconstruction.
- `symbolic/flatten.rs`: remove wire tags and their validation; apply the same normalization
  when reconstructing nodes, while retaining checked topology, domains, lengths, and degrees.
- Compiler `ir/mod.rs`: remove the coefficient-tag re-export.
- Native `index.rs`: remove overload bytes from CSE keys after normalization.
- Native `rust_eval.rs`: replace tag-driven binary/LC rendering with inferred legal dispatch.
- Native `plan.rs`: inspect base operands beneath `Lift`; simply checking their extension
  handle's class would lose mixed-dot recovery after ordinary `Into<Self>` conversion.
- Replace tests requiring different overload tags with normalization/CSE and dispatch tests.

**Required behavior:** the examples above normalize together and share emitted work; dynamic
base coefficients retain mixed dispatch; typed extension-to-base misuse stays rejected; all
outputs preserve polynomial values. :codex-annotation{index="1"}

The same rule applies to binary operations such as `x * c` and to linear combinations such
as `x0*c0 + x1*c1`. Both hash paths now omit the removed overload metadata, so binary
fingerprints and linear combinations follow the same policy. :codex-annotation{index="4"}

### A2. Separate source/setup identity from polynomial equivalence

The current code has three different identities:

| Identity | Purpose |
| --- | --- |
| Descriptor/source fingerprint | Associate the current kernel with preprocessing/setup and select cached setup |
| ACE circuit digest | Authenticate the actual encoded circuit the recursive verifier executes |
| Protocol relation digest | Bind the proof transcript to the protocol ID and circuit digest |

Retain the current kernel/setup association. Do not replace it with a shape- or degree-only
hash, which could associate different constraints with the same setup description.

The source fingerprint is structural. It does not need to be equal for every equivalent
polynomial. For example, the following contract is sufficient:

```text
value(x.square(), assignment) == value(x * x, assignment)

fingerprint(x.square()) == fingerprint(x * x) is NOT required
```

The second line states an absent requirement, not a requirement that the hashes differ.
We will not expand arbitrary polynomials or add a general equivalence/canonical-hashing engine.

**Current identity policy:**

- Remove incidental overload metadata from all source hash paths as part of A1.
- Keep actual constants, input namespaces, source base/extension domains, operation parameters,
  and ordered structure in the current encoding.
- Use a purpose-specific source namespace, such as `miden.native-air.source\0`, rather than
  presenting this local identity as a versioned protocol relation. Regenerate embedded current
  source fingerprints; do not retain aliases for old encodings.
- Keep allocation addresses and phantom capture types out of stable identity. Actual extension
  constant coefficients still count.
- Preserve the actual current circuit digest, relation digest, and preprocessing commitment
  checks. Those protect current verification and are not backwards-compatibility machinery.

**Files:** core `air/analysis.rs`, descriptor generation/expectations, source identity tests,
source/setup documentation, and any current artifacts affected by regeneration. The existing
setup-association checks in `preprocessed.rs` remain in place unless separately redesigned.

**Required behavior:** correct current setup validates; a mismatched setup/kernel is rejected;
current generated descriptor identities reproduce; no test demands equality of fingerprints
for arbitrary equivalent representations. :codex-annotation{index="3"}

### A3. Replace structural comparisons with semantic compiler checks

**Before — current comparison, simplified:**

```rust
assert_eq!(tree_nodes, ir_nodes);
assert_eq!(tree_root, ir_root);
```

This requires a second test-only lowering implementation that reproduces node order. It is
stronger than the intended polynomial contract.

**After — semantic check, abbreviated:**

```rust
let expected = eval_authored_air_concretely(&air, &frame, &inputs);
let actual = eval_current_ace(&air, &frame, &inputs);
assert_eq!(actual, expected);
```

The reference helper executes the authored `LiftedAir::eval` with concrete extension-field
values, preserves assertion class/order, and folds the results using the intended current
layout. It must not obtain expected values through `capture_program`, `Graph`, `eval_graph`,
or a production lowerer. Reuse existing independent input, periodic-value, quotient, and
DAG/circuit evaluation helpers. Keep existing source-expression evaluation checks as
complementary coverage.

Test all four VM AIRs and twelve PVM AIRs, supported native/MASM layouts, and multiple arbitrary
full extension-field assignments. Check both the current DAG and encoded circuit against the
concrete source. Randomized evaluation is regression evidence, not a formal proof of arbitrary
polynomial equality. Encoded ACE padding repeatedly squares the residual; the decoded
unpadded root is compared with the source and the padding tail is checked separately.

**For example:** `x*c + y*c` and `(x+y)*c` are allowed to produce different node lists. Their
constraint residuals must agree on the tested inputs. The current encoded stream must still
match its current authenticated digest.

**Remove the complete obsolete path:**

- Delete `crates/ace/src/compiler/dag/lower.rs`, including `Primitive`, `Recipe`, and its separate
  folding/expansion implementation.
- Remove its module/export and obsolete test-only public exports from `dag/mod.rs` and
  `compiler/mod.rs`. Keep production lowerers and internal periodic data where still used.
- Remove `Norm`, `normalized`, the exact node/root comparison, and unused imports from
  `crates/air/generated/tests/ace_codegen.rs`.
- Update traversal-parity comments in `dag/lower_ir.rs`, module docs, and the stale periodic
  helper reference in `compiler/tests/basic.rs`.
- Remove the unused `canonical_ids` helper and its unused imports from constraint-compiler
  `testing.rs`.
- Replace structural “handwritten/generated are distinct captures” checks in
  `generated_drift.rs` and `precompiles_generated_drift.rs` with direct source-versus-generated
  concrete checks. Identical root IDs are not a failure. Keep regeneration tied to authored
  source rather than generated artifacts; add the VM concrete `DirectKernel` check analogous
  to the existing PVM check.

**Retain:** current semantic evaluations, layout/assertion mapping, source-based generation,
preparation correctness, deterministic emission for the same input, and current circuit pin
checks. Do not remove `capture_constraints` or source evaluation helpers that current semantic
tests still use.

**Required behavior:** different equivalent shapes are accepted; incorrect arithmetic, input
binding, assertion mapping, or quotient handling still fails independent value checks.
:codex-annotation{index="6"}

### A4. Delete historical AIR reference artifacts and comparisons

Removed:

```text
crates/air/generated/tests/native_air_reference.rs
crates/air/generated/tests/native_air_reference_coverage.rs
crates/air/generated/tests/fixtures/native_air_reference/README.md
crates/air/generated/tests/fixtures/native_air_reference/reference.txt
crates/air/generated/tests/fixtures/native_air_reference/coverage.txt
```

The archived revision/lock hashes, generation environment variables, historical protocol recorder,
and unused observation/formatting helpers are removed with them.

The compiled `current_inputs` fixture retains the useful scenarios with direct hand-calculated
expectations: every input namespace, selectors, mixed base/extension emissions, duplicate zero-gated
assertions, and auxiliary exports. For example:

```text
source emissions:    [Base(0), Extension(r0), Base(0), Extension(r1)]
generated emissions: [Base(0), Extension(r0), Base(0), Extension(r1)]
```

Here `r0` and `r1` are calculated by the current independent numerical reference. No archived
text file or previous checkout supplies the expectation.

**Required behavior:** no tests or generation tasks depend on an archived source checkout;
the useful current scenarios remain tested after the historical files are removed.
:codex-annotation{index="7"}

### A5. Delete old proof-version fixtures and preserve current rejection checks

Removed both old binary/root pairs:

```text
crates/stark/precompiles/tests/fixtures/pvm_eidos_v0_31.bin
crates/stark/precompiles/tests/fixtures/pvm_eidos_v0_31.root
crates/stark/precompiles/tests/fixtures/pvm_eidos_v0_35.bin
crates/stark/precompiles/tests/fixtures/pvm_eidos_v0_35.root
```

Their rejection tests and fixture references are removed from
`crates/stark/precompiles/src/verifier.rs`. A current proof now checks the same useful rejection
behavior after first verifying successfully with the correct root and relation binding.

**Current verification cases, abbreviated:**

```rust
assert!(verify_deferred(&current_proof, correct_root).is_ok());
assert!(verify_deferred(&current_proof, incorrect_root).is_err());
// A test-only altered relation digest also rejects this same current proof.
```

The replacement reuses the current fixture and a test-only altered configuration. No production
compatibility registry is added; `fixture_root` remains in use by current tests.

**Required behavior:** archived versions are gone; current valid proofs verify; incorrect
current statements/bindings are rejected. Current `v1_0` fixtures remain active correctness
fixtures and can be regenerated.

### A6. Consolidate documentation and preserve minimal provenance

The consolidated documentation layout is:

```text
symbolic/mod.rs + Expr/ExprView Rustdoc       representation/API contracts and short provenance
constraint-compiler/src/lib.rs               short current pipeline overview
stark/core/docs/native-air-design.md         one current architecture guide, with history removed
PR_DESCRIPTION.md                           rationale, examples, and this approval plan
symbolic/LICENSE-MIT + LICENSE-APACHE        existing upstream license texts
```

Removed `symbolic/README.md` after moving its essential provenance and current guidance.
The four copied-source headers now point to module documentation. Upstream attribution, SPDX
notices, and the existing license files remain. The old source-file hash table is removed; the upstream attribution and licenses remain.

Retired these historical planning/migration documents after moving useful current API guidance
into the locations above:

```text
crates/stark/core/docs/native-air-migration.md
crates/stark/core/docs/native-air-implementation-plan.md
crates/stark/core/docs/native-air-goal-prompt.md
crates/stark/core/docs/native-air-completion.md
```

The current architecture guide replaces baseline-only and archived-oracle sections. References
in `CHANGELOG.md` and `crates/air/source/docs/expression-source-review.md` now resolve to current
documentation; obsolete historical-comparison requirements are removed.

**Required behavior:** one current architecture guide remains; API contracts are near their
owners; source provenance remains available; no link points to deleted documentation.
:codex-annotation{index="8"}

### A7. Keep compact current correctness tests

Replace representation-specific assertions with cases that exercise the intended behavior.
The test suite should cover:

| Case | Required check |
| --- | --- |
| Constant/conversion spellings in A1 | Same normalized computation and legal specialized call |
| Dynamic base coefficients under `Lift` | Mixed extension/base dispatch is still recognized |
| Known constants versus degree-zero public inputs | Runtime values are not mistaken for literals |
| Compound `to_base` conversions | Success for base-only content; rejection for extension-only content |
| All retained operations | Correct source, lowered, native scalar, and packed values |
| Wire roundtrips | Current canonical values/domains/sharing survive decode and re-encode |
| Invalid wire inputs | Invalid references/domains/lengths/degrees remain rejected |
| Degree bounds | Checked overflow, shared subtrees, and zero-degree large powers |
| Preparation | Challenge-only results computed once; row work uses cached values |
| Current ACE | Independent source, DAG, and encoded-circuit evaluations agree |
| Current verifier | Valid current proofs pass; incorrect current claims/bindings fail |

Degree recipes stay. For a trace column at height eight:

```text
degree(x) = 7
degree(x.square()) = 14
degree(x.exp_power_of_2(3)) = degree(x^8) = 56
```

A public input with numerical value `7` still has degree zero in the trace variable. Its
powers have degree zero even when their field values are nonzero. Return that bound before
constructing an enormous exponent; use checked arithmetic for nonzero-degree bounds. The
recipe computes polynomial degree, not the value of the constraint.
:codex-annotation{index="2"}

Keep the compiled operation fixture and the current preparation regression. A compiled golden
can remain as a current emitted-code check; it must not establish compatibility with an old
implementation. Update tests that required different overload tags or different graph IDs.
No benchmark is introduced as part of these tests.

### A8. Regenerate current artifacts and validate the final state

Generated descriptors were rebuilt with normalized operands and `miden.native-air.source\0`.
The compiled preparation golden was regenerated. Its only changes are three local binding names
and their uses; arithmetic, cache slots, and assertion order are unchanged.

Both current artifact generators pass in `--check` mode:

```sh
cargo run --offline --locked -p miden-core-lib --features constraints-tools \
  --bin regenerate-constraints -- --check
cargo run --offline --locked -p miden-precompiles-stark --features constants-tools \
  --bin pvm-constants-regen -- --check
```

Current circuit shapes/digests, relation digests, MASM constants, verifier roots, and proof bytes
need no further regeneration after the foundation checkpoint. Their current consistency checks
remain active:

```text
current encoded ACE stream -> current circuit digest
current protocol ID + circuit digest -> current relation digest
current compiled verifier -> current declared verifier root
current kernel + preprocessing -> valid setup association
```

The current symbolic schema discriminator and checked decoding remain. No legacy symbolic reader
was added, and unrelated proof-transport version handling remains outside this cleanup.

Observed validation in this implementation session (runs overlap; counts are per run):

| Check | Result |
| --- | --- |
| Core/compiler, operation fixture, and preparation-session checks | 105 passed |
| ACE and VM/PVM generated-source checks, including current circuit/setup pins | 90 passed; 2 existing timing tests skipped |
| Current input fixture and current-proof binding checks | 12 passed |
| Exact regenerated golden, capture, degree, row, and auxiliary checks | 14 passed |
| Final current VM/PVM proof/advice, verifier roots, and affected helper checks | 9 passed |
| Core doctests, including typed-domain compile failures | 3 passed; 2 existing examples ignored |
| Clippy: core, compiler, ACE, generated AIR, precompile backend; libraries/tests with warnings denied | Passed |
| Host `no_std`: `miden-stark` and `miden-air` | Passed |
| Scoped Rust formatting, whitespace, removed-name and documentation-link checks | Passed |

All Rust builds and tests passed the required AC and heavy-work guards. Benchmarks remain deferred.

## Implementation checklist

- [x] A1 — normalize constants/conversions and infer coefficient dispatch; delete overload metadata.
- [x] A2 — keep a clear structural source/setup identity, with no polynomial-canonical or historical-version promise.
- [x] A3 — add independent current semantic checks; remove exact structural oracle and unused test helpers.
- [x] A4 — delete archived AIR references; retain useful cases as current tests.
- [x] A5 — delete old PVM proof-version artifacts; retain current negative verification coverage.
- [x] A6 — remove duplicated/historical documentation and preserve minimal provenance.
- [x] A7 — restore compact current normalization, conversion, persistence, and execution regressions.
- [x] A8 — regenerate affected current outputs and validate the completed implementation.

Each checklist item corresponds to one implementation commit after the foundation checkpoint.
