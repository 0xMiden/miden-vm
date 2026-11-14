# Own and extend the symbolic AIR representation

This PR imports the pinned Plonky3 symbolic AIR implementation into Miden and adapts it for our
constraint compiler. Base and extension expressions share one typed representation, useful ring
and algebra operations survive capture, and the compiler uses those expressions to generate
native Rust and derive primitive arithmetic for ACE.

The imported representation records leaves and basic `Add`, `Sub`, `Mul`, and `Neg` operations.
Higher-level calls generally expand before the compiler sees them. Separate base/extension leaf
families and builder-based variable resolution also tie the representation to the upstream AIR
interface. Owning the implementation lets us change those boundaries and retain information that
concrete field implementations can use.

For example:

```text
Authored expression       Captured operation       Native computation
x.square()                Exp(x, 2)                x.square()
x.exp_u64(7)              Exp(x, 7)                x.exp_const_u64::<7>()
mixed dot product         LinearCombination        typed mixed_dot_product
x - y                     Sum([x, Neg(y)])         x - y
```

The compiler can still expand these operations into ordinary arithmetic for ACE. Native emission
can choose specialized methods without reconstructing every operation from a multiplication tree.

## Import and adapt the existing implementation

The starting point is the symbolic code from `p3-air` 0.8.0, copied into
[`miden_stark::air::symbolic`](crates/stark/core/src/air/symbolic/mod.rs). Upstream already supplied
shared expression trees, constant folding, cached degree information, memoized traversal,
serialization, and recovery of base expressions. This PR builds on that implementation.

Plonky3's numerical `PrimeCharacteristicRing` and `Algebra` traits remain the dispatch interface.
Their same-type blanket implementations remain unchanged. The local symbolic implementation owns
its storage, input addresses, construction rules, traversal, and serialization.

## One representation for base and extension expressions

The imported types used a generic tree with separate leaf families:

```rust
// Before, abbreviated.
type SymbolicExpression<F> = SymbolicExpr<BaseLeaf<F>>;
type SymbolicExpressionExt<F, EF> = SymbolicExpr<ExtLeaf<F, EF>>;
// An extension leaf could contain an entire base expression.
```

They now use one private storage representation with typed handles:

```rust
pub struct Expr<F, EF = F, D = Base> {
    raw: RawExpr<F, EF>,
    marker: PhantomData<D>,
}

type SymbolicExpression<F, EF = F> = Expr<F, EF, Base>;
type SymbolicExpressionExt<F, EF> = Expr<F, EF, Extension>;
```

`Base` and `Extension` identify the authored algebra. They preserve type safety even when both
classes evaluate numerically in an extension field at an out-of-domain point. Dynamic base values
enter extension expressions through an explicit `Lift`; extension-only content cannot silently
become a base expression.

Leaves remain inline so ring identities can be associated constants. Immutable operation nodes
and their checked degree caches are shared through `Arc`. `ExprRef` and `ExprView` provide borrowed
inspection while constructors keep domain and arity invariants private. This replaces `SymLeaf`,
`BaseLeaf`, `ExtLeaf`, and builder-specific variable resolution.

Input leaves use field-independent addresses for main/preprocessed rows, public/periodic values,
auxiliary rows, challenges, and exports. Current/next row offsets and selector leaves remain
explicit. Capture retains assertion class and global order, including duplicate and zero-gated
assertions.

## Preserve useful ring and algebra operations

The current operation vocabulary is:

| Source operation | Captured node |
| --- | --- |
| Addition and iterator sums | `Sum` |
| Subtraction | `Sum` with `Neg` terms |
| Unary negation | `Neg` |
| Binary multiplication | `Mul` |
| Iterator products | `Product` |
| Base-to-extension conversion | `Lift` |
| Homogeneous/mixed dots and supported mixed batched combinations | `LinearCombination` |
| Square, cube, constant/runtime `u64` powers | `Exp` |
| Repeated squaring | `ExpPowerOf2` |
| Double, halve, multiply/divide by powers of two | Signed `ScalePow2` |
| Boolean polynomial check | `BoolCheck` |

`Exp` merges constant-generic and runtime exponent capture. `ScalePow2` uses a signed `i128`,
preserving the full `u64` magnitude for multiplication and division. Every node produces one value.
Quadratic-extension squaring, XOR, XOR3, and ANDN use the traits' ordinary arithmetic expansions;
there are no pair/projection nodes or dedicated bitwise nodes.

Addition and subtraction retain small sum nodes during construction. Direct constants and simple
identities fold, but nested sums are not eagerly flattened. This preserves reusable intermediates
and keeps repeated accumulation linear in the number of terms. The compiler uses actual use counts
to flatten suitable regions while respecting sharing and preparation boundaries. Small signed
sums emit ordinary `+`/`-`; larger regions can use bounded sums and dot products.

### Normalize coefficients by value and domain

Equivalent constant spellings normalize together:

```rust
// B and E abbreviate the base and extension symbolic expression types.
x * Felt::from_u64(7)
x * B::from_u64(7)

e * Felt::from_u64(7)
e * B::from_u64(7)
e * E::from(Felt::from_u64(7))
```

These do not need different nodes merely because Rust selected different overloads. The removed
`CoefficientDomain` tags and operand wrappers no longer carry that provenance. Linear-combination
coefficients also normalize into the result domain, allowing structural CSE to recognize equivalent
spellings. :codex-annotation{index="1"} :codex-annotation{index="4"}

Dynamic base coefficients still retain `Lift(base_expression)`. Native dispatch examines the
normalized children: known base constants can use `Algebra<Felt>`, extension/base combinations use
`Algebra<BaseExpr>`, and genuinely extension-valued expressions use homogeneous extension calls.
A public input remains dynamic even though its degree in the trace variable is zero.

Generated extension code respects the promised `E: Algebra<B>` bound; it does not assume
`E: Algebra<Felt>`. Arbitrary non-base extension literals remain unsupported by the generic native
emitter when those bounds cannot construct them.

## Compile the retained expressions directly

`CapturedProgram` owns the ordered source assertions and their derived arithmetic graph:

```text
Authored constraint evaluation
    -> ordered symbolic assertions
    -> CapturedProgram
        +-> borrowed expression index + native plan -> generated Rust
        +-> primitive arithmetic Graph -> ACE DAG -> encoded circuit
```

Native emission reads the retained expressions through a temporary index for structural CSE, use
counts, and preparation slots. One emitter and preparation planner handle the native path.
Existing preparation and arithmetic optimizations are adapted to the expression index rather
than maintained as separate generation paths.

The emitter preserves useful specialized operations and can recover square/scaling, sum/dot, and
factoring patterns. Sum/dot pattern recovery uses bounded regions, and long mixed linear
combinations use the batched method. Shared expressions and prepared results remain materialized
rather than being expanded into every consumer.

ACE and arithmetic analyses consume the derived primitive graph, which still has
`Add`/`Sub`/`Mul`/`Neg` operations. The source vocabulary does not force ACE to add corresponding
special-purpose gates. There is no additional owned rich-graph language between the symbolic
expressions and native emission.

## Extend degree handling, serialization, and source identity

The existing degree machinery is extended for the retained operations. Cached and alternate
leaf-degree traversals share the operation rules, and runtime descriptor recipes retain checked
power/scale calculations. At trace height eight:

```text
degree(x)                       = 7
degree(x.square())              = 14
degree(x.exp_power_of_2(3))      = 56
degree(public_value)            = 0
```

Degree-zero powers return zero before constructing an enormous exponent. Nonzero bounds use
checked arithmetic. These are polynomial-degree bounds, independently of the expression's
numerical value. :codex-annotation{index="2"}

The current topological wire format is version 3. Decoding checks references, domains, arities,
linear-combination lengths, scaling limits, and degree overflow, then reconstructs degree caches.
Constant normalization follows validation so it cannot erase an invalid extension-to-base edge.
Roundtrips preserve current values, domains, and operation sharing.

Source fingerprints describe normalized ordered source structure under
`miden.native-air.source\0`. They include actual constants, input namespaces, domains, and operation
parameters, while excluding allocation identities, diagnostics, and phantom capture types.
They associate a source capture with its setup; they are not canonical hashes of arbitrary
equivalent polynomials. Encoded-circuit authentication and proof-transcript relation binding remain
separate. :codex-annotation{index="3"}

## Check polynomial semantics across the compiler

Correctness checks compare values and ordered assertion classes across source expressions,
primitive lowering, and generated scalar/packed execution. ACE checks execute the authored source
concretely and compare it with the DAG, off-VM circuit, and supported encoded streams across all
four VM and twelve precompile AIRs. Encoded padding is checked separately because it repeatedly
squares the final residual.

Different equivalent expression shapes and gate insertion orders are allowed. The test-only
symbolic ACE lowerer and node-for-node parity checks are removed; deterministic generation and
authentication of the current circuit remain required. :codex-annotation{index="6"}

Regression cases cover normalized coefficients, dynamic lifts, compound `to_base` conversions,
shared subtrees, checked wire decoding, degree overflow, preparation reuse, all retained
operations, and independent hand-calculated input/emission cases. Historical evaluator comparisons
and old PVM proof fixtures are removed, with useful namespace, selector, duplicate-zero, auxiliary,
and rejection scenarios retained in current tests. :codex-annotation{index="7"}

Representation and lowering changes update affected current descriptors, circuit/relation digests,
MASM artifacts, verifier roots, and proof fixtures. Previous graph bytes, circuit shapes, symbolic
schemas, and proof bindings are not compatibility targets. :codex-annotation{index="9"}

## Documentation and validation

Representation contracts and short provenance live beside `Expr`/`ExprView`; the compiler overview
and [native AIR architecture guide](crates/stark/core/docs/native-air-design.md) describe their
integration. The symbolic README and duplicated planning documents are removed. Upstream
attribution and the [MIT](crates/stark/core/src/air/symbolic/LICENSE-MIT) and
[Apache-2.0](crates/stark/core/src/air/symbolic/LICENSE-APACHE) license texts remain.
:codex-annotation{index="8"}

The current sum/negation representation, wire schema, and regenerated artifacts passed 173 focused
tests covering symbolic/compiler behavior, native scalar/packed execution, ACE, preparation, wire
validation, degrees, and proof bindings. Two existing timing tests were skipped. Three doctests
passed, including typed-domain compile failures; two existing examples remained ignored. Clippy
with warnings denied, host `no_std`, scoped formatting, and both artifact consistency checks passed.

Compiler memory consumption and compilation time are not acceptance criteria for this change.
Benchmarks remain deferred, and no measured performance improvement is claimed.
:codex-annotation{index="5"} :codex-annotation{index="10"}
