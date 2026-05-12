# Lifted STARK Prover

End-to-end proving for the lifted STARK protocol using LMCS commitments
and the lifted FRI PCS. Supports multiple traces of different power-of-two
heights via virtual lifting.

Protocol-level overview lives in `miden-lifted-stark/README.md`.

## Entry Points

| Item | Purpose |
|------|---------|
| `prove_single` | Prove a single-AIR STARK |
| `prove_multi` | Prove a multi-trace STARK |
| `AirWitness` | Bundle a trace with its public values |

```text
prove_single(config, air, trace, public_values, var_len_public_inputs, aux_builder, challenger)
prove_multi(config, &[(air, witness, aux_builder), ...], challenger)
```

The proof is written into the provided transcript channel. This crate does not
prescribe the *initial* challenger state used for Fiat-Shamir.

## Fiat-Shamir / transcript binding

The caller must bind protocol parameters, public values, variable-length
public inputs, AIR configurations, and `air_order` into the challenger
before calling `prove_multi`. See the Rust module-level docs for the full contract
and code examples.

## Protocol flow

1. Validate trace dimensions against AIR definition.
2. Commit main trace LDE on nested coset (bit-reversed), observe commitment.
3. Sample aux randomness, build aux trace, commit aux LDE.
4. Sample constraint folding challenge `alpha` and cross-trace accumulator `beta`.
5. Build periodic LDEs for periodic columns.
6. Compute each AIR's quotient on its native quotient coset.
7. Lift and accumulate per-AIR quotients onto the max quotient domain.
8. Commit quotient chunks via fused iDFT + scaling + DFT pipeline.
9. Sample OOD point `z` (rejection-sampled outside trace domain), derive `z_next`.
10. Open via PCS at `[z, z_next]` for main, aux, and quotient trees.

## Mathematical background

This section assumes familiarity with classic STARKs and focuses on what
changes with **lifting** — how the prover avoids work on the largest
("lifted") domains. All sizes are powers of two.

### Domains and cosets

Let:

- $N$ be the **maximum** trace height across all AIRs in the proof; $n_j$ is AIR
  $j$'s trace height and $r_j = N / n_j$.
- $D_j$ be AIR $j$'s **quotient degree factor**, derived from its
  constraint-degree bound; its native quotient evaluation domain has size
  $n_j D_j$. Let $D_{\max} = \max_j D_j$.
- $B$ be the **PCS/FRI blowup** used for commitment domains, with
  $D_{\max} \le B$.
- $g$ be the fixed multiplicative shift (`F::GENERATOR`).

Define two-adic subgroups:

$$
H = \langle \omega_H \rangle,\ |H| = N
\qquad
J = \langle \omega_J \rangle,\ |J| = N\,D_{\max}
\qquad
K = \langle \omega_K \rangle,\ |K| = N\,B
$$

with the usual relationships:

$$
\omega_H = \omega_J^{D_{\max}} = \omega_K^B
\qquad
H = J^{D_{\max}} = K^B
\qquad
J = K^{B/D_{\max}}.
$$

We work over shifted cosets $gH, gJ, gK$. The **global quotient coset** is
$gJ$ of size $N D_{\max}$.

### Mixed heights via lifting

Trace $T_j$ has height $n_j = N / r_j$ with $r_j$ a power of two.

Intuitively, **lifting** makes $T_j$ look like a height-$N$ trace by stacking $r_j$
copies of it. Algebraically, if $t_j(X)$ is the degree-$<n_j$ interpolant over $H^{r_j}$,
the *lifted* polynomial is

$$
t_j^*(X) = t_j(X^{r_j}),
$$

which has degree $< N$.

The key map is the projection

$$
\pi_{r}(X) = X^{r}.
$$

It maps max-size domains onto smaller ones:

$$
\pi_{r_j}(H) = H^{r_j} \quad\text{and}\quad \pi_{r_j}(gK) = (gK)^{r_j} = g^{r_j} K^{r_j}.
$$

#### Commitment domains: nested cosets without extra LDE work

For each trace $T_j$, the prover commits to its LDE evaluations on the **nested**
coset $(gK)^{r_j}$ (size $n_j B$), not on the full $gK$ (size $N B$).

Concretely, `commit_traces` chooses the per-trace coset shift

$$
\text{shift}_j = g^{r_j},
$$

so that evaluating on $\text{shift}_j \cdot K^{r_j}$ matches the image of $gK$
under $X \mapsto X^{r_j}$. This is the core "no work on the lifted domain" win:
computing an LDE for a short trace stays $\Theta(n_j B)$, not $\Theta(N B)$.

### Quotient-domain constraint evaluation

As in a classic STARK, constraints produce a numerator polynomial divisible by the
trace vanishing polynomial. The twist is **where** we evaluate it.

For a single AIR with quotient degree factor $D_j$, the quotient $Q_j$ has
degree bound $n_j D_j$, so it suffices to evaluate it on a coset of
size $n_j D_j$ rather than on the full commitment coset of size $n_j B$.

Implementation-wise:

- The committed trace LDEs are stored on $gK$ (or its nested coset for short
  traces) in **bit-reversed** row order.
- The native quotient coset of size $n_j D_j$ is the first $n_j D_j$ points of
  the per-trace LDE coset under this ordering.
- We obtain a zero-copy natural-order view of trace values on that coset by
  truncating and bit-reversing. This is what
  `Committed::evals_on_quotient_domain` encodes.

### Folding per-AIR quotients

For AIR $j$, let $D_j$ be the quotient degree factor required by its
constraints. The expensive part of proving is evaluating constraints across a
domain. We avoid the global $gJ$ entirely: each AIR is divided locally on its
native coset, and the per-AIR quotient evaluations are then folded together via
cyclic lifting.

This is the implementation form of the older "lift numerators, divide once on
$gJ$" identity. The two views agree because, with $Y = X^{r_j}$,

$$
Z_{H^{r_j}}(X^{r_j}) = X^N - 1 = Z_H(X),
$$

so if a numerator factors as $N_j(Y) = Z_{H^{r_j}}(Y)\,Q_j(Y)$ on the small
domain, then on the global domain

$$
\frac{N_j(X^{r_j})}{Z_H(X)} = Q_j(X^{r_j}).
$$

Lifting the small quotient $Q_j$ by $X \mapsto X^{r_j}$ produces exactly what
the lifted numerator would have produced after a global division by $Z_H$. So
we may divide AIR-by-AIR on the small domain and fold afterwards.

Write $gJ_j$ for AIR $j$'s native quotient coset of size $n_j D_j$. After
degree extension it is evaluated on the corresponding size-$n_j D_{\max}$
target coset used for cyclic lifting into $gJ$. The procedure for each AIR is:

1. Evaluate the $\alpha$-folded constraint numerator on $gJ_j$.

2. Divide by $Z_{H^{r_j}}(X) = X^{n_j} - 1$ on $gJ_j$ to obtain $Q_j$ on $gJ_j$.

3. If AIR $j$ requires a smaller quotient degree factor than the batch maximum
   ($D_j < D_{\max}$), low-degree extend $Q_j$ from $gJ_j$ (size $n_j D_j$) to
   the size-$n_j D_{\max}$ target coset — same polynomial, denser sampling on
   the coset chosen so that the next step's cyclic extension lands on $gJ$.

4. Lift the running accumulator from its current size $L$ onto $n_j D_{\max}$
   by cyclic extension:

$$
\mathrm{lift}_{r}(v)\lbrack i\rbrack = v\lbrack i \bmod L\rbrack,\quad i \in \lbrack 0, r L),
\qquad r = n_j D_{\max} / L,
$$

   and Horner-fold $Q_j$ in:

$$
\mathrm{acc} \leftarrow \mathrm{lift}_{r}(\mathrm{acc}) \cdot \beta + Q_j.
$$

Cyclic extension matches $X \mapsto X^{r}$ on two-adic cosets: iterating a
size-$rL$ coset in natural order and raising each point to the $r$-th power
cycles through its size-$L$ image coset, repeating each value $r$ times. So
copying entries by $i \bmod L$ on the target buffer evaluates the lifted
polynomial in the right places. After all AIRs are folded in, the accumulator
holds the combined quotient $Q$ on the global $gJ$ of size $N D_{\max}$.

### Vanishing division (periodicity trick)

On $gJ_j$ (size $n_j D_j$), the AIR's local vanishing polynomial

$$
Z_{H^{r_j}}(X) = X^{n_j} - 1
$$

takes only $D_j$ distinct values, since for $x = g^{r_j}\,\omega^i$ with $\omega$
of order $n_j D_j$:

$$
x^{n_j} = g^{n_j r_j}\,\omega_S^i
\qquad\text{where } \omega_S := \omega^{n_j} \text{ has order } D_j.
$$

So division by $Z_{H^{r_j}}$ on $gJ_j$ batch-inverts those $D_j$ values once and
indexes them by $i \bmod D_j$ — only $D_j$ inversions, not $n_j D_j$.

### Quotient commitment (fused scaling)

After all AIRs are folded in we have $Q$ evaluated on $gJ$ in natural order.
We commit to LDE evaluations of the $D_{\max}$ degree-$<N$ chunks
$q_0,\dots,q_{D_{\max}-1}$ on $gK$.

The decomposition: $gJ$ splits into $D_{\max}$ disjoint $H$-cosets,

$$
gJ = \bigsqcup_{t=0}^{D_{\max}-1} g\,\omega_J^t\,H,
$$

and $q_t$ is the unique degree-$<N$ polynomial agreeing with $Q$ on
$g\,\omega_J^t\,H$.

The `commit_quotient` pipeline computes LDE commitments via fused scaling:

1. Reshape $Q(gJ)$ into an $N \times D_{\max}$ matrix; column $t$ is $Q$ on
   $g\,\omega_J^t\,H$.
2. Batched iDFT over $H$ (treating each column as if on $H$), yielding
   coefficients with an extra $(g\,\omega_J^t)^k$ factor.
3. Multiply row $k$, column $t$ by $(\omega_J^t)^{-k}$ so coefficients become
   "$g^k$-shifted but $t$-independent".
4. Zero-pad from $N$ to $N B$ and run a plain (non-coset) DFT. The $g^k$
   factor baked into coefficients produces evaluations on $gK$.

This avoids $D_{\max}$ separate coset DFTs and aligns with how the verifier
reconstructs $Q(z)$ from the opened chunk values.
