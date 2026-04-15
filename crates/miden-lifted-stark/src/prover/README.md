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

This crate does not enforce a single transcript layout. The protocol implementation
assumes the challenger inside the channel has already observed all variable statement
inputs (in particular the `public_values`).

This is required to support applications that obtain public inputs out-of-band and
do not want them duplicated inside the proof. If you do not bind public inputs into
Fiat-Shamir, the sampled challenges are independent of them.

Ergonomic recommendation: pre-seed the challenger (domain separator + AIR/version tag +
statement metadata + public inputs) *before* constructing `ProverTranscript`, so you can
bind without bloating the proof.

## Multi-trace ordering

For `prove_multi`, instances must be provided in ascending trace height order
(smallest first). Internally, traces are committed and quotient numerators are
accumulated in this order.

Log trace heights are observed into the Fiat-Shamir challenger before the
transcript begins, so the protocol identity depends on the input ordering.

## Protocol flow

1. Validate trace dimensions against AIR definition.
2. Commit main trace LDE on nested coset (bit-reversed), observe commitment.
3. Sample aux randomness, build aux trace, commit aux LDE.
4. Sample constraint folding challenge `alpha` and cross-trace accumulator `beta`.
5. Build periodic LDEs for periodic columns.
6. Compute folded constraint numerators on each trace's quotient domain `gJ`.
7. Lift and beta-accumulate numerators onto the max quotient domain.
8. Divide by the max vanishing polynomial to obtain Q(gJ).
9. Commit quotient chunks via fused iDFT + scaling + DFT pipeline.
10. Sample OOD point `z` (rejection-sampled outside trace domain), derive `z_next`.
11. Open via PCS at `[z, z_next]` for main, aux, and quotient trees.

## Mathematical background

This section assumes familiarity with classic STARKs and focuses on what
changes with **lifting** — how the prover avoids work on the largest
("lifted") domains. All sizes are powers of two.

### Domains and cosets

Let:

- $N = 2^n$ be the **maximum** trace height across all traces in the proof.
- $D = 2^d$ be the **constraint degree** (quotient-domain blowup).
- $B = 2^b$ be the **PCS/FRI blowup** (commitment-domain blowup), with $D \le B$.
- $g$ be the fixed multiplicative shift (`F::GENERATOR`).

Define two-adic subgroups:

$$
H = \langle \omega_H \rangle,\ |H| = N
\qquad
J = \langle \omega_J \rangle,\ |J| = N\,D
\qquad
K = \langle \omega_K \rangle,\ |K| = N\,B
$$

with the usual relationships:

$$
\omega_H = \omega_J^D = \omega_K^B
\qquad
H = J^D = K^B
\qquad
J = K^{B/D}\ \text{(when } D \le B\text{)}
$$

We work over shifted cosets $gH, gJ, gK$.

### Mixed heights via lifting

Suppose trace $T_j$ has height

$$
n_j = N / r_j
\qquad\text{where } r_j = 2^{\ell_j} \text{ is a power of two.}
$$

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

Let $Q(X)$ be the quotient we will ultimately commit. Its degree bound is controlled
by the AIR's constraint degree $D$, so it suffices to evaluate the constraint numerator
on the **quotient coset** $gJ$ (size $N D$) rather than on the full LDE coset $gK$
(size $N B$).

Implementation-wise:

- The committed trace LDEs are stored on $gK$ in **bit-reversed** row order.
- The quotient domain $gJ$ is the first $N D$ points of $gK$ under this ordering.
- Therefore we obtain a zero-copy natural-order view of trace values on $gJ$ by
  truncating to $N D$ rows and bit-reversing. This is what
  `Committed::evals_on_quotient_domain` encodes.

### Lifting numerators instead of re-evaluating constraints

The expensive part of proving is evaluating constraints across a domain.
For a short trace $T_j$ we do **not** evaluate constraints over the max domain.

Instead:

1. Evaluate the folded constraint numerator $N_j$ on the *small* quotient coset
   $(gJ)^{r_j}$ of size $n_j D$.

2. **Lift** $N_j$ onto the max quotient coset $gJ$ by cyclic extension:

$$
\big(\mathrm{lift}_{r}(v)\big)\lbrack i\rbrack = v\lbrack i \bmod |v|\rbrack,\quad i \in \lbrack 0, r\,|v|).
$$

This matches $X \mapsto X^{r}$ on two-adic cosets: iterating the $gJ$ points
in natural order, raising them to the $r$-th power cycles through $(gJ)^r$ with period
$| (gJ)^r |$.

3. Combine lifted numerators across traces using challenge $\beta$ (Horner):

$$
N_{\mathrm{acc}} \leftarrow \mathrm{lift}_{r}(N_{\mathrm{acc}}) \cdot \beta + N_j.
$$

Because $Z_{H^{r_j}}(X^{r_j}) = Z_H(X)$, lifting turns "divisible by $Z_{H^{r_j}}$" into
"divisible by $Z_H$". After combining, the result is still divisible by $Z_H$,
so we divide **once** on the max domain.

### Vanishing division (periodicity trick)

On $gJ$, the vanishing polynomial

$$
Z_H(X) = X^N - 1
$$

takes only $D$ distinct values, since for $x = g\,\omega_J^i$:

$$
x^N = g^N\,(\omega_J^N)^i = g^N\,\omega_S^i
\qquad\text{where } \omega_S := \omega_J^N \text{ has order } D.
$$

Division by $Z_H$ batch-inverts those $D$ values once and indexes by
$i \bmod D$ (a bitmask in code).

### Quotient commitment (fused scaling)

After division we have $Q$ evaluated on $gJ$ in natural order. We commit to
LDE evaluations of the $D$ degree-$<N$ chunks $q_0,\dots,q_{D-1}$ on $gK$.

The decomposition: $gJ$ splits into $D$ disjoint $H$-cosets,

$$
gJ = \bigsqcup_{t=0}^{D-1} g\,\omega_J^t\,H,
$$

and $q_t$ is the unique degree-$<N$ polynomial agreeing with $Q$ on
$g\,\omega_J^t\,H$.

The `commit_quotient` pipeline computes LDE commitments via fused scaling:

1. Reshape $Q(gJ)$ into an $N \times D$ matrix; column $t$ is $Q$ on
   $g\,\omega_J^t\,H$.
2. Batched iDFT over $H$ (treating each column as if on $H$), yielding
   coefficients with an extra $(g\,\omega_J^t)^k$ factor.
3. Multiply row $k$, column $t$ by $(\omega_J^t)^{-k}$ so coefficients become
   "$g^k$-shifted but $t$-independent".
4. Zero-pad from $N$ to $N B$ and run a plain (non-coset) DFT. The $g^k$
   factor baked into coefficients produces evaluations on $gK$.

This avoids $D$ separate coset DFTs and aligns with how the verifier
reconstructs $Q(z)$ from the opened chunk values.
