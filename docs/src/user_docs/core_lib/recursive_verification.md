---
title: "Verifying proofs in MASM"
sidebar_position: 9
---

# Verifying proofs in MASM

## Verifier contracts

`C` is the commitment to the execution-claim (program, kernel, input stack, output stack), and `D` is its
deferred root.

| Procedure | Input stack | Output stack |
| --- | --- | --- |
| `sys::vm::verify_proof` | `[C, ...]` | `[security_descriptor, D, ...]` |
| `sys::pvm::request_proof` | `[D, ...]` | `[D, ...]` |
| `sys::pvm::verify_proof` | `[D, ...]` | `[security_descriptor, ...]` |
| `stark::security::compute_conjectured_security_level` | `[security_descriptor, ...]` | `[level, ...]` |

Both verifiers consume their proof data from the advice stack.

`D = TRUE_DIGEST` (`[0, 0, 0, 0]`) means the execution left no deferred work,
so no PVM proof is needed.
Otherwise, to fully close verification we need to settle `D` or explicitly propagate it as an obligation for a later verifier.

## Checking proof security

Both verifiers return the same twelve-field descriptor, in this stack order:

```text
[lookup_pow_bits, num_composed_constraints, max_constraint_degree, num_deep_terms,
 max_message_width, num_lookup_boundary_terms, lookup_fractions_per_row,
 log_max_height, num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits]
```

These fields give our security estimator the parameters it needs to compute the proof's
conjectured security level.
Pass the descriptor unchanged to `compute_conjectured_security_level` and check the returned bit count against your required minimum security target for each MVM and PVM proof.
Remember that the weakest proof limits the security of the whole.

## Example: settle a deferred execution

`proof` is a Miden VM `ExecutionProof` with a nonzero deferred root, and `claim` is its
`ExecutionClaim`:

```rust
use miden_core_lib::CoreLibrary;
use miden_processor::StackInputs;
use miden_verifier::recursive::RecursiveVerifierInputs;

let core_lib = CoreLibrary::default();
let inputs = RecursiveVerifierInputs::for_request(
    core_lib.vm_recursive_verifier_root(),
    &proof,
    &claim,
)?;
let (advice_inputs, claim_commitment) = inputs.into_parts();
let stack_inputs = StackInputs::new(claim_commitment.as_elements())?;
```

The adapter stores the MVM proof under `proof_request_key(verifier_root, claim_commitment)` and
supplies the claim preimage, kernel procedure list, and advice data. MASM derives the same key
with `procref.vm::verify_proof` and takes `claim_commitment` as public input. If `proof` includes
a PVM proof, supply it through the separate PVM request described below.

```masm title="settle_deferred.masm"
use miden::core::sys
use miden::core::stark::security
use miden::core::sys::pvm
use miden::core::sys::vm

const MIN_SECURITY_BITS = 96

begin
    # Keep C for verify_proof while fetching the proof from advice.
    dupw
    procref.vm::verify_proof exec.sys::build_proof_request_key
    adv.push_mapval dropw
    exec.vm::verify_proof
    # => [security_descriptor, D, ...]

    exec.security::compute_conjectured_security_level
    # => [level, D, ...]
    u32lt.MIN_SECURITY_BITS assertz.err="MVM proof security is below the required minimum"
    # => [D, ...]

    # Request a proof for the root returned by the MVM verifier.
    exec.pvm::request_proof
    exec.pvm::verify_proof
    # => [security_descriptor, ...]

    exec.security::compute_conjectured_security_level
    u32lt.MIN_SECURITY_BITS assertz.err="PVM proof security is below the required minimum"
end
```

## Supplying the PVM proof

`pvm::request_proof` emits a `miden_core_lib::PVM_PROOF_REQUEST_EVENT_NAME` event. A `Host::on_event`
handler supplies the PVM proof and may await its generation or retrieval. The core library
provides no default handler.

At the event, the operand stack is `[event_id, VERIFIER_ROOT, D, ...]`. The handler then checks that `VERIFIER_ROOT` matches the PVM verifier your host supports, then obtains
a PVM proof for `D` compatible with `VERIFIER_ROOT`. Generating it requires the original execution's deferred witness data.

Package `pvm_proof` with `PvmRecursiveVerifierInputs::for_request`, which uses
`pvm_proof.aggregate_root()` for the request key. For a single execution and hence for a single root, `pvm_proof.roots` is
`[D]`. Return the advice map and Merkle nodes from the event handler:

```rust
use miden_precompiles_verifier::masm_verifier::PvmRecursiveVerifierInputs;
use miden_processor::advice::AdviceMutation;

let package = PvmRecursiveVerifierInputs::for_request(verifier_root, &pvm_proof)?;
let (advice, _) = package.into_parts();
let (_, advice_map, store) = advice.into_parts();

Ok(vec![
    AdviceMutation::extend_map(advice_map),
    AdviceMutation::extend_merkle_store(store.inner_nodes()),
])
```

`request_proof` loads advice under `proof_request_key(verifier_root, D)`. The PVM verifier checks
the proof against `D` returned by the MVM verifier.

For proof generation and the event handler, see the
[settlement integration test](https://github.com/0xMiden/miden-vm/blob/next/crates/lib/core/tests/stark/pvm_settlement.rs).

## Example: batch N executions

`verify_batch` in the [MASM batcher](https://github.com/0xMiden/miden-vm/blob/next/crates/lib/core/tests/stark/pvm_settlement/batch.masm)
accepts a caller-provided buffer and an even runtime count from 2 through `MAX_CLAIMS` (4).
The [Rust example](https://github.com/0xMiden/miden-vm/blob/next/crates/lib/core/tests/stark/pvm_settlement/batch.rs)
uses two ECDSA executions as transaction stand-ins but this is generalisable in a straightforward manner to N transactions.

`CLAIMS_COMMITMENT` is the hash of the ordered claim commitments `[C1, ..., CN]`. The
example exposes `[N, CLAIMS_COMMITMENT]` as public inputs and supplies the list and MVM proofs
through advice. MASM checks the list's hash before verifying the claims.

### Combining the deferred roots

Skip TRUE roots and use the first nonzero root unchanged. Append subsequent roots in claim order
using AND nodes. For `[A, TRUE, B, A]`, the folded root is:

```text
D = digest(AND(digest(AND(A, B)), A))
```

Order and repeated nonzero roots are preserved. Each AND node uses one Poseidon2 permutation
with `AND_TAG = [1, 0, 0, 0]`, matching `miden_core::deferred::fold_deferred_root`.

### Proving the combined work

Reconstruct each `DeferredState` from `PrecompileStatus::Deferred` with `DeferredState::from_wire`.
Here, `deferred_states` contains states with nonzero roots in claim order, including repeats:

```rust
use miden_core::deferred::PrecompileWitness;

let witnesses = deferred_states
    .into_iter()
    .map(PrecompileWitness::new)
    .collect::<Result<Vec<_>, _>>()?;
let merged = PrecompileWitness::merge(witnesses)?;
```

Merging computes `D` and combines the witness data. On the request for `D`, prove the merged
witness with `Prover::prove_precompile` and return the packaged advice.

The resulting `PrecompileProof` contains one STARK proof for `roots = [A, B, A]`. Its `aggregate_root()`
recomputes `D` from the metadata. The batcher verifies the PVM proof against `D`, which it computed
from the deferred roots returned by the MVM verifiers, and checks the proof's security level.

If all roots are TRUE, skip merging witnesses and requesting a PVM proof.

### Proving the batcher

After settlement, the batcher's MVM proof has no deferred work. Its claim includes
`[N, CLAIMS_COMMITMENT]` as public inputs, identifying the ordered batch it settles.

For the meaning and composition of deferred roots, see
[deferred proof obligations](../../design/deferred/semantics.md#proof-obligations-and-composition).
