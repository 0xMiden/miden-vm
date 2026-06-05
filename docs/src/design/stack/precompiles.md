---
title: "Precompiles"
sidebar_position: 12
---

# Precompiles

This page is a transitional stack-level guide for deferred precompiles. It distinguishes the
assembly package that makes procedures callable from the registry that gives deferred tags their
host-side and verifier-side meaning.

## `log_deferred`

`log_deferred` is the VM operation that advances the rolling deferred root. The statement digest is
read from stack offsets 4..8, checked by the host-side deferred state, and folded as:

```text
DEFERRED_ROOT_NEW = Node::and(DEFERRED_ROOT_PREV, STATEMENT).digest()
```

The opcode byte remains `0b0101_1110`. The old `log_precompile` spelling is not accepted by the
parser.

## Deferred-root tracking

The processor maintains a host-side `DeferredState` while a program runs. Deferred assembly wrappers
register nodes through `adv.register_deferred` or `adv.register_deferred_data`, derive the same node
digest in-circuit, and then call `log_deferred` through wrapper code such as
`miden::precompiles::sys::log_node_digest`.

The VM proof public inputs bind the final deferred root. `ExecutionProof` currently serializes the
opened deferred state as `DeferredStateWire`; verification rehydrates that opening under the
installed `PrecompileRegistry`, evaluates the opened root to `Node::TRUE`, and compares the root to
the value committed by the VM proof.

## Package loading and registry installation

Loading a MASM package and installing a registry are separate operations:

- Loading `miden-precompiles` exposes procedures under the `miden::precompiles` namespace so MASM can
  link and execute wrappers such as `crypto::hashes::keccak256::hash_bytes` and
  `crypto::dsa::ecdsa_k256_keccak::verify_prehash`.
- Installing `miden_precompiles::registry()` tells the host, prover, and verifier how to decode and
  evaluate the deferred tags those wrappers register.

Top-level `miden_vm::{prove, prove_sync, verify}` install the default `miden-precompiles` registry.
The CLI also loads the MASM package and installs the same default registry for run/prove/verify.
Lower-level `miden_prover` and `miden_verifier` APIs keep their empty-registry defaults; callers that
need proof-bound deferred precompiles should use their explicit `*_with_precompiles` entry points.

## Compatibility wrappers

Legacy procedures under `miden::core::crypto` remain callable for compatibility. The hash and DSA
helpers there are advice-backed helpers: they can execute cryptographic work through the host, but
they do not log deferred statements and do not create proof-bound claims.

Proof-bound concrete precompile use lives under `miden::precompiles`. New programs that need the VM
proof to bind a deferred hash or signature claim should import wrappers from that namespace.

The older request-list proof architecture has been removed. Deferred precompiles now use
content-addressed node registration, deferred-root tracking, and deferred-state serialization.
