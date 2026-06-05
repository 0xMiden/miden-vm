---
title: "Deferred-state serialization"
sidebar_position: 3
---

# Deferred-state serialization

`DeferredStateWire` is the serialized opening of a deferred root. It is the format carried in
`ExecutionProof` today so a verifier can reconstruct the opened deferred state and bind it to the VM
proof's public input. It is not the PVM's native interface.

## Opened deferred state

An opened deferred state is the root's reachable opening: the nodes needed to prove that the opened
root evaluates to `Node::TRUE` under an installed `PrecompileRegistry`. Cached helper or evaluation
nodes are implementation details unless they are reachable from the root that is being opened.

`DeferredState::to_wire()` lowers the root-reachable closure into a deterministic child-first stream:

- wire index `0` is the implicit `TRUE_DIGEST`;
- explicit entries have index `i + 1`;
- join entries may reference only index `0` or earlier explicit entries;
- an empty wire opens `TRUE_DIGEST`;
- a non-empty wire opens the digest of the final entry.

## Rehydration

`DeferredState::from_wire(registry, wire, max_elements)` is the trusted path from bytes back to a
validated state. It performs structural checks, verifies canonical ordering by requiring
`state.to_wire() == wire`, evaluates the opened root to `Node::TRUE`, and returns a state whose
`root()` is the opened root.

Current VM verification uses that state as follows:

1. `ExecutionProof` carries the `DeferredStateWire` alongside the STARK proof bytes.
2. The verifier rehydrates the wire under the supplied `PrecompileRegistry`.
3. Rehydration evaluates the opened root and rejects false or malformed openings.
4. The verifier compares the rehydrated root to the deferred root committed by the VM proof public
   input.

This gives the VM proof deferred-root proof binding without requiring the VM circuit to evaluate the
deferred computation itself.

## Target handoff

The target PVM handoff does not require the in-process prover to serialize its own native state first.
When the PVM is invoked directly from the VM prover, it can consume `ExecutionOutput.deferred_state`
as the live opened state. `DeferredStateWire` remains useful for partial proofs, external proving
handoff, persisted proof artifacts, and verifier-side rehydration.
