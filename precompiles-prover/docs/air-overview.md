# Precompile Prover AIR Overview

This crate proves deferred precompile work as a multi-AIR session. Each chiplet owns one relation family, and `SessionTraces::check()` verifies that all LogUp buses balance across the combined trace set.

This document describes the current review boundary. It is not a design history, benchmark report, or plan for future DSA work.

## Session Stack

`Session` records precompile work into independent accumulators, then `Session::finish()` lowers them into traces. `SessionTraces::mains()` and `ChipletAir::all()` use this order: chunk, Poseidon2, Keccak round, bitwise64, byte-pair lookup table, Keccak sponge, Keccak node, transcript eval, uint store, uint add, uint mul, EC groups, EC point store, EC group add, and EC MSM.

The logical dependency flow is different from the trace order. Several chiplets use byte and range lookups from the byte-pair lookup table. EC data and MSM expressions are built out of uint values. The Keccak traces cover chunking, Poseidon2, sponge execution, node assertions, and round execution. Transcript eval binds the public root to the typed values proven by the other chiplets.

The transcript eval trace owns the public root. It consumes or provides bindings between transcript hashes and typed values. The typed chiplets prove the underlying arithmetic or hash work.

## Shared Buses

The crate uses typed buses rather than an unstructured global relation. `Binding` connects a transcript digest to a typed value. Current value tags cover truthy results, uint field elements, and curve points. `UintVal`, `UintAdd`, and `UintMul` connect uint leaves and uint operations to the uint store and arithmetic chiplets. `Field` connects a uint modulus pointer to the Poseidon2 field tag used by uint value nodes.

The EC buses are separate. `EcGroup`, `EcPoint`, and `EcGroupAdd` connect EC transcript nodes to the EC stores and group-add chiplet. `MsmExpr`, `MsmTerm`, and `MsmClaimTerm` connect symbolic MSM expressions to their term rows and claimed values. The hash buses connect chunking, sponge rows, Keccak rounds, and Keccak assertion nodes.

Padding rows must not contribute to any bus. Chiplets that carry provide multiplicities pin those multiplicities to zero when inactive.

## Transcript Eval

`TranscriptEvalAir` proves the content-addressed transcript DAG used by the prover session. It has rows for static truthy nodes, including zero, `and`, and equality checks. It also has rows for uint value nodes, uint arithmetic joins, EC point creation, point-at-infinity creation, EC group joins, and EC equality checks.

Uint neg is intentionally rejected in the eval AIR because there is no canonical uint-neg deferred node in the product precompile API. EC neg is allowed as an internal helper because EC sub and MSM negation need the EC group-add cancellation proof.

EC point-at-infinity rows reuse the EC value cap with zero children. The AIR constrains every left and right child limb to zero on those rows, so a finite EC value digest cannot be relabeled as infinity.

## EC MSM Boundary

The EC MSM chiplet proves symbolic expression construction:

- `intro` promotes a stored point to a one-term expression with scalar `1`.
- `combine` merges two expression term lists and proves the value point with one EC group-add.
- `neg` negates every term scalar and proves the value point with an EC group-add cancellation.

This layer is a chiplet mechanism. The current segment does not define a canonical deferred MSM transcript node. The product curve precompile exposes MSM through a pair-list tag that commits `(scalar_digest, point_digest)` pairs. That pair-list transcript shape is not encoded in `TranscriptEvalAir` in this segment. A later branch should add it as its own review unit if the prover needs to expose a public Curve MSM deferred node.

## Keccak Boundary

The Keccak path proves a byte preimage, sponge execution, round execution, and a transcript assertion node. The assertion tag carries the byte length, so empty input and trailing-zero input remain distinct.

The Keccak public-root bridge is synthetic in this crate: it builds the same deferred root shape that the VM verifier expects, then proves the prover-side chiplets close against that root.

## Review Rules

Keep future branches narrow:

- Add transcript node shapes in the transcript eval branch that consumes them.
- Add chiplet rows and buses in the chiplet branch that proves them.
- Add benchmarks after the code they measure is merged.
- Do not publish agent-memory notes, stale research logs, or broad design drafts as crate documentation.
