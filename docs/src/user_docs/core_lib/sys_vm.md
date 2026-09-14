---
title: "VM Utilities"
sidebar_position: 8
---

# miden::core::sys::vm

Use `miden::core::sys::vm::verify_proof` to check an execution claim inside another MASM program.
It returns a security descriptor and a root for any deferred precompile work.
[Verifying proofs in MASM](./recursive_verification.md) explains how to prepare the inputs, check
the proof's security level, and settle the deferred work with a PVM proof.

## Modules

| Module | Description |
| --- | --- |
| `miden::core::sys::vm::aux_trace` | Procedures for observing the auxiliary execution trace in the recursive verifier. |
| `miden::core::sys::vm::constraints_eval` | Procedures that perform the constraints evaluation check and manage its associated parameters. |
| `miden::core::sys::vm::deep_queries` | Utilities that construct the DEEP queries needed during proof verification. |
| `miden::core::sys::vm` | Verifies MVM execution claims and returns their security descriptors and deferred roots. |
| `miden::core::sys::vm::ood_frames` | Helpers for processing out-of-domain evaluation frames. |
| `miden::core::sys::vm::public_inputs` | Routines for loading, hashing, and processing public inputs. |
