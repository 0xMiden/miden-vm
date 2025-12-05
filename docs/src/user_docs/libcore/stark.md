---
title: "STARK Verification Helpers"
sidebar_position: 7
---

# miden::core::stark

Namespace `miden::core::stark` bundles procedures and helper utilities that are used when verifying STARK proofs inside the VM.
These helpers expose constants, memory layout pointers, and routines shared across the STARK verification pipeline.

## Modules

| Module | Description |
| --- | --- |
| `miden::core::stark::constants` | Defines memory layout constants and general constants used by the verifier. |
| `miden::core::stark::random_coin` | Contains procedures for sampling and updating the RPO-based random coin used throughout the verifier. |
| `miden::core::stark::deep_queries` | Implements helper procedures for constructing DEEP queries. |
| `miden::core::stark::ood_frames` | Exposes helpers for processing out-of-domain evaluation frames. |
| `miden::core::stark::public_inputs` | Procedures for loading and hashing public inputs. |
| `miden::core::stark::verifier` | High-level procedures that orchestrate STARK proof verification. |
| `miden::core::stark::utils` | Miscellaneous helper functions shared by the verifier modules. |
