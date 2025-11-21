---
title: "STARK Verification Helpers"
sidebar_position: 7
---

# std::stark

Namespace `std::stark` bundles procedures and helper utilities that are used when verifying STARK proofs inside the VM.
These helpers expose constants, memory layout pointers, and routines shared across the STARK verification pipeline.

## Modules

| Module | Description |
| --- | --- |
| `std::stark::constants` | Defines memory layout constants and general constants used by the verifier. |
| `std::stark::random_coin` | Contains procedures for sampling and updating the RPO-based random coin used throughout the verifier. |
| `std::stark::deep_queries` | Implements helper procedures for constructing DEEP queries. |
| `std::stark::ood_frames` | Exposes helpers for processing out-of-domain evaluation frames. |
| `std::stark::public_inputs` | Procedures for loading and hashing public inputs. |
| `std::stark::verifier` | High-level procedures that orchestrate STARK proof verification. |
| `std::stark::utils` | Miscellaneous helper functions shared by the verifier modules. |