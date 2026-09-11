---
title: "STARK Verification Helpers"
sidebar_position: 7
---

# miden::core::stark

`miden::core::stark` contains the verification routines shared by the MVM and PVM verifiers,
including the security estimator. [Verifying proofs in MASM](./recursive_verification.md) explains
how to call those verifiers and check that their proofs meet your application's security policy.

## Modules

| Module | Description |
| --- | --- |
| `miden::core::stark` | Top-level entry point that re-exports `verifier::verify`; the public STARK verification procedure. |
| `miden::core::stark::constants` | Defines memory layout constants and general constants used by the verifier. |
| `miden::core::stark::random_coin` | Contains procedures for sampling and updating the Poseidon2-based random coin used throughout the verifier. |
| `miden::core::stark::deep_queries` | Implements helper procedures for constructing DEEP queries. |
| `miden::core::stark::ood_frames` | Exposes helpers for processing out-of-domain evaluation frames. |
| `miden::core::stark::public_inputs` | Procedures for loading and hashing public inputs. |
| `miden::core::stark::verifier` | High-level procedures that orchestrate STARK proof verification. |
| `miden::core::stark::utils` | Miscellaneous helper functions shared by the verifier modules. |
