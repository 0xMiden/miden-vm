---
title: "VM Utilities"
sidebar_position: 8
---

# miden::core::sys::vm

Namespace `miden::core::sys::vm` contains low-level helper procedures that are primarily intended for use by the Miden VM recursive verifier.

## Modules

| Module | Description |
| --- | --- |
| `miden::core::sys::vm::constraints_eval` | Procedures that perform the constraints evaluation check and manage its associated parameters. |
| `miden::core::sys::vm::deep_queries` | Utilities that construct the DEEP queries needed during proof verification. |
| `miden::core::sys::vm::mod` | Entry-point procedures that orchestrate the overall recursive verification flow. |
| `miden::core::sys::vm::ood_frames` | Helpers for processing out-of-domain evaluation frames. |
| `miden::core::sys::vm::public_inputs` | Routines for loading, hashing, and processing public inputs. |
