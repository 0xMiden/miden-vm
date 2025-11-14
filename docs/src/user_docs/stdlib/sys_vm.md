---
title: "VM Utilities"
sidebar_position: 8
---

# std::sys::vm

Namespace `std::sys::vm` contains low-level helper procedures that are primarily intended for use by the Miden VM recursive verifier.

## Modules

| Module | Description |
| --- | --- |
| `std::sys::vm::constraints_eval` | Procedures that perform the constraints evaluation check and manage its associated parameters. |
| `std::sys::vm::deep_queries` | Utilities that construct the DEEP queries needed during proof verification. |
| `std::sys::vm::mod` | Entry-point procedures that orchestrate the overall recursive verification flow. |
| `std::sys::vm::ood_frames` | Helpers for processing out-of-domain evaluation frames. |
| `std::sys::vm::public_inputs` | Routines for loading, hashing, and processing public inputs. |