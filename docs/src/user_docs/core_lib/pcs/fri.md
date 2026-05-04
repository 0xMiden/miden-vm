---
title: "FRI Verification Procedures"
sidebar_position: 2
---

# FRI verification procedures
Namespace `miden::core::pcs::fri` contains modules for verifying [FRI](https://eccc.weizmann.ac.il/report/2017/134/) proofs.

## FRI Extension 2, Fold 4

Module `miden::core::pcs::fri::frie2f4` contains procedures for verifying FRI proofs generated over the quadratic extension of the Miden VM's base field. Moreover, the procedures assume that layer folding during the commit phase of FRI protocol was performed using folding factor 4.

| Procedure | Description |
| ----------- | ------------- |
| verify | Verifies a FRI proof where the proof was generated over the quadratic extension of the base field and layer folding was performed using folding factor 4.<br /><br />Input:  `[...]`<br />Output: `[...]`<br /><br />Cycles:<br />- Polynomial degree less than 64: `24 + num_queries * (107 + num_layers * 80)`<br />- Polynomial degree less than 128: `24 + num_queries * (140 + num_layers * 80)` |
