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
| verify | Verifies a FRI proof where the proof was generated over the quadratic extension of the base field and layer folding was performed using folding factor 4.<br /><br />Input:  `[query_start_ptr, query_end_ptr, layer_ptr, rem_ptr, g, ...]`><br />Output: `[...]`<br /><br />- `query_start_ptr` is a pointer to a list of tuples of the form `(e0, e1, p, 0)` where `p` is a query index at the first layer and `(e0, e1)` is an extension field element corresponding to the value of the first layer at index p.<br />- `query_end_ptr` is a pointer to the first empty memory address after the last `(e0, e1, p, 0)` tuple.<br />- `layer_ptr` is a pointer to the first layer commitment denoted throughout the code by C. `layer_ptr + 1` points to the first `(alpha0, alpha1, t_depth, d_size)` where `d_size` is the size of initial domain divided by 4, `t_depth` is the depth of the Merkle tree commitment to the first layer and `(alpha0, alpha1)` is the first challenge used in folding the first layer. Both `t_depth` and `d_size` are expected to be smaller than 2^32. Otherwise, the result of this procedure is undefined.<br />- `rem_ptr` is a pointer to the first tuple of two consecutive degree 2 extension field elements making up the remainder codeword. This codeword can be of length either 32 or 64.<br /><br />The memory referenced above is used contiguously, as follows:<br />`[layer_ptr ... rem_ptr ... query_start_ptr ... query_end_ptr]`<br /><br />This means for example that:<br />1. `rem_ptr - 1` points to the last `(alpha0, alpha1, t_depth, d_size)` tuple.<br />2. The length of the remainder codeword is `2 * (rem_ptr - query_start_ptr)`.<br /><br />Cycles: for domains of size `2^n` where:<br />- `n` is even: 12 + 6 + num_queries * (40 + num_layers * 76 + 69) + 2626<br />- `n` is odd:  12 + 6 + num_queries * (40 + num_layers * 76 + 69) + 1356 |
