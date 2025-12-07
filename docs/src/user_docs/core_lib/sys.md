---
title: "System Procedures"
sidebar_position: 7
---

# System procedures
Module `miden::core::sys` contains a set of system-level utility procedures.

| Procedure      | Description   |
| -------------- | ------------- |
| truncate_stack | Removes elements deep in the stack until the depth of the stack is exactly 16. The elements are removed in such a way that the top 16 elements of the stack remain unchanged. If the stack would otherwise contain more than 16 elements at the end of execution, then adding a call to this function at the end will reduce the size of the public inputs that are shared with the verifier.<br/>Input: Stack with 16 or more elements.<br/> Output: Stack with only the original top 16 elements. |
