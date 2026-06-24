---
title: "Debugging"
sidebar_position: 11
---

# Debugging

Miden assembly provides event-based debugging procedures through the `miden::core::debug` module. These procedures emit well-known events which the host handles by printing the requested piece of VM state (operand stack, memory, advice stack, or advice map).

The `miden::core::debug` module provides the following procedures:

- `print_stack` prints the entire operand stack (3 cycles).
- `print_mem` prints memory in the range `[start, end)` (5 cycles). Consumes `start` and `end` from the stack.
- `print_mem_all` prints the full memory of the current context (3 cycles).
- `print_adv_stack` prints the advice stack in the range `[start, end)` (5 cycles). Consumes `start` and `end` from the stack.
- `print_adv_stack_all` prints the full advice stack (7 cycles).
- `print_adv_map_all` prints the full advice map (3 cycles).
- `print_adv_map_item` looks up a WORD key in the advice map and prints the associated list of field elements (7 cycles). Consumes the key from the stack.

These procedures emit ordinary events and print whenever invoked, regardless of whether the program was assembled in debug mode. Because they are regular procedure calls, adding them changes the program being executed. Only stack-neutral procedures preserve the operand stack; procedures that consume stack inputs change VM state by removing those inputs. Remove these calls from production programs.

Default core handlers print stack and memory state. Advice stack and advice map printers require hosts to register `advice_debug_handlers()`, because they can reveal witness data.

To use these procedures, import the `miden::core::debug` module and call the appropriate procedure:

```masm
use miden::core::debug

begin
    push.1.2.3
    exec.debug::print_stack
end
```
