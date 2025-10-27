---
title: "System Operations"
sidebar_position: 3
---

# System Operations
In this section we describe the AIR constraints for Miden VM system operations.

## NOOP
The `NOOP` operation advances the cycle counter but does not change the state of the operand stack (i.e., the depth of the stack and the values on the stack remain the same).

The `NOOP` operation does not impose any constraints besides the ones needed to ensure that the entire state of the stack is copied over. This constraint looks like so:

$$
s'_i - s_i = 0 \ \text{ for } i \in [0, 16) \text { | degree} = 1
$$

## EMIT
The `EMIT` operation interrupts execution for a single cycle and hands control to the host. During this interruption, the host can read the current state of the execution and modify the advice provider as it sees fit. From the VM's perspective, this operation has exactly the same semantics as [`NOOP`](#noop) - the operand stack remains completely unchanged.

By convention, the top element of the stack is used to encode an event ID (see the [events documentation](../../user_docs/assembly/events.md) for details on event structure and usage). The host can use this event ID to determine what actions to take during the execution interruption.

## ASSERT
The `ASSERT` operation pops an element off the stack and checks if the popped element is equal to $1$. If the element is not equal to $1$, program execution fails.

![assert](../../img/design/stack/system_ops/ASSERT.png)

Stack transition for this operation must satisfy the following constraints:

$$
s_0 - 1 = 0 \text{ | degree} = 1
$$

The effect on the rest of the stack is:
* **Left shift** starting from position $1$.

## CLK
The `CLK` operation pushes the current value of the clock cycle onto the stack. The diagram below illustrates this graphically.

![clk](../../img/design/stack/system_ops/CLK.png)

The stack transition for this operation must follow the following constraint:

$$
s_0' - clk = 0 \text{ | degree} = 1
$$

The effect on the rest of the stack is:
* **Right shift** starting from position $0$.
