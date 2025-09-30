---
title: "Flow Control"
sidebar_position: 4
---

## Flow control
As mentioned above, Miden assembly provides high-level constructs to facilitate flow control. These constructs are:

- *if-else* expressions for conditional execution.
- *repeat* expressions for bounded counter-controlled loops.
- *while* expressions for unbounded condition-controlled loops.

### Conditional execution
Conditional execution in Miden VM can be accomplished with *if-else* statements. These statements can take one of the following forms:

#### `if.true .. else .. end`

This is the full form, when there is work to be done on both branches:

    if.true
      ..instructions..
    else
      ..instructions..
    end


#### `if.true .. end`

This is the abbreviated form, for when there is only work to be done on one branch. In these cases the "unused" branch can be elided:

    if.true
      ..instructions..
    end

In addition to `if.true`, there is also `if.false`, which is identical in syntax, but for false-conditioned branches. It is equivalent in semantics to using `if.true` and swapping the branches.

The body of each branch, i.e. `..instructions..` in the examples above, can be a sequence of zero or more instructions (an empty body is only valid so long as at least one branch is non-empty). These can consist of any instruction, including nested control flow.

> [!TIP]
>
> As with other control structures described below that have nested blocks,
> it is essential that you ensure that the state of the operand stack is
> consistent at join points in control flow. For example, with `if.true`
> control flow implicitly joins at the end of each branch. If you have moved
> items around on the operand stack, or added/removed items, and those
> modifications would persist past the end of that branch, it is highly
> recommended that you make equivalent modifications in the opposite branch.
> This is not required if modifications are local to a block.

The semantics of the `if.true` and `if.false` control operator are as follows:

1. The condition is popped from the top of the stack. It must be a boolean value, i.e. $0$ for false, $1$ for true. If the condition is _not_ a boolean value, then execution traps.
2. The conditional branch is chosen:
  a.  If the operator is `if.true`, and the condition is true, instructions in the first branch are executed; otherwise, if the condition is false, then the second branch is executed. If a branch was elided or empty, the assembler provides a default body consisting of a single `nop` instruction.
  b. If the operator is `if.false`, the behavior is identical to that of `if.true`, except the condition must be false for the first branch to be taken, and true for the second branch.
3. Control joins at the next instruction immediately following the `if.true`/`if.false` instruction.

> [!TIP]
>
> A note on performance: using *if-else* statements incurs a small, but non-negligible overhead. Thus, for simple conditional statements, it may be more efficient to compute the result of both branches, and then select the result using [conditional drop](./stack_manipulation.md#conditional-manipulation) instructions.
>
> This does not apply to *if-else* statements whose bodies contain side-effects that cannot be easily adapted to this type of rewrite. For example, writing a value to global memory is a side effect, but if both branches would write to the same address, and only the value being written differs, then this can likely be rewritten to use `cdrop`.


### Counter-controlled loops
Executing a sequence of instructions a predefined number of times can be accomplished with *repeat* statements. These statements look like so:
```
repeat.<count>
    <instructions>
end
```
where:

* `instructions` can be a sequence of any instructions, including nested control structures.
* `count` is the number of times the `instructions` sequence should be repeated (e.g. `repeat.10`). `count` must be an integer or a [constant](./code_organization.md#constants) greater than $0$.

> **Note**: During compilation the `repeat.<count>` blocks are unrolled and expanded into `<count>` copies of its inner block, there is no additional cost for counting variables in this case.

### Condition-controlled loops
Executing a sequence of instructions zero or more times based on some condition can be accomplished with *while loop* expressions. These expressions look like so:
```
while.true
    <instructions>
end
```
where `instructions` can be a sequence of any instructions, including nested control structures. The above does the following:

1. Pops the top item from the stack.
2. If the value of the item is $1$, `instructions` in the loop body are executed.
    1. After the body is executed, the stack is popped again, and if the popped value is $1$, the body is executed again.
    2. If the popped value is $0$, the loop is exited.
    3. If the popped value is not binary, the execution fails.
3. If the value of the item is $0$, execution of loop body is skipped.
4. If the value is not binary, the execution fails.

Example:

```
# push the boolean true to the stack
push.1

# pop the top element of the stack and loop while it is true
while.true
    # push the boolean false to the stack, finishing the loop for the next iteration
    push.0
end
```

### No-op

While rare, there may be situations where you have an empty block and require a do-nothing placeholder instruction, or where you specifically want to advance the cycle counter without any side-effects. The `nop` instruction can be used in these instances.

```
if.true
  nop
else
  ..instructions..
end
```

In the example above, we do not want to perform any work if the condition is true, so we place a `nop` in that branch. This explicit representation of "empty" blocks is automatically done by the assembler when parsing `if.true` or `if.false` in abbreviated form, or when one of the branches is empty.

The semantics of this instruction are to increment the cycle count, and that is it - no other effects.
