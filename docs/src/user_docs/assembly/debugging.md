# Debugging

To support basic debugging capabilities, Miden assembly provides a `debug` instruction. This instruction prints out the state of the VM at the time when the `debug` instruction is executed. The instruction can be parameterized as follows:

- `debug.stack` prints out the entire contents of the stack.
- `debug.stack.<n>` prints out the top $n$ items of the stack. When $n=0$, the entire advice stack is printed.
- `debug.mem` prints out the entire contents of RAM.
- `debug.mem.<n>` prints out contents of memory at address $n$.
- `debug.mem.<n>.<m>` prints out the contents of memory starting at address $n$ and ending at address $m$ (both inclusive). $m$ must be greater or equal to $n$.
- `debug.local` prints out the whole local memory of the currently executing procedure.
- `debug.local.<n>` prints out contents of the local memory at index $n$ for the currently executing procedure. $n$ must be greater or equal to $0$ and smaller than $65536$.
- `debug.local.<n>.<m>` prints out contents of the local memory starting at index $n$ and ending at index $m$ (both inclusive). $m$ must be greater or equal to $n$. $n$ and $m$ must be greater or equal to $0$ and smaller than $65536$.
- `debug.adv_stack` prints out the entire contents of the advice stack.
- `debug.adv_stack.<n>` prints out the top $n$ items of the advice stack. When $n=0$, the entire advice stack is printed.

Debug instructions do not affect the VM state and do not change the program hash.

To make use of the `debug` instruction, programs must be compiled with an assembler instantiated in the debug mode. Otherwise, the assembler will simply ignore the `debug` instructions.
