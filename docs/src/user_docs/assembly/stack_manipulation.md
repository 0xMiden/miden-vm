## Stack manipulation
Miden VM stack is a push-down stack of field elements. The stack has a maximum depth of $2^{32}$, but only the top $16$ elements are directly accessible via the instructions listed below.

In addition to the typical stack manipulation instructions such as `drop`, `dup`, `swap` etc., Miden assembly provides several conditional instructions which can be used to manipulate the stack based on some condition - e.g., conditional swap `cswap` or conditional drop `cdrop`.

| Instruction                      | Stack_input        | Stack_output       | Notes                                                                                                                                |
| -------------------------------- | ------------------ | ------------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| drop <br> - *(1 cycle)*          | [a, ... ]          | [ ... ]            | Deletes the top stack item.                                                                                                          |
| dropw <br> - *(4 cycles)*        | [A, ... ]          | [ ... ]            | Deletes a word (4 elements) from the top of the stack.                                                                               |
| padw  <br> - *(4 cycles)*        | [ ... ]            | [0, 0, 0, 0, ... ] | Pushes four $0$ values onto the stack. <br> Note: simple `pad` is not provided because `push.0` does the same thing.                 |
| dup.*n* <br> - *(1-3 cycles)*    | [ ..., a, ... ]    | [a, ..., a, ... ]  | Pushes a copy of the $n$th stack item onto the stack. `dup` and `dup.0` are the same instruction. Valid for $n \in \{0, ..., 15\}$   |
| dupw.*n* <br> - *(4 cycles)*     | [ ..., A, ... ]    | [A, ..., A, ... ]  | Pushes a copy of the $n$th stack word onto the stack. `dupw` and `dupw.0` are the same instruction. Valid for $n \in \{0, 1, 2, 3\}$ |
| swap.*n* <br> - *(1-6 cycles)*   | [a, ..., b, ... ]  | [b, ..., a, ... ]  | Swaps the top stack item with the $n$th stack item. `swap` and `swap.1` are the same instruction. Valid for $n \in \{1, ..., 15\}$   |
| swapw.*n* <br> - *(1 cycle)*     | [A, ..., B, ... ]  | [B, ..., A, ... ]  | Swaps the top stack word with the $n$th stack word. `swapw` and `swapw.1` are the same instruction. Valid for $n \in \{1, 2, 3\}$    |
| swapdw <br> - *(1 cycle)*        | [D, C, B, A, ... ] | [B, A, D, C ... ]  | Swaps words on the top of the stack. The 1st with the 3rd, and the 2nd with the 4th.                                                 |
| movup.*n* <br> - *(1-4 cycles)*  | [ ..., a, ... ]    | [a, ... ]          | Moves the $n$th stack item to the top of the stack. Valid for $n \in \{2, ..., 15\}$                                                 |
| movupw.*n* <br> - *(2-3 cycles)* | [ ..., A, ... ]    | [A, ... ]          | Moves the $n$th stack word to the top of the stack. Valid for $n \in \{2, 3\}$                                                       |
| movdn.*n* <br> - *(1-4 cycles)*  | [a, ... ]          | [ ..., a, ... ]    | Moves the top stack item to the $n$th position of the stack. Valid for $n \in \{2, ..., 15\}$                                        |
| movdnw.*n* <br> - *(2-3 cycles)* | [A, ... ]          | [ ..., A, ... ]    | Moves the top stack word to the $n$th word position of the stack. Valid for $n \in \{2, 3\}$                                         |
| reversew <br> - *(3 cycles)*     | [a, b, c, d, ... ] | [d, c, b, a, ... ] | Reverses the order of the top four stack elements (a word).                                                                          |
| reversedw <br> - *(7 cycles)*    | [a, b, c, d, e, f, g, h, ... ] | [h, g, f, e, d, c, b, a, ... ] | Reverses the order of the top eight stack elements (double word).                                                                    |

### Conditional manipulation

| Instruction                 | Stack_input       | Stack_output       | Notes                                                                                                                                                                                       |
| --------------------------- | ----------------- | ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| cswap  <br> - *(1 cycle)*   | [c, b, a, ... ]   | [e, d, ... ]       | $d = \begin{cases} a, & \text{if}\ c = 0 \\ b, & \text{if}\ c = 1\ \end{cases}$ <br> $e = \begin{cases} b, & \text{if}\ c = 0 \\ a, & \text{if}\ c = 1\ \end{cases}$  <br> Fails if $c > 1$ |
| cswapw  <br> - *(1 cycle)*  | [c, B, A, ... ]   | [E, D, ... ]       | $D = \begin{cases} A, & \text{if}\ c = 0 \\ B, & \text{if}\ c = 1\ \end{cases}$ <br> $E = \begin{cases} B, & \text{if}\ c = 0 \\ A, & \text{if}\ c = 1\ \end{cases}$  <br> Fails if $c > 1$ |
| cdrop   <br> - *(2 cycles)* | [c, b, a, ... ]   | [d, ... ]          | $d = \begin{cases} a, & \text{if}\ c = 0 \\ b, & \text{if}\ c = 1\ \end{cases}$ <br> Fails if $c > 1$                                                                                       |
| cdropw  <br> - *(5 cycles)* | [c, B, A, ... ]   | [D, ... ]          | $D = \begin{cases} A, & \text{if}\ c = 0 \\ B, & \text{if}\ c = 1\ \end{cases}$ <br> Fails if $c > 1$                                                                                       |
