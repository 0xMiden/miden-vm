---
title: "Kernel ROM Chiplet"
sidebar_position: 6
---

# Kernel ROM chiplet

The kernel ROM authenticates procedures invoked by `SYSCALL`. A syscall executes in the root
context, and its export key must resolve to an authorized implementation digest in the kernel
identified by the public Merkle root $K$. The full export map is private execution data;
verification takes only $K$. Each accessed export supplies its path depth $d$ as private trace data.

## Kernel commitment

`KernelDescriptor` sorts unique export keys $k_i$ by their byte encoding. Each binding
$k_i \mapsto D_i$ is hashed as $L_i = H_{\mathrm{KERNEL\_EXPORT}}(k_i \mathbin{\|} D_i)$,
under the registered `KERNEL_EXPORT` Felt-sequence domain. The payload is exactly eight Felts:
one compression block `key | digest`, initialized with
`Eidos::init_chaining_word(KERNEL_EXPORT, 8)`. Stable syscall keys hash canonical exported
procedure paths under `KERNEL_KEY`; identity bindings $D_i \mapsto D_i$ authorize legacy syscalls.
Distinct keys may share an implementation digest.

These leaf hashes retain the key ordering and are followed by zero words up to
`max(2, next_power_of_two(number_of_exports))` leaves. Padding is raw zero, rather than a hashed
export pair.

Internal nodes use the standard VM Merkle hash. The empty kernel therefore has root
`merge(zero, zero)`. The descriptor allows at most 255 exports, so $1 \le d \le 8$.
Stable and identity bindings each count toward this limit.

The execution claim remains `P | K | I | O`. Chiplets public inputs contain only $K$.
Depth is a private kernel-row column, committed with the execution trace. It adds no public-input
field, proof metadata, or separate Fiat–Shamir observation.

The leaf domain differs from the Merkle inner-node domain. A path starting at an authenticated
leaf hash therefore cannot reinterpret an authorized export pair as an inner node, even if
the descriptor contains arbitrary words. The chiplet proves the leaf hash as well as its Merkle
membership. Authenticating an export through a zero padding leaf requires a hash preimage of
zero.

## Kernel ROM trace {#constraints}

There is one row per distinct accessed export key. Unused exports produce no kernel rows.
The ROM uses 17 internal columns within the unchanged shared Chiplets trace width:

```text
| selectors[5] | m | key[4] | digest[4] | start | index | bit | depth | leaf[4] | mode | clock |
```

| Field | Meaning |
|---|---|
| `m` | Number of syscalls to this export key |
| `key[4]` | Export key committed by the syscall node |
| `digest[4]` | Callee procedure digest |
| `start` | First hasher-controller row of this membership verification |
| `index` | Leaf index in the full canonical kernel tree |
| `bit` | Least significant bit of `index` |
| `depth` | Private path length, bound to the controller's final level |
| `leaf[4]` | Domain-separated hash of `key | digest`, authenticated against $K$ |

For example, if exports $a,b,c$ occupy indices 0,1,2 and calls use $a$ once and $c$ three times,
the kernel table has two rows, with multiplicities 1 and 3 and indices 0 and 2. Each row requests
one path verification, independently of its multiplicity.

## Lookup constraints

Using `require` for a consumed message and `provide` for a supplied message, an active kernel row
emits:

```text
public Chiplets inputs: K[4]

for each active kernel row:
    provide CompressionRequest(key | digest, KernelExportCV, leaf) count 1
    require Hasher.MerkleVerifyInit(start, index, bit, leaf)   count 1
    require Hasher.ReturnMerkleRoot(start + depth - 1, depth, K) count 1
    provide KernelRomCall(key, digest)                       count m

for each syscall:
    require KernelRomCall(key, executed_callee_digest)        count 1

for each terminal Merkle controller row:
    provide Hasher.ReturnMerkleRoot(clock, level + 1, digest) count 1

for each valid Eidos compression execution:
    require CompressionRequest(block, input_cv, output_cv) count compression_multiplicity
```

`KernelExportCV` is the fixed initial chaining word for `KERNEL_EXPORT` and payload length eight.
The compression-link lookup binds the syscall key and resolved implementation digest to the
export leaf, using one existing Eidos compression cycle. Kernel ROM rows provide the compression
request directly, so leaf hashing needs no additional controller operation or bus.

The existing hasher-controller constraints enforce the direction bit, index decomposition,
Merkle hashing, and path termination. One controller row represents one tree level, which makes
the final address `start + depth - 1`. Root-return messages also bind `depth = level + 1`,
which ties the requested ending to the same operation as `start`. A row cannot swap in another
path's ending by inventing a depth. A separate Merkle-return bus prevents ordinary hash outputs
from satisfying these requests. The syscall code commitment hashes `[key, 0]` in the syscall
MAST domain. The decoder carries the resolved implementation digest separately; the kernel-call
lookup authenticates `(key, digest)`, and the block-hash relation binds that digest to the body
actually executed.

Membership requests share the hash-kernel lookup column. Call responses use the chiplet response
column. There is no kernel-list boundary correction; the former `KernelRomInit` bus ID remains
reserved. The outer LogUp correction contains only the program-root and initial/final deferred-root
terms.

Trace generation appends membership operations after ordinary hasher operations, including when
the hasher was built during streaming execution. It then accounts for the added controller and
compression rows before choosing padded heights, collecting range checks, or enforcing the prover
memory budget. Leaf compression requests participate in the same sizing, deduplication, and range
accounting. The number of accessed export keys is maintained as calls are replayed, so checking the
kernel trace length does not rescan the export list after every syscall.
