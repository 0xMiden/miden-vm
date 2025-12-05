---
title: "Overview"
sidebar_position: 2
---

# Miden VM overview

Miden VM is a stack machine. The base data type of the VM is a field element in a 64-bit [prime field](https://en.wikipedia.org/wiki/Finite_field) defined by modulus $p = 2^{64} - 2^{32} + 1$. This means that all values that the VM operates with are field elements in this field (i.e., values between $0$ and $2^{64} - 2^{32}$, both inclusive).

Miden VM consists of four high-level components as illustrated below.

![vm_components](./img/intro/vm_components.png)

These components are:

- **Stack** which is a push-down stack where each item is a field element. Most assembly instructions operate with values located on the stack. The stack can grow up to $2^{32}$ items deep, however, only the top 16 items are directly accessible.
- **Memory** which is a linear random-access read-write memory. The memory is element-addressable, meaning, a single element is located at each address. However, there are instructions to read and write elements to/from memory both individually or in batches of four, since the latter is quite common. Memory addresses can be in the range $[0, 2^{32})$.
- **Chiplets** which are specialized circuits for accelerating certain types of computations. These include Rescue Prime Optimized (RPO) hash function, 32-bit binary operations, and 16-bit range checks.
- **Host** which is a way for the prover to communicate with the VM during runtime. This includes responding to the VM's requests for non-deterministic inputs and handling messages sent by the VM (e.g., for debugging purposes). The requests for non-deterministic inputs are handled by the host's _advice provider_.

Miden VM comes with a default implementation of the host interface (with an in-memory advice provider). However, the users are able to provide their own implementations which can connect the VM to arbitrary data sources (e.g., a database or RPC calls) and define custom logic for handling events emitted by the VM.

## Writing programs

Our goal is to make Miden VM an easy compilation target for high-level languages such as Rust, Move, Sway, and others. We believe it is important to let people write programs in the languages of their choice. However, compilers to help with this have not been developed yet. Thus, for now, the primary way to write programs for Miden VM is to use [Miden assembly](./user_docs/assembly/index.md).

While writing programs in assembly is far from ideal, Miden assembly does make this task a little bit easier by supporting high-level flow control structures and named procedures.

## Inputs and outputs

External inputs can be provided to Miden VM in two ways:

1. Public inputs can be supplied to the VM by initializing the stack with desired values before a program starts executing. At most 16 values can be initialized in this way, so providing more than 16 values will cause an error.
2. Secret (or nondeterministic) inputs can be supplied to the VM via the [_advice provider_](#nondeterministic-inputs). There is no limit on how much data the advice provider can hold.

After a program finishes executing, the elements remaining on the stack become the outputs of the program. Notice that having more than 16 values on the stack at the end of execution will cause an error, so the values beyond the top 16 elements of the stack should be dropped. We've provided the [`truncate_stack`](./user_docs/libcore/sys.md) utility procedure in the core library for this purpose.

The number of public inputs and outputs of a program can be reduced by making use of the advice stack and Merkle trees. Just 4 elements are sufficient to represent a root of a Merkle tree, which can be expanded into an arbitrary number of values.

For example, if we wanted to provide a thousand public input values to the VM, we could put these values into a Merkle tree, initialize the stack with the root of this tree, initialize the advice provider with the tree itself, and then retrieve values from the tree during program execution using `mtree_get` instruction (described [here](./user_docs/assembly/cryptographic_operations.md#hashing-and-merkle-trees)).

### Stack depth restrictions

For reasons explained [here](./design/stack/index.md), the VM imposes the restriction that the stack depth cannot be smaller than $16$. This has the following effects:

- When initializing a program with fewer than $16$ inputs, the VM will pad the stack with zeros to ensure the depth is $16$ at the beginning of execution.
- If an operation would result in the stack depth dropping below $16$, the VM will insert a zero at the deep end of the stack to make sure the depth stays at $16$.

### Nondeterministic inputs

The _advice provider_ component is responsible for supplying nondeterministic inputs to the VM. These inputs only need to be known to the prover (i.e., they do not need to be shared with the verifier).

The advice provider consists of three components:

- **Advice stack** which is a one-dimensional array of field elements. Being a stack, the VM can either push new elements onto the advice stack, or pop the elements from its top.
- **Advice map** which is a key-value map where keys are words and values are vectors (dynamic arrays) of field elements. The VM can copy values from the advice map onto the advice stack as well as insert new values into the advice map (e.g., from a region of memory).
- **Merkle store** which contain structured data reducible to Merkle paths. Some examples of such structures are: Merkle tree, Sparse Merkle Tree, and a collection of Merkle paths. The VM can request Merkle paths from the Merkle store, as well as mutate it by updating or merging nodes contained in the store.

The prover initializes the advice provider prior to executing a program, and from that point on the advice provider is manipulated solely by executing operations on the VM. **Security note:** When reading data from the advice provider, we can't assume it is valid - we always have to verify this (e.g., when writing and then reading the data, we need to make sure that the data we read hashes to some expected value).
