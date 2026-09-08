---
title: "Multiset Checks"
sidebar_position: 2
---

# Multiset checks

A [multiset check](https://hackmd.io/@relgabizon/ByFgSDA7D) proves that two collections contain the
same elements with the same multiplicities, regardless of order. Both [virtual tables](#virtual-tables)
and [communication buses](./index.md#communication-buses-in-miden-vm) have these semantics. This
page presents the standard running-product construction for intuition; Miden VM enforces its
multiset relations with [LogUp](./logup.md).

## Running product columns

One way to compare two vectors $a$ and $b$ as multisets is to use a single running-product column:

- The running product column is initialized to a value $x$ at the beginning of the trace. (We typically use $x = 1$.)
- All values of $a$ are multiplied into the running product column.
- All values of $b$ are divided out of the running product column.
- If $a$ and $b$ were multiset equal, then the running product column will equal $x$ at the end of the trace.

The row values are encoded using random challenges $\alpha_0, \alpha_1, \ldots$ sent to the prover
after it commits to the execution trace.

## Virtual tables

Virtual tables can be used to store intermediate data which is computed at one cycle and used at a different cycle. When the data is computed, the row is added to the table, and when it is used later, the row is deleted from the table. Thus, all that needs to be proved is the data consistency between the row that was added and the row that was deleted.

The consistency of a virtual table can be proved with a single trace column $p$, which keeps a
running product of rows that were inserted into and deleted from the table. This is done by
reducing each row to a single value, multiplying the value into $p$ when the row is inserted, and
dividing the value out of $p$ when the row is removed. Thus, at any step of the computation, $p$
contains a product of all rows currently in the table.

The initial value of $p$ is set to 1. If the table is empty when the computation finishes, the final
value of $p$ is also 1. Boundary constraints enforce these initial and final values.

### Computing a virtual table's trace column

To compute a product of rows, each row is first reduced to a single value.

Let $t_0, t_1, t_2, ...$ be columns in the virtual table, and assume the verifier sends a set of random values $\alpha_0$, $\alpha_1, ...$ to the prover after the prover commits to the execution trace of the program.

The prover reduces row $i$ in the table to a single value $r_i$ as:

$$
r_i = \alpha_0 + \alpha_1 \cdot t_{0, i} + \alpha_2 \cdot t_{1, i} + \alpha_3 \cdot t_{2, i} + ...
$$

Then, when row $i$ is added to the table, we'll update the value in the $p$ column like so:

$$
p' = p \cdot r_i
$$

Analogously, when row $i$ is removed from the table, we'll update the value in column $p$ like so:

$$
p' = \frac{p}{r_i}
$$

### Virtual tables in Miden VM

Miden VM's [virtual-table relations](./index.md#virtual-tables-in-miden-vm) retain the
insertion-and-removal semantics above, but their auxiliary columns use the signed LogUp
construction rather than a running product.

## Communication buses {#communication-buses}

A communication bus can be modeled as a multiset equality between requests and responses. In a
running-product realization, a single trace column $b$ records the communication as follows:

- Each request is encoded from the operation type, inputs, and outputs, then divided out of the
  running-product column $b$.
- Each provider response encodes the same data and is multiplied into $b$.

Thus, if the requests and responses match, and the bus column $b$ is initialized to $1$, then $b$ will start and end with the value $1$. This condition is enforced by boundary constraints on column $b$.

Note that the order of the requests and responses does not matter, as long as they are all included in $b$. In fact, requests and responses for the same operation will generally occur at different cycles. Additionally, there could be multiple requests sent in the same cycle, and there could also be a response provided at the same cycle that a request is received.

### Communication bus constraints

These constraints have two requirements:

- The lookup value must be computed using random values $\alpha_0, \alpha_1$, etc. that are provided by the verifier after the prover has committed to the main execution trace.
- The lookup value must include all uniquely identifying information for the component/operation and its inputs and outputs.

Given an example operation $op_{ex}$ with inputs $i_0, ..., i_n$ and outputs $o_0, ..., o_m$, the lookup value can be computed as follows:

$$lookup = \alpha_0 + \alpha_1 \cdot op_{ex} + \alpha_2 \cdot i_0 + ... + \alpha_{n+2} \cdot i_n + \alpha_{n+3} \cdot o_0 + ... + \alpha_{n + 2 + m} \cdot o_m$$

The constraint for sending this to the bus as a request would be:

$$b' \cdot lookup = b$$

The constraint for sending this to the bus as a response would be:

$$b' = b \cdot lookup$$

However, these constraints must be combined, since it's possible that requests and responses both occur during the same cycle.

To combine them, let $u_{lookup}$ be the request value and let $v_{lookup}$ be the response value. These values are both computed the same way as shown above, but the data sources are different, since the input/output values used to compute $u_{lookup}$ come from the trace of the component that's "offloading" the computation, while the input/output values used to compute $v_{lookup}$ come from the trace of the specialized component.

The final constraint can be expressed as:

$$b' \cdot u_{lookup} = b \cdot v_{lookup}$$

### Communication buses in Miden VM

The native VM execution proof applies these multiset semantics to typed relations among the Core,
Chiplets, Eidos compression, and And8 lookup AIRs. It uses domain-separated LogUp: providers emit
positive fractions, consumers emit matching negative fractions, and the verifier checks their
cross-AIR balance. See [LogUp usage in Miden VM](./logup.md#usage-in-miden-vm) for the encoding,
per-relation sign conventions, and closure equations.
