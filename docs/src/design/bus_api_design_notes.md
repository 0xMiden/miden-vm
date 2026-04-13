# Bus API Design Notes

Discussion notes on the next-generation API for describing LogUp bus interactions.
The goal is a single interaction description that serves both **constraint evaluation**
(symbolic, all paths evaluated) and **prover fraction generation** (concrete, only
active interactions computed), with zero heap allocations and minimal wasted EF×BF work.

These notes reference the current implementation in `air/src/constraints/logup.rs`,
`logup_bus.rs`, and `logup_msg.rs`.

---

## 1. Motivation

The current API (`RationalSet`, `Batch`, `Column`) is constraint-evaluation-only.
The prover's auxiliary trace generation is a completely separate code path. We want to
converge toward a single interaction description that drives both:

- **Constraint evaluation**: symbolic expressions, all interactions evaluated
  unconditionally, EF×BF multiplications are the dominant cost.
- **Prover trace generation**: concrete field values, only active interactions
  computed, branching on selector flags to skip work.

### Current pain points

1. **Redundant encoding**: chiplet response messages (hasher, memory, bitwise) that
   share column values across ME variants re-encode them independently. For the 7
   hasher chiplet responses, `addr` and `node_index` are encoded 7 times each.

2. **Conditional messages**: `MemoryResponseMsg` does arithmetic conditional selection
   inside `encode()` — computing two full EF encodings then muxing the results. This
   wastes ~40% of EF work compared to alternatives.

3. **No code sharing**: constraint and prover paths are entirely separate, with no
   shared interaction description.

---

## 2. Key Constraints

### Degree budget

Pre-muxing fields inside the encoding (i.e., `encode(Σ flag_i · field_ij)`) is
**degree-toxic** when variant flags are high degree. The ME set accumulation computes:

```
U = 1 + Σ (v_r − 1) · s_r
```

If `v_r = encode(flag · field)`, then `deg(v_r) = deg(flag) + deg(field)`, and
`deg((v_r − 1) · s_r)` doubles the flag contribution. For hasher flags at degree 5,
pre-muxing would give degree 11 — far over the budget of 9.

**Rule**: variant flags must stay OUTSIDE the encoding, in the `U/V` accumulation only.
Each ME variant gets its own `encode()` call with non-conditional fields.

Pre-muxing is safe only when the variant flag is low-degree. Memory's `is_word`
(degree 1) is the one case where it works — but we prefer the uniform approach of
separate ME entries for simplicity.

### Zero allocation

The prover path must not heap-allocate per row. The only allocation is pushing
`(multiplicity, denominator)` pairs onto a pre-allocated buffer for active
interactions.

### Closure-based laziness

Both `add_single(flag, || msg)` and `add_encoded(flag, || v)` take closures. For
constraints (`RationalSet`), the closure is always called. For prover
(`FractionCollector`), the closure is called only when `flag != 0`. This gives
both paths exactly the laziness they need without branching in the generic code.

---

## 3. The `InteractionSink` Trait

Abstracts over the accumulation backend. Both `RationalSet` (constraints) and a future
`FractionCollector` (prover) implement it.

```rust
trait InteractionSink<E, EF> {
    fn challenges(&self) -> &Challenges<EF>;

    // Default path: construct message, encode it internally.
    fn add_single<M: LogUpMessage<E, EF>>(&mut self, flag: E, msg_fn: impl FnOnce() -> M);
    fn remove_single<M: LogUpMessage<E, EF>>(&mut self, flag: E, msg_fn: impl FnOnce() -> M);
    fn add_batch(&mut self, flag: E, build: impl FnOnce(&mut Batch<E, EF>));

    // Optimized path: denominator already computed externally.
    fn add_encoded(&mut self, flag: E, v_fn: impl FnOnce() -> EF);
    fn remove_encoded(&mut self, flag: E, v_fn: impl FnOnce() -> EF);
    fn insert_encoded(&mut self, flag: E, m: E, v_fn: impl FnOnce() -> EF);

    // Existing helpers (insert_me, replace, always, etc.)
}
```

For `RationalSet`: closures always called. `add_encoded` folds `(v − 1) · flag` into
`U` and `flag` into `V`.

For `FractionCollector`: checks `flag != 0` before calling any closure. Active
interactions push `(m, d)` onto the buffer.

---

## 4. The `InteractionGroup` Trait

The core abstraction. A group of related interactions with an optional
constraint-path optimization.

```rust
trait InteractionGroup<E, EF> {
    /// The canonical description: each interaction with its flag and message.
    /// This is the prover default — the sink skips inactive flags.
    fn fold(self, sink: &mut impl InteractionSink<E, EF>);

    /// Constraint evaluation override: all interactions are evaluated
    /// unconditionally, so shared encoding fragments can be precomputed.
    /// Default: delegates to fold().
    fn fold_constraints(self, set: &mut RationalSet<'_, E, EF>)
    where Self: Sized
    {
        self.fold(set)
    }
}
```

### Design rationale

- **`fold` is the source of truth** — the readable interaction inventory. It
  describes each `(flag, message)` pair. This doubles as the prover path: the sink
  skips closures for zero flags, so only the active interaction encodes.

- **`fold_constraints` is the optimization hook** — overridden only when there are
  shared encoding fragments worth caching. The default just delegates to `fold`.

- **Prover path is the default, constraint path is the override.** Under mutual
  exclusivity, only one interaction is active per row — the natural description
  enumerates each possibility and lets the sink pick. The constraint path deviates by
  evaluating everything unconditionally and can exploit shared structure.

### Dispatch

```rust
impl RationalSet {
    pub fn add_group(&mut self, group: impl InteractionGroup<E, EF>) {
        group.fold_constraints(self);  // uses override if available
    }
}

impl FractionCollector {
    pub fn add_group(&mut self, group: impl InteractionGroup<E, EF>) {
        group.fold(self);  // always uses the generic path
    }
}
```

### Usage pattern

Components that don't benefit from caching just implement `fold`:

```rust
impl InteractionGroup<E, EF> for BitwiseResponse<E, M> {
    fn fold(self, sink: &mut impl InteractionSink<E, EF>) {
        sink.add_single(self.flag, || self.msg);
    }
}
```

Components with shared structure override `fold_constraints`:

```rust
impl InteractionGroup<E, EF> for HasherResponses<E> {
    fn fold(self, sink: &mut impl InteractionSink<E, EF>) {
        // 7 independent add_single calls — prover skips 6 of 7
        sink.add_single(self.f_bp, || HasherMsg::State { ... });
        sink.add_single(self.f_mp, || HasherMsg::Word { ... });
        // ...
    }

    fn fold_constraints(self, set: &mut RationalSet<'_, E, EF>) {
        // Precompute shared fragments, emit with add_encoded closures
        let (base, h4, h12, leaf4, rate8) = { /* 26 EF×BF muls */ };
        set.add_encoded(self.f_bp, || base + label + h12);
        // ...
    }
}
```

Simple components and optimized components coexist in the same function:

```rust
set.add_group(HasherResponses::new(...));           // optimized
set.add_single(is_bitwise, || BitwiseMsg { ... });  // default, no wrapper needed
set.add_group(MemoryResponses { ... });              // optimized
set.add_single(is_ace, || AceInitMsg { ... });       // default
```

---

## 5. Encoding Cache Strategy

### How it works

The encoding `v = α + Σ β^i · field_i` breaks down into EF×BF multiplications
(`β^i · field_i`). When multiple ME messages share field values at the same β
positions, those products can be computed once and reused.

The `fold_constraints` override precomputes shared products in a scoped block (to
release the `set.challenges()` borrow), then emits each variant using `add_encoded`
closures that assemble from cached fragments with pure EF additions.

```rust
fn fold_constraints(self, set: &mut RationalSet<'_, E, EF>) {
    // Phase 1: precompute (borrows challenges)
    let (base, h4, h12, leaf4, rate8) = {
        let ch = set.challenges();
        // ... EF×BF multiplications ...
    }; // borrow released

    // Phase 2: emit (borrows set mutably)
    // Each closure: 0 EF×BF, just EF clones + additions.
    set.add_encoded(flag, || base.clone() + label_constant + fragment.clone());
}
```

### Where it helps

Analysis of all main-trace and chiplet-trace groups, counting EF×BF multiplications:

**Chiplet trace (C1: chiplet bus responses)**

| Component | Variants | Without cache | With cache | Savings |
|-----------|----------|---------------|------------|---------|
| Hasher responses | 7 ME | 62 | 26 | **58%** |
| Memory responses | 2 ME | 13 | 8 | **38%** |
| Bitwise | 1 | 4 | 4 | — |
| ACE init | 1 | 6 | 6 | — |
| Kernel ROM | 1 | 5 | 5 | — |
| **C1 total** | | **90** | **49** | **46%** |

Hasher cache breakdown:
- `base = α + β¹·addr + β²·node_index`: 2 EF×BF (shared by all 7)
- `h4 = β³·h[0] + … + β⁶·h[3]`: 4 EF×BF (checkpoint, used by f_hout)
- `h12 = h4 + β⁷·h[4] + … + β¹⁴·h[11]`: +8 EF×BF (used by f_bp, f_sout)
- `leaf4 = β³·leaf[0] + … + β⁶·leaf[3]`: 4 EF×BF (used by f_mp, f_mv, f_mu)
- `rate8 = β³·h_next[0] + … + β¹⁰·h_next[7]`: 8 EF×BF (used by f_abp)

**Main trace groups**

| Group | Interactions | Without cache | With cache | Savings | Worth grouping? |
|-------|-------------|---------------|------------|---------|-----------------|
| G_bstack | 8 | ~45 | ~35 | 22% | No |
| G_bqueue | 6 | 32 | 15 | **53%** | **Yes** |
| G_creq (control blocks) | 6 | 54 | 9 | **83%** | **Yes** |
| G_creq (memory ops) | 4 | 12 | 3 | **75%** | **Yes** |
| G_creq (rest) | ~10 | ~210 | ~210 | 0% | No |
| G_opgrp | 4 | ~20 | ~17 | 15% | No |
| G_rtable | 1 | ~1 | ~1 | — | No |
| G_rstack_logcap | 2 | ~10 | ~10 | — | No |

G_bqueue sharing: `β⁰·addr_next` (all 6 messages) and `β¹..β⁴·h_first` (4 messages).

G_creq control block sharing: JOIN, SPLIT, LOOP, SPAN, CALL, SYSCALL all use
`control_block(addr_next, he, opcode)` — everything shared except the opcode constant.

G_creq memory sharing: MLOAD, MSTORE, MLOADW, MSTOREW share `MemoryHeader { ctx, s0, clk }`.

### Total savings

Across all constraint groups: **~108 EF×BF muls per row** saved.
In a quadratic extension: **~216 base-field muls per row**.

---

## 6. Concrete Example: Hasher Chiplet Responses

### Struct

```rust
struct HasherResponses<E> {
    f_bp: E, f_mp: E, f_mv: E, f_mu: E,
    f_hout: E, f_sout: E, f_abp: E,
    addr: E, node_index: E,
    h: [E; 12], leaf: [E; 4], h_next_rate: [E; 8],
}
```

Constructor computes flags from raw selectors:

```rust
impl HasherResponses<E> {
    fn new(is_hasher, cycle_row_0, cycle_row_31, hs0, hs1, hs2,
           addr, node_index, h, leaf, h_next_rate) -> Self {
        Self {
            f_bp: is_hasher * f_bp(cycle_row_0, hs0, hs1, hs2),
            // ... 6 more flags ...
            addr, node_index, h, leaf, h_next_rate,
        }
    }
}
```

### `fold` — prover default

Each interaction is an independent `add_single`. The sink skips closures for zero
flags. On a hasher row, exactly 1 of 7 closures fires — one message construction,
one encode call.

```rust
fn fold(self, sink: &mut impl InteractionSink<E, EF>) {
    sink.add_single(self.f_bp, || HasherMsg::State {
        label_value: LINEAR_HASH_LABEL + 16,
        addr: self.addr, node_index: self.node_index, state: self.h,
    });
    sink.add_single(self.f_mp, || HasherMsg::Word {
        label_value: MP_VERIFY_LABEL + 16,
        addr: self.addr, node_index: self.node_index, word: self.leaf,
    });
    // ... f_mv, f_mu, f_hout, f_sout, f_abp ...
}
```

### `fold_constraints` — cached encoding override

Phase 1 precomputes 26 EF×BF muls. Phase 2 emits 7 closures that do pure EF
additions.

```rust
fn fold_constraints(self, set: &mut RationalSet<'_, E, EF>) {
    let (base, h4, h12, leaf4, rate8) = {
        let ch = set.challenges();
        let base = ch.alpha + ch.beta_powers[1] * self.addr
                             + ch.beta_powers[2] * self.node_index;
        let mut h4 = EF::ZERO;
        for i in 0..4 { h4 += ch.beta_powers[3+i] * self.h[i]; }
        let mut h12 = h4.clone();
        for i in 4..12 { h12 += ch.beta_powers[3+i] * self.h[i]; }
        // ... leaf4, rate8 ...
        (base, h4, h12, leaf4, rate8)
    };

    set.add_encoded(self.f_bp,   || base + label_bp   + h12);
    set.add_encoded(self.f_mp,   || base + label_mp   + leaf4);
    set.add_encoded(self.f_mv,   || base + label_mv   + leaf4);
    set.add_encoded(self.f_mu,   || base + label_mu   + leaf4);
    set.add_encoded(self.f_hout, || base + label_hout + h4);
    set.add_encoded(self.f_sout, || base + label_sout + h12);
    set.add_encoded(self.f_abp,  || base + label_abp  + rate8);
}
```

### Call site

```rust
let g_chiplet_resp = {
    let mut set = RationalSet::new(&challenges);

    set.add_group(HasherResponses::new(
        is_hasher, cycle_row_0, cycle_row_31, hs0, hs1, hs2,
        hasher_addr, node_index, h, leaf_word(&h, &bit),
        array::from_fn(|i| h_next[i]),
    ));

    set.add_single(is_bitwise, || BitwiseResponseMsg { label, a, b, z });
    set.add_single(is_memory, || compute_memory_response_msg(local));
    set.add_single(is_ace, || AceInitMsg { ... });
    set.add_single(is_kernel_rom, || KernelRomResponseMsg { ... });

    set
};
```

---

## 7. Eliminating Conditional Response Messages

The current `MemoryResponseMsg`, `BitwiseResponseMsg`, and `KernelRomResponseMsg`
do arithmetic conditional selection inside `encode()`. With the `InteractionGroup`
pattern, these are replaced by ME variant decomposition:

- **Memory**: split into `MemoryMsg::Element` and `MemoryMsg::Word` entries with
  flags `is_memory * (1 - is_word)` and `is_memory * is_word`. Reuses the existing
  request-side `MemoryMsg` type. No conditional encoding.

- **Bitwise**: split into AND and XOR entries with flags
  `is_bitwise * (1 - sel)` and `is_bitwise * sel`. Reuses the existing
  `BitwiseMsg::and` / `BitwiseMsg::xor`.

- **Kernel ROM**: split into INIT and CALL entries with flags
  `is_krom * s_first` and `is_krom * (1 - s_first)`. Reuses `KernelRomMsg` with
  the appropriate constant label.

This eliminates three response-specific message types and their conditional `encode`
implementations.

---

## 8. Future: Prover Integration

When the prover's auxiliary trace generation is refactored to use `InteractionSink`,
the same `InteractionGroup` implementations serve both paths:

```rust
// Constraint evaluation (existing)
let mut set = RationalSet::new(&challenges);
set.add_group(HasherResponses::new(...));  // calls fold_constraints

// Prover trace generation (future)
let mut collector = FractionCollector::new(&challenges, &mut buffer);
collector.add_group(HasherResponses::new(...));  // calls fold
```

The `fold` method is the single source of truth for the interaction inventory. The
`fold_constraints` override is a pure performance optimization. Adding a new
interaction means adding it to `fold` — the constraint path picks it up
automatically through the default delegation.

---

## 9. Open Questions

- **Batch interactions in groups**: `add_batch` (for simultaneous interactions like
  CALL = control_block + FMP_write) could also benefit from pre-encoded denominators
  via `Batch::insert_encoded(m, v)`. The `InteractionGroup` could precompute the
  hasher control_block encoding and pass it to the batch.

- **G_creq control block group**: the 6 control_block requests in G_creq
  (JOIN/SPLIT/LOOP/SPAN/CALL/SYSCALL) share 9 EF×BF muls of encoding. However,
  CALL and SYSCALL are in `add_batch` calls with other interactions. The group
  would need to precompute the control_block encoding and pass it as a pre-encoded
  value to the batch's `remove_encoded`.

- **Prover outer guards**: for the prover, constructing a group struct on non-active
  rows wastes a few field clones. A sink-level `EAGER` const could gate group
  construction:
  ```rust
  if S::EAGER || is_hasher_active(local) {
      sink.add_group(HasherResponses::new(...));
  }
  ```
  For constraints `EAGER = true` compiles the branch away. For the prover it skips
  the entire group on non-hasher rows.

- **Sharing across groups**: some encoding fragments (like `addr_next` or `h_first`)
  appear in multiple groups (G_bqueue, G_creq). Cross-group caching would require
  hoisting the precomputation above the individual group constructions. This may not
  be worth the API complexity.
