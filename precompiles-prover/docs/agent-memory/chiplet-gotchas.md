# Per-chiplet gotchas

Column layouts, constraint degrees, and slot tables live in [`../chiplets/`](../chiplets/) — consult
those docs, not this file. The non-obvious traps worth carrying into a session:

- **ROL's predecessor must be a LOGIC row** (`is_rol_next · (1 − is_logic) = 0`, cyclic). So
  Keccak's trailing ρπ rows are **XORROL with `src_b = ZERO`** (a dummy XOR), not pure ROL — that's
  what lets Bitwise64's IR materialize the Real-LOGIC + Carrier pair the invariant needs.
- **Fused XORROL rows set both `is_xor` and `is_rol`** — any per-row count built from the selector
  sum double-counts them; subtract the one-hot `is_xorrol` (this was the bug behind the first
  end-to-end bus imbalance).
- **Bitwise64 ROL decomposition**: the `+2³²` offset on `((lo+2³²)·k, (hi+2³²)·k)` kills the low-end
  limb alias and the `k < 2³¹` bound the high-end one. `op_or_k` / `b_limbs` are dual-purpose:
  op-tag vs `k`; bytes vs limbs.
- **Keccak ρπ slot table is post-π indexed** (`slot_b(out_x, out_y)`, input resolved via
  `pi_inverse`, ρ of the *input* lane) — the classic off-by-π bug.
- **Multi-value memory provides use `g.insert(ONE, −dst_mult)`**, never `g.remove(dst_mult)` (which
  hard-codes mult −1 and mis-accounts the `dst_mult ∈ {1, 2, 3, 5, 12}` writes).
- **Permutation chaining is address-separated via a dead round**: 25 rounds = 24 active + 1 dead =
  3200 rows. The sponge feeds each perm's round-0 inputs into the previous cycle's dead-round IP
  gap, and `act` gates every bus mult so the dead round / padding stay off the bus.
- **Logic64's `op` slot is `is_xor`** (`AndNot = 0`, `Xor = 1`).
