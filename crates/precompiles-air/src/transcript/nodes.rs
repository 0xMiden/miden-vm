//! Selector-local operation discriminants used by transcript nodes.
//!
//! Eidos construction selectors come from the shared protocol registry or a concrete precompile;
//! this module defines only the operation ids interpreted within those constructions.

/// Operation discriminant for VM uint op rows.
///
/// The chain context is `[UintPrecompile::id(), op_id, 0, 0]`; operand/result pointers and
/// `bound_ptr` are carried by `Binding` and relation witnesses.
///
/// | op | children (lhs, rhs) | relation consumed |
/// |---|---|---|
/// | `Add` | a, b | `UintAdd(bp, a, b, r)` — `r = a + b mod p` |
/// | `Sub` | a, b | `UintAdd(bp, b, r, a)` — `r = a − b mod p` |
/// | `Mul` | a, b | `UintMul(1, 0, a, b, bp, r, bp)` — `r = a·b mod p` |
/// | `Is` | a, b | none — `a ≡ b` asserted as binding-ptr equality |
///
/// `Add`/`Sub`/`Mul` bind `(h, Uint, r_ptr, bound_ptr)`; `Is` binds
/// `(h, True)` — the predicate that folds uint values into the spine.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UintOpId {
    Add = 1,
    Sub = 2,
    Mul = 3,
    Is = 4,
}

/// Operation discriminant of a curve binary-op node.
///
/// The VM chain context is `[CurvePrecompile::id(), op_id, 0, 0]`. The compression block is
/// `lhs_hash ‖ rhs_hash` over two `Group` children; the result point rides
/// the node's `Binding` as a nondeterministic ptr. The curve threads from
/// the operands' curve VALUE contexts.
///
/// | op | children (lhs, rhs) | relation consumed |
/// |---|---|---|
/// | `Add` | P, Q | `EcGroupAdd(g, p, q, r)` — `R = P + Q` |
/// | `Sub` | P, Q | `EcGroupAdd(g, r, q, p)` — `R = P − Q` |
/// | `Is` | P, Q | none — `P ≡ Q` asserted as binding-ptr equality |
///
/// `Add`/`Sub` bind `(h, Group, r_ptr)`; `Is` binds `(h, True)` —
/// the predicate folding a curve point into the transcript spine.
/// `Sub` (2) consumes the *rearranged* relation `EcGroupAdd(g, r, q, p)`
/// — `R + Q = P` with the bound `R` the subtraction result — exactly as
/// [`UintOpId::Sub`] rearranges its `UintAdd`. The witness `R = P − Q` is
/// interned, then the add relation re-derives and certifies `R + Q = P`
/// (deduping the result onto `P`).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EcOpId {
    Add = 1,
    Sub = 2,
    Is = 3,
}
