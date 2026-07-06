//! [`UintRequire`] — the uint layer's recording facade.
//!
//! A transient view over the three uint chiplet accumulators (store +
//! add / mul relations) that hides their cross-chiplet plumbing: each
//! arithmetic method resolves its operands' values, computes the result,
//! interns it canonically (equal values share one ptr — see
//! [`UintStoreRequires::intern`]), and records the relation tuple with
//! its provide multiplicity 1 — every op recorded here is consumed
//! exactly once by the layer that requested it (an eval uint-op node, an
//! EC membership row, or an EC group-law certificate).
//!
//! Honest-prover determinism is the layer's contract: ptrs are handles
//! the *store* assigns, never the caller, so result ptrs are a pure
//! function of the recorded op sequence and ptr-identity coincides with
//! value-identity. A malicious prover can of course lay traces violating
//! that — the only relation the chiplets *prove* is the arithmetic
//! itself, which is all the `is` predicate needs.

use crate::math::{U256, add_reduce, mac_reduce, sub_reduce};
use crate::uint::add::trace::UintAddRequires;
use crate::uint::mul::trace::UintMulRequires;
use crate::uint::trace::{Uint, UintPtr, UintStoreRequires};

/// Borrowed view over the uint chiplet accumulators; construct one per
/// recording burst (it is `&mut`-cheap and holds no state of its own).
#[derive(Debug)]
pub struct UintRequire<'a> {
    store: &'a mut UintStoreRequires,
    add: &'a mut UintAddRequires,
    mul: &'a mut UintMulRequires,
}

impl<'a> UintRequire<'a> {
    pub fn new(
        store: &'a mut UintStoreRequires,
        add: &'a mut UintAddRequires,
        mul: &'a mut UintMulRequires,
    ) -> Self {
        Self { store, add, mul }
    }

    /// Canonically intern `value` under the modulus `bound` and return
    /// its handle — the free-witness entry (e.g. a slope λ, pinned down
    /// by the arrangement recorded over it); range-membership rides the
    /// store block.
    pub fn intern(&mut self, value: U256, bound: UintPtr) -> UintPtr {
        self.store.intern(value, bound)
    }

    /// The stored value behind a handle.
    pub fn value(&self, ptr: UintPtr) -> U256 {
        self.store.uint(ptr).value
    }

    /// The stored uint behind a handle plus its resolved modulus value —
    /// the lookup every arithmetic op starts from.
    fn resolve(&self, ptr: UintPtr) -> (Uint, U256) {
        let u = *self.store.uint(ptr);
        (u, self.store.uint(u.bound_ptr).value)
    }

    /// Record the modular addition `a + b mod p` of two stored uints
    /// sharing a modulus, interning the sum. Returns the sum's handle.
    pub fn add(&mut self, a_ptr: UintPtr, b_ptr: UintPtr) -> UintPtr {
        let (a, bound) = self.resolve(a_ptr);
        let (b, _) = self.resolve(b_ptr);
        assert_eq!(
            a.bound_ptr, b.bound_ptr,
            "add operands must share a modulus"
        );
        let c = add_reduce(a.value, b.value, bound);
        let c_ptr = self.store.intern(c, a.bound_ptr);
        self.add.record(a_ptr, b_ptr, c_ptr, a.bound_ptr, 1);
        c_ptr
    }

    /// Record the modular subtraction `x − y mod p` as the add
    /// arrangement `y + z = x`, interning the difference `z`. Returns
    /// `z`'s handle.
    pub fn sub(&mut self, x_ptr: UintPtr, y_ptr: UintPtr) -> UintPtr {
        let (x, bound) = self.resolve(x_ptr);
        let (y, _) = self.resolve(y_ptr);
        assert_eq!(
            x.bound_ptr, y.bound_ptr,
            "sub operands must share a modulus"
        );
        let z = sub_reduce(x.value, y.value, bound);
        let z_ptr = self.store.intern(z, x.bound_ptr);
        self.add.record(y_ptr, z_ptr, x_ptr, x.bound_ptr, 1);
        z_ptr
    }

    /// Record the modular negation `−v mod p`, interning `z = p − v` (or
    /// 0 for `v = 0`) and proving `v + z ≡ 0` via the `is_c_zero` add
    /// mode — the zero result is *unstored*, so no typed zero pin is
    /// needed. Returns `z`'s handle.
    pub fn neg(&mut self, v_ptr: UintPtr) -> UintPtr {
        let (v, bound) = self.resolve(v_ptr);
        let z = sub_reduce(U256::ZERO, v.value, bound);
        let z_ptr = self.store.intern(z, v.bound_ptr);
        self.add.record_to_zero(v_ptr, z_ptr, v.bound_ptr, 1);
        z_ptr
    }

    /// Record `a + b ≡ 0 (mod p)` over two *stored* uints — the
    /// zero-result certificate (e.g. the group law's `cancel` case);
    /// nothing is interned. Panics unless the values do sum to zero.
    pub fn add_to_zero(&mut self, a_ptr: UintPtr, b_ptr: UintPtr) {
        let (a, bound) = self.resolve(a_ptr);
        let (b, _) = self.resolve(b_ptr);
        assert_eq!(
            a.bound_ptr, b.bound_ptr,
            "add operands must share a modulus"
        );
        assert_eq!(
            add_reduce(a.value, b.value, bound),
            U256::ZERO,
            "a + b must reduce to zero",
        );
        self.add.record_to_zero(a_ptr, b_ptr, a.bound_ptr, 1);
    }

    /// Record the stored-value **equality certificate** `a = c` — the
    /// `is_b_zero` add `a + 0 ≡ c (mod p)` over two stored uints (`b` is
    /// the unstored zero: no `b` lookup, no zero pin). Both values are
    /// canonical under the shared modulus, so the modular identity is
    /// exactly value equality; the certificate is value-level, so two
    /// distinct ptrs binding equal values still close. Panics unless the
    /// stored values are equal.
    pub fn value_eq(&mut self, a_ptr: UintPtr, c_ptr: UintPtr) {
        let (a, _) = self.resolve(a_ptr);
        let (c, _) = self.resolve(c_ptr);
        assert_eq!(a.bound_ptr, c.bound_ptr, "eq operands must share a modulus");
        assert_eq!(a.value, c.value, "a must equal c");
        self.add.record_eq(a_ptr, c_ptr, a.bound_ptr, 1);
    }

    /// Record the scaled MAC `κₐ·a·b + κ_c·c mod p` over stored uints
    /// sharing a modulus, interning the result. Returns the result's
    /// handle.
    ///
    /// The κ's are the relation's sub-limb constants (`κ ≲ 2⁹` for the
    /// honest-carry window): `κ_c = 0` makes a pure product (pass the
    /// modulus ptr as the dummy `c_ptr`); squaring is `a_ptr == b_ptr`.
    pub fn mac(
        &mut self,
        kappa_a: u16,
        a_ptr: UintPtr,
        b_ptr: UintPtr,
        kappa_c: u16,
        c_ptr: UintPtr,
    ) -> UintPtr {
        let (a, bound) = self.resolve(a_ptr);
        let (b, _) = self.resolve(b_ptr);
        let (c, _) = self.resolve(c_ptr);
        assert!(
            a.bound_ptr == b.bound_ptr && a.bound_ptr == c.bound_ptr,
            "mac operands must share a modulus",
        );
        let r = mac_reduce(kappa_a, a.value, b.value, kappa_c, c.value, bound);
        let r_ptr = self.store.intern(r, a.bound_ptr);
        self.mul
            .record(kappa_a, a_ptr, b_ptr, kappa_c, c_ptr, r_ptr, a.bound_ptr, 1);
        r_ptr
    }

    /// Record a MAC whose result is the *already stored* uint at `r_ptr`
    /// — the shared-result-ptr arrangement (e.g. the membership trio's
    /// `y² ≡ w`, or a slope pinned by `λ·d + y₁ ≡ y₂`). Panics unless
    /// the identity holds over the stored values.
    pub fn mac_into(
        &mut self,
        kappa_a: u16,
        a_ptr: UintPtr,
        b_ptr: UintPtr,
        kappa_c: u16,
        c_ptr: UintPtr,
        r_ptr: UintPtr,
    ) {
        let (a, bound) = self.resolve(a_ptr);
        let (b, _) = self.resolve(b_ptr);
        let (c, _) = self.resolve(c_ptr);
        let (r, _) = self.resolve(r_ptr);
        assert!(
            a.bound_ptr == b.bound_ptr && a.bound_ptr == c.bound_ptr && a.bound_ptr == r.bound_ptr,
            "mac operands must share a modulus",
        );
        assert_eq!(
            mac_reduce(kappa_a, a.value, b.value, kappa_c, c.value, bound),
            r.value,
            "κₐ·a·b + κ_c·c must reduce to the stored r",
        );
        self.mul
            .record(kappa_a, a_ptr, b_ptr, kappa_c, c_ptr, r_ptr, a.bound_ptr, 1);
    }
}

/// The three uint chiplet accumulators that travel together — the store
/// plus its add / mul relations. [`require`](Self::require) lends a
/// transient [`UintRequire`] view over all three (the recording layer);
/// trace-gen consumes the fields individually.
#[derive(Debug, Default)]
pub struct UintStores {
    pub(crate) store: UintStoreRequires,
    pub(crate) add: UintAddRequires,
    pub(crate) mul: UintMulRequires,
}

impl UintStores {
    pub fn new() -> Self {
        Self::default()
    }

    /// A [`UintRequire`] view borrowing all three accumulators — the
    /// recording entry point. One borrow of the bundle, so a caller can
    /// hold it alongside disjoint sibling borrows (eval, Poseidon2).
    pub fn require(&mut self) -> UintRequire<'_> {
        UintRequire::new(&mut self.store, &mut self.add, &mut self.mul)
    }
}
