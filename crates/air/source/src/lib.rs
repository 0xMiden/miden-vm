#![no_std]

//! Authored VM and precompile AIRs, trace schemas, and shared equations.
//!
//! Production evaluators, protocol configuration, and derived artifacts live in `miden-air`.
//!
//! # Writing constraints
//!
//! Use [`LiftedAirBuilder`](miden_stark::air::LiftedAirBuilder) methods that state the obligation:
//! `assert_eq`, `assert_one`, and their array and extension variants. Use `assert_bool` or
//! `assert_bools` for the canonical Boolean polynomial `x * (x - 1)`, and `.bool_check()` when
//! that polynomial belongs inside another equation. Name common gates and use `when(gate)`
//! around related obligations. Array assertions retain independent constraints in element order;
//! replacing them with one assertion on their sum would allow residuals to cancel.
//!
//! Write mathematical reductions with `.map(...).sum()` or `sum_array`. Use
//! [`dot_product`](p3_field::PrimeCharacteristicRing::dot_product) for homogeneous weighted sums
//! and [`mixed_dot_product`](p3_field::Algebra::mixed_dot_product) for algebra values weighted
//! by base elements. Keep coefficients and gates in the narrowest available domain. Factor
//! repeated extension values through sums of base gates, and group subtraction tails into a
//! positive sum or an equality when that makes the equation easier to audit.
//!
//! Ring methods such as `.square()`, `.double()`, and `.mul_2exp_u64()` retain the intended
//! operation in symbolic capture. Preserve useful shared prefixes, readable Horner forms, and
//! independently derived reference equations.
//!
//! Uniform subexpressions depend only on constants, public values, challenges, and exports.
//! Trace cells, periodic values, and row selectors remain row-dependent even when named.
//! Compiler preparation follows these dependencies.

#[macro_use]
extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

#[cfg(feature = "compiler")]
pub mod compiler;

pub mod precompiles;
pub mod shared;
pub mod vm;
