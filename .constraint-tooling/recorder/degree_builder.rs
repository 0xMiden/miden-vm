//! Debug-only `MidenAirBuilder` that tracks polynomial degrees.
//!
//! ## How to run it
//!
//! This file is not compiled into the `miden-air` crate. To use it:
//!
//! 1. Copy it to `air/src/constraints/degree_builder.rs`.
//! 2. Add `#[cfg(test)] mod degree_builder;` to `air/src/constraints/mod.rs`.
//! 3. Run `cargo test -p miden-air --lib constraints::degree_builder`.
//!
//! Revert the two edits once you're done so the debug-only code doesn't ship.
//!
//! ## What it does
//!
//! Every non-`F` associated type is [`Degree`], a `u64` wrapper. Arithmetic
//! follows plonky3's `SymbolicExpression::degree_multiple` rules:
//!
//! - `a + b`, `a - b` → `max(a, b)`
//! - `-a` → `a`
//! - `a * b` → `a + b`
//! - constants (from `Felt`, `QuadFelt`, bool/integer conversions) → `0`
//! - trace variables (main, preprocessed, periodic, permutation) → `1`
//! - `is_first_row`, `is_last_row` → `1`
//! - `is_transition_window(2)` → `0` (matches plonky3 `BaseLeaf::IsTransition`)
//!
//! `assert_zero` / `assert_zero_ext` panic if the reported degree exceeds
//! [`MAX_DEGREE`]. The panic's backtrace identifies the constraint site that
//! emitted the offending polynomial.

use alloc::{vec, vec::Vec};
use core::{
    iter::{Product, Sum},
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use miden_core::field::{Algebra, PrimeCharacteristicRing, QuadFelt};
use miden_crypto::stark::air::{
    AirBuilder, EmptyWindow, ExtensionBuilder, PeriodicAirBuilder, PermutationAirBuilder,
    WindowAccess,
};

use crate::{
    Felt,
    constraints::chiplets::columns::NUM_PERIODIC_COLUMNS,
    trace::{AUX_TRACE_RAND_CHALLENGES, AUX_TRACE_WIDTH, TRACE_WIDTH},
};

/// Maximum allowed constraint degree.
pub const MAX_DEGREE: u64 = 9;

// DEGREE TYPE
// ================================================================================================

/// Polynomial degree tracker. `Copy`, `#[repr(transparent)]` over `u64` so that
/// `MainCols<Degree>` has the same layout as `MainCols<Felt>` (both are 8-byte
/// columns), preserving the `Borrow<MainCols<T>>` `align_to` invariant.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Degree(pub u64);

impl Add for Degree {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Degree(self.0.max(rhs.0))
    }
}
impl Sub for Degree {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Degree(self.0.max(rhs.0))
    }
}
impl Mul for Degree {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Degree(self.0 + rhs.0)
    }
}
impl Neg for Degree {
    type Output = Self;
    fn neg(self) -> Self {
        self
    }
}
impl AddAssign for Degree {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}
impl SubAssign for Degree {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}
impl MulAssign for Degree {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

// Mixed ops with Felt (field constants have degree 0).
impl Add<Felt> for Degree {
    type Output = Self;
    fn add(self, _: Felt) -> Self {
        self
    }
}
impl Sub<Felt> for Degree {
    type Output = Self;
    fn sub(self, _: Felt) -> Self {
        self
    }
}
impl Mul<Felt> for Degree {
    type Output = Self;
    fn mul(self, _: Felt) -> Self {
        self
    }
}
impl AddAssign<Felt> for Degree {
    fn add_assign(&mut self, _: Felt) {}
}
impl SubAssign<Felt> for Degree {
    fn sub_assign(&mut self, _: Felt) {}
}
impl MulAssign<Felt> for Degree {
    fn mul_assign(&mut self, _: Felt) {}
}

// Mixed ops with QuadFelt (extension field constants have degree 0).
impl Add<QuadFelt> for Degree {
    type Output = Self;
    fn add(self, _: QuadFelt) -> Self {
        self
    }
}
impl Sub<QuadFelt> for Degree {
    type Output = Self;
    fn sub(self, _: QuadFelt) -> Self {
        self
    }
}
impl Mul<QuadFelt> for Degree {
    type Output = Self;
    fn mul(self, _: QuadFelt) -> Self {
        self
    }
}
impl AddAssign<QuadFelt> for Degree {
    fn add_assign(&mut self, _: QuadFelt) {}
}
impl SubAssign<QuadFelt> for Degree {
    fn sub_assign(&mut self, _: QuadFelt) {}
}
impl MulAssign<QuadFelt> for Degree {
    fn mul_assign(&mut self, _: QuadFelt) {}
}

impl From<Felt> for Degree {
    fn from(_: Felt) -> Self {
        Degree(0)
    }
}
impl From<QuadFelt> for Degree {
    fn from(_: QuadFelt) -> Self {
        Degree(0)
    }
}

impl Sum for Degree {
    fn sum<I: Iterator<Item = Self>>(it: I) -> Self {
        it.fold(Degree(0), Add::add)
    }
}
impl Product for Degree {
    fn product<I: Iterator<Item = Self>>(it: I) -> Self {
        it.fold(Degree(0), Mul::mul)
    }
}

impl PrimeCharacteristicRing for Degree {
    type PrimeSubfield = <Felt as PrimeCharacteristicRing>::PrimeSubfield;

    const ZERO: Self = Degree(0);
    const ONE: Self = Degree(0);
    const TWO: Self = Degree(0);
    const NEG_ONE: Self = Degree(0);

    fn from_prime_subfield(_: Self::PrimeSubfield) -> Self {
        Degree(0)
    }
}

// `Expr = Degree` must be an algebra over `F` and over `EF = QuadFelt`.
// `Algebra<Degree> for Degree` is covered by the blanket
// `impl<R: PrimeCharacteristicRing> Algebra<R> for R` in `p3_field`.
impl Algebra<Felt> for Degree {}
impl Algebra<QuadFelt> for Degree {}

// WINDOW
// ================================================================================================

/// Owned two-row window of [`Degree`] values.
#[derive(Clone)]
pub struct DegreeWindow {
    values: Vec<Degree>,
    width: usize,
}

impl WindowAccess<Degree> for DegreeWindow {
    fn current_slice(&self) -> &[Degree] {
        &self.values[..self.width]
    }
    fn next_slice(&self) -> &[Degree] {
        &self.values[self.width..]
    }
}

// VIOLATION RECORD
// ================================================================================================

/// A single over-degree constraint captured during evaluation.
pub struct Violation {
    pub kind: &'static str,
    pub degree: u64,
    pub backtrace: alloc::string::String,
}

/// Filter a full backtrace down to frames that mention the `miden_air`
/// constraint modules — the rest is plonky3 / Rust internals that add noise.
fn filter_backtrace(bt: &std::backtrace::Backtrace) -> alloc::string::String {
    use alloc::string::ToString;
    let full = bt.to_string();
    let mut lines = Vec::new();
    let mut last_was_relevant = false;

    for line in full.lines() {
        let trimmed = line.trim();
        let is_relevant = trimmed.contains("miden_air::constraints")
            || trimmed.contains("constraints::")
            || trimmed.contains("air::lib")
            || (trimmed.starts_with("at ") && last_was_relevant);

        if is_relevant
            && !trimmed.contains("degree_builder")
            && !trimmed.contains("FilteredAirBuilder")
        {
            lines.push(trimmed.to_string());
            last_was_relevant = true;
        } else if trimmed.starts_with("at ") && last_was_relevant {
            lines.push(format!("  {trimmed}"));
            last_was_relevant = false;
        } else {
            last_was_relevant = false;
        }
    }

    if lines.is_empty() {
        full.lines().take(12).collect::<Vec<_>>().join("\n")
    } else {
        lines.join("\n")
    }
}

// DEGREE BUILDER
// ================================================================================================

/// Debug-only builder that records every constraint whose degree exceeds
/// [`MAX_DEGREE`] along with a filtered backtrace to the call site. After
/// running `eval`, inspect [`DegreeBuilder::violations`] — any entries
/// indicate over-degree constraints.
pub struct DegreeBuilder {
    main_data: DegreeWindow,
    perm_data: DegreeWindow,
    public_values: Vec<Degree>,
    periodic: Vec<Degree>,
    perm_challenges: Vec<Degree>,
    perm_values: Vec<Degree>,
    violations: Vec<Violation>,
}

impl DegreeBuilder {
    pub fn new() -> Self {
        Self {
            main_data: DegreeWindow {
                values: vec![Degree(1); 2 * TRACE_WIDTH],
                width: TRACE_WIDTH,
            },
            perm_data: DegreeWindow {
                values: vec![Degree(1); 2 * AUX_TRACE_WIDTH],
                width: AUX_TRACE_WIDTH,
            },
            public_values: vec![Degree(0); crate::NUM_PUBLIC_VALUES],
            periodic: vec![Degree(1); NUM_PERIODIC_COLUMNS],
            perm_challenges: vec![Degree(0); AUX_TRACE_RAND_CHALLENGES],
            perm_values: vec![Degree(0); AUX_TRACE_WIDTH],
            violations: Vec::new(),
        }
    }

    /// All recorded over-degree constraints.
    pub fn violations(&self) -> &[Violation] {
        &self.violations
    }

    fn record(&mut self, kind: &'static str, degree: u64) {
        let bt = std::backtrace::Backtrace::force_capture();
        let backtrace = filter_backtrace(&bt);
        self.violations.push(Violation { kind, degree, backtrace });
    }
}

impl Default for DegreeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AirBuilder for DegreeBuilder {
    type F = Felt;
    type Expr = Degree;
    type Var = Degree;
    type PreprocessedWindow = EmptyWindow<Degree>;
    type MainWindow = DegreeWindow;
    type PublicVar = Degree;

    fn main(&self) -> Self::MainWindow {
        self.main_data.clone()
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        EmptyWindow::empty_ref()
    }

    fn is_first_row(&self) -> Self::Expr {
        Degree(1)
    }

    fn is_last_row(&self) -> Self::Expr {
        Degree(1)
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        assert_eq!(size, 2, "only window size 2 is supported");
        // Matches plonky3 `BaseLeaf::IsTransition` — degree 0.
        Degree(0)
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let d = x.into().0;
        if d > MAX_DEGREE {
            self.record("base", d);
        }
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        &self.public_values
    }
}

impl PeriodicAirBuilder for DegreeBuilder {
    type PeriodicVar = Degree;

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        &self.periodic
    }
}

impl ExtensionBuilder for DegreeBuilder {
    type EF = QuadFelt;
    type ExprEF = Degree;
    type VarEF = Degree;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        let d = x.into().0;
        if d > MAX_DEGREE {
            self.record("ext", d);
        }
    }
}

impl PermutationAirBuilder for DegreeBuilder {
    type MP = DegreeWindow;
    type RandomVar = Degree;
    type PermutationVar = Degree;

    fn permutation(&self) -> Self::MP {
        self.perm_data.clone()
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        &self.perm_challenges
    }

    fn permutation_values(&self) -> &[Self::PermutationVar] {
        &self.perm_values
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use std::eprintln;

    use super::*;
    use crate::{LiftedAir, ProcessorAir};

    #[test]
    fn processor_air_constraint_degrees() {
        let air = ProcessorAir;
        let mut builder = DegreeBuilder::new();
        <ProcessorAir as LiftedAir<Felt, QuadFelt>>::eval(&air, &mut builder);

        let violations = builder.violations();
        if violations.is_empty() {
            return;
        }

        eprintln!("\n{} constraint(s) exceeded degree limit of {MAX_DEGREE}:\n", violations.len());
        for (i, v) in violations.iter().enumerate() {
            eprintln!("---- [{i}] {} constraint degree {} ----", v.kind, v.degree);
            eprintln!("{}\n", v.backtrace);
        }

        panic!("{} over-degree constraint(s); see stack traces above", violations.len());
    }
}
