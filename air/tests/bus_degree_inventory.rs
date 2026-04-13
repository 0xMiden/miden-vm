//! Bus constraint degree inventory via a degree-logging symbolic builder.
//!
//! Wraps `SymbolicAirBuilder` and intercepts every `assert_zero_ext` call to print
//! the constraint's `degree_multiple` plus a backtrace showing which bus function
//! emitted it.  Run with:
//!
//! ```sh
//! cargo test -p miden-air --test bus_degree_inventory -- --nocapture
//! ```

use miden_air::{
    LiftedAir, NUM_PUBLIC_VALUES, ProcessorAir,
    trace::{AUX_TRACE_RAND_CHALLENGES, AUX_TRACE_WIDTH, TRACE_WIDTH},
};
use miden_core::{Felt, field::QuadFelt};
use miden_crypto::stark::air::{
    AirBuilder, ExtensionBuilder, PeriodicAirBuilder, PermutationAirBuilder,
    symbolic::{AirLayout, SymbolicAirBuilder},
};

// ================================================================================================
// DEGREE-LOGGING BUILDER
// ================================================================================================

type SB = SymbolicAirBuilder<Felt, QuadFelt>;

/// Thin wrapper: delegates everything to `SymbolicAirBuilder`, but prints the
/// degree (and a short call-site) on every `assert_zero` / `assert_zero_ext`.
struct DegreeLog {
    inner: SB,
    ext_idx: usize,
    base_idx: usize,
}

impl DegreeLog {
    fn new(inner: SB) -> Self {
        Self { inner, ext_idx: 0, base_idx: 0 }
    }
}

/// Extract a short call chain from a backtrace, showing only the constraint
/// function names (deepest-first).
fn caller_location() -> String {
    let bt = std::backtrace::Backtrace::force_capture();
    let text = bt.to_string();
    let mut hits: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.contains("bus_degree_inventory") || line.contains("DegreeLog") {
            continue;
        }
        if let Some(start) = line.find("miden_air::constraints::") {
            let raw = &line[start + "miden_air::".len()..];
            // Strip closure / generic suffixes
            let func = raw.split("::{{").next().unwrap_or(raw);
            // Skip the tagging wrapper noise
            if func.contains("tagging::fallback") || func.contains("tagging::enabled") {
                continue;
            }
            if hits.last().is_none_or(|prev| prev != func) {
                hits.push(func.to_string());
            }
        }
    }
    if hits.is_empty() {
        "???".into()
    } else {
        // Show deepest (most specific) first, keep at most 3 frames
        hits.truncate(3);
        hits.join(" <- ")
    }
}

// --- AirBuilder (delegate everything, log assert_zero) -----------------------

impl AirBuilder for DegreeLog {
    type F = <SB as AirBuilder>::F;
    type Expr = <SB as AirBuilder>::Expr;
    type Var = <SB as AirBuilder>::Var;
    type PreprocessedWindow = <SB as AirBuilder>::PreprocessedWindow;
    type MainWindow = <SB as AirBuilder>::MainWindow;
    type PublicVar = <SB as AirBuilder>::PublicVar;

    fn main(&self) -> Self::MainWindow {
        self.inner.main()
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        self.inner.preprocessed()
    }

    fn is_first_row(&self) -> Self::Expr {
        self.inner.is_first_row()
    }

    fn is_last_row(&self) -> Self::Expr {
        self.inner.is_last_row()
    }

    fn is_transition(&self) -> Self::Expr {
        self.inner.is_transition()
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        self.inner.is_transition_window(size)
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let expr: Self::Expr = x.into();
        let deg = expr.degree_multiple();
        self.base_idx += 1;
        // only log high-degree base constraints (skip degree ≤ 2)
        if deg > 2 {
            println!(
                "  BASE[{idx:>3}]  deg={deg}  @ {loc}",
                idx = self.base_idx - 1,
                loc = caller_location(),
            );
        }
        self.inner.assert_zero(expr);
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.inner.public_values()
    }
}

// --- ExtensionBuilder (intercept assert_zero_ext) ----------------------------

impl ExtensionBuilder for DegreeLog {
    type EF = <SB as ExtensionBuilder>::EF;
    type ExprEF = <SB as ExtensionBuilder>::ExprEF;
    type VarEF = <SB as ExtensionBuilder>::VarEF;

    fn assert_zero_ext<I: Into<Self::ExprEF>>(&mut self, x: I) {
        let expr: Self::ExprEF = x.into();
        let deg = expr.degree_multiple();
        println!(
            "  EXT[{idx:>2}]  deg={deg}  @ {loc}",
            idx = self.ext_idx,
            loc = caller_location(),
        );
        self.ext_idx += 1;
        self.inner.assert_zero_ext(expr);
    }
}

// --- PermutationAirBuilder (pure delegation) ---------------------------------

impl PermutationAirBuilder for DegreeLog {
    type MP = <SB as PermutationAirBuilder>::MP;
    type RandomVar = <SB as PermutationAirBuilder>::RandomVar;
    type PermutationVar = <SB as PermutationAirBuilder>::PermutationVar;

    fn permutation(&self) -> Self::MP {
        self.inner.permutation()
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        self.inner.permutation_randomness()
    }

    fn permutation_values(&self) -> &[Self::PermutationVar] {
        self.inner.permutation_values()
    }
}

// --- PeriodicAirBuilder (pure delegation) ------------------------------------

impl PeriodicAirBuilder for DegreeLog {
    type PeriodicVar = <SB as PeriodicAirBuilder>::PeriodicVar;

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        self.inner.periodic_values()
    }
}

// LiftedAirBuilder is auto-implemented (marker trait).
// TaggingAirBuilderExt is blanket-implemented for all LiftedAirBuilder.

// ================================================================================================
// TEST
// ================================================================================================

fn make_builder() -> DegreeLog {
    let num_periodic = LiftedAir::<Felt, QuadFelt>::periodic_columns(&ProcessorAir).len();
    let layout = AirLayout {
        preprocessed_width: 0,
        main_width: TRACE_WIDTH,
        num_public_values: NUM_PUBLIC_VALUES,
        permutation_width: AUX_TRACE_WIDTH,
        num_permutation_challenges: AUX_TRACE_RAND_CHALLENGES,
        num_permutation_values: AUX_TRACE_WIDTH,
        num_periodic_columns: num_periodic,
    };
    DegreeLog::new(SymbolicAirBuilder::<Felt, QuadFelt>::new(layout))
}

#[test]
#[allow(clippy::print_stdout)]
fn log_all_constraint_degrees() {
    let mut builder = make_builder();
    println!("=== Evaluating ProcessorAir through DegreeLog builder ===");
    println!("  (showing base constraints with degree > 2)\n");
    LiftedAir::<Felt, QuadFelt>::eval(&ProcessorAir, &mut builder);
    println!(
        "\n=== Done: {} base constraints, {} extension constraints ===",
        builder.base_idx, builder.ext_idx,
    );
}
