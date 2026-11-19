//! Structural checks and concrete row diagnostics for native AIR kernels.

use alloc::{vec, vec::Vec};

use p3_challenger::{CanObserve, CanSample};
use p3_field::{ExtensionField, Field};
use p3_matrix::{Matrix, dense::RowMajorMatrix};

use crate::{
    air,
    air::{AirKernel, MultiAir, ProverStatement, debug::assert_multi_air_valid},
    order::TraceOrder,
    prover::periodic::periodic_matrix,
};

/// Assert descriptor structure without materializing fixed matrices or witnesses.
pub fn assert_prover_setup<F, EF, MA>(prover_statement: &ProverStatement<F, EF, MA>)
where
    F: Field,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
{
    assert_multi_air_valid::<F, EF, MA>(prover_statement.statement().multi_air());
}

/// Check concrete constraints using explicitly supplied, setup-owned fixed matrices.
///
/// The optional slice is in instance order. It is shared by both row passes and auxiliary
/// construction; this function never invokes fixed-data factories. Base assertions are checked
/// before auxiliary construction, then the complete relation and external closure are checked.
///
/// Challenges observe only the statement and instance heights, preserving the local debugger's
/// derivation rather than replaying proof commitments. Constraint failures and witness errors
/// panic.
pub fn check_constraints<F, EF, MA, Ch>(
    prover_statement: &ProverStatement<F, EF, MA>,
    preprocessed: Option<&[Option<RowMajorMatrix<F>>]>,
    mut challenger: Ch,
) where
    F: Field,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
    MA::Air: air::ProverAir<EF> + air::LiftedAir<F = F>,
    Ch: CanObserve<F> + CanSample<F>,
{
    let statement = prover_statement.statement();
    let airs = statement.airs();
    let traces = prover_statement.traces();
    assert_multi_air_valid::<F, EF, MA>(statement.multi_air());
    if let Some(fixed) = preprocessed {
        assert_eq!(fixed.len(), airs.len(), "fixed matrix count must match instances");
    }
    for (instance, (kernel, main)) in airs.iter().zip(traces).enumerate() {
        let spec = kernel.descriptor().spec();
        let fixed = preprocessed.and_then(|tables| tables[instance].as_ref());
        assert_eq!(
            fixed.is_some(),
            spec.preprocessed.is_some(),
            "instance {instance}: fixed presence"
        );
        if let Some(table) = fixed {
            let shape = spec.preprocessed.expect("fixed presence was checked");
            assert_eq!(table.width(), shape.width, "instance {instance}: fixed width");
            assert_eq!(
                table.values.len(),
                main.height() * shape.width,
                "instance {instance}: fixed raw rows"
            );
            assert_eq!(
                main.height(),
                1usize << shape.log_height,
                "instance {instance}: fixed native height"
            );
        }
        let chunks = air::resolve_quotient_chunks(kernel).expect("valid kernel allocation");
        kernel
            .descriptor()
            .analysis()
            .degree_profile()
            .validate_capacity(main.height(), chunks)
            .expect("allocation must fit the actual trace height");
    }
    let trace_heights: Vec<_> = traces.iter().map(Matrix::height).collect();
    let order = TraceOrder::from_trace_heights(airs, &trace_heights)
        .expect("trace heights must satisfy the AIR contracts");
    statement.observe(&mut challenger, order.log_heights());
    order.observe_shape::<F, _>(&mut challenger);
    let max_challenges = airs
        .iter()
        .map(|kernel| kernel.descriptor().spec().num_challenges)
        .max()
        .unwrap_or(0);
    let challenges: Vec<EF> = (0..max_challenges)
        .map(|_| EF::from_basis_coefficients_fn(|_| challenger.sample()))
        .collect();
    let mut auxiliaries = Vec::with_capacity(airs.len());
    for (instance, (kernel, main)) in airs.iter().zip(traces).enumerate() {
        let spec = kernel.descriptor().spec();
        let fixed = preprocessed.and_then(|tables| tables[instance].as_ref());
        check_single_trace(
            kernel,
            main,
            fixed,
            None,
            &vec![EF::ZERO; spec.num_exports],
            &statement.air_inputs()[instance],
            &challenges[..spec.num_challenges],
            instance,
        );
        let auxiliary = air::ProverAir::build_aux_trace(
            kernel,
            air::AuxTraceInputs {
                main,
                preprocessed: fixed,
                public_values: &statement.air_inputs()[instance],
                statement: statement.aux_inputs(),
                challenges: &challenges[..spec.num_challenges],
            },
        )
        .unwrap_or_else(|error| {
            panic!("instance {instance}: auxiliary witness construction failed: {error}")
        });
        assert_eq!(
            auxiliary.columns.width(),
            spec.aux_width,
            "instance {instance}: auxiliary width"
        );
        assert_eq!(
            auxiliary.columns.values.len(),
            main.height() * spec.aux_width,
            "instance {instance}: auxiliary raw rows"
        );
        assert_eq!(auxiliary.exports.len(), spec.num_exports, "instance {instance}: export count");
        auxiliaries.push(auxiliary);
    }
    let views: Vec<_> = auxiliaries.iter().map(|aux| aux.exports.as_slice()).collect();
    let assertions = statement
        .eval_external(&challenges, &views, order.log_heights())
        .expect("eval_external failed during check_constraints");
    for (assertion, value) in assertions.into_iter().enumerate() {
        assert_eq!(value, EF::ZERO, "external assertion {assertion} is non-zero");
    }
    for (instance, ((kernel, main), auxiliary)) in
        airs.iter().zip(traces).zip(&auxiliaries).enumerate()
    {
        let spec = kernel.descriptor().spec();
        check_single_trace(
            kernel,
            main,
            preprocessed.and_then(|tables| tables[instance].as_ref()),
            Some(&auxiliary.columns),
            &auxiliary.exports,
            &statement.air_inputs()[instance],
            &challenges[..spec.num_challenges],
            instance,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn check_single_trace<F, EF, K>(
    kernel: &K,
    main: &RowMajorMatrix<F>,
    fixed: Option<&RowMajorMatrix<F>>,
    auxiliary: Option<&RowMajorMatrix<EF>>,
    exports: &[EF],
    public_values: &[F],
    challenges: &[EF],
    instance: usize,
) where
    F: Field,
    EF: ExtensionField<F>,
    K: AirKernel<F = F>,
{
    let descriptor = kernel.descriptor();
    let spec = descriptor.spec();
    let height = main.height();
    let periodic = periodic_matrix(&spec.periodic_columns);
    let dummy_aux = vec![EF::ZERO; spec.aux_width];
    let session = kernel
        .bind(air::UniformInputs { public_values, challenges, exports })
        .expect("debug uniforms must match the descriptor");
    for row in 0..height {
        let next = (row + 1) % height;
        let main_current = main.row_slice(row).expect("main current row");
        let main_next = main.row_slice(next).expect("main next row");
        let fixed_current = fixed.map(|table| table.row_slice(row).expect("fixed current row"));
        let fixed_next = fixed.map(|table| table.row_slice(next).expect("fixed next row"));
        let aux_current =
            auxiliary.map(|trace| trace.row_slice(row).expect("auxiliary current row"));
        let aux_next = auxiliary.map(|trace| trace.row_slice(next).expect("auxiliary next row"));
        let periodic_row = periodic
            .as_ref()
            .map(|matrix| matrix.row_slice(row % matrix.height()).expect("periodic row"));
        let frame = air::AirFrame {
            main: air::Rows { current: &main_current, next: &main_next },
            preprocessed: air::Rows {
                current: fixed_current.as_deref().unwrap_or(&[]),
                next: fixed_next.as_deref().unwrap_or(&[]),
            },
            aux: air::Rows {
                current: aux_current.as_deref().unwrap_or(&dummy_aux),
                next: aux_next.as_deref().unwrap_or(&dummy_aux),
            },
            periodic: periodic_row.as_deref().unwrap_or(&[]),
            selectors: air::Selectors {
                first: F::from_bool(row == 0),
                last: F::from_bool(row + 1 == height),
                transition: F::from_bool(row + 1 < height),
            },
        };
        let mut sink = DebugConstraintBuilder {
            descriptor,
            instance,
            row,
            ordinal: 0,
            check_extension: auxiliary.is_some(),
            _ef: core::marker::PhantomData,
        };
        session.eval(&frame, &mut sink);
        debug_assert_eq!(sink.ordinal, descriptor.analysis().layout().total_constraints());
    }
}

struct DebugConstraintBuilder<'a, F: Field, EF> {
    descriptor: &'a air::AirDescriptor<F>,
    instance: usize,
    row: usize,
    ordinal: usize,
    check_extension: bool,
    _ef: core::marker::PhantomData<EF>,
}

impl<F: Field, EF> DebugConstraintBuilder<'_, F, EF> {
    fn failed(&self, class: &str, ordinal: usize, value: impl core::fmt::Debug) -> ! {
        let instance = self.instance;
        let row = self.row;
        if let Some(label) = self.descriptor.label(ordinal) {
            panic!(
                "{class} constraint not satisfied: instance {instance}, row {row}, constraint {ordinal} ({label}): {value:?}"
            );
        }
        panic!(
            "{class} constraint not satisfied: instance {instance}, row {row}, constraint {ordinal}: {value:?}"
        );
    }
}

impl<F: Field, EF: ExtensionField<F>> air::LiftedAirBuilder for DebugConstraintBuilder<'_, F, EF> {
    type F = F;
    type Expr = F;
    type ExtExpr = EF;

    fn emit_base(&mut self, value: F, _meta: air::ConstraintMeta<'_>) {
        let ordinal = self.ordinal;
        self.ordinal += 1;
        if value != F::ZERO {
            self.failed("base", ordinal, value);
        }
    }

    fn emit_ext(&mut self, value: EF, _meta: air::ConstraintMeta<'_>) {
        let ordinal = self.ordinal;
        self.ordinal += 1;
        if self.check_extension && value != EF::ZERO {
            self.failed("ext", ordinal, value);
        }
    }
}
