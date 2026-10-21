//! Production AIR evaluators and proof protocol for the Miden VM.
//!
//! The authored constraints and trace layouts live in [`miden_air_source::vm`]. This module
//! combines their trace metadata and lookup construction with the generated evaluators used by
//! native proving and verification.

use alloc::{borrow::Cow, vec::Vec};

use miden_air_source::vm::{
    self as source, AUX_DEFERRED_ROOT, AUX_KERNEL_DIGESTS, AUX_PROGRAM_HASH,
};
use miden_core::{
    WORD_SIZE,
    field::ExtensionField,
    program::{KernelDescriptor, NUM_CLAIM_ELEMENTS},
    utils::RowMajorMatrix,
};
use miden_stark::{
    air::ReductionError,
    challenger::CanObserve,
    lookup::{BoundaryBuilder, Challenges, LookupAir, LookupBuilder},
};
use source::{
    logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
    trace,
};

#[cfg(feature = "codegen")]
pub mod ace;
pub mod config;
mod generated;
pub mod memory;
pub mod security;

pub use miden_air_source::vm::{MIDEN_AIR_COUNT, NUM_PUBLIC_VALUES, PublicInputs};
pub use miden_core::{Felt, serde::DeserializationError};
pub use miden_stark::{
    StarkConfig,
    air::{
        AirBuilder, BaseAir, ConstraintCounts, ConstraintDegrees, ExtensionBuilder, LiftedAir,
        LiftedAirBuilder, MultiAir, PermutationAirBuilder, ProverStatement, Statement,
    },
    debug,
    pcs::PcsParams,
};

/// Production AIRs in the canonical instance order defined by the authored relation.
pub const AIRS: [MidenAir; MIDEN_AIR_COUNT] = {
    let mut airs = [MidenAir(source::AIRS[0]); MIDEN_AIR_COUNT];
    let mut index = 0;
    while index < MIDEN_AIR_COUNT {
        airs[index] = MidenAir(source::AIRS[index]);
        index += 1;
    }
    airs
};

/// Generated evaluator for one AIR in the Miden VM relation.
///
/// Trace metadata, auxiliary-trace construction, and lookup interactions delegate to the
/// authored AIR; only constraint evaluation uses the generated implementation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MidenAir(pub source::MidenAir);

impl MidenAir {
    pub const CORE: Self = Self(source::MidenAir::CORE);
    pub const CHIPLETS: Self = Self(source::MidenAir::CHIPLETS);
    pub const EIDOS_COMPRESSION: Self = Self(source::MidenAir::EIDOS_COMPRESSION);
    pub const AND8_LOOKUP: Self = Self(source::MidenAir::AND8_LOOKUP);

    pub const fn instance_index(self) -> usize {
        self.0.instance_index()
    }

    pub const fn name(self) -> &'static str {
        self.0.name()
    }

    /// Lookup fractions emitted per row, one entry per auxiliary lookup column.
    pub fn column_shape(self) -> &'static [usize] {
        self.0.column_shape()
    }

    pub const fn file_token(self) -> &'static str {
        self.0.file_token()
    }

    fn boundary_correction<EF: ExtensionField<Felt>>(
        self,
        challenges: &Challenges<EF>,
        aux_inputs: &[Felt],
    ) -> Result<EF, ReductionError> {
        self.0.boundary_correction(challenges, aux_inputs)
    }
}

impl BaseAir<Felt> for MidenAir {
    fn width(&self) -> usize {
        self.0.width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        self.0.preprocessed_trace()
    }

    fn preprocessed_width(&self) -> usize {
        self.0.preprocessed_width()
    }

    fn num_public_values(&self) -> usize {
        BaseAir::<Felt>::num_public_values(&self.0)
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        self.0.periodic_columns()
    }
}

impl<EF: ExtensionField<Felt>> LiftedAir<Felt, EF> for MidenAir {
    fn num_randomness(&self) -> usize {
        LiftedAir::<Felt, EF>::num_randomness(&self.0)
    }

    fn aux_width(&self) -> usize {
        LiftedAir::<Felt, EF>::aux_width(&self.0)
    }

    fn num_aux_values(&self) -> usize {
        LiftedAir::<Felt, EF>::num_aux_values(&self.0)
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        self.0.build_aux_trace(main, air_inputs, aux_inputs, challenges)
    }

    fn build_aux_trace_with_preprocessed(
        &self,
        main: &RowMajorMatrix<Felt>,
        preprocessed: Option<&RowMajorMatrix<Felt>>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[EF],
    ) -> (RowMajorMatrix<EF>, Vec<EF>) {
        self.0.build_aux_trace_with_preprocessed(
            main,
            preprocessed,
            air_inputs,
            aux_inputs,
            challenges,
        )
    }

    fn constraint_degree(&self) -> ConstraintDegrees {
        LiftedAir::<Felt, EF>::constraint_degree(&self.0)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        match self.0 {
            source::MidenAir::Core => generated::eval_core(builder),
            source::MidenAir::Chiplets => generated::eval_chiplets(builder),
            source::MidenAir::EidosCompression => generated::eval_eidos_compression(builder),
            source::MidenAir::And8Lookup => generated::eval_and8_lookup(builder),
        }
    }
}

impl<LB: LookupBuilder> LookupAir<LB> for MidenAir
where
    source::MidenAir: LookupAir<LB>,
{
    fn column_shape(&self) -> &[usize] {
        <source::MidenAir as LookupAir<LB>>::column_shape(&self.0)
    }

    fn max_message_width(&self) -> usize {
        <source::MidenAir as LookupAir<LB>>::max_message_width(&self.0)
    }

    fn num_bus_ids(&self) -> usize {
        <source::MidenAir as LookupAir<LB>>::num_bus_ids(&self.0)
    }

    fn eval(&self, builder: &mut LB) {
        <source::MidenAir as LookupAir<LB>>::eval(&self.0, builder)
    }

    fn eval_boundary<B>(&self, boundary: &mut B)
    where
        B: BoundaryBuilder<F = LB::F, EF = LB::EF>,
    {
        <source::MidenAir as LookupAir<LB>>::eval_boundary(&self.0, boundary)
    }
}

// MIDEN MULTI-AIR
// ================================================================================================

/// The cross-AIR statement for the Miden VM proof.
///
/// AIR instances come from [`AIRS`], and the external reduction combines the trace-length-weighted
/// normalized LogUp sums with the open-bus boundary corrections.
///
/// Instance order is `[Core, Chiplets, EidosCompression, And8Lookup]`; every per-AIR slice follows
/// that ordering.
#[derive(Copy, Clone, Debug)]
pub struct MidenMultiAir;

impl MidenMultiAir {
    /// Construct the Miden multi-AIR statement marker.
    pub const fn new() -> Self {
        Self
    }
}

impl Default for MidenMultiAir {
    fn default() -> Self {
        Self::new()
    }
}

impl<EF: ExtensionField<Felt>> MultiAir<Felt, EF> for MidenMultiAir {
    type Air = MidenAir;

    fn airs(&self) -> &[MidenAir] {
        &AIRS
    }

    fn max_aux_inputs(&self) -> usize {
        // aux_inputs = program hash (1 word) + deferred root (1 word) + the var-len
        // kernel-digest group: one `Word` per kernel procedure, capped at
        // `KernelDescriptor::MAX_NUM_PROCEDURES`.
        AUX_KERNEL_DIGESTS + KernelDescriptor::MAX_NUM_PROCEDURES * WORD_SIZE
    }

    /// Absorb statement-owned public inputs into the Fiat-Shamir challenger.
    ///
    /// One complete Eidos block: `[CLAIM_HASH (4) | deferred_root (4)]`, where `CLAIM_HASH` is the
    /// canonical execution-claim commitment (see `miden_core::program::ExecutionClaim`) over
    /// `program_hash ‖ kernel_H ‖ stack_inputs ‖ stack_outputs`. With the relation digest
    /// pre-loaded in the challenger (see `config`), the transcript state after this block
    /// realizes the factored statement binding `H(RELATION_DIGEST ‖ CLAIM_HASH ‖ D)`.
    ///
    /// The kernel digests enter the transcript only through `kernel_H` (see
    /// [`hash_kernel_digests`]); the raw stack I/O and digest list remain public values for
    /// constraint evaluation and are not separately absorbed.
    fn observe<C: CanObserve<Felt>>(
        &self,
        challenger: &mut C,
        air_inputs: &[Vec<Felt>],
        aux_inputs: &[Felt],
        _log_trace_heights: &[u8],
    ) {
        let core_inputs = &air_inputs[0];
        assert_eq!(core_inputs.len(), NUM_PUBLIC_VALUES, "unexpected public-value count");
        assert!(
            aux_inputs.len() >= AUX_KERNEL_DIGESTS,
            "aux inputs shorter than the fixed program-hash + deferred-root prefix"
        );

        let kernel_h = hash_kernel_digests(&aux_inputs[AUX_KERNEL_DIGESTS..]);
        let program_hash = &aux_inputs[AUX_PROGRAM_HASH..AUX_PROGRAM_HASH + WORD_SIZE];
        let deferred_root = &aux_inputs[AUX_DEFERRED_ROOT..AUX_DEFERRED_ROOT + WORD_SIZE];

        // Canonical claim encoding P ‖ K ‖ I ‖ O; the offset layout of
        // `ExecutionClaim::to_elements`, pinned by `observe_matches_execution_claim_commitment`.
        let mut claim = [Felt::ZERO; NUM_CLAIM_ELEMENTS];
        claim[0..WORD_SIZE].copy_from_slice(program_hash);
        claim[WORD_SIZE..2 * WORD_SIZE].copy_from_slice(&kernel_h);
        claim[2 * WORD_SIZE..].copy_from_slice(core_inputs);
        let claim_hash = miden_core::program::claim_commitment(&claim);

        for &v in claim_hash.as_elements().iter().chain(deferred_root) {
            challenger.observe(v);
        }
    }

    /// Cross-AIR LogUp closure: each AIR commits `sigma_prime_i = sigma_i / n_i`, so the
    /// trace-length-weighted sum `sum_i(n_i * sigma_prime_i)` plus the per-trace boundary
    /// corrections must vanish. Boundary corrections are added once and are not trace-length
    /// scaled. `aux_values` and `log_trace_heights` are parallel in instance order. `aux_inputs`
    /// carries the program hash and deferred root followed by kernel digests.
    fn eval_external(
        &self,
        challenges: &[EF],
        air_inputs: &[Vec<Felt>],
        aux_inputs: &[Felt],
        aux_values: &[&[EF]],
        log_trace_heights: &[u8],
    ) -> Result<Vec<EF>, ReductionError> {
        if aux_values.len() != AIRS.len() {
            return Err(format!(
                "expected aux values for {} AIRs, got {}",
                AIRS.len(),
                aux_values.len()
            )
            .into());
        }
        if log_trace_heights.len() != AIRS.len() {
            return Err(format!(
                "expected log heights for {} AIRs, got {}",
                AIRS.len(),
                log_trace_heights.len()
            )
            .into());
        }
        if challenges.len() != trace::AUX_TRACE_RAND_CHALLENGES {
            return Err(format!(
                "expected {} aux trace challenges, got {}",
                trace::AUX_TRACE_RAND_CHALLENGES,
                challenges.len()
            )
            .into());
        }
        if air_inputs[0].len() != NUM_PUBLIC_VALUES {
            return Err(format!(
                "expected {NUM_PUBLIC_VALUES} public values, got {}",
                air_inputs[0].len()
            )
            .into());
        }
        if aux_inputs.len() < AUX_KERNEL_DIGESTS {
            return Err(format!(
                "aux_inputs length {} is shorter than the fixed prefix {AUX_KERNEL_DIGESTS}",
                aux_inputs.len()
            )
            .into());
        }
        let max_aux_inputs = <MidenMultiAir as MultiAir<Felt, EF>>::max_aux_inputs(self);
        if aux_inputs.len() > max_aux_inputs {
            return Err(format!(
                "aux_inputs length {} exceeds maximum {max_aux_inputs}",
                aux_inputs.len()
            )
            .into());
        }
        let challenges = Challenges::<EF>::new(
            challenges[0],
            challenges[1],
            MIDEN_MAX_MESSAGE_WIDTH,
            BusId::COUNT,
        );

        let mut weighted_aux_sum = EF::ZERO;
        let mut boundary_correction = EF::ZERO;
        for ((air, values), &log_height) in
            AIRS.iter().copied().zip(aux_values.iter()).zip(log_trace_heights)
        {
            boundary_correction += air.boundary_correction(&challenges, aux_inputs)?;
            let expected = <MidenAir as LiftedAir<Felt, EF>>::num_aux_values(&air);
            if values.len() != expected {
                return Err(format!(
                    "{} expects {expected} aux boundary values, got {}",
                    air.name(),
                    values.len()
                )
                .into());
            }

            let trace_length = 1_u64.checked_shl(u32::from(log_height)).ok_or_else(|| {
                ReductionError::from(format!(
                    "{} log trace height {log_height} does not fit in u64",
                    air.name()
                ))
            })?;
            weighted_aux_sum +=
                values.iter().copied().sum::<EF>() * Felt::new_unchecked(trace_length);
        }

        Ok(vec![weighted_aux_sum + boundary_correction])
    }
}

// KERNEL DIGEST SUMMARY HASH
// ================================================================================================

/// Computes `kernel_H`, the fixed-size commitment to the kernel-procedure digests.
///
/// This is the canonical [`KernelDescriptor::commitment`] value expressed over the flattened digest
/// felts: the domain-tagged linear hash (`hash_elements_in_domain` with
/// [`miden_core::program::KERNEL_DOMAIN_TAG`]) of `kernel_felts`. The empty digest list yields
/// the canonical empty-input value under the same domain.
///
/// `kernel_H` is absorbed into the Fiat-Shamir transcript in place of the unbounded kernel
/// digest list, committing to the kernel with a fixed-size value.
pub fn hash_kernel_digests(kernel_felts: &[Felt]) -> [Felt; WORD_SIZE] {
    assert!(
        kernel_felts.len().is_multiple_of(WORD_SIZE),
        "kernel digest felts must be whole words"
    );
    assert!(
        kernel_felts.len() <= KernelDescriptor::MAX_NUM_PROCEDURES * WORD_SIZE,
        "kernel digest felts exceed KernelDescriptor::MAX_NUM_PROCEDURES"
    );

    hash_kernel_input_felts(kernel_felts)
}

fn hash_kernel_input_felts(kernel_felts: &[Felt]) -> [Felt; WORD_SIZE] {
    miden_core::chiplets::hasher::hash_elements_in_domain(
        kernel_felts,
        miden_core::program::domain::KERNEL_COMMITMENT,
    )
    .into()
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use miden_core::{
        Word,
        field::{PrimeCharacteristicRing, QuadFelt},
        program::{MIN_STACK_DEPTH, ProgramInfo, StackInputs, StackOutputs},
    };

    use super::*;

    #[test]
    fn eval_external_weights_normalized_sums_by_trace_length() {
        let multi_air = MidenMultiAir::new();
        let raw_challenges = [QuadFelt::from_u32(7), QuadFelt::from_u32(11)];
        let air_inputs = [vec![Felt::ZERO; NUM_PUBLIC_VALUES], vec![], vec![], vec![]];
        let aux_inputs = vec![Felt::ZERO; AUX_KERNEL_DIGESTS];
        let normalized_sums = [
            QuadFelt::from_u32(13),
            QuadFelt::from_u32(17),
            QuadFelt::from_u32(19),
            QuadFelt::from_u32(23),
        ];
        let core_values = [normalized_sums[0]];
        let chiplets_values = [normalized_sums[1]];
        let eidos_compression_values = [normalized_sums[2]];
        let and8_values = [normalized_sums[3]];
        let aux_values: [&[QuadFelt]; MIDEN_AIR_COUNT] =
            [&core_values, &chiplets_values, &eidos_compression_values, &and8_values];
        let log_trace_heights = [6, 9, 7, 16];

        let lookup_challenges = Challenges::new(
            raw_challenges[0],
            raw_challenges[1],
            MIDEN_MAX_MESSAGE_WIDTH,
            BusId::COUNT,
        );
        let mut boundary_correction = QuadFelt::ZERO;
        for air in AIRS {
            boundary_correction +=
                air.boundary_correction(&lookup_challenges, &aux_inputs).unwrap();
        }

        let result = <MidenMultiAir as MultiAir<Felt, QuadFelt>>::eval_external(
            &multi_air,
            &raw_challenges,
            &air_inputs,
            &aux_inputs,
            &aux_values,
            &log_trace_heights,
        )
        .unwrap();

        let weighted_sum = normalized_sums
            .iter()
            .zip(log_trace_heights)
            .map(|(&value, log_height)| value * Felt::new_unchecked(1_u64 << u32::from(log_height)))
            .sum::<QuadFelt>();
        assert_eq!(result, vec![weighted_sum + boundary_correction]);
    }

    #[test]
    fn eval_external_rejects_partial_kernel_digest() {
        let challenges =
            [QuadFelt::from(Felt::new_unchecked(3)), QuadFelt::from(Felt::new_unchecked(5))];
        let air_inputs = [vec![Felt::ZERO; NUM_PUBLIC_VALUES], vec![], vec![], vec![]];
        let mut aux_inputs = vec![Felt::ZERO; AUX_KERNEL_DIGESTS];
        aux_inputs.push(Felt::ONE);
        let zero = QuadFelt::from(Felt::ZERO);
        let core_aux = [zero];
        let chiplets_aux = [zero];
        let eidos_compression_aux = [zero];
        let and8_aux = [zero];
        let aux_values = [
            core_aux.as_slice(),
            chiplets_aux.as_slice(),
            eidos_compression_aux.as_slice(),
            and8_aux.as_slice(),
        ];

        let err = MidenMultiAir::new()
            .eval_external(&challenges, &air_inputs, &aux_inputs, &aux_values, &[8, 8, 8, 16])
            .unwrap_err();

        assert!(err.to_string().contains("kernel digest felts length 1 is not a multiple of 4"));
    }

    #[test]
    fn eval_external_rejects_too_many_kernel_digests() {
        let challenges =
            [QuadFelt::from(Felt::new_unchecked(3)), QuadFelt::from(Felt::new_unchecked(5))];
        let air_inputs = [vec![Felt::ZERO; NUM_PUBLIC_VALUES], vec![], vec![], vec![]];
        let max_aux_inputs = AUX_KERNEL_DIGESTS + KernelDescriptor::MAX_NUM_PROCEDURES * WORD_SIZE;
        let actual_aux_inputs = max_aux_inputs + WORD_SIZE;
        let aux_inputs = vec![Felt::ZERO; actual_aux_inputs];
        let zero = QuadFelt::from(Felt::ZERO);
        let core_aux = [zero];
        let chiplets_aux = [zero];
        let eidos_compression_aux = [zero];
        let and8_aux = [zero];
        let aux_values = [
            core_aux.as_slice(),
            chiplets_aux.as_slice(),
            eidos_compression_aux.as_slice(),
            and8_aux.as_slice(),
        ];

        let err = MidenMultiAir::new()
            .eval_external(&challenges, &air_inputs, &aux_inputs, &aux_values, &[8, 8, 8, 16])
            .unwrap_err();

        assert!(err.to_string().contains(&format!(
            "aux_inputs length {actual_aux_inputs} exceeds maximum {max_aux_inputs}"
        )));
    }

    #[test]
    fn hash_kernel_digests_matches_kernel_descriptor_commitment() {
        // The transcript-side helper and `KernelDescriptor::commitment` are two computations of
        // the same normative value; this pins them together (including the empty kernel).
        use miden_core::Word;

        let word = |a: u64| -> Word {
            [Felt::new_unchecked(a), Felt::new_unchecked(a + 1), Felt::ZERO, Felt::ONE].into()
        };
        for procs in [vec![], vec![word(10)], vec![word(10), word(20), word(30)]] {
            let descriptor = KernelDescriptor::from_hashes(procs).unwrap();
            let flattened: Vec<Felt> =
                descriptor.proc_hashes().iter().flat_map(|w| w.as_elements().to_vec()).collect();
            assert_eq!(
                Word::new(hash_kernel_digests(&flattened)),
                descriptor.commitment(),
                "hash_kernel_digests diverged from KernelDescriptor::commitment"
            );
        }
    }

    #[test]
    #[should_panic(expected = "kernel digest felts exceed KernelDescriptor::MAX_NUM_PROCEDURES")]
    fn hash_kernel_digests_rejects_too_many_digest_felts() {
        let kernel_felts = vec![Felt::ZERO; (KernelDescriptor::MAX_NUM_PROCEDURES + 1) * WORD_SIZE];

        let _ = hash_kernel_digests(&kernel_felts);
    }

    #[test]
    fn observe_matches_execution_claim_commitment() {
        // The transcript's statement block must open with exactly
        // `ExecutionClaim::commitment()` for the same statement, followed by the deferred
        // root — pinning `observe`'s inline claim encoding to the canonical one.
        use miden_core::{field::QuadFelt, program::ExecutionClaim};

        #[derive(Default)]
        struct FeltSink {
            observed: Vec<Felt>,
        }
        impl CanObserve<Felt> for FeltSink {
            fn observe(&mut self, value: Felt) {
                self.observed.push(value);
            }
        }

        let word = |a: u64| -> Word {
            [
                Felt::new_unchecked(a),
                Felt::new_unchecked(a + 1),
                Felt::new_unchecked(a + 2),
                Felt::new_unchecked(a + 3),
            ]
            .into()
        };
        let kernel = KernelDescriptor::from_hashes(vec![word(50), word(60)]).unwrap();
        let program_hash = word(1);
        let stack_inputs =
            StackInputs::new(&[Felt::new_unchecked(5), Felt::new_unchecked(6)]).unwrap();
        let stack_outputs = StackOutputs::new(&[Felt::new_unchecked(7)]).unwrap();
        let deferred_root = word(90);

        let claim = ExecutionClaim::from_program_info(
            ProgramInfo::new(program_hash, kernel.clone()),
            stack_inputs,
            stack_outputs,
        );

        // air_inputs = I ‖ O; aux_inputs = P ‖ D ‖ kernel digest felts.
        let mut air_inputs = [Felt::ZERO; NUM_PUBLIC_VALUES];
        air_inputs[0..MIN_STACK_DEPTH].copy_from_slice(&stack_inputs[..]);
        air_inputs[MIN_STACK_DEPTH..].copy_from_slice(&stack_outputs[..]);
        let air_inputs = [air_inputs.to_vec(), vec![], vec![], vec![]];
        let mut aux_inputs: Vec<Felt> = Vec::new();
        aux_inputs.extend(program_hash.as_elements());
        aux_inputs.extend(deferred_root.as_elements());
        aux_inputs.extend(Word::words_as_elements(kernel.proc_hashes()));

        let mut sink = FeltSink::default();
        <MidenMultiAir as MultiAir<Felt, QuadFelt>>::observe(
            &MidenMultiAir::new(),
            &mut sink,
            &air_inputs,
            &aux_inputs,
            &[10, 10, 10, 16],
        );

        let mut expected: Vec<Felt> = claim.commitment().as_elements().to_vec();
        expected.extend(deferred_root.as_elements());
        assert_eq!(sink.observed, expected, "observe must emit [CLAIM_HASH | D]");
    }

    #[test]
    #[should_panic(
        expected = "aux inputs shorter than the fixed program-hash + deferred-root prefix"
    )]
    fn observe_rejects_short_aux_inputs() {
        #[derive(Default)]
        struct FeltSink {
            observed: Vec<Felt>,
        }

        impl CanObserve<Felt> for FeltSink {
            fn observe(&mut self, value: Felt) {
                self.observed.push(value);
            }
        }

        let mut challenger = FeltSink::default();
        let air_inputs = [vec![Felt::ZERO; NUM_PUBLIC_VALUES], vec![], vec![], vec![]];
        let multi_air = MidenMultiAir::new();

        <MidenMultiAir as MultiAir<Felt, QuadFelt>>::observe(
            &multi_air,
            &mut challenger,
            &air_inputs,
            &[],
            &[8, 8, 8, 16],
        );
    }
}
