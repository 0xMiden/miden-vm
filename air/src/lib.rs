#![no_std]

#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::vec::Vec;
use core::borrow::Borrow;

use miden_core::{
    WORD_SIZE, Word,
    field::ExtensionField,
    precompile::PrecompileTranscriptState,
    program::{MIN_STACK_DEPTH, ProgramInfo, StackInputs, StackOutputs},
};
use miden_crypto::stark::air::{
    ReducedAuxValues, ReductionError, VarLenPublicInputs, WindowAccess,
};

pub mod ace;
pub mod config;
mod constraints;

/// Public surface for the prover-side LogUp collection phase.
///
/// Re-exports the stable API of the internal `constraints::lookup` module so downstream
/// crates (notably `miden-processor` tests) can drive `MidenLookupAir` through
/// [`build_lookup_fractions`] without the rest of `constraints::lookup` leaking.
pub mod lookup {
    pub use crate::constraints::lookup::{
        ColumnOracleBuilder, LookupAir, LookupChallenges, LookupFractions, MidenLookupAir,
        MidenLookupAuxBuilder, ProverLookupBuilder, accumulate, accumulate_slow,
        build_lookup_fractions, collect_column_oracle_folds,
    };
}

pub mod trace;
use constraints::columns::MainCols;
use trace::{TRACE_WIDTH, bus_types};

// RE-EXPORTS
// ================================================================================================
mod export {
    pub use miden_core::{
        Felt,
        serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
        utils::ToElements,
    };
    pub use miden_crypto::stark::{
        air::{
            AirBuilder, AirWitness, AuxBuilder, BaseAir, ExtensionBuilder, LiftedAir,
            LiftedAirBuilder, PermutationAirBuilder,
        },
        debug,
    };
}

pub use export::*;

// MIDEN AIR BUILDER
// ================================================================================================

/// Convenience super-trait that pins `LiftedAirBuilder` to our field.
///
/// All constraint functions in this crate should be generic over `AB: MidenAirBuilder`
/// instead of spelling out the full `LiftedAirBuilder<F = Felt>` bound.
pub trait MidenAirBuilder: LiftedAirBuilder<F = Felt> {}
impl<T: LiftedAirBuilder<F = Felt>> MidenAirBuilder for T {}

// PUBLIC INPUTS
// ================================================================================================

#[derive(Debug, Clone)]
pub struct PublicInputs {
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    pc_transcript_state: PrecompileTranscriptState,
}

impl PublicInputs {
    /// Creates a new instance of `PublicInputs` from program information, stack inputs and outputs,
    /// and the precompile transcript state (capacity of an internal sponge).
    pub fn new(
        program_info: ProgramInfo,
        stack_inputs: StackInputs,
        stack_outputs: StackOutputs,
        pc_transcript_state: PrecompileTranscriptState,
    ) -> Self {
        Self {
            program_info,
            stack_inputs,
            stack_outputs,
            pc_transcript_state,
        }
    }

    pub fn stack_inputs(&self) -> StackInputs {
        self.stack_inputs
    }

    pub fn stack_outputs(&self) -> StackOutputs {
        self.stack_outputs
    }

    pub fn program_info(&self) -> ProgramInfo {
        self.program_info.clone()
    }

    /// Returns the precompile transcript state.
    pub fn pc_transcript_state(&self) -> PrecompileTranscriptState {
        self.pc_transcript_state
    }

    /// Returns the fixed-length public values and the variable-length kernel procedure digests
    /// as a flat slice of `Felt`s.
    ///
    /// The fixed-length public values layout is:
    ///   [0..4]   program hash
    ///   [4..20]  stack inputs
    ///   [20..36] stack outputs
    ///   [36..40] precompile transcript state
    ///
    /// The kernel procedure digests are returned as a single flat `Vec<Felt>` (concatenated
    /// words), to be passed as a single variable-length public input slice to the verifier.
    pub fn to_air_inputs(&self) -> (Vec<Felt>, Vec<Felt>) {
        let mut public_values = Vec::with_capacity(NUM_PUBLIC_VALUES);
        public_values.extend_from_slice(self.program_info.program_hash().as_elements());
        public_values.extend_from_slice(self.stack_inputs.as_ref());
        public_values.extend_from_slice(self.stack_outputs.as_ref());
        public_values.extend_from_slice(self.pc_transcript_state.as_ref());

        let kernel_felts: Vec<Felt> =
            Word::words_as_elements(self.program_info.kernel_procedures()).to_vec();

        (public_values, kernel_felts)
    }

    /// Converts public inputs into a vector of field elements (Felt) in the canonical order:
    /// - program info elements (including kernel procedure hashes)
    /// - stack inputs
    /// - stack outputs
    /// - precompile transcript state
    pub fn to_elements(&self) -> Vec<Felt> {
        let mut result = self.program_info.to_elements();
        result.extend_from_slice(self.stack_inputs.as_ref());
        result.extend_from_slice(self.stack_outputs.as_ref());
        result.extend_from_slice(self.pc_transcript_state.as_ref());
        result
    }
}

// SERIALIZATION
// ================================================================================================

impl Serializable for PublicInputs {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.program_info.write_into(target);
        self.stack_inputs.write_into(target);
        self.stack_outputs.write_into(target);
        self.pc_transcript_state.write_into(target);
    }
}

impl Deserializable for PublicInputs {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let program_info = ProgramInfo::read_from(source)?;
        let stack_inputs = StackInputs::read_from(source)?;
        let stack_outputs = StackOutputs::read_from(source)?;
        let pc_transcript_state = PrecompileTranscriptState::read_from(source)?;

        Ok(PublicInputs {
            program_info,
            stack_inputs,
            stack_outputs,
            pc_transcript_state,
        })
    }
}

// PROCESSOR AIR
// ================================================================================================

/// Number of fixed-length public values for the Miden VM AIR.
///
/// Layout (40 Felts total):
///   [0..4]   program hash
///   [4..20]  stack inputs
///   [20..36] stack outputs
///   [36..40] precompile transcript state
pub const NUM_PUBLIC_VALUES: usize = WORD_SIZE + MIN_STACK_DEPTH + MIN_STACK_DEPTH + WORD_SIZE;

/// LogUp aux trace width — 4 main-trace columns (M1, M_2+5, M3, M4) + 3 chiplet-trace
/// columns (C1, C2, C3). Matches `MidenLookupAir::num_columns()` and the per-row shape
/// returned by `MidenLookupAuxBuilder::build_aux_trace`.
pub const LOGUP_AUX_TRACE_WIDTH: usize = 7;

// Public values layout offsets.
//
// Currently unused while `ProcessorAir::reduced_aux_values` is stubbed (Milestone B,
// decision D3). Kept in place because the follow-up milestone will reuse them when
// restoring real LogUp boundary checks with public-input correction terms.
#[allow(dead_code)]
const PV_PROGRAM_HASH: usize = 0;
#[allow(dead_code)]
const PV_TRANSCRIPT_STATE: usize = NUM_PUBLIC_VALUES - WORD_SIZE;

/// Miden VM Processor AIR implementation.
///
/// Auxiliary trace building is handled separately via [`AuxBuilder`].
///
/// Public-input-dependent boundary checks are performed in [`LiftedAir::reduced_aux_values`].
/// Aux columns are NOT initialized with boundary terms -- they start at identity. The verifier
/// independently computes expected boundary messages from variable length public values and checks
/// them against the final column values.
#[derive(Copy, Clone, Debug, Default)]
pub struct ProcessorAir;

// --- Upstream trait impls for ProcessorAir ---

impl BaseAir<Felt> for ProcessorAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

// --- LiftedAir impl ---

impl<EF: ExtensionField<Felt>> LiftedAir<Felt, EF> for ProcessorAir {
    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        constraints::chiplets::columns::PeriodicCols::periodic_columns()
    }

    fn num_randomness(&self) -> usize {
        trace::AUX_TRACE_RAND_CHALLENGES
    }

    fn aux_width(&self) -> usize {
        // Milestone B: the LogUp lookup argument occupies 7 columns —
        // 4 main-trace columns (M1, M_2+5, M3, M4) + 3 chiplet-trace columns (C1, C2, C3).
        // Matches `MidenLookupAir::num_columns()` and the per-row shape returned by
        // `MidenLookupAuxBuilder::build_aux_trace`. The legacy `AUX_TRACE_WIDTH = 8`
        // constant is still in `trace::mod` for now and will be removed alongside the
        // legacy multiset offset constants in a follow-up commit.
        LOGUP_AUX_TRACE_WIDTH
    }

    fn num_aux_values(&self) -> usize {
        LOGUP_AUX_TRACE_WIDTH
    }

    /// Returns the number of variable-length public input slices.
    ///
    /// The Miden VM AIR uses a single variable-length slice that contains all kernel
    /// procedure digests as concatenated field elements (each digest is `WORD_SIZE`
    /// elements). The verifier framework uses this count to validate that the correct
    /// number of slices is provided.
    fn num_var_len_public_inputs(&self) -> usize {
        1
    }

    fn reduced_aux_values(
        &self,
        _aux_values: &[EF],
        _challenges: &[EF],
        _public_values: &[Felt],
        _var_len_public_inputs: VarLenPublicInputs<'_, Felt>,
    ) -> Result<ReducedAuxValues<EF>, ReductionError>
    where
        EF: ExtensionField<Felt>,
    {
        // Milestone B (decision D3): stub — return the verifier identity.
        //
        // The verifier checks `reduced_aux.is_identity()` (i.e. `prod == ONE && sum == ZERO`)
        // after combining contributions from every AIR. Returning the identity directly
        // is the only safe stub; any other choice triggers `VerifierError::InvalidReducedAux`.
        //
        // The LogUp boundary / transition constraints are commented out in
        // `air/src/constraints/lookup/constraint.rs::ConstraintColumn::column`, so the aux
        // trace is committed and observed but not symbolically constrained. The follow-up
        // milestone will restore real boundary checks (with public-input correction terms
        // for the open buses: block_hash, chiplets bus, log_precompile transcript) and
        // recompute `prod` / `sum` from the LogUp column finals.
        Ok(ReducedAuxValues { prod: EF::ONE, sum: EF::ZERO })
    }

    fn eval<AB: MidenAirBuilder>(&self, builder: &mut AB) {
        use crate::constraints::{
            self,
            lookup::{ConstraintLookupBuilder, LookupAir, MidenLookupAir},
        };

        let main = builder.main();

        // Access the two rows: current (local) and next
        let local = main.current_slice();
        let next = main.next_slice();

        // Use structured column access via MainTraceCols
        let local: &MainCols<AB::Var> = (*local).borrow();
        let next: &MainCols<AB::Var> = (*next).borrow();

        // Build chiplet selectors and op flags once, shared by main and bus constraints.
        let selectors =
            constraints::chiplets::selectors::build_chiplet_selectors(builder, local, next);
        let op_flags =
            constraints::op_flags::OpFlags::new(&local.decoder, &local.stack, &next.decoder);

        // Main trace constraints.
        constraints::enforce_main(builder, local, next, &selectors, &op_flags);

        // LogUp lookup-argument constraints (Milestone B). The closure-based
        // `MidenLookupAir` aggregates the four main-trace columns and three chiplet-trace
        // columns; `ConstraintLookupBuilder::new` reads α/β out of `permutation_randomness()`
        // and precomputes the bus prefix table from the AIR's `column_shape`. Boundary /
        // first-row / last-row checks inside `ConstraintColumn::column` are commented out
        // for this milestone — see the `TODO(milestone-B-followup)` block in
        // `air/src/constraints/lookup/constraint.rs`.
        {
            let mut lb = ConstraintLookupBuilder::new(builder, &MidenLookupAir);
            MidenLookupAir.eval(&mut lb);
        }

        // Public inputs boundary constraints.
        constraints::public_inputs::enforce_main(builder, local);
    }
}

// REDUCED AUX VALUES HELPERS
// ================================================================================================
//
// Milestone B (decision D3): `ProcessorAir::reduced_aux_values` is stubbed to the verifier
// identity, so the helpers below have no live caller. They are kept in place because the
// follow-up milestone will reuse them when restoring real LogUp boundary checks (with
// public-input correction terms for the open buses: block_hash, chiplets bus,
// log_precompile transcript).

/// Builds the program-hash bus message for the block-hash table boundary term.
///
/// Must match `BlockHashTableRow::from_end().collapse()` on the prover side for the
/// root block, which encodes `[parent_id=0, hash[0..4], is_first_child=0, is_loop_body=0]`.
#[allow(dead_code)]
fn program_hash_message<EF: ExtensionField<Felt>>(
    challenges: &trace::Challenges<EF>,
    program_hash: &Word,
) -> EF {
    challenges.encode(
        bus_types::BLOCK_HASH_TABLE,
        [
            Felt::ZERO, // parent_id = 0 (root block)
            program_hash[0],
            program_hash[1],
            program_hash[2],
            program_hash[3],
            Felt::ZERO, // is_first_child = false
            Felt::ZERO, // is_loop_body = false
        ],
    )
}

/// Returns the pair of (initial, final) log-precompile transcript messages for the
/// virtual-table bus boundary term.
///
/// The initial message uses the default (zero) capacity state; the final message uses
/// the public-input transcript state.
#[allow(dead_code)]
fn transcript_messages<EF: ExtensionField<Felt>>(
    challenges: &trace::Challenges<EF>,
    final_state: PrecompileTranscriptState,
) -> (EF, EF) {
    let encode = |state: PrecompileTranscriptState| {
        let cap: &[Felt] = state.as_ref();
        challenges.encode(
            bus_types::LOG_PRECOMPILE_TRANSCRIPT,
            [Felt::from_u8(trace::LOG_PRECOMPILE_LABEL), cap[0], cap[1], cap[2], cap[3]],
        )
    };
    (encode(PrecompileTranscriptState::default()), encode(final_state))
}

/// Builds the kernel procedure init message for the kernel ROM bus.
///
/// Must match `KernelRomInitMessage::value()` on the prover side, which encodes
/// `[KERNEL_PROC_INIT_LABEL, digest[0..4]]`.
#[allow(dead_code)]
fn kernel_proc_message<EF: ExtensionField<Felt>>(
    challenges: &trace::Challenges<EF>,
    digest: &Word,
) -> EF {
    challenges.encode(
        bus_types::CHIPLETS_BUS,
        [
            trace::chiplets::kernel_rom::KERNEL_PROC_INIT_LABEL,
            digest[0],
            digest[1],
            digest[2],
            digest[3],
        ],
    )
}

/// Reduces kernel procedure digests from var-len public inputs into a multiset product.
///
/// Expects exactly one variable-length public input slice containing all kernel digests
/// as concatenated `Felt`s (i.e. `len % WORD_SIZE == 0`).
#[allow(dead_code)]
fn kernel_reduced_from_var_len<EF: ExtensionField<Felt>>(
    challenges: &trace::Challenges<EF>,
    var_len_public_inputs: VarLenPublicInputs<'_, Felt>,
) -> Result<EF, ReductionError> {
    if var_len_public_inputs.len() != 1 {
        return Err(format!(
            "expected 1 var-len public input slice, got {}",
            var_len_public_inputs.len()
        )
        .into());
    }
    let kernel_felts = var_len_public_inputs[0];
    if !kernel_felts.len().is_multiple_of(WORD_SIZE) {
        return Err(format!(
            "kernel digest felts length {} is not a multiple of {}",
            kernel_felts.len(),
            WORD_SIZE
        )
        .into());
    }
    let mut acc = EF::ONE;
    for digest in kernel_felts.chunks_exact(WORD_SIZE) {
        let word: Word = [digest[0], digest[1], digest[2], digest[3]].into();
        acc *= kernel_proc_message(challenges, &word);
    }
    Ok(acc)
}
