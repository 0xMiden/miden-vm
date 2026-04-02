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

pub mod config;
mod constraints;

pub mod trace;
use trace::{AUX_TRACE_WIDTH, MainTraceRow, TRACE_WIDTH, bus_types};

// RE-EXPORTS
// ================================================================================================
mod export {
    pub use miden_core::{
        Felt,
        serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
        utils::ToElements,
    };
    pub use miden_crypto::stark::air::{
        AirBuilder, AuxBuilder, BaseAir, ExtensionBuilder, LiftedAir, LiftedAirBuilder,
        PermutationAirBuilder,
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

// Public values layout offsets.
const PV_PROGRAM_HASH: usize = 0;
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
        trace::chiplets::PeriodicCols::periodic_columns()
    }

    fn num_randomness(&self) -> usize {
        trace::AUX_TRACE_RAND_CHALLENGES
    }

    fn aux_width(&self) -> usize {
        AUX_TRACE_WIDTH
    }

    fn num_aux_values(&self) -> usize {
        AUX_TRACE_WIDTH
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
        aux_values: &[EF],
        challenges: &[EF],
        public_values: &[Felt],
        var_len_public_inputs: VarLenPublicInputs<'_, Felt>,
    ) -> Result<ReducedAuxValues<EF>, ReductionError>
    where
        EF: ExtensionField<Felt>,
    {
        // Extract final aux column values.
        let p1 = aux_values[trace::DECODER_AUX_TRACE_OFFSET];
        let p2 = aux_values[trace::DECODER_AUX_TRACE_OFFSET + 1];
        let p3 = aux_values[trace::DECODER_AUX_TRACE_OFFSET + 2];
        let s_aux = aux_values[trace::STACK_AUX_TRACE_OFFSET];
        let b_range = aux_values[trace::RANGE_CHECK_AUX_TRACE_OFFSET];
        let b_hash_kernel = aux_values[trace::HASH_KERNEL_VTABLE_AUX_TRACE_OFFSET];
        let b_chiplets = aux_values[trace::CHIPLETS_BUS_AUX_TRACE_OFFSET];
        let v_wiring = aux_values[trace::ACE_CHIPLET_WIRING_BUS_OFFSET];

        // Parse fixed-length public values (see `NUM_PUBLIC_VALUES` for layout).
        if public_values.len() != NUM_PUBLIC_VALUES {
            return Err(format!(
                "expected {} public values, got {}",
                NUM_PUBLIC_VALUES,
                public_values.len()
            )
            .into());
        }
        let program_hash: Word = public_values[PV_PROGRAM_HASH..PV_PROGRAM_HASH + WORD_SIZE]
            .try_into()
            .map_err(|_| -> ReductionError { "invalid program hash slice".into() })?;
        let pc_transcript_state: PrecompileTranscriptState = public_values
            [PV_TRANSCRIPT_STATE..PV_TRANSCRIPT_STATE + WORD_SIZE]
            .try_into()
            .map_err(|_| -> ReductionError { "invalid transcript state slice".into() })?;

        // Precompute challenge powers once for all bus message encodings.
        let challenges = trace::Challenges::<EF>::new(challenges[0], challenges[1]);

        // Compute expected bus messages from public inputs and derived challenges.
        let ph_msg = program_hash_message(&challenges, &program_hash);

        let (default_transcript_msg, final_transcript_msg) =
            transcript_messages(&challenges, pc_transcript_state);

        let kernel_reduced = kernel_reduced_from_var_len(&challenges, var_len_public_inputs)?;

        // Combine all multiset column finals with reduced variable length public-inputs.
        //
        // Running-product columns accumulate `responses / requests` at each row, so
        // their final value is product(responses) / product(requests) over the entire trace.
        //
        // Columns whose requests and responses fully cancel end at 1:
        //   p1  (block stack table) -- every block pushed is later popped
        //   p3  (op group table)    -- every op group pushed is later consumed
        //   s_aux (stack overflow)  -- every overflow push has a matching pop
        //
        // Columns with public-input-dependent boundary terms end at non-unity values:
        //
        //   p2 (block hash table):
        //     The root block's hash is removed from the table at END, but was never
        //     added (the root has no parent that would add it). This leaves one
        //     unmatched removal: p2_final = 1 / ph_msg.
        //
        //   b_hash_kernel (chiplets virtual table: sibling table + transcript state):
        //     The log_precompile transcript tracking chain starts by removing
        //     default_transcript_msg (initial capacity state) and ends by inserting
        //     final_transcript_msg (final capacity state). On the other hand, sibling table
        //     entries cancel out. Net: b_hk_final = final_transcript_msg / default_transcript_msg.
        //
        //   b_chiplets (chiplets bus):
        //     Each unique kernel procedure produces a KernelRomInitMessage response
        //     from the kernel ROM chiplet These init messages are matched by the verifier
        //     via public inputs. Net: b_ch_final = product(kernel_init_msgs) = kernel_reduced.
        //
        // Multiplying all finals with correction terms:
        //   prod = (p1 * p3 * s_aux)                               -- each is 1
        //        * (p2 * ph_msg)                                   -- (1/ph_msg) * ph_msg = 1
        //        * (b_hk * default_msg / final_msg)                -- cancels to 1
        //        * (b_ch / kernel_reduced)                         -- cancels to 1
        //
        // Rearranged: prod = all_finals * ph_msg * default_msg / (final_msg * kernel_reduced) (= 1)
        let expected_denom = final_transcript_msg * kernel_reduced;
        let expected_denom_inv = expected_denom
            .try_inverse()
            .ok_or_else(|| -> ReductionError { "zero denominator in reduced_aux_values".into() })?;

        let prod = p1
            * p2
            * p3
            * s_aux
            * b_hash_kernel
            * b_chiplets
            * ph_msg
            * default_transcript_msg
            * expected_denom_inv;

        // LogUp: all columns should end at 0.
        let sum = b_range + v_wiring;

        Ok(ReducedAuxValues { prod, sum })
    }

    fn eval<AB: MidenAirBuilder>(&self, builder: &mut AB) {
        use crate::constraints;

        let main = builder.main();

        // Access the two rows: current (local) and next
        let local = main.current_slice();
        let next = main.next_slice();

        // Use structured column access via MainTraceCols
        let local: &MainTraceRow<AB::Var> = (*local).borrow();
        let next: &MainTraceRow<AB::Var> = (*next).borrow();

        // Build chiplet selectors once, pass to both main and bus constraints.
        let selectors =
            constraints::chiplets::selectors::build_chiplet_selectors(builder, local, next);

        // Main trace constraints.
        constraints::enforce_main(builder, local, next, &selectors);

        // Auxiliary (bus) constraints.
        constraints::enforce_bus(builder, local, next, &selectors);

        // Public inputs boundary constraints.
        constraints::public_inputs::enforce_main(builder, local);
    }
}

// REDUCED AUX VALUES HELPERS
// ================================================================================================

/// Builds the program-hash bus message for the block-hash table boundary term.
///
/// Must match `BlockHashTableRow::from_end().collapse()` on the prover side for the
/// root block, which encodes `[parent_id=0, hash[0..4], is_first_child=0, is_loop_body=0]`.
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
