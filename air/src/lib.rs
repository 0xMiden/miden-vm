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
    program::{ProgramInfo, StackInputs, StackOutputs},
};
use miden_crypto::stark::matrix::{Matrix, RowMajorMatrix};

pub mod config;
mod constraints;

pub mod trace;
use trace::{AUX_TRACE_WIDTH, AuxTraceBuilder, MainTraceRow, TRACE_WIDTH};

// RE-EXPORTS
// ================================================================================================
mod export {
    pub use miden_core::{
        Felt,
        serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
        utils::ToElements,
    };
    pub use miden_crypto::stark::air::{Air, AirBuilder, BaseAir, MidenAir, MidenAirBuilder};
    pub use p3_miden_air::BusType;
}

pub use export::*;

// PUBLIC INPUTS
// ================================================================================================

const BUS_TYPES: [BusType; 8] = [
    BusType::Multiset, // p1 block stack
    BusType::Multiset, // p2 block hash
    BusType::Multiset, // p3 op group
    BusType::Multiset, // s_aux stack overflow
    BusType::Logup,    // b_range
    BusType::Multiset, // b_hash_kernel (v_table)
    BusType::Multiset, // b_chiplets
    BusType::Logup,    // v_wiring
];

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

    /// Converts public inputs into a vector of field elements (Felt) in the canonical order:
    /// - program info elements
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

/// Miden VM Processor AIR implementation.
///
/// This struct defines the constraints for the Miden VM processor.
/// Generic over aux trace builder to support different extension fields.
pub struct ProcessorAir<B = ()> {
    /// Auxiliary trace builder for generating auxiliary columns.
    aux_builder: Option<B>,
    /// Public inputs cached for verifier-side checks.
    public_inputs: PublicInputs,
}

impl Default for ProcessorAir<()> {
    fn default() -> Self {
        Self::new(PublicInputs::new(
            ProgramInfo::default(),
            StackInputs::default(),
            StackOutputs::default(),
            PrecompileTranscriptState::default(),
        ))
    }
}

impl ProcessorAir<()> {
    /// Creates a new ProcessorAir without auxiliary trace support.
    pub fn new(public_inputs: PublicInputs) -> Self {
        Self { aux_builder: None, public_inputs }
    }
}

impl<B> ProcessorAir<B> {
    /// Creates a new ProcessorAir with auxiliary trace support.
    pub fn with_aux_builder(public_inputs: PublicInputs, builder: B) -> Self {
        Self {
            aux_builder: Some(builder),
            public_inputs,
        }
    }
}

impl<EF, B> MidenAir<Felt, EF> for ProcessorAir<B>
where
    EF: ExtensionField<Felt>,
    B: AuxTraceBuilder<EF>,
{
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn aux_width(&self) -> usize {
        // Return the number of extension field columns
        // The prover will interpret the returned base field data as EF columns
        AUX_TRACE_WIDTH
    }

    fn bus_types(&self) -> &[BusType] {
        &BUS_TYPES
    }

    fn num_randomness(&self) -> usize {
        trace::AUX_TRACE_RAND_ELEMENTS
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        challenges: &[EF],
    ) -> Option<RowMajorMatrix<Felt>> {
        let _span = tracing::info_span!("build_aux_trace").entered();

        let builders = self.aux_builder.as_ref()?;

        Some(builders.build_aux_columns(main, challenges))
    }

    fn eval<AB: MidenAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        use crate::constraints;

        let main = builder.main();

        // Access the two rows: current (local) and next
        let local = main.row_slice(0).expect("Matrix should have at least 1 row");
        let next = main.row_slice(1).expect("Matrix should have at least 2 rows");

        // Use structured column access via MainTraceCols
        let local: &MainTraceRow<AB::Var> = (*local).borrow();
        let next: &MainTraceRow<AB::Var> = (*next).borrow();

        // Main trace constraints.
        constraints::enforce_main(builder, local, next);

        // Auxiliary (bus) constraints.
        constraints::enforce_bus(builder, local, next);
    }

    /// Verifier hook: check aux_finals against public inputs and randomness-derived messages.
    fn verify_aux_finals(
        &self,
        randomness: &[EF],
        aux_finals: &[EF],
        _public_values: &[Felt],
        var_len_public_inputs: &[&[&[Felt]]],
    ) -> bool {
        use crate::constraints::bus::indices;

        if aux_finals.len() < AUX_TRACE_WIDTH || randomness.len() < trace::AUX_TRACE_RAND_ELEMENTS {
            return false;
        }

        let alphas = randomness;

        let aux = AuxFinals {
            p1: aux_finals[indices::P1_BLOCK_STACK],
            p2: aux_finals[indices::P2_BLOCK_HASH],
            p3: aux_finals[indices::P3_OP_GROUP],
            s_aux: aux_finals[indices::S_AUX_STACK],
            b_range: aux_finals[indices::B_RANGE],
            b_hash_kernel: aux_finals[indices::B_HASH_KERNEL],
            b_chiplets: aux_finals[indices::B_CHIPLETS],
            v_wiring: aux_finals[indices::V_WIRING],
        };

        // Program-specific bindings.
        let program_info = self.public_inputs.program_info();
        let program_hash_msg = program_hash_message(alphas, program_info.program_hash());

        // Kernel ROM digests are reduced via multiset product (var-len public inputs required).
        let kernel_procs = program_info.kernel_procedures();
        let kernel_reduced =
            match kernel_reduced_from_var_len(alphas, var_len_public_inputs, kernel_procs.len()) {
                Some(value) => value,
                None => return false,
            };

        // Transcript initial/final states for log_precompile.
        let default_state_msg =
            trace::log_precompile::transcript_message(alphas, PrecompileTranscriptState::default());
        let final_state_msg = trace::log_precompile::transcript_message(
            alphas,
            self.public_inputs.pc_transcript_state(),
        );

        // Expected final identities for simple buses. First-row initialization constraints live
        // in the wrapper AIR (AirWithBoundaryConstraints) on the p3-miden side.
        let identity_finals_ok = aux.p1 == EF::ONE
            && aux.p3 == EF::ONE
            && aux.s_aux == EF::ONE
            && aux.b_range == EF::ZERO
            && aux.v_wiring == EF::ZERO;

        // Bind the program hash to the last-row value of the block-hash table (p2).
        let program_hash_ok = aux.p2 * program_hash_msg == EF::ONE;

        // Balance hash-kernel and chiplets buses. This cancels ACE memory read requests against
        // memory chiplet responses, then links the transcript (init -> final) and kernel digests.
        // Soundness relies on the randomized message encoding: each message type has a unique
        // label in its first tuple element (domain separation), so distinct messages collide only
        // with negligible probability over random alphas.
        let bus_balance_ok = aux.b_hash_kernel * aux.b_chiplets * default_state_msg
            == kernel_reduced * final_state_msg;

        identity_finals_ok && program_hash_ok && bus_balance_ok
    }
}

// AUX FINALS HELPERS
// ================================================================================================

/// Aux-final values for each bus column used by `verify_aux_finals`.
#[derive(Clone, Copy, Debug)]
struct AuxFinals<EF> {
    p1: EF,
    p2: EF,
    p3: EF,
    s_aux: EF,
    b_range: EF,
    b_hash_kernel: EF,
    b_chiplets: EF,
    v_wiring: EF,
}

fn program_hash_message<EF: ExtensionField<Felt>>(alphas: &[EF], program_hash: &Word) -> EF {
    // Build the program-hash bus message for the initial block-hash table row.
    // Matches semantics of BlockHashTableRow::collapse for the initial program hash row:
    // parent_id=0, is_first_child=0, is_loop_body=0.
    alphas[0]
        + alphas[2] * program_hash[0]
        + alphas[3] * program_hash[1]
        + alphas[4] * program_hash[2]
        + alphas[5] * program_hash[3]
}

fn kernel_reduced_from_var_len<EF: ExtensionField<Felt>>(
    alphas: &[EF],
    var_len_public_inputs: &[&[&[Felt]]],
    expected_len: usize,
) -> Option<EF> {
    // Expect exactly one var-len group containing kernel procedure digests, each as 4 felts.
    // Return None if the group is missing, has the wrong length, or contains malformed digests.
    // On success, return the multiset product of the kernel-proc messages for those digests.
    if var_len_public_inputs.len() != 1 {
        return None;
    }

    let kernel_digests = var_len_public_inputs[0];

    if kernel_digests.len() != expected_len {
        return None;
    }

    let mut acc = EF::ONE;
    for digest in kernel_digests.iter() {
        let digest = *digest;
        if digest.len() != WORD_SIZE {
            return None;
        }

        let word: Word = [digest[0], digest[1], digest[2], digest[3]].into();
        acc *= kernel_proc_message(alphas, &word);
    }

    Some(acc)
}

fn kernel_proc_message<EF: ExtensionField<Felt>>(alphas: &[EF], digest: &Word) -> EF {
    // Build the kernel-proc init message.
    alphas[0]
        + alphas[1] * trace::chiplets::kernel_rom::KERNEL_PROC_INIT_LABEL
        + alphas[2] * digest[0]
        + alphas[3] * digest[1]
        + alphas[4] * digest[2]
        + alphas[5] * digest[3]
}
