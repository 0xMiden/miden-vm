//! VM public values, statement-input layout, and public-input serialization.

use alloc::vec::Vec;

#[cfg(feature = "arbitrary")]
use miden_core::program::KernelDescriptor;
use miden_core::{
    Felt, WORD_SIZE, Word,
    deferred::DeferredRoot,
    program::{MIN_STACK_DEPTH, ProgramInfo, StackInputs, StackOutputs},
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
    utils::ToElements,
};
#[cfg(feature = "arbitrary")]
use proptest::{
    arbitrary::{Arbitrary, any},
    strategy::{BoxedStrategy, Strategy},
};

// INPUT LAYOUT
// ================================================================================================

/// Number of public values read by Core; the other Miden VM AIRs have no public values.
///
/// Layout (32 Felts total):
///   [0..16]  stack inputs
///   [16..32] stack outputs
///
/// The program hash and final deferred root are not read by any AIR constraint, so they
/// are carried as `aux_inputs` and consumed only by
/// [`MidenMultiAir::observe`](miden_lifted_air::MultiAir::observe) and
/// [`MidenMultiAir::eval_external`](miden_lifted_air::MultiAir::eval_external).
pub const NUM_PUBLIC_VALUES: usize = MIN_STACK_DEPTH + MIN_STACK_DEPTH;

// `aux_inputs` layout offsets — statement inputs that the AIRs do not read. The fixed program
// hash and final deferred root occupy the first two words; the variable-length kernel-procedure
// digests follow.
pub(super) const AUX_PROGRAM_HASH: usize = 0;
pub(super) const AUX_DEFERRED_ROOT: usize = WORD_SIZE;
pub(super) const AUX_KERNEL_DIGESTS: usize = 2 * WORD_SIZE;

// PUBLIC INPUTS
// ================================================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serialization_macros::serialization_test
)]
pub struct PublicInputs {
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    deferred_root: DeferredRoot,
}

impl PublicInputs {
    /// Creates a new instance of `PublicInputs` from program information, stack inputs and outputs,
    /// and the final deferred root.
    pub fn new(
        program_info: ProgramInfo,
        stack_inputs: StackInputs,
        stack_outputs: StackOutputs,
        deferred_root: DeferredRoot,
    ) -> Self {
        Self {
            program_info,
            stack_inputs,
            stack_outputs,
            deferred_root,
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

    /// Returns the final deferred root.
    pub fn deferred_root(&self) -> DeferredRoot {
        self.deferred_root
    }

    /// Returns the canonical commitment to the kernel of the verified statement: the value the
    /// recursive verifier observes into the transcript in place of the raw kernel-procedure
    /// digest list. See
    /// [`KernelDescriptor::commitment`](miden_core::program::KernelDescriptor::commitment).
    pub fn kernel_commitment(&self) -> Word {
        self.program_info.kernel_commitment()
    }

    /// Returns the AIR public values (`air_inputs`) and statement inputs (`aux_inputs`).
    ///
    /// `air_inputs` (read by Core; all other AIRs have empty slices) layout:
    ///   [0..16]  stack inputs
    ///   [16..32] stack outputs
    ///
    /// `aux_inputs` (statement inputs not read by the AIRs, consumed only by `observe` and
    /// `eval_external`) layout:
    ///   [0..4]   program hash
    ///   [4..8]   final deferred root
    ///   [8..]    kernel procedure digests (concatenated words, variable length)
    pub fn to_air_inputs(&self) -> (Vec<Felt>, Vec<Felt>) {
        let mut air_inputs = Vec::with_capacity(NUM_PUBLIC_VALUES);
        air_inputs.extend_from_slice(self.stack_inputs.as_ref());
        air_inputs.extend_from_slice(self.stack_outputs.as_ref());

        let kernel_felts = Word::words_as_elements(self.program_info.kernel_procedures());
        let mut aux_inputs = Vec::with_capacity(AUX_KERNEL_DIGESTS + kernel_felts.len());
        aux_inputs.extend_from_slice(self.program_info.program_hash().as_elements());
        aux_inputs.extend_from_slice(self.deferred_root.as_ref());
        aux_inputs.extend_from_slice(kernel_felts);

        (air_inputs, aux_inputs)
    }

    /// Converts public inputs into a vector of field elements (Felt) in the canonical order:
    /// - program info elements (including kernel procedure hashes)
    /// - stack inputs
    /// - stack outputs
    /// - final deferred root
    pub fn to_elements(&self) -> Vec<Felt> {
        let mut result = self.program_info.to_elements();
        result.extend_from_slice(self.stack_inputs.as_ref());
        result.extend_from_slice(self.stack_outputs.as_ref());
        result.extend_from_slice(self.deferred_root.as_ref());
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
        self.deferred_root.write_into(target);
    }
}

impl Deserializable for PublicInputs {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let program_info = ProgramInfo::read_from(source)?;
        let stack_inputs = StackInputs::read_from(source)?;
        let stack_outputs = StackOutputs::read_from(source)?;
        let deferred_root = DeferredRoot::read_from(source)?;

        Ok(PublicInputs {
            program_info,
            stack_inputs,
            stack_outputs,
            deferred_root,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl Arbitrary for PublicInputs {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        fn felt_strategy() -> impl Strategy<Value = Felt> {
            any::<u32>().prop_map(Felt::from)
        }

        fn word_strategy() -> impl Strategy<Value = Word> {
            any::<[u32; WORD_SIZE]>().prop_map(|values| Word::new(values.map(Felt::from)))
        }

        let program_info = word_strategy()
            .prop_map(|program_hash| ProgramInfo::new(program_hash, KernelDescriptor::default()));
        let stack_inputs = proptest::collection::vec(felt_strategy(), 0..=MIN_STACK_DEPTH)
            .prop_map(|values| StackInputs::new(&values).expect("generated stack inputs fit"));
        let stack_outputs = proptest::collection::vec(felt_strategy(), 0..=MIN_STACK_DEPTH)
            .prop_map(|values| StackOutputs::new(&values).expect("generated stack outputs fit"));

        (program_info, stack_inputs, stack_outputs, word_strategy())
            .prop_map(|(program_info, stack_inputs, stack_outputs, deferred_root)| {
                Self::new(program_info, stack_inputs, stack_outputs, deferred_root)
            })
            .boxed()
    }
}
