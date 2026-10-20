use alloc::{sync::Arc, vec::Vec};
use core::fmt;

use crate::{
    Felt, WORD_SIZE, Word,
    advice::AdviceMap,
    mast::{MastForest, MastNode, MastNodeExt, MastNodeId},
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
    utils::ToElements,
};

mod claim;
pub use claim::{CLAIM_DOMAIN_TAG, ExecutionClaim, NUM_CLAIM_ELEMENTS, claim_commitment};

pub mod domain;

mod request;
pub use request::{PROOF_REQUEST_DOMAIN_TAG, proof_request_key};

mod kernel;
pub use kernel::{KERNEL_DOMAIN_TAG, KernelDescriptor, KernelError, hash_kernel_leaf};

mod stack;
pub use stack::{InputError, MIN_STACK_DEPTH, OutputError, StackInputs, StackOutputs};

// PROGRAM
// ===============================================================================================

/// An executable program for Miden VM.
///
/// A program consists of a MAST forest, an entrypoint defining the MAST node at which the program
/// execution begins, and a definition of the kernel against which the program must be executed
/// (the kernel can be an empty kernel).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serialization_macros::serialization_test
)]
pub struct Program {
    mast_forest: Arc<MastForest>,
    /// The "entrypoint" is the node where execution of the program begins.
    entrypoint: MastNodeId,
    kernel: KernelDescriptor,
}

/// Constructors
impl Program {
    /// Construct a new [`Program`] from the given MAST forest and entrypoint. The kernel is assumed
    /// to be empty.
    ///
    /// # Panics:
    /// - if `mast_forest` doesn't contain the specified entrypoint.
    /// - if the specified entrypoint is not a procedure root in the `mast_forest`.
    pub fn new(mast_forest: Arc<MastForest>, entrypoint: MastNodeId) -> Self {
        Self::with_kernel(mast_forest, entrypoint, KernelDescriptor::default())
    }

    /// Construct a new [`Program`] from the given MAST forest, entrypoint, and kernel.
    ///
    /// # Panics:
    /// - if `mast_forest` doesn't contain the specified entrypoint.
    /// - if the specified entrypoint is not a procedure root in the `mast_forest`.
    pub fn with_kernel(
        mast_forest: Arc<MastForest>,
        entrypoint: MastNodeId,
        kernel: KernelDescriptor,
    ) -> Self {
        assert!(mast_forest.get_node_by_id(entrypoint).is_some(), "invalid entrypoint");
        assert!(mast_forest.is_procedure_root(entrypoint), "entrypoint not a procedure");

        Self { mast_forest, entrypoint, kernel }
    }

    /// Produces a new program with the existing [`MastForest`] and where all key/values in the
    /// provided advice map are added to the internal advice map.
    pub fn with_advice_map(self, advice_map: AdviceMap) -> Self {
        Self {
            mast_forest: Arc::new((*self.mast_forest).clone().with_advice_map(advice_map)),
            ..self
        }
    }
}

// ------------------------------------------------------------------------------------------------
/// Public accessors
impl Program {
    /// Returns the hash of the program's entrypoint.
    ///
    /// Equivalently, returns the hash of the root of the entrypoint procedure.
    pub fn hash(&self) -> Word {
        self.mast_forest[self.entrypoint].digest()
    }

    /// Returns the entrypoint associated with this program.
    pub fn entrypoint(&self) -> MastNodeId {
        self.entrypoint
    }

    /// Returns a reference to the underlying [`MastForest`].
    pub fn mast_forest(&self) -> &Arc<MastForest> {
        &self.mast_forest
    }

    /// Returns the kernel associated with this program.
    pub fn kernel(&self) -> &KernelDescriptor {
        &self.kernel
    }

    /// Returns the [`MastNode`] associated with the provided [`MastNodeId`] if valid, or else
    /// `None`.
    ///
    /// This is the fallible version of indexing (e.g. `program[node_id]`).
    #[inline(always)]
    pub fn get_node_by_id(&self, node_id: MastNodeId) -> Option<&MastNode> {
        self.mast_forest.get_node_by_id(node_id)
    }

    /// Returns the [`MastNodeId`] of the procedure root associated with a given digest, if any.
    #[inline(always)]
    pub fn find_procedure_root(&self, digest: Word) -> Option<MastNodeId> {
        self.mast_forest.find_procedure_root(digest)
    }

    /// Returns the number of procedures in this program.
    pub fn num_procedures(&self) -> u32 {
        self.mast_forest.num_procedures()
    }

    /// Returns basic information about this program (i.e., program hash and kernel).
    pub fn to_info(&self) -> ProgramInfo {
        ProgramInfo::new(self.hash(), self.kernel().commitment())
    }
}

// ------------------------------------------------------------------------------------------------
/// Serialization
#[cfg(feature = "std")]
impl Program {
    /// Writes this [Program] to the provided file path.
    pub fn write_to_file<P>(&self, path: P) -> std::io::Result<()>
    where
        P: AsRef<std::path::Path>,
    {
        let path = path.as_ref();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }

        // NOTE: We're protecting against unwinds here due to i/o errors that will get turned into
        // panics if writing to the underlying file fails. This is because ByteWriter does not have
        // fallible APIs, thus WriteAdapter has to panic if writes fail. This could be fixed, but
        // that has to happen upstream in miden-crypto
        std::panic::catch_unwind(|| match std::fs::File::create(path) {
            Ok(ref mut file) => {
                self.write_into(file);
                Ok(())
            },
            Err(err) => Err(err),
        })
        .map_err(|p| match p.downcast::<std::io::Error>() {
            Ok(err) => *err,
            // Propagate unknown panics
            Err(err) => std::panic::resume_unwind(err),
        })?
    }
}

impl Serializable for Program {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.mast_forest.write_into(target);
        self.kernel.write_into(target);
        target.write_u32(self.entrypoint.into());
    }
}

impl Deserializable for Program {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mast_forest = Arc::new(source.read()?);
        let kernel = source.read()?;
        let entrypoint = MastNodeId::from_u32_safe(source.read_u32()?, &mast_forest)?;

        if !mast_forest.is_procedure_root(entrypoint) {
            return Err(DeserializationError::InvalidValue(format!(
                "entrypoint {entrypoint} is not a procedure"
            )));
        }

        Ok(Self::with_kernel(mast_forest, entrypoint, kernel))
    }
}

// ------------------------------------------------------------------------------------------------
// Pretty-printing

impl crate::prettier::PrettyPrint for Program {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;
        let entrypoint = self.mast_forest[self.entrypoint()].to_pretty_print(&self.mast_forest);

        indent(4, const_text("begin") + nl() + entrypoint.render()) + nl() + const_text("end")
    }
}

impl fmt::Display for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::prettier::PrettyPrint;
        self.pretty_print(f)
    }
}

// PROGRAM INFO
// ===============================================================================================

/// Public program identity: its MAST root and the authorized kernel Merkle root.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serialization_macros::serialization_test
)]
pub struct ProgramInfo {
    program_hash: Word,
    kernel_root: Word,
}

impl ProgramInfo {
    /// Creates public program identity from the expected program and kernel roots.
    pub const fn new(program_hash: Word, kernel_root: Word) -> Self {
        Self { program_hash, kernel_root }
    }

    /// Returns the program's MAST root.
    pub const fn program_hash(&self) -> &Word {
        &self.program_hash
    }

    /// Returns the authorized kernel Merkle root.
    pub const fn kernel_root(&self) -> Word {
        self.kernel_root
    }

    /// Splits this identity into its program and kernel roots.
    pub fn into_parts(self) -> (Word, Word) {
        (self.program_hash, self.kernel_root)
    }
}

impl Default for ProgramInfo {
    fn default() -> Self {
        Self::new(Word::default(), KernelDescriptor::default().commitment())
    }
}

impl From<Program> for ProgramInfo {
    fn from(program: Program) -> Self {
        program.to_info()
    }
}

impl Serializable for ProgramInfo {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.program_hash.write_into(target);
        self.kernel_root.write_into(target);
    }
}

impl Deserializable for ProgramInfo {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        Ok(Self::new(source.read()?, source.read()?))
    }
}

impl ToElements for ProgramInfo {
    fn to_elements(&self) -> Vec<Felt> {
        let mut elements = Vec::with_capacity(2 * WORD_SIZE);
        elements.extend_from_slice(self.program_hash.as_elements());
        elements.extend_from_slice(self.kernel_root.as_elements());
        elements
    }
}

// // ARBITRARY (proptest)
// ================================================================================================

#[cfg(any(test, feature = "arbitrary"))]
mod arbitrary {
    use proptest::prelude::*;

    use super::{KernelDescriptor, ProgramInfo};
    use crate::Word;

    impl Arbitrary for ProgramInfo {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            // KernelDescriptor's own strategy already produces normalized, valid kernels
            // (distinct words below `MAX_NUM_PROCEDURES`), and any word is a valid program hash.
            (any::<Word>(), any::<KernelDescriptor>())
                .prop_map(|(program_hash, kernel)| {
                    ProgramInfo::new(program_hash, kernel.commitment())
                })
                .boxed()
        }
    }
}
