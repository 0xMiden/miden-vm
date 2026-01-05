use alloc::{sync::Arc, vec::Vec};
use core::fmt;

use miden_crypto::{
    Felt, WORD_SIZE, Word,
    field::PrimeCharacteristicRing,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::Kernel;
use crate::{
    AdviceMap,
    mast::{MastForest, MastNode, MastNodeExt, MastNodeId},
    utils::ToElements,
};

// PROGRAM
// ===============================================================================================

/// An executable program for Miden VM.
///
/// A program consists of a MAST forest, an entrypoint defining the MAST node at which the program
/// execution begins, and a definition of the kernel against which the program must be executed
/// (the kernel can be an empty kernel).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true))
)]
pub struct Program {
    mast_forest: Arc<MastForest>,
    /// The "entrypoint" is the node where execution of the program begins.
    entrypoint: MastNodeId,
    kernel: Kernel,
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
        Self::with_kernel(mast_forest, entrypoint, Kernel::default())
    }

    /// Construct a new [`Program`] from the given MAST forest, entrypoint, and kernel.
    ///
    /// # Panics:
    /// - if `mast_forest` doesn't contain the specified entrypoint.
    /// - if the specified entrypoint is not a procedure root in the `mast_forest`.
    pub fn with_kernel(
        mast_forest: Arc<MastForest>,
        entrypoint: MastNodeId,
        kernel: Kernel,
    ) -> Self {
        assert!(mast_forest.get_node_by_id(entrypoint).is_some(), "invalid entrypoint");
        assert!(mast_forest.is_procedure_root(entrypoint), "entrypoint not a procedure");

        Self { mast_forest, entrypoint, kernel }
    }

    /// Produces a new program with the existing [`MastForest`] and where all key/values in the
    /// provided advice map are added to the internal advice map.
    pub fn with_advice_map(self, advice_map: AdviceMap) -> Self {
        let mut mast_forest = (*self.mast_forest).clone();
        mast_forest.advice_map_mut().extend(advice_map);
        Self {
            mast_forest: Arc::new(mast_forest),
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
    pub fn kernel(&self) -> &Kernel {
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
        .map_err(|p| {
            match p.downcast::<std::io::Error>() {
                // SAFETY: It is guaranteed to be safe to read Box<std::io::Error>
                Ok(err) => unsafe { core::ptr::read(&*err) },
                // Propagate unknown panics
                Err(err) => std::panic::resume_unwind(err),
            }
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

/// A program information set consisting of its MAST root and set of kernel procedure roots used
/// for its compilation.
///
/// This will be used as public inputs of the proof so we bind its verification to the kernel and
/// root used to execute the program. This way, we extend the correctness of the proof to the
/// security guarantees provided by the kernel. We also allow the user to easily prove the
/// membership of a given kernel procedure for a given proof, without compromising its
/// zero-knowledge properties.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProgramInfo {
    program_hash: Word,
    kernel: Kernel,
}

impl ProgramInfo {
    /// Creates a new instance of a program info.
    pub const fn new(program_hash: Word, kernel: Kernel) -> Self {
        Self { program_hash, kernel }
    }

    /// Returns the program hash computed from its code block root.
    pub const fn program_hash(&self) -> &Word {
        &self.program_hash
    }

    /// Returns the program kernel used during the compilation.
    pub const fn kernel(&self) -> &Kernel {
        &self.kernel
    }

    /// Returns the list of procedures of the kernel used during the compilation.
    pub fn kernel_procedures(&self) -> &[Word] {
        self.kernel.proc_hashes()
    }
}

impl From<Program> for ProgramInfo {
    fn from(program: Program) -> Self {
        let program_hash = program.hash();
        let kernel = program.kernel().clone();

        Self { program_hash, kernel }
    }
}

// ------------------------------------------------------------------------------------------------
// Serialization

impl Serializable for ProgramInfo {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.program_hash.write_into(target);
        self.kernel.write_into(target);
    }
}

impl Deserializable for ProgramInfo {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let program_hash = source.read()?;
        let kernel = source.read()?;
        Ok(Self { program_hash, kernel })
    }
}

// ------------------------------------------------------------------------------------------------
// ToElements implementation

impl ToElements for ProgramInfo {
    fn to_elements(&self) -> Vec<Felt> {
        let num_kernel_proc_elements = self.kernel.proc_hashes().len() * WORD_SIZE;
        let mut result = Vec::with_capacity(2 * WORD_SIZE + num_kernel_proc_elements);

        // append program hash elements where we pad with zero so as to make the fixed length
        // public inputs section of the public inputs of length a multiple of 8 i.e., double-word
        // aligned
        result.extend_from_slice(self.program_hash.as_elements());
        result.extend_from_slice(&[Felt::ZERO; 4]);

        // append kernel procedure hash elements
        // we reverse the digests in order to make reducing them using auxiliary randomness easier
        // we also pad them to the next multiple of 8
        for proc_hash in self.kernel.proc_hashes() {
            let mut proc_hash_elements = proc_hash.as_elements().to_vec();
            pad_next_mul_8(&mut proc_hash_elements);
            proc_hash_elements.reverse();
            result.extend_from_slice(&proc_hash_elements);
        }
        result
    }
}

// HELPER
// ===============================================================================================

/// Pads a vector of field elements using zeros to the next multiple of 8.
fn pad_next_mul_8(input: &mut Vec<Felt>) {
    let output_len = input.len().next_multiple_of(8);
    input.resize(output_len, Felt::ZERO);
}
