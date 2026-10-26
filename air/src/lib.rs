//! Production VM and precompile AIRs, generated artifacts, and accepted identities.

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod ace;
mod airs;
pub mod config;
mod handwritten;
pub mod precompiles;
mod proof_order;
pub mod security;
pub mod shared;
mod statement;

pub use airs::MidenAir;
pub use handwritten::HandwrittenMidenAir;
// Authored trace layouts, lookup contracts, and public-input types used by production AIRs.
pub use miden_air_definitions::{
    AceCols, AceEvalCols, AceReadCols, AeadStreamCols, AeadStreamHighFirstCols,
    AeadStreamHighSecondCols, AeadStreamLowSecondCols, AeadStreamReadCols, And8LookupAir,
    And8LookupCols, And8LookupPreprocessedCols, BitwiseCols, ChipletCols, ChipletsAir,
    ControllerCols, CoreAir, CoreCols, DecoderCols, EidosCompressionAir, EidosCompressionCols,
    KernelRomCols, LOGUP_AUX_TRACE_WIDTH, MemoryCols, MidenAirBuilder, NUM_EIDOS_COMPRESSION_COLS,
    NUM_PUBLIC_VALUES, PublicInputs, QuadFeltExpr, StackCols, SystemCols, and8_lookup,
    eidos_compression, geometry, hash_kernel_digests, logup, lookup, trace,
};
// Existing generic compatibility exports remain available at their public root paths.
pub use miden_core::{
    Felt,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
    utils::ToElements,
};
pub use miden_lifted_stark::{
    StarkConfig,
    air::{
        AirBuilder, BaseAir, ConstraintCounts, ConstraintDegrees, ExtensionBuilder, LiftedAir,
        LiftedAirBuilder, MultiAir, PermutationAirBuilder, ProverStatement, Statement,
    },
    debug,
    pcs::PcsParams,
};
pub use proof_order::{AIRS, MIDEN_AIR_COUNT, PROOF_ORDER_COUNT, ProofOrder};
pub use statement::MidenMultiAir;
