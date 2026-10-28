//! Authored Miden VM AIRs, trace schemas, public inputs, and relation boundaries.

pub mod ace;
mod airs;
mod constraints;
mod execution_trace;
mod inputs;
pub mod logup;
#[cfg(test)]
mod lookup_tests;
mod proof_order;
pub mod statement;
pub mod trace;

#[cfg(test)]
mod tests;

pub use airs::{
    And8LookupAir, ChipletsAir, CoreAir, EidosCompressionAir, LOGUP_AUX_TRACE_WIDTH, MidenAir,
    MidenAirBuilder,
};
pub use constraints::{
    and8_lookup,
    and8_lookup::columns::{And8LookupCols, And8LookupPreprocessedCols},
    chiplets::columns::{
        AceCols, AceEvalCols, AceReadCols, AeadStreamCols, AeadStreamHighFirstCols,
        AeadStreamHighSecondCols, AeadStreamLowSecondCols, AeadStreamReadCols, BitwiseCols,
        ControllerCols, KernelRomCols, MemoryCols,
    },
    columns::{ChipletCols, CoreCols},
    decoder::columns::DecoderCols,
    eidos_compression,
    eidos_compression::{EidosCompressionCols, NUM_COLS as NUM_EIDOS_COMPRESSION_COLS},
    ext_field::QuadFeltExpr,
    stack::columns::StackCols,
    system::columns::SystemCols,
};
pub use execution_trace::{ChipletsLengths, TraceLenSummary, VmTrace};
pub use inputs::{NUM_PUBLIC_VALUES, PublicInputs};
pub use miden_core::{
    Felt,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
    utils::ToElements,
};
pub use miden_stark::{
    StarkConfig,
    air::{
        AirBuilder, BaseAir, ConstraintCounts, ConstraintDegrees, ExtensionBuilder, LiftedAir,
        LiftedAirBuilder, MultiAir, PermutationAirBuilder, ProverStatement, Statement,
    },
    debug,
    pcs::PcsParams,
};
pub use proof_order::{AIRS, MIDEN_AIR_COUNT};
pub use statement::hash_kernel_digests;
