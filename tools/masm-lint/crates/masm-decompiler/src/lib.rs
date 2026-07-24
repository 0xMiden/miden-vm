mod abstract_interp;
mod callgraph;
mod frontend;
mod ir;
mod lift;
mod semantics;
mod signature;
mod symbol;
mod types;

#[doc(hidden)]
pub mod analysis {
    //! Internal analysis-facing surface consumed by `masm-analysis`.

    pub use crate::{
        abstract_interp::{
            FixpointConfig, FixpointOutcome, FixpointResult, JoinSemiLattice, iterate_to_fixpoint,
        },
        callgraph::CallGraph,
        frontend::{LibraryRoot, Program, Workspace},
        ir::{
            AdvLoad, AdvStore, BinOp, Call, Constant, Expr, IfPhi, IndexExpr, Intrinsic,
            LocalAccessKind, LocalLoad, LocalStore, LocalStoreW, LoopPhi, LoopVar, MemAccessKind,
            MemLoad, MemStore, Stmt, UnOp, ValueId, Var, VarBase,
        },
        lift::{LiftingError, LiftingResult, lift_proc},
        semantics::{
            IntrinsicAdviceTransferShape, IntrinsicArgRequirements,
            intrinsic_advice_transfer_shape, intrinsic_arg_requirements,
            intrinsic_asserts_u32_args, intrinsic_base_name, intrinsic_memory_address_arg_index,
            intrinsic_merkle_root_arg_range, intrinsic_nonzero_arg_index,
            intrinsic_positional_u32_arg_range, intrinsic_requires_u32_precondition,
        },
        signature::{
            ProcSignature, SignatureMap, infer_signatures, refine_public_signature_inputs,
        },
        symbol::{
            path::SymbolPath,
            resolution::{ResolutionError, ResolutionResult, SymbolResolver, create_resolver},
        },
        types::{
            InferredType, TypeRequirement, TypeSummary, TypeSummaryMap, VarKey,
            infer_type_summaries_from_lifted,
        },
    };
}
