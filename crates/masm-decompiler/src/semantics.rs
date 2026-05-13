//! Shared MASM instruction classification used by lifting-adjacent analyses.

use std::ops::Range;

use miden_assembly_syntax::ast::Instruction;

pub(crate) const INTRINSIC_ADV_PIPE: &str = "adv_pipe";
pub(crate) const INTRINSIC_ADV_PUSH: &str = "adv_push";
pub(crate) const INTRINSIC_ADV_PUSHW: &str = "adv_pushw";
pub(crate) const INTRINSIC_MEM_STREAM: &str = "mem_stream";
pub(crate) const INTRINSIC_MTREE_GET: &str = "mtree_get";
pub(crate) const INTRINSIC_MTREE_MERGE: &str = "mtree_merge";
pub(crate) const INTRINSIC_MTREE_SET: &str = "mtree_set";
pub(crate) const INTRINSIC_MTREE_VERIFY: &str = "mtree_verify";
pub(crate) const INTRINSIC_U32DIV: &str = "u32div";
pub(crate) const INTRINSIC_U32DIVMOD: &str = "u32divmod";
pub(crate) const INTRINSIC_U32MOD: &str = "u32mod";

/// Return the base intrinsic name before immediates or `.err=*` suffixes.
pub fn intrinsic_base_name(name: &str) -> &str {
    name.split_once('.').map_or(name, |(base, _)| base)
}

/// Return true if an intrinsic requires caller-side `U32` preconditions.
pub fn intrinsic_requires_u32_precondition(name: &str) -> bool {
    if !name.starts_with("u32") {
        return false;
    }

    !matches!(
        intrinsic_base_name(name),
        "u32assert" | "u32assert2" | "u32assertw" | "u32cast" | "u32split" | "u32test" | "u32testw"
    )
}

/// Return true if this intrinsic asserts that all arguments are valid `u32` values.
pub fn intrinsic_asserts_u32_args(name: &str) -> bool {
    matches!(intrinsic_base_name(name), "u32assert" | "u32assert2" | "u32assertw")
}

/// Return the memory address argument for streaming advice intrinsics.
pub fn intrinsic_memory_address_arg_index(name: &str, arg_count: usize) -> Option<usize> {
    match intrinsic_base_name(name) {
        INTRINSIC_MEM_STREAM | INTRINSIC_ADV_PIPE => arg_count.checked_sub(1),
        _ => None,
    }
}

/// Return the positional argument range that must satisfy `u32` for this intrinsic.
pub fn intrinsic_positional_u32_arg_range(name: &str, arg_count: usize) -> Option<Range<usize>> {
    match intrinsic_base_name(name) {
        INTRINSIC_MTREE_GET | INTRINSIC_MTREE_SET if arg_count >= 2 => Some(0..2),
        INTRINSIC_MTREE_VERIFY if arg_count >= 6 => Some(4..6),
        _ => intrinsic_memory_address_arg_index(name, arg_count).map(|index| index..index + 1),
    }
}

/// Return the Merkle-root argument range for Merkle tree intrinsics.
pub fn intrinsic_merkle_root_arg_range(
    name: &str,
    arg_count: usize,
    result_count: usize,
) -> Option<Range<usize>> {
    match intrinsic_base_name(name) {
        INTRINSIC_MTREE_GET if arg_count == 6 && result_count == 4 => Some(2..6),
        INTRINSIC_MTREE_SET if arg_count == 10 && result_count == 8 => Some(2..6),
        INTRINSIC_MTREE_VERIFY if arg_count == 10 && result_count == 0 => Some(6..10),
        _ => None,
    }
}

/// Return the divisor-like argument that must be non-zero for this intrinsic.
pub fn intrinsic_nonzero_arg_index(name: &str) -> Option<usize> {
    match name {
        INTRINSIC_U32DIV | INTRINSIC_U32MOD | INTRINSIC_U32DIVMOD => Some(0),
        _ => None,
    }
}

/// Advice transfer shape for intrinsics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntrinsicAdviceTransferShape {
    /// Outputs are direct advice sources.
    AdviceSourceOutputs,
    /// Arguments are sanitized by the intrinsic.
    SanitizeArguments,
    /// `u32split`, whose top result is known to be `u32`.
    U32Split,
    /// `u32testw`, whose flag is known to be `u32` and whose other outputs preserve inputs.
    U32TestWord,
    /// `adv_pipe`, whose sponge capacity is preserved and whose remaining outputs are advice.
    AdvicePipe,
    /// `mem_stream`, whose address is propagated and whose sponge capacity is preserved.
    MemoryStream,
    /// Outputs are unconstrained by advice and carry no metadata.
    BottomOutputs,
    /// Outputs are unconstrained by advice and known to be `u32`.
    U32Outputs,
    /// Outputs inherit joined advice provenance from all arguments.
    PropagateJoinedInputs,
}

/// Return the intrinsic transfer shape used by unconstrained-advice analysis.
pub fn intrinsic_advice_transfer_shape(name: &str) -> IntrinsicAdviceTransferShape {
    let base = intrinsic_base_name(name);
    match base {
        INTRINSIC_ADV_PUSH | INTRINSIC_ADV_PUSHW => {
            IntrinsicAdviceTransferShape::AdviceSourceOutputs
        },
        "u32assert" | "u32assert2" | "u32assertw" => {
            IntrinsicAdviceTransferShape::SanitizeArguments
        },
        "u32split" => IntrinsicAdviceTransferShape::U32Split,
        "u32testw" => IntrinsicAdviceTransferShape::U32TestWord,
        INTRINSIC_ADV_PIPE => IntrinsicAdviceTransferShape::AdvicePipe,
        INTRINSIC_MEM_STREAM => IntrinsicAdviceTransferShape::MemoryStream,
        "is_odd" | "sdepth" => IntrinsicAdviceTransferShape::BottomOutputs,
        _ if name.starts_with("locaddr") => IntrinsicAdviceTransferShape::BottomOutputs,
        _ if intrinsic_requires_u32_precondition(name) => IntrinsicAdviceTransferShape::U32Outputs,
        _ => IntrinsicAdviceTransferShape::PropagateJoinedInputs,
    }
}

/// Type shape for intrinsic outputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IntrinsicOutputTypeShape {
    /// Every output is a felt unless another analysis proves more.
    Felt,
    /// Every output is a `U32`.
    U32,
    /// Every output is a boolean.
    Bool,
    /// Multi-output shape where non-top outputs are `U32` and the top output is boolean.
    U32WithTopBool,
    /// Multi-output shape where non-top outputs are boolean and the top output is `U32`.
    BoolWithTopU32,
    /// `u32widening_add3`, whose carry output depends on the carry input type.
    U32WideningAdd3,
}

/// Return the intrinsic output type shape used by type inference.
pub(crate) fn intrinsic_output_type_shape(name: &str) -> IntrinsicOutputTypeShape {
    let base = intrinsic_base_name(name);
    match base {
        "u32overflowing_add" | "u32overflowing_sub" | "u32overflowing_add3" => {
            IntrinsicOutputTypeShape::U32WithTopBool
        },
        "u32widening_add" => IntrinsicOutputTypeShape::BoolWithTopU32,
        "u32widening_add3" => IntrinsicOutputTypeShape::U32WideningAdd3,
        "u32widening_mul" | "u32widening_madd" | "u32divmod" | "u32split" | "u32mod"
        | "u32wrapping_add3" | "u32wrapping_madd" => IntrinsicOutputTypeShape::U32,
        "u32testw" => IntrinsicOutputTypeShape::Bool,
        _ if base.starts_with("u32") || name == "sdepth" || name.starts_with("locaddr.") => {
            IntrinsicOutputTypeShape::U32
        },
        "is_odd" => IntrinsicOutputTypeShape::Bool,
        _ => IntrinsicOutputTypeShape::Felt,
    }
}

/// Repetitive stack-operation families that carry a depth or word index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StackFamily {
    Dup(usize),
    DupWord(usize),
    Swap(usize),
    SwapWord(usize),
    SwapDoubleWord,
    MovUp(usize),
    MovUpWord(usize),
    MovDown(usize),
    MovDownWord(usize),
}

/// Stack effect metadata for a repetitive stack-operation family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StackFamilyEffect {
    pub(crate) pops: usize,
    pub(crate) pushes: usize,
    pub(crate) required_depth: usize,
}

impl StackFamily {
    pub(crate) const fn effect(self) -> StackFamilyEffect {
        match self {
            StackFamily::Dup(index) => StackFamilyEffect {
                pops: 0,
                pushes: 1,
                required_depth: index + 1,
            },
            StackFamily::DupWord(index) => StackFamilyEffect {
                pops: 0,
                pushes: 4,
                required_depth: (index + 1) * 4,
            },
            StackFamily::Swap(index) | StackFamily::MovUp(index) | StackFamily::MovDown(index) => {
                let depth = index + 1;
                StackFamilyEffect {
                    pops: depth,
                    pushes: depth,
                    required_depth: depth,
                }
            },
            StackFamily::SwapWord(index)
            | StackFamily::MovUpWord(index)
            | StackFamily::MovDownWord(index) => {
                let depth = (index + 1) * 4;
                StackFamilyEffect {
                    pops: depth,
                    pushes: depth,
                    required_depth: depth,
                }
            },
            StackFamily::SwapDoubleWord => {
                StackFamilyEffect { pops: 16, pushes: 16, required_depth: 16 }
            },
        }
    }
}

/// Return stack-family metadata for indexed stack manipulation instructions.
pub(crate) fn stack_family(inst: &Instruction) -> Option<StackFamily> {
    use Instruction::*;

    Some(match inst {
        Dup0 => StackFamily::Dup(0),
        Dup1 => StackFamily::Dup(1),
        Dup2 => StackFamily::Dup(2),
        Dup3 => StackFamily::Dup(3),
        Dup4 => StackFamily::Dup(4),
        Dup5 => StackFamily::Dup(5),
        Dup6 => StackFamily::Dup(6),
        Dup7 => StackFamily::Dup(7),
        Dup8 => StackFamily::Dup(8),
        Dup9 => StackFamily::Dup(9),
        Dup10 => StackFamily::Dup(10),
        Dup11 => StackFamily::Dup(11),
        Dup12 => StackFamily::Dup(12),
        Dup13 => StackFamily::Dup(13),
        Dup14 => StackFamily::Dup(14),
        Dup15 => StackFamily::Dup(15),

        DupW0 => StackFamily::DupWord(0),
        DupW1 => StackFamily::DupWord(1),
        DupW2 => StackFamily::DupWord(2),
        DupW3 => StackFamily::DupWord(3),

        Swap1 => StackFamily::Swap(1),
        Swap2 => StackFamily::Swap(2),
        Swap3 => StackFamily::Swap(3),
        Swap4 => StackFamily::Swap(4),
        Swap5 => StackFamily::Swap(5),
        Swap6 => StackFamily::Swap(6),
        Swap7 => StackFamily::Swap(7),
        Swap8 => StackFamily::Swap(8),
        Swap9 => StackFamily::Swap(9),
        Swap10 => StackFamily::Swap(10),
        Swap11 => StackFamily::Swap(11),
        Swap12 => StackFamily::Swap(12),
        Swap13 => StackFamily::Swap(13),
        Swap14 => StackFamily::Swap(14),
        Swap15 => StackFamily::Swap(15),

        SwapW1 => StackFamily::SwapWord(1),
        SwapW2 => StackFamily::SwapWord(2),
        SwapW3 => StackFamily::SwapWord(3),
        SwapDw => StackFamily::SwapDoubleWord,

        MovUp2 => StackFamily::MovUp(2),
        MovUp3 => StackFamily::MovUp(3),
        MovUp4 => StackFamily::MovUp(4),
        MovUp5 => StackFamily::MovUp(5),
        MovUp6 => StackFamily::MovUp(6),
        MovUp7 => StackFamily::MovUp(7),
        MovUp8 => StackFamily::MovUp(8),
        MovUp9 => StackFamily::MovUp(9),
        MovUp10 => StackFamily::MovUp(10),
        MovUp11 => StackFamily::MovUp(11),
        MovUp12 => StackFamily::MovUp(12),
        MovUp13 => StackFamily::MovUp(13),
        MovUp14 => StackFamily::MovUp(14),
        MovUp15 => StackFamily::MovUp(15),

        MovUpW2 => StackFamily::MovUpWord(2),
        MovUpW3 => StackFamily::MovUpWord(3),

        MovDn2 => StackFamily::MovDown(2),
        MovDn3 => StackFamily::MovDown(3),
        MovDn4 => StackFamily::MovDown(4),
        MovDn5 => StackFamily::MovDown(5),
        MovDn6 => StackFamily::MovDown(6),
        MovDn7 => StackFamily::MovDown(7),
        MovDn8 => StackFamily::MovDown(8),
        MovDn9 => StackFamily::MovDown(9),
        MovDn10 => StackFamily::MovDown(10),
        MovDn11 => StackFamily::MovDown(11),
        MovDn12 => StackFamily::MovDown(12),
        MovDn13 => StackFamily::MovDown(13),
        MovDn14 => StackFamily::MovDown(14),
        MovDn15 => StackFamily::MovDown(15),

        MovDnW2 => StackFamily::MovDownWord(2),
        MovDnW3 => StackFamily::MovDownWord(3),

        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use miden_assembly_syntax::ast::Instruction;

    use super::{
        IntrinsicAdviceTransferShape, IntrinsicOutputTypeShape, intrinsic_advice_transfer_shape,
        intrinsic_asserts_u32_args, intrinsic_base_name, intrinsic_memory_address_arg_index,
        intrinsic_merkle_root_arg_range, intrinsic_nonzero_arg_index, intrinsic_output_type_shape,
        intrinsic_positional_u32_arg_range, intrinsic_requires_u32_precondition, stack_family,
    };

    #[test]
    fn intrinsic_base_name_strips_suffixes() {
        assert_eq!(intrinsic_base_name("u32assert.err=123"), "u32assert");
        assert_eq!(intrinsic_base_name("u32div.7"), "u32div");
        assert_eq!(intrinsic_base_name("adv_pipe"), "adv_pipe");
    }

    #[test]
    fn u32_precondition_classification_matches_lint_semantics() {
        assert!(intrinsic_requires_u32_precondition("u32div"));
        assert!(intrinsic_requires_u32_precondition("u32div.7"));

        assert!(!intrinsic_requires_u32_precondition("u32assert"));
        assert!(!intrinsic_requires_u32_precondition("u32assert.err=123"));
        assert!(!intrinsic_requires_u32_precondition("u32split"));
        assert!(!intrinsic_requires_u32_precondition("u32test"));
        assert!(!intrinsic_requires_u32_precondition("u32testw"));
        assert!(!intrinsic_requires_u32_precondition("mtree_get"));
    }

    #[test]
    fn u32_assert_classification_includes_error_suffixes() {
        assert!(intrinsic_asserts_u32_args("u32assert"));
        assert!(intrinsic_asserts_u32_args("u32assert2"));
        assert!(intrinsic_asserts_u32_args("u32assertw.err=123"));

        assert!(!intrinsic_asserts_u32_args("u32div"));
        assert!(!intrinsic_asserts_u32_args("u32split"));
    }

    #[test]
    fn positional_u32_arg_ranges_cover_special_intrinsics() {
        assert_eq!(intrinsic_positional_u32_arg_range("mtree_get", 6), Some(0..2));
        assert_eq!(intrinsic_positional_u32_arg_range("mtree_set", 10), Some(0..2));
        assert_eq!(intrinsic_positional_u32_arg_range("mtree_verify", 10), Some(4..6));
        assert_eq!(intrinsic_positional_u32_arg_range("adv_pipe", 13), Some(12..13));
        assert_eq!(intrinsic_positional_u32_arg_range("mem_stream", 13), Some(12..13));

        assert_eq!(intrinsic_positional_u32_arg_range("mtree_verify", 5), None);
        assert_eq!(intrinsic_positional_u32_arg_range("assert_eq", 2), None);
    }

    #[test]
    fn memory_address_arg_index_is_last_streaming_arg() {
        assert_eq!(intrinsic_memory_address_arg_index("adv_pipe", 13), Some(12));
        assert_eq!(intrinsic_memory_address_arg_index("mem_stream", 1), Some(0));
        assert_eq!(intrinsic_memory_address_arg_index("mem_stream", 0), None);
        assert_eq!(intrinsic_memory_address_arg_index("mtree_get", 6), None);
    }

    #[test]
    fn merkle_root_arg_ranges_require_expected_shapes() {
        assert_eq!(intrinsic_merkle_root_arg_range("mtree_get", 6, 4), Some(2..6));
        assert_eq!(intrinsic_merkle_root_arg_range("mtree_set", 10, 8), Some(2..6));
        assert_eq!(intrinsic_merkle_root_arg_range("mtree_verify", 10, 0), Some(6..10));

        assert_eq!(intrinsic_merkle_root_arg_range("mtree_get", 5, 4), None);
        assert_eq!(intrinsic_merkle_root_arg_range("mtree_verify", 10, 1), None);
        assert_eq!(intrinsic_merkle_root_arg_range("adv_pipe", 13, 13), None);
    }

    #[test]
    fn nonzero_arg_index_only_covers_runtime_divisors() {
        assert_eq!(intrinsic_nonzero_arg_index("u32div"), Some(0));
        assert_eq!(intrinsic_nonzero_arg_index("u32mod"), Some(0));
        assert_eq!(intrinsic_nonzero_arg_index("u32divmod"), Some(0));

        assert_eq!(intrinsic_nonzero_arg_index("u32div.4"), None);
        assert_eq!(intrinsic_nonzero_arg_index("u32mod.4"), None);
        assert_eq!(intrinsic_nonzero_arg_index("inv"), None);
    }

    #[test]
    fn intrinsic_advice_transfer_shapes_cover_advice_analysis_cases() {
        assert_eq!(
            intrinsic_advice_transfer_shape("adv_pushw"),
            IntrinsicAdviceTransferShape::AdviceSourceOutputs
        );
        assert_eq!(
            intrinsic_advice_transfer_shape("u32assert.err=123"),
            IntrinsicAdviceTransferShape::SanitizeArguments
        );
        assert_eq!(
            intrinsic_advice_transfer_shape("u32split"),
            IntrinsicAdviceTransferShape::U32Split
        );
        assert_eq!(
            intrinsic_advice_transfer_shape("u32testw"),
            IntrinsicAdviceTransferShape::U32TestWord
        );
        assert_eq!(
            intrinsic_advice_transfer_shape("adv_pipe"),
            IntrinsicAdviceTransferShape::AdvicePipe
        );
        assert_eq!(
            intrinsic_advice_transfer_shape("mem_stream"),
            IntrinsicAdviceTransferShape::MemoryStream
        );
        assert_eq!(
            intrinsic_advice_transfer_shape("locaddr.0"),
            IntrinsicAdviceTransferShape::BottomOutputs
        );
        assert_eq!(
            intrinsic_advice_transfer_shape("u32div"),
            IntrinsicAdviceTransferShape::U32Outputs
        );
        assert_eq!(
            intrinsic_advice_transfer_shape("assert_eq"),
            IntrinsicAdviceTransferShape::PropagateJoinedInputs
        );
    }

    #[test]
    fn intrinsic_output_type_shapes_cover_type_inference_cases() {
        assert_eq!(
            intrinsic_output_type_shape("u32overflowing_add"),
            IntrinsicOutputTypeShape::U32WithTopBool
        );
        assert_eq!(
            intrinsic_output_type_shape("u32widening_add"),
            IntrinsicOutputTypeShape::BoolWithTopU32
        );
        assert_eq!(
            intrinsic_output_type_shape("u32widening_add3"),
            IntrinsicOutputTypeShape::U32WideningAdd3
        );
        assert_eq!(intrinsic_output_type_shape("u32divmod"), IntrinsicOutputTypeShape::U32);
        assert_eq!(intrinsic_output_type_shape("u32testw"), IntrinsicOutputTypeShape::Bool);
        assert_eq!(intrinsic_output_type_shape("u32div.4"), IntrinsicOutputTypeShape::U32);
        assert_eq!(intrinsic_output_type_shape("locaddr.0"), IntrinsicOutputTypeShape::U32);
        assert_eq!(intrinsic_output_type_shape("is_odd"), IntrinsicOutputTypeShape::Bool);
        assert_eq!(intrinsic_output_type_shape("adv_pipe"), IntrinsicOutputTypeShape::Felt);
    }

    #[test]
    fn stack_family_effects_cover_repetitive_stack_instructions() {
        let effect = stack_family(&Instruction::Dup3).expect("dup classified").effect();
        assert_eq!((effect.pops, effect.pushes, effect.required_depth), (0, 1, 4));

        let effect = stack_family(&Instruction::DupW2).expect("dupw classified").effect();
        assert_eq!((effect.pops, effect.pushes, effect.required_depth), (0, 4, 12));

        let effect = stack_family(&Instruction::Swap4).expect("swap classified").effect();
        assert_eq!((effect.pops, effect.pushes, effect.required_depth), (5, 5, 5));

        let effect = stack_family(&Instruction::MovUpW3).expect("movupw classified").effect();
        assert_eq!((effect.pops, effect.pushes, effect.required_depth), (16, 16, 16));

        let effect = stack_family(&Instruction::MovDn15).expect("movdn classified").effect();
        assert_eq!((effect.pops, effect.pushes, effect.required_depth), (16, 16, 16));

        let effect = stack_family(&Instruction::SwapDw).expect("swapdw classified").effect();
        assert_eq!((effect.pops, effect.pushes, effect.required_depth), (16, 16, 16));

        assert!(stack_family(&Instruction::Drop).is_none());
    }
}
