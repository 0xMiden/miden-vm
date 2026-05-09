//! Shared MASM instruction classification used by lifting-adjacent analyses.

use std::ops::Range;

pub const INTRINSIC_ADV_PIPE: &str = "adv_pipe";
pub const INTRINSIC_ADV_PUSH: &str = "adv_push";
pub const INTRINSIC_ADV_PUSHW: &str = "adv_pushw";
pub const INTRINSIC_MEM_STREAM: &str = "mem_stream";
pub const INTRINSIC_MTREE_GET: &str = "mtree_get";
pub const INTRINSIC_MTREE_MERGE: &str = "mtree_merge";
pub const INTRINSIC_MTREE_SET: &str = "mtree_set";
pub const INTRINSIC_MTREE_VERIFY: &str = "mtree_verify";
pub const INTRINSIC_U32DIV: &str = "u32div";
pub const INTRINSIC_U32DIVMOD: &str = "u32divmod";
pub const INTRINSIC_U32MOD: &str = "u32mod";

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

#[cfg(test)]
mod tests {
    use super::{
        intrinsic_asserts_u32_args, intrinsic_base_name, intrinsic_memory_address_arg_index,
        intrinsic_merkle_root_arg_range, intrinsic_nonzero_arg_index,
        intrinsic_positional_u32_arg_range, intrinsic_requires_u32_precondition,
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
}
