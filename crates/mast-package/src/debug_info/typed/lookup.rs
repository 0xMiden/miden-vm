//! Read-only helpers over a [`Package`]'s debug sections: section loading, function lookup,
//! and shared type-name predicates.

use alloc::{
    format,
    string::{String, ToString},
};

use super::super::{DebugFunctionInfo, DebugFunctionsSection, DebugTypesSection};
use crate::{Package, PackageDebugInfoError};

/// Reads both debug sections from `package` through the trusted [`Package::debug_info`] path.
///
/// `Ok(None)` if the package carries no debug info or has it but is missing either the functions or
/// the types section. `Err` propagates the package debug-info trust and decode policy (untrusted or
/// malformed sections); the caller decides whether to surface it or degrade to an untyped display.
pub(super) fn read_debug_sections(
    package: &Package,
) -> Result<Option<(DebugFunctionsSection, DebugTypesSection)>, PackageDebugInfoError> {
    let Some(info) = package.debug_info()? else {
        return Ok(None);
    };
    match (info.functions, info.types) {
        (Some(funcs), Some(types)) => Ok(Some((funcs, types))),
        _ => Ok(None),
    }
}

/// Finds the debug entry for `procedure_name`.
///
/// Each entry has a long compiler name; we compare only its bare leaf (via `proc_display_name`).
/// The exact query name is tried first, the kebab form second, so a hand-written MASM proc
/// whose name really contains `_` (`foo_bar`) is never shadowed by a compiler entry that only
/// matches after the rewrite (`foo-bar`). Rust contract names become kebab (`get-count`), so a
/// `get_count` query resolves through the kebab pass.
///
/// The compiler writes the same procedure under two names: the `::`-path form (`..."get-count"`)
/// carries the full typed signature, the `#`-form (`...@0.1.0#get-count`) the lowered (felt) one.
/// Within each pass we prefer the `::`-path form, because it retains the high-level WIT
/// types (e.g. `AccountId`, `Word`) we want to preserve, whereas the `#`-form has already been
/// lowered to raw felts. We fall back to any entry with a `type_idx`, then to any match at all;
/// ties keep the first entry in iteration order.
pub(super) fn find_debug_fn<'a>(
    funcs: &'a DebugFunctionsSection,
    procedure_name: &str,
) -> Option<&'a DebugFunctionInfo> {
    let kebab = procedure_name.replace('_', "-");
    [procedure_name, kebab.as_str()].into_iter().find_map(|target| {
        let mut typed_path: Option<&DebugFunctionInfo> = None;
        let mut typed_any: Option<&DebugFunctionInfo> = None;
        let mut first_any: Option<&DebugFunctionInfo> = None;
        for f in &funcs.functions {
            let Some(s) = funcs.strings.get(f.name_idx as usize) else {
                continue;
            };
            let s = s.as_ref();
            if proc_display_name(s) != target {
                continue;
            }
            first_any.get_or_insert(f);
            if f.type_idx.is_some() {
                typed_any.get_or_insert(f);
                if !s.contains('#') {
                    typed_path.get_or_insert(f);
                }
            }
        }
        typed_path.or(typed_any).or(first_any)
    })
}

/// The bare type name from a full WIT path.
///
/// Debug type names are full WIT paths with namespace and version, e.g.
/// `miden:base/core-types@1.0.0/account-id`. We want the last `/`-segment (`account-id`) for
/// display and for matching a type regardless of package or version. Empty if `name` is empty or
/// ends in `/`.
pub(super) fn wit_type_name(name: &str) -> &str {
    name.rsplit('/').next().filter(|s| !s.is_empty()).unwrap_or("")
}

/// The short procedure name from a long compiler name: take the last `::` part, remove the quotes,
/// and drop anything before `#`. `::"miden:cc/mcc@0.1.0"::"get-count"` becomes `get-count`.
pub(super) fn proc_display_name(raw: &str) -> &str {
    let seg = raw.rsplit("::").next().unwrap_or(raw).trim_matches('"');
    seg.rsplit('#').next().unwrap_or(seg)
}

/// Whether a struct's short name is anonymous, so callers render its fields instead of a name.
/// `<anon>` is the sentinel the compiler writes when it has no name for a struct.
pub(super) fn is_anonymous(short: &str) -> bool {
    short.is_empty() || short == "<anon>"
}

/// The type/field name string at `name_idx`, or `""` when the string table has no entry.
pub(super) fn type_name_raw(types: &DebugTypesSection, name_idx: u32) -> &str {
    types.strings.get(name_idx as usize).map_or("", AsRef::as_ref)
}

/// Display name of a struct field at `name_idx`, falling back to `f<idx>` when the string table
/// has no entry.
pub(super) fn field_name(types: &DebugTypesSection, name_idx: u32) -> String {
    types
        .strings
        .get(name_idx as usize)
        .map_or_else(|| format!("f{name_idx}"), |s| s.as_ref().to_string())
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use super::{
        super::super::{DebugFunctionInfo, DebugFunctionsSection, DebugTypeIdx},
        find_debug_fn, proc_display_name,
    };

    /// A debug function entry with the given name and a typed signature.
    // `LineNumber`/`ColumnNumber` aren't re-exported here, so we can't name them for the
    // line/column defaults.
    #[allow(clippy::default_trait_access)]
    fn typed_fn(name_idx: u32, type_idx: DebugTypeIdx) -> DebugFunctionInfo {
        DebugFunctionInfo::new(name_idx, 0, Default::default(), Default::default())
            .with_type(type_idx)
    }

    #[test]
    #[allow(clippy::default_trait_access)]
    fn find_debug_fn_untyped_masm_leaves_exact_underscore_wins() {
        // Faithful to `mixed_names.masm`: `pub proc "foo-bar"` and `pub proc foo_bar`, neither with
        // a signature, so both DEBUG_FUNCTIONS entries are untyped (`first_any`, not `typed_path`).
        // A `foo_bar` query must resolve to the exact `_` leaf, never the kebab `foo-bar` one,
        // whichever order the assembler wrote them in.
        for order in [
            ["::mix::\"foo-bar\"", "::mix::foo_bar"],
            ["::mix::foo_bar", "::mix::\"foo-bar\""],
        ] {
            let mut funcs = DebugFunctionsSection::new();
            let mut exact_idx = None;
            for leaf in order {
                let idx = funcs.add_string(Arc::from(leaf));
                funcs.add_function(DebugFunctionInfo::new(
                    idx,
                    0,
                    Default::default(),
                    Default::default(),
                ));
                if leaf.ends_with("foo_bar") {
                    exact_idx = Some(idx);
                }
            }
            let found = find_debug_fn(&funcs, "foo_bar").unwrap();
            let found_raw = funcs.strings.get(found.name_idx as usize).unwrap().as_ref();
            assert_eq!(found.name_idx, exact_idx.unwrap());
            assert_eq!(proc_display_name(found_raw), "foo_bar");
        }
    }

    #[test]
    fn proc_display_name_extracts_leaf() {
        // Quoted WIT leaf, `#`-qualified form, and a bare plain name.
        assert_eq!(
            proc_display_name("::\"miden:cc/mcc@0.1.0\"::\"take-account-id\""),
            "take-account-id"
        );
        assert_eq!(
            proc_display_name("::\"x\"::counter_contract::\"miden:cc/mcc@0.1.0#take-account-id\""),
            "take-account-id"
        );
        assert_eq!(proc_display_name("take-account-id"), "take-account-id");

        // A WIT name with no dash (`mixed`) is unquoted, so its leaf is a bare `::mixed`.
        assert_eq!(proc_display_name("::\"miden:cc/mcc@0.1.0\"::mixed"), "mixed");

        // The whole leaf is kept: `-` is not a boundary, so these are not truncated to `count` or
        // `mixed` — which is what lets `find_debug_fn` reject a partial-name query.
        assert_eq!(proc_display_name("::\"x\"::\"get-count\""), "get-count");
        assert_eq!(proc_display_name("foo#get-count"), "get-count");
        assert_eq!(proc_display_name("::\"miden:cc/mcc@0.1.0\"::\"mixed-format\""), "mixed-format");
    }

    #[test]
    fn find_debug_fn_prefers_bare_colon_path_over_hash_form() {
        // Like `mixed`: the `#mixed` entry has the lowered signature, the `::mixed` entry the
        // typed one. The `::` form must win.
        let mut funcs = DebugFunctionsSection::new();
        let hash = funcs.add_string(Arc::from(
            "::\"miden:cc/mcc@0.1.0\"::counter_contract::\"miden:cc/mcc@0.1.0#mixed\"",
        ));
        let path = funcs.add_string(Arc::from("::\"miden:cc/mcc@0.1.0\"::mixed"));
        let ty = DebugTypeIdx::from(0);
        funcs.add_function(typed_fn(hash, ty));
        funcs.add_function(typed_fn(path, ty));

        let found = find_debug_fn(&funcs, "mixed").unwrap();
        assert_eq!(found.name_idx, path);
    }

    #[test]
    fn find_debug_fn_typed_leaves_exact_underscore_wins() {
        for order in [
            ["::\"miden:cc/mcc@0.1.0\"::\"take-account-id\"", "::mcc::take_account_id"],
            ["::mcc::take_account_id", "::\"miden:cc/mcc@0.1.0\"::\"take-account-id\""],
        ] {
            let mut funcs = DebugFunctionsSection::new();
            let mut exact_idx = None;
            for leaf in order {
                let idx = funcs.add_string(Arc::from(leaf));
                funcs.add_function(typed_fn(idx, DebugTypeIdx::from(0)));
                if leaf.ends_with("take_account_id") {
                    exact_idx = Some(idx);
                }
            }
            let found = find_debug_fn(&funcs, "take_account_id").unwrap();
            assert_eq!(found.name_idx, exact_idx.unwrap());
        }
    }

    #[test]
    fn find_debug_fn_matches_kebab_and_exact_underscore_leaves() {
        // A `take_account_id` query must find both a kebab leaf (`take-account-id`, from Rust) and
        // a leaf that keeps `_` (`take_account_id`, from hand-written MASM).
        for leaf in [
            "::\"miden:cc/mcc@0.1.0\"::\"take-account-id\"",
            "::\"miden:cc/mcc@0.1.0\"::take_account_id",
        ] {
            let mut funcs = DebugFunctionsSection::new();
            let path = funcs.add_string(Arc::from(leaf));
            funcs.add_function(typed_fn(path, DebugTypeIdx::from(0)));

            let found = find_debug_fn(&funcs, "take_account_id").unwrap();
            assert_eq!(found.name_idx, path);
        }
    }
}
