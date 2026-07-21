//! Read-only helpers over a [`Package`]'s debug sections: section loading, function lookup,
//! and shared type-name predicates.

use alloc::{
    format,
    string::{String, ToString},
};

use miden_assembly_syntax::ast::path::Path;

use super::super::{DebugFieldInfo, DebugFunctionInfo, DebugFunctionsSection, DebugTypesSection};
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
/// The compiler can list the same procedure under several names: a mangled Rust symbol
/// (`_RNvXs...get_count`), a lowered form (`...@0.1.0#get-count`), and the interface form
/// (`"get-count"`). Only the interface form has `get-count` as its leaf, so it is the only one
/// that matches the query. That form also keeps the high-level types (`AccountId`, `Word`), so
/// matching by leaf gives us the typed entry with no special-casing. Among matches we prefer one
/// with a `type_idx`, else take any match; ties keep the first in iteration order.
pub(super) fn find_debug_fn<'a>(
    funcs: &'a DebugFunctionsSection,
    procedure_name: &str,
) -> Option<&'a DebugFunctionInfo> {
    let kebab = procedure_name.replace('_', "-");
    [procedure_name, kebab.as_str()].into_iter().find_map(|target| {
        let mut typed: Option<&DebugFunctionInfo> = None;
        let mut first_any: Option<&DebugFunctionInfo> = None;
        for f in &funcs.functions {
            let Some(s) = funcs.strings.get(f.name_idx as usize) else {
                continue;
            };
            if proc_display_name(s.as_ref()) != target {
                continue;
            }
            first_any.get_or_insert(f);
            if f.type_idx.is_some() {
                typed.get_or_insert(f);
            }
        }
        typed.or(first_any)
    })
}

/// The bare leaf of a type name.
///
/// Debug type names come in a few shapes: WIT-style `/`-paths with a namespace and version
/// (`miden:base/core-types@1.0.0/account-id`), `::`-paths (`crate::module::Point`), or a plain name
/// with no separator (`point`). This returns the last component — after the final `/`, then after
/// the final `::` — with surrounding quotes removed, so a type matches regardless of package,
/// version, or module path. A plain name is returned as is; the result is empty only when `name` is
/// empty or ends in a separator.
pub(super) fn type_leaf_name(name: &str) -> &str {
    let after_slash = name.rsplit('/').next().unwrap_or(name);
    after_slash.rsplit("::").next().unwrap_or(after_slash).trim_matches('"')
}

/// The short procedure name from a long compiler name: the last path component with surrounding
/// quotes removed. `::"miden:cc/mcc@0.1.0"::"get-count"` becomes `get-count`.
///
/// The `::` splitting goes through [`Path::split_last`] rather than a manual `rsplit`, so it reuses
/// the assembler's own path parsing (which respects quoting) instead of re-encoding those rules
/// here. `split_last` keeps the surrounding quotes on a component, so we still trim them.
pub(super) fn proc_display_name(raw: &str) -> &str {
    Path::new(raw).split_last().map_or(raw, |(last, _)| last).trim_matches('"')
}

/// Whether a struct's short name means it is anonymous, so callers show its fields, not a name. An
/// empty name and the `<anon>` name the assembler writes both count as anonymous.
pub(super) fn is_anonymous(short: &str) -> bool {
    short.is_empty() || short == "<anon>"
}

/// How many of `fields` are unnamed. `0` means a record, shown as `{ x: a, y: b }`; `fields.len()`
/// means a tuple, shown as `(a, b)` — that is how a multi-result return reaches us. Anything in
/// between mixes the two, which the assembler never writes, so callers treat it as invalid.
pub(super) fn unnamed_field_count(types: &DebugTypesSection, fields: &[DebugFieldInfo]) -> usize {
    fields
        .iter()
        .enumerate()
        .filter(|(i, f)| is_unnamed_struct_field(type_name_raw(types, f.name_idx), *i))
        .count()
}

/// Whether `name` is what the assembler writes for an unnamed field at position `index`: the index
/// as text (`"0"`, `"1"`, ...), or an empty name. Real field names are not just numbers, so they
/// never match their index.
fn is_unnamed_struct_field(name: &str, index: usize) -> bool {
    name.is_empty() || name.parse::<usize>() == Ok(index)
}

/// The type/field name string at `name_idx`, or the empty string when the string table has no
/// entry.
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
        find_debug_fn, proc_display_name, type_leaf_name,
    };

    #[test]
    fn type_leaf_name_extracts_leaf() {
        // WIT-style `/`-separated path.
        assert_eq!(type_leaf_name("miden:base/core-types@1.0.0/account-id"), "account-id");
        // Plain `::`-separated path.
        assert_eq!(type_leaf_name("crate::module::Point"), "Point");
        // Quoted `::` leaf is unquoted.
        assert_eq!(type_leaf_name("::\"pkg\"::\"Point\""), "Point");
        // No separator: returned unchanged.
        assert_eq!(type_leaf_name("Point"), "Point");
        // Empty or trailing separator yields an empty leaf.
        assert_eq!(type_leaf_name(""), "");
        assert_eq!(type_leaf_name("a/b/"), "");
    }

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
        // Quoted WIT leaf and a bare plain name.
        assert_eq!(
            proc_display_name("::\"miden:cc/mcc@0.1.0\"::\"take-account-id\""),
            "take-account-id"
        );
        // A `#`-qualified leaf is kept whole, so it does not match a bare `take-account-id` query;
        // the interface-form entry is the one that matches.
        assert_eq!(
            proc_display_name("::\"x\"::counter_contract::\"miden:cc/mcc@0.1.0#take-account-id\""),
            "miden:cc/mcc@0.1.0#take-account-id"
        );
        assert_eq!(proc_display_name("take-account-id"), "take-account-id");

        // A WIT name with no dash (`mixed`) is unquoted, so its leaf is a bare `::mixed`.
        assert_eq!(proc_display_name("::\"miden:cc/mcc@0.1.0\"::mixed"), "mixed");

        // The whole leaf is kept: `-` is not a boundary, so these are not truncated to `count` or
        // `mixed` — which is what lets `find_debug_fn` reject a partial-name query.
        assert_eq!(proc_display_name("::\"x\"::\"get-count\""), "get-count");
        assert_eq!(proc_display_name("::\"miden:cc/mcc@0.1.0\"::\"mixed-format\""), "mixed-format");
    }

    #[test]
    fn find_debug_fn_prefers_bare_colon_path_over_hash_form() {
        // The `#mixed` entry's leaf keeps the `#`-qualified interface, so it does not match a bare
        // `mixed` query; only the `::mixed` entry matches, so it is the one returned.
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
