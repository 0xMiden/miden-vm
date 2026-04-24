//! Semantics-preserving call-target shortening for display output.

use std::collections::HashMap;

use crate::{
    ir::Stmt,
    symbol::{path::SymbolPath, resolution::SymbolResolver},
};

/// Shorten call targets in-place when a shorter target resolves to the same callee.
///
/// This pass is purely a readability optimization. It never changes call semantics:
/// every shortened candidate is validated against the module-local resolver.
pub fn shorten_call_targets(stmts: &mut [Stmt], resolver: &SymbolResolver<'_>) {
    let mut cache = HashMap::<String, String>::new();
    shorten_call_targets_in_block(stmts, resolver, &mut cache);
}

/// Apply call-target shortening recursively to a statement block.
fn shorten_call_targets_in_block(
    stmts: &mut [Stmt],
    resolver: &SymbolResolver<'_>,
    cache: &mut HashMap<String, String>,
) {
    for stmt in stmts {
        match stmt {
            Stmt::Call { call, .. } | Stmt::Exec { call, .. } | Stmt::SysCall { call, .. } => {
                let original = call.target.clone();
                let shortened = if let Some(shortened) = cache.get(&original) {
                    shortened.clone()
                } else {
                    let shortened = shortest_equivalent_call_target(&original, resolver);
                    cache.insert(original.clone(), shortened.clone());
                    shortened
                };
                call.target = shortened;
            },
            Stmt::Repeat { body, .. } | Stmt::While { body, .. } => {
                shorten_call_targets_in_block(body, resolver, cache);
            },
            Stmt::If { then_body, else_body, .. } => {
                shorten_call_targets_in_block(then_body, resolver, cache);
                shorten_call_targets_in_block(else_body, resolver, cache);
            },
            _ => {},
        }
    }
}

/// Compute the shortest equivalent call target for display.
///
/// Candidates are tested from shortest to longest suffix (`bar`, `foo::bar`, ...),
/// and only accepted if resolver lookup proves semantic equivalence.
fn shortest_equivalent_call_target(target: &str, resolver: &SymbolResolver<'_>) -> String {
    let full_target = SymbolPath::new(target.to_string());
    let segments: Vec<&str> = full_target.segments().collect();
    if segments.is_empty() {
        return target.to_string();
    }

    for suffix_len in 1..=segments.len() {
        let candidate = segments[segments.len() - suffix_len..].join("::");
        if candidate.len() >= target.len() {
            continue;
        }
        if resolves_to_same_target(&candidate, &full_target, resolver) {
            return candidate;
        }
    }

    target.to_string()
}

/// Return true if `candidate` resolves to `expected` in this module context.
fn resolves_to_same_target(
    candidate: &str,
    expected: &SymbolPath,
    resolver: &SymbolResolver<'_>,
) -> bool {
    let resolved = if candidate.contains("::") {
        resolver.resolve_path(candidate)
    } else {
        resolver.resolve_symbol(candidate)
    };
    matches!(resolved, Ok(path) if path == *expected)
}
