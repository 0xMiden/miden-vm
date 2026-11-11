use alloc::{borrow::ToOwned, string::String, vec::Vec};

use miden_debug_types::Uri;

/// Converts a source URI or path into a stable form for loading and comparison.
pub fn normalize_source_path(path: &str) -> String {
    let path = path.trim();
    let path = Uri::new(path)
        .to_path()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_owned());
    let mut path = path.replace('\\', "/");
    if path
        .as_bytes()
        .get(0..2)
        .is_some_and(|bytes| bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
    {
        path.replace_range(..1, &path[..1].to_ascii_lowercase());
    }

    let is_absolute = path.starts_with('/');
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|last| *last != "..") {
                    parts.pop();
                } else {
                    parts.push(part);
                }
            }
            _ => parts.push(part),
        }
    }

    let normalized = parts.join("/");
    if is_absolute && !normalized.is_empty() {
        format!("/{normalized}")
    } else {
        normalized
    }
}

#[cfg(test)]
mod tests;
