use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct RustdocJson {
    index: BTreeMap<String, Value>,
    paths: BTreeMap<String, PathInfo>,
}

#[derive(Debug, Deserialize)]
struct PathInfo {
    path: Vec<String>,
}

fn main() {
    let json_path = match std::env::args().nth(1) {
        Some(path) => PathBuf::from(path),
        None => {
            eprintln!("usage: zeroize-audit <rustdoc-json>");
            std::process::exit(2);
        }
    };

    let data = fs::read_to_string(&json_path)
        .unwrap_or_else(|err| die(&format!("failed to read {json_path:?}: {err}")));
    let doc: RustdocJson =
        serde_json::from_str(&data).unwrap_or_else(|err| die(&format!("invalid json: {err}")));

    let secret_type_re = Regex::new(r"(?i)(secret|private|seed)").unwrap();
    let secret_field_re =
        Regex::new(r"(?i)(secret|seed|priv|private|secret_key|secretkey|(^|_)sk(_|$))").unwrap();

    let zeroize_impls = collect_zeroize_impls(&doc.index);

    let mut ok = Vec::new();
    let mut failures = Vec::new();

    for item in doc.index.values() {
        if item.pointer("/inner/struct").is_none() {
            continue;
        }

        let name = item.pointer("/name").and_then(|v| v.as_str()).unwrap_or("");
        let is_secret_named = secret_type_re.is_match(name);

        let fields = struct_fields(&doc.index, item);
        let secret_fields: Vec<_> = fields
            .iter()
            .filter(|(field_name, _, _)| secret_field_re.is_match(field_name))
            .collect();
        let is_field_secret = !secret_fields.is_empty();

        if !is_secret_named && !is_field_secret {
            continue;
        }

        let item_id = item
            .pointer("/id")
            .and_then(|v| v.as_u64())
            .unwrap_or_default();
        let item_path = full_path(&doc.paths, item_id).unwrap_or_else(|| name.to_string());
        let loc = span_location(item);

        if zeroize_impls.contains(&item_id) {
            ok.push((item_path, loc, "impl Zeroize/ZeroizeOnDrop"));
            continue;
        }

        if is_field_secret {
            let all_secret_zeroized = secret_fields
                .iter()
                .all(|(_, field_type, _)| type_is_zeroized(field_type, &zeroize_impls));
            if all_secret_zeroized {
                ok.push((item_path, loc, "secret fields wrapped/zeroized"));
                continue;
            }
        }

        failures.push((item_path, loc));
    }

    println!("Zeroize audit results:");
    for (item_path, loc, reason) in &ok {
        println!("- {item_path} ({loc}): ok ({reason})");
    }

    if !failures.is_empty() {
        eprintln!("\nMissing Zeroize on secret-bearing types:");
        for (item_path, loc) in failures {
            eprintln!("- {item_path} ({loc}): missing Zeroize");
        }
        std::process::exit(1);
    }
}

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(2)
}

fn full_path(paths: &BTreeMap<String, PathInfo>, item_id: u64) -> Option<String> {
    paths
        .get(&item_id.to_string())
        .map(|info| info.path.join("::"))
}

fn span_location(item: &Value) -> String {
    let filename = item
        .pointer("/span/filename")
        .and_then(|v| v.as_str())
        .unwrap_or("<unknown>");
    let line = item
        .pointer("/span/begin/0")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    format!("{filename}:{line}")
}

fn collect_zeroize_impls(index: &BTreeMap<String, Value>) -> BTreeSet<u64> {
    let mut ids = BTreeSet::new();
    for item in index.values() {
        let trait_path = item
            .pointer("/inner/impl/trait/path")
            .and_then(|v| v.as_str());
        let trait_name = trait_path.and_then(|path| path.split("::").last());
        if !matches!(trait_name, Some("Zeroize" | "ZeroizeOnDrop")) {
            continue;
        }
        if let Some(id) = item
            .pointer("/inner/impl/for/resolved_path/id")
            .and_then(|v| v.as_u64())
        {
            ids.insert(id);
        }
    }
    ids
}

fn struct_fields<'a>(index: &'a BTreeMap<String, Value>, item: &'a Value) -> Vec<(String, &'a Value, &'a Value)> {
    let mut out = Vec::new();
    let kind = match item.pointer("/inner/struct/kind") {
        Some(kind) => kind,
        None => return out,
    };

    let field_ids: Vec<u64> = if let Some(fields) = kind.pointer("/plain/fields") {
        match fields.as_array() {
            Some(list) => list.iter().filter_map(|v| v.as_u64()).collect(),
            None => Vec::new(),
        }
    } else if let Some(fields) = kind.pointer("/tuple") {
        match fields.as_array() {
            Some(list) => list.iter().filter_map(|v| v.as_u64()).collect(),
            None => Vec::new(),
        }
    } else {
        Vec::new()
    };

    for fid in field_ids {
        if let Some(field) = index.get(&fid.to_string()) {
            let field_name = field
                .pointer("/name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let field_type = field
                .pointer("/inner/struct_field")
                .unwrap_or(&Value::Null);
            out.push((field_name, field_type, field));
        }
    }

    out
}

fn type_is_zeroized(ty: &Value, zeroize_impls: &BTreeSet<u64>) -> bool {
    if ty.is_null() {
        return false;
    }

    if let Some(resolved) = ty.get("resolved_path") {
        let path = resolved.get("path").and_then(|v| v.as_str()).unwrap_or("");
        if path.split("::").last() == Some("Zeroizing") {
            return true;
        }
        if let Some(id) = resolved.get("id").and_then(|v| v.as_u64()) {
            return zeroize_impls.contains(&id);
        }
        if let Some(container) = path.split("::").last() {
            if matches!(
                container,
                "Option"
                    | "Result"
                    | "Vec"
                    | "VecDeque"
                    | "LinkedList"
                    | "BinaryHeap"
                    | "Box"
                    | "Rc"
                    | "Arc"
                    | "Cow"
                    | "BTreeMap"
                    | "BTreeSet"
                    | "HashMap"
                    | "HashSet"
            ) {
                let args = resolved.get("args");
                let type_args = collect_type_args(args);
                if !type_args.is_empty() {
                    return type_args
                        .into_iter()
                        .all(|arg| type_is_zeroized(arg, zeroize_impls));
                }
            }
        }
        return false;
    }

    if let Some(borrowed) = ty.get("borrowed_ref") {
        if let Some(inner) = borrowed.get("type") {
            return type_is_zeroized(inner, zeroize_impls);
        }
    }

    if let Some(array) = ty.get("array") {
        if let Some(inner) = array.get("type") {
            return type_is_zeroized(inner, zeroize_impls);
        }
    }

    if let Some(slice) = ty.get("slice") {
        if let Some(inner) = slice.get("type") {
            return type_is_zeroized(inner, zeroize_impls);
        }
    }

    if let Some(tuple) = ty.get("tuple") {
        if let Some(elems) = tuple.as_array() {
            return elems.iter().all(|elem| type_is_zeroized(elem, zeroize_impls));
        }
        return false;
    }

    if let Some(inner) = ty.get("type") {
        return type_is_zeroized(inner, zeroize_impls);
    }

    false
}

fn collect_type_args(args: Option<&Value>) -> Vec<&Value> {
    let mut out = Vec::new();
    let Some(args) = args else {
        return out;
    };

    if let Some(angle) = args.get("angle_bracketed") {
        if let Some(values) = angle.get("args").and_then(|v| v.as_array()) {
            for value in values {
                if let Some(ty) = value.get("type") {
                    out.push(ty);
                }
            }
        }
    }

    if let Some(parenthesized) = args.get("parenthesized") {
        if let Some(inputs) = parenthesized.get("inputs").and_then(|v| v.as_array()) {
            out.extend(inputs.iter());
        }
        if let Some(output) = parenthesized.get("output") {
            out.push(output);
        }
    }

    out
}
