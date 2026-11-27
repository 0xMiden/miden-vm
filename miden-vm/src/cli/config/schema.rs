use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use miden_assembly::diagnostics::Report;
use miden_vm::HashFunction;
use serde::Deserialize;
use toml::de::{DeTable, DeValue};

use crate::cli::utils::parse_byte_size;

pub(super) type Layer = BTreeMap<String, Value>;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(super) enum Value {
    Bool(bool),
    U32(u32),
    U64(u64),
    Usize(usize),
    Hash(HashFunction),
}

pub(super) struct Schema {
    version: u32,
    fields: BTreeMap<String, Field>,
    tables: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct Definition {
    schema_version: u32,
    settings: Section,
    groups: BTreeMap<String, Section>,
}

type Section = BTreeMap<String, Entry>;

#[derive(Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum Entry {
    Field(Field),
    Group { group: String },
    Section(Section),
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Field {
    #[serde(rename = "type")]
    kind: Kind,
    description: String,
    default: Option<Scalar>,
}

#[derive(Clone, Deserialize)]
#[serde(untagged)]
enum Scalar {
    Bool(bool),
    Integer(u64),
    String(String),
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Kind {
    Bool,
    U32,
    U64,
    Usize,
    HashFunction,
    BytesU32,
    BytesU64,
    BytesUsize,
}

impl Schema {
    pub(super) fn load() -> Result<Self, Report> {
        Self::from_definition(include_str!("../cli-schema.toml"))
    }

    fn from_definition(source: &str) -> Result<Self, Report> {
        let definition: Definition = toml::from_str(source)
            .map_err(|err| Report::msg(format!("invalid embedded CLI schema: {err}")))?;
        let mut schema = Self {
            version: definition.schema_version,
            fields: BTreeMap::new(),
            tables: BTreeSet::new(),
        };
        schema.expand("", &definition.settings, &definition.groups, &mut Vec::new())?;
        Ok(schema)
    }

    fn expand<'a>(
        &mut self,
        prefix: &str,
        section: &'a Section,
        groups: &'a BTreeMap<String, Section>,
        active: &mut Vec<&'a str>,
    ) -> Result<(), Report> {
        for (name, entry) in section {
            let key = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}.{name}")
            };
            if name.is_empty() || name.contains('.') {
                return Err(Report::msg(format!("invalid CLI schema key component '{name}'")));
            }
            match entry {
                Entry::Field(field) => {
                    self.fields.insert(key, field.clone());
                },
                Entry::Section(children) => {
                    self.tables.insert(key.clone());
                    self.expand(&key, children, groups, active)?;
                },
                Entry::Group { group } => {
                    if active.contains(&group.as_str()) {
                        return Err(Report::msg(format!(
                            "recursive CLI schema group '{group}' at '{key}'"
                        )));
                    }
                    let children = groups.get(group).ok_or_else(|| {
                        Report::msg(format!("unknown CLI schema group '{group}' at '{key}'"))
                    })?;
                    self.tables.insert(key.clone());
                    active.push(group);
                    self.expand(&key, children, groups, active)?;
                    active.pop();
                },
            }
        }
        Ok(())
    }

    pub(super) fn defaults(&self) -> Result<Layer, Report> {
        let mut defaults = Layer::new();
        for (key, field) in &self.fields {
            if let Some(default) = &field.default {
                let value = field
                    .kind
                    .parse(default)
                    .map_err(|err| Report::msg(format!("default for '{key}': {err}")))?;
                defaults.insert(key.clone(), value);
            }
        }
        Ok(defaults)
    }

    pub(super) fn file(&self, path: &Path, source: &str) -> Result<Layer, Report> {
        // The lossless TOML parser keeps the integer's digits and radix, including for u64::MAX.
        let root = DeTable::parse(source)
            .map_err(|err| Report::msg(format!("{}: {err}", path.display())))?;
        let mut layer = Layer::new();
        self.read_table(root.get_ref(), "", &mut layer).map_err(|(offset, err)| {
            let before = &source[..offset];
            let line = before.bytes().filter(|&byte| byte == b'\n').count() + 1;
            let column = before.rsplit('\n').next().unwrap_or("").chars().count() + 1;
            Report::msg(format!("{}:{line}:{column}: {err}", path.display()))
        })?;
        Ok(layer)
    }

    fn read_table(
        &self,
        table: &DeTable<'_>,
        prefix: &str,
        layer: &mut Layer,
    ) -> Result<(), (usize, String)> {
        for (name, input) in table {
            let name_offset = name.span().start;
            let offset = input.span().start;
            let name: &str = name.get_ref();
            let key = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}.{name}")
            };
            let input = input.get_ref();
            if name.contains('.') {
                return Err((
                    name_offset,
                    format!("invalid setting '{key}': a quoted key component contains a dot"),
                ));
            }
            if key == "schema-version" {
                let version = unsigned_integer(input)
                    .map_err(|err| (offset, format!("invalid 'schema-version': {err}")))?;
                if version != u64::from(self.version) {
                    return Err((
                        offset,
                        format!(
                            "unsupported 'schema-version' {version}, expected {}",
                            self.version
                        ),
                    ));
                }
            } else if self.tables.contains(&key) {
                let nested = input
                    .as_table()
                    .ok_or_else(|| (offset, format!("expected a table at '{key}'")))?;
                self.read_table(nested, &key, layer)?;
            } else {
                let field = self
                    .fields
                    .get(&key)
                    .ok_or_else(|| (name_offset, format!("unknown setting '{key}'")))?;
                let value = field.parse(&key, input).map_err(|err| (offset, err))?;
                layer.insert(key, value);
            }
        }
        Ok(())
    }

    pub(super) fn overrides(&self, assignments: &[String]) -> Result<Layer, Report> {
        let mut layer = Layer::new();
        for assignment in assignments {
            let (key, raw) = assignment.split_once('=').ok_or_else(|| {
                Report::msg(format!("invalid --set '{assignment}', expected section.key=value"))
            })?;
            let (key, raw) = (key.trim(), raw.trim());
            let field = self.fields.get(key).ok_or_else(|| {
                Report::msg(format!("--set {assignment}: unknown setting '{key}'"))
            })?;
            let parsed = DeValue::parse(raw)
                .map_err(|err| err.to_string())
                .and_then(|input| field.parse(key, input.get_ref()));
            // Shell arguments also allow unquoted byte quantities and hash names. A token like
            // 1_024KiB can lex as an integer and fail only when its digits are converted.
            let value = match parsed {
                Err(_) if field.kind.accepts_bare_string() && !raw.starts_with(['\'', '"']) => {
                    field.parse(key, &DeValue::String(raw.into()))
                },
                result => result,
            }
            .map_err(|err| Report::msg(format!("--set {assignment}: {err}")))?;
            layer.insert(key.to_owned(), value);
        }
        Ok(layer)
    }

    #[cfg(test)]
    pub(super) fn sample_assignments(&self) -> impl Iterator<Item = String> {
        self.fields.iter().map(|(key, field)| {
            let value = match field.kind {
                Kind::Bool => "true",
                Kind::HashFunction => "'eidos'",
                Kind::U32 | Kind::U64 | Kind::Usize => "64",
                Kind::BytesU32 | Kind::BytesU64 | Kind::BytesUsize => "'64B'",
            };
            format!("{key}={value}")
        })
    }
}

impl Field {
    fn parse(&self, key: &str, input: &DeValue<'_>) -> Result<Value, String> {
        let value = match input {
            DeValue::Boolean(b) => Ok(Scalar::Bool(*b)),
            DeValue::String(s) => Ok(Scalar::String(s.to_string())),
            DeValue::Integer(_) => unsigned_integer(input).map(Scalar::Integer),
            _ => Err("expected a boolean, integer, or string".into()),
        };
        value
            .and_then(|v| self.kind.parse(&v))
            .map_err(|err| format!("invalid '{key}': {err}. {}", self.description))
    }
}

impl Kind {
    fn accepts_bare_string(self) -> bool {
        matches!(self, Self::HashFunction | Self::BytesU32 | Self::BytesU64 | Self::BytesUsize)
    }

    fn parse(self, input: &Scalar) -> Result<Value, String> {
        let number = || match input {
            Scalar::Integer(n) => Ok(*n),
            Scalar::String(s) if self.accepts_bare_string() => parse_byte_size(s),
            _ => Err("expected a nonnegative integer".to_owned()),
        };
        match self {
            Self::Bool => match input {
                Scalar::Bool(b) => Ok(Value::Bool(*b)),
                _ => Err("expected a boolean".into()),
            },
            Self::HashFunction => match input {
                Scalar::String(s) => HashFunction::try_from(s.as_str())
                    .map(Value::Hash)
                    .map_err(|err| err.to_string()),
                _ => Err("expected a hash function name".into()),
            },
            Self::U32 | Self::BytesU32 => u32::try_from(number()?)
                .map(Value::U32)
                .map_err(|_| "value exceeds the u32 maximum".into()),
            Self::Usize | Self::BytesUsize => usize::try_from(number()?)
                .map(Value::Usize)
                .map_err(|_| "value exceeds the usize maximum".into()),
            Self::U64 | Self::BytesU64 => Ok(Value::U64(number()?)),
        }
    }
}

fn unsigned_integer(input: &DeValue<'_>) -> Result<u64, String> {
    let integer = input.as_integer().ok_or("expected a nonnegative integer")?;
    u64::from_str_radix(integer.as_str(), integer.radix())
        .map_err(|_| "expected a nonnegative integer that fits in u64".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definitions_reject_unknown_and_recursive_group_references() {
        let definition = "schema-version = 1\n[settings.test]\nlimit = { group = 'a' }\n[groups.a]\nnested = { group = 'b' }";
        let error = Schema::from_definition(definition).err().unwrap().to_string();
        assert!(error.contains("unknown CLI schema group 'b'"), "{error}");
        let cyclic = format!("{definition}\n[groups.b]\nnested = {{ group = 'a' }}");
        let error = Schema::from_definition(&cyclic).err().unwrap().to_string();
        assert!(error.contains("recursive CLI schema group 'a'"), "{error}");
    }

    #[test]
    fn file_and_override_values_use_the_same_types_and_widths() {
        let schema = Schema::load().unwrap();
        for (key, literal, argument, expected) in [
            (
                "precompiles.hash.max-total-size",
                "18446744073709551615",
                "18446744073709551615",
                Value::U64(u64::MAX),
            ),
            ("resources.vm-prover-memory", "'32MiB'", "32MiB", Value::U64(32 << 20)),
            ("precompiles.hash.max-size", "'1_024KiB'", "1_024KiB", Value::U32(1 << 20)),
            ("resources.vm-prover-memory", "'8 GiB'", "8 GiB", Value::U64(8 << 30)),
            ("execution.max-stack-depth", "1_024", "1_024", Value::Usize(1024)),
            (
                "proving.hasher",
                "'blake3-256'",
                "blake3-256",
                Value::Hash(HashFunction::Blake3_256),
            ),
            ("display.num-outputs", "0", "0", Value::Usize(0)),
            ("bundle.release", "false", "false", Value::Bool(false)),
        ] {
            let file = schema.file(Path::new("test.toml"), &format!("{key}={literal}")).unwrap();
            let overrides = schema.overrides(&[format!("{key}={argument}")]).unwrap();
            assert_eq!(file, overrides);
            assert_eq!(file[key], expected);
        }
    }

    #[test]
    fn invalid_files_identify_the_path_and_setting() {
        let schema = Schema::load().unwrap();
        for (source, setting) in [
            ("[unknown]", "unknown"),
            ("[execution.unused]", "execution.unused"),
            ("'execution.max-cycles' = 64", "execution.max-cycles"),
            ("schema-version = 2", "schema-version"),
            ("schema-version = false", "schema-version"),
            ("resources.vm-prover-memory = -1", "resources.vm-prover-memory"),
            ("precompiles.hash.max-size = 4294967296", "precompiles.hash.max-size"),
            ("precompiles.max-elements = 18446744073709551616", "precompiles.max-elements"),
            ("execution.max-cycles = '64'", "execution.max-cycles"),
            ("execution.max-stack-depth = 18446744073709551616", "execution.max-stack-depth"),
            ("verification = true", "verification"),
            ("verification.require-complete = true", "verification.require-complete"),
            ("proving.hasher = 'unknown'", "proving.hasher"),
        ] {
            let error = schema.file(Path::new("test.toml"), source).unwrap_err().to_string();
            assert!(error.contains("test.toml") && error.contains(setting), "{error}");
        }
    }

    #[test]
    fn overrides_validate_each_assignment_and_replace_repeated_keys() {
        let schema = Schema::load().unwrap();
        let layer = schema
            .overrides(&["execution.max-cycles=128".into(), "execution.max-cycles=64".into()])
            .unwrap();
        assert_eq!(layer["execution.max-cycles"], Value::U32(64));
        for assignment in [
            "missing-equals",
            "schema-version=1",
            "resources.vm-prover-memory=bad=32Mi",
            "proving.hasher=",
            "execution.max-cycles=-1",
            "resources.vm-prover-memory=16MiB=2",
            "execution.max-stack-depth=18446744073709551616",
            "precompiles.hash.max-size=4294967296",
        ] {
            assert!(schema.overrides(&[assignment.into()]).is_err(), "{assignment}");
        }
        assert!(
            schema
                .overrides(&[
                    "execution.max-cycles=invalid".into(),
                    "execution.max-cycles=64".into()
                ])
                .is_err()
        );
    }
}
