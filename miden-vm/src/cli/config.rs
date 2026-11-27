//! Resolve reusable CLI parameters before commands open their inputs.

use std::{fs, io, path::Path};

use miden_assembly::diagnostics::Report;
use miden_vm::{
    CURVE_WORK, ExecutionOptions, HASH_WORK, MSM_WORK, PrecompileLimits, Prover, UINT_WORK,
    Verifier, processor::ExecutionOptionsError,
};

mod schema;

use schema::{Layer, Schema, Value};

pub(crate) struct Settings {
    pub execution: ExecutionOptions,
    pub prover: Prover,
    pub verifier: Verifier,
    pub num_outputs: usize,
    pub release: bool,
}

// The schema controls input types. Consuming each value lets us catch drift between the schema
// and the Rust bindings, including settings declared in the schema but never applied.
macro_rules! take {
    ($params:expr, $key:expr, $variant:ident) => {{
        let key: &str = $key;
        match $params.remove(key) {
            Some(Value::$variant(value)) => Some(value),
            None => None,
            Some(_) => return Err(Report::msg(format!("CLI schema type mismatch for '{key}'"))),
        }
    }};
}

impl Settings {
    pub fn load(explicit_path: Option<&Path>, assignments: &[String]) -> Result<Self, Report> {
        let path = explicit_path.unwrap_or(Path::new("miden-vm.toml"));
        let schema = Schema::load()?;
        let file = match fs::read_to_string(path) {
            Ok(source) => schema.file(path, &source)?,
            // A dangling symlink is a selected configuration we could not read.
            Err(err)
                if explicit_path.is_none()
                    && err.kind() == io::ErrorKind::NotFound
                    && fs::symlink_metadata(path)
                        .is_err_and(|err| err.kind() == io::ErrorKind::NotFound) =>
            {
                Layer::new()
            },
            Err(err) => return Err(Report::msg(format!("cannot read {}: {err}", path.display()))),
        };
        Self::resolve(&schema, path, &file, &schema.overrides(assignments)?)
    }

    #[cfg(test)]
    pub fn from_overrides(assignments: &[String]) -> Result<Self, Report> {
        let schema = Schema::load()?;
        Self::resolve(
            &schema,
            Path::new("miden-vm.toml"),
            &Layer::new(),
            &schema.overrides(assignments)?,
        )
    }

    fn resolve(
        schema: &Schema,
        path: &Path,
        file: &Layer,
        overrides: &Layer,
    ) -> Result<Self, Report> {
        let mut values = Layer::new();
        overlay(&mut values, &schema.defaults()?);
        overlay(&mut values, file);
        overlay(&mut values, overrides);

        let describe = |key: &str| {
            if overrides.contains_key(key) {
                format!("--set {key}")
            } else if file.contains_key(key) {
                format!("{}: {key}", path.display())
            } else {
                key.to_owned()
            }
        };

        let defaults = ExecutionOptions::default();
        let max_cycles = take!(values, "execution.max-cycles", U32);
        let expected_cycles =
            take!(values, "execution.expected-cycles", U32).unwrap_or(defaults.expected_cycles());
        let fragment_size = take!(values, "execution.core-trace-fragment-size", Usize)
            .unwrap_or(defaults.core_trace_fragment_size());
        let mut execution = ExecutionOptions::new(max_cycles, expected_cycles, fragment_size)
            .map_err(|err| {
                let keys = match err {
                    ExecutionOptionsError::ExpectedCyclesTooBig { .. } => format!(
                        "{} and {}",
                        describe("execution.expected-cycles"),
                        describe("execution.max-cycles")
                    ),
                    ExecutionOptionsError::CoreTraceFragmentSizeTooSmall => {
                        describe("execution.core-trace-fragment-size")
                    },
                    _ => describe("execution.max-cycles"),
                };
                Report::msg(format!("{keys}: {err}"))
            })?;
        if let Some(bytes) = take!(values, "execution.max-advice-size-bytes", Usize) {
            execution = execution.with_max_advice_size_bytes(bytes);
        }
        if let Some(bytes) = take!(values, "execution.max-hash-input-bytes", Usize) {
            execution = execution.with_max_hash_len_bytes(bytes);
        }
        if let Some(count) = take!(values, "execution.max-num-continuations", Usize) {
            execution = execution.with_max_num_continuations(count);
        }
        if let Some(depth) = take!(values, "execution.max-stack-depth", Usize) {
            execution = execution.with_max_stack_depth(depth).map_err(|err| {
                Report::msg(format!("{}: {err}", describe("execution.max-stack-depth")))
            })?;
        }
        if let Some(elements) = take!(values, "execution.max-memory-elements", Usize) {
            execution = execution.with_max_memory_elements(elements);
        }

        let execution_limits = policy(
            &mut values,
            "execution.precompiles",
            execution.execution_precompile_limits().clone(),
        )?;
        let verification_limits = policy(
            &mut values,
            "verification.precompiles",
            execution.verification_precompile_limits().clone(),
        )?;
        execution = execution
            .with_execution_precompile_limits(execution_limits)
            .with_verification_precompile_limits(verification_limits.clone());
        let mut prover =
            Prover::new().with_verification_precompile_limits(verification_limits.clone());
        let mut verifier = Verifier::new().with_verification_precompile_limits(verification_limits);

        if let Some(bytes) = take!(values, "resources.vm-prover-memory", U64) {
            prover = prover.with_max_prover_memory_bytes(bytes);
        }
        if let Some(bytes) = take!(values, "resources.precompile-prover-memory", U64) {
            prover = prover.with_max_precompile_prover_memory_bytes(bytes);
        }
        if let Some(hasher) = take!(values, "proving.hasher", Hash) {
            prover = prover.with_hash_fn(hasher);
        }
        if let Some(enabled) = take!(values, "proving.hash-lde-blocks", Bool) {
            prover = prover.with_hash_lde_blocks(enabled);
        }
        if let Some(bits) = take!(values, "verification.min-security-bits", U32) {
            verifier = verifier.with_min_conjectured_security_level_per_stark(bits);
        }

        let num_outputs = take!(values, "display.num-outputs", Usize)
            .expect("CLI schema supplies display.num-outputs");
        let release =
            take!(values, "bundle.release", Bool).expect("CLI schema supplies bundle.release");
        if let Some(key) = values.keys().next() {
            return Err(Report::msg(format!("CLI schema setting '{key}' has no binding")));
        }
        Ok(Self {
            execution,
            prover,
            verifier,
            num_outputs,
            release,
        })
    }
}

/// Expand shared settings into their individual destinations within each layer. This lets a
/// shared command-line override supersede a scope-specific file setting.
fn overlay(values: &mut Layer, layer: &Layer) {
    for (key, &value) in layer {
        if key.starts_with("precompiles.") {
            values.insert(format!("execution.{key}"), value);
            values.insert(format!("verification.{key}"), value);
        } else if key == "resources.max-prover-memory" {
            values.insert("resources.vm-prover-memory".into(), value);
            values.insert("resources.precompile-prover-memory".into(), value);
        }
    }
    for (key, &value) in layer {
        if !key.starts_with("precompiles.") && key != "resources.max-prover-memory" {
            values.insert(key.clone(), value);
        }
    }
}

fn policy(
    values: &mut Layer,
    prefix: &str,
    mut limits: PrecompileLimits,
) -> Result<PrecompileLimits, Report> {
    if let Some(elements) = take!(values, &format!("{prefix}.max-elements"), U64) {
        limits = limits.with_max_elements(elements);
    }
    for class in [HASH_WORK, MSM_WORK, UINT_WORK, CURVE_WORK] {
        let key = format!("{prefix}.{}", class.as_str());
        let mut limit = limits.class(&class).expect("library policy includes each built-in class");
        if let Some(count) = take!(values, &format!("{key}.max-count"), U64) {
            limit.max_count = count;
        }
        if let Some(total) = take!(values, &format!("{key}.max-total-size"), U64) {
            limit.max_total_size = total;
        }
        if let Some(size) = take!(values, &format!("{key}.max-size"), U32) {
            limit.max_size = size;
        }
        limits = limits.with_class(class, limit);
    }
    Ok(limits)
}

#[cfg(test)]
mod tests;
