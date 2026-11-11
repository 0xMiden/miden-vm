use alloc::{
    string::{String, ToString},
    vec::Vec,
};
#[cfg(feature = "std")]
use std::{ffi::OsStr, path::Path};

use miden_processor::{
    ExecutionOptions, StackInputs,
    advice::{AdviceInputs, AdviceStack},
};
use serde::Deserialize;

use crate::felt::Felt;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(try_from = "ExecutionConfigFile")]
pub struct ExecutionConfig {
    pub inputs: StackInputs,
    pub advice_inputs: AdviceInputs,
    pub options: ExecutionOptions,
}

impl TryFrom<ExecutionConfigFile> for ExecutionConfig {
    type Error = String;

    #[inline]
    fn try_from(file: ExecutionConfigFile) -> Result<Self, Self::Error> {
        Self::from_inputs_file(file)
    }
}

impl ExecutionConfig {
    #[cfg(feature = "std")]
    pub fn parse_file<P>(path: P) -> std::io::Result<Self>
    where
        P: AsRef<std::path::Path>,
    {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;

        let file =
            toml::from_str::<ExecutionConfigFile>(&content).map_err(std::io::Error::other)?;
        Self::from_inputs_file(file).map_err(std::io::Error::other)
    }

    pub fn parse_str(content: &str) -> Result<Self, String> {
        let file = toml::from_str::<ExecutionConfigFile>(content).map_err(|err| err.to_string())?;

        Self::from_inputs_file(file)
    }

    fn from_inputs_file(file: ExecutionConfigFile) -> Result<Self, String> {
        let felts: Vec<_> = file.inputs.stack.into_iter().map(|felt| felt.0).collect();
        let inputs =
            StackInputs::new(&felts).map_err(|err| format!("invalid value for 'stack': {err}"))?;
        let advice_inputs = AdviceInputs::default()
            .with_stack(
                file.inputs.advice.stack.into_iter().map(|felt| felt.0).collect::<AdviceStack>(),
            )
            .with_map(file.inputs.advice.map.into_iter().map(|entry| {
                (entry.digest.0, entry.values.into_iter().map(|felt| felt.0).collect::<Vec<_>>())
            }));

        Ok(Self {
            inputs,
            advice_inputs,
            options: file.options,
        })
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct ExecutionConfigFile {
    inputs: Inputs,
    #[serde(deserialize_with = "deserialize_execution_options")]
    options: ExecutionOptions,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct Inputs {
    /// The contents of the operand stack, top is leftmost
    stack: Vec<Felt>,
    /// The inputs to the advice provider
    advice: Advice,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct Advice {
    /// The contents of the advice stack, top is leftmost
    stack: Vec<Felt>,
    /// Entries to populate the advice map with
    map: Vec<AdviceMapEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct AdviceMapEntry {
    digest: Word,
    /// Values that will be pushed to the advice stack when this entry is requested
    values: Vec<Felt>,
}

#[cfg(feature = "std")]
impl clap::builder::ValueParserFactory for ExecutionConfig {
    type Parser = ExecutionConfigParser;

    fn value_parser() -> Self::Parser {
        ExecutionConfigParser
    }
}

#[cfg(feature = "std")]
#[doc(hidden)]
#[derive(Clone)]
pub struct ExecutionConfigParser;

#[cfg(feature = "std")]
impl clap::builder::TypedValueParser for ExecutionConfigParser {
    type Value = ExecutionConfig;

    fn parse_ref(
        &self,
        _cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &OsStr,
    ) -> Result<Self::Value, clap::error::Error> {
        use clap::error::{Error, ErrorKind};

        let inputs_path = Path::new(value);
        if !inputs_path.is_file() {
            return Err(Error::raw(
                ErrorKind::InvalidValue,
                format!("invalid inputs file: '{}' is not a file", inputs_path.display()),
            ));
        }

        let content = std::fs::read_to_string(inputs_path).map_err(|err| {
            Error::raw(ErrorKind::ValueValidation, format!("failed to read inputs file: {err}"))
        })?;
        let inputs_file = toml::from_str::<ExecutionConfigFile>(&content).map_err(|err| {
            Error::raw(ErrorKind::ValueValidation, format!("invalid inputs file: {err}"))
        })?;

        ExecutionConfig::from_inputs_file(inputs_file).map_err(|err| {
            Error::raw(ErrorKind::ValueValidation, format!("invalid inputs file: {err}"))
        })
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Word(miden_core::Word);
impl<'de> Deserialize<'de> for Word {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let digest = String::deserialize(deserializer)?;
        miden_core::Word::try_from(&digest)
            .map_err(|err| serde::de::Error::custom(format!("invalid digest: {err}")))
            .map(Self)
    }
}

fn deserialize_execution_options<'de, D>(deserializer: D) -> Result<ExecutionOptions, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct ExecOptions {
        max_cycles: Option<u32>,
        expected_cycles: u32,
    }

    ExecOptions::deserialize(deserializer).and_then(|opts| {
        ExecutionOptions::new(
            opts.max_cycles,
            opts.expected_cycles,
            ExecutionOptions::DEFAULT_CORE_TRACE_FRAGMENT_SIZE,
        )
        .map_err(|err| serde::de::Error::custom(format!("invalid execution options: {err}")))
    })
}

#[cfg(test)]
mod tests;
