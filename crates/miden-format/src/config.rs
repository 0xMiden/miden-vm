use serde::{Deserialize, Serialize};

const DEFAULT_INDENT_SIZE: u8 = 4;
const DEFAULT_MAX_LINE_LENGTH: u8 = 100;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid config file: {0}")]
    InvalidFormat(#[from] toml::de::Error),
    #[error("failed to read config: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// The width of an indent (in spaces)
    #[serde(
        default,
        rename = "indent_width",
        alias = "indent_size",
        skip_serializing_if = "Option::is_none"
    )]
    pub indent_size: Option<u8>,
    /// The maximum length (in characters) of any line before line breaks are introduced
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_line_length: Option<u8>,
}

/// Constructors
impl Config {
    /// Load configuration from `path`
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, ConfigError> {
        let bytes = std::fs::read(path)?;
        toml::from_slice(&bytes).map_err(ConfigError::InvalidFormat)
    }

    /// Merge non-default configuration options from `other` on top of `self`
    pub fn merge(&mut self, other: &Self) {
        if other.indent_size.is_some() {
            self.indent_size = other.indent_size;
        }
        if other.max_line_length.is_some() {
            self.max_line_length = other.max_line_length;
        }
    }
}

/// Accessors
impl Config {
    #[inline]
    pub fn indent_size(&self) -> usize {
        self.indent_size.unwrap_or(DEFAULT_INDENT_SIZE) as usize
    }

    #[inline]
    pub fn max_line_length(&self) -> usize {
        self.max_line_length.unwrap_or(DEFAULT_MAX_LINE_LENGTH) as usize
    }
}

impl clap::builder::ValueParserFactory for Config {
    type Parser = ConfigValueParser;
    fn value_parser() -> Self::Parser {
        ConfigValueParser
    }
}

#[derive(Default, Debug, Copy, Clone)]
pub struct ConfigValueParser;

impl clap::builder::TypedValueParser for ConfigValueParser {
    type Value = Config;

    fn parse_ref(
        &self,
        _cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        use clap::error::ErrorKind;

        if value.is_empty() {
            return Err(clap::Error::raw(
                ErrorKind::ValueValidation,
                "you must provide at least one configuration option",
            ));
        }

        let raw_value = value.to_str().ok_or_else(|| clap::Error::new(ErrorKind::InvalidUtf8))?;

        let mut config = Config::default();

        for opt in raw_value.split(',') {
            let opt = opt.trim();
            let kv = opt.split_once('=').map(|(k, v)| (k.trim(), v.trim()));
            match kv {
                Some(("indent_width" | "indent_size", value)) => {
                    config.indent_size = Some(parse_u8(value, "indent_width")?);
                },
                Some(("max_line_length", value)) => {
                    config.max_line_length = Some(parse_u8(value, "max_line_length")?);
                },
                _ => {
                    return Err(clap::Error::raw(
                        ErrorKind::ValueValidation,
                        format!("unrecognized configuration option '{opt}'"),
                    ));
                },
            }
        }

        Ok(config)
    }
}

fn parse_u8(input: &str, prop: &str) -> Result<u8, clap::Error> {
    use clap::error::ErrorKind;
    input.parse::<u8>().map_err(|err| {
        clap::Error::raw(ErrorKind::ValueValidation, format!("invalid value for {prop}: {err}"))
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use clap::builder::TypedValueParser;

    use super::*;

    #[test]
    fn toml_config_accepts_documented_indent_width() {
        let config: Config = toml::from_str("indent_width = 2").unwrap();
        assert_eq!(config.indent_size(), 2);
    }

    #[test]
    fn toml_config_keeps_indent_size_as_legacy_alias() {
        let config: Config = toml::from_str("indent_size = 2").unwrap();
        assert_eq!(config.indent_size(), 2);
    }

    #[test]
    fn cli_config_accepts_documented_indent_width() {
        let command = clap::Command::new("miden-format");
        let config = ConfigValueParser
            .parse_ref(&command, None, OsStr::new("indent_width=2,max_line_length=80"))
            .unwrap();

        assert_eq!(config.indent_size(), 2);
        assert_eq!(config.max_line_length(), 80);
    }
}
