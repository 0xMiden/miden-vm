use once_cell::sync::Lazy;
use regex::Regex;

pub const INDENT: &str = "    ";
pub const DEFAULT_MAX_COMMENT_LENGTH: usize = 100;

pub static SINGLE_LINE_EXPORT_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^export\..*(?:(?:::)|(?:->)).*$").unwrap());
