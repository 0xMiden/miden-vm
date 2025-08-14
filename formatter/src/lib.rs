use std::{
    fs::File,
    io::{self, BufRead, BufReader, Write},
    path::Path,
};

use once_cell::sync::Lazy;
use regex::Regex;

static SINGLE_LINE_EXPORT_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^export\..*(?:(?:::)|(?:->)).*$").unwrap());

#[derive(Debug, PartialEq, Clone)]
enum ConstructType {
    Proc,
    Export,
    Begin,
    End,
    While,
    Repeat,
    If,
    Else,
}

impl ConstructType {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "proc" => Some(Self::Proc),
            "export" => Some(Self::Export),
            "begin" => Some(Self::Begin),
            "end" => Some(Self::End),
            "while" => Some(Self::While),
            "repeat" => Some(Self::Repeat),
            "if" => Some(Self::If),
            "else" => Some(Self::Else),
            _ => None,
        }
    }
}

const INDENT: &str = "    ";

fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with('#')
}

fn is_stack_comment(line: &str) -> bool {
    line.trim_start().starts_with("# =>")
}

fn is_single_export_line(line: &str) -> bool {
    SINGLE_LINE_EXPORT_REGEX.is_match(line)
}

fn is_use_statement(line: &str) -> bool {
    line.trim_start().starts_with("use.")
}

fn extract_and_sort_imports(lines: &[&str]) -> (Vec<String>, usize) {
    let mut imports = Vec::new();
    let mut import_end_index = 0;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if is_use_statement(trimmed) {
            imports.push(trimmed.to_string());
            import_end_index = i + 1;
        } else if !trimmed.is_empty() {
            // Stop collecting imports when we hit non-empty, non-import line
            break;
        } else if !imports.is_empty() {
            // Include empty lines that come after imports but before other content
            import_end_index = i + 1;
        }
    }

    // Sort imports alphabetically
    imports.sort();

    (imports, import_end_index)
}

pub fn format_code(code: &str) -> String {
    let lines: Vec<&str> = code.lines().collect();

    // Extract and sort imports
    let (sorted_imports, import_end_index) = extract_and_sort_imports(&lines);

    let mut formatted_code = String::new();
    let mut indentation_level = 0;
    let mut construct_stack = Vec::new();
    let mut last_line_was_empty = false;
    let mut last_was_export_line = false;
    let mut last_line_was_stack_comment = false;

    // Add sorted imports first
    for import in sorted_imports {
        formatted_code.push_str(&import);
        formatted_code.push('\n');
    }

    // Add empty line after imports if there were any and the next line isn't empty
    if import_end_index > 0
        && import_end_index < lines.len()
        && !lines[import_end_index].trim().is_empty()
    {
        formatted_code.push('\n');
    }

    // Process remaining lines (skip the import section)
    let remaining_lines = &lines[import_end_index..];

    for line in remaining_lines {
        let trimmed_line = line.trim();

        if !trimmed_line.is_empty() {
            if is_comment(trimmed_line) {
                last_line_was_stack_comment = is_stack_comment(trimmed_line);

                if last_was_export_line {
                    formatted_code.push_str(trimmed_line);
                } else {
                    if let Some(prev_line) = formatted_code.lines().last() {
                        let prev_indent_level =
                            prev_line.chars().take_while(|&c| c == ' ').count() / 4;
                        if prev_line.trim_start().starts_with("export") {
                            formatted_code.push_str(&INDENT.repeat(prev_indent_level + 1));
                        } else {
                            formatted_code.push_str(&INDENT.repeat(indentation_level));
                        }
                    } else {
                        formatted_code.push_str(&INDENT.repeat(indentation_level));
                    }
                    formatted_code.push_str(trimmed_line);
                }
                formatted_code.push('\n');
                last_line_was_empty = false;
                continue;
            }

            if is_single_export_line(trimmed_line) {
                formatted_code.push_str(trimmed_line);
                formatted_code.push('\n');
                last_line_was_empty = false;
                last_was_export_line = true;
                continue;
            }

            last_was_export_line = false;

            // Remove inline comment for keyword extraction.
            let code_without_comment = trimmed_line.split('#').next().unwrap().trim();
            let first_word = code_without_comment.split('.').next();

            // Special handling for stack comment newline
            if last_line_was_stack_comment {
                if let Some(word) = first_word
                    && word != "end"
                    && !last_line_was_empty
                {
                    formatted_code.push('\n');
                }
                last_line_was_stack_comment = false;
            }

            if let Some(word) = first_word
                && let Some(construct) = ConstructType::from_str(word)
            {
                match construct {
                    ConstructType::End => {
                        if let Some(last_construct) = construct_stack.pop()
                            && last_construct != ConstructType::End
                            && indentation_level > 0
                        {
                            indentation_level -= 1;
                        }
                    },
                    ConstructType::Else => {
                        if let Some(last_construct) = construct_stack.last()
                            && *last_construct == ConstructType::If
                            && indentation_level > 0
                        {
                            indentation_level -= 1;
                        }
                    },
                    _ => {
                        construct_stack.push(construct.clone());
                    },
                }

                formatted_code.push_str(&INDENT.repeat(indentation_level));
                formatted_code.push_str(trimmed_line);
                formatted_code.push('\n');
                last_line_was_empty = false;

                match construct {
                    ConstructType::Begin
                    | ConstructType::If
                    | ConstructType::Proc
                    | ConstructType::Export
                    | ConstructType::Repeat
                    | ConstructType::While
                    | ConstructType::Else => {
                        indentation_level += 1;
                    },
                    _ => {},
                }

                continue;
            }

            formatted_code.push_str(&INDENT.repeat(indentation_level));
            formatted_code.push_str(trimmed_line);
            formatted_code.push('\n');
            last_line_was_empty = false;
        } else if !last_line_was_empty {
            formatted_code.push('\n');
            last_line_was_empty = true;
        }
    }

    // Ensure the output ends with exactly one newline.
    while formatted_code.ends_with('\n') {
        formatted_code.pop();
    }
    formatted_code.push('\n');

    formatted_code
}

pub fn format_file(file_path: &Path) -> io::Result<()> {
    let file = File::open(file_path)?;
    let mut input_code = String::new();

    let reader = BufReader::new(file);
    for line in reader.lines() {
        input_code.push_str(&line?);
        input_code.push('\n');
    }

    let formatted_code = format_code(&input_code);

    let mut file = File::create(file_path)?;
    file.write_all(formatted_code.as_bytes())?;

    Ok(())
}
