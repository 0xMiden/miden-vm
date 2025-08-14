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
    let trimmed = line.trim_start();
    trimmed.starts_with("# => [") || trimmed.starts_with("#! => [")
}

fn is_single_export_line(line: &str) -> bool {
    SINGLE_LINE_EXPORT_REGEX.is_match(line)
}

fn is_use_statement(line: &str) -> bool {
    line.trim_start().starts_with("use.")
}

fn is_proc_or_export(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with("proc.") || trimmed.starts_with("export.")
}

fn is_section_separator_comment(line: &str) -> bool {
    let trimmed = line.trim_start();
    (trimmed.starts_with("# ====") || trimmed.starts_with("#! ====")) && trimmed.contains("====")
}

#[derive(Debug, Clone)]
enum LineType {
    Import(String),
    Comment(String),
    Empty,
    Other(String),
}

fn classify_line(line: &str) -> LineType {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        LineType::Empty
    } else if is_use_statement(trimmed) {
        LineType::Import(trimmed.to_string())
    } else if is_comment(trimmed) {
        LineType::Comment(trimmed.to_string())
    } else {
        LineType::Other(trimmed.to_string())
    }
}

fn process_import_section(lines: &[&str]) -> (Vec<String>, usize) {
    let mut result = Vec::new();
    let mut current_import_group = Vec::new();
    let mut end_index = 0;

    for (i, line) in lines.iter().enumerate() {
        let line_type = classify_line(line);

        match line_type {
            LineType::Import(import) => {
                current_import_group.push(import);
                end_index = i + 1;
            },
            LineType::Comment(comment) => {
                // If we have imports in the current group, sort and add them
                if !current_import_group.is_empty() {
                    current_import_group.sort();
                    result.extend(current_import_group.drain(..));
                    // Add empty line after imports before comment
                    result.push(String::new());
                }
                // Add the comment
                result.push(comment);
                end_index = i + 1;
            },
            LineType::Empty => {
                // Empty lines are preserved in their position, but avoid multiple consecutive empty lines
                if !result.is_empty() && !result.last().map_or(false, |s| s.is_empty()) {
                    result.push(String::new());
                    end_index = i + 1;
                }
            },
            LineType::Other(content) => {
                // Stop processing when we hit const or other non-import content
                if content.starts_with("const.") {
                    break;
                }
                // If we have imports in the current group, sort and add them
                if !current_import_group.is_empty() {
                    current_import_group.sort();
                    result.extend(current_import_group.drain(..));
                }
                break;
            },
        }
    }

    // Handle any remaining imports in the current group
    if !current_import_group.is_empty() {
        current_import_group.sort();
        result.extend(current_import_group);
    }

    (result, end_index)
}

pub fn format_code(code: &str) -> String {
    let lines: Vec<&str> = code.lines().collect();

    // Extract and sort imports
    let (sorted_imports, import_end_index) = process_import_section(&lines);

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

    // Add empty line after imports if there were any and the next line exists
    if import_end_index > 0 && import_end_index < lines.len() {
        // Always add empty line after imports, unless the next line is already empty
        let next_line = lines[import_end_index].trim();
        if !next_line.is_empty() {
            formatted_code.push('\n');
        }
    }

    // Process remaining lines (skip the import section)
    let remaining_lines = &lines[import_end_index..];

    for (i, line) in remaining_lines.iter().enumerate() {
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
                    && word != "else"
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
                        let was_proc_or_export_end =
                            if let Some(last_construct) = construct_stack.pop() {
                                let is_proc_or_export = matches!(
                                    last_construct,
                                    ConstructType::Proc | ConstructType::Export
                                );
                                if last_construct != ConstructType::End && indentation_level > 0 {
                                    indentation_level -= 1;
                                }
                                is_proc_or_export
                            } else {
                                false
                            };

                        formatted_code.push_str(&INDENT.repeat(indentation_level));
                        formatted_code.push_str(trimmed_line);
                        formatted_code.push('\n');
                        last_line_was_empty = false;

                        // Add blank line after procedure/export end if there's more content
                        if was_proc_or_export_end && i + 1 < remaining_lines.len() {
                            let next_line = remaining_lines[i + 1].trim();
                            if !next_line.is_empty() {
                                formatted_code.push('\n');
                                last_line_was_empty = true;
                            }
                        }
                        // Add blank line after any "end" statement if followed by non-"end" opcode
                        // and not a stack comment, and not "else"
                        else if !was_proc_or_export_end && i + 1 < remaining_lines.len() {
                            let next_line = remaining_lines[i + 1].trim();
                            if !next_line.is_empty() && !is_stack_comment(next_line) {
                                // Check if the next line is another "end" statement or "else"
                                let next_code_without_comment =
                                    next_line.split('#').next().unwrap().trim();
                                let next_first_word = next_code_without_comment.split('.').next();
                                if let Some(next_word) = next_first_word {
                                    if next_word != "end" && next_word != "else" {
                                        formatted_code.push('\n');
                                        last_line_was_empty = true;
                                    }
                                }
                            }
                        }

                        continue;
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
        } else {
            // This is an empty line in the input
            // Check if we should skip adding it (e.g., between comment and const)
            let should_skip_empty_line = if i + 1 < remaining_lines.len() && !last_line_was_empty {
                let next_line = remaining_lines[i + 1].trim();
                let prev_lines: Vec<&str> = formatted_code.lines().collect();
                let prev_line = prev_lines.last().map(|l| l.trim()).unwrap_or("");

                // Skip empty line if previous line is a comment and next line is a const
                is_comment(prev_line) && next_line.starts_with("const.")
            } else {
                false
            };

            if !should_skip_empty_line && !last_line_was_empty {
                formatted_code.push('\n');
                last_line_was_empty = true;
            }
        }
    }

    // Ensure the output ends with exactly one newline.
    while formatted_code.ends_with('\n') {
        formatted_code.pop();
    }
    formatted_code.push('\n');

    // Final pass: collapse any remaining multiple consecutive empty lines (3+ becomes 1)
    // Also prevent blank lines between comments and proc/export declarations
    let lines: Vec<&str> = formatted_code.lines().collect();
    let mut final_output = String::new();
    let mut consecutive_empty_count = 0;

    for (i, line) in lines.iter().enumerate() {
        let is_empty = line.trim().is_empty();

        if is_empty {
            consecutive_empty_count += 1;

            // Check if this empty line is between a comment and proc/export/const
            let should_skip_empty_line = if i > 0 && i + 1 < lines.len() {
                let prev_line = lines[i - 1].trim();
                let next_line = lines[i + 1].trim();
                // Skip empty lines between regular comments and proc/export/const, but preserve them after section separators
                is_comment(prev_line)
                    && (is_proc_or_export(next_line) || next_line.starts_with("const."))
                    && !is_section_separator_comment(prev_line)
            } else {
                false
            };

            // Allow up to 1 empty line, collapse 2+ into 1, but skip if between comment and proc/export
            if consecutive_empty_count <= 1 && !should_skip_empty_line {
                final_output.push_str(line);
                final_output.push('\n');
            }
            // Skip additional consecutive empty lines (2nd, 3rd, etc.) or comment-proc gaps
        } else {
            final_output.push_str(line);
            final_output.push('\n');
            consecutive_empty_count = 0;
        }
    }

    // Ensure the final output ends with exactly one newline
    while final_output.ends_with('\n') {
        final_output.pop();
    }
    final_output.push('\n');

    final_output
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
