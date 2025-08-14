use std::{
    fs::File,
    io::{self, BufRead, BufReader, Write},
    path::Path,
};

mod constants;
mod types;
mod utils;

use constants::{DEFAULT_MAX_COMMENT_LENGTH, INDENT};
use types::ConstructType;
use utils::{
    is_comment, is_proc_or_export, is_section_separator_comment, is_single_export_line,
    is_stack_comment, preprocess_long_comments, process_import_section,
};

pub fn format_code(code: &str) -> String {
    // First pass: preprocess long comments
    let preprocessed_code = preprocess_long_comments(code, DEFAULT_MAX_COMMENT_LENGTH);
    let lines: Vec<&str> = preprocessed_code.lines().collect();

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
                let current_is_stack_comment = is_stack_comment(trimmed_line);

                // Add blank line between stack comment and regular comment
                if last_line_was_stack_comment && !current_is_stack_comment && !last_line_was_empty
                {
                    formatted_code.push('\n');
                }

                last_line_was_stack_comment = current_is_stack_comment;

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
                                if let Some(next_word) = next_first_word
                                    && next_word != "end"
                                    && next_word != "else"
                                {
                                    formatted_code.push('\n');
                                    last_line_was_empty = true;
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
                // Skip empty lines between regular comments and proc/export/const, but preserve
                // them after section separators
                is_comment(prev_line)
                    && (is_proc_or_export(next_line) || next_line.starts_with("const."))
                    && !is_section_separator_comment(prev_line)
            } else {
                false
            };

            // Allow up to 1 empty line, collapse 2+ into 1, but skip if between comment and
            // proc/export
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
