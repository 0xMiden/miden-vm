use crate::{constants::SINGLE_LINE_EXPORT_REGEX, types::LineType};

pub fn is_comment(line: &str) -> bool {
    line.trim_start().starts_with('#')
}

pub fn is_stack_comment(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("# => [") || trimmed.starts_with("#! => [")
}

pub fn is_single_export_line(line: &str) -> bool {
    SINGLE_LINE_EXPORT_REGEX.is_match(line)
}

pub fn is_use_statement(line: &str) -> bool {
    line.trim_start().starts_with("use.")
}

pub fn is_proc_or_export(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with("proc.") || trimmed.starts_with("export.")
}

pub fn is_section_separator_comment(line: &str) -> bool {
    let trimmed = line.trim_start();
    (trimmed.starts_with("# ====") || trimmed.starts_with("#! ====")) && trimmed.contains("====")
}

pub fn classify_line(line: &str) -> LineType {
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

/// Breaks a long comment line into multiple lines at word boundaries
pub fn break_long_comment_line(line: &str, max_length: usize) -> Vec<String> {
    let trimmed = line.trim();

    // Check if it's a comment line
    if !trimmed.starts_with('#') {
        return vec![line.to_string()];
    }

    // If the line is not longer than max_length, return as is
    if trimmed.len() <= max_length {
        return vec![line.to_string()];
    }

    // Determine the comment prefix (# or #!)
    let comment_prefix = if trimmed.starts_with("#!") { "#!" } else { "#" };

    // Extract the comment content (everything after the prefix and optional space)
    let content_start = if trimmed.starts_with(&format!("{} ", comment_prefix)) {
        comment_prefix.len() + 1
    } else {
        comment_prefix.len()
    };

    let comment_content = &trimmed[content_start..];
    let available_length = max_length - comment_prefix.len() - 1; // -1 for the space after prefix

    let mut result = Vec::new();
    let mut current_line = String::new();

    for word in comment_content.split_whitespace() {
        // Check if adding this word would exceed the line length
        let would_exceed = if current_line.is_empty() {
            word.len() > available_length
        } else {
            current_line.len() + 1 + word.len() > available_length // +1 for space
        };

        if would_exceed && !current_line.is_empty() {
            // Finalize current line and start a new one
            result.push(format!("{} {}", comment_prefix, current_line));
            current_line = word.to_string();
        } else {
            // Add word to current line
            if current_line.is_empty() {
                current_line = word.to_string();
            } else {
                current_line.push(' ');
                current_line.push_str(word);
            }
        }
    }

    // Add the last line if it has content
    if !current_line.is_empty() {
        result.push(format!("{} {}", comment_prefix, current_line));
    }

    // If no result was generated (shouldn't happen), return original line
    if result.is_empty() {
        result.push(line.to_string());
    }

    result
}

/// Preprocesses the input to break long comment lines
pub fn preprocess_long_comments(code: &str, max_length: usize) -> String {
    let lines: Vec<&str> = code.lines().collect();
    let mut result = Vec::new();

    for line in lines {
        let broken_lines = break_long_comment_line(line, max_length);
        result.extend(broken_lines);
    }

    result.join("\n")
}

pub fn process_import_section(lines: &[&str]) -> (Vec<String>, usize) {
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
                    result.append(&mut current_import_group);
                    // Add empty line after imports before comment
                    result.push(String::new());
                }
                // Add the comment
                result.push(comment);
                end_index = i + 1;
            },
            LineType::Empty => {
                // Empty lines are preserved in their position, but avoid multiple consecutive empty
                // lines
                if !result.is_empty() && !result.last().is_some_and(|s| s.is_empty()) {
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
                    result.append(&mut current_import_group);
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
