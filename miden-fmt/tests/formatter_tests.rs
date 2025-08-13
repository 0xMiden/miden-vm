use std::{fs::read_to_string, path::Path};

// Import the formatting functions from your crate.
use miden_fmt::format_code;

fn read_file_to_string(path: &Path) -> String {
    read_to_string(path).expect("Unable to read file")
}

#[test]
fn test_format_simple() {
    let input = "begin\nend";
    let expected_output = "begin\nend\n";
    assert_eq!(format_code(input), expected_output);
}

#[test]
fn test_format_with_indentation() {
    let input = "begin\n    proc\n    end\nend";
    let expected_output = "begin\n    proc\n    end\n\nend\n";
    assert_eq!(format_code(input), expected_output);
}

#[test]
fn test_format_if_else() {
    let input = "if\n    begin\n    end\nelse\n    begin\n    end\nend";
    let expected_output = "if\n    begin\n    end\nelse\n    begin\n    end\nend\n";
    assert_eq!(format_code(input), expected_output);
}

#[test]
fn test_format_complex() {
    let input = "begin\n    if\n        while\n        end\n    else\n        repeat\n        end\n    end\nend";
    let expected_output = "begin\n    if\n        while\n        end\n    else\n        repeat\n        end\n    end\nend\n";
    assert_eq!(format_code(input), expected_output);
}

#[test]
fn test_format_with_empty_lines() {
    let input = "begin\n\n    proc\n\n    end\n\nend";
    let expected_output = "begin\n\n    proc\n\n    end\n\nend\n";
    assert_eq!(format_code(input), expected_output);
}

#[test]
fn test_alphabetize_imports() {
    let input = "use.std::sys\nuse.miden::account\nuse.miden::note\nuse.std::crypto::hashes::native\n\nbegin\nend";
    let expected_output = "use.miden::account\nuse.miden::note\nuse.std::crypto::hashes::native\nuse.std::sys\n\nbegin\nend\n";
    assert_eq!(format_code(input), expected_output);
}

#[test]
fn test_alphabetize_imports_complex() {
    let input = "use.miden::note\nuse.miden::contracts::wallets::basic->wallet\nuse.miden::tx\nuse.miden::account\nuse.std::sys\nuse.std::crypto::hashes::native\nuse.std::math::u64\n\n# CONSTANTS\nconst.TEST=1\nbegin\nend";
    let expected_output = "use.miden::account\nuse.miden::contracts::wallets::basic->wallet\nuse.miden::note\nuse.miden::tx\nuse.std::crypto::hashes::native\nuse.std::math::u64\nuse.std::sys\n\n# CONSTANTS\n\nconst.TEST=1\nbegin\nend\n";
    assert_eq!(format_code(input), expected_output);
}

#[test]
fn test_single_empty_line_at_end() {
    let input = "begin\nend\n\n\n";
    let expected_output = "begin\nend\n";
    assert_eq!(format_code(input), expected_output);
}

#[test]
fn test_single_empty_line_at_end_no_trailing_newlines() {
    let input = "begin\nend";
    let expected_output = "begin\nend\n";
    assert_eq!(format_code(input), expected_output);
}

#[test]
fn test_imports_and_file_ending() {
    let input = "use.std::sys\nuse.miden::account\n\nbegin\nend\n\n";
    let expected_output = "use.miden::account\nuse.std::sys\n\nbegin\nend\n";
    assert_eq!(format_code(input), expected_output);
}

// New focused test files
#[test]
fn test_format_basic_formatting() {
    let input_path = Path::new("tests/unformatted/basic_formatting.masm");
    let expected_output_path = Path::new("tests/expected/basic_formatting_formatted.masm");

    let input_code = read_file_to_string(input_path);
    let expected_output = read_file_to_string(expected_output_path);

    let formatted_code = format_code(&input_code);
    assert_eq!(formatted_code, expected_output);
}

#[test]
fn test_format_procedure_formatting() {
    let input_path = Path::new("tests/unformatted/procedure_formatting.masm");
    let expected_output_path = Path::new("tests/expected/procedure_formatting_formatted.masm");

    let input_code = read_file_to_string(input_path);
    let expected_output = read_file_to_string(expected_output_path);

    let formatted_code = format_code(&input_code);
    assert_eq!(formatted_code, expected_output);
}

#[test]
fn test_format_control_flow() {
    let input_path = Path::new("tests/unformatted/control_flow.masm");
    let expected_output_path = Path::new("tests/expected/control_flow_formatted.masm");

    let input_code = read_file_to_string(input_path);
    let expected_output = read_file_to_string(expected_output_path);

    let formatted_code = format_code(&input_code);
    assert_eq!(formatted_code, expected_output);
}

#[test]
fn test_format_stack_operations() {
    let input_path = Path::new("tests/unformatted/stack_operations.masm");
    let expected_output_path = Path::new("tests/expected/stack_operations_formatted.masm");

    let input_code = read_file_to_string(input_path);
    let expected_output = read_file_to_string(expected_output_path);

    let formatted_code = format_code(&input_code);
    assert_eq!(formatted_code, expected_output);
}
