use std::{fs, fs::read_to_string, path::Path};

// Import the formatting functions from your crate.
use formatter::{format_code, format_file};
use tempfile::tempdir;

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
    let expected_output = "begin\n    proc\n    end\nend\n";
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
fn test_format_example1() {
    let input_path = Path::new("tests/unformatted/example1.masm");
    let expected_output_path = Path::new("tests/expected/example1_formatted.masm");

    let input_code = read_file_to_string(input_path);
    let expected_output = read_file_to_string(expected_output_path);

    let formatted_code = format_code(&input_code);
    assert_eq!(formatted_code, expected_output);
}

#[test]
fn test_format_example2() {
    let input_path = Path::new("tests/unformatted/example2.masm");
    let expected_output_path = Path::new("tests/expected/example2_formatted.masm");

    let input_code = read_file_to_string(input_path);
    let expected_output = read_file_to_string(expected_output_path);

    let formatted_code = format_code(&input_code);
    assert_eq!(formatted_code, expected_output);
}

#[test]
fn test_format_example3() {
    let input_path = Path::new("tests/unformatted/example3.masm");
    let expected_output_path = Path::new("tests/expected/example3_formatted.masm");

    let input_code = read_file_to_string(input_path);
    let expected_output = read_file_to_string(expected_output_path);

    let formatted_code = format_code(&input_code);
    assert_eq!(formatted_code, expected_output);
}

#[test]
fn test_format_example4() {
    let input_path = Path::new("tests/unformatted/example4.masm");
    let expected_output_path = Path::new("tests/expected/example4_formatted.masm");

    let input_code = read_file_to_string(input_path);
    let expected_output = read_file_to_string(expected_output_path);

    let formatted_code = format_code(&input_code);
    assert_eq!(formatted_code, expected_output);
}

#[test]
fn test_nested_directory_formatting_example5() {
    // Create a temporary directory.
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let temp_nested_dir = temp_dir.path().join("nested_dir_test");
    fs::create_dir_all(&temp_nested_dir).expect("Failed to create nested dir in temp");

    // Copy the original file from tests/unformatted/nested_dir_test/example5.masm
    let src_path = Path::new("tests/unformatted/nested_dir_test/example5.masm");
    let dest_path = temp_nested_dir.join("example5.masm");
    fs::copy(src_path, &dest_path).expect("Failed to copy file to temp directory");

    // Read the original content from the temporary file.
    let original_content = read_file_to_string(&dest_path);

    // Run the formatter on the temporary file.
    format_file(&dest_path).expect("Formatting failed");

    // Read the formatted content.
    let formatted_content = read_file_to_string(&dest_path);

    // If you have an expected formatted file, you can compare with it.
    let expected_path = Path::new("tests/expected/example5_formatted.masm");
    if expected_path.exists() {
        let expected_content = read_file_to_string(expected_path);
        assert_eq!(formatted_content, expected_content, "The file was not formatted as expected.");
    } else {
        // Otherwise, ensure that formatting has changed the content.
        assert_ne!(
            formatted_content, original_content,
            "The file content did not change after formatting."
        );
    }
}

#[test]
fn test_format_example6() {
    let input_path = Path::new("tests/unformatted/example6.masm");
    let expected_output_path = Path::new("tests/expected/example6_formatted.masm");

    let input_code = read_file_to_string(input_path);
    let expected_output = read_file_to_string(expected_output_path);

    let formatted_code = format_code(&input_code);
    assert_eq!(formatted_code, expected_output);
}

#[test]
fn test_format_example7() {
    let input_path = Path::new("tests/unformatted/example7.masm");
    let expected_output_path = Path::new("tests/expected/example7_formatted.masm");

    let input_code = read_file_to_string(input_path);
    let expected_output = read_file_to_string(expected_output_path);

    let formatted_code = format_code(&input_code);
    assert_eq!(formatted_code, expected_output);
}

#[test]
fn test_format_example8() {
    let input_path = Path::new("tests/unformatted/example8.masm");
    let expected_output_path = Path::new("tests/expected/example8_formatted.masm");

    let input_code = read_file_to_string(input_path);
    let expected_output = read_file_to_string(expected_output_path);

    let formatted_code = format_code(&input_code);
    assert_eq!(formatted_code, expected_output);
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
    let expected_output = "use.miden::account\nuse.miden::contracts::wallets::basic->wallet\nuse.miden::note\nuse.miden::tx\nuse.std::crypto::hashes::native\nuse.std::math::u64\nuse.std::sys\n\n# CONSTANTS\nconst.TEST=1\nbegin\nend\n";
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
