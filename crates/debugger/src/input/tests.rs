use alloc::string::ToString;

use clap::builder::TypedValueParser;

use super::*;

#[test]
fn parser_accepts_compiled_packages() {
    let package = tempfile::Builder::new().suffix(".masp").tempfile().unwrap();
    let input = InputFileParser
        .parse_ref(&clap::Command::new("test"), None, package.path().as_os_str())
        .unwrap();

    assert_matches!(input.path.to_path(), Some(path) if path == package.path());
}

#[test]
fn input_files_read_embedded_and_disk_content_and_report_io_and_scheme_errors() {
    let input = InputFile::default();
    assert_eq!(input.file_name(), "<noname>");
    assert!(input.bytes().unwrap().is_empty());
    assert!(input.to_path().is_none());
    let input = InputFile::new(Uri::new("stdin://input.masp"), Some(Box::from(&b"package"[..])));
    assert_eq!(input.file_name(), "input.masp");
    assert_eq!(input.bytes().unwrap().as_ref(), b"package");
    assert!(format!("{input:?}").contains("length: 7"));
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("input.masp");
    std::fs::write(&path, b"disk package").unwrap();
    let input = InputFile::from_path(&path);
    assert_eq!(input.file_name(), "input.masp");
    assert_eq!(input.bytes().unwrap().as_ref(), b"disk package");
    assert!(format!("{input:?}").contains("None"));
    std::fs::remove_file(path).unwrap();
    assert!(matches!(input.bytes(), Err(InvalidInputError::Io(_))));
    let remote = InputFile::new(Uri::new("https://example.com/input.masp"), None);
    assert!(matches!(remote.bytes(), Err(InvalidInputError::UnsupportedScheme(_))));
}

#[test]
fn input_parser_reports_missing_files_and_accepts_case_insensitive_extensions() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing.masp");
    assert!(
        InputFileParser
            .parse_ref(&clap::Command::new("test"), None, missing.as_os_str())
            .unwrap_err()
            .to_string()
            .contains("does not exist")
    );
    let package = directory.path().join("test.MASP");
    std::fs::write(&package, []).unwrap();
    let input = InputFileParser
        .parse_ref(&clap::Command::new("test"), None, package.as_os_str())
        .unwrap();
    assert_eq!(input.to_path().unwrap(), package);
}
