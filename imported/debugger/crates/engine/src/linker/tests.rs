use std::{ffi::OsStr, string::ToString};

use clap::builder::TypedValueParser;

use super::*;

#[test]
fn parser_rejects_masm_sources() {
    let source = tempfile::Builder::new().suffix(".masm").tempfile().unwrap();
    let error = LinkLibraryParser
        .parse_ref(&clap::Command::new("test"), None, source.path().as_os_str())
        .unwrap_err();

    assert!(error.to_string().contains("compiled .masp package"));
}

#[test]
fn parser_rejects_project_directories() {
    let project = tempfile::tempdir().unwrap();
    let error = LinkLibraryParser
        .parse_ref(&clap::Command::new("test"), None, project.path().as_os_str())
        .unwrap_err();

    assert!(error.to_string().contains("compiled .masp package"));
}

#[test]
fn parser_rejects_source_kind() {
    let error = LinkLibraryParser
        .parse_ref(&clap::Command::new("test"), None, OsStr::new("masm=library"))
        .unwrap_err();

    assert!(error.to_string().contains("supported values are 'masp'"));
}

#[test]
fn parser_accepts_explicit_static_package() {
    let package = tempfile::Builder::new().suffix(".masp").tempfile().unwrap();
    let value = format!("masp:static={}", package.path().display());
    let library = LinkLibraryParser
        .parse_ref(&clap::Command::new("test"), None, OsStr::new(&value))
        .unwrap();

    assert_eq!(library.linkage, Linkage::Static);
    assert_eq!(library.path.unwrap(), package.path().canonicalize().unwrap());
}

#[test]
fn parser_accepts_names_and_linkage_aliases() {
    let dynamic = LinkLibraryParser
        .parse_ref(&clap::Command::new("test"), None, OsStr::new("stdlib"))
        .unwrap();
    assert_eq!(dynamic.name(), "stdlib");
    assert_eq!(dynamic.linkage, Linkage::Dynamic);

    for value in ["masp=stdlib", "masp:dynamic=stdlib"] {
        let library = LinkLibraryParser
            .parse_ref(&clap::Command::new("test"), None, OsStr::new(value))
            .unwrap();
        assert_eq!(library.name(), "stdlib");
        assert_eq!(library.linkage, Linkage::Dynamic);
    }

    let core = LinkLibrary {
        name: "miden-core".into(),
        path: None,
        linkage: Linkage::Dynamic,
    };
    assert!(core.is_core());
    assert!(!core.is_protocol());
    let protocol = LinkLibrary {
        name: "base".into(),
        path: None,
        linkage: Linkage::Static,
    };
    assert!(protocol.is_protocol());
    assert!(!protocol.is_core());
}

#[test]
fn parser_reports_invalid_linkage_and_paths() {
    for value in ["masp:invalid=stdlib", "wasm=stdlib", "masp=", "missing.masm"] {
        let error = LinkLibraryParser
            .parse_ref(&clap::Command::new("test"), None, OsStr::new(value))
            .unwrap_err();
        assert!(!error.to_string().is_empty());
    }
}

#[test]
fn loading_reports_invalid_packages_and_search_paths() {
    let directory = tempfile::tempdir().unwrap();
    let invalid = directory.path().join("invalid.masp");
    std::fs::write(&invalid, b"not a package").unwrap();

    let from_path = LinkLibrary {
        name: "invalid".into(),
        path: Some(invalid.clone()),
        linkage: Linkage::Dynamic,
    };
    assert!(
        from_path
            .load(&[])
            .unwrap_err()
            .to_string()
            .contains("failed to load Miden package")
    );

    let wrong_extension = LinkLibrary {
        name: "source".into(),
        path: Some(directory.path().join("source.masm")),
        linkage: Linkage::Dynamic,
    };
    assert!(
        wrong_extension
            .load(&[])
            .unwrap_err()
            .to_string()
            .contains("not a compiled .masp package")
    );

    let missing = LinkLibrary {
        name: "missing".into(),
        path: None,
        linkage: Linkage::Dynamic,
    };
    assert!(
        missing
            .load(&[directory.path().to_path_buf()])
            .unwrap_err()
            .to_string()
            .contains("unable to locate library 'missing'")
    );

    let bad_entry = directory.path().join("bad.masp");
    std::fs::create_dir(&bad_entry).unwrap();
    let bad_entry_library = LinkLibrary {
        name: "bad".into(),
        path: None,
        linkage: Linkage::Dynamic,
    };
    assert!(
        bad_entry_library
            .load(&[directory.path().to_path_buf()])
            .unwrap_err()
            .to_string()
            .contains("not a file")
    );
}
