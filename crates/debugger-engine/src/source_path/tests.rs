use super::normalize_source_path;

#[test]
fn normalizes_file_uris_and_windows_drive_letters() {
    assert_eq!(
        normalize_source_path("file:///C:/Users/me/program.masm"),
        "c:/Users/me/program.masm"
    );
    assert_eq!(
        normalize_source_path("file:///c:/Users/me/program.masm"),
        "c:/Users/me/program.masm"
    );
    assert_eq!(
        normalize_source_path("file://localhost/C:/Users/me/program.masm"),
        "c:/Users/me/program.masm"
    );
    assert_eq!(normalize_source_path("C:\\Users\\me\\program.masm"), "c:/Users/me/program.masm");
}

#[test]
fn normalizes_path_components() {
    assert_eq!(normalize_source_path("/home/me/./src/../program.masm"), "/home/me/program.masm");
    assert_eq!(normalize_source_path("relative/./src/../program.masm"), "relative/program.masm");
}
