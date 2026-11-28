use std::{fs, process::Command};

#[test]
fn version_selection_and_invalid_input() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("history.json");
    let mixed =
        r#"{"versions":[{"num":"1.2.0","yanked":false},{"num":"1.2.1-rc.1","yanked":false}]}"#;
    let rc_only = r#"{"versions":[{"num":"1.2.0-rc.1","yanked":false}]}"#;
    for (command, current, history, expected) in [
        ("latest", "1.2.1", mixed, Some("1.2.1-rc.1")),
        ("baseline", "1.2.1", mixed, Some("1.2.0")),
        ("baseline", "invalid", rc_only, None),
    ] {
        fs::write(&path, history).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_miden-release-policy"))
            .args([command, current])
            .arg(&path)
            .output()
            .unwrap();
        if let Some(expected) = expected {
            assert!(output.status.success(), "{output:?}");
            assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), expected);
        } else {
            assert_eq!(output.status.code(), Some(1));
            assert_eq!(
                String::from_utf8(output.stderr).unwrap(),
                "release policy: invalid current version \"invalid\": unexpected character 'i' while parsing major version number\n"
            );
        }
    }
}

#[test]
fn stable_release_follows_its_prerelease() {
    let output = Command::new(env!("CARGO_BIN_EXE_miden-release-policy"))
        .args(["compare", "1.5.0", "1.5.0-alpha.3"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"1\n");
}
