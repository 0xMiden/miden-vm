use super::*;

#[test]
fn test_version_display() {
    let version = Version {
        major: 1,
        minor: 62,
        patch: None,
        git_commit: "7f284b169ecd19602487eb4d290ae651d4398ce7".to_string(),
    };
    assert_eq!(version.to_string(), "1.62.x");

    let version = Version {
        major: 1,
        minor: 62,
        patch: Some(1),
        git_commit: "7f284b169ecd19602487eb4d290ae651d4398ce7".to_string(),
    };
    assert_eq!(version.to_string(), "1.62.1");
}
