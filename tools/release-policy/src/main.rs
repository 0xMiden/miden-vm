use std::{env, error::Error, fs::File};

use semver::Version;
use serde::Deserialize;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Deserialize)]
struct History {
    versions: Vec<PublishedVersion>,
}

#[derive(Deserialize)]
struct PublishedVersion {
    num: Version,
    yanked: bool,
}

fn latest(history: &History, current: &Version) -> Result<Version> {
    let same_line =
        |v: &&PublishedVersion| v.num.major == current.major && v.num.minor == current.minor;
    let mut baseline: Vec<_> = history.versions.iter().filter(same_line).collect();
    if baseline.is_empty() {
        baseline = history.versions.iter().filter(|v| v.num.pre.is_empty()).collect();
    }
    if baseline.is_empty() {
        baseline = history.versions.iter().collect();
    }
    let has_available = baseline.iter().any(|v| !v.yanked);
    baseline
        .into_iter()
        .filter(|v| !has_available || !v.yanked)
        .max_by(|a, b| a.num.cmp_precedence(&b.num))
        .map(|v| v.num.clone())
        .ok_or_else(|| "published version history is empty".into())
}

fn branch_allowed(branch: &str, tag: &str) -> Result<()> {
    let version = Version::parse(tag.strip_prefix('v').ok_or("release tag must start with v")?)?;
    let rc = version
        .pre
        .as_str()
        .strip_prefix("rc.")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    if !version.build.is_empty() || (!version.pre.is_empty() && !rc) {
        return Err(format!("expected a stable tag or rc.N tag, got {tag}").into());
    }
    let stable = version.pre.is_empty();
    let allowed = match branch {
        "main" => stable,
        "next" => !stable,
        _ => {
            stable
                && version.patch > 0
                && (branch == format!("release/v{version}")
                    || branch == format!("release-v{version}"))
        },
    };
    if !allowed {
        return Err(format!("unsupported release branch {branch} for {tag}").into());
    }
    Ok(())
}

fn run(args: &[String]) -> Result<()> {
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["compare", left, right] => {
            println!("{}", Version::parse(left)?.cmp_precedence(&Version::parse(right)?) as i8)
        },
        ["latest", current, path] => {
            let history = serde_json::from_reader(File::open(path)?)?;
            println!("{}", latest(&history, &Version::parse(current)?)?);
        },
        ["branch", branch, tag] => branch_allowed(branch, tag)?,
        _ => return Err("expected compare, latest, or branch arguments".into()),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run(&env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("release policy: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_branches() {
        for (branch, tag, allowed) in [
            ("main", "v0.36.0", true),
            ("next", "v1.0.0-rc.10", true),
            ("next", "v1.0.0", false),
            ("main", "v1.0.0-rc.1", false),
            ("release/v0.35.1", "v0.35.1", true),
            ("release-v0.35.2", "v0.35.2", true),
            ("release/v0.35.1", "v0.35.2", false),
            ("release/v0.36.0", "v0.36.0", false),
            ("feature/release", "v0.36.0", false),
            ("main", "v1.0.0+build", false),
        ] {
            assert_eq!(branch_allowed(branch, tag).is_ok(), allowed, "{branch} {tag}");
        }
    }

    #[test]
    fn maintenance_and_rc_baselines() {
        let history = serde_json::from_str::<History>(
            r#"{"versions":[
            {"num":"0.35.0","yanked":false},{"num":"0.35.1","yanked":false},
            {"num":"0.35.9","yanked":true},{"num":"0.36.0","yanked":false},
            {"num":"1.0.0-rc.2","yanked":false},{"num":"1.0.0-rc.10","yanked":false}
        ]}"#,
        )
        .unwrap();
        for (current, expected) in [
            ("0.35.2", "0.35.1"),
            ("0.36.1", "0.36.0"),
            ("1.0.0-rc.11", "1.0.0-rc.10"),
            ("2.0.0", "0.36.0"),
        ] {
            assert_eq!(
                latest(&history, &Version::parse(current).unwrap()).unwrap(),
                Version::parse(expected).unwrap()
            );
        }
    }

    #[test]
    fn yanked_and_invalid_history() {
        let history = serde_json::from_str::<History>(
            r#"{"versions":[
            {"num":"0.35.0+build","yanked":true},{"num":"1.0.0-rc.1","yanked":false}
        ]}"#,
        )
        .unwrap();
        for current in ["0.35.1", "0.36.0"] {
            assert_eq!(
                latest(&history, &Version::parse(current).unwrap()).unwrap().to_string(),
                "0.35.0+build"
            );
        }
        assert!(
            serde_json::from_str::<History>(r#"{"versions":[{"num":"invalid","yanked":false}]}"#)
                .is_err()
        );
        assert!(latest(&History { versions: vec![] }, &Version::parse("0.36.0").unwrap()).is_err());
    }
}
