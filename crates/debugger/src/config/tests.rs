use clap::Parser;

use super::*;

#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    config: DebuggerConfig,
}

#[test]
fn parses_artifact_execution_and_linker_options() {
    let artifact = tempfile::Builder::new().suffix(".masp").tempfile().unwrap();
    let cli = Cli::try_parse_from([
        "miden-debug",
        artifact.path().to_str().unwrap(),
        "--repl",
        "--color",
        "never",
        "--working-dir",
        "workspace",
        "--entrypoint",
        "example::main",
        "--source-path-prefix",
        "/workspace",
        "-L",
        "libraries",
        "-l",
        "masp:static=example",
        "--commands",
        "commands.txt",
        "--",
        "42",
        "true",
    ])
    .unwrap();
    assert!(cli.config.input.is_some());
    assert!(cli.config.repl);
    assert_eq!(cli.config.color, ColorChoice::Never);
    assert_eq!(cli.config.working_dir, Some(PathBuf::from("workspace")));
    assert_eq!(cli.config.entrypoint.as_deref(), Some("example::main"));
    assert_eq!(cli.config.source_path_prefixes, [PathBuf::from("/workspace")]);
    assert_eq!(cli.config.search_path, [PathBuf::from("libraries")]);
    assert_eq!(cli.config.link_libraries[0].name(), "example");
    assert_eq!(cli.config.link_libraries[0].linkage, miden_debug_engine::Linkage::Static);
    assert_eq!(cli.config.commands, Some(PathBuf::from("commands.txt")));
    assert_eq!(cli.config.args, ["42", "true"]);
    assert!(Cli::try_parse_from(["miden-debug", "--color", "invalid"]).is_err());
}

#[test]
fn color_choices_parse_and_respect_forced_preferences() {
    for (text, expected) in [
        ("always", ColorChoice::Always),
        ("ALWAYS-ANSI", ColorChoice::AlwaysAnsi),
        ("never", ColorChoice::Never),
        ("auto", ColorChoice::Auto),
    ] {
        assert_eq!(text.parse::<ColorChoice>().unwrap(), expected);
    }
    assert_eq!(
        "invalid".parse::<ColorChoice>().unwrap_err().to_string(),
        "invalid color choice: invalid"
    );
    assert!(ColorChoice::Always.should_attempt_color());
    assert!(ColorChoice::AlwaysAnsi.should_attempt_color());
    assert!(!ColorChoice::Never.should_attempt_color());
    assert_eq!(ColorChoice::Auto.should_attempt_color(), ColorChoice::Auto.env_allows_color());
    assert_eq!(ColorChoice::default(), ColorChoice::Auto);
}
