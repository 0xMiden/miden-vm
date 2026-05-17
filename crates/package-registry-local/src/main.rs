use std::{io::Write, path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
use miden_package_registry::{PackageId, PackageRegistry, Version};
use miden_package_registry_local::LocalPackageRegistry;

#[derive(Debug, Parser)]
#[command(
    name = "miden-registry",
    version,
    about,
    rename_all = "kebab-case",
    arg_required_else_help(true)
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Publish `package` to the local package registry
    Publish { package: PathBuf },
    /// List all available packages known to the local registry
    List {
        /// Emit package list in JSON format, rather than the default human-readable format
        #[arg(long)]
        json: bool,
    },
    /// Query for information about a package in the registry
    Show {
        /// The package identifier/name
        package: String,
        /// The version of the package to show information for.
        ///
        /// If not specified, the latest version of the package is shown.
        #[arg(long)]
        version: Option<String>,
        /// If an error occurs, do not emit any output, just exit with a non-zero code
        #[arg(long)]
        quiet: bool,
        /// Emit package information in JSON format, rather than the default human-readable format
        #[arg(long)]
        json: bool,
    },
}

fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mut registry = LocalPackageRegistry::load_from_env()?;

    run(cli, &mut registry)
}

fn run(
    cli: Cli,
    registry: &mut LocalPackageRegistry,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match cli.command {
        Command::Publish { package } => {
            let published = registry.publish(package)?;
            println!(
                "published {}@{} -> {}",
                published.name,
                published.version,
                published.artifact_path.display()
            );
        },
        Command::List { json } => {
            let summaries = registry.list();
            if json {
                let mut stdout = std::io::stdout();
                serde_json::to_writer_pretty(&mut stdout, &summaries)?;
                writeln!(&mut stdout)?;
            } else {
                for package in registry.list() {
                    println!("{} {}", package.name, package.version);
                }
            }
        },
        Command::Show { package, version, quiet, json } => {
            let package_id = PackageId::from(package);
            let version = match version {
                Some(version) => match version.parse::<Version>() {
                    Ok(version) => Some(version),
                    Err(err) => {
                        if quiet {
                            return Ok(ExitCode::from(2));
                        }
                        return Err(Box::new(err));
                    },
                },
                None => None,
            };
            if let Some(summary) = registry.show(&package_id, version.as_ref()) {
                if json {
                    let mut stdout = std::io::stdout();
                    serde_json::to_writer_pretty(&mut stdout, &summary)?;
                    writeln!(&mut stdout)?;
                } else {
                    println!("package: {}", summary.name);
                    println!("version: {}", summary.version);
                    if let Some(description) = summary.description {
                        println!("description: {description}");
                    }
                    if let Some(path) = summary.artifact_path {
                        println!("artifact: {}", path.display());
                    }
                    if summary.dependencies.is_empty() {
                        println!("dependencies: none");
                    } else {
                        println!("dependencies:");
                        for (dependency, requirement) in summary.dependencies {
                            println!("  {dependency} {requirement}");
                        }
                    }
                }
            } else {
                if !quiet {
                    if registry.is_available(&package_id) {
                        if let Some(version) = version {
                            eprintln!(
                                "Version '{version}' does not exist for package '{package_id}'"
                            );
                        } else {
                            eprintln!("No available versions for package '{package_id}'");
                        }
                    } else {
                        eprintln!("'{package_id}' is not a registered package");
                    }
                }
                return Ok(ExitCode::from(2));
            }
        },
    }

    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    fn empty_test_registry() -> (tempfile::TempDir, LocalPackageRegistry) {
        let tempdir = tempfile::TempDir::new().unwrap();
        let registry = LocalPackageRegistry::load(
            tempdir.path().join("etc").join("registry").join("index.toml"),
            tempdir.path().join("lib"),
        )
        .unwrap();

        (tempdir, registry)
    }

    #[test]
    fn help_uses_public_binary_name() {
        let mut command = Cli::command();
        assert_eq!(command.get_name(), "miden-registry");

        let help = command.render_help().to_string();
        assert!(
            help.contains("Usage: miden-registry"),
            "help should advertise the public binary name:\n{help}",
        );
    }

    #[test]
    fn show_quiet_invalid_version_returns_error_code_without_registry_lookup() {
        let (_tempdir, mut registry) = empty_test_registry();
        let cli = Cli::parse_from([
            "miden-registry",
            "show",
            "some-package",
            "--version",
            "not-a-version",
            "--quiet",
        ]);

        let exit_code = run(cli, &mut registry).expect("quiet parse errors should not escape");

        assert_eq!(exit_code, ExitCode::from(2));
    }

    #[test]
    fn show_invalid_version_without_quiet_returns_parse_error() {
        let (_tempdir, mut registry) = empty_test_registry();
        let cli = Cli::parse_from([
            "miden-registry",
            "show",
            "some-package",
            "--version",
            "not-a-version",
        ]);

        let err = run(cli, &mut registry).expect_err("non-quiet parse errors should escape");

        assert!(err.to_string().contains("invalid semantic version"), "{err}");
    }
}
