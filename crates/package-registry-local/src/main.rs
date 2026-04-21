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
            let version = version.map(|version| version.parse::<Version>()).transpose()?;
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
