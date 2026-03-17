use std::path::PathBuf;

use clap::{Parser, Subcommand};
use miden_package_registry::{PackageId, Version};
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
    List,
    /// Query for information about a package in the registry
    Show {
        /// The package identifier/name
        package: String,
        /// The version of the package to show information for.
        ///
        /// If not specified, the latest version of the package is shown.
        #[arg(long)]
        version: Option<String>,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
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
        Command::List => {
            for package in registry.list() {
                println!("{} {}", package.name, package.version);
            }
        },
        Command::Show { package, version } => {
            let package_id = PackageId::from(package);
            let version = version.map(|version| version.parse::<Version>()).transpose()?;
            if let Some(summary) = registry.show(&package_id, version.as_ref()) {
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
        },
    }

    Ok(())
}
