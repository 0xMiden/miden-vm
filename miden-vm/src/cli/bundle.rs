use std::path::PathBuf;

use clap::Parser;
use miden_assembly::{
    Assembler, Linkage, PathBuf as LibraryPath, ast,
    diagnostics::{IntoDiagnostic, Report},
};
use miden_core_lib::CoreLibrary;
use miden_mast_package::Package;
use miden_vm::diagnostics::{DiagnosticCollector, Outcome};

#[derive(Debug, Clone, Parser)]
#[command(
    name = "Compile Library",
    about = "Bundles .masm files into a single .masp library with access to the core library."
)]
pub struct BundleCmd {
    /// Disable debug symbols (release mode)
    #[arg(short = 'r', long = "release")]
    release: bool,
    /// Path to the root `.masm` file for the library
    #[arg(value_parser)]
    root: PathBuf,
    /// Defines the top-level namespace, e.g. `mylib`, otherwise a `namespace` declaration is
    /// expected in the root module. For a kernel library the namespace defaults to `$kernel`.
    #[arg(short, long)]
    namespace: Option<String>,
    /// Version of the library, defaults to `0.1.0`.
    #[arg(short, long, default_value = "0.1.0")]
    version: String,
    /// Indicates that the artifact produced is a kernel package.
    ///
    /// This requires that `root` be a path to the root module of the kernel.
    #[arg(short, long)]
    kernel: bool,
    /// Path of the output `.masp` file.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

impl BundleCmd {
    pub fn execute(&self) -> Outcome<()> {
        println!("============================================================");
        println!("Build library");
        println!("============================================================");

        let mut assembler = Assembler::new();

        if !self.root.is_file() {
            return Outcome::from_report(Report::msg("`root` must be a '.masm' file."));
        }

        // write the masp output
        let mut collector = DiagnosticCollector::default();
        let output_file = match &self.output {
            Some(output) => output,
            None => {
                let parent = collector
                    .capture(self.root.parent().ok_or("Invalid output path").map_err(Report::msg));
                if let Some(parent) = parent {
                    &parent.join("out").with_extension(Package::EXTENSION)
                } else {
                    return Outcome {
                        result: Err(()),
                        diagnostics: collector.finish(),
                    };
                }
            },
        };

        if self.kernel {
            if collector
                .capture(assembler.link_package(CoreLibrary::default().package(), Linkage::Dynamic))
                .is_none()
            {
                return Outcome {
                    result: Err(()),
                    diagnostics: collector.finish(),
                };
            }
            let namespace = match self.namespace.as_deref() {
                Some(ns) => ns,
                None => ast::Path::KERNEL_PATH,
            };
            assembler.assemble_kernel_from_root(namespace, &self.root).and_then(
                |package, collector| {
                    let result = collector
                        .capture(package.write_to_file(output_file).into_diagnostic())
                        .ok_or(());
                    if result.is_ok() {
                        println!(
                            "Built kernel library {} from {}",
                            package.name,
                            self.root.display()
                        );
                    }
                    result
                },
            )
        } else {
            let library_namespace = match self.namespace.as_ref() {
                Some(ns) => match collector.capture(LibraryPath::new(ns).into_diagnostic()) {
                    Some(path) => Some(path),
                    None => {
                        return Outcome {
                            result: Err(()),
                            diagnostics: collector.finish(),
                        };
                    },
                },
                None => None,
            };
            if collector
                .capture(assembler.link_package(CoreLibrary::default().package(), Linkage::Dynamic))
                .is_none()
            {
                return Outcome {
                    result: Err(()),
                    diagnostics: collector.finish(),
                };
            }
            assembler
                .assemble_library_from_root(&self.root, library_namespace.as_deref())
                .and_then(|package, collector| {
                    let result = collector
                        .capture(package.write_to_file(output_file).into_diagnostic())
                        .ok_or(());
                    if result.is_ok() {
                        println!("Built package '{}'", package.name);
                    }
                    result
                })
        }
    }
}
