use std::path::PathBuf;

use clap::Parser;
use miden_assembly::{
    Assembler, Linkage, PathBuf as LibraryPath, ast,
    diagnostics::{IntoDiagnostic, Report},
};
use miden_core_lib::CoreLibrary;
use miden_mast_package::Package;

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
    pub fn execute(&self) -> Result<(), Report> {
        println!("============================================================");
        println!("Build library");
        println!("============================================================");

        let mut assembler = Assembler::default();

        if !self.root.is_file() {
            return Err(Report::msg("`root` must be a '.masm' file."));
        }

        // write the masp output
        let output_file = match &self.output {
            Some(output) => output,
            None => {
                let parent =
                    &self.root.parent().ok_or("Invalid output path").map_err(Report::msg)?;
                &parent.join("out").with_extension(Package::EXTENSION)
            },
        };

        if self.kernel {
            assembler.link_package(CoreLibrary::default().package(), Linkage::Dynamic)?;
            let namespace = match self.namespace.as_deref() {
                Some(ns) => ns,
                None => ast::Path::KERNEL_PATH,
            };
            let library = assembler.assemble_kernel_from_root(namespace, &self.root)?;
            library.write_to_file(output_file).into_diagnostic()?;
            println!("Built kernel library {} from {}", library.name, self.root.display());
        } else {
            let library_namespace = match self.namespace.as_ref() {
                Some(ns) => Some(LibraryPath::new(ns).into_diagnostic()?),
                None => None,
            };
            assembler.link_package(CoreLibrary::default().package(), Linkage::Dynamic)?;
            let library =
                assembler.assemble_library_from_root(&self.root, library_namespace.as_deref())?;
            library.write_to_file(output_file).into_diagnostic()?;
            println!("Built package '{}'", library.name);
        }

        Ok(())
    }
}
