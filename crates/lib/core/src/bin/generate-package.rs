use std::{env, error::Error, fs, path::PathBuf};

use miden_core_lib::CoreLibrary;

fn main() -> Result<(), Box<dyn Error>> {
    let output_path = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("expected the output path as the first argument");

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output_path, CoreLibrary::SERIALIZED)?;

    println!("wrote miden-core.masp to {}", output_path.display());
    Ok(())
}
