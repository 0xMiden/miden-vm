use std::{env, error::Error, fs, path::PathBuf};

use miden_core_lib::CoreLibrary;

fn main() -> Result<(), Box<dyn Error>> {
    let output_path = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("expected the output path as the first argument");

    let output_dir = output_path.parent().expect("output path must have a parent directory");
    fs::create_dir_all(output_dir)?;
    fs::write(&output_path, CoreLibrary::SERIALIZED)?;
    let precompiles_output_path = output_dir.join("miden-precompiles.masp");
    fs::write(&precompiles_output_path, CoreLibrary::PRECOMPILES_SERIALIZED)?;

    println!("wrote miden-core.masp to {}", output_path.display());
    println!("wrote miden-precompiles.masp to {}", precompiles_output_path.display());
    Ok(())
}
