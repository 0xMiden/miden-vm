fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/prover.proto");
    tonic_prost_build::configure().compile_protos(&["proto/prover.proto"], &["proto"])?;
    Ok(())
}
