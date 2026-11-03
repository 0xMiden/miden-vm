fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/prover.proto");
    tonic_prost_build::configure()
        .build_server(cfg!(feature = "server"))
        .compile_protos(&["proto/prover.proto"], &["proto"])?;
    Ok(())
}
