fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    #[cfg(feature = "masm")]
    assemble_verifier_programs();
}

#[cfg(feature = "masm")]
fn assemble_verifier_programs() {
    use std::{env, path::PathBuf};

    use miden_assembly::{Assembler, Linkage};
    use miden_core_lib::CoreLibrary;

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo provides OUT_DIR"));
    let assembler = Assembler::default()
        .with_package(CoreLibrary::default().package(), Linkage::Dynamic)
        .expect("link the embedded core library");

    for relation in ["vm", "pvm"] {
        // The input word is the claim commitment used by the relation's advice builder. Preserve
        // it while fetching the request, then retain the verifier's result as the program output.
        let source = format!(
            "use miden::core::sys
             use miden::core::sys::{relation}
             begin
                 dupw procref.{relation}::verify_proof exec.sys::build_proof_request_key
                 adv.push_mapval dropw
                 exec.{relation}::verify_proof
                 exec.sys::truncate_stack
             end"
        );
        assembler
            .clone()
            .assemble_program(relation, source)
            .expect("assemble recursive verification program")
            .unwrap_program()
            .write_to_file(out_dir.join(format!("{relation}.masb")))
            .expect("write recursive verification program");
    }
}
