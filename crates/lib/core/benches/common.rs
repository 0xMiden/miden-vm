use miden_assembly::{Assembler, Linkage};
use miden_core_lib::CoreLibrary;
use miden_processor::{DefaultHost, FastProcessor, Felt, Program, StackInputs, Word, ZERO};

pub fn compile(core_lib: &CoreLibrary, source: &str) -> Program {
    Assembler::default()
        .with_package(core_lib.package(), Linkage::Dynamic)
        .expect("link core library")
        .assemble_program("benchmark", source)
        .expect("assemble benchmark program")
        .unwrap_program()
}

pub fn processor_inputs(core_lib: &CoreLibrary) -> (DefaultHost, FastProcessor) {
    let host = DefaultHost::default()
        .with_library(core_lib)
        .expect("load core library host data");
    (host, FastProcessor::new(StackInputs::default()))
}

pub fn push_word(word: Word) -> String {
    let [a, b, c, d]: [Felt; 4] = word.into();
    format!(
        "push.{}.{}.{}.{}",
        d.as_canonical_u64(),
        c.as_canonical_u64(),
        b.as_canonical_u64(),
        a.as_canonical_u64(),
    )
}

pub fn word_from_u64(value: u64) -> Word {
    [ZERO, ZERO, ZERO, Felt::new_unchecked(value)].into()
}
