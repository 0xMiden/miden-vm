use miden_assembly::Assembler;
use miden_core_lib::CoreLibrary;
use miden_processor::{DefaultHost, FastProcessor, Felt, Program, StackInputs, Word, ZERO};

pub fn compile(core_lib: &CoreLibrary, source: &str) -> Program {
    Assembler::default()
        .with_static_library(core_lib.library())
        .expect("link core library")
        .assemble_program(source)
        .expect("assemble benchmark program")
}

pub fn processor_inputs(core_lib: &CoreLibrary) -> (DefaultHost, FastProcessor) {
    let mut host = DefaultHost::default();
    host.load_library(core_lib).expect("load core library host data");
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
