// PROGRAM SERIALIZATION AND DESERIALIZATION
// ================================================================================================

use super::*;

#[test]
fn test_program_serde_simple() {
    let source = "
    begin
        push.1.2
        add
        drop
    end
    ";

    let assembler = Assembler::default();
    let original_program = assembler.assemble_program("test", source).unwrap().unwrap_program();

    let mut target = Vec::new();
    original_program.write_into(&mut target);
    let deserialized_program = Program::read_from_bytes(&target).unwrap();

    assert_eq!(original_program, deserialized_program);
}
