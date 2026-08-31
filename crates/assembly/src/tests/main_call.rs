// PROGRAM WITH $main CALL
// ================================================================================================

use super::*;

#[test]
fn simple_main_call() -> TestResult {
    let mut context = TestContext::default();

    // compile account module
    let account_code = context.parse_module(source_file!(
        &context,
        "\
        namespace context::account
        pub proc account_method_1
            push.2.1 add
        end

        pub proc account_method_2
            push.3.1 sub
        end
        "
    ))?;

    context.add_module(account_code)?;

    // compile note 1 program
    context.assemble(source_file!(
        &context,
        "
        use context::account
        begin
          call.account::account_method_1
        end
        "
    ))?;

    // compile note 2 program
    context.assemble(source_file!(
        &context,
        "
        use context::account
        begin
          call.account::account_method_2
        end
        "
    ))?;
    Ok(())
}

#[test]
fn call_without_path() -> TestResult {
    let context = TestContext::default();

    let account_code1_src = source_file!(
        &context,
        "\
namespace account_code1

pub proc account_method_1
    push.2.1 add
end

pub proc account_method_2
    push.3.1 sub
end
"
    );
    let account_code2_src = source_file!(
        &context,
        "\
namespace account_code2

pub proc account_method_1
    push.2.2 add
end

pub proc account_method_2
    push.4.1 sub
end
"
    );

    // compile program in which functions from different modules but with equal names are called
    let main_src = source_file!(
        &context,
        "
        begin
            # call the account_method_1 from the first module (account_code1)
            call.0x81e0b1afdbd431e4c9d4b86599b82c3852ecf507ae318b71c099cdeba0169068

            # call the account_method_2 from the first module (account_code1)
            call.0x1bc375fc794af6637af3f428286bf6ac1a24617640ed29f8bc533f48316c6d75

            # call the account_method_1 from the second module (account_code2)
            call.0xcfadd74886ea075d15826a4f59fb4db3a10cde6e6e953603cba96b4dcbb94321

            # call the account_method_2 from the second module (account_code2)
            call.0x1976bf72d457bd567036d3648b7e3f3c22eca4096936931e59796ec05c0ecb10
        end
        "
    );

    let account_code1 = context.parse_module(account_code1_src)?;
    let account_code2 = context.parse_module(account_code2_src)?;
    let main = context.parse_program(main_src)?;

    let mut assembler = Assembler::new(context.source_manager());
    assembler.compile_and_statically_link_all([account_code1, account_code2])?;
    assembler.assemble_program("main", main)?;

    Ok(())
}
