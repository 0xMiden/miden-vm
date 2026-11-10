def cycle(debugger, command, exe_ctx, result, internal_dict):
    print(debugger.get_cycle(), file=result)


def __miden_init_module(debugger, internal_dict):
    internal_dict["cycle_example_loaded"] = True
