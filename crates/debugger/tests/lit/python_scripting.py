def __miden_init_module(debugger, internal_dict):
    internal_dict["loaded_cycle"] = debugger.get_cycle()


def cycle(debugger, command, exe_ctx, result, internal_dict):
    print(f"cycle={debugger.get_cycle()} args={command}", file=result)


def never_stop(frame, breakpoint, internal_dict):
    internal_dict["callback_count"] = internal_dict.get("callback_count", 0) + 1
    return False
