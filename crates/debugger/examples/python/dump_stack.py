def dump_stack(debugger, command, exe_ctx, result, internal_dict):
    stack = exe_ctx.process().stack()
    for index, value in enumerate(stack):
        print(f"{index:02}: {value}", file=result)
