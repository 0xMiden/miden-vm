def stop_when_iter_is_5(frame, breakpoint, internal_dict):
    value = frame.variables().get("iter")
    return value is not None and value.value == 5
