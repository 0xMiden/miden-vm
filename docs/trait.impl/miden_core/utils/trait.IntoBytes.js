(function() {
    const implementors = Object.fromEntries([["miden_assembly",[]],["miden_core",[]],["miden_processor",[]],["miden_prover",[]],["miden_test_utils",[]],["miden_vm",[]]]);
    if (window.register_implementors) {
        window.register_implementors(implementors);
    } else {
        window.pending_implementors = implementors;
    }
})()
//{"start":59,"fragment_lengths":[21,18,23,20,24,16]}