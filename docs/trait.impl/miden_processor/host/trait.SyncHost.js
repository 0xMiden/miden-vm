(function() {
    const implementors = Object.fromEntries([["miden_processor",[]],["miden_prover",[]],["miden_vm",[]]]);
    if (window.register_implementors) {
        window.register_implementors(implementors);
    } else {
        window.pending_implementors = implementors;
    }
})()
//{"start":59,"fragment_lengths":[22,20,16]}