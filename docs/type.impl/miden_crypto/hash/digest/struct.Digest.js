(function() {
    var type_impls = Object.fromEntries([["miden_assembly",[]],["miden_core",[]],["miden_processor",[]],["miden_prover",[]],["miden_vm",[]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[21,18,23,20,16]}