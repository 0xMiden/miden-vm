
## std::sys::vm::constraints_eval
| Procedure | Description |
| ----------- | ------------- |
| execute_constraint_evaluation_check | Executes the constraints evaluation check by evaluating an arithmetic circuit using the ACE<br />chiplet.<br /><br />The circuit description is hardcoded into the verifier using its commitment, which is computed as<br />the sequential hash of its description using RPO hasher. The circuit description, containing both<br />constants and evaluation gates description, is stored at the contiguous memory region starting<br />at `ACE_CIRCUIT_PTR`. The variable part of the circuit input is stored at the contiguous memory<br />region starting at `pi_ptr`. The (variable) inputs to the circuit are laid out such that the<br />aforementioned memory regions are together contiguous with the (variable) inputs section.<br /><br />Inputs:  []<br />Outputs: []<br /> |
