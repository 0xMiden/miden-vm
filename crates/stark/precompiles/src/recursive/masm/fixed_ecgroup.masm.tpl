    # EcGroup: {{label}} (group={{group_ptr}}).
    # A={{a_ptr}}, B={{b_ptr}}, base bound={{bound_ptr}}, scalar bound={{scalar_bound_ptr}}, beta={{beta_ptr}}, lambda={{lambda_ptr}}.
    push.{{lambda_ptr}}.{{beta_ptr}}.{{scalar_bound_ptr}}.{{bound_ptr}}.{{b_ptr}}.{{a_ptr}}.{{group_ptr}}
    movup.10 movup.10
    exec.fold_ec_group_payload
    push.EC_GROUP_BUS_SCALE exec.compute_bus_prefix ext2add ext2inv
    movup.5 movup.5 ext2add
