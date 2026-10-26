use miden::core::stark::types
use miden::core::sys::pvm::layout
use {UINT_VAL_BUS_SCALE, EC_GROUP_BUS_SCALE} from miden::core::sys::pvm::parameters

#! An address in the PVM fixed environment, carried as a 32-bit bus-message value.
type EnvironmentPtr = u32

#! Fixed-environment unsigned integer and its domain-bound pointer.
type UintValPayload = struct {
    ptr: EnvironmentPtr,
    bound_ptr: EnvironmentPtr,
    value: u256,
}

#! Fixed elliptic-curve group parameters, represented by their environment pointers.
type EcGroupPayload = struct {
    group: EnvironmentPtr,
    a: EnvironmentPtr,
    b: EnvironmentPtr,
    bound: EnvironmentPtr,
    scalar_bound: EnvironmentPtr,
    beta: EnvironmentPtr,
    lambda: EnvironmentPtr,
}

#! Computes gamma = beta^18 for the PVM fixed-message domain prefix.
#!
#! Four squarings produce beta^16; the retained beta^2 supplies the remaining factor. The result
#! is stored as `[gamma0, gamma1, 0, 0]`.
#!
#! Input:  [...]
#! Output: [...]
proc compute_bus_gamma()
    exec.load_beta
    dup.1 dup.1 ext2mul   # beta^2
    dup.1 dup.1           # retain beta^2
    dup.1 dup.1 ext2mul   # beta^4, beta^2
    dup.1 dup.1 ext2mul   # beta^8
    dup.1 dup.1 ext2mul   # beta^16
    ext2mul                # beta^18
    push.0.0 movup.3 movup.3
    exec.layout::bus_gamma_ptr mem_storew_le
    dropw
end

#! Loads beta from `[beta0, beta1, alpha0, alpha1]`.
#!
#! Input:  [...]
#! Output: [beta0, beta1, ...]
proc load_beta() -> types::QuadFelt
    exec.layout::aux_rand_elem_ptr add.1 mem_load
    exec.layout::aux_rand_elem_ptr mem_load
end

#! Loads alpha from `[beta0, beta1, alpha0, alpha1]`.
#!
#! Input:  [...]
#! Output: [alpha0, alpha1, ...]
proc load_alpha() -> types::QuadFelt
    exec.layout::aux_rand_elem_ptr add.3 mem_load
    exec.layout::aux_rand_elem_ptr add.2 mem_load
end

#! Loads gamma from its relation-local scratch word.
#!
#! Input:  [...]
#! Output: [gamma0, gamma1, ...]
proc load_gamma() -> types::QuadFelt
    exec.layout::bus_gamma_ptr add.1 mem_load
    exec.layout::bus_gamma_ptr mem_load
end

#! Horner-folds a UintVal payload `(ptr, bound_ptr, c0, ..., c7)`.
#!
#! Keeps beta below the accumulator so all nine multiplications reuse the same stack copy.
#!
#! Input:  [beta0, beta1, m0, ..., m9, ...]
#! Output: [msg0, msg1, beta0, beta1, ...]
proc fold_uint_val_payload(
    beta: types::QuadFelt,
    payload: UintValPayload,
) -> (types::QuadFelt, types::QuadFelt)
    movup.11 push.0 swap
    dup.3 dup.3 ext2mul movup.12 add
    dup.3 dup.3 ext2mul movup.11 add
    dup.3 dup.3 ext2mul movup.10 add
    dup.3 dup.3 ext2mul movup.9 add
    dup.3 dup.3 ext2mul movup.8 add
    dup.3 dup.3 ext2mul movup.7 add
    dup.3 dup.3 ext2mul movup.6 add
    dup.3 dup.3 ext2mul movup.5 add
    dup.3 dup.3 ext2mul movup.4 add
end

#! Horner-folds an EcGroup payload
#! `(group_ptr, a_ptr, b_ptr, bound_ptr, scalar_bound_ptr, beta_ptr, lambda_ptr)`.
#!
#! Keeps beta below the accumulator so all six multiplications reuse the same stack copy.
#!
#! Input:  [beta0, beta1, m0, ..., m6, ...]
#! Output: [msg0, msg1, beta0, beta1, ...]
proc fold_ec_group_payload(
    beta: types::QuadFelt,
    payload: EcGroupPayload,
) -> (types::QuadFelt, types::QuadFelt)
    movup.8 push.0 swap
    dup.3 dup.3 ext2mul movup.9 add
    dup.3 dup.3 ext2mul movup.8 add
    dup.3 dup.3 ext2mul movup.7 add
    dup.3 dup.3 ext2mul movup.6 add
    dup.3 dup.3 ext2mul movup.5 add
    dup.3 dup.3 ext2mul movup.4 add
end

#! Computes the domain prefix `alpha + i*gamma`.
#!
#! Input:  [i, ...]
#! Output: [prefix0, prefix1, ...]
proc compute_bus_prefix(bus_id_plus_one: u8) -> types::QuadFelt
    exec.load_gamma
    # => [gamma0, gamma1, i, ...]
    dup.2 mul
    # => [i*gamma0, gamma1, i, ...]
    movup.2 movup.2 mul swap
    # => [i*gamma0, i*gamma1, ...]
    exec.load_alpha
    ext2add
end

#! Adds a cached bus prefix to a message, inverts the result, and adds it to the running sum.
#!
#! Input:  [msg0, msg1, beta0, beta1, sum0, sum1, prefix0, prefix1, ...]
#! Output: [sum0, sum1, beta0, beta1, prefix0, prefix1, ...]
proc add_cached_prefix_inverse_to_sum(
    message: types::QuadFelt,
    beta: types::QuadFelt,
    sum: types::QuadFelt,
    prefix: types::QuadFelt,
) -> (types::QuadFelt, types::QuadFelt, types::QuadFelt)
    dup.7 dup.7
    ext2add ext2inv
    movup.5 movup.5 ext2add
end

#! Sums the inverses of the compressed fixed-environment UintVal and EcGroup bus messages.
#!
#! Reads beta and alpha from the relation's auxiliary-randomness region, stores beta^18 in
#! BUS_GAMMA_PTR, and stores the sum in C_TOTAL_PTR. All caller stack elements are preserved.
#! Fails if an encoded message denominator is zero.
#!
#! Input:  [...]
#! Output: [...]
pub proc compute_fixed_boundary_correction()
    exec.compute_bus_gamma
    exec.load_beta
    push.0.0
    push.UINT_VAL_BUS_SCALE exec.compute_bus_prefix
    movdn.5 movdn.5
    # => [sum0, sum1, beta0, beta1, uint_prefix0, uint_prefix1, ...]
    # Each literal push covers beta with the payload. Lift beta back above the payload for the
    # fold; the running sum and cached prefix stay beneath it.

{{uintval_messages}}

    # Discard the cached UintVal prefix; the EcGroup messages use a different one.
    movup.5 drop movup.4 drop

{{ecgroup_messages}}

    exec.layout::c_total_ptr mem_store
    exec.layout::c_total_ptr add.1 mem_store
    drop drop
end
