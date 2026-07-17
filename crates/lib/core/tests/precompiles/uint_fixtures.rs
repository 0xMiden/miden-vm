use std::marker::PhantomData;

use miden_core::{
    Felt,
    deferred::{DeferredError, PrecompileError, TRUE_DIGEST},
};
use miden_precompiles::UintSpec;
use miden_processor::{ExecutionError, ExecutionOutput};

use super::helpers::{
    TRUNCATE_STACK_TO_OUTPUT_PROC, U32x8, assert_deferred_state_round_trips, assert_memory_u32x8,
    assert_stack_u32x8, expect_precompile_trap, masm_push_u32x8, masm_store_u32x8,
    read_memory_felts, run_precompile_program,
};

const MEM_PTR: u32 = 0;
const OUT_PTR: u32 = 32;

const ZERO: U32x8 = [0, 0, 0, 0, 0, 0, 0, 0];
const ONE: U32x8 = [1, 0, 0, 0, 0, 0, 0, 0];
const TWO: U32x8 = [2, 0, 0, 0, 0, 0, 0, 0];
const MAX: U32x8 = [u32::MAX; 8];

fn assert_invalid_payload_error(error: ExecutionError) {
    let ExecutionError::DeferredError { err, .. } = error else {
        panic!("expected deferred invalid-payload error, got {error:?}");
    };
    assert!(
        matches!(err.root(), PrecompileError::Other(DeferredError::InvalidPayload)),
        "expected invalid payload, got {err:?}",
    );
}

#[derive(Clone, Copy)]
struct BinaryCase {
    proc_name: &'static str,
    lhs: U32x8,
    rhs: U32x8,
    expected: U32x8,
}

const PRIME_FIELD_BINARY_CASES: &[BinaryCase] = &[
    BinaryCase {
        proc_name: "add",
        lhs: ONE,
        rhs: ONE,
        expected: TWO,
    },
    BinaryCase {
        proc_name: "sub",
        lhs: TWO,
        rhs: ONE,
        expected: ONE,
    },
    BinaryCase {
        proc_name: "mul",
        lhs: TWO,
        rhs: TWO,
        expected: [4, 0, 0, 0, 0, 0, 0, 0],
    },
];

const U256_BINARY_CASES: &[BinaryCase] = &[
    BinaryCase {
        proc_name: "add",
        lhs: [u32::MAX, 0, 0, 0, 0, 0, 0, 0],
        rhs: ONE,
        expected: [0, 1, 0, 0, 0, 0, 0, 0],
    },
    BinaryCase {
        proc_name: "sub",
        lhs: [0, 1, 0, 0, 0, 0, 0, 0],
        rhs: ONE,
        expected: [u32::MAX, 0, 0, 0, 0, 0, 0, 0],
    },
    BinaryCase {
        proc_name: "mul",
        lhs: [u32::MAX, 0, 0, 0, 0, 0, 0, 0],
        rhs: TWO,
        expected: [u32::MAX - 1, 1, 0, 0, 0, 0, 0, 0],
    },
    BinaryCase {
        proc_name: "add",
        lhs: MAX,
        rhs: ONE,
        expected: ZERO,
    },
    BinaryCase {
        proc_name: "sub",
        lhs: ZERO,
        rhs: ONE,
        expected: MAX,
    },
    BinaryCase {
        proc_name: "mul",
        lhs: MAX,
        rhs: TWO,
        expected: [
            u32::MAX - 1,
            u32::MAX,
            u32::MAX,
            u32::MAX,
            u32::MAX,
            u32::MAX,
            u32::MAX,
            u32::MAX,
        ],
    },
];

pub struct UintModule<M: UintSpec> {
    module: &'static str,
    _marker: PhantomData<M>,
}

impl<M: UintSpec> UintModule<M> {
    pub const fn new(module: &'static str) -> Self {
        Self { module, _marker: PhantomData }
    }

    pub fn assert_u256_contract(&self, masm_source: &str) {
        assert!(!M::IS_PRIME_FIELD, "{} must not be a prime-field modulus", self.module);

        self.assert_common_uint_contract(U256_BINARY_CASES);
        self.assert_u256_specific_contract(masm_source);
    }

    pub fn assert_prime_field_contract(&self) {
        assert!(M::IS_PRIME_FIELD, "{} must be a prime-field modulus", self.module);

        self.assert_common_uint_contract(PRIME_FIELD_BINARY_CASES);
        self.assert_prime_field_specific_contract();
    }

    fn assert_common_uint_contract(&self, binary_cases: &[BinaryCase]) {
        self.assert_load_eval_and_memory([1, 2, 3, 4, 5, 6, 7, 8], [0, 1, 0, 2, 0, 3, 0, 4]);
        self.assert_open_value([7, 6, 5, 4, 3, 2, 1, 0]);
        self.expect_open_expression_digest_trap();
        self.assert_load_mem_stream_advances_pointer([8, 7, 6, 5, 4, 3, 2, 1]);
        self.assert_common_constants_eval();
        self.assert_binary_cases(binary_cases);
        self.assert_common_predicates();
        self.expect_assert_eq_inequality_trap();
        self.expect_non_u32_limb_trap();
    }

    fn assert_load_eval_and_memory(&self, stack_value: U32x8, memory_value: U32x8) {
        let source = format!(
            "
            {TRUNCATE_STACK_TO_OUTPUT_PROC}

            use {module_use_path}
            begin
                {stores}
                push.{MEM_PTR}
                exec.{module}::load_mem
                exec.{module}::eval

                {push_value}
                exec.{module}::load
                exec.{module}::eval
                push.{OUT_PTR} mem_storew_le dropw
                push.{out_hi} mem_storew_le dropw

                exec.truncate_stack_to_output
            end
            ",
            module = self.module,
            module_use_path = self.module_use_path(),
            stores = masm_store_u32x8(stack_value, MEM_PTR),
            push_value = masm_push_u32x8(memory_value),
            out_hi = OUT_PTR + 4,
        );

        let output = run_precompile_program(&source).expect("load/eval roundtrip must succeed");
        assert_stack_u32x8(&output, stack_value);
        assert_memory_u32x8(&output, OUT_PTR, memory_value);
        assert_deferred_state_round_trips(&output);
    }

    fn assert_open_value(&self, expected: U32x8) {
        let proof_bound_value = format!(
            "
            {value}
            exec.{module}::load
            dupw dupw
            exec.{module}::assert_eq
            ",
            module = self.module,
            value = masm_push_u32x8(expected),
        );

        let baseline =
            self.run(&format!("{proof_bound_value}\ndropw"), "proof-bound VALUE baseline");
        let opened = self.run_stack(
            &format!("{proof_bound_value}\nexec.{}::open_value", self.module),
            expected,
            "open_value",
        );

        assert_ne!(
            baseline.deferred_state.root(),
            TRUE_DIGEST,
            "open_value test input must be proof-bound by a nonempty deferred root",
        );
        assert_eq!(
            opened.deferred_state.root(),
            baseline.deferred_state.root(),
            "open_value must not advance the deferred root",
        );
        assert_eq!(
            opened.deferred_state.to_wire().expect("opened wire must encode"),
            baseline.deferred_state.to_wire().expect("baseline wire must encode"),
            "open_value must not add deferred wire entries",
        );
    }

    fn expect_open_expression_digest_trap(&self) {
        self.expect_trap(
            "exec.{module}::push_one_digest\nexec.{module}::push_two_digest\nexec.{module}::add\nexec.{module}::open_value",
        );
    }

    fn assert_load_mem_stream_advances_pointer(&self, expected: U32x8) {
        let body = format!(
            "
            {stores}
            push.{MEM_PTR}
            exec.{module}::load_mem_stream
            movup.4 push.{OUT_PTR} mem_store
            exec.{module}::eval
            ",
            module = self.module,
            stores = masm_store_u32x8(expected, MEM_PTR),
        );

        let output = self.run_stack(&body, expected, "load_mem_stream");
        assert_eq!(
            read_memory_felts(&output, OUT_PTR, 1)[0],
            Felt::from_u32(MEM_PTR + 8),
            "load_mem_stream must advance the pointer by 8"
        );
    }

    fn assert_common_constants_eval(&self) {
        for (proc_name, expected) in
            [("push_zero_digest", ZERO), ("push_one_digest", ONE), ("push_two_digest", TWO)]
        {
            self.assert_constant_eval(proc_name, expected);
        }

        for (proc_name, expected) in
            [("push_zero_value", ZERO), ("push_one_value", ONE), ("push_two_value", TWO)]
        {
            self.assert_raw_constant_eval(proc_name, expected);
        }
    }

    fn assert_constant_eval(&self, proc_name: &str, expected: U32x8) {
        self.run_stack(
            &format!("exec.{}::{proc_name}\nexec.{}::eval", self.module, self.module),
            expected,
            proc_name,
        );
    }

    fn assert_raw_constant_eval(&self, proc_name: &str, expected: U32x8) {
        self.run_stack(
            &format!(
                "exec.{}::{proc_name}\nexec.{}::load\nexec.{}::eval",
                self.module, self.module, self.module
            ),
            expected,
            proc_name,
        );
    }

    fn assert_binary_cases(&self, binary_cases: &[BinaryCase]) {
        for case in binary_cases {
            self.assert_binary_case_assert_eq(case);
            self.assert_binary_case_eval(case);
        }
    }

    fn assert_binary_case_assert_eq(&self, case: &BinaryCase) {
        let body = format!(
            "
            {rhs}
            exec.{module}::load
            {lhs}
            exec.{module}::load
            exec.{module}::{proc_name}
            {expected}
            exec.{module}::load
            exec.{module}::assert_eq
            ",
            module = self.module,
            proc_name = case.proc_name,
            lhs = masm_push_u32x8(case.lhs),
            rhs = masm_push_u32x8(case.rhs),
            expected = masm_push_u32x8(case.expected),
        );

        self.run(&body, &format!("{} assert_eq binary case", case.proc_name));
    }

    fn assert_binary_case_eval(&self, case: &BinaryCase) {
        let body = format!(
            "
            {rhs}
            exec.{module}::load
            {lhs}
            exec.{module}::load
            exec.{module}::{proc_name}
            exec.{module}::eval
            ",
            module = self.module,
            proc_name = case.proc_name,
            lhs = masm_push_u32x8(case.lhs),
            rhs = masm_push_u32x8(case.rhs),
        );

        self.run_stack(&body, case.expected, &format!("{} eval binary case", case.proc_name));
    }

    fn assert_common_predicates(&self) {
        let body = format!(
            "
            exec.{module}::push_one_digest
            exec.{module}::push_one_digest
            exec.{module}::is_eq
            assert

            exec.{module}::push_one_digest
            exec.{module}::push_two_digest
            exec.{module}::is_eq
            assertz

            exec.{module}::push_one_digest
            exec.{module}::push_one_digest
            exec.{module}::is_eq_digest
            assert

            exec.{module}::push_one_digest
            exec.{module}::push_two_digest
            exec.{module}::is_eq_digest
            assertz

            exec.{module}::push_one_digest
            exec.{module}::push_one_digest
            exec.{module}::sub
            exec.{module}::is_zero
            assert

            exec.{module}::push_zero_digest
            exec.{module}::push_one_digest
            exec.{module}::add
            exec.{module}::is_one
            assert

            exec.{module}::push_one_digest
            exec.{module}::is_zero
            assertz
            ",
            module = self.module,
        );

        self.run(&body, "common predicates");
    }

    fn expect_assert_eq_inequality_trap(&self) {
        self.expect_trap(
            "exec.{module}::push_one_digest\nexec.{module}::push_zero_digest\nexec.{module}::assert_eq",
        );
    }

    fn expect_non_u32_limb_trap(&self) {
        self.expect_invalid_payload_registration_trap(
            "push.0.0.0.0.0.0.0.4294967296\nexec.{module}::load",
        );
    }

    fn assert_prime_field_specific_contract(&self) {
        self.assert_prime_field_identities();
        self.expect_inv_zero_trap();
        self.expect_div_zero_trap();
        self.expect_modulus_as_noncanonical_value_trap();
    }

    fn assert_prime_field_identities(&self) {
        let body = format!(
            "
            exec.{module}::push_two_digest
            exec.{module}::inv
            exec.{module}::push_two_digest
            exec.{module}::mul
            exec.{module}::push_one_digest
            exec.{module}::assert_eq

            exec.{module}::push_two_digest
            exec.{module}::push_one_digest
            exec.{module}::div
            exec.{module}::push_two_digest
            exec.{module}::mul
            exec.{module}::push_one_digest
            exec.{module}::assert_eq

            exec.{module}::push_one_digest
            exec.{module}::push_minus_one_digest
            exec.{module}::add
            exec.{module}::push_zero_digest
            exec.{module}::assert_eq

            exec.{module}::push_minus_one_value
            exec.{module}::load
            exec.{module}::push_minus_one_digest
            exec.{module}::mul
            exec.{module}::push_one_digest
            exec.{module}::assert_eq

            exec.{module}::push_half_digest
            exec.{module}::push_half_digest
            exec.{module}::add
            exec.{module}::push_one_digest
            exec.{module}::assert_eq

            exec.{module}::push_half_value
            exec.{module}::load
            exec.{module}::push_two_digest
            exec.{module}::mul
            exec.{module}::push_one_digest
            exec.{module}::assert_eq

            {minus_one}
            exec.{module}::load
            exec.{module}::push_one_digest
            exec.{module}::add
            exec.{module}::push_zero_digest
            exec.{module}::assert_eq
            ",
            module = self.module,
            minus_one = masm_push_u32x8(M::minus_one()),
        );

        self.run(&body, "prime-field identities");
    }

    fn expect_inv_zero_trap(&self) {
        self.expect_trap(
            "exec.{module}::push_zero_digest\nexec.{module}::inv\nexec.{module}::eval",
        );
    }

    fn expect_div_zero_trap(&self) {
        self.expect_trap(
            "exec.{module}::push_zero_digest\nexec.{module}::push_one_digest\nexec.{module}::div\nexec.{module}::eval",
        );
    }

    fn expect_modulus_as_noncanonical_value_trap(&self) {
        self.expect_invalid_payload_registration_trap(&format!(
            "{}\npush.{MEM_PTR}\nexec.{{module}}::load_mem",
            masm_store_u32x8(M::ENCODED_MODULUS, MEM_PTR),
        ));
    }

    fn assert_u256_specific_contract(&self, masm_source: &str) {
        self.assert_u256_masm_does_not_export_field_ops(masm_source);
        self.assert_constant_eval("push_max_digest", MAX);
        self.assert_raw_constant_eval("push_max_value", MAX);
    }

    fn assert_u256_masm_does_not_export_field_ops(&self, masm_source: &str) {
        for proc_name in ["inv", "div"] {
            let exported_proc = format!("pub proc {proc_name}");
            assert!(
                !masm_source.lines().any(|line| line.trim() == exported_proc),
                "{} must not export field-only procedure `{proc_name}`",
                self.module
            );
        }
    }

    fn run(&self, body: &str, label: &str) -> ExecutionOutput {
        let source = self.program(body);
        let output = run_precompile_program(&source).unwrap_or_else(|err| {
            panic!("{} {label} must succeed: {err:?}", self.module);
        });
        assert_deferred_state_round_trips(&output);
        output
    }

    fn run_stack(&self, body: &str, expected: U32x8, label: &str) -> ExecutionOutput {
        let source = format!(
            "
            {TRUNCATE_STACK_TO_OUTPUT_PROC}

            use {module_use_path}
            begin
                {body}
                exec.truncate_stack_to_output
            end
            ",
            module_use_path = self.module_use_path(),
        );
        let output = run_precompile_program(&source).unwrap_or_else(|err| {
            panic!("{} {label} must succeed: {err:?}", self.module);
        });
        assert_stack_u32x8(&output, expected);
        assert_deferred_state_round_trips(&output);
        output
    }

    fn expect_trap(&self, body: &str) {
        let body = body.replace("{module}", self.module);
        expect_precompile_trap(&self.program(&body));
    }

    fn expect_invalid_payload_registration_trap(&self, body: &str) {
        let body = body.replace("{module}", self.module);
        let error = expect_precompile_trap(&self.program(&body));
        assert_invalid_payload_error(error);
    }

    fn program(&self, body: &str) -> String {
        format!(
            "
            use {module_use_path}
            begin
                {body}
            end
            ",
            module_use_path = self.module_use_path(),
        )
    }

    fn module_use_path(&self) -> String {
        if M::IS_PRIME_FIELD {
            format!("miden::precompiles::fields::{}", self.module)
        } else {
            format!("miden::precompiles::{}", self.module)
        }
    }
}

pub fn assert_u256_contract<M: UintSpec>(module: &'static str, masm_source: &str) {
    UintModule::<M>::new(module).assert_u256_contract(masm_source);
}

pub fn assert_prime_field_contract<M: UintSpec>(module: &'static str) {
    UintModule::<M>::new(module).assert_prime_field_contract();
}

pub fn assert_cross_modulus_children_rejected(lhs: &'static str, rhs: &'static str) {
    assert_ne!(lhs, rhs, "cross-modulus rejection requires two distinct modules");

    let source = format!(
        "
        use miden::precompiles::fields::{lhs}
        use miden::precompiles::fields::{rhs}
        begin
            exec.{rhs}::push_one_digest
            exec.{lhs}::push_one_digest
            exec.{lhs}::add
        end
        "
    );

    let error = expect_precompile_trap(&source);
    assert_invalid_payload_error(error);
}

pub fn assert_cross_modulus_open_rejected(expected: &'static str, actual: &'static str) {
    assert_ne!(expected, actual, "cross-modulus opening requires two distinct modules");

    let source = format!(
        "
        use miden::precompiles::fields::{expected}
        use miden::precompiles::fields::{actual}
        begin
            exec.{actual}::push_one_digest
            exec.{expected}::open_value
        end
        "
    );

    expect_precompile_trap(&source);
}
