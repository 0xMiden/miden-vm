//! The recursive estimator must retain the complete proven decoding bounds.

use miden_air::vm::{config, security::COMMITMENT_ALIGNMENT};
use miden_core::proof::HashFunction;
use miden_vm_stark::security;

fn vm_parameters(height: u32) -> security::ProofSecurityParameters {
    security::proof_security_parameters(
        &config::pcs_params(),
        height,
        0,
        COMMITMENT_ALIGNMENT,
        HashFunction::Eidos,
    )
}

fn descriptor(parameters: &security::ProofSecurityParameters) -> [u64; 12] {
    let protocol = &parameters.protocol_params;
    let air = &parameters.air_shape;
    let lookup = air.lookup.unwrap();
    [
        protocol.lookup_pow_bits.into(),
        air.num_composed_constraints.into(),
        air.max_constraint_degree.into(),
        air.num_deep_terms.unwrap().into(),
        lookup.max_message_width.into(),
        parameters.num_lookup_boundary_terms.into(),
        lookup.fractions_per_row.into(),
        parameters.instance_shape.log_max_height.into(),
        protocol.num_queries.into(),
        protocol.query_pow_bits.into(),
        protocol.deep_pow_bits.into(),
        protocol.folding_pow_bits.into(),
    ]
}

fn run_estimator(parameters: &security::ProofSecurityParameters) -> u64 {
    let source = "
        use miden::core::stark::security
        begin
            exec.security::compute_proven_security_level
        end
    ";
    let (output, _) = build_test!(source, &descriptor(parameters))
        .execute_for_output()
        .expect("proven estimator execution failed");
    output.stack.get_num_elements(1)[0].as_canonical_u64()
}

/// The deployed preset is list-decoding limited. Reusing the conjectured estimator or selecting
/// only unique decoding would respectively overstate or lose this 57-bit bound.
#[test]
fn deployed_preset_selects_the_complete_list_decoding_bound() {
    let parameters = vm_parameters(20);
    assert_eq!(parameters.proven_security_level(), 57);
    assert_eq!(run_estimator(&parameters), 57);
}

fn pvm_parameters(height: u32) -> security::ProofSecurityParameters {
    miden_precompiles_stark::setup::security::proof_security_parameters(
        &miden_air::precompiles::policy::precompile_pcs_params(),
        height,
        COMMITMENT_ALIGNMENT,
        HashFunction::Eidos,
    )
}

/// Batch calls into one execution so the matrix checks arithmetic and search boundaries without
/// recompiling a separate VM program at every cell. Every descriptor comes from a native builder.
fn run_estimators(parameters: &[security::ProofSecurityParameters]) -> Vec<u64> {
    // Limit each program to stay within the assembler's block size. Collect every cycle count
    // before checking the budget so a regression reports the worst case, not the first one.
    let results: Vec<_> = parameters.chunks(256).flat_map(run_estimator_batch).collect();
    let (index, &(_, peak)) = results
        .iter()
        .enumerate()
        .max_by_key(|(_, (_, cycles))| cycles)
        .expect("the matrix must contain cases");
    println!("proven estimator peak: {peak} cycles for {:?}", parameters[index]);
    assert!(peak < 2_250, "estimation took {peak} cycles: {:?}", parameters[index]);
    results.into_iter().map(|(level, _)| level).collect()
}

fn run_estimator_batch(parameters: &[security::ProofSecurityParameters]) -> Vec<(u64, u64)> {
    use std::fmt::Write;

    use miden_core::Felt;
    use miden_processor::ContextId;

    let mut source = String::from("use miden::core::stark::security\nbegin\n");
    for (index, parameters) in parameters.iter().enumerate() {
        for value in descriptor(parameters).into_iter().rev() {
            writeln!(source, "push.{value}").unwrap();
        }
        let address = 3 * index;
        writeln!(source, "clk mem_store.{}", address + 1).unwrap();
        writeln!(source, "exec.security::compute_proven_security_level mem_store.{address}")
            .unwrap();
        writeln!(source, "clk mem_store.{}", address + 2).unwrap();
    }
    source.push_str("end");
    let (output, _) = build_test!(source.as_str(), &[])
        .execute_for_output()
        .expect("proven estimator matrix execution failed");
    (0..parameters.len())
        .map(|index| {
            let read = |address| {
                output
                    .memory
                    .read_element(ContextId::root(), Felt::from_u32(address))
                    .expect("each matrix result and cycle count was stored")
                    .as_canonical_u64()
            };
            let address = 3 * index as u32;
            let cycles = read(address + 2) - read(address + 1);
            (read(address), cycles)
        })
        .collect()
}

/// Independent reference: exact coefficients rounded to Q16, enumerating every permissible m.
/// It shares none of the MASM's logarithm approximation, query bound, or search.
fn exhaustive_level(parameters: &security::ProofSecurityParameters) -> u64 {
    const ONE: i64 = 1 << 16;
    let upper_log = |value: f64| (value.log2() * ONE as f64).ceil() as i64;
    let protocol = &parameters.protocol_params;
    let air = &parameters.air_shape;
    let h = parameters.instance_shape.log_max_height;
    let height = (1u64 << h) as f64;
    let n = air.num_deep_terms.unwrap();
    let cap = i64::from(parameters.conjectured_security_level()) * ONE;
    let batch_pow = i64::from(protocol.deep_pow_bits) * ONE;
    let fold_pow = i64::from(protocol.folding_pow_bits) * ONE;
    let query_pow = i64::from(protocol.query_pow_bits) * ONE;
    let queries = i64::from(protocol.num_queries);
    // The descriptor has no quotient-chunk count; the recursive estimator allows all eight.
    let degree = f64::from(air.max_constraint_degree.max(1));
    let factor = (degree * (height + 1.0) + height - 1.0).max(9.0 * height + 1.0);
    let base =
        125 * ONE - upper_log(f64::from(air.num_composed_constraints)).max(upper_log(factor));
    // List decoding charges the lookup round's Q16 bound its list size, as it does `base`.
    let lookup = parameters
        .conjectured_security_report()
        .terms()
        .iter()
        .find(|term| term.label == p3_security::budget::report::LOOKUP_LABEL)
        .map(|term| term.bits as i64)
        .unwrap();
    let mut best = queries
        * ((f64::from(h) + 4.0) * ONE as f64 - (9.0 * height + 2.0).log2() * ONE as f64).floor()
            as i64
        + query_pow;
    if n > 1 {
        best =
            best.min(125 * ONE + batch_pow - i64::from(h + 3) * ONE - upper_log(f64::from(n - 1)));
    }
    best = best.min(cap);
    for m in 3..=1000.min((1usize << h) / 2) {
        let u = (2 * m + 1) as f64;
        let list = upper_log(u) + ONE / 2;
        let d = ((2.0 * f64::from(h) + 6.0 + 3.0 * u.log2() - (height - 1.0).log2()) * ONE as f64)
            .ceil() as i64;
        let rate = ((1.5 - (1.0 + 1.0 / (2 * m) as f64).log2()) * ONE as f64).floor() as i64;
        let mut candidate = (queries * rate + query_pow).min(base.min(lookup) - list).min(cap);
        if n > 1 {
            candidate = candidate.min(
                125 * ONE + batch_pow + (3.0f64.log2() * ONE as f64).floor() as i64
                    - upper_log(f64::from(n - 1))
                    - d,
            );
        }
        if h > 7 {
            candidate = candidate.min(125 * ONE + fold_pow - d);
        }
        best = best.max(candidate);
    }
    (best / ONE) as u64
}

/// Covers no, partial, and full folding (h=6/7, 8, 16), every fixed LDR endpoint (h=6..=11),
/// and the largest domain (h=29) across all query counts and grinding extremes. Each result must
/// be conservative and within one bit of native.
#[test]
fn deployed_shapes_are_conservative_and_track_exhaustive_search() {
    let mut cases = Vec::new();
    for base in [
        vm_parameters(6),
        vm_parameters(7),
        vm_parameters(8),
        vm_parameters(9),
        vm_parameters(10),
        vm_parameters(11),
        vm_parameters(16),
        vm_parameters(20),
        vm_parameters(29),
        pvm_parameters(16),
        pvm_parameters(20),
        pvm_parameters(29),
    ] {
        for queries in 0..=150 {
            for (query_pow, deep_pow, folding_pow) in
                [(0, 0, 0), (31, 0, 0), (0, 31, 0), (0, 0, 31), (31, 31, 31), (17, 12, 4)]
            {
                let mut parameters = base;
                parameters.protocol_params.num_queries = queries;
                parameters.protocol_params.query_pow_bits = query_pow;
                parameters.protocol_params.deep_pow_bits = deep_pow;
                parameters.protocol_params.folding_pow_bits = folding_pow;
                cases.push(parameters);
            }
        }
    }
    for (parameters, actual) in cases.iter().zip(run_estimators(&cases)) {
        let native = u64::from(parameters.proven_security_level());
        let exhaustive = exhaustive_level(parameters);
        assert!(actual <= native, "overstated native {native}: actual {actual}, {parameters:?}");
        assert!(native - actual <= 1, "lost native {native}: actual {actual}, {parameters:?}");
        assert!(
            actual <= exhaustive,
            "overstated exhaustive {exhaustive}: {actual}, {parameters:?}"
        );
        assert!(
            exhaustive - actual <= 1,
            "missed exhaustive {exhaustive}: {actual}, {parameters:?}"
        );
    }
}

/// n=1 removes the batching challenge, while low-degree descriptors can lose additional bits
/// because the descriptor omits the quotient-chunk count. Conservatism still applies there.
#[test]
fn envelope_without_batching_remains_conservative() {
    let mut cases = Vec::new();
    for h in [6, 7, 8, 29] {
        for degree in [0, 1, 7, 8, 9] {
            let mut parameters = vm_parameters(h);
            parameters.air_shape.num_composed_constraints = 1;
            parameters.air_shape.max_constraint_degree = degree;
            parameters.air_shape.num_quotient_chunks =
                degree.saturating_sub(1).max(1).next_power_of_two();
            parameters.air_shape.num_deep_terms = Some(1);
            parameters.air_shape.lookup = Some(security::LookupShape {
                fractions_per_row: 1,
                max_message_width: 255,
            });
            parameters.num_lookup_boundary_terms = 0;
            parameters.protocol_params.num_queries = 67;
            parameters.protocol_params.query_pow_bits = 12;
            parameters.protocol_params.deep_pow_bits = 0;
            parameters.protocol_params.folding_pow_bits = 0;
            cases.push(parameters);
        }
    }
    for (parameters, actual) in cases.iter().zip(run_estimators(&cases)) {
        assert!(actual <= u64::from(parameters.proven_security_level()), "{parameters:?}");
        let exhaustive = exhaustive_level(parameters);
        assert!(actual <= exhaustive && exhaustive - actual <= 1, "{parameters:?}");
    }
}

/// The largest accepted lookup coefficient and boundary correction leave the least room for
/// the list-scaled lookup round. Its subtractions must stay in range and remain conservative.
#[test]
fn list_scaled_lookup_stays_in_range_at_the_envelope_corner() {
    let cases: Vec<_> = [6, 7, 11, 29]
        .into_iter()
        .map(|h| {
            let mut parameters = vm_parameters(h);
            parameters.air_shape.lookup = Some(security::LookupShape {
                fractions_per_row: 1,
                max_message_width: 65534,
            });
            parameters.num_lookup_boundary_terms = 4096;
            parameters
        })
        .collect();
    for (parameters, actual) in cases.iter().zip(run_estimators(&cases)) {
        assert!(actual <= u64::from(parameters.proven_security_level()), "{parameters:?}");
        let exhaustive = exhaustive_level(parameters);
        assert!(actual <= exhaustive && exhaustive - actual <= 1, "{parameters:?}");
    }
}
