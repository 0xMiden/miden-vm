use miden_core::program::KernelDescriptor;
use miden_vm_stark::setup::config;

const SECURITY_ESTIMATOR_PATH: &str = "stark/security.masm";
const RELATION_DIGEST_PATH: &str = "sys/vm/mod.masm";
const GENERIC_UTILS_PATH: &str = "stark/utils.masm";

#[test]
fn security_masm_constants_and_envelope_match_air() {
    security_masm_matches_air().unwrap();
}

fn read_file(path: &str) -> std::io::Result<String> {
    std::fs::read_to_string(std::path::Path::new(env!("MIDEN_CORE_ASM_DIR")).join(path))
}

pub fn security_masm_matches_air() -> Result<(), String> {
    let estimator = read_file(SECURITY_ESTIMATOR_PATH).map_err(|e| e.to_string())?;
    // These literals define the shared fixed-point format and the PCS values used to bound the
    // terms omitted by the MASM estimator. The remaining limits are checked below against the MVM
    // relation and the generic verifier.
    let fractional_bits = miden_vm_stark::security::FIXED_POINT_FRACTIONAL_BITS;
    let fixed_point_one = miden_vm_stark::security::FIXED_POINT_ONE;
    let sample_bits = miden_vm_stark::security::EIDOS_CHALLENGE_SAMPLE_BITS;
    let shared_literals: [(&str, u64); 9] = [
        ("FP_SHIFT", u64::from(fractional_bits)),
        ("FP_ONE", fixed_point_one),
        ("BITS_PER_QUERY_FP", miden_vm_stark::security::BITS_PER_QUERY),
        ("CHALLENGE_SAMPLE_BITS", sample_bits >> fractional_bits),
        ("SECURITY_CAP_BITS", miden_vm_stark::security::SECURITY_CAP >> fractional_bits),
        (
            "DEEP_FIELD_BASE_BITS",
            (sample_bits >> fractional_bits) - u64::from(config::pcs_params().log_blowup()),
        ),
        (
            "FRI_FOLDING_BASE_BITS",
            miden_vm_stark::security::FOLDING_BASE >> fractional_bits,
        ),
        ("LOG2_E_FP", miden_vm_stark::security::LOG2_E),
        ("MAX_CONSTRAINT_DEGREE", (1u64 << config::pcs_params().log_blowup()) + 1),
    ];

    for (name, expected) in shared_literals {
        let actual = parse_masm_const::<u64>(&estimator, name, SECURITY_ESTIMATOR_PATH)?;
        if actual != expected {
            return Err(format!("{name} in {SECURITY_ESTIMATOR_PATH} is stale"));
        }
    }

    // The estimator omits four native security terms only while the MVM shape and the generic
    // verifier's parameter ranges satisfy its documented bounds. `air_shape_matches_symbolic`
    // checks the stored shape against the AIRs; the checks below fail if that shape leaves the
    // estimator envelope. This function also pins the generic verifier bounds directly.
    let wrapper = read_file(RELATION_DIGEST_PATH).map_err(|e| e.to_string())?;
    let utils = read_file(GENERIC_UTILS_PATH).map_err(|e| e.to_string())?;
    let air_shape = miden_vm_stark::security::AIR_SHAPE;
    let parsed = |name: &str| parse_masm_const::<u64>(&estimator, name, SECURITY_ESTIMATOR_PATH);
    let lookup = air_shape.lookup.expect("the MVM uses a lookup argument");
    let lookup_coefficient =
        (u64::from(lookup.max_message_width) + 2) * u64::from(lookup.fractions_per_row);
    let max_boundary_terms = u64::from(miden_vm_stark::security::CORE_BOUNDARY_LOOKUP_TERMS)
        + KernelDescriptor::MAX_NUM_PROCEDURES as u64;
    if u64::from(air_shape.num_composed_constraints) > parsed("MAX_COMPOSED_CONSTRAINTS")? {
        return Err("the MVM composed-constraint count exceeds the estimator envelope".into());
    }
    if u64::from(air_shape.max_constraint_degree) > parsed("MAX_CONSTRAINT_DEGREE")? {
        return Err("the MVM constraint degree exceeds the estimator envelope".into());
    }
    if u64::from(air_shape.num_deep_terms.expect("the MVM uses DEEP composition"))
        > parsed("MAX_DEEP_TERMS")?
    {
        return Err("the MVM DEEP term count exceeds the estimator envelope".into());
    }
    if lookup_coefficient < parsed("MIN_LOOKUP_COEFFICIENT")? {
        return Err("the MVM lookup coefficient falls below the estimator envelope".into());
    }
    if lookup_coefficient > parsed("MAX_LOOKUP_COEFFICIENT")? {
        return Err("the MVM lookup coefficient exceeds the estimator envelope".into());
    }
    if max_boundary_terms > parsed("MAX_BOUNDARY_TERMS")? {
        return Err("the MVM boundary-term maximum exceeds the estimator envelope".into());
    }
    if parsed("MIN_LOG_HEIGHT")?
        != parse_masm_const::<u64>(&wrapper, "LOG_HEIGHT_MIN", RELATION_DIGEST_PATH)?
    {
        return Err(format!("MIN_LOG_HEIGHT in {SECURITY_ESTIMATOR_PATH} is stale"));
    }
    let estimator_heights = parsed("MAX_LOG_HEIGHT")?;
    if parsed("MAX_NUM_QUERIES")?
        != parse_masm_const::<u64>(&utils, "NUM_QUERIES_MAX", GENERIC_UTILS_PATH)?
    {
        return Err(format!("MAX_NUM_QUERIES in {SECURITY_ESTIMATOR_PATH} is stale"));
    }
    if parsed("MAX_POW_BITS")?
        != parse_masm_const::<u64>(&utils, "POW_BITS_MAX", GENERIC_UTILS_PATH)?
    {
        return Err(format!("MAX_POW_BITS in {SECURITY_ESTIMATOR_PATH} is stale"));
    }

    let descriptor_literals: [(&str, u64); 9] = [
        ("LOOKUP_POW_BITS", miden_vm_stark::security::LOOKUP_POW_BITS as u64),
        (
            "MAX_MESSAGE_WIDTH",
            miden_vm_stark::security::LOOKUP_SHAPE.max_message_width as u64,
        ),
        (
            "NUM_COMPOSED_CONSTRAINTS",
            miden_vm_stark::security::AIR_SHAPE.num_composed_constraints as u64,
        ),
        (
            "MAX_CONSTRAINT_DEGREE",
            miden_vm_stark::security::AIR_SHAPE.max_constraint_degree as u64,
        ),
        (
            "NUM_DEEP_TERMS",
            miden_vm_stark::security::AIR_SHAPE
                .num_deep_terms
                .expect("the MVM uses DEEP composition") as u64,
        ),
        (
            "CORE_BOUNDARY_LOOKUP_TERMS",
            miden_vm_stark::security::CORE_BOUNDARY_LOOKUP_TERMS as u64,
        ),
        (
            "LOOKUP_FRACTIONS_PER_ROW",
            miden_vm_stark::security::LOOKUP_SHAPE.fractions_per_row as u64,
        ),
        ("MAX_NUM_KERNEL_PROCEDURES", KernelDescriptor::MAX_NUM_PROCEDURES as u64),
        ("LOG_HEIGHT_MAX", estimator_heights),
    ];

    for (name, expected) in descriptor_literals {
        let actual = parse_masm_const::<u64>(&wrapper, name, RELATION_DIGEST_PATH)?;
        if actual != expected {
            return Err(format!("{name} in {RELATION_DIGEST_PATH} is stale"));
        }
    }

    Ok(())
}

fn parse_masm_const<T: core::str::FromStr>(
    masm: &str,
    name: &str,
    file_label: &str,
) -> Result<T, String>
where
    T::Err: core::fmt::Debug,
{
    let prefix = format!("const {name} = ");
    masm.lines()
        .find_map(|line| {
            let line = line.trim();
            let value = line.strip_prefix("pub ").unwrap_or(line).strip_prefix(&prefix)?;
            let value = value.split('#').next().unwrap_or(value).trim();
            value.parse::<T>().ok()
        })
        .ok_or_else(|| format!("constant {name} not found in {file_label}"))
}
