use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::num::NonZeroU32;
use std::{fs, path::Path};

use miden_core::Word;

use crate::{
    CodegenCurveId, CurvePrecompileDescriptor, Limbs, ONE_LIMBS, TWO_LIMBS, UintDomain,
    UintPrecompileDescriptor, ZERO_LIMBS,
};

const UINT_TEMPLATE_PATH: &str = "precompiles/codegen/src/templates/uint.masm.tpl";
const UINT_TEMPLATE: &str = include_str!("templates/uint.masm.tpl");
const U256_CONSTANTS_TEMPLATE: &str = include_str!("templates/u256_constants.masm.tpl");
const FIELD_CONSTANTS_TEMPLATE: &str = include_str!("templates/field_constants.masm.tpl");
const FIELD_EXTRA_OPS_TEMPLATE: &str = include_str!("templates/field_extra_ops.masm.tpl");
const CURVE_TEMPLATE_PATH: &str = "precompiles/codegen/src/templates/curve.masm.tpl";
const CURVE_TEMPLATE: &str = include_str!("templates/curve.masm.tpl");
const REGENERATE_COMMAND: &str =
    "cargo run -p miden-precompiles-codegen -- --out target/miden-precompiles-generated-asm";
const ASM_PATH_PREFIX: &str = "asm/";

const U256_CONFIG: UintMasmConfig = UintMasmConfig {
    path: "asm/math/u256.masm",
    title: "U256",
    domain: UintDomain::U256,
};

const K1_BASE_FIELD: UintMasmConfig = UintMasmConfig {
    path: "asm/math/k1_base.masm",
    title: "SECP256K1 BASE-FIELD",
    domain: UintDomain::K1Base,
};

const K1_SCALAR_FIELD: UintMasmConfig = UintMasmConfig {
    path: "asm/math/k1_scalar.masm",
    title: "SECP256K1 SCALAR-FIELD",
    domain: UintDomain::K1Scalar,
};

const R1_BASE_FIELD: UintMasmConfig = UintMasmConfig {
    path: "asm/math/r1_base.masm",
    title: "SECP256R1 BASE-FIELD",
    domain: UintDomain::R1Base,
};

const R1_SCALAR_FIELD: UintMasmConfig = UintMasmConfig {
    path: "asm/math/r1_scalar.masm",
    title: "SECP256R1 SCALAR-FIELD",
    domain: UintDomain::R1Scalar,
};

const ED25519_BASE_FIELD: UintMasmConfig = UintMasmConfig {
    path: "asm/math/ed25519_base.masm",
    title: "ED25519 BASE-FIELD",
    domain: UintDomain::Ed25519Base,
};

const ED25519_SCALAR_FIELD: UintMasmConfig = UintMasmConfig {
    path: "asm/math/ed25519_scalar.masm",
    title: "ED25519 SCALAR-FIELD",
    domain: UintDomain::Ed25519Scalar,
};

const FIELD_CONFIGS: &[UintMasmConfig] = &[
    K1_BASE_FIELD,
    K1_SCALAR_FIELD,
    R1_BASE_FIELD,
    R1_SCALAR_FIELD,
    ED25519_BASE_FIELD,
    ED25519_SCALAR_FIELD,
];

const CURVE_CONFIGS: &[CurveMasmConfig] = &[
    CurveMasmConfig {
        path: "asm/math/secp256k1.masm",
        title: "SECP256K1",
        base_field_module: "k1_base",
        base_field_description: "secp256k1 base-field",
        curve: CodegenCurveId::Secp256k1,
    },
    CurveMasmConfig {
        path: "asm/math/secp256r1.masm",
        title: "SECP256R1",
        base_field_module: "r1_base",
        base_field_description: "secp256r1 base-field",
        curve: CodegenCurveId::Secp256r1,
    },
    CurveMasmConfig {
        path: "asm/math/ed25519_sw.masm",
        title: "ED25519-SW",
        base_field_module: "ed25519_base",
        base_field_description: "Ed25519 base-field",
        curve: CodegenCurveId::Ed25519Sw,
    },
];

fn generated_files() -> Result<Vec<GeneratedFile>, String> {
    let mut generated = Vec::with_capacity(1 + FIELD_CONFIGS.len() + CURVE_CONFIGS.len());

    generated.push(GeneratedFile {
        path: U256_CONFIG.path,
        contents: render_uint(&U256_CONFIG)?,
    });

    for config in FIELD_CONFIGS {
        generated.push(GeneratedFile {
            path: config.path,
            contents: render_uint(config)?,
        });
    }

    for config in CURVE_CONFIGS {
        generated.push(GeneratedFile {
            path: config.path,
            contents: render_curve(config)?,
        });
    }

    Ok(generated)
}

fn render_uint(config: &UintMasmConfig) -> Result<String, String> {
    let domain = config.domain;
    let zero = constant(ZERO_LIMBS, domain);
    let one = constant(ONE_LIMBS, domain);
    let two = constant(TWO_LIMBS, domain);
    let domain_constants = render_uint_constants(config)?;
    let domain_extra_procs = render_uint_extra_procs(config)?;
    let op_tag = |op_id| word_literal(tag_word(UintPrecompileDescriptor::op_tag(op_id)));

    let replacements = vec![
        ("TEMPLATE_PATH", UINT_TEMPLATE_PATH.to_string()),
        ("REGENERATE_COMMAND", REGENERATE_COMMAND.to_string()),
        ("TITLE", config.title.to_string()),
        ("DOMAIN_KIND", domain_kind(domain).to_string()),
        ("VALUE_KIND", value_kind(domain).to_string()),
        ("ENCODED_MODULUS_NOTE", encoded_modulus_note(domain).to_string()),
        ("MODULUS_ID", domain.id().as_canonical_u64().to_string()),
        ("ENCODED_MODULUS_LIMBS", limbs_literal(domain.encoded_modulus())),
        ("PRECOMPILE_ID", UintPrecompileDescriptor::id().as_canonical_u64().to_string()),
        ("VALUE_TAG", word_literal(tag_word(UintPrecompileDescriptor::value_tag(domain)))),
        ("ADD_TAG", op_tag(UintPrecompileDescriptor::ADD_OP_ID)),
        ("SUB_TAG", op_tag(UintPrecompileDescriptor::SUB_OP_ID)),
        ("MUL_TAG", op_tag(UintPrecompileDescriptor::MUL_OP_ID)),
        ("EQ_TAG", op_tag(UintPrecompileDescriptor::EQ_OP_ID)),
        ("ZERO_DIGEST", zero.digest),
        ("ZERO_LO_WORD", zero.lo_word),
        ("ZERO_HI_WORD", zero.hi_word),
        ("ONE_DIGEST", one.digest),
        ("ONE_LO_WORD", one.lo_word),
        ("ONE_HI_WORD", one.hi_word),
        ("TWO_DIGEST", two.digest),
        ("TWO_LO_WORD", two.lo_word),
        ("TWO_HI_WORD", two.hi_word),
        ("DOMAIN_CONSTANT_PROCS", domain_constants),
        ("DOMAIN_EXTRA_PROCS", domain_extra_procs),
    ];

    render_template(UINT_TEMPLATE, &replacements)
}

fn render_uint_constants(config: &UintMasmConfig) -> Result<String, String> {
    let domain = config.domain;
    if domain == UintDomain::U256 {
        let max = constant(domain.max().expect("u256 max is defined"), domain);
        return render_template(
            U256_CONSTANTS_TEMPLATE,
            &[
                ("MAX_DIGEST", max.digest),
                ("MAX_LO_WORD", max.lo_word),
                ("MAX_HI_WORD", max.hi_word),
            ],
        );
    }

    if !domain.is_prime_field() {
        return Err(format!("{} must be marked as a prime-field domain", config.title));
    }

    let minus_one = constant(domain.minus_one(), domain);
    let half = constant(domain.half().expect("field half is defined"), domain);
    let pow_2_128 = constant(domain.pow2_mod(128).expect("field 2^128 is defined"), domain);
    let pow_2_256 = constant(domain.pow2_mod(256).expect("field 2^256 is defined"), domain);
    let pow_2_384 = constant(domain.pow2_mod(384).expect("field 2^384 is defined"), domain);
    render_template(
        FIELD_CONSTANTS_TEMPLATE,
        &[
            ("MINUS_ONE_DIGEST", minus_one.digest),
            ("MINUS_ONE_LO_WORD", minus_one.lo_word),
            ("MINUS_ONE_HI_WORD", minus_one.hi_word),
            ("HALF_DIGEST", half.digest),
            ("HALF_LO_WORD", half.lo_word),
            ("HALF_HI_WORD", half.hi_word),
            ("POW_2_128_DIGEST", pow_2_128.digest),
            ("POW_2_128_LO_WORD", pow_2_128.lo_word),
            ("POW_2_128_HI_WORD", pow_2_128.hi_word),
            ("POW_2_256_DIGEST", pow_2_256.digest),
            ("POW_2_256_LO_WORD", pow_2_256.lo_word),
            ("POW_2_256_HI_WORD", pow_2_256.hi_word),
            ("POW_2_384_DIGEST", pow_2_384.digest),
            ("POW_2_384_LO_WORD", pow_2_384.lo_word),
            ("POW_2_384_HI_WORD", pow_2_384.hi_word),
        ],
    )
}

fn render_uint_extra_procs(config: &UintMasmConfig) -> Result<String, String> {
    if config.domain == UintDomain::U256 {
        Ok(String::new())
    } else {
        render_template(FIELD_EXTRA_OPS_TEMPLATE, &[])
    }
}

fn constant(value: Limbs, domain: UintDomain) -> ConstantMasm {
    let digest = UintPrecompileDescriptor::value_node(domain, value).digest();
    let [lo, hi] = value_words(value);
    ConstantMasm {
        digest: word_literal(digest_word(digest)),
        lo_word: limb_word_literal(lo),
        hi_word: limb_word_literal(hi),
    }
}

fn render_curve(config: &CurveMasmConfig) -> Result<String, String> {
    let curve = config.curve;
    let op_tag = |op_id| word_literal(tag_word(CurvePrecompileDescriptor::op_tag(op_id)));
    let replacements = vec![
        ("TEMPLATE_PATH", CURVE_TEMPLATE_PATH.to_string()),
        ("REGENERATE_COMMAND", REGENERATE_COMMAND.to_string()),
        ("TITLE", config.title.to_string()),
        ("BASE_FIELD_MODULE", config.base_field_module.to_string()),
        ("BASE_FIELD_DESCRIPTION", config.base_field_description.to_string()),
        ("PRECOMPILE_ID", CurvePrecompileDescriptor::id().as_canonical_u64().to_string()),
        ("CURVE_ID", curve.id().as_canonical_u64().to_string()),
        ("VALUE_OP_ID", CurvePrecompileDescriptor::VALUE_OP_ID.to_string()),
        ("ADD_OP_ID", CurvePrecompileDescriptor::ADD_OP_ID.to_string()),
        ("SUB_OP_ID", CurvePrecompileDescriptor::SUB_OP_ID.to_string()),
        ("EQ_OP_ID", CurvePrecompileDescriptor::EQ_OP_ID.to_string()),
        ("MSM_OP_ID", CurvePrecompileDescriptor::MSM_OP_ID.to_string()),
        ("VALUE_TAG", word_literal(tag_word(CurvePrecompileDescriptor::value_tag(curve)))),
        ("ADD_TAG", op_tag(CurvePrecompileDescriptor::ADD_OP_ID)),
        ("SUB_TAG", op_tag(CurvePrecompileDescriptor::SUB_OP_ID)),
        ("EQ_TAG", op_tag(CurvePrecompileDescriptor::EQ_OP_ID)),
        (
            "MSM_TAG",
            word_literal(tag_word(CurvePrecompileDescriptor::msm_tag(curve, NonZeroU32::MIN))),
        ),
        (
            "IDENTITY_DIGEST",
            word_literal(digest_word(CurvePrecompileDescriptor::identity_node(curve).digest())),
        ),
        (
            "GENERATOR_DIGEST",
            word_literal(digest_word(CurvePrecompileDescriptor::generator_node(curve).digest())),
        ),
    ];

    render_template(CURVE_TEMPLATE, &replacements)
}

fn render_template(template: &str, replacements: &[(&str, String)]) -> Result<String, String> {
    let mut rendered = template.to_string();
    apply_template_replacements(&mut rendered, replacements)?;
    ensure_no_template_placeholders(&rendered)?;
    Ok(rendered)
}

fn apply_template_replacements(
    rendered: &mut String,
    replacements: &[(&str, String)],
) -> Result<(), String> {
    for (name, value) in replacements {
        let placeholder = format!("{{{{{name}}}}}");
        if rendered.contains(&placeholder) {
            *rendered = rendered.replace(&placeholder, value);
        } else {
            return Err(format!("template placeholder {placeholder} not found"));
        }
    }

    Ok(())
}

/// Writes generated MASM files into an assembled MASM project root.
pub fn write_math_masm(asm_dir: impl AsRef<Path>) -> Result<(), String> {
    let asm_dir = asm_dir.as_ref();
    for file in generated_files()? {
        let relative_path = file.path.strip_prefix(ASM_PATH_PREFIX).ok_or_else(|| {
            format!("generated path {} does not start with {ASM_PATH_PREFIX}", file.path)
        })?;
        write_file_if_changed(&asm_dir.join(relative_path), &file.contents)?;
    }
    Ok(())
}

/// Renders the generated U256 MASM module source.
pub fn render_u256_masm() -> Result<String, String> {
    render_uint(&U256_CONFIG)
}

/// Writes generated MASM files into a developer preview directory.
pub fn write_to_dir(out_dir: impl AsRef<Path>) -> Result<(), String> {
    let out_dir = out_dir.as_ref();
    for file in generated_files()? {
        write_file_if_changed(&out_dir.join(file.path), &file.contents)?;
    }
    Ok(())
}

fn ensure_no_template_placeholders(rendered: &str) -> Result<(), String> {
    if let Some(start) = rendered.find("{{") {
        let end = rendered[start..]
            .find("}}")
            .map(|offset| start + offset + 2)
            .unwrap_or_else(|| (start + 40).min(rendered.len()));
        return Err(format!("unreplaced template placeholder remains: {}", &rendered[start..end]));
    }

    if let Some(start) = rendered.find("}}") {
        let end = (start + 40).min(rendered.len());
        return Err(format!(
            "unmatched template placeholder terminator remains: {}",
            &rendered[start..end]
        ));
    }

    Ok(())
}

fn tag_word(tag: miden_core::deferred::Tag) -> [u64; 4] {
    let word = tag.as_word();
    core::array::from_fn(|i| word[i].as_canonical_u64())
}

fn digest_word(digest: Word) -> [u64; 4] {
    let elements = digest.as_elements();
    core::array::from_fn(|i| elements[i].as_canonical_u64())
}

fn word_literal(word: [u64; 4]) -> String {
    format!("[{}, {}, {}, {}]", word[0], word[1], word[2], word[3])
}

fn value_words(limbs: [u32; 8]) -> [[u32; 4]; 2] {
    [
        [limbs[0], limbs[1], limbs[2], limbs[3]],
        [limbs[4], limbs[5], limbs[6], limbs[7]],
    ]
}

fn limb_word_literal(word: [u32; 4]) -> String {
    format!("[{}, {}, {}, {}]", word[0], word[1], word[2], word[3])
}

fn limbs_literal(limbs: [u32; 8]) -> String {
    let limbs: Vec<String> = limbs.iter().map(|limb| format!("0x{limb:08x}")).collect();
    format!("[{}]", limbs.join(", "))
}

fn write_file_if_changed(path: &Path, contents: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    }
    match fs::read_to_string(path) {
        Ok(actual) if actual == contents => Ok(()),
        Ok(_) | Err(_) => fs::write(path, contents.as_bytes())
            .map_err(|error| format!("failed to write {}: {error}", path.display())),
    }
}

struct ConstantMasm {
    digest: String,
    lo_word: String,
    hi_word: String,
}

struct GeneratedFile {
    path: &'static str,
    contents: String,
}

fn domain_kind(domain: UintDomain) -> &'static str {
    if domain == UintDomain::U256 { "UINT" } else { "FIELD" }
}

fn value_kind(domain: UintDomain) -> &'static str {
    if domain == UintDomain::U256 { "uint" } else { "field" }
}

fn encoded_modulus_note(domain: UintDomain) -> &'static str {
    if domain == UintDomain::U256 {
        ", all-zero means 2^256"
    } else {
        ""
    }
}

#[derive(Clone, Copy)]
struct UintMasmConfig {
    path: &'static str,
    title: &'static str,
    domain: UintDomain,
}

struct CurveMasmConfig {
    path: &'static str,
    title: &'static str,
    base_field_module: &'static str,
    base_field_description: &'static str,
    curve: CodegenCurveId,
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    #[test]
    fn write_to_dir_preserves_unrelated_files() {
        let out_dir = unique_temp_dir("miden-precompiles-codegen-write-to-dir");
        let unrelated_file = out_dir.join("notes.txt");
        fs::create_dir_all(&out_dir).unwrap();
        fs::write(&unrelated_file, "keep me").unwrap();

        write_to_dir(&out_dir).unwrap();

        assert_eq!(fs::read_to_string(&unrelated_file).unwrap(), "keep me");
        assert!(out_dir.join("asm/math/u256.masm").exists());

        fs::remove_dir_all(&out_dir).unwrap();
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
    }
}
