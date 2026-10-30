//! Allocation, alias, and immediate-access checks for recursive-verifier memory.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use miden_assembly::{
    ModuleParser, Path as MasmPath, PathBuf as MasmPathBuf,
    ast::{
        ConstantExpr, Form, Ident, Immediate, Import, Instruction,
        constants::{
            ConstEnvironment, ConstEvalError,
            eval::{self, CachedConstantValue},
        },
        visit::Visit,
    },
    debuginfo::{DefaultSourceManager, SourceFile, SourceManagerExt, SourceSpan, Span},
    testing::parser::parse_forms,
};

use crate::support::security::NUM_QUERIES_MAX;

const FRI_QUERY_REGION_SIZE: u64 = NUM_QUERIES_MAX * 4;
const FRI_FORWARD_REGION_SIZE: u64 = 512;

/// `(name, offset from the declared address, extent in felts)`.
///
/// Every allocation must occur exactly once. There is deliberately no one-felt default:
/// an unlisted address must be derived from a declared allocation, or the test fails.
const GENERIC_REGIONS: &[(&str, i64, u64)] = &[
    ("DOMAIN_OFFSET_PTR", 0, 1),
    ("DOMAIN_OFFSET_INV_PTR", 0, 1),
    ("LDE_DOMAIN_INFO_PTR", 0, 4),
    ("LDE_DOMAIN_SIZE_PTR", 0, 1),
    ("LOG_LDE_DOMAIN_SIZE_PTR", 0, 1),
    ("LDE_DOMAIN_GENERATOR_PTR", 0, 1),
    ("NUM_QUERIES_PTR", 0, 1),
    ("REMAINDER_POLY_SIZE_PTR", 0, 1),
    ("NUM_FRI_LAYERS_PTR", 0, 1),
    ("REMAINDER_POLY_ADDRESS_PTR", 0, 1),
    ("TRACE_LENGTH_PTR", 0, 1),
    ("FRI_QUERIES_ADDRESS_PTR", 0, 1),
    ("LOG_TRACE_LENGTH_PTR", 0, 1),
    ("MAIN_TRACE_COM_PTR", 0, 4),
    ("AUX_TRACE_COM_PTR", 0, 4),
    ("COMPOSITION_POLY_COM_PTR", 0, 4),
    ("OOD_POINT_PTR", 0, 4),
    ("ZERO_WORD_PTR", 0, 4),
    ("DEEP_ALPHA_ADVICE_PTR", 0, 4),
    ("OOD_FIXED_TERM_HORNER_EVALUATIONS_PTR", 0, 4),
    ("RANDOM_COIN_CV_PTR", 0, 4),
    ("RANDOM_COIN_OUTPUT_WORD_PTR", 0, 4),
    ("RANDOM_COIN_INPUT_BUF_PTR", 0, 8),
    ("TRACE_DOMAIN_GENERATOR_PTR", 0, 1),
    ("PUBLIC_INPUTS_ADDRESS_PTR", 0, 1),
    ("FRI_VERIFY_STATE_PTR", 0, 4),
    ("TMP1_PTR", 0, 4),
    ("TMP2_PTR", 0, 4),
    ("TMP3_PTR", 0, 4),
    ("TMP4_PTR", 0, 4),
    ("CONSTRAINT_COMPOSITION_COEFS_PTR", 0, 4),
    ("DEEP_COMPOSITION_COEFS_PTR", 0, 4),
    ("NUM_FIXED_LENGTH_PUBLIC_INPUTS_PTR", 0, 1),
    ("NUM_ACE_INPUTS_PTR", 0, 1),
    ("NUM_ACE_GATES_PTR", 0, 1),
    ("LOG_MAX_CYCLE_LENGTH_PTR", 0, 1),
    ("QUERY_POW_BITS_PTR", 0, 1),
    ("DEEP_POW_BITS_PTR", 0, 1),
    ("FOLDING_POW_BITS_PTR", 0, 1),
    ("HOOK_COMPUTE_DEEP_COMPOSITION_POLYNOMIAL_QUERIES_PTR", 0, 4),
    ("HOOK_EXECUTE_CONSTRAINT_EVALUATION_CHECK_PTR", 0, 4),
    ("HOOK_PROCESS_ROW_OOD_EVALUATIONS_PTR", 0, 4),
    ("HOOK_PROCESS_PUBLIC_INPUTS_PTR", 0, 4),
    ("HOOK_OBSERVE_AUX_TRACE_PTR", 0, 4),
    ("RANDOM_COIN_INPUT_LENGTH_PTR", 0, 1),
    ("RANDOM_COIN_OUTPUT_LENGTH_PTR", 0, 1),
    ("OOD_EVALUATIONS_ADDRESS_PTR", 0, 1),
    ("CURRENT_TRACE_ROW_ADDRESS_PTR", 0, 1),
    ("GENERIC_RESERVED_CELL_PTR", 0, 1),
    ("LOG_AIR_TRACE_LENGTHS_PTR", 0, 16),
    ("RELATION_DIGEST_PTR", 0, 4),
    ("GENERIC_RESERVED_WORD_PTR", 0, 4),
    ("PREPROCESSED_TRACE_COM_PTR", 0, 4),
    ("RANDOM_COIN_COUNTER_PTR", 0, 1),
    ("AUXILIARY_ACE_INPUTS_ADDRESS_PTR", 0, 1),
    ("AUX_RAND_ELEM_ADDRESS_PTR", 0, 1),
    ("GENERIC_ALIGNMENT_PADDING_PTR", 0, 2),
    // One word per accepted query grows backward; FRI layers and the remainder grow forward.
    (
        "FRI_COM_PTR",
        -(FRI_QUERY_REGION_SIZE as i64),
        FRI_QUERY_REGION_SIZE + FRI_FORWARD_REGION_SIZE,
    ),
];

// These declarations name fields inside LDE_DOMAIN_INFO_PTR rather than distinct storage.
const GENERIC_ALIASES: &[&str] =
    &["LDE_DOMAIN_SIZE_PTR", "LOG_LDE_DOMAIN_SIZE_PTR", "LDE_DOMAIN_GENERATOR_PTR"];

const GENERIC_FRAME_START: u64 = 3_223_322_624;
const GENERIC_FRAME_END: u64 = 3_223_322_776;
const VM_FRAME_END: u64 = 3_223_323_864;
const VM_ACE_READ_START: u64 = 3_225_419_776;
const PVM_FRAME_START: u64 = 3_225_432_064;

#[derive(Clone, Copy, Debug)]
enum RegionExtent {
    Fixed(u64),
    Until(&'static str),
    UntilAddress(u64),
    FractionOf {
        start: &'static str,
        end: &'static str,
        divisor: u64,
    },
}
use RegionExtent::{Fixed, FractionOf, Until, UntilAddress};

/// `(path below asm/sys, name, offset from the declared address, extent)`.
///
/// Pointer-delimited extents resolve across modules of the same relation. Each entry still
/// pins the declaring file, and every relation-owned allocation must be listed explicitly.
/// Derived pointers are checked separately against the allocation they reference.
const RELATION_REGIONS: &[(&str, &str, i64, RegionExtent)] = &[
    ("pvm/layout.masm", "PUBLIC_INPUTS_PTR", 0, Until("AUX_RAND_ELEM_PTR")),
    ("pvm/layout.masm", "AUX_RAND_ELEM_PTR", 0, Until("PREPROCESSED_CURRENT_PTR")),
    ("pvm/layout.masm", "PREPROCESSED_CURRENT_PTR", 0, Until("MAIN_CURRENT_PTR")),
    ("pvm/layout.masm", "MAIN_CURRENT_PTR", 0, Until("AUX_CURRENT_PTR")),
    ("pvm/layout.masm", "AUX_CURRENT_PTR", 0, Until("QUOTIENT_CURRENT_PTR")),
    ("pvm/layout.masm", "QUOTIENT_CURRENT_PTR", 0, Until("PREPROCESSED_NEXT_PTR")),
    ("pvm/layout.masm", "PREPROCESSED_NEXT_PTR", 0, Until("MAIN_NEXT_PTR")),
    ("pvm/layout.masm", "MAIN_NEXT_PTR", 0, Until("AUX_NEXT_PTR")),
    ("pvm/layout.masm", "AUX_NEXT_PTR", 0, Until("QUOTIENT_NEXT_PTR")),
    ("pvm/layout.masm", "QUOTIENT_NEXT_PTR", 0, Until("AUX_BUS_BOUNDARY_PTR")),
    ("pvm/layout.masm", "AUX_BUS_BOUNDARY_PTR", 0, Until("AUXILIARY_ACE_INPUTS_PTR")),
    (
        "pvm/layout.masm",
        "AUXILIARY_ACE_INPUTS_PTR",
        0,
        Until("ACE_CIRCUIT_STREAM_PTR"),
    ),
    ("pvm/layout.masm", "ACE_CIRCUIT_STREAM_PTR", 0, Until("BUS_GAMMA_PTR")),
    ("pvm/layout.masm", "BUS_GAMMA_PTR", 0, Until("C_TOTAL_PTR")),
    ("pvm/layout.masm", "C_TOTAL_PTR", 0, Until("CURRENT_TRACE_ROW_PTR")),
    ("pvm/layout.masm", "CURRENT_TRACE_ROW_PTR", 0, Until("PREPROCESSED_COM_PTR")),
    ("pvm/layout.masm", "PREPROCESSED_COM_PTR", 0, Fixed(4)),
    (
        "pvm/layout.masm",
        "OOD_SCATTER_TABLE_PTR",
        0,
        Until("PROOF_ORDER_POSITIONS_PTR"),
    ),
    // Twelve live position cells, followed by one ID per proof position.
    ("pvm/layout.masm", "PROOF_ORDER_POSITIONS_PTR", 0, Until("PROOF_ORDER_IDS_PTR")),
    ("pvm/layout.masm", "PROOF_ORDER_IDS_PTR", 0, Fixed(12)),
    ("vm/layout.masm", "NUM_KERNEL_PROCEDURES_PTR", 0, Fixed(1)),
    ("vm/layout.masm", "CONTROL_ALIGNMENT_PADDING_PTR", 0, Fixed(3)),
    ("vm/layout.masm", "BUS_GAMMA_PTR", 0, Fixed(4)),
    ("vm/layout.masm", "C_TOTAL_PTR", 0, Fixed(4)),
    ("vm/layout.masm", "CLAIM_COMMITMENT_PTR", 0, Fixed(4)),
    ("vm/layout.masm", "CLAIM_PTR", 0, Fixed(40)),
    ("vm/layout.masm", "BOUNDARY_ANCHOR_PADDING_PTR", 0, Fixed(4)),
    ("vm/layout.masm", "BOUNDARY_INPUTS_PTR", 0, Fixed(8)),
    ("vm/layout.masm", "KERNEL_WITNESS_PTR", 0, Fixed(1020)),
    // Out-of-domain scatter table: row base, per-position dispatch records, and the `pipe_k`
    // digests, followed by the two proof-order maps inside the same 64-felt reserve. Sits
    // immediately after the VM control frame, so it is outside that frame's tiling.
    ("vm/layout.masm", "OOD_SCATTER_TABLE_PTR", 0, Until("PROOF_ORDER_POSITIONS_PTR")),
    (
        "vm/parameters.masm",
        "PROOF_ORDER_POSITIONS_PTR",
        0,
        Until("PROOF_ORDER_IDS_PTR"),
    ),
    ("vm/parameters.masm", "PROOF_ORDER_IDS_PTR", 0, Fixed(4)),
    // Includes the alignment word before OOD_EVALUATIONS_PTR.
    ("vm/layout.masm", "AUX_RAND_ELEM_PTR", 0, Fixed(8)),
    ("vm/parameters.masm", "OOD_EVALUATIONS_PTR", 0, Until("AUX_BUS_BOUNDARY_PTR")),
    ("vm/parameters.masm", "AUX_BUS_BOUNDARY_PTR", 0, Fixed(8)),
    // 10 shared STARK slots + 3 selectors per AIR + 4 fold coefficients + 2 padding slots,
    // each occupying two base felts: (10 + 3 * 4 + 4 + 2) * 2 = 56.
    ("vm/parameters.masm", "AUXILIARY_ACE_INPUTS_PTR", 0, Fixed(56)),
    // Fixed VM stream reservation ending at the PVM allocation.
    ("vm/parameters.masm", "ACE_CIRCUIT_STREAM_PTR", 0, UntilAddress(PVM_FRAME_START)),
    (
        "vm/layout.masm",
        "CURRENT_TRACE_ROW_PTR",
        0,
        FractionOf {
            start: "OOD_EVALUATIONS_PTR",
            end: "AUX_BUS_BOUNDARY_PTR",
            // The OOD allocation contains current and next rows, with every scalar
            // evaluation represented by EXT_DEGREE base-field coordinates.
            divisor: 2 * miden_ace::EXT_DEGREE as u64,
        },
    ),
];

#[derive(Debug)]
struct Region {
    source: String,
    name: String,
    lo: u64,
    hi: u64,
}

struct AddressDeclaration {
    name: String,
    address: u64,
    referenced_addresses: Vec<u64>,
}

struct MemoryAccess {
    address: u64,
    width: u64,
}

struct AccessVisitor<'a> {
    env: &'a mut ConstantEnv,
    accesses: Vec<MemoryAccess>,
}

impl Visit for AccessVisitor<'_> {
    fn visit_inst(&mut self, inst: &Span<Instruction>) -> std::ops::ControlFlow<()> {
        let (immediate, width) = match inst.inner() {
            Instruction::MemLoadImm(imm) | Instruction::MemStoreImm(imm) => (imm, 1),
            Instruction::MemLoadWBeImm(imm)
            | Instruction::MemLoadWLeImm(imm)
            | Instruction::MemStoreWBeImm(imm)
            | Instruction::MemStoreWLeImm(imm) => (imm, 4),
            _ => return std::ops::ControlFlow::Continue(()),
        };
        let address = match immediate {
            Immediate::Value(value) => u64::from(*value.inner()),
            Immediate::Constant(name) => {
                let expr = self
                    .env
                    .constants
                    .get(name.as_str())
                    .unwrap_or_else(|| panic!("unresolved memory address {name}"))
                    .clone();
                eval::expr(&expr, self.env)
                    .expect("memory address evaluates")
                    .expect_int()
                    .as_int()
            },
        };
        if ((1 << 31)..=u32::MAX as u64).contains(&address) {
            self.accesses.push(MemoryAccess { address, width });
        }
        std::ops::ControlFlow::Continue(())
    }
}

struct ConstantEnv {
    constants: BTreeMap<String, ConstantExpr>,
}

impl ConstEnvironment for ConstantEnv {
    type Error = ConstEvalError;

    fn get_source_file_for(&self, _span: SourceSpan) -> Option<Arc<SourceFile>> {
        None
    }

    fn get(&mut self, name: &Ident) -> Result<Option<CachedConstantValue<'_>>, Self::Error> {
        Ok(self.constants.get(name.as_str()).map(CachedConstantValue::Miss))
    }

    fn get_by_path(
        &mut self,
        path: Span<&MasmPath>,
    ) -> Result<Option<CachedConstantValue<'_>>, Self::Error> {
        Ok(self
            .constants
            .get(path.to_string().trim_start_matches("::"))
            .map(CachedConstantValue::Miss))
    }
}

fn is_address(name: &str, value: u64) -> bool {
    name.ends_with("_PTR") || ((1 << 31)..=u32::MAX as u64).contains(&value)
}

/// Semantically evaluated fixed-memory declarations in a MASM module.
///
/// MASM constants may be expressions (`const NEW_PTR = OLD_PTR + 1`), so this uses
/// the semantic constant evaluator rather than text parsing. Anything numeric that remains
/// unresolved fails closed instead of escaping the manifest.
/// Pointer-named constants are included at any address; other numeric constants
/// are treated as addresses only in the verifier's high 32-bit address band.
/// This permits field offsets alongside addresses in layout modules.
/// Named allocation comments retain boundaries whose constants are unused by MASM.
fn declarations(
    path: &Path,
    exports: &BTreeMap<String, ConstantExpr>,
) -> (Vec<AddressDeclaration>, Vec<MemoryAccess>) {
    let relative_path = path
        .strip_prefix(concat!(env!("CARGO_MANIFEST_DIR"), "/asm"))
        .expect("module is below asm")
        .with_extension("");
    let relative_path = relative_path.to_string_lossy().replace(['/', '\\'], "::");
    let module_path: MasmPathBuf =
        format!("miden::core::{}", relative_path.strip_suffix("::mod").unwrap_or(&relative_path))
            .parse()
            .expect("valid core module path");
    let source_manager = Arc::new(DefaultSourceManager::default());
    let source = source_manager.load_file(path).expect("MASM module is readable");
    // Semantic analysis folds local expressions. Retain their raw ASTs so `BASE + offset`
    // still carries its allocation provenance when BASE is defined in the same module.
    let forms = parse_forms(source.clone()).expect("MASM forms parse");
    let mut parser = ModuleParser::default();
    let module = parser
        .parse(Some(&module_path), source, source_manager)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    // Imported values come from the assembled package, including re-exports. Local
    // expressions still use the assembler's evaluator so unresolved addresses fail closed.
    let mut env = ConstantEnv { constants: exports.clone() };
    let local_prefix = format!("{module_path}::");
    for (path, value) in exports {
        if let Some(name) = path.strip_prefix(&local_prefix) {
            env.constants.insert(name.to_string(), value.clone());
        }
    }
    for import in module.imports() {
        let module_path = import.module_path().to_string();
        let prefix = format!("{}::", module_path.trim_start_matches("::"));
        match import {
            Import::Module(import) => {
                for (path, value) in exports {
                    if let Some(name) = path.strip_prefix(&prefix) {
                        env.constants
                            .insert(format!("{}::{name}", import.local_name()), value.clone());
                    }
                }
            },
            Import::Item(import) => {
                if let Some(value) = exports.get(&format!("{prefix}{}", import.source_name())) {
                    env.constants.insert(import.local_name().to_string(), value.clone());
                }
            },
        }
    }
    env.constants.extend(
        module
            .constants()
            .map(|constant| (constant.name().as_str().to_string(), constant.value.clone())),
    );
    let mut declarations: Vec<_> = forms
        .iter()
        .filter_map(|form| match form {
            Form::Constant(constant) => Some(constant),
            _ => None,
        })
        .filter_map(|constant| {
            let value = eval::expr(&constant.value, &mut env).unwrap_or_else(|err| {
                panic!("failed to evaluate {}:{}: {err}", path.display(), constant.name())
            });
            match value {
                ConstantExpr::Int(value) => {
                    let value = value.inner().as_int();
                    let name = constant.name().as_str();
                    is_address(name, value).then(|| {
                        let referenced_addresses = constant
                            .value
                            .references()
                            .into_iter()
                            .filter_map(|reference| {
                                let name = reference.to_string();
                                let value = eval::expr(&ConstantExpr::Var(reference), &mut env)
                                    .expect("address reference evaluates")
                                    .expect_int()
                                    .as_int();
                                is_address(&name, value).then_some(value)
                            })
                            .collect();
                        AddressDeclaration {
                            name: name.to_string(),
                            address: value,
                            referenced_addresses,
                        }
                    })
                },
                ConstantExpr::String(_) | ConstantExpr::Word(_) | ConstantExpr::Hash(..) => None,
                ConstantExpr::Var(_) | ConstantExpr::BinaryOp { .. } => panic!(
                    "{}:{} has an unevaluated numeric constant expression",
                    path.display(),
                    constant.name()
                ),
            }
        })
        .collect();

    let source = std::fs::read_to_string(path).expect("MASM module is readable");
    for line in source.lines() {
        let Some((name, description)) =
            line.trim().strip_prefix("### ").and_then(|line| line.split_once(": "))
        else {
            continue;
        };
        let Some((_, range)) = description.split_once(" felts at ") else {
            continue;
        };
        let (start, _) = range.split_once("..").expect("documented allocation has a range");
        let address = start.parse::<u64>().expect("documented allocation has an address");
        if let Some(declared) = declarations.iter().find(|declared| declared.name == name) {
            assert_eq!(
                declared.address, address,
                "documented address for {name} differs from MASM"
            );
        } else {
            declarations.push(AddressDeclaration {
                name: name.to_string(),
                address,
                referenced_addresses: Vec::new(),
            });
        }
    }
    let mut visitor = AccessVisitor { env: &mut env, accesses: Vec::new() };
    assert!(visitor.visit_module(&module).is_continue());
    (declarations, visitor.accesses)
}

fn region(source: &str, name: String, address: u64, offset: i64, felts: u64) -> Region {
    assert!(felts > 0, "{source}:{name} has an empty region");
    let lo = if offset < 0 {
        address.checked_sub(offset.unsigned_abs())
    } else {
        address.checked_add(offset as u64)
    }
    .unwrap_or_else(|| panic!("{source}:{name} region start overflows"));
    let hi = lo
        .checked_add(felts - 1)
        .unwrap_or_else(|| panic!("{source}:{name} region end overflows"));
    Region { source: source.to_string(), name, lo, hi }
}

fn collect_masm_files(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("MASM directory is readable") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            collect_masm_files(&path, files);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("masm") {
            files.push(path);
        }
    }
}

fn overlaps(a: &Region, b: &Region) -> bool {
    a.lo <= b.hi && b.lo <= a.hi
}

fn assert_disjoint(regions: &[&Region], label: &str) {
    for (index, region) in regions.iter().enumerate() {
        if let Some(other) = regions[index + 1..].iter().find(|other| overlaps(region, other)) {
            panic!(
                "{label} region {}:{} ({}..={}) overlaps {}:{} ({}..={})",
                region.source,
                region.name,
                region.lo,
                region.hi,
                other.source,
                other.name,
                other.lo,
                other.hi
            );
        }
    }
}

fn namespace(source: &str) -> &str {
    source.split_once('/').expect("address source has a namespace").0
}

fn assert_tiled_frame(regions: &[&Region], owner: &str, frame_start: u64, frame_end: u64) {
    let mut frame_regions = Vec::new();
    for region in regions.iter().filter(|region| namespace(&region.source) == owner) {
        if region.lo < frame_end && frame_start <= region.hi {
            assert!(
                frame_start <= region.lo && region.hi < frame_end,
                "{}:{} crosses the {} frame boundary",
                region.source,
                region.name,
                owner
            );
            frame_regions.push(*region);
        }
    }
    frame_regions.sort_unstable_by_key(|region| region.lo);

    let mut next = frame_start;
    for region in frame_regions {
        assert_eq!(
            region.lo, next,
            "gap before {}:{} in the {} frame",
            region.source, region.name, owner
        );
        next = region.hi.checked_add(1).expect("frame address overflows");
    }
    assert_eq!(next, frame_end, "{owner} frame does not end at its declared boundary");
}

/// Every fixed verifier-memory region must be declared, disjoint, and correctly sized.
///
/// The generic module and each relation's layout and parameter modules share one memory map.
/// A generic constant added at an address a relation already uses would assemble cleanly and
/// corrupt that relation's state at runtime. This manifest checks allocations across those modules.
///
/// Allocations have explicit extents; field aliases must remain within their base allocation.
/// Immediate memory accesses must fit in that allocation, including all four cells of a word.
#[test]
fn verifier_memory_layout_is_complete_dense_and_disjoint() {
    let base = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/asm"));
    let exports = miden_core_lib::CoreLibrary::default()
        .package()
        .manifest
        .exports()
        .filter_map(|export| export.as_constant())
        .map(|constant| {
            (
                constant.path.to_string().trim_start_matches("::").to_string(),
                constant.value.clone().into(),
            )
        })
        .collect();
    let generic_path = base.join("stark/constants.masm");
    let (generic_declarations, generic_accesses) = declarations(&generic_path, &exports);
    assert!(!generic_declarations.is_empty(), "the generic layer must declare addresses");
    let mut accesses = vec![("stark/constants.masm".to_string(), generic_accesses)];
    let mut aliases = Vec::new();

    let mut generic_manifest: BTreeMap<&str, (i64, u64)> = BTreeMap::new();
    for &(name, offset, felts) in GENERIC_REGIONS {
        assert!(
            generic_manifest.insert(name, (offset, felts)).is_none(),
            "duplicate generic region manifest entry: {name}"
        );
    }
    let mut generic_regions = Vec::new();
    for AddressDeclaration { name, address, referenced_addresses } in generic_declarations {
        if let Some((offset, felts)) = generic_manifest.remove(name.as_str()) {
            generic_regions.push(region("stark/constants.masm", name, address, offset, felts));
        } else {
            let [base_address] = referenced_addresses.as_slice() else {
                panic!("unmanifested generic address: {name}");
            };
            aliases.push(("stark/constants.masm".to_string(), name, address, *base_address));
        }
    }
    assert!(
        generic_manifest.is_empty(),
        "generic region manifest entries have no declaration: {:?}",
        generic_manifest.keys().collect::<Vec<_>>()
    );

    let mut shared_files = Vec::new();
    collect_masm_files(&base.join("stark"), &mut shared_files);
    collect_masm_files(&base.join("pcs"), &mut shared_files);
    shared_files.sort();
    for path in shared_files.into_iter().filter(|path| path != &generic_path) {
        let source = path
            .strip_prefix(base)
            .expect("shared module is below asm")
            .to_string_lossy()
            .replace('\\', "/");
        let (source_constants, source_accesses) = declarations(&path, &exports);
        accesses.push((source.clone(), source_accesses));
        for AddressDeclaration { name, address, referenced_addresses } in source_constants {
            let [base_address] = referenced_addresses.as_slice() else {
                panic!("unmanifested shared address: {source}:{name}");
            };
            aliases.push((source.clone(), name, address, *base_address));
        }
    }

    let sys = base.join("sys");
    let mut relation_files = Vec::new();
    collect_masm_files(&sys, &mut relation_files);
    relation_files.sort();

    let mut relation_manifest: BTreeMap<(String, String), (i64, RegionExtent)> = BTreeMap::new();
    for &(source, name, offset, extent) in RELATION_REGIONS {
        assert!(
            relation_manifest
                .insert((source.to_string(), name.to_string()), (offset, extent))
                .is_none(),
            "duplicate relation region manifest entry: {source}:{name}"
        );
    }

    let mut relation_declarations = BTreeMap::new();
    for path in relation_files {
        let source = path
            .strip_prefix(&sys)
            .expect("relation module is below asm/sys")
            .to_string_lossy()
            .replace('\\', "/");
        let mut source_declarations = BTreeMap::new();
        let (source_constants, source_accesses) = declarations(&path, &exports);
        accesses.push((source.clone(), source_accesses));
        for declaration in source_constants {
            let AddressDeclaration { name, address, referenced_addresses } = declaration;
            if !relation_manifest.contains_key(&(source.clone(), name.clone())) {
                let [base_address] = referenced_addresses.as_slice() else {
                    panic!("unmanifested relation address: {source}:{name}");
                };
                aliases.push((source.clone(), name, address, *base_address));
                continue;
            }
            assert!(
                source_declarations.insert(name.clone(), address).is_none(),
                "duplicate relation address declaration: {source}:{name}"
            );
        }
        if !source_declarations.is_empty() {
            assert!(
                relation_declarations.insert(source.clone(), source_declarations).is_none(),
                "relation source visited twice: {source}"
            );
        }
    }

    // Boundary names are shared by a relation's modules, with VM and PVM kept separate.
    let mut relation_addresses = BTreeMap::new();
    for (source, declarations) in &relation_declarations {
        let owner = namespace(source);
        for (name, &address) in declarations {
            assert!(
                relation_addresses.insert((owner, name.as_str()), address).is_none(),
                "duplicate address name in relation {owner}: {name}"
            );
        }
    }

    let extent_between = |source: &str, start: &str, end: &str| {
        let owner = namespace(source);
        let start_address = relation_addresses
            .get(&(owner, start))
            .unwrap_or_else(|| panic!("{owner} relation is missing extent boundary {start}"));
        let end_address = relation_addresses
            .get(&(owner, end))
            .unwrap_or_else(|| panic!("{owner} relation is missing extent boundary {end}"));
        end_address
            .checked_sub(*start_address)
            .unwrap_or_else(|| panic!("{source}:{end} precedes {start}"))
    };

    let mut relation_regions = Vec::new();
    for (source, declarations) in &relation_declarations {
        for (name, &address) in declarations {
            let (offset, extent) = relation_manifest
                .remove(&(source.clone(), name.clone()))
                .unwrap_or_else(|| panic!("unmanifested relation address: {source}:{name}"));
            let felts = match extent {
                Fixed(felts) => felts,
                Until(end) => extent_between(source, name, end),
                UntilAddress(end) => end
                    .checked_sub(address)
                    .unwrap_or_else(|| panic!("{source}:{name} begins after its frame boundary")),
                FractionOf { start, end, divisor } => {
                    assert_ne!(divisor, 0, "{source}:{name} has a zero extent divisor");
                    let span = extent_between(source, start, end);
                    assert_eq!(
                        span % divisor,
                        0,
                        "{source}:{name} source span is not divisible by {divisor}"
                    );
                    span / divisor
                },
            };
            relation_regions.push(region(source, name.clone(), address, offset, felts));
        }
    }
    assert!(
        relation_manifest.is_empty(),
        "relation region manifest entries have no declaration: {:?}",
        relation_manifest.keys().collect::<Vec<_>>()
    );

    for relation in &relation_regions {
        if let Some(generic) = generic_regions.iter().find(|generic| overlaps(relation, generic)) {
            panic!(
                "relation region {}:{} ({}..={}) overlaps generic region {}:{} ({}..={})",
                relation.source,
                relation.name,
                relation.lo,
                relation.hi,
                generic.source,
                generic.name,
                generic.lo,
                generic.hi
            );
        }
    }

    let canonical_generic_regions: Vec<_> = generic_regions
        .iter()
        .filter(|region| !GENERIC_ALIASES.contains(&region.name.as_str()))
        .collect();
    let heights = generic_regions
        .iter()
        .find(|region| region.name == "LOG_AIR_TRACE_LENGTHS_PTR")
        .expect("the per-AIR height array is allocated");
    assert!(
        heights.hi - heights.lo + 1 >= miden_ace::MAX_ORDER_AIRS as u64,
        "the height array must hold every supported AIR"
    );
    let relation_region_refs: Vec<_> = relation_regions.iter().collect();
    let pvm_frame_end = relation_regions
        .iter()
        .find(|region| region.source == "pvm/layout.masm" && region.name == "PROOF_ORDER_IDS_PTR")
        .and_then(|region| region.hi.checked_add(1))
        .expect("the terminal PVM proof-order-IDs region must define the frame end");

    assert_disjoint(&canonical_generic_regions, "generic");
    assert_disjoint(&relation_region_refs, "relation");

    // Shared modules use generic allocations; relation modules can also use their own.
    let allocation_for = |source: &str, address: u64| {
        canonical_generic_regions
            .iter()
            .copied()
            .chain(
                relation_regions
                    .iter()
                    .filter(|region| namespace(&region.source) == namespace(source)),
            )
            .find(|region| region.lo <= address && address <= region.hi)
    };

    for (source, name, address, base_address) in aliases {
        let allocation = allocation_for(&source, base_address).unwrap_or_else(|| {
            panic!("{source}:{name} references an unallocated address {base_address}")
        });
        assert!(
            allocation.lo <= address && address <= allocation.hi,
            "{source}:{name} ({address}) escapes {}:{} ({}..={})",
            allocation.source,
            allocation.name,
            allocation.lo,
            allocation.hi
        );
    }

    for (source, source_accesses) in accesses {
        for MemoryAccess { address, width } in source_accesses {
            let allocation = allocation_for(&source, address)
                .unwrap_or_else(|| panic!("{source} accesses unallocated address {address}"));
            let end = address.checked_add(width - 1).expect("memory access end overflows");
            assert!(
                end <= allocation.hi,
                "{source} access at {address} spans {width} felts and escapes {}:{} ({}..={})",
                allocation.source,
                allocation.name,
                allocation.lo,
                allocation.hi
            );
        }
    }

    let lde_info = generic_regions
        .iter()
        .find(|region| region.name == "LDE_DOMAIN_INFO_PTR")
        .expect("LDE domain info region is declared");
    for alias in GENERIC_ALIASES {
        let region = generic_regions
            .iter()
            .find(|region| region.name == *alias)
            .unwrap_or_else(|| panic!("missing generic alias: {alias}"));
        assert!(
            lde_info.lo <= region.lo && region.hi <= lde_info.hi,
            "{alias} must remain inside LDE_DOMAIN_INFO_PTR"
        );
    }

    assert_tiled_frame(&canonical_generic_regions, "stark", GENERIC_FRAME_START, GENERIC_FRAME_END);
    assert_tiled_frame(&relation_region_refs, "vm", GENERIC_FRAME_END, VM_FRAME_END);
    assert_tiled_frame(&relation_region_refs, "vm", VM_ACE_READ_START, PVM_FRAME_START);
    assert_tiled_frame(&relation_region_refs, "pvm", PVM_FRAME_START, pvm_frame_end);

    let kernel_witness = relation_regions
        .iter()
        .find(|region| region.source == "vm/layout.masm" && region.name == "KERNEL_WITNESS_PTR")
        .expect("VM kernel witness region is declared");
    assert_eq!(
        kernel_witness.hi - kernel_witness.lo + 1,
        (miden_core::program::KernelDescriptor::MAX_NUM_PROCEDURES * 4) as u64,
        "the VM kernel witness must hold the maximum number of procedure digests"
    );
}
