use clap::Args;
use miden_vm::{ExecutionOptions, HASH_WORK, MSM_WORK, PrecompileLimits, WorkLimit};

use super::utils::parse_byte_size;

#[derive(Debug, Clone, Default, Args)]
pub struct PrecompileArgs {
    /// Maximum structural field elements in each precompile accounting scope
    ///
    /// run/prove apply supplied ceilings independently to execution and verification;
    /// verify applies only its verification policy. Unspecified limits retain their
    /// library defaults. Zero is a real ceiling.
    /// Hard transport, allocation, and root-count safety ceilings remain in force.
    #[arg(long, value_name = "ELEMENTS")]
    max_precompile_elements: Option<u64>,

    /// Maximum total hash input bytes in each accounting scope (512M, 32Gi)
    ///
    /// Accepts bare bytes or K/M/G/Ki/Mi/Gi suffixes. The per-hash item limit is unchanged.
    #[arg(long, value_name = "BYTES", value_parser = parse_byte_size)]
    max_precompile_hash_bytes: Option<u64>,

    /// Maximum terms in one MSM, independently of the total term ceiling
    #[arg(long, value_name = "TERMS")]
    max_precompile_msm_terms: Option<u32>,

    /// Maximum total MSM terms in each accounting scope, independently of the per-MSM ceiling
    #[arg(long, value_name = "TERMS")]
    max_precompile_total_msm_terms: Option<u64>,
}

impl PrecompileArgs {
    pub fn apply_to(&self, options: ExecutionOptions) -> ExecutionOptions {
        let execution = self.apply(options.execution_precompile_limits().clone());
        let verification = self.apply(options.verification_precompile_limits().clone());
        options
            .with_execution_precompile_limits(execution)
            .with_verification_precompile_limits(verification)
    }

    pub fn apply(&self, mut limits: PrecompileLimits) -> PrecompileLimits {
        if let Some(elements) = self.max_precompile_elements {
            limits = limits.with_max_elements(elements);
        }
        if let Some(bytes) = self.max_precompile_hash_bytes {
            let hash = limits.class(HASH_WORK).expect("library policy includes hash work");
            limits = limits.with_class(HASH_WORK, WorkLimit { max_total_size: bytes, ..hash });
        }
        if self.max_precompile_msm_terms.is_some() || self.max_precompile_total_msm_terms.is_some()
        {
            let msm = limits.class(MSM_WORK).expect("library policy includes MSM work");
            limits = limits.with_class(
                MSM_WORK,
                WorkLimit {
                    max_size: self.max_precompile_msm_terms.unwrap_or(msm.max_size),
                    max_total_size: self
                        .max_precompile_total_msm_terms
                        .unwrap_or(msm.max_total_size),
                    ..msm
                },
            );
        }
        limits
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use miden_vm::{default_execution_precompile_limits, default_verification_precompile_limits};

    use super::*;

    #[derive(Parser)]
    struct Command {
        #[command(flatten)]
        limits: PrecompileArgs,
    }

    #[test]
    fn optional_overrides_preserve_scope_defaults_and_other_fields() {
        let execution = default_execution_precompile_limits();
        let hash = execution.class(HASH_WORK).unwrap();
        let options = ExecutionOptions::default().with_execution_precompile_limits(
            execution.with_class(HASH_WORK, WorkLimit { max_count: 3, ..hash }),
        );
        let unchanged = PrecompileArgs::default().apply_to(options.clone());
        assert_eq!(unchanged.execution_precompile_limits(), options.execution_precompile_limits());
        assert_eq!(
            unchanged.verification_precompile_limits(),
            &default_verification_precompile_limits()
        );

        for (args, size, total) in [
            (vec!["--max-precompile-msm-terms", "16"], Some(16), None),
            (vec!["--max-precompile-total-msm-terms", "64"], None, Some(64)),
            (
                vec!["--max-precompile-msm-terms", "16", "--max-precompile-total-msm-terms", "64"],
                Some(16),
                Some(64),
            ),
        ] {
            let cmd = Command::try_parse_from(
                ["test", "--max-precompile-elements", "0", "--max-precompile-hash-bytes", "16Mi"]
                    .into_iter()
                    .chain(args),
            )
            .unwrap();
            let actual = cmd.limits.apply_to(options.clone());
            for (base, actual) in [
                (options.execution_precompile_limits(), actual.execution_precompile_limits()),
                (
                    options.verification_precompile_limits(),
                    actual.verification_precompile_limits(),
                ),
            ] {
                let hash = base.class(HASH_WORK).unwrap();
                let msm = base.class(MSM_WORK).unwrap();
                assert_eq!(
                    actual,
                    &base
                        .clone()
                        .with_max_elements(0)
                        .with_class(HASH_WORK, WorkLimit { max_total_size: 16 << 20, ..hash })
                        .with_class(
                            MSM_WORK,
                            WorkLimit {
                                max_size: size.unwrap_or(msm.max_size),
                                max_total_size: total.unwrap_or(msm.max_total_size),
                                ..msm
                            }
                        )
                );
            }
        }
    }
}
