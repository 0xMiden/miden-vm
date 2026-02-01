//! Validates that synthetic benchmarks match their source profiles

use anyhow::{bail, Result};

use crate::profile::VmProfile;

/// Validates a VM profile for correctness
pub struct ProfileValidator;

impl Default for ProfileValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl ProfileValidator {
    pub fn new() -> Self {
        Self
    }

    /// Validate a profile
    pub fn validate(&self, profile: &VmProfile) -> Result<()> {
        // Check version
        if profile.profile_version != "1.0" {
            bail!("Unsupported profile version: {}", profile.profile_version);
        }

        // Validate instruction mix sums to ~1.0
        profile.transaction_kernel.instruction_mix.validate()?;

        // Check that total cycles matches sum of phases
        let phase_total: u64 = profile.transaction_kernel.phases.values().map(|p| p.cycles).sum();

        if phase_total == 0 {
            bail!("Total cycles is zero");
        }

        // Allow 1% tolerance, with minimum of 1 to avoid zero tolerance for small profiles
        let diff = phase_total.abs_diff(profile.transaction_kernel.total_cycles);

        let tolerance = (profile.transaction_kernel.total_cycles / 100).max(1);
        if diff > tolerance {
            bail!(
                "Phase cycle sum ({}) differs from total ({}) by more than 1%",
                phase_total,
                profile.transaction_kernel.total_cycles
            );
        }

        Ok(())
    }

    /// Compare two profiles and report differences
    pub fn compare_profiles(&self, baseline: &VmProfile, current: &VmProfile) -> ProfileDiff {
        let (phase_deltas, missing_phases, new_phases) = self.compare_phases(baseline, current);

        ProfileDiff {
            total_cycles_delta: current.transaction_kernel.total_cycles as i64
                - baseline.transaction_kernel.total_cycles as i64,
            phase_deltas,
            missing_phases,
            new_phases,
        }
    }

    fn compare_phases(
        &self,
        baseline: &VmProfile,
        current: &VmProfile,
    ) -> (Vec<PhaseDelta>, Vec<String>, Vec<String>) {
        let mut deltas = Vec::new();
        let mut missing_phases = Vec::new();
        let mut new_phases = Vec::new();

        // Find phases in current that differ from or are missing in baseline
        for (name, current_phase) in &current.transaction_kernel.phases {
            if let Some(baseline_phase) = baseline.transaction_kernel.phases.get(name) {
                let delta = current_phase.cycles as i64 - baseline_phase.cycles as i64;
                let pct_change = if baseline_phase.cycles == 0 {
                    if current_phase.cycles == 0 {
                        0.0
                    } else {
                        f64::INFINITY
                    }
                } else {
                    (delta as f64 / baseline_phase.cycles as f64) * 100.0
                };

                deltas.push(PhaseDelta {
                    name: name.clone(),
                    cycles_delta: delta,
                    percent_change: pct_change,
                });
            } else {
                new_phases.push(name.clone());
            }
        }

        // Find phases in baseline that are missing in current
        for name in baseline.transaction_kernel.phases.keys() {
            if !current.transaction_kernel.phases.contains_key(name) {
                missing_phases.push(name.clone());
            }
        }

        (deltas, missing_phases, new_phases)
    }
}

#[derive(Debug)]
pub struct ProfileDiff {
    pub total_cycles_delta: i64,
    pub phase_deltas: Vec<PhaseDelta>,
    /// Phases present in baseline but missing in current
    pub missing_phases: Vec<String>,
    /// Phases present in current but not in baseline
    pub new_phases: Vec<String>,
}

#[derive(Debug)]
pub struct PhaseDelta {
    pub name: String,
    pub cycles_delta: i64,
    pub percent_change: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{InstructionMix, PhaseProfile, ProcedureProfile, TransactionKernelProfile};
    use std::collections::BTreeMap;

    fn create_test_profile(version: &str, total_cycles: u64, phases: BTreeMap<String, PhaseProfile>) -> VmProfile {
        VmProfile {
            profile_version: version.to_string(),
            source: "test".to_string(),
            timestamp: "2024-01-15T10:30:00Z".to_string(),
            miden_vm_version: "0.20.0".to_string(),
            transaction_kernel: TransactionKernelProfile {
                total_cycles,
                phases,
                instruction_mix: InstructionMix {
                    arithmetic: 0.2,
                    hashing: 0.2,
                    memory: 0.2,
                    control_flow: 0.2,
                    signature_verify: 0.2,
                },
                key_procedures: vec![ProcedureProfile {
                    name: "test".to_string(),
                    cycles: 100,
                    invocations: 1,
                }],
            },
        }
    }

    #[test]
    fn validate_valid_profile_passes() {
        let mut phases = BTreeMap::new();
        phases.insert("prologue".to_string(), PhaseProfile { cycles: 50, operations: BTreeMap::new() });
        phases.insert("epilogue".to_string(), PhaseProfile { cycles: 50, operations: BTreeMap::new() });

        let profile = create_test_profile("1.0", 100, phases);
        let validator = ProfileValidator::new();

        assert!(validator.validate(&profile).is_ok());
    }

    #[test]
    fn validate_unsupported_version_fails() {
        let mut phases = BTreeMap::new();
        phases.insert("prologue".to_string(), PhaseProfile { cycles: 100, operations: BTreeMap::new() });

        let profile = create_test_profile("2.0", 100, phases);
        let validator = ProfileValidator::new();

        let result = validator.validate(&profile);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported profile version"));
    }

    #[test]
    fn validate_zero_cycles_fails() {
        let phases = BTreeMap::new();
        let profile = create_test_profile("1.0", 0, phases);
        let validator = ProfileValidator::new();

        let result = validator.validate(&profile);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Total cycles is zero"));
    }

    #[test]
    fn validate_mismatched_totals_fails() {
        let mut phases = BTreeMap::new();
        phases.insert("prologue".to_string(), PhaseProfile { cycles: 50, operations: BTreeMap::new() });
        // total_cycles is 1000 but phases only sum to 50
        let profile = create_test_profile("1.0", 1000, phases);
        let validator = ProfileValidator::new();

        let result = validator.validate(&profile);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("differs from total"));
    }

    #[test]
    fn validate_small_profile_with_min_tolerance() {
        // Profile with total_cycles < 100 should still work with max(1) tolerance
        let mut phases = BTreeMap::new();
        phases.insert("prologue".to_string(), PhaseProfile { cycles: 10, operations: BTreeMap::new() });

        // total_cycles = 10, phases sum to 10, diff = 0, tolerance = max(10/100, 1) = 1
        let profile = create_test_profile("1.0", 10, phases);
        let validator = ProfileValidator::new();

        assert!(validator.validate(&profile).is_ok());
    }

    #[test]
    fn compare_profiles_detects_deltas() {
        let mut baseline_phases = BTreeMap::new();
        baseline_phases.insert("prologue".to_string(), PhaseProfile { cycles: 100, operations: BTreeMap::new() });

        let mut current_phases = BTreeMap::new();
        current_phases.insert("prologue".to_string(), PhaseProfile { cycles: 150, operations: BTreeMap::new() });

        let baseline = create_test_profile("1.0", 100, baseline_phases);
        let current = create_test_profile("1.0", 150, current_phases);

        let validator = ProfileValidator::new();
        let diff = validator.compare_profiles(&baseline, &current);

        assert_eq!(diff.total_cycles_delta, 50);
        assert_eq!(diff.phase_deltas.len(), 1);
        assert_eq!(diff.phase_deltas[0].name, "prologue");
        assert_eq!(diff.phase_deltas[0].cycles_delta, 50);
        assert_eq!(diff.phase_deltas[0].percent_change, 50.0);
    }

    #[test]
    fn compare_profiles_zero_baseline_cycles() {
        let mut baseline_phases = BTreeMap::new();
        baseline_phases.insert("prologue".to_string(), PhaseProfile { cycles: 0, operations: BTreeMap::new() });

        let mut current_phases = BTreeMap::new();
        current_phases.insert("prologue".to_string(), PhaseProfile { cycles: 50, operations: BTreeMap::new() });

        let baseline = create_test_profile("1.0", 0, baseline_phases);
        let current = create_test_profile("1.0", 50, current_phases);

        let validator = ProfileValidator::new();
        let diff = validator.compare_profiles(&baseline, &current);

        assert_eq!(diff.phase_deltas.len(), 1);
        assert_eq!(diff.phase_deltas[0].percent_change, f64::INFINITY);
    }

    #[test]
    fn compare_profiles_both_zero_cycles() {
        let mut baseline_phases = BTreeMap::new();
        baseline_phases.insert("prologue".to_string(), PhaseProfile { cycles: 0, operations: BTreeMap::new() });

        let mut current_phases = BTreeMap::new();
        current_phases.insert("prologue".to_string(), PhaseProfile { cycles: 0, operations: BTreeMap::new() });

        let baseline = create_test_profile("1.0", 0, baseline_phases);
        let current = create_test_profile("1.0", 0, current_phases);

        let validator = ProfileValidator::new();
        let diff = validator.compare_profiles(&baseline, &current);

        assert_eq!(diff.phase_deltas.len(), 1);
        assert_eq!(diff.phase_deltas[0].percent_change, 0.0);
    }

    #[test]
    fn compare_profiles_detects_missing_phases() {
        let mut baseline_phases = BTreeMap::new();
        baseline_phases.insert("prologue".to_string(), PhaseProfile { cycles: 100, operations: BTreeMap::new() });
        baseline_phases.insert("epilogue".to_string(), PhaseProfile { cycles: 100, operations: BTreeMap::new() });

        let mut current_phases = BTreeMap::new();
        current_phases.insert("prologue".to_string(), PhaseProfile { cycles: 100, operations: BTreeMap::new() });
        // epilogue is missing

        let baseline = create_test_profile("1.0", 200, baseline_phases);
        let current = create_test_profile("1.0", 100, current_phases);

        let validator = ProfileValidator::new();
        let diff = validator.compare_profiles(&baseline, &current);

        assert_eq!(diff.missing_phases.len(), 1);
        assert_eq!(diff.missing_phases[0], "epilogue");
    }

    #[test]
    fn compare_profiles_detects_new_phases() {
        let mut baseline_phases = BTreeMap::new();
        baseline_phases.insert("prologue".to_string(), PhaseProfile { cycles: 100, operations: BTreeMap::new() });

        let mut current_phases = BTreeMap::new();
        current_phases.insert("prologue".to_string(), PhaseProfile { cycles: 100, operations: BTreeMap::new() });
        current_phases.insert("new_phase".to_string(), PhaseProfile { cycles: 50, operations: BTreeMap::new() });

        let baseline = create_test_profile("1.0", 100, baseline_phases);
        let current = create_test_profile("1.0", 150, current_phases);

        let validator = ProfileValidator::new();
        let diff = validator.compare_profiles(&baseline, &current);

        assert_eq!(diff.new_phases.len(), 1);
        assert_eq!(diff.new_phases[0], "new_phase");
    }

    #[test]
    fn default_validator_works() {
        let validator = ProfileValidator::default();
        let mut phases = BTreeMap::new();
        phases.insert("prologue".to_string(), PhaseProfile { cycles: 100, operations: BTreeMap::new() });

        let profile = create_test_profile("1.0", 100, phases);
        assert!(validator.validate(&profile).is_ok());
    }
}
