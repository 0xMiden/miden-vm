//! Validates that synthetic benchmarks match their source profiles

use crate::profile::VmProfile;
use anyhow::{Result, bail};

/// Validates a VM profile for correctness
pub struct ProfileValidator;

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
        let phase_total: u64 = profile.transaction_kernel.phases.values()
            .map(|p| p.cycles)
            .sum();

        if phase_total == 0 {
            bail!("Total cycles is zero");
        }

        // Allow 1% tolerance
        let diff = if phase_total > profile.transaction_kernel.total_cycles {
            phase_total - profile.transaction_kernel.total_cycles
        } else {
            profile.transaction_kernel.total_cycles - phase_total
        };

        let tolerance = profile.transaction_kernel.total_cycles / 100;
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
        ProfileDiff {
            total_cycles_delta: current.transaction_kernel.total_cycles as i64
                - baseline.transaction_kernel.total_cycles as i64,
            phase_deltas: self.compare_phases(baseline, current),
        }
    }

    fn compare_phases(&self, baseline: &VmProfile, current: &VmProfile) -> Vec<PhaseDelta> {
        let mut deltas = Vec::new();

        for (name, current_phase) in &current.transaction_kernel.phases {
            if let Some(baseline_phase) = baseline.transaction_kernel.phases.get(name) {
                let delta = current_phase.cycles as i64 - baseline_phase.cycles as i64;
                let pct_change = (delta as f64 / baseline_phase.cycles as f64) * 100.0;

                deltas.push(PhaseDelta {
                    name: name.clone(),
                    cycles_delta: delta,
                    percent_change: pct_change,
                });
            }
        }

        deltas
    }
}

#[derive(Debug)]
pub struct ProfileDiff {
    pub total_cycles_delta: i64,
    pub phase_deltas: Vec<PhaseDelta>,
}

#[derive(Debug)]
pub struct PhaseDelta {
    pub name: String,
    pub cycles_delta: i64,
    pub percent_change: f64,
}
