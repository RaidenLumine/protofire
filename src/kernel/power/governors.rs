//! src/kernel/power/governors.rs
//!
//! CPU frequency scaling governors.

// ============================================================================
// Type definitions
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernorType {
    Performance, // max performance: always run at max frequency
    Powersave,   // power saving: always run at min frequency
    Ondemand,    // on-demand: scale up on load, down slowly
    Schedutil,   // scheduler load: direct mapping
    Userspace,   // user-controlled: never scales automatically
}

impl GovernorType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Performance => "performance",
            Self::Powersave => "powersave",
            Self::Ondemand => "ondemand",
            Self::Schedutil => "schedutil",
            Self::Userspace => "userspace",
        }
    }
}

// ============================================================================
// Ondemand parameters
// ============================================================================

const ONDEMAND_UP_THRESHOLD: u8 = 80; // scale up when load > 80%
const ONDEMAND_DOWN_THRESHOLD: u8 = 25; // scale down when load < 25%
const ONDEMAND_STEP_PERCENT: u32 = 10; // step up by 10% each time

// ============================================================================
// Schedutil parameters
// ============================================================================

const SCHEDUTIL_UP_RATE: u8 = 15; // scale up when load rises 15%
const SCHEDUTIL_DOWN_RATE: u8 = 10; // scale down when load drops 10%

// ============================================================================
// Core logic
// ============================================================================

/// Compute the target frequency for a governor.
///
/// `min_freq`/`max_freq`/`current` are in KHz; `load` is the CPU-busy ratio
/// in 0..=100.  Returns `None` when no frequency change is warranted (or for
/// `Userspace`, which never scales automatically).  The caller passes the
/// current frequency as a snapshot so the pure policy logic stays
/// unit-testable.
pub fn calculate_target(
    gov: GovernorType,
    load: u8,
    min_freq: u32,
    max_freq: u32,
    current: u32,
) -> Option<u32> {
    if max_freq <= min_freq {
        return None;
    }
    let load = load.min(100);

    match gov {
        GovernorType::Performance => Some(max_freq),
        GovernorType::Powersave => Some(min_freq),
        GovernorType::Userspace => None,

        GovernorType::Ondemand => {
            // Sampling throttle lives in the scheduler: `update_policy` calls this at 1 Hz.
            if load >= ONDEMAND_UP_THRESHOLD {
                // Scale up quickly
                let step =
                    ((max_freq - min_freq) as u64 * ONDEMAND_STEP_PERCENT as u64 / 100) as u32;
                let step = step.max(50_000); // at least 50 MHz
                Some(current.saturating_add(step).min(max_freq))
            } else if load <= ONDEMAND_DOWN_THRESHOLD {
                // Scale down slowly
                let step =
                    ((current - min_freq) as u64 * ONDEMAND_STEP_PERCENT as u64 / 100 / 2) as u32;
                let step = step.max(25_000); // at least 25 MHz
                Some(current.saturating_sub(step).max(min_freq))
            } else {
                None
            }
        }

        GovernorType::Schedutil => {
            // Map the scheduler load directly to a frequency
            let target_freq = min_freq + ((max_freq - min_freq) as u64 * load as u64 / 100) as u32;

            // Extreme loads set the bounds directly
            match load {
                95..=100 => return Some(max_freq),
                0..=5 => return Some(min_freq),
                _ => {}
            }

            // Prevent frequency jitter: add hysteresis
            if target_freq > current {
                // Scale up: load must be high enough
                if load >= SCHEDUTIL_UP_RATE {
                    Some(target_freq)
                } else {
                    None
                }
            } else if target_freq < current {
                // Scale down: load must be low enough
                if load < 100 - SCHEDUTIL_DOWN_RATE {
                    Some(target_freq)
                } else {
                    None
                }
            } else {
                None
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governor_names_are_stable() {
        assert_eq!(GovernorType::Performance.name(), "performance");
        assert_eq!(GovernorType::Powersave.name(), "powersave");
        assert_eq!(GovernorType::Ondemand.name(), "ondemand");
        assert_eq!(GovernorType::Schedutil.name(), "schedutil");
        assert_eq!(GovernorType::Userspace.name(), "userspace");
    }

    #[test]
    fn userspace_never_scales() {
        assert_eq!(
            calculate_target(GovernorType::Userspace, 50, 100_000, 400_000, 200_000),
            None
        );
    }

    #[test]
    fn performance_always_returns_max() {
        assert_eq!(
            calculate_target(GovernorType::Performance, 0, 100_000, 400_000, 200_000),
            Some(400_000)
        );
        assert_eq!(
            calculate_target(GovernorType::Performance, 100, 100_000, 400_000, 200_000),
            Some(400_000)
        );
    }

    #[test]
    fn powersave_always_returns_min() {
        assert_eq!(
            calculate_target(GovernorType::Powersave, 100, 100_000, 400_000, 200_000),
            Some(100_000)
        );
    }

    #[test]
    fn schedutil_maps_load_to_frequency() {
        // Load 50% of range [100k, 400k] → 250 MHz, well within hysteresis.
        let target = calculate_target(GovernorType::Schedutil, 50, 100_000, 400_000, 200_000);
        assert_eq!(target, Some(250_000));
    }

    #[test]
    fn schedutil_extremes_are_direct() {
        assert_eq!(
            calculate_target(GovernorType::Schedutil, 95, 100_000, 400_000, 200_000),
            Some(400_000)
        );
        assert_eq!(
            calculate_target(GovernorType::Schedutil, 5, 100_000, 400_000, 200_000),
            Some(100_000)
        );
    }

    #[test]
    fn schedutil_prevents_frequency_jitter() {
        // Up-move blocked: load 14 % maps to 142 MHz, but a raise from
        // 140 MHz requires load >= 15, so the frequency holds.
        assert_eq!(
            calculate_target(GovernorType::Schedutil, 14, 100_000, 400_000, 140_000),
            None
        );

        // Down-move blocked: load 90 % maps to 370 MHz, but a cut from
        // 400 MHz requires load < 90, so the frequency holds.
        assert_eq!(
            calculate_target(GovernorType::Schedutil, 90, 100_000, 400_000, 400_000),
            None
        );

        // A large load drop (5%) forces the floor directly.
        assert_eq!(
            calculate_target(GovernorType::Schedutil, 5, 100_000, 400_000, 250_000),
            Some(100_000)
        );
    }

    #[test]
    fn ondemand_raises_frequency_on_high_load() {
        let target = calculate_target(GovernorType::Ondemand, 90, 100_000, 400_000, 200_000);
        assert!(target.is_some());
        let target = target.unwrap();
        assert!((200_000..=400_000).contains(&target));
        assert!(target > 200_000);
    }

    #[test]
    fn ondemand_lowers_frequency_on_low_load() {
        let target = calculate_target(GovernorType::Ondemand, 10, 100_000, 400_000, 300_000);
        assert!(target.is_some());
        let target = target.unwrap();
        assert!((100_000..=300_000).contains(&target));
        assert!(target < 300_000);
    }

    #[test]
    fn degenerate_range_returns_none() {
        assert_eq!(
            calculate_target(GovernorType::Performance, 50, 400_000, 400_000, 400_000),
            None
        );
    }
}
