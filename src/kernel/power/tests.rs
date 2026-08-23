//! src/kernel/power/tests.rs
//! Host-side unit tests for the power-management subsystem.

use super::governors::{calculate_target, GovernorType};

/// The power subsystem is inert without an architecture driver: the default
/// governor is still installed, but policy updates never reach the hardware.
/// These tests exercise the pieces that are meaningful on the host (policy
/// pure functions); driver probing itself is a bare-metal concern.
#[test]
fn governor_policy_pure_logic_is_stable() {
    // Performance is always the ceiling, Powersave the floor, Userspace inert.
    assert_eq!(
        calculate_target(GovernorType::Performance, 42, 100_000, 400_000, 100_000),
        Some(400_000)
    );
    assert_eq!(
        calculate_target(GovernorType::Powersave, 42, 100_000, 400_000, 400_000),
        Some(100_000)
    );
    assert_eq!(
        calculate_target(GovernorType::Userspace, 42, 100_000, 400_000, 200_000),
        None
    );
}

#[test]
fn schedutil_tracks_load() {
    // Linear mapping: 50% of [100k, 400k] from a 200k baseline → 250 MHz.
    assert_eq!(
        calculate_target(GovernorType::Schedutil, 50, 100_000, 400_000, 200_000),
        Some(250_000)
    );
}
