//! src/kernel/network/link/mod.rs
//!
//! Link-layer modules: network device abstraction, Ethernet framing, and
//! educational protocol simulations (CSMA/CD, CSMA/CA, STP).
pub mod device;
pub mod ethernet;

// Educational networking modules — see individual files for pedagogical context.
#[cfg(any(test, feature = "educational_networking"))]
pub mod csma_ca;
#[cfg(any(test, feature = "educational_networking"))]
pub mod csma_cd;
#[cfg(any(test, feature = "educational_networking"))]
pub mod stp;
