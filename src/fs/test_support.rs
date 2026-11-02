//! src/fs/test_support.rs
//!
//! Test-support helpers for host-side tests.
//!
//! The former PyroFs zone-image builders (`build_test_zone_image` and
//! `build_minimal_test_zone_image`) had no callers in any build and were
//! removed.  Code that needs a PyroFs image should call
//! `PyroFs::build_image` directly.
