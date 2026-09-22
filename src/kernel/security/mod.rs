//! src/kernel/security/mod.rs
//!
//! The security layer: identities, the token a request runs as, and the MAC
//! policy that labels subjects and objects.
//!
//! It sits below both `process` and `fs`.  The filesystem has to know who is
//! asking before it answers, and the process layer has to decide what a token
//! may do — neither should have to name the other to ask the question, which is
//! what `kernel::process::SecurityToken` used to force.
//!
//! `process` re-exports everything here, so the historical paths keep working:
//! `crate::kernel::process::SecurityToken` is the same type as
//! `crate::kernel::security::SecurityToken`.

pub mod mac;
pub mod token;

pub use mac::MacType;
pub use mac::MAC_TYPE_SYSTEM;
pub use mac::MAC_TYPE_UNTRUSTED;
pub use mac::MAC_TYPE_USER;
pub use token::GroupId;
pub use token::IntegrityLevel;
pub use token::SecurityToken;
pub use token::UserId;
pub use token::DEFAULT_GUEST_GROUP_ID;
pub use token::DEFAULT_GUEST_USER_ID;
pub use token::HANDLE_RIGHT_READ;
pub use token::HANDLE_RIGHT_WRITE;
pub use token::ROOT_GROUP_ID;
pub use token::ROOT_USER_ID;
