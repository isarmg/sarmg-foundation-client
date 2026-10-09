//! Client-only common support in one physical Rust package.
//! Desktop lifecycle stays desktop-only; protected storage, logs and mobile
//! mechanisms retain their platform-specific ownership and safety contracts.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub mod cli;
pub mod contracts;
pub mod error;
pub mod fs_safety;
pub mod log;
#[cfg(feature = "mobile-ffi")]
pub mod mobile_ffi;
pub mod runtime;
pub mod schema_identity;
pub mod secret;
pub mod secret_envelope;
pub mod secure_xml;
#[cfg(all(target_os = "linux", feature = "offline-maintenance"))]
pub mod sqlite;
#[cfg(all(target_os = "linux", feature = "offline-maintenance"))]
pub mod state_file;
