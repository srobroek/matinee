//! Daemon for the Matinee MVP: in-memory state, lifecycle, sessions, and transports.
//!
//! The registry is process-local by design. A daemon restart starts with no
//! requests, sessions, operations, or artifact metadata.

mod control_auth;
pub mod failure;
pub mod lifecycle;
pub mod record;
pub mod registry;
pub mod server;
