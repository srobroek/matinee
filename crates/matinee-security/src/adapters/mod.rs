//! Private platform seams.
//!
//! Each seam returns opaque custody and closed, redacted outcomes. Nothing here is
//! re-exported: an adapter is reachable only from inside this crate.

pub(crate) mod credential_store;
pub(crate) mod os_pipe;
