//! Stable public failure codes for the MVP boundaries.
//!
//! The string form of each code is the wire value.

use std::fmt;

/// A stable, caller-visible failure code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FailureCode {
    /// Another process owns the state directory.
    DaemonStartConflict,
    /// The daemon instance changed after the client connected.
    DaemonRestarted,
    /// The extension disconnected before an operation outcome was observed.
    ExtensionDisconnected,
    /// The operation target disappeared before its outcome was observed.
    TargetLost,
    /// The operation deadline elapsed before its outcome was observed.
    DeadlineExpired,
    /// The candidate revision expired or no longer matches.
    CandidateRevisionStale,
    /// The document generation changed before dispatch.
    GenerationStale,
    /// The tab incarnation no longer exists.
    IncarnationStale,
    /// An idempotency key was reused with a different request fingerprint.
    IdempotencyConflict,
    /// The principal does not own the target.
    AuthorizationDenied,
    /// The origin is not the pinned fixture or extension origin.
    OriginRejected,
    /// The state-directory lock or in-memory registry is unavailable.
    StorageUnavailable,
}

impl FailureCode {
    /// Returns the stable wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DaemonStartConflict => "daemon.start_conflict",
            Self::DaemonRestarted => "daemon.restarted",
            Self::ExtensionDisconnected => "operation.extension_disconnected",
            Self::TargetLost => "operation.target_lost",
            Self::DeadlineExpired => "operation.deadline_expired",
            Self::CandidateRevisionStale => "candidate.revision_stale",
            Self::GenerationStale => "generation.stale",
            Self::IncarnationStale => "incarnation.stale",
            Self::IdempotencyConflict => "idempotency.conflict",
            Self::AuthorizationDenied => "authorization.denied",
            Self::OriginRejected => "origin.rejected",
            Self::StorageUnavailable => "storage.unavailable",
        }
    }

    /// Reports whether a caller may retry the same request unchanged.
    pub const fn retryable(self) -> bool {
        matches!(self, Self::DaemonStartConflict | Self::StorageUnavailable)
    }
}

impl fmt::Display for FailureCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
