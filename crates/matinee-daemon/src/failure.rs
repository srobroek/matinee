//! Stable public failure codes for the MVP boundaries.
//!
//! Contract: `specs/006.5-demonstrable-browser-mvp/contracts/mcp-tools.md`.

use std::fmt;

/// A stable, caller-visible failure code.
///
/// The string form is the wire value and MUST NOT change without a contract
/// revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FailureCode {
    /// Another process owns the state directory.
    DaemonStartConflict,
    /// Stop or recovery cancelled work that never reached the browser.
    DaemonStoppedBeforeDispatch,
    /// An uncertain operation blocks a clean stop.
    DaemonStopBlocked,
    /// The extension cannot prove the outcome of a dispatched effect.
    OperationUncertain,
    /// A dispatched effect has no authoritative result.
    ReconciliationRequired,
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
    /// The durable store is unavailable or corrupt.
    StorageUnavailable,
}

impl FailureCode {
    /// Returns the stable wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DaemonStartConflict => "daemon.start_conflict",
            Self::DaemonStoppedBeforeDispatch => "daemon.stopped_before_dispatch",
            Self::DaemonStopBlocked => "daemon.stop_blocked",
            Self::OperationUncertain => "operation.uncertain",
            Self::ReconciliationRequired => "reconciliation_required",
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
