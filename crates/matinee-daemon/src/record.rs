//! Canonical public states for daemon records.

use std::fmt;

/// Canonical `Session` state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// A session is being opened.
    Opening,
    /// A session is usable.
    Active,
    /// A session is changing its browser binding.
    Rebinding,
    /// A session is being released.
    Releasing,
    /// A session is closed.
    Closed,
    /// A session failed before it could be used or released.
    Failed,
}

/// Canonical `Request` state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestState {
    /// The request was admitted but has not started.
    Accepted,
    /// At least one operation is executing.
    Running,
    /// Every operation completed successfully.
    Succeeded,
    /// The request completed with a failure.
    Failed,
    /// The request was cancelled before completion.
    Cancelled,
    /// The request deadline elapsed before completion.
    Expired,
}

/// Canonical `Operation` state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationState {
    /// The operation has been planned.
    Planned,
    /// The operation is waiting for dispatch admission.
    Queued,
    /// The operation is checking its target.
    Preflight,
    /// The operation crossed the browser effect boundary.
    Dispatching,
    /// The operation is waiting for user attention.
    AwaitingAttention,
    /// The operation completed successfully.
    Succeeded,
    /// The operation completed with a failure.
    Failed,
    /// The operation deadline elapsed before completion.
    Expired,
    /// The operation was cancelled before dispatch.
    Cancelled,
}

impl SessionState {
    /// Returns the stable wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Opening => "opening",
            Self::Active => "active",
            Self::Rebinding => "rebinding",
            Self::Releasing => "releasing",
            Self::Closed => "closed",
            Self::Failed => "failed",
        }
    }

    /// Reports whether the state admits no further transition.
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Closed | Self::Failed)
    }
}

impl RequestState {
    /// Returns the stable wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    /// Reports whether the request reached its single terminal outcome.
    pub const fn terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::Expired
        )
    }
}

impl OperationState {
    /// Returns the stable wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Queued => "queued",
            Self::Preflight => "preflight",
            Self::Dispatching => "dispatching",
            Self::AwaitingAttention => "awaiting_attention",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    /// Reports whether the operation has not crossed the effect boundary.
    pub const fn before_dispatch(self) -> bool {
        matches!(
            self,
            Self::Planned | Self::Queued | Self::Preflight | Self::AwaitingAttention
        )
    }
}

impl fmt::Display for SessionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Display for RequestState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Display for OperationState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
