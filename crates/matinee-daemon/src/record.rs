//! Canonical public states and private dispatch phases.
//!
//! Public `Request`, `Operation`, and `Session` states stay inside the
//! `matinee.tools.v1` enumerations. The dispatch phase is private and adds no
//! public state.
//!
//! Data model: `specs/006.5-demonstrable-browser-mvp/data-model.md`.

use std::fmt;

/// Canonical `Session` state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    Opening,
    Active,
    Rebinding,
    Releasing,
    Closed,
    Failed,
}

/// Canonical `Request` state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestState {
    Accepted,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Expired,
    ReconciliationRequired,
}

/// Canonical `Operation` state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationState {
    Planned,
    Queued,
    Preflight,
    Dispatching,
    AwaitingAttention,
    Succeeded,
    Failed,
    Uncertain,
    Reconciling,
    Expired,
    Cancelled,
}

/// Private dispatch-journal phase for one effectful operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchPhase {
    /// Committed while the operation is in `Preflight`.
    Prepared,
    /// Committed with the move to `Dispatching`, before the extension receives
    /// the command.
    Dispatched,
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
            Self::ReconciliationRequired => "reconciliation_required",
        }
    }

    /// Reports whether the request reached its single terminal outcome.
    pub const fn terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::Cancelled
                | Self::Expired
                | Self::ReconciliationRequired
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
            Self::Uncertain => "uncertain",
            Self::Reconciling => "reconciling",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    /// Reports whether the operation may still be cancelled without reaching
    /// the browser.
    pub const fn before_dispatch(self) -> bool {
        matches!(
            self,
            Self::Planned | Self::Queued | Self::Preflight | Self::AwaitingAttention
        )
    }
}

impl DispatchPhase {
    /// Returns the stable stored value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Dispatched => "dispatched",
        }
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

impl fmt::Display for DispatchPhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
