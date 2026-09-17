//! Closed, bounded failures for the security boundary.
//!
//! This module deliberately has no text-bearing error input.  Callers classify an
//! untrusted condition into one of the closed [`FailureCode`] values.  Consequently
//! formatting a [`SecurityFailure`] cannot accidentally disclose bytes from a
//! frame, credential, URL, or protected object.

use std::fmt;

use uuid::Uuid;

/// The security boundary at which a failure was classified.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum FailureBoundary {
    Authentication,
    Authorization,
    Compatibility,
    MalformedInput,
    Origin,
    Endpoint,
    Replay,
    RateLimit,
    CredentialStore,
    ResourceLimit,
    StaleEpoch,
    Revocation,
    Transition,
    EventSink,
}

impl FailureBoundary {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::Authorization => "authorization",
            Self::Compatibility => "compatibility",
            Self::MalformedInput => "malformed",
            Self::Origin => "origin",
            Self::Endpoint => "endpoint",
            Self::Replay => "replay",
            Self::RateLimit => "rate-limit",
            Self::CredentialStore => "credential-store",
            Self::ResourceLimit => "resource-limit",
            Self::StaleEpoch => "stale-epoch",
            Self::Revocation => "revocation",
            Self::Transition => "transition",
            Self::EventSink => "event-sink",
        }
    }
}

/// Stable, bounded reason classes.  The string values are the wire/event names.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum FailureCode {
    AuthenticationFailed,
    AuthorizationDenied,
    ObjectNotFound,
    CompatibilityUnsupported,
    DowngradeRejected,
    MalformedInput,
    OriginRejected,
    EndpointRejected,
    ReplayDetected,
    CounterMismatch,
    RateLimited,
    CredentialStoreUnavailable,
    CredentialStoreMismatch,
    ResourceLimit,
    StaleEpoch,
    Revoked,
    TransitionUnknown,
    EventSinkUnavailable,
    CryptographicFailure,
}

impl FailureCode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticationFailed => "authentication.failed",
            Self::AuthorizationDenied => "authorization.denied",
            Self::ObjectNotFound => "object.not_found",
            Self::CompatibilityUnsupported => "compatibility.unsupported",
            Self::DowngradeRejected => "compatibility.downgrade",
            Self::MalformedInput => "malformed.input",
            Self::OriginRejected => "origin.rejected",
            Self::EndpointRejected => "endpoint.rejected",
            Self::ReplayDetected => "replay.detected",
            Self::CounterMismatch => "replay.counter",
            Self::RateLimited => "rate_limited",
            Self::CredentialStoreUnavailable => "credential_store.unavailable",
            Self::CredentialStoreMismatch => "credential_store.mismatch",
            Self::ResourceLimit => "resource_limit",
            Self::StaleEpoch => "stale_epoch",
            Self::Revoked => "revoked",
            Self::TransitionUnknown => "transition.unknown",
            Self::EventSinkUnavailable => "event_sink.unavailable",
            Self::CryptographicFailure => "authentication.cryptographic",
        }
    }

    pub(crate) const fn boundary(self) -> FailureBoundary {
        match self {
            Self::AuthenticationFailed | Self::CryptographicFailure => {
                FailureBoundary::Authentication
            }
            Self::AuthorizationDenied | Self::ObjectNotFound => FailureBoundary::Authorization,
            Self::CompatibilityUnsupported | Self::DowngradeRejected => {
                FailureBoundary::Compatibility
            }
            Self::MalformedInput => FailureBoundary::MalformedInput,
            Self::OriginRejected => FailureBoundary::Origin,
            Self::EndpointRejected => FailureBoundary::Endpoint,
            Self::ReplayDetected | Self::CounterMismatch => FailureBoundary::Replay,
            Self::RateLimited => FailureBoundary::RateLimit,
            Self::CredentialStoreUnavailable | Self::CredentialStoreMismatch => {
                FailureBoundary::CredentialStore
            }
            Self::ResourceLimit => FailureBoundary::ResourceLimit,
            Self::StaleEpoch => FailureBoundary::StaleEpoch,
            Self::Revoked => FailureBoundary::Revocation,
            Self::TransitionUnknown => FailureBoundary::Transition,
            Self::EventSinkUnavailable => FailureBoundary::EventSink,
        }
    }

    pub(crate) const fn safe_next_action(self) -> SafeNextAction {
        match self {
            Self::AuthenticationFailed => SafeNextAction::VerifyCredentialAndReconnect,
            Self::AuthorizationDenied => SafeNextAction::RequestAdministratorGrant,
            Self::ObjectNotFound => SafeNextAction::DoNotInferObjectExistence,
            Self::CompatibilityUnsupported | Self::DowngradeRejected => {
                SafeNextAction::UseFixedContractPeer
            }
            Self::MalformedInput => SafeNextAction::DiscardAndReconnect,
            Self::OriginRejected => SafeNextAction::PairExpectedExtension,
            Self::EndpointRejected => SafeNextAction::UseConfiguredEndpoint,
            Self::ReplayDetected | Self::CounterMismatch => {
                SafeNextAction::DiscardAndEstablishFreshChannel
            }
            Self::RateLimited => SafeNextAction::WaitForRetryWindow,
            Self::CredentialStoreUnavailable => SafeNextAction::RestoreCredentialService,
            Self::CredentialStoreMismatch => SafeNextAction::StopAndAdministratorRepair,
            Self::ResourceLimit => SafeNextAction::ReduceToDeclaredBound,
            Self::StaleEpoch => SafeNextAction::ReconnectCurrentEpoch,
            Self::Revoked => SafeNextAction::StopAndAdministratorRepair,
            Self::TransitionUnknown => SafeNextAction::InspectTransitionStatus,
            Self::EventSinkUnavailable => SafeNextAction::RepairEventSink,
            Self::CryptographicFailure => SafeNextAction::DiscardAndReconnect,
        }
    }
}

/// A closed value describing what a caller may safely do next.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum SafeNextAction {
    VerifyCredentialAndReconnect,
    RequestAdministratorGrant,
    DoNotInferObjectExistence,
    UseFixedContractPeer,
    DiscardAndReconnect,
    PairExpectedExtension,
    DiscardAndEstablishFreshChannel,
    WaitForRetryWindow,
    RestoreCredentialService,
    StopAndAdministratorRepair,
    ReduceToDeclaredBound,
    ReconnectCurrentEpoch,
    InspectTransitionStatus,
    RepairEventSink,
}

impl SafeNextAction {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::VerifyCredentialAndReconnect => "verify-credential-and-reconnect",
            Self::RequestAdministratorGrant => "request-administrator-grant",
            Self::DoNotInferObjectExistence => "do-not-infer-object-existence",
            Self::UseFixedContractPeer => "use-fixed-contract-peer",
            Self::DiscardAndReconnect => "discard-and-reconnect",
            Self::PairExpectedExtension => "pair-expected-extension",
            Self::DiscardAndEstablishFreshChannel => "discard-and-establish-fresh-channel",
            Self::WaitForRetryWindow => "wait-for-retry-window",
            Self::RestoreCredentialService => "restore-credential-service",
            Self::StopAndAdministratorRepair => "stop-and-administrator-repair",
            Self::ReduceToDeclaredBound => "reduce-to-declared-bound",
            Self::ReconnectCurrentEpoch => "reconnect-current-epoch",
            Self::InspectTransitionStatus => "inspect-transition-status",
            Self::RepairEventSink => "repair-event-sink",
        }
    }
}

/// A safe failure projection.  No constructor accepts untrusted text or secret data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SecurityFailure {
    boundary: FailureBoundary,
    code: FailureCode,
    principal_id: Option<Uuid>,
    connection_id: Option<Uuid>,
}

impl SecurityFailure {
    pub(crate) const fn new(code: FailureCode) -> Self {
        Self {
            boundary: code.boundary(),
            code,
            principal_id: None,
            connection_id: None,
        }
    }

    pub(crate) const fn with_safe_ids(
        code: FailureCode,
        principal_id: Option<Uuid>,
        connection_id: Option<Uuid>,
    ) -> Self {
        Self {
            boundary: code.boundary(),
            code,
            principal_id,
            connection_id,
        }
    }

    pub(crate) const fn boundary(self) -> FailureBoundary {
        self.boundary
    }
    pub(crate) const fn code(self) -> FailureCode {
        self.code
    }
    pub(crate) const fn safe_next_action(self) -> SafeNextAction {
        self.code.safe_next_action()
    }
    pub(crate) const fn principal_id(self) -> Option<Uuid> {
        self.principal_id
    }
    pub(crate) const fn connection_id(self) -> Option<Uuid> {
        self.connection_id
    }

    /// Stable fields suitable for event serialization; no raw detail is retained.
    pub(crate) const fn redacted(self) -> (FailureBoundary, FailureCode, SafeNextAction) {
        (self.boundary, self.code, self.safe_next_action())
    }
}

impl fmt::Display for SecurityFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (boundary: {}; next: {})",
            self.code.as_str(),
            self.boundary.as_str(),
            self.safe_next_action().as_str()
        )
    }
}

// Intentional aliases make the contract vocabulary explicit to sibling modules.
pub(crate) type StableFailureCode = FailureCode;
pub(crate) type Failure = SecurityFailure;
#[cfg(test)]
mod tests {
    use super::*;

    const ALL_CODES: [FailureCode; 19] = [
        FailureCode::AuthenticationFailed,
        FailureCode::AuthorizationDenied,
        FailureCode::ObjectNotFound,
        FailureCode::CompatibilityUnsupported,
        FailureCode::DowngradeRejected,
        FailureCode::MalformedInput,
        FailureCode::OriginRejected,
        FailureCode::EndpointRejected,
        FailureCode::ReplayDetected,
        FailureCode::CounterMismatch,
        FailureCode::RateLimited,
        FailureCode::CredentialStoreUnavailable,
        FailureCode::CredentialStoreMismatch,
        FailureCode::ResourceLimit,
        FailureCode::StaleEpoch,
        FailureCode::Revoked,
        FailureCode::TransitionUnknown,
        FailureCode::EventSinkUnavailable,
        FailureCode::CryptographicFailure,
    ];

    #[test]
    fn codes_are_stable_unique_and_bounded() {
        for (index, code) in ALL_CODES.iter().enumerate() {
            let value = code.as_str();
            assert!(!value.is_empty() && value.len() <= 32);
            assert!(
                ALL_CODES[..index]
                    .iter()
                    .all(|prior| prior.as_str() != value)
            );
            assert_eq!(SecurityFailure::new(*code).boundary(), code.boundary());
            assert_eq!(
                SecurityFailure::new(*code).safe_next_action(),
                code.safe_next_action()
            );
        }
    }

    #[test]
    fn formatting_has_no_untrusted_detail() {
        let failure = SecurityFailure::with_safe_ids(
            FailureCode::CredentialStoreMismatch,
            Some(Uuid::nil()),
            Some(Uuid::nil()),
        );
        let rendered = failure.to_string();
        assert!(rendered.contains("credential_store.mismatch"));
        for secret in [
            "private-key",
            "PKCS#8",
            "cookie",
            "Authorization",
            "https://",
            "payload",
        ] {
            assert!(!rendered.contains(secret));
        }
    }

    #[test]
    fn object_privacy_uses_one_safe_result() {
        let unknown = SecurityFailure::new(FailureCode::ObjectNotFound);
        let denied = SecurityFailure::new(FailureCode::AuthorizationDenied);
        assert_eq!(unknown.boundary(), denied.boundary());
        assert_eq!(
            unknown.safe_next_action(),
            SafeNextAction::DoNotInferObjectExistence
        );
        assert_ne!(unknown.code(), denied.code());
    }
}
