// Bounded, redacted security-event facts.
//
// This module owns no clock, persistence, or queue. A caller supplies the event time
// and a sink decides whether the fact is accepted or aggregated.

use std::collections::HashMap;
use uuid::Uuid;

const MAX_EVENT_BYTES: usize = 2_048;
const MAX_METADATA_ENTRIES: usize = 8;
const MAX_METADATA_KEY_BYTES: usize = 32;
const MAX_METADATA_VALUE_BYTES: usize = 128;
const MAX_METADATA_BYTES: usize = 512;
const MAX_BUCKETS: usize = 64;
const MAX_COUNT: u8 = u8::MAX;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum EventBoundary { Bootstrap, Enrollment, Authentication, Authorization, Rotation, Revocation, Channel, Input }

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum SecurityCode {
    EnrollmentAccepted, ProofRejected, OriginRejected, AuthenticationFailed,
    AuthorizationDenied, Rotation, Revocation, ReplayDetected, Downgrade,
    MalformedInput, ResourceLimit, RateLimited, EventSinkUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum EventOutcome { Accepted, Rejected, Failed, Committed, Aggregated, Unavailable }

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum SafeNextAction { Retry, Reconnect, RePair, Discard, Wait, FailClosed }

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum EndpointClass { Native, Extension, Loopback, Unknown }

/// A timestamp supplied by the owning contract; this module does not read a clock.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct EventTime(pub(crate) u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MetadataEntry { pub(crate) key: String, pub(crate) value: String }

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SecurityEvent {
    pub(crate) event_id: Uuid,
    pub(crate) boundary: EventBoundary,
    pub(crate) code: SecurityCode,
    pub(crate) outcome: EventOutcome,
    pub(crate) next_action: SafeNextAction,
    pub(crate) principal_id: Option<Uuid>,
    pub(crate) connection_id: Option<Uuid>,
    pub(crate) endpoint: EndpointClass,
    pub(crate) time: EventTime,
    pub(crate) state_directory_id: Uuid,
    pub(crate) metadata: Vec<MetadataEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventBuildError { TooManyMetadata, MetadataKeyTooLong, MetadataValueTooLong, MetadataTooLarge, Redacted, EventTooLarge }

impl SecurityEvent {
    pub(crate) fn new(
        event_id: Uuid, boundary: EventBoundary, code: SecurityCode,
        outcome: EventOutcome, next_action: SafeNextAction,
        principal_id: Option<Uuid>, connection_id: Option<Uuid>, endpoint: EndpointClass,
        time: EventTime, state_directory_id: Uuid, metadata: Vec<MetadataEntry>,
    ) -> Result<Self, EventBuildError> {
        if metadata.len() > MAX_METADATA_ENTRIES { return Err(EventBuildError::TooManyMetadata); }
        let mut metadata_bytes = 0usize;
        for entry in &metadata {
            let key_len = entry.key.len();
            let value_len = entry.value.len();
            if key_len > MAX_METADATA_KEY_BYTES { return Err(EventBuildError::MetadataKeyTooLong); }
            if value_len > MAX_METADATA_VALUE_BYTES { return Err(EventBuildError::MetadataValueTooLong); }
            if contains_secret(&entry.key) || contains_secret(&entry.value) { return Err(EventBuildError::Redacted); }
            metadata_bytes = metadata_bytes.saturating_add(key_len).saturating_add(value_len);
        }
        if metadata_bytes > MAX_METADATA_BYTES { return Err(EventBuildError::MetadataTooLarge); }
        let event = Self { event_id, boundary, code, outcome, next_action, principal_id, connection_id,
            endpoint, time, state_directory_id, metadata };
        if event.encoded_len() > MAX_EVENT_BYTES { return Err(EventBuildError::EventTooLarge); }
        Ok(event)
    }

    /// Deterministic upper-bound encoding length for the closed event representation.
    pub(crate) fn encoded_len(&self) -> usize {
        16 + 1 + 1 + 1 + 1 + 1 + 8 + 16 + 1 + self.principal_id.is_some() as usize * 16
            + self.connection_id.is_some() as usize * 16
            + self.metadata.iter().map(|m| 4 + m.key.len() + m.value.len()).sum::<usize>()
    }

    pub(crate) fn metadata(&self) -> &[MetadataEntry] { &self.metadata }
}

fn contains_secret(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    ["private", "secret", "credential", "password", "cookie", "token", "authorization", "pkcs8", "payload", "https://", "http://", "url", "object_id", "artifact_id", "stream_id"]
        .iter().any(|needle| lower.contains(needle))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SecurityEventSinkResult { Accepted, Aggregated, Unavailable }
pub(crate) type SinkResult = SecurityEventSinkResult;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequiredEventError { Unavailable }

/// A required event must be available before a protected mutation is committed.
/// Callers perform the mutation only after this returns `Ok`.
pub(crate) fn emit_required<S>(sink: Option<&mut S>, event: SecurityEvent) -> Result<SecurityEventSinkResult, RequiredEventError>
where S: SecurityEventSink {
    let Some(sink) = sink else { return Err(RequiredEventError::Unavailable); };
    match sink.emit(event) {
        SecurityEventSinkResult::Unavailable => Err(RequiredEventError::Unavailable),
        result => Ok(result),
    }
}

pub(crate) trait SecurityEventSink {
    fn emit(&mut self, event: SecurityEvent) -> SecurityEventSinkResult;
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct AggregationKey { boundary: EventBoundary, code: SecurityCode, principal_id: Option<Uuid>, connection_id: Option<Uuid>, endpoint: EndpointClass }

#[derive(Clone, Debug, Default)]
struct AggregationState { buckets: HashMap<AggregationKey, u8> }

impl AggregationState {
    fn record(&mut self, event: &SecurityEvent) -> SecurityEventSinkResult {
        let key = AggregationKey { boundary: event.boundary, code: event.code, principal_id: event.principal_id,
            connection_id: event.connection_id, endpoint: event.endpoint };
        if let Some(count) = self.buckets.get_mut(&key) {
            *count = count.saturating_add(1).min(MAX_COUNT);
            return SecurityEventSinkResult::Aggregated;
        }
        if self.buckets.len() >= MAX_BUCKETS { return SecurityEventSinkResult::Unavailable; }
        self.buckets.insert(key, 1);
        SecurityEventSinkResult::Aggregated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(metadata: Vec<MetadataEntry>) -> SecurityEvent {
        SecurityEvent::new(Uuid::nil(), EventBoundary::Channel, SecurityCode::MalformedInput,
            EventOutcome::Failed, SafeNextAction::Discard, None, None, EndpointClass::Native,
            EventTime(0), Uuid::nil(), metadata).unwrap()
    }
    #[test] fn bounds_and_redaction() {
        assert_eq!(event(vec![]).metadata().len(), 0);
        assert_eq!(SecurityEvent::new(Uuid::nil(), EventBoundary::Channel, SecurityCode::MalformedInput,
            EventOutcome::Failed, SafeNextAction::Discard, None, None, EndpointClass::Native, EventTime(0), Uuid::nil(),
            vec![MetadataEntry { key: "secret".into(), value: "x".into() }]), Err(EventBuildError::Redacted));
    }
    #[test] fn aggregation_saturates_and_bounds_buckets() {
        let mut state = AggregationState::default(); let e = event(vec![]);
        for _ in 0..300 { assert_eq!(state.record(&e), SecurityEventSinkResult::Aggregated); }
        assert_eq!(state.buckets.values().copied().next(), Some(255));
        for i in 1..=64 { let e = SecurityEvent::new(Uuid::from_u128(i), EventBoundary::Channel, SecurityCode::MalformedInput,
            EventOutcome::Failed, SafeNextAction::Discard, None, None, EndpointClass::Native, EventTime(0), Uuid::nil(), vec![]).unwrap();
            let _ = state.record(&e); }
        assert!(state.buckets.len() <= MAX_BUCKETS);
    }
}
