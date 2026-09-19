// Bounded, redacted security-event facts.
//
// This module owns no clock, persistence, or queue. A caller supplies the event time
// and a sink decides whether the fact is accepted or aggregated.
// Spec 015 owns durable event delivery; Spec 006 keeps this complete typed sink
// boundary for that downstream wiring while tests cover the redaction contract.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::HashMap;
use uuid::Uuid;

const MAX_EVENT_BYTES: usize = 2_048;
const MAX_METADATA_ENTRIES: usize = 8;
const MAX_METADATA_KEY_BYTES: usize = 32;
const MAX_METADATA_VALUE_BYTES: usize = 128;
const MAX_METADATA_BYTES: usize = 512;
const MAX_BUCKETS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EventBoundary {
    Bootstrap,
    Enrollment,
    Authentication,
    Authorization,
    Rotation,
    Revocation,
    Channel,
    Input,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecurityCode {
    EnrollmentAccepted,
    AuthorizationAccepted,
    ProofRejected,
    OriginRejected,
    AuthenticationFailed,
    AuthorizationDenied,
    Rotation,
    Revocation,
    ReplayDetected,
    Downgrade,
    CounterRejected,
    CryptographicFailure,
    MalformedInput,
    ResourceLimit,
    RateLimited,
    EventSinkUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EventOutcome {
    Accepted,
    Rejected,
    Failed,
    Committed,
    Aggregated,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SafeNextAction {
    Retry,
    Reconnect,
    RePair,
    Discard,
    Wait,
    Continue,
    FailClosed,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EndpointClass {
    Native,
    Extension,
    Loopback,
    Unknown,
}

/// A timestamp supplied by the owning contract; this module does not read a clock.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct EventTime(pub(crate) u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataEntry {
    pub(crate) key: String,
    pub(crate) value: String,
}
impl MetadataEntry {
    pub fn key(&self) -> &str {
        &self.key
    }
    pub fn value(&self) -> &str {
        &self.value
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityEvent {
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
pub(crate) enum EventBuildError {
    TooManyMetadata,
    MetadataKeyTooLong,
    MetadataValueTooLong,
    MetadataTooLarge,
    Redacted,
    EventTooLarge,
}

impl SecurityEvent {
    // Event contract fields are fixed individually for redaction and audit bounds.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        event_id: Uuid,
        boundary: EventBoundary,
        code: SecurityCode,
        outcome: EventOutcome,
        next_action: SafeNextAction,
        principal_id: Option<Uuid>,
        connection_id: Option<Uuid>,
        endpoint: EndpointClass,
        time: EventTime,
        state_directory_id: Uuid,
        metadata: Vec<MetadataEntry>,
    ) -> Result<Self, EventBuildError> {
        if metadata.len() > MAX_METADATA_ENTRIES {
            return Err(EventBuildError::TooManyMetadata);
        }
        let mut metadata_bytes = 0usize;
        for entry in &metadata {
            let key_len = entry.key.len();
            let value_len = entry.value.len();
            if key_len > MAX_METADATA_KEY_BYTES {
                return Err(EventBuildError::MetadataKeyTooLong);
            }
            if value_len > MAX_METADATA_VALUE_BYTES {
                return Err(EventBuildError::MetadataValueTooLong);
            }
            if contains_secret(&entry.key) || contains_secret(&entry.value) {
                return Err(EventBuildError::Redacted);
            }
            metadata_bytes = metadata_bytes
                .saturating_add(key_len)
                .saturating_add(value_len);
        }
        if metadata_bytes > MAX_METADATA_BYTES {
            return Err(EventBuildError::MetadataTooLarge);
        }
        let event = Self {
            event_id,
            boundary,
            code,
            outcome,
            next_action,
            principal_id,
            connection_id,
            endpoint,
            time,
            state_directory_id,
            metadata,
        };
        if event.encoded_len() > MAX_EVENT_BYTES {
            return Err(EventBuildError::EventTooLarge);
        }
        Ok(event)
    }

    /// Deterministic upper-bound encoding length for the closed event representation.
    pub(crate) fn encoded_len(&self) -> usize {
        16 + 1
            + 1
            + 1
            + 1
            + 1
            + 8
            + 16
            + 1
            + self.principal_id.is_some() as usize * 16
            + self.connection_id.is_some() as usize * 16
            + self
                .metadata
                .iter()
                .map(|m| 4 + m.key.len() + m.value.len())
                .sum::<usize>()
    }

    pub fn boundary(&self) -> EventBoundary {
        self.boundary
    }
    pub fn code(&self) -> SecurityCode {
        self.code
    }
    pub fn outcome(&self) -> EventOutcome {
        self.outcome
    }
    pub fn next_action(&self) -> SafeNextAction {
        self.next_action
    }
    pub fn principal_id(&self) -> Option<Uuid> {
        self.principal_id
    }
    pub fn connection_id(&self) -> Option<Uuid> {
        self.connection_id
    }
    /// The local-state directory the fact is attributed to. A sink needs it to keep facts
    /// from separate state directories apart; it is an identity, never a path.
    pub fn state_directory_id(&self) -> Uuid {
        self.state_directory_id
    }
    pub fn metadata(&self) -> &[MetadataEntry] {
        &self.metadata
    }
}

fn contains_secret(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    [
        "private",
        "secret",
        "credential",
        "password",
        "cookie",
        "token",
        "authorization",
        "header",
        "pkcs8",
        "payload",
        "https://",
        "http://",
        "url",
        "object_id",
        "identifier",
        "artifact_id",
        "stream_id",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityEventSinkResult {
    Accepted,
    Aggregated,
    Unavailable,
}
#[cfg_attr(test, allow(dead_code))]
pub(crate) type SinkResult = SecurityEventSinkResult;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequiredEventError {
    Unavailable,
}

/// A required event must be available before a protected mutation is committed.
/// Callers perform the mutation only after this returns `Ok`.
pub(crate) fn emit_required<S>(
    sink: Option<&mut S>,
    event: SecurityEvent,
) -> Result<SecurityEventSinkResult, RequiredEventError>
where
    S: SecurityEventSink + ?Sized,
{
    let Some(sink) = sink else {
        return Err(RequiredEventError::Unavailable);
    };
    match sink.emit(event) {
        SecurityEventSinkResult::Unavailable => Err(RequiredEventError::Unavailable),
        result => Ok(result),
    }
}

pub trait SecurityEventSink {
    fn emit(&mut self, event: SecurityEvent) -> SecurityEventSinkResult;
}

/// Adapts a crate-local callback to the event-sink seam without exposing event
/// delivery outside this crate. The callback receives only bounded, redacted data.
#[cfg_attr(test, allow(dead_code))]
pub(crate) struct CallbackSecurityEventSink<F> {
    callback: F,
}

#[cfg_attr(test, allow(dead_code))]
impl<F> CallbackSecurityEventSink<F> {
    pub(crate) fn new(callback: F) -> Self {
        Self { callback }
    }
}

impl<F> SecurityEventSink for CallbackSecurityEventSink<F>
where
    F: FnMut(SecurityEvent) -> SecurityEventSinkResult,
{
    fn emit(&mut self, event: SecurityEvent) -> SecurityEventSinkResult {
        (self.callback)(event)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct AggregationKey {
    boundary: EventBoundary,
    code: SecurityCode,
    principal_id: Option<Uuid>,
    connection_id: Option<Uuid>,
    endpoint: EndpointClass,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct AggregationState {
    buckets: HashMap<AggregationKey, u8>,
}

impl AggregationState {
    fn record(&mut self, event: &SecurityEvent) -> SecurityEventSinkResult {
        let key = AggregationKey {
            boundary: event.boundary,
            code: event.code,
            principal_id: event.principal_id,
            connection_id: event.connection_id,
            endpoint: event.endpoint,
        };
        if let Some(count) = self.buckets.get_mut(&key) {
            *count = count.saturating_add(1);
            return SecurityEventSinkResult::Aggregated;
        }
        if self.buckets.len() >= MAX_BUCKETS {
            return SecurityEventSinkResult::Unavailable;
        }
        self.buckets.insert(key, 1);
        SecurityEventSinkResult::Aggregated
    }
}

#[cfg(test)]
impl AggregationState {
    pub(crate) fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    pub(crate) fn count_for(&self, event: &SecurityEvent) -> Option<u8> {
        let key = AggregationKey {
            boundary: event.boundary,
            code: event.code,
            principal_id: event.principal_id,
            connection_id: event.connection_id,
            endpoint: event.endpoint,
        };
        self.buckets.get(&key).copied()
    }
}
impl SecurityEventSink for AggregationState {
    fn emit(&mut self, event: SecurityEvent) -> SecurityEventSinkResult {
        self.record(&event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(metadata: Vec<MetadataEntry>) -> SecurityEvent {
        SecurityEvent::new(
            Uuid::nil(),
            EventBoundary::Channel,
            SecurityCode::MalformedInput,
            EventOutcome::Failed,
            SafeNextAction::Discard,
            None,
            None,
            EndpointClass::Native,
            EventTime(0),
            Uuid::nil(),
            metadata,
        )
        .unwrap()
    }
    #[test]
    fn bounds_and_redaction() {
        assert_eq!(event(vec![]).metadata().len(), 0);
        assert_eq!(
            SecurityEvent::new(
                Uuid::nil(),
                EventBoundary::Channel,
                SecurityCode::MalformedInput,
                EventOutcome::Failed,
                SafeNextAction::Discard,
                None,
                None,
                EndpointClass::Native,
                EventTime(0),
                Uuid::nil(),
                vec![MetadataEntry {
                    key: "secret".into(),
                    value: "x".into()
                }]
            ),
            Err(EventBuildError::Redacted)
        );
    }
    #[test]
    fn aggregation_saturates_and_bounds_buckets() {
        let mut state = AggregationState::default();
        let e = event(vec![]);
        for _ in 0..300 {
            assert_eq!(state.record(&e), SecurityEventSinkResult::Aggregated);
        }
        assert_eq!(state.buckets.values().copied().next(), Some(255));
        for i in 1..=64 {
            let e = SecurityEvent::new(
                Uuid::from_u128(i),
                EventBoundary::Channel,
                SecurityCode::MalformedInput,
                EventOutcome::Failed,
                SafeNextAction::Discard,
                None,
                None,
                EndpointClass::Native,
                EventTime(0),
                Uuid::nil(),
                vec![],
            )
            .unwrap();
            let _ = state.record(&e);
        }
        assert!(state.buckets.len() <= MAX_BUCKETS);
    }
    #[test]
    fn callback_sink_forwards_bounded_event_and_preserves_result() {
        let mut seen = Vec::new();
        let mut sink = CallbackSecurityEventSink::new(|event| {
            seen.push(event);
            SecurityEventSinkResult::Accepted
        });
        assert_eq!(
            emit_required(Some(&mut sink), event(vec![])),
            Ok(SecurityEventSinkResult::Accepted)
        );
        assert_eq!(seen.len(), 1);
        assert!(seen[0].encoded_len() <= MAX_EVENT_BYTES);
    }

    #[test]
    fn aggregation_sink_returns_unavailable_without_mutating_full_state() {
        let mut sink = AggregationState::default();
        for i in 0..MAX_BUCKETS {
            let mut current = event(vec![]);
            current.event_id = Uuid::from_u128((i + 1) as u128);
            current.principal_id = Some(Uuid::from_u128((i + 1) as u128));
            assert_eq!(sink.emit(current), SecurityEventSinkResult::Aggregated);
        }
        let before = sink.buckets.clone();
        let mut overflow = event(vec![]);
        overflow.event_id = Uuid::from_u128(10_000);
        overflow.principal_id = Some(Uuid::from_u128(10_000));
        assert_eq!(
            emit_required(Some(&mut sink), overflow),
            Err(RequiredEventError::Unavailable)
        );
        assert_eq!(sink.buckets, before);
    }
}
